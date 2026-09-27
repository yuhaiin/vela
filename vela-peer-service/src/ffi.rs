use std::{
    ffi::{CString, c_char},
    future::Future,
    path::PathBuf,
    ptr,
    sync::{Arc, Mutex},
    thread::{self, JoinHandle},
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use tokio::{
    runtime::{Builder, Runtime},
    sync::oneshot,
};
use vela_crypto::{Identity, MembershipCredential};
use vela_diagnostic::{DashboardSnapshot, PeerConfig, PeerRegistration, PeerSecrets};

use crate::{PeerService, PeerServiceMaterial};

const MAX_FFI_INPUT_BYTES: usize = 1024 * 1024;

#[derive(Serialize)]
struct IdentityKeyResponse {
    signing_private: String,
    noise_private: String,
}

#[derive(Serialize)]
struct RegistrationResponse {
    config: PeerConfig,
    credential: MembershipCredential,
}

#[derive(Deserialize)]
struct ServiceStartRequest {
    state_dir: PathBuf,
    peer: PeerConfig,
    secrets: ServiceSecrets,
    port: Option<u16>,
    mtu: usize,
    tun_name: String,
}

#[derive(Deserialize)]
struct ServiceSecrets {
    #[serde(with = "vela_proto::base64_32_serde")]
    signing_private: [u8; 32],
    #[serde(with = "vela_proto::base64_32_serde")]
    noise_private: [u8; 32],
    credential: MembershipCredential,
}

#[derive(Clone, Debug, Default, Serialize)]
struct ServiceStatus {
    running: bool,
    node_id: Option<String>,
    tun_name: Option<String>,
    dashboard: Option<DashboardSnapshot>,
    credential: Option<MembershipCredential>,
    error: Option<String>,
}

pub struct VelaPeerServiceHandle {
    shutdown: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<()>>,
    status: Arc<Mutex<ServiceStatus>>,
}

fn make_runtime() -> Result<Runtime, String> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())
}

fn run_async<F: Future>(future: F) -> Result<F::Output, String> {
    let runtime = make_runtime()?;
    Ok(runtime.block_on(future))
}

fn c_string(value: impl AsRef<str>) -> *mut c_char {
    let value = value.as_ref().replace('\0', "\\0");
    CString::new(value)
        .expect("NUL bytes were replaced")
        .into_raw()
}

unsafe fn read_input<'a>(pointer: *const u8, length: usize) -> Result<&'a [u8], String> {
    if length > MAX_FFI_INPUT_BYTES {
        return Err(format!("input exceeds {MAX_FFI_INPUT_BYTES} bytes"));
    }
    if length == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() {
        return Err("input pointer is null".to_owned());
    }
    // SAFETY: the exported functions document that non-null pointers must
    // reference `length` readable bytes for the duration of the call.
    Ok(unsafe { std::slice::from_raw_parts(pointer, length) })
}

unsafe fn set_error(output: *mut *mut c_char, message: impl AsRef<str>) {
    if !output.is_null() {
        // SAFETY: callers provide a valid writable pointer slot when non-null.
        unsafe { *output = c_string(message) };
    }
}

fn lock_status(status: &Mutex<ServiceStatus>) -> std::sync::MutexGuard<'_, ServiceStatus> {
    status
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn json_string(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| error.to_string())
}

/// Creates a new coordinator config with Vela's current default resolver
/// settings and no registration credential.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vela_peer_config_create(
    server: *const u8,
    server_length: usize,
    server_key_base64: *const u8,
    server_key_length: usize,
    error_output: *mut *mut c_char,
) -> *mut c_char {
    if !error_output.is_null() {
        // SAFETY: validated as a writable output slot in the function contract.
        unsafe { *error_output = ptr::null_mut() };
    }
    let result = (|| {
        // SAFETY: pointer validity is part of this function's C contract.
        let server = unsafe { read_input(server, server_length)? };
        // SAFETY: pointer validity is part of this function's C contract.
        let server_key = unsafe { read_input(server_key_base64, server_key_length)? };
        let server = std::str::from_utf8(server).map_err(|error| error.to_string())?;
        let server_key = std::str::from_utf8(server_key).map_err(|error| error.to_string())?;
        let server_key = BASE64
            .decode(server_key)
            .map_err(|error| error.to_string())?;
        let server_key: [u8; 32] = server_key
            .try_into()
            .map_err(|_| "Coordinator key must decode to exactly 32 bytes".to_owned())?;
        let config = PeerConfig::new(server.to_owned(), server_key, Vec::new());
        json_string(&config)
    })();
    match result {
        Ok(config) => c_string(config),
        Err(error) => {
            // SAFETY: this output pointer follows the function's documented contract.
            unsafe { set_error(error_output, error) };
            ptr::null_mut()
        }
    }
}

/// Generates a new Vela identity as JSON containing two base64 private keys.
///
/// The caller must store the keys in a secure credential store and release the
/// returned string with [`vela_string_free`].
#[unsafe(no_mangle)]
pub extern "C" fn vela_identity_generate() -> *mut c_char {
    let identity = Identity::generate();
    let (signing_private, noise_private) = identity.private_keys();
    c_string(
        json_string(&IdentityKeyResponse {
            signing_private: BASE64.encode(signing_private),
            noise_private: BASE64.encode(noise_private),
        })
        .unwrap_or_else(|error| format!("{{\"error\":{error:?}}}")),
    )
}

/// Performs invite registration without writing identity or credentials to
/// disk. `identity_bytes` is signing key bytes followed by Noise key bytes.
///
/// All non-empty input pointers must reference the stated number of readable
/// bytes. `error_output`, when non-null, must reference a writable pointer slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vela_peer_register(
    config_json: *const u8,
    config_json_length: usize,
    identity_bytes: *const u8,
    identity_length: usize,
    invite: *const u8,
    invite_length: usize,
    port: u16,
    error_output: *mut *mut c_char,
) -> *mut c_char {
    if !error_output.is_null() {
        // SAFETY: validated as a writable output slot in the function contract.
        unsafe { *error_output = ptr::null_mut() };
    }
    let result = (|| {
        // SAFETY: pointer validity is part of this function's C contract.
        let config_bytes = unsafe { read_input(config_json, config_json_length)? };
        // SAFETY: pointer validity is part of this function's C contract.
        let identity = unsafe { read_input(identity_bytes, identity_length)? };
        // SAFETY: pointer validity is part of this function's C contract.
        let invite = unsafe { read_input(invite, invite_length)? };
        if identity.len() != 64 {
            return Err("identity material must contain exactly 64 bytes".to_owned());
        }
        let config: PeerConfig =
            serde_json::from_slice(config_bytes).map_err(|error| error.to_string())?;
        let invite = std::str::from_utf8(invite).map_err(|error| error.to_string())?;
        let signing_private: [u8; 32] = identity[..32]
            .try_into()
            .map_err(|_| "invalid signing key length".to_owned())?;
        let noise_private: [u8; 32] = identity[32..]
            .try_into()
            .map_err(|_| "invalid Noise key length".to_owned())?;
        let identity = Identity::from_private_keys(signing_private, noise_private);
        let registration = run_async(vela_diagnostic::register_with_material(
            config, identity, invite, port,
        ))?
        .map_err(|error| error.to_string())?;
        let PeerRegistration { config, secrets } = registration;
        json_string(&RegistrationResponse {
            config,
            credential: secrets.credential,
        })
    })();

    match result {
        Ok(response) => c_string(response),
        Err(error) => {
            // SAFETY: this output pointer follows the function's documented contract.
            unsafe { set_error(error_output, error) };
            ptr::null_mut()
        }
    }
}

/// Starts the managed peer from JSON app settings and Keychain material.
///
/// The request contains `peer`, `state_dir`, `port`, `mtu`, `tun_name`, and a
/// `secrets` object with base64 key fields plus the serialized credential.
/// The helper process should call `vela_peer_service_stop` when its owning XPC
/// client disconnects. Input and error pointer safety follows
/// [`vela_peer_register`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vela_peer_service_start(
    request_json: *const u8,
    request_length: usize,
    error_output: *mut *mut c_char,
) -> *mut VelaPeerServiceHandle {
    if !error_output.is_null() {
        // SAFETY: validated as a writable output slot in the function contract.
        unsafe { *error_output = ptr::null_mut() };
    }

    let result = (|| {
        // SAFETY: pointer validity is part of this function's C contract.
        let request_bytes = unsafe { read_input(request_json, request_length)? };
        let request: ServiceStartRequest =
            serde_json::from_slice(request_bytes).map_err(|error| error.to_string())?;
        let (startup_tx, startup_rx) = std::sync::mpsc::sync_channel(1);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let status = Arc::new(Mutex::new(ServiceStatus::default()));
        let worker_status = Arc::clone(&status);
        let worker = thread::Builder::new()
            .name("vela-peer-service".to_owned())
            .spawn(move || {
                let runtime = match make_runtime() {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = startup_tx.send(Err(error));
                        return;
                    }
                };
                let identity = Identity::from_private_keys(
                    request.secrets.signing_private,
                    request.secrets.noise_private,
                );
                let material = PeerServiceMaterial {
                    state_dir: request.state_dir,
                    peer: request.peer,
                    secrets: PeerSecrets {
                        identity,
                        credential: request.secrets.credential,
                    },
                    port: request.port,
                    mtu: request.mtu,
                    tun_name: request.tun_name,
                };
                let mut service = match runtime.block_on(PeerService::start_with_material(material))
                {
                    Ok(service) => service,
                    Err(error) => {
                        let message = error.to_string();
                        lock_status(&worker_status).error = Some(message.clone());
                        let _ = startup_tx.send(Err(message));
                        return;
                    }
                };
                let mut dashboards = service.dashboard_updates();
                let mut credentials = service.credential_updates();
                {
                    let mut snapshot = lock_status(&worker_status);
                    snapshot.running = true;
                    snapshot.node_id = Some(service.node_id().to_string());
                    snapshot.tun_name = Some(service.tun_name().to_owned());
                    snapshot.dashboard = Some(dashboards.borrow().clone());
                    snapshot.credential = credentials.borrow().clone();
                }
                let _ = startup_tx.send(Ok(()));

                runtime.block_on(async move {
                    let mut shutdown_rx = shutdown_rx;
                    let mut requested_stop = false;
                    let mut dashboard_open = true;
                    let mut credential_open = true;
                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => {
                                requested_stop = true;
                                break;
                            }
                            result = service.wait() => {
                                let error = result.err().map(|error| error.to_string());
                                let mut snapshot = lock_status(&worker_status);
                                snapshot.running = false;
                                snapshot.error = error;
                                break;
                            }
                            changed = dashboards.changed(), if dashboard_open => {
                                if changed.is_err() {
                                    dashboard_open = false;
                                } else {
                                    let dashboard = dashboards.borrow().clone();
                                    lock_status(&worker_status).dashboard = Some(dashboard);
                                }
                            }
                            changed = credentials.changed(), if credential_open => {
                                if changed.is_err() {
                                    credential_open = false;
                                } else {
                                    let credential = credentials.borrow().clone();
                                    lock_status(&worker_status).credential = credential;
                                }
                            }
                        }
                    }
                    if requested_stop {
                        let error = service.stop().await.err().map(|error| error.to_string());
                        let mut snapshot = lock_status(&worker_status);
                        snapshot.running = false;
                        snapshot.error = error;
                    }
                });
            })
            .map_err(|error| error.to_string())?;

        match startup_rx.recv().map_err(|error| error.to_string())? {
            Ok(()) => Ok(VelaPeerServiceHandle {
                shutdown: Some(shutdown),
                worker: Some(worker),
                status,
            }),
            Err(error) => {
                let _ = worker.join();
                Err(error)
            }
        }
    })();

    match result {
        Ok(handle) => Box::into_raw(Box::new(handle)),
        Err(error) => {
            // SAFETY: this output pointer follows the function's documented contract.
            unsafe { set_error(error_output, error) };
            ptr::null_mut()
        }
    }
}

/// Returns a JSON snapshot of peer status and the latest Keychain credential.
/// The returned string must be released with [`vela_string_free`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vela_peer_service_status(
    handle: *const VelaPeerServiceHandle,
) -> *mut c_char {
    if handle.is_null() {
        return c_string("{\"running\":false,\"error\":\"service handle is null\"}");
    }
    // SAFETY: callers must pass a live handle returned by
    // `vela_peer_service_start` and not concurrently stop or free it.
    let handle = unsafe { &*handle };
    let status = lock_status(&handle.status).clone();
    c_string(
        json_string(&status)
            .unwrap_or_else(|error| format!("{{\"running\":false,\"error\":{error:?}}}")),
    )
}

/// Stops the peer, releases route leases, joins the worker, and frees the
/// service handle. Returns a JSON error string or null on success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vela_peer_service_stop(handle: *mut VelaPeerServiceHandle) -> *mut c_char {
    if handle.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: callers must pass a live handle returned by
    // `vela_peer_service_start` exactly once.
    let mut handle = unsafe { Box::from_raw(handle) };
    if let Some(shutdown) = handle.shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(worker) = handle.worker.take()
        && worker.join().is_err()
    {
        return c_string("peer service worker panicked");
    }
    let error = lock_status(&handle.status).error.clone();
    error.map_or(ptr::null_mut(), c_string)
}

/// Releases a string returned by this module's C API.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vela_string_free(value: *mut c_char) {
    if !value.is_null() {
        // SAFETY: value must be an unfreed string returned by this module.
        drop(unsafe { CString::from_raw(value) });
    }
}
