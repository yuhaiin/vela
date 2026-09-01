use crate::{
    DashboardSnapshot, DiagnosticError, PeerStatus, PingReport,
    runtime::{RuntimeCommand, RuntimeStore},
};
use fs2::FileExt;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
#[cfg(not(unix))]
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::{Notify, Semaphore, mpsc, oneshot},
    time::{Duration as TokioDuration, timeout},
};
use tracing::warn;
use vela_proto::{NodeId, PeerSummary};

const CONTROL_FILE: &str = "control.json";
const CONTROL_SOCKET: &str = "control.sock";
const LOCK_FILE: &str = "peer.lock";
const CONTROL_VERSION: u8 = 1;
const MAX_REQUEST_BYTES: usize = 128 * 1024;
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ControlTransport {
    Unix,
    Tcp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControlEndpoint {
    pub version: u8,
    transport: ControlTransport,
    pub socket: Option<PathBuf>,
    pub address: Option<SocketAddr>,
    pub token: Option<String>,
    pub pid: u32,
    pub incarnation: u64,
}

pub struct StateLock {
    _file: File,
}

impl StateLock {
    pub(crate) fn acquire(state_dir: &Path) -> Result<Self, DiagnosticError> {
        fs::create_dir_all(state_dir)?;
        let path = state_dir.join(LOCK_FILE);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)?;
        super::set_private(&path)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(Self { _file: file }),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                Err(DiagnosticError::AlreadyRunning)
            }
            Err(error) => Err(DiagnosticError::Io(error)),
        }
    }
}

#[derive(Clone)]
struct LocalControlState {
    store: Arc<RuntimeStore>,
    commands: mpsc::Sender<RuntimeCommand>,
    tcp_token: Option<String>,
    connection_limit: Arc<Semaphore>,
}

pub(crate) struct LocalControlServer {
    shutdown: Arc<Notify>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    socket_path: Option<PathBuf>,
    endpoint_path: PathBuf,
    endpoint: ControlEndpoint,
    _lock: StateLock,
}

impl LocalControlServer {
    pub(crate) async fn start_with_lock(
        state_dir: &Path,
        _node_id: NodeId,
        incarnation: u64,
        store: Arc<RuntimeStore>,
        commands: mpsc::Sender<RuntimeCommand>,
        dashboard_bind: SocketAddr,
        lock: StateLock,
    ) -> Result<Self, DiagnosticError> {
        let endpoint_path = state_dir.join(CONTROL_FILE);
        let tcp_token = Some(random_token());
        let state = Arc::new(LocalControlState {
            store,
            commands,
            tcp_token: tcp_token.clone(),
            connection_limit: Arc::new(Semaphore::new(64)),
        });
        let dashboard_listener = TcpListener::bind(dashboard_bind).await?;
        let dashboard_addr = dashboard_listener.local_addr()?;

        #[cfg(unix)]
        let (socket_path, socket_listener, transport) = {
            let socket_path = state_dir.join(CONTROL_SOCKET);
            if socket_path.exists() {
                fs::remove_file(&socket_path)?;
            }
            let listener = UnixListener::bind(&socket_path)?;
            super::set_private(&socket_path)?;
            (Some(socket_path), Some(listener), ControlTransport::Unix)
        };

        #[cfg(not(unix))]
        let (socket_path, socket_listener, transport) =
            (None, None::<TcpListener>, ControlTransport::Tcp);

        let endpoint = ControlEndpoint {
            version: CONTROL_VERSION,
            transport,
            socket: socket_path.clone(),
            address: Some(dashboard_addr),
            token: tcp_token,
            pid: std::process::id(),
            incarnation,
        };
        write_endpoint(&endpoint_path, &endpoint)?;
        let shutdown = Arc::new(Notify::new());
        let mut tasks = vec![tokio::spawn(run_tcp_listener(
            dashboard_listener,
            Arc::clone(&state),
            Arc::clone(&shutdown),
        ))];
        #[cfg(unix)]
        if let Some(listener) = socket_listener {
            tasks.push(tokio::spawn(run_unix_listener(
                listener,
                Arc::clone(&state),
                Arc::clone(&shutdown),
            )));
        }
        if !dashboard_addr.ip().is_loopback() {
            warn!(
                address = %dashboard_addr,
                "dashboard is exposed beyond loopback; local status endpoints require the control token"
            );
        }
        Ok(Self {
            shutdown,
            tasks,
            socket_path,
            endpoint_path,
            endpoint,
            _lock: lock,
        })
    }

    pub(crate) fn endpoint(&self) -> &ControlEndpoint {
        &self.endpoint
    }

    pub(crate) async fn shutdown(mut self) {
        self.shutdown.notify_waiters();
        for task in self.tasks.drain(..) {
            task.abort();
            let _ = task.await;
        }
        if let Some(path) = self.socket_path.as_ref() {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(&self.endpoint_path);
    }
}

impl Drop for LocalControlServer {
    fn drop(&mut self) {
        self.shutdown.notify_waiters();
        for task in &self.tasks {
            task.abort();
        }
        if let Some(path) = self.socket_path.as_ref() {
            let _ = fs::remove_file(path);
        }
        let _ = fs::remove_file(&self.endpoint_path);
    }
}

fn random_token() -> String {
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token)
}

fn write_endpoint(path: &Path, endpoint: &ControlEndpoint) -> Result<(), DiagnosticError> {
    let temporary = path.with_extension("json.tmp");
    fs::write(&temporary, serde_json::to_vec_pretty(endpoint)?)?;
    super::set_private(&temporary)?;
    #[cfg(windows)]
    let _ = fs::remove_file(path);
    fs::rename(temporary, path)?;
    Ok(())
}

async fn run_tcp_listener(
    listener: TcpListener,
    state: Arc<LocalControlState>,
    shutdown: Arc<Notify>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => return,
            result = listener.accept() => {
                let Ok((stream, _)) = result else { return };
                let state = Arc::clone(&state);
                tokio::spawn(async move { serve_connection(stream, state, true).await });
            }
        }
    }
}

#[cfg(unix)]
async fn run_unix_listener(
    listener: UnixListener,
    state: Arc<LocalControlState>,
    shutdown: Arc<Notify>,
) {
    loop {
        tokio::select! {
            _ = shutdown.notified() => return,
            result = listener.accept() => {
                let Ok((stream, _)) = result else { return };
                let state = Arc::clone(&state);
                tokio::spawn(async move { serve_connection(stream, state, false).await });
            }
        }
    }
}

async fn serve_connection<S>(mut stream: S, state: Arc<LocalControlState>, tcp: bool)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Ok(_permit) = Arc::clone(&state.connection_limit).acquire_owned().await else {
        return;
    };
    let response = match timeout(TokioDuration::from_secs(5), read_request(&mut stream)).await {
        Ok(Ok(request)) => dispatch(request, &state, tcp).await,
        Ok(Err(error)) => error_response(400, "invalid_request", error),
        Err(_) => error_response(408, "request_timeout", "request timed out".to_owned()),
    };
    let _ = write_response(&mut stream, response).await;
}

#[derive(Debug)]
struct HttpRequest {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

async fn read_request<S>(stream: &mut S) -> Result<HttpRequest, String>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::with_capacity(4096);
    let header_end = loop {
        let mut chunk = [0u8; 4096];
        let length = stream
            .read(&mut chunk)
            .await
            .map_err(|error| error.to_string())?;
        if length == 0 {
            return Err("connection closed before request headers".to_owned());
        }
        bytes.extend_from_slice(&chunk[..length]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("request is too large".to_owned());
        }
        if let Some(position) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let header_text = std::str::from_utf8(&bytes[..header_end - 4])
        .map_err(|_| "request headers are not UTF-8".to_owned())?;
    let mut lines = header_text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "missing request line".to_owned())?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| "missing HTTP method".to_owned())?
        .to_owned();
    let path = request_parts
        .next()
        .ok_or_else(|| "missing request path".to_owned())?
        .to_owned();
    if request_parts.next() != Some("HTTP/1.1") {
        return Err("only HTTP/1.1 is supported".to_owned());
    }
    let mut headers = HashMap::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "malformed HTTP header".to_owned())?;
        headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
    }
    if headers
        .get("transfer-encoding")
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err("chunked request bodies are not supported".to_owned());
    }
    let content_length = headers.get("content-length").map_or(Ok(0), |value| {
        value
            .parse::<usize>()
            .map_err(|_| "invalid content length".to_owned())
    })?;
    if content_length > MAX_REQUEST_BYTES || header_end + content_length > MAX_REQUEST_BYTES {
        return Err("request body is too large".to_owned());
    }
    while bytes.len() < header_end + content_length {
        let mut chunk = [0u8; 4096];
        let length = stream
            .read(&mut chunk)
            .await
            .map_err(|error| error.to_string())?;
        if length == 0 {
            return Err("connection closed before request body".to_owned());
        }
        bytes.extend_from_slice(&chunk[..length]);
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err("request is too large".to_owned());
        }
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: bytes[header_end..header_end + content_length].to_vec(),
    })
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
    content_type: &'static str,
}

async fn write_response<S>(stream: &mut S, response: HttpResponse) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Error",
    };
    let headers = format!(
        "HTTP/1.1 {} {reason}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len()
    );
    stream.write_all(headers.as_bytes()).await?;
    stream.write_all(&response.body).await
}

async fn dispatch(request: HttpRequest, state: &LocalControlState, tcp: bool) -> HttpResponse {
    let is_dashboard = request.path == "/" || request.path == "/api/v1/dashboard";
    if tcp && !is_dashboard && !authorized(&request, state.tcp_token.as_deref()) {
        return error_response(
            401,
            "unauthorized",
            "local control token is required".to_owned(),
        );
    }
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => HttpResponse {
            status: 200,
            body: include_bytes!("dashboard.html").to_vec(),
            content_type: "text/html; charset=utf-8",
        },
        ("GET", "/api/v1/dashboard") | ("GET", "/local/v1/runtime") => {
            json_response(200, state.store.dashboard().await)
        }
        ("GET", "/local/v1/status") => json_response(200, state.store.status().await),
        ("GET", "/local/v1/peers") => json_response(200, state.store.peers().await),
        ("POST", "/local/v1/ping") => handle_ping(request.body, state).await,
        _ => error_response(
            404,
            "not_found",
            "local control endpoint was not found".to_owned(),
        ),
    }
}

fn authorized(request: &HttpRequest, token: Option<&str>) -> bool {
    let Some(token) = token else { return false };
    request
        .headers
        .get("authorization")
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|value| value == token)
}

async fn handle_ping(body: Vec<u8>, state: &LocalControlState) -> HttpResponse {
    let request: PingRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => return error_response(400, "invalid_json", error.to_string()),
    };
    let (reply, result) = oneshot::channel();
    if state
        .commands
        .send(RuntimeCommand::Ping {
            target: request.target,
            count: request.count,
            timeout: Duration::from_millis(request.timeout_ms),
            reply,
        })
        .await
        .is_err()
    {
        return error_response(
            503,
            "service_unavailable",
            "peer runtime has stopped".to_owned(),
        );
    }
    match result.await {
        Ok(Ok(report)) => json_response(200, report),
        Ok(Err(error)) => diagnostic_error_response(error),
        Err(_) => error_response(
            503,
            "service_unavailable",
            "peer runtime has stopped".to_owned(),
        ),
    }
}

#[derive(Deserialize)]
struct PingRequest {
    target: NodeId,
    count: usize,
    timeout_ms: u64,
}

fn json_response<T: Serialize>(status: u16, value: T) -> HttpResponse {
    match serde_json::to_vec(&value) {
        Ok(body) => HttpResponse {
            status,
            body,
            content_type: "application/json",
        },
        Err(error) => error_response(500, "serialization_error", error.to_string()),
    }
}

fn error_response(status: u16, code: &str, message: String) -> HttpResponse {
    json_response(
        status,
        serde_json::json!({"error": {"code": code, "message": message}}),
    )
}

fn diagnostic_error_response(error: DiagnosticError) -> HttpResponse {
    let (status, code) = match &error {
        DiagnosticError::InvalidPingRequest(_) => (400, "invalid_ping_request"),
        DiagnosticError::ServiceUnavailable => (503, "service_unavailable"),
        DiagnosticError::Connect(crate::ConnectError::Timeout)
        | DiagnosticError::Ping(crate::DiagnosticPingError::Timeout) => (504, "timeout"),
        DiagnosticError::Connect(crate::ConnectError::UnknownPeer)
        | DiagnosticError::Ping(crate::DiagnosticPingError::UnknownPeer) => (404, "unknown_peer"),
        DiagnosticError::Ping(crate::DiagnosticPingError::NotConnected) => (409, "not_connected"),
        _ => (502, "runtime_error"),
    };
    error_response(status, code, error.to_string())
}

pub struct LocalControlClient {
    #[cfg(unix)]
    socket_path: PathBuf,
    #[cfg(not(unix))]
    address: SocketAddr,
    token: Option<String>,
}

impl LocalControlClient {
    pub async fn open(state_dir: impl AsRef<Path>) -> Result<Self, DiagnosticError> {
        let state_dir = state_dir.as_ref();
        #[cfg(unix)]
        {
            Ok(Self {
                socket_path: state_dir.join(CONTROL_SOCKET),
                token: None,
            })
        }
        #[cfg(not(unix))]
        {
            let endpoint = read_endpoint(state_dir)?;
            if endpoint.version != CONTROL_VERSION {
                return Err(DiagnosticError::ControlProtocol(format!(
                    "unsupported control protocol version {}",
                    endpoint.version
                )));
            }
            let address = endpoint.address.ok_or_else(|| {
                DiagnosticError::ControlProtocol("control endpoint has no address".to_owned())
            })?;
            if !matches!(endpoint.transport, ControlTransport::Tcp) {
                return Err(DiagnosticError::ControlProtocol(
                    "unsupported control transport".to_owned(),
                ));
            }
            Ok(Self {
                address,
                token: endpoint.token,
            })
        }
    }

    pub async fn status(&self) -> Result<PeerStatus, DiagnosticError> {
        self.get("/local/v1/status").await
    }

    pub async fn peers(&self) -> Result<Vec<PeerSummary>, DiagnosticError> {
        self.get("/local/v1/peers").await
    }

    pub async fn runtime(&self) -> Result<DashboardSnapshot, DiagnosticError> {
        self.get("/local/v1/runtime").await
    }

    pub async fn ping(
        &self,
        target: NodeId,
        count: usize,
        timeout: Duration,
    ) -> Result<PingReport, DiagnosticError> {
        self.post(
            "/local/v1/ping",
            &serde_json::json!({
                "target": target,
                "count": count,
                "timeout_ms": timeout.as_millis().min(u128::from(u64::MAX)) as u64,
            }),
        )
        .await
    }

    async fn get<T: for<'de> Deserialize<'de>>(&self, path: &str) -> Result<T, DiagnosticError> {
        self.request("GET", path, &[]).await
    }

    async fn post<T: for<'de> Deserialize<'de>, V: Serialize>(
        &self,
        path: &str,
        value: &V,
    ) -> Result<T, DiagnosticError> {
        let body = serde_json::to_vec(value)?;
        self.request("POST", path, &body).await
    }

    async fn request<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<T, DiagnosticError> {
        #[cfg(unix)]
        {
            let stream = UnixStream::connect(&self.socket_path)
                .await
                .map_err(|_| DiagnosticError::ServiceUnavailable)?;
            return request_stream(stream, method, path, body, self.token.as_deref()).await;
        }
        #[cfg(not(unix))]
        {
            let stream = TcpStream::connect(self.address)
                .await
                .map_err(|_| DiagnosticError::ServiceUnavailable)?;
            request_stream(stream, method, path, body, self.token.as_deref()).await
        }
    }
}

async fn request_stream<S, T>(
    mut stream: S,
    method: &str,
    path: &str,
    body: &[u8],
    token: Option<&str>,
) -> Result<T, DiagnosticError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let authorization = token
        .map(|token| format!("Authorization: Bearer {token}\r\n"))
        .unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Length: {}\r\n{authorization}\r\n",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;
    let response = timeout(TokioDuration::from_secs(65), read_response(&mut stream))
        .await
        .map_err(|_| DiagnosticError::ControlProtocol("control response timed out".to_owned()))??;
    if response.status >= 400 {
        let error: ControlError = serde_json::from_slice(&response.body)
            .map_err(|_| DiagnosticError::ControlProtocol("invalid error response".to_owned()))?;
        return Err(DiagnosticError::ControlRequest {
            code: error
                .error
                .get("code")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("remote_error")
                .to_owned(),
            message: error
                .error
                .get("message")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("local control request failed")
                .to_owned(),
        });
    }
    serde_json::from_slice(&response.body).map_err(DiagnosticError::Serialization)
}

struct HttpResponseBody {
    status: u16,
    body: Vec<u8>,
}

async fn read_response<S>(stream: &mut S) -> Result<HttpResponseBody, DiagnosticError>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let mut chunk = [0u8; 8192];
        let length = stream.read(&mut chunk).await?;
        if length == 0 {
            break;
        }
        if bytes.len().saturating_add(length) > MAX_RESPONSE_BYTES {
            return Err(DiagnosticError::ControlProtocol(
                "response is too large".to_owned(),
            ));
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
        .ok_or_else(|| DiagnosticError::ControlProtocol("malformed HTTP response".to_owned()))?;
    let header_text = std::str::from_utf8(&bytes[..header_end - 4]).map_err(|_| {
        DiagnosticError::ControlProtocol("response headers are not UTF-8".to_owned())
    })?;
    let mut lines = header_text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| DiagnosticError::ControlProtocol("missing HTTP status".to_owned()))?;
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .ok_or_else(|| DiagnosticError::ControlProtocol("missing response length".to_owned()))?;
    if content_length > MAX_RESPONSE_BYTES {
        return Err(DiagnosticError::ControlProtocol(
            "response body is too large".to_owned(),
        ));
    }
    let body_end = header_end.checked_add(content_length).ok_or_else(|| {
        DiagnosticError::ControlProtocol("response body length overflow".to_owned())
    })?;
    if bytes.len() < body_end {
        return Err(DiagnosticError::ControlProtocol(
            "truncated HTTP response".to_owned(),
        ));
    }
    Ok(HttpResponseBody {
        status,
        body: bytes[header_end..body_end].to_vec(),
    })
}

#[derive(Deserialize)]
struct ControlError {
    error: serde_json::Map<String, serde_json::Value>,
}

#[cfg(not(unix))]
fn read_endpoint(state_dir: &Path) -> Result<ControlEndpoint, DiagnosticError> {
    let bytes = fs::read(state_dir.join(CONTROL_FILE)).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            DiagnosticError::ServiceUnavailable
        } else {
            DiagnosticError::Io(error)
        }
    })?;
    serde_json::from_slice(&bytes).map_err(DiagnosticError::Serialization)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn request_parser_accepts_body_split_across_reads() {
        let (mut client, mut server) = duplex(4096);
        let parser = tokio::spawn(async move { read_request(&mut server).await });
        client
            .write_all(
                b"POST /local/v1/ping HTTP/1.1\r\nHost: localhost\r\nContent-Length: 7\r\n\r\n{\"x\":1}",
            )
            .await
            .unwrap();
        let request = parser.await.unwrap().unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/local/v1/ping");
        assert_eq!(request.body, b"{\"x\":1}");
    }

    #[tokio::test]
    async fn request_parser_rejects_chunked_encoding() {
        let (mut client, mut server) = duplex(1024);
        let parser = tokio::spawn(async move { read_request(&mut server).await });
        client
            .write_all(
                b"POST /local/v1/ping HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n",
            )
            .await
            .unwrap();
        let error = parser.await.unwrap().unwrap_err();
        assert!(error.contains("chunked"));
    }

    #[test]
    fn state_lock_allows_only_one_owner() {
        let state_dir = std::env::temp_dir().join(format!(
            "vela-control-lock-{}-{}",
            std::process::id(),
            random_token()
        ));
        let first = StateLock::acquire(&state_dir).unwrap();
        assert!(matches!(
            StateLock::acquire(&state_dir),
            Err(DiagnosticError::AlreadyRunning)
        ));
        drop(first);
        fs::remove_dir_all(state_dir).unwrap();
    }
}
