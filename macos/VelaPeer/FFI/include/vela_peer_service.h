#ifndef VELA_PEER_SERVICE_H
#define VELA_PEER_SERVICE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns JSON with base64 `signing_private` and `noise_private` values. */
char *vela_identity_generate(void);

/* Builds a new PeerConfig from a Coordinator URL and base64 public key. */
char *vela_peer_config_create(const uint8_t *server,
                              size_t server_length,
                              const uint8_t *server_key_base64,
                              size_t server_key_length,
                              char **error_output);

/*
 * Registers a peer using a JSON PeerConfig and 64 bytes of private keys
 * (signing key first, Noise key second). Returns JSON with `config` and
 * `credential`, or NULL and a caller-owned error string.
 */
char *vela_peer_register(const uint8_t *config_json,
                         size_t config_json_length,
                         const uint8_t *identity_bytes,
                         size_t identity_length,
                         const uint8_t *invite,
                         size_t invite_length,
                         uint16_t port,
                         char **error_output);

/*
 * Starts a root-owned peer service from a JSON request containing `state_dir`,
 * `peer`, `secrets`, `port`, `mtu`, and `tun_name`. The secrets object contains
 * base64 `signing_private`, `noise_private`, and serialized `credential`.
 */
void *vela_peer_service_start(const uint8_t *request_json,
                              size_t request_length,
                              char **error_output);

/* Returns service state, latest dashboard snapshot, and credential as JSON. */
char *vela_peer_service_status(const void *handle);

/* Stops the peer, waits for route cleanup, and frees the handle. */
char *vela_peer_service_stop(void *handle);

/* Frees any string returned by this API. */
void vela_string_free(char *value);

#ifdef __cplusplus
}
#endif

#endif /* VELA_PEER_SERVICE_H */
