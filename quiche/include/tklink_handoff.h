/* PATCH(tk-link): C ABI for QUIC connection handoff.
 *
 * Companion to quiche.h, shipped by the same `ffi` feature and linked from the
 * same library. It declares only what upstream does not: adopting a connection
 * another host handshook.
 *
 * See docs/QUIC_HANDOFF.md. The Go binding is sdk/go/quic.
 *
 * NOT declared here, deliberately:
 *
 *   - Export. A backend adopts connections and never hands one on, and the
 *     snapshot export produces carries the connection's 1-RTT traffic secrets.
 *
 *   - Connection-ID helpers. Advertising a supplied CID is
 *     quiche_conn_new_scid() and asking how many more the peer will accept is
 *     quiche_conn_scids_left(), both already in quiche.h. A backend uses those
 *     unchanged — and MUST NOT generate its own CIDs (see below).
 */

#ifndef TKLINK_HANDOFF_H
#define TKLINK_HANDOFF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>

#include "quiche.h"

#if defined(__cplusplus)
extern "C" {
#endif

/* The snapshot wire version this build produces and accepts.
 *
 * A backend can compare this against what it was built for and refuse a
 * snapshot it will not understand, rather than discovering that inside
 * quiche_handoff_accept(). */
uint16_t quiche_handoff_version(void);

/* Advertised preferred server endpoint; negative when absent. */
int quiche_handoff_preferred_addr(const quiche_conn *conn,
    struct sockaddr_storage *out, socklen_t *out_len);

/* Continues a connection the backbone handshook.
 *
 * `snapshot` is the HANDOFF frame's snapshot field, verbatim. The returned
 * connection is established and serving: it holds the client's keys, its
 * connection IDs and its packet number state. Free it with quiche_conn_free().
 *
 * `config` needs NO certificate and NO private key. The handshake is over, and
 * authorization happened at the edge before the connection was handed over.
 * The config supplies only what the handshake did not fix — congestion control,
 * buffer sizing, PMTUD. Transport parameters come from the snapshot, never from
 * the config, because the client has already been told what they are.
 *
 * Returns NULL if the snapshot is malformed, truncated, or from a wire version
 * this build does not know.
 *
 * After adopting, install every connection ID that arrived in the HANDOFF frame
 * with quiche_conn_new_scid(). A backend MUST NOT generate its own: a
 * self-generated CID does not decrypt to a flow, so the backbone cannot route
 * it and the client would be sending into a black hole. */
quiche_conn *quiche_handoff_accept(const uint8_t *snapshot, size_t snapshot_len,
                                   quiche_config *config);

/* Reads a snapshot's addresses without importing it.
 *
 * `local` is the address the client is sending to — the fleet VIP. A backend
 * needs it to tell quiche_conn_recv() where an inbound packet arrived; the
 * backend's own socket address is unrelated and using it makes every packet
 * look like it landed on an unknown path.
 *
 * Either pair of out-params may be NULL. Returns 0 on success, or a negative
 * quiche error code. */
int quiche_handoff_peek_addrs(const uint8_t *snapshot, size_t snapshot_len,
                              struct sockaddr_storage *local,
                              socklen_t *local_len,
                              struct sockaddr_storage *peer,
                              socklen_t *peer_len);

/* Copies the snapshot's opaque application blob into `out`.
 *
 * For tk-link this is the verified client identity: the same PROXY v2 0xE0 TLV
 * value the TCP tunnel path carries, so a backend parses one format for both
 * transports.
 *
 * Writes at most `out_len` bytes and returns the blob's true length, so a
 * caller can size a buffer by calling once with `out` NULL. Returns a negative
 * quiche error code if the snapshot cannot be read.
 *
 * The identity also arrives in the HANDOFF frame itself, which is where a
 * backend normally reads it; this exists so the two can be cross-checked, and
 * for a backend that receives a snapshot by some other route. */
ssize_t quiche_handoff_peek_app_data(const uint8_t *snapshot,
                                     size_t snapshot_len, uint8_t *out,
                                     size_t out_len);

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* TKLINK_HANDOFF_H */
