// PATCH(tk-link): C ABI for connection handoff.
//
// The handoff API is ours, not upstream's, so it is not in `include/quiche.h`.
// This module is its C surface, shipped alongside upstream's `ffi` module and
// enabled by the same `ffi` feature. The header lives at
// `include/tklink_handoff.h` and is what `sdk/go/quic` binds to.
//
// Conventions follow upstream's `ffi.rs` exactly, because a caller linking one
// library should not have to hold two mental models:
//
//   * a returned `*mut Connection` is owned by the caller and freed with
//     `quiche_conn_free`; NULL means failure;
//   * an `int` return is 0 on success and a negative `quiche::Error` code
//     otherwise;
//   * addresses cross as `sockaddr_storage` plus a length.
//
// One thing is deliberately NOT exposed: export. A backend adopts connections
// and never hands one on, so `handoff_export` has no business being reachable
// from C — and the snapshot it produces carries 1-RTT traffic secrets.
//
// Nothing else is added either. Advertising a supplied connection ID and asking
// how many more the peer will take are `quiche_conn_new_scid` and
// `quiche_conn_scids_left`, which upstream already exports; a backend uses those
// unchanged.

use std::ptr;
use std::slice;

use libc::c_int;
use libc::size_t;
use libc::sockaddr_storage;
use libc::socklen_t;

use crate::handoff;
use crate::Config;
use crate::Connection;

/// Continues a connection the backbone handshook.
///
/// `snapshot` is the `HANDOFF` frame's snapshot field, verbatim. The returned
/// connection is established and serving: it holds the client's keys, its
/// connection IDs and its packet number state.
///
/// `config` needs **no certificate and no private key** — the handshake is
/// over, and authorization happened at the edge before the connection was
/// handed over. It supplies only what the handshake did not fix: congestion
/// control, buffer sizing, PMTUD.
///
/// Returns NULL if the snapshot is malformed, truncated, or from a wire version
/// this build does not know.
#[no_mangle]
pub extern "C" fn quiche_handoff_accept(
    snapshot: *const u8, snapshot_len: size_t, config: &mut Config,
) -> *mut Connection {
    let bytes = unsafe { slice::from_raw_parts(snapshot, snapshot_len) };

    let state = match handoff::HandoffState::from_bytes(bytes) {
        Ok(state) => state,
        Err(_) => return ptr::null_mut(),
    };

    match handoff::accept_handoff(&state, config) {
        Ok(conn) => Box::into_raw(Box::new(conn)),
        Err(_) => ptr::null_mut(),
    }
}

/// Reads the addresses out of a snapshot without importing it.
///
/// A backend needs `local` — the address the client is sending to — to tell its
/// QUIC stack where an inbound packet arrived, and getting that wrong makes
/// every packet look like it landed on an unknown path. It is in the snapshot
/// rather than inferred from the socket because the backend's own socket
/// address has nothing to do with the VIP the client is addressing.
///
/// Either pair of out-params may be NULL if the caller does not want it.
/// Returns 0 on success, or a negative error code.
#[no_mangle]
pub extern "C" fn quiche_handoff_peek_addrs(
    snapshot: *const u8, snapshot_len: size_t, local: *mut sockaddr_storage,
    local_len: *mut socklen_t, peer: *mut sockaddr_storage,
    peer_len: *mut socklen_t,
) -> c_int {
    let bytes = unsafe { slice::from_raw_parts(snapshot, snapshot_len) };

    let state = match handoff::HandoffState::from_bytes(bytes) {
        Ok(state) => state,
        Err(e) => return e.to_c() as c_int,
    };

    if !local.is_null() && !local_len.is_null() {
        unsafe {
            *local_len = crate::ffi::std_addr_to_c(&state.local_addr, &mut *local);
        }
    }

    if !peer.is_null() && !peer_len.is_null() {
        unsafe {
            *peer_len = crate::ffi::std_addr_to_c(&state.peer_addr, &mut *peer);
        }
    }

    0
}

/// Copies the snapshot's opaque application blob into `out`.
///
/// For tk-link this is the verified client identity — the same PROXY v2 `0xE0`
/// TLV value the TCP tunnel path carries. Writes at most `out_len` bytes and
/// returns how many the blob actually has, so a caller can size a buffer by
/// calling once with a NULL `out`.
///
/// Returns a negative error code if the snapshot cannot be read.
#[no_mangle]
pub extern "C" fn quiche_handoff_peek_app_data(
    snapshot: *const u8, snapshot_len: size_t, out: *mut u8, out_len: size_t,
) -> isize {
    let bytes = unsafe { slice::from_raw_parts(snapshot, snapshot_len) };

    let state = match handoff::HandoffState::from_bytes(bytes) {
        Ok(state) => state,
        Err(e) => return e.to_c() as isize,
    };

    let app = &state.app_data;

    if !out.is_null() && out_len > 0 {
        let n = std::cmp::min(out_len, app.len());
        unsafe {
            ptr::copy_nonoverlapping(app.as_ptr(), out, n);
        }
    }

    app.len() as isize
}

/// The wire version of the snapshot format this build produces and accepts.
///
/// A backend can refuse a snapshot it will not understand rather than
/// discovering it inside `quiche_handoff_accept`.
#[no_mangle]
pub extern "C" fn quiche_handoff_version() -> u16 {
    handoff::WIRE_VERSION
}

/// Reads the server endpoint authenticated by the original handshake, if any.
#[no_mangle]
pub extern "C" fn quiche_handoff_preferred_addr(
    conn: &Connection, out: &mut sockaddr_storage, out_len: &mut socklen_t,
) -> c_int {
    let Some(p) = &conn.local_transport_params.preferred_address else { return -1; };
    let addr = if p.ipv4.port() != 0 {
        std::net::SocketAddr::V4(p.ipv4)
    } else {
        std::net::SocketAddr::V6(p.ipv6)
    };
    *out_len = crate::ffi::std_addr_to_c(&addr, out);
    0
}
