// PATCH(tk-link): QUIC connection handoff.
//
// This whole module is a tk-link addition. It is deliberately a child module of
// the crate root so it can read and write `Connection`'s private state without
// widening anything in lib.rs; the handful of accessors it needs on `crypto`,
// `packet`, `cid` and `stream` (which are separate modules) are marked
// `PATCH(tk-link)` at their definitions.
//
//! Exporting an established server connection so another host can continue it.
//!
//! tk-link terminates a client's QUIC handshake at the edge — where the client
//! certificate is verified and authorization is decided — and then hands the
//! established connection to the backend that will actually serve it. The
//! backend continues the *same* QUIC connection: same keys, same connection
//! IDs, same packet number space. The client is a stock, unmodified QUIC
//! implementation and observes nothing at all.
//!
//! # The quiescent boundary
//!
//! A handoff is only attempted at a point where the server side of the
//! connection has no work outstanding, which is what keeps the exported state
//! small enough to be obviously correct:
//!
//! * the handshake is confirmed **and** our HANDSHAKE_DONE has been acked, so
//!   no handshake-epoch frame can still need retransmitting;
//! * nothing is in flight and nothing is pending advertisement, so there is no
//!   loss-recovery or congestion state worth moving — a fresh path re-measures
//!   RTT from the first exchange;
//! * we have never created an HTTP/3 layer, opened a stream, or sent
//!   stream/flow-control frames, so all send-side state is at its initial
//!   values and is rebuilt from the transport parameters on import.
//!
//! What is *not* assumed is that the client has been silent. A stock HTTP/3
//! client sends its control stream, SETTINGS and QPACK streams — often a whole
//! request — in the same flight as its handshake Finished, and those packets
//! are acked by the exporting side before any of this code runs. Discarding
//! them would lose data the client will never retransmit, so the snapshot
//! carries every client-opened stream's buffered bytes and the connection-level
//! receive accounting that goes with them. [`Connection::handoff_ready`]
//! refuses to export while any of those streams has a gap, so the replay on the
//! importing side is always a contiguous write from offset 0.
//!
//! # Single writer
//!
//! [`Connection::handoff_export`] consumes the connection: it marks it closed
//! before returning, so the exporting host physically cannot emit another
//! packet on a connection the importing host now owns. Two writers on one
//! packet number space would reuse an AEAD nonce, which is a far worse failure
//! than a dropped connection.

use std::net::SocketAddr;

use crate::cid;
use crate::crypto;
use crate::packet;
use crate::range_buf::RangeBuf;
use crate::recovery::RecoveryOps;
use crate::Config;
use crate::Connection;
use crate::ConnectionId;
use crate::Error;
use crate::Result;
use crate::TransportParams;

/// Magic prefix of a serialized [`HandoffState`].
const HANDOFF_MAGIC: &[u8; 4] = b"TKH0";

/// Wire version of the serialized form. Bumped on any layout change; the
/// decoder refuses anything it does not recognise rather than guessing.
const HANDOFF_VERSION: u16 = 1;

/// Wire version of the serialized snapshot format.
///
// PATCH(tk-link): exposed so the C ABI can report it (`quiche_handoff_version`)
// and a backend can refuse a snapshot it will not understand, rather than
// discovering that inside the importer.
pub const WIRE_VERSION: u16 = HANDOFF_VERSION;

/// Upper bound on a serialized snapshot. The only elastic parts are the
/// client-opened streams and the opaque application blob; everything else is a
/// few hundred bytes. A client that has buffered more than this before the
/// handshake is even confirmed is not one we want to hand off.
pub const MAX_HANDOFF_BYTES: usize = 64 * 1024;

/// One connection ID with the metadata its peer already knows about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffCid {
    /// The connection ID itself.
    pub cid: Vec<u8>,

    /// Its sequence number, as advertised to (or received from) the peer.
    pub seq: u64,

    /// Its stateless reset token, if it has one.
    pub reset_token: Option<u128>,
}

/// A stream the client opened before the handoff, with the bytes it sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffStream {
    /// Stream ID.
    pub id: u64,

    /// Contiguous data received from offset 0 and not yet read by any
    /// application (the exporting side never reads).
    pub data: Vec<u8>,

    /// Whether the peer finished the stream.
    pub fin: bool,
}

/// An established server connection, in a form another host can continue.
#[derive(Debug, Clone, PartialEq)]
pub struct HandoffState {
    /// QUIC wire version.
    pub version: u32,

    /// Negotiated ALPN protocol.
    pub alpn: Vec<u8>,

    /// AEAD algorithm of the 1-RTT keys.
    pub aead: u8,

    /// Client's 1-RTT traffic secret (what the server opens with).
    pub open_secret: Vec<u8>,

    /// Server's 1-RTT traffic secret (what the server seals with).
    pub seal_secret: Vec<u8>,

    /// Key phase bit for outgoing packets.
    pub key_phase: bool,

    /// Our transport parameters, exactly as the client received them.
    pub local_transport_params: Vec<u8>,

    /// The client's transport parameters.
    pub peer_transport_params: Vec<u8>,

    /// Next packet number to use.
    pub next_pkt_num: u64,

    /// Largest packet number we sent in the Application space, if any. Kept so
    /// the importing side still rejects an ACK for a packet nobody sent.
    pub largest_tx_pkt_num: Option<u64>,

    /// Largest packet number received in the Application space.
    pub largest_rx_pkt_num: u64,

    /// Largest non-probing packet number received in the Application space.
    pub largest_rx_non_probing_pkt_num: u64,

    /// Packet numbers still needing an ACK, as `[start, end)` pairs.
    pub recv_pkt_need_ack: Vec<(u64, u64)>,

    /// Replay-detection window: `(lower, bitmap)`.
    pub recv_pkt_num_window: (u64, u128),

    /// Connection IDs we issued; these are the client's valid destinations.
    pub scids: Vec<HandoffCid>,

    /// Connection IDs the client issued; the importing side sends to these.
    pub dcids: Vec<HandoffCid>,

    /// Sequence number of the SCID the client is currently sending to.
    pub active_scid_seq: Option<u64>,

    /// Sequence number of the DCID we are currently sending to.
    pub active_dcid_seq: Option<u64>,

    /// Next source connection ID sequence number to hand out.
    pub next_scid_seq: u64,

    /// "Retire prior to" we advertise.
    pub retire_prior_to: u64,

    /// Largest "retire prior to" the client sent us.
    pub largest_peer_retire_prior_to: u64,

    /// Largest connection ID sequence number the client sent us.
    pub largest_destination_seq: u64,

    /// Maximum number of source connection IDs the client allows us.
    pub source_conn_id_limit: u64,

    /// Whether the client uses a zero-length connection ID.
    pub zero_length_dcid: bool,

    /// Local address the client is sending to (our VIP).
    pub local_addr: SocketAddr,

    /// The client's address.
    pub peer_addr: SocketAddr,

    /// Connection-level send limit the client granted us. Starts at the
    /// client's `initial_max_data` but a MAX_DATA frame may have raised it.
    pub max_tx_data: u64,

    /// Current bidirectional stream limit the client granted us.
    pub peer_max_streams_bidi: u64,

    /// Current unidirectional stream limit the client granted us.
    pub peer_max_streams_uni: u64,

    /// Total bytes received from the client, for connection-level flow control.
    pub rx_data: u64,

    /// Streams the client opened before the handoff.
    pub streams: Vec<HandoffStream>,

    /// Packets received so far. Transferred because quiche closes a server
    /// connection on the first undecryptable packet when nothing has been
    /// received yet, and an imported connection's first datagram may well be a
    /// stray.
    pub recv_count: u64,

    /// Packets sent so far (statistics continuity only).
    pub sent_count: u64,

    /// Opaque application data, carried verbatim. tk-link puts the verified
    /// client identity here, which is what replaces the PROXY protocol TLV the
    /// TCP tunnel path uses.
    pub app_data: Vec<u8>,
}

// -------------------------------------------------------------------------
// Wire codec
// -------------------------------------------------------------------------

fn put_u8(out: &mut Vec<u8>, v: u8) {
    out.push(v);
}

fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u128(out: &mut Vec<u8>, v: u128) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_bool(out: &mut Vec<u8>, v: bool) {
    out.push(u8::from(v));
}

fn put_opt_u64(out: &mut Vec<u8>, v: Option<u64>) {
    match v {
        Some(v) => {
            put_bool(out, true);
            put_u64(out, v);
        },
        None => put_bool(out, false),
    }
}

fn put_bytes16(out: &mut Vec<u8>, v: &[u8]) -> Result<()> {
    let len = u16::try_from(v.len()).map_err(|_| Error::BufferTooShort)?;
    put_u16(out, len);
    out.extend_from_slice(v);
    Ok(())
}

fn put_bytes32(out: &mut Vec<u8>, v: &[u8]) -> Result<()> {
    let len = u32::try_from(v.len()).map_err(|_| Error::BufferTooShort)?;
    put_u32(out, len);
    out.extend_from_slice(v);
    Ok(())
}

fn put_addr(out: &mut Vec<u8>, addr: &SocketAddr) {
    match addr {
        SocketAddr::V4(a) => {
            put_u8(out, 4);
            out.extend_from_slice(&a.ip().octets());
        },
        SocketAddr::V6(a) => {
            put_u8(out, 6);
            out.extend_from_slice(&a.ip().octets());
        },
    }
    put_u16(out, addr.port());
}

/// Cursor over a serialized snapshot. Every read is bounds-checked and a short
/// buffer is an error rather than a panic — this data arrives over a network.
struct Cursor<'a> {
    buf: &'a [u8],
    off: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, off: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.off.checked_add(n).ok_or(Error::BufferTooShort)?;
        if end > self.buf.len() {
            return Err(Error::BufferTooShort);
        }
        let out = &self.buf[self.off..end];
        self.off = end;
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn u128(&mut self) -> Result<u128> {
        Ok(u128::from_be_bytes(self.take(16)?.try_into().unwrap()))
    }

    fn bool(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidState),
        }
    }

    fn opt_u64(&mut self) -> Result<Option<u64>> {
        if self.bool()? {
            Ok(Some(self.u64()?))
        } else {
            Ok(None)
        }
    }

    fn bytes16(&mut self) -> Result<Vec<u8>> {
        let len = self.u16()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn bytes32(&mut self) -> Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }

    fn addr(&mut self) -> Result<SocketAddr> {
        let addr = match self.u8()? {
            4 => {
                let o: [u8; 4] = self.take(4)?.try_into().unwrap();
                std::net::IpAddr::from(o)
            },
            6 => {
                let o: [u8; 16] = self.take(16)?.try_into().unwrap();
                std::net::IpAddr::from(o)
            },
            _ => return Err(Error::InvalidState),
        };
        let port = self.u16()?;
        Ok(SocketAddr::new(addr, port))
    }

    fn finish(&self) -> Result<()> {
        // Trailing bytes mean the peer serialized something we do not
        // understand. Refuse rather than silently ignore it.
        if self.off == self.buf.len() {
            Ok(())
        } else {
            Err(Error::InvalidState)
        }
    }
}

fn aead_to_u8(alg: crypto::Algorithm) -> u8 {
    match alg {
        crypto::Algorithm::AES128_GCM => 1,
        crypto::Algorithm::AES256_GCM => 2,
        crypto::Algorithm::ChaCha20_Poly1305 => 3,
    }
}

fn aead_from_u8(v: u8) -> Result<crypto::Algorithm> {
    match v {
        1 => Ok(crypto::Algorithm::AES128_GCM),
        2 => Ok(crypto::Algorithm::AES256_GCM),
        3 => Ok(crypto::Algorithm::ChaCha20_Poly1305),
        _ => Err(Error::InvalidState),
    }
}

impl HandoffState {
    /// Serializes the snapshot.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(512);

        out.extend_from_slice(HANDOFF_MAGIC);
        put_u16(&mut out, HANDOFF_VERSION);

        put_u32(&mut out, self.version);
        put_bytes16(&mut out, &self.alpn)?;
        put_u8(&mut out, self.aead);
        put_bytes16(&mut out, &self.open_secret)?;
        put_bytes16(&mut out, &self.seal_secret)?;
        put_bool(&mut out, self.key_phase);

        put_bytes16(&mut out, &self.local_transport_params)?;
        put_bytes16(&mut out, &self.peer_transport_params)?;

        put_u64(&mut out, self.next_pkt_num);
        put_opt_u64(&mut out, self.largest_tx_pkt_num);
        put_u64(&mut out, self.largest_rx_pkt_num);
        put_u64(&mut out, self.largest_rx_non_probing_pkt_num);

        let ranges =
            u16::try_from(self.recv_pkt_need_ack.len()).map_err(|_| Error::BufferTooShort)?;
        put_u16(&mut out, ranges);
        for (start, end) in &self.recv_pkt_need_ack {
            put_u64(&mut out, *start);
            put_u64(&mut out, *end);
        }

        put_u64(&mut out, self.recv_pkt_num_window.0);
        put_u128(&mut out, self.recv_pkt_num_window.1);

        put_cids(&mut out, &self.scids)?;
        put_cids(&mut out, &self.dcids)?;

        put_opt_u64(&mut out, self.active_scid_seq);
        put_opt_u64(&mut out, self.active_dcid_seq);
        put_u64(&mut out, self.next_scid_seq);
        put_u64(&mut out, self.retire_prior_to);
        put_u64(&mut out, self.largest_peer_retire_prior_to);
        put_u64(&mut out, self.largest_destination_seq);
        put_u64(&mut out, self.source_conn_id_limit);
        put_bool(&mut out, self.zero_length_dcid);

        put_addr(&mut out, &self.local_addr);
        put_addr(&mut out, &self.peer_addr);

        put_u64(&mut out, self.max_tx_data);
        put_u64(&mut out, self.peer_max_streams_bidi);
        put_u64(&mut out, self.peer_max_streams_uni);
        put_u64(&mut out, self.rx_data);

        let streams =
            u16::try_from(self.streams.len()).map_err(|_| Error::BufferTooShort)?;
        put_u16(&mut out, streams);
        for s in &self.streams {
            put_u64(&mut out, s.id);
            put_bool(&mut out, s.fin);
            put_bytes32(&mut out, &s.data)?;
        }

        put_u64(&mut out, self.recv_count);
        put_u64(&mut out, self.sent_count);
        put_bytes32(&mut out, &self.app_data)?;

        if out.len() > MAX_HANDOFF_BYTES {
            return Err(Error::BufferTooShort);
        }

        Ok(out)
    }

    /// Parses a snapshot produced by [`HandoffState::to_bytes`].
    pub fn from_bytes(buf: &[u8]) -> Result<HandoffState> {
        if buf.len() > MAX_HANDOFF_BYTES {
            return Err(Error::BufferTooShort);
        }

        let mut b = Cursor::new(buf);

        if b.take(4)? != HANDOFF_MAGIC {
            return Err(Error::InvalidState);
        }

        if b.u16()? != HANDOFF_VERSION {
            return Err(Error::InvalidState);
        }

        let version = b.u32()?;
        let alpn = b.bytes16()?;
        let aead = b.u8()?;
        let open_secret = b.bytes16()?;
        let seal_secret = b.bytes16()?;
        let key_phase = b.bool()?;

        let local_transport_params = b.bytes16()?;
        let peer_transport_params = b.bytes16()?;

        let next_pkt_num = b.u64()?;
        let largest_tx_pkt_num = b.opt_u64()?;
        let largest_rx_pkt_num = b.u64()?;
        let largest_rx_non_probing_pkt_num = b.u64()?;

        let n = b.u16()? as usize;
        let mut recv_pkt_need_ack = Vec::with_capacity(n);
        for _ in 0..n {
            let start = b.u64()?;
            let end = b.u64()?;
            if end < start {
                return Err(Error::InvalidState);
            }
            recv_pkt_need_ack.push((start, end));
        }

        let recv_pkt_num_window = (b.u64()?, b.u128()?);

        let scids = get_cids(&mut b)?;
        let dcids = get_cids(&mut b)?;

        let active_scid_seq = b.opt_u64()?;
        let active_dcid_seq = b.opt_u64()?;
        let next_scid_seq = b.u64()?;
        let retire_prior_to = b.u64()?;
        let largest_peer_retire_prior_to = b.u64()?;
        let largest_destination_seq = b.u64()?;
        let source_conn_id_limit = b.u64()?;
        let zero_length_dcid = b.bool()?;

        let local_addr = b.addr()?;
        let peer_addr = b.addr()?;

        let max_tx_data = b.u64()?;
        let peer_max_streams_bidi = b.u64()?;
        let peer_max_streams_uni = b.u64()?;
        let rx_data = b.u64()?;

        let n = b.u16()? as usize;
        let mut streams = Vec::with_capacity(n);
        for _ in 0..n {
            let id = b.u64()?;
            let fin = b.bool()?;
            let data = b.bytes32()?;
            streams.push(HandoffStream { id, data, fin });
        }

        let recv_count = b.u64()?;
        let sent_count = b.u64()?;
        let app_data = b.bytes32()?;

        b.finish()?;

        if scids.is_empty() || dcids.is_empty() {
            return Err(Error::InvalidState);
        }

        Ok(HandoffState {
            version,
            alpn,
            aead,
            open_secret,
            seal_secret,
            key_phase,
            local_transport_params,
            peer_transport_params,
            next_pkt_num,
            largest_tx_pkt_num,
            largest_rx_pkt_num,
            largest_rx_non_probing_pkt_num,
            recv_pkt_need_ack,
            recv_pkt_num_window,
            scids,
            dcids,
            active_scid_seq,
            active_dcid_seq,
            next_scid_seq,
            retire_prior_to,
            largest_peer_retire_prior_to,
            largest_destination_seq,
            source_conn_id_limit,
            zero_length_dcid,
            local_addr,
            peer_addr,
            max_tx_data,
            peer_max_streams_bidi,
            peer_max_streams_uni,
            rx_data,
            streams,
            recv_count,
            sent_count,
            app_data,
        })
    }
}

fn put_cids(out: &mut Vec<u8>, cids: &[HandoffCid]) -> Result<()> {
    let n = u16::try_from(cids.len()).map_err(|_| Error::BufferTooShort)?;
    put_u16(out, n);
    for c in cids {
        let len = u8::try_from(c.cid.len()).map_err(|_| Error::BufferTooShort)?;
        put_u8(out, len);
        out.extend_from_slice(&c.cid);
        put_u64(out, c.seq);
        match c.reset_token {
            Some(t) => {
                put_bool(out, true);
                put_u128(out, t);
            },
            None => put_bool(out, false),
        }
    }
    Ok(())
}

fn get_cids(b: &mut Cursor) -> Result<Vec<HandoffCid>> {
    let n = b.u16()? as usize;
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let len = b.u8()? as usize;
        if len > crate::MAX_CONN_ID_LEN {
            return Err(Error::InvalidState);
        }
        let cid = b.take(len)?.to_vec();
        let seq = b.u64()?;
        let reset_token = if b.bool()? { Some(b.u128()?) } else { None };
        out.push(HandoffCid {
            cid,
            seq,
            reset_token,
        });
    }
    Ok(out)
}

// -------------------------------------------------------------------------
// Export
// -------------------------------------------------------------------------

/// Why a connection cannot be handed off (yet).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffBlocked {
    /// Not a server connection. Only the server side can be handed off.
    NotServer,

    /// The handshake has not completed, or the peer has not acked our
    /// HANDSHAKE_DONE. Exporting earlier would leave a handshake-epoch frame
    /// that nobody will retransmit.
    HandshakeNotConfirmed,

    /// The connection is closing, closed or already exported.
    Closing,

    /// We still owe the peer an ACK, or have connection IDs pending
    /// advertisement. Drive `send()` once more and retry.
    SendPending,

    /// Bytes are still in flight. Nothing may be unacknowledged at the
    /// boundary, because the importing side gets no loss-recovery state.
    BytesInFlight,

    /// A client-opened stream has a gap in its receive buffer. The missing
    /// packet is still in flight; retry after the client retransmits.
    StreamGap,

    /// The exporting side has already used the connection for application
    /// data. Handoff is only defined before any of that exists.
    ApplicationDataSent,
}

impl<F: crate::BufFactory> Connection<F> {
    /// Reports whether the connection is at a quiescent handoff boundary.
    ///
    /// See the module documentation for what each condition rules out.
    pub fn handoff_ready(&self) -> std::result::Result<(), HandoffBlocked> {
        if !self.is_server {
            return Err(HandoffBlocked::NotServer);
        }

        if self.closed || self.draining_timer.is_some() ||
            self.local_error.is_some() ||
            self.peer_error.is_some()
        {
            return Err(HandoffBlocked::Closing);
        }

        // `handshake_done_acked` is strictly stronger than
        // `handshake_confirmed`: it proves the client processed HANDSHAKE_DONE,
        // so we do not have to carry the obligation to resend it.
        if !self.handshake_completed || !self.handshake_confirmed ||
            !self.handshake_done_acked
        {
            return Err(HandoffBlocked::HandshakeNotConfirmed);
        }

        // We must never have written application data: the importing side
        // rebuilds all send-side state from the transport parameters.
        if self.tx_data > 0 || self.tx_buffered > 0 {
            return Err(HandoffBlocked::ApplicationDataSent);
        }

        if self.pkt_num_spaces[packet::Epoch::Application].ack_elicited ||
            self.ids.has_new_scids()
        {
            return Err(HandoffBlocked::SendPending);
        }

        let path = self
            .paths
            .get_active()
            .map_err(|_| HandoffBlocked::Closing)?;

        // The loss-detection timer is cleared precisely when nothing is in
        // flight and the peer's address is verified (see
        // `set_loss_detection_timer`), both of which hold here — so an armed
        // timer means we still owe a retransmission the importing side would
        // know nothing about. `bytes_in_flight()` itself is test-only.
        if path.recovery.loss_detection_timer().is_some() {
            return Err(HandoffBlocked::BytesInFlight);
        }

        // Every client-opened stream must be contiguous from offset 0, so the
        // replay on the importing side is a single write. `off_front` is 0
        // because the exporting side never reads a stream.
        for id in self.streams.readable() {
            if let Some(s) = self.streams.get(id) {
                if s.recv.off_front() != 0 || !s.recv.is_contiguous() {
                    return Err(HandoffBlocked::StreamGap);
                }
            }
        }

        Ok(())
    }

    /// Exports the connection, consuming it.
    ///
    /// The connection is marked closed before returning: after a successful
    /// export this host must never emit another packet for it, because the
    /// importing host owns the packet number space.
    pub fn handoff_export(&mut self) -> Result<HandoffState> {
        self.handoff_ready().map_err(|_| Error::InvalidState)?;

        let ctx = &self.crypto_ctx[packet::Epoch::Application];
        let open = ctx.crypto_open.as_ref().ok_or(Error::InvalidState)?;
        let seal = ctx.crypto_seal.as_ref().ok_or(Error::InvalidState)?;

        if open.alg() != seal.alg() {
            return Err(Error::InvalidState);
        }

        let aead = aead_to_u8(seal.alg());
        let open_secret = open.secret().to_vec();
        let seal_secret = seal.secret().to_vec();

        let mut local_tp = [0u8; 512];
        let local_transport_params =
            TransportParams::encode(&self.local_transport_params, true, &mut local_tp)?
                .to_vec();

        let mut peer_tp = [0u8; 512];
        let peer_transport_params =
            TransportParams::encode(&self.peer_transport_params, false, &mut peer_tp)?
                .to_vec();

        let space = &self.pkt_num_spaces[packet::Epoch::Application];
        let recv_pkt_need_ack = space
            .recv_pkt_need_ack
            .iter()
            .map(|r| (r.start, r.end))
            .collect();
        let recv_pkt_num_window = space.recv_pkt_num.as_parts();

        let scids: Vec<HandoffCid> = self
            .ids
            .scid_entries()
            .map(|e| HandoffCid {
                cid: e.cid.as_ref().to_vec(),
                seq: e.seq,
                reset_token: e.reset_token,
            })
            .collect();

        let dcids: Vec<HandoffCid> = self
            .ids
            .dcid_entries()
            .map(|e| HandoffCid {
                cid: e.cid.as_ref().to_vec(),
                seq: e.seq,
                reset_token: e.reset_token,
            })
            .collect();

        let (
            next_scid_seq,
            retire_prior_to,
            largest_peer_retire_prior_to,
            largest_destination_seq,
            source_conn_id_limit,
        ) = self.ids.snapshot_counters();

        let path = self.paths.get_active()?;
        let local_addr = path.local_addr();
        let peer_addr = path.peer_addr();
        let active_scid_seq = path.active_scid_seq;
        let active_dcid_seq = path.active_dcid_seq;

        // Drain every client-opened stream. Consuming here is fine — the
        // connection is being destroyed — and `handoff_ready` has already
        // established that each buffer is contiguous from offset 0.
        let ids: Vec<u64> = self.streams.readable().collect();
        let mut streams = Vec::with_capacity(ids.len());
        for id in ids {
            let mut data = Vec::new();
            let mut fin = false;
            let mut buf = [0u8; 4096];

            while let Ok((len, f)) = self.streams
                .get_mut(id)
                .ok_or(Error::InvalidState)?
                .recv
                .emit(&mut buf)
            {
                data.extend_from_slice(&buf[..len]);
                fin = f;
                if f || len == 0 {
                    break;
                }
            }

            streams.push(HandoffStream { id, data, fin });
        }

        let state = HandoffState {
            version: self.version,
            alpn: self.alpn.clone(),
            aead,
            open_secret,
            seal_secret,
            key_phase: self.key_phase,
            local_transport_params,
            peer_transport_params,
            next_pkt_num: self.next_pkt_num,
            largest_tx_pkt_num: space.largest_tx_pkt_num,
            largest_rx_pkt_num: space.largest_rx_pkt_num,
            largest_rx_non_probing_pkt_num: space.largest_rx_non_probing_pkt_num,
            recv_pkt_need_ack,
            recv_pkt_num_window,
            scids,
            dcids,
            active_scid_seq,
            active_dcid_seq,
            next_scid_seq,
            retire_prior_to,
            largest_peer_retire_prior_to,
            largest_destination_seq,
            source_conn_id_limit: source_conn_id_limit as u64,
            zero_length_dcid: self.ids.zero_length_dcid(),
            local_addr,
            peer_addr,
            max_tx_data: self.max_tx_data,
            peer_max_streams_bidi: self.streams.peer_max_streams_bidi(),
            peer_max_streams_uni: self.streams.peer_max_streams_uni(),
            rx_data: self.rx_data,
            streams,
            recv_count: self.recv_count as u64,
            sent_count: self.sent_count as u64,
            app_data: Vec::new(),
        };

        // Poison: one packet number space, one writer, forever.
        self.closed = true;

        Ok(state)
    }
}

// -------------------------------------------------------------------------
// Import
// -------------------------------------------------------------------------

/// Continues a connection another host handshook.
///
/// The returned connection is established: it has the peer's keys, connection
/// IDs and packet number state, and will serve the peer's streams as if it had
/// performed the handshake itself. The TLS state is a fresh, never-driven stub
/// — the handshake is over and its only remaining consumers are getters.
///
/// `config` supplies the parameters the handshake itself did not fix: the
/// congestion control algorithm, buffer sizing, and PMTUD. The transport
/// parameters come from the snapshot, never from `config`, because the peer
/// has already been told what they are.
pub fn accept_handoff(
    state: &HandoffState, config: &mut Config,
) -> Result<Connection> {
    let active_scid_seq = state.active_scid_seq.unwrap_or(0);
    let scid_entry = state
        .scids
        .iter()
        .find(|c| c.seq == active_scid_seq)
        .or_else(|| state.scids.first())
        .ok_or(Error::InvalidState)?;

    let scid = ConnectionId::from_ref(&scid_entry.cid);

    // Build a normal server connection: this gives a real (never-driven) TLS
    // handshake object from the config, a validated initial path, and defaults
    // for everything we are about to overwrite.
    let mut conn =
        Connection::new(&scid, None, state.local_addr, state.peer_addr, config, true)?;

    conn.version = state.version;
    conn.alpn = state.alpn.clone();

    // Transport parameters, ours and theirs, exactly as negotiated. Ours are
    // restored rather than taken from `config` because the peer is already
    // enforcing the values it was sent; a config that has drifted since would
    // otherwise produce spurious flow-control violations.
    //
    // Mind the flag: `encode`'s `is_server` asks whether the parameters belong
    // to a server, while `decode`'s asks whether *the caller* is one (i.e.
    // whether the parameters came from a client). So each set is decoded with
    // the opposite value it was encoded with.
    let local_tp =
        TransportParams::decode(&state.local_transport_params, false, None)?;
    let peer_tp =
        TransportParams::decode(&state.peer_transport_params, true, None)?;

    conn.local_transport_params = local_tp;
    conn.flow_control = crate::flowcontrol::FlowControl::new(
        conn.local_transport_params.initial_max_data,
        std::cmp::min(
            conn.local_transport_params.initial_max_data / 2 * 3,
            crate::DEFAULT_CONNECTION_WINDOW,
        ),
        config.max_connection_window,
    );
    conn.streams = crate::stream::StreamMap::new(
        conn.local_transport_params.initial_max_streams_bidi,
        conn.local_transport_params.initial_max_streams_uni,
        config.max_stream_window,
    );

    // Run the peer's parameters through the same path the handshake would
    // have, so every derived value (send capacity, ack delay, path MTU, CID
    // limit) is set the way the original connection set it...
    conn.process_peer_transport_params(peer_tp)?;
    conn.parsed_peer_transport_params = true;

    // ...then apply the values the peer has since raised by frame.
    conn.max_tx_data = conn.max_tx_data.max(state.max_tx_data);
    conn.streams
        .update_peer_max_streams_bidi(state.peer_max_streams_bidi);
    conn.streams
        .update_peer_max_streams_uni(state.peer_max_streams_uni);
    conn.update_tx_cap();

    // 1-RTT keys, rebuilt from the traffic secrets. Both directions derive
    // their next generation by HKDF from these, so key update keeps working
    // with no TLS involvement at all.
    let aead = aead_from_u8(state.aead)?;
    let ctx = &mut conn.crypto_ctx[packet::Epoch::Application];
    ctx.crypto_open = Some(crypto::Open::from_secret(aead, &state.open_secret)?);
    ctx.crypto_seal = Some(crypto::Seal::from_secret(aead, &state.seal_secret)?);
    conn.key_phase = state.key_phase;

    // Packet number state. The send counter continues where the exporter left
    // off — restarting it would make the peer discard our packets as replays —
    // and the receive window transfers verbatim so replay detection is exact.
    conn.next_pkt_num = state.next_pkt_num;

    let space = &mut conn.pkt_num_spaces[packet::Epoch::Application];
    space.largest_tx_pkt_num = state.largest_tx_pkt_num;
    space.largest_rx_pkt_num = state.largest_rx_pkt_num;
    space.largest_rx_non_probing_pkt_num = state.largest_rx_non_probing_pkt_num;
    space.recv_pkt_num =
        packet::PktNumWindow::from_parts(state.recv_pkt_num_window.0, state.recv_pkt_num_window.1);
    for (start, end) in &state.recv_pkt_need_ack {
        space.recv_pkt_need_ack.insert(*start..*end);
    }

    // Connection IDs, with the sequence numbers and reset tokens the peer
    // already knows. `new()` would renumber them from zero.
    let to_entry = |c: &HandoffCid, path_id: Option<usize>| cid::ConnectionIdEntry {
        cid: ConnectionId::from_ref(&c.cid).into_owned(),
        seq: c.seq,
        reset_token: c.reset_token,
        path_id,
    };

    let active_path_id = conn.paths.get_active_path_id()?;

    let scids: Vec<cid::ConnectionIdEntry> = state
        .scids
        .iter()
        .map(|c| {
            let p = (Some(c.seq) == state.active_scid_seq).then_some(active_path_id);
            to_entry(c, p)
        })
        .collect();

    let dcids: Vec<cid::ConnectionIdEntry> = state
        .dcids
        .iter()
        .map(|c| {
            let p = (Some(c.seq) == state.active_dcid_seq).then_some(active_path_id);
            to_entry(c, p)
        })
        .collect();

    conn.ids = cid::ConnectionIdentifiers::restore(
        scids,
        dcids,
        state.next_scid_seq,
        state.retire_prior_to,
        state.largest_peer_retire_prior_to,
        state.largest_destination_seq,
        conn.local_transport_params.active_conn_id_limit as usize,
        state.source_conn_id_limit as usize,
        scid_entry.cid.is_empty(),
        state.zero_length_dcid,
    )?;

    {
        let path = conn.paths.get_active_mut()?;
        path.active_scid_seq = state.active_scid_seq;
        path.active_dcid_seq = state.active_dcid_seq;
        // The peer completed a handshake with the exporting host, which proves
        // both addresses; there is nothing left to validate or amplify against.
        path.verified_peer_address = true;
        path.peer_verified_local_address = true;
    }

    // Replay what the peer sent before the handoff. This must go through
    // `get_or_create` so the stream-count accounting matches what the peer
    // believes it has opened.
    for s in &state.streams {
        let local_params = conn.local_transport_params.clone();
        let peer_params = conn.peer_transport_params.clone();
        let stream = conn.streams.get_or_create(
            s.id,
            &local_params,
            &peer_params,
            false,
            true,
        )?;

        if !s.data.is_empty() || s.fin {
            stream
                .recv
                .write(RangeBuf::from(&s.data, 0, s.fin))?;
        }

        if stream.is_readable() {
            let priority_key = std::sync::Arc::clone(&stream.priority_key);
            conn.streams.insert_readable(&priority_key);
        }
    }

    conn.rx_data = state.rx_data;
    conn.recv_count = state.recv_count as usize;
    conn.sent_count = state.sent_count as usize;

    // Handshake-completion flags. `derived_initial_secrets` and
    // `got_peer_conn_id` are load-bearing rather than cosmetic: without the
    // first, `send()` returns `Done` forever; without the second, the first
    // short-header packet's empty source CID would overwrite the peer's
    // connection IDs.
    conn.handshake_completed = true;
    conn.handshake_confirmed = true;
    conn.handshake_done_sent = true;
    conn.handshake_done_acked = true;
    conn.derived_initial_secrets = true;
    conn.got_peer_conn_id = true;
    conn.peer_verified_initial_address = true;
    conn.did_version_negotiation = true;

    // The idle timer is wall-clock state and cannot travel; re-arm it from the
    // negotiated timeout, which both sides already agree on.
    if let Some(timeout) = conn.idle_timeout() {
        conn.idle_timer = Some(std::time::Instant::now() + timeout);
    }

    Ok(conn)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_utils;

    /// A config generous enough to carry a real HTTP/3 exchange, with the ALPN
    /// tk-link's public edge negotiates.
    fn edge_config() -> Config {
        let mut config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        config
            .load_cert_chain_from_pem_file("examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("examples/cert.key")
            .unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_stream_data_bidi_remote(100_000);
        config.set_initial_max_stream_data_uni(100_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_max_idle_timeout(180_000);
        config.verify_peer(false);
        config
    }

    /// The config the *backend* imports with. Deliberately holds no
    /// certificate and no private key: the whole point of handing off after the
    /// handshake is that the backend never performs one.
    fn backend_config() -> Config {
        let mut config = Config::new(crate::PROTOCOL_VERSION).unwrap();
        config.set_application_protos(&[b"h3"]).unwrap();
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_stream_data_bidi_remote(100_000);
        config.set_initial_max_stream_data_uni(100_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_max_idle_timeout(180_000);
        config
    }

    /// Drives the pipe until the server reaches the quiescent boundary.
    fn quiesce(pipe: &mut test_utils::Pipe) {
        for _ in 0..16 {
            if pipe.server.handoff_ready().is_ok() {
                return;
            }
            pipe.advance().unwrap();
        }

        panic!(
            "server never reached a handoff boundary: {:?}",
            pipe.server.handoff_ready()
        );
    }

    /// Exports, round-trips through the wire codec, and imports — i.e. exactly
    /// what crossing the control channel to the backend does.
    fn handoff(pipe: &mut test_utils::Pipe, config: &mut Config) {
        let state = pipe.server.handoff_export().unwrap();
        let bytes = state.to_bytes().unwrap();
        let decoded = HandoffState::from_bytes(&bytes).unwrap();
        assert_eq!(state, decoded);

        pipe.server = accept_handoff(&decoded, config).unwrap();
    }

    fn sample_state() -> HandoffState {
        HandoffState {
            version: crate::PROTOCOL_VERSION,
            alpn: b"h3".to_vec(),
            aead: 1,
            open_secret: vec![0xaa; 32],
            seal_secret: vec![0xbb; 32],
            key_phase: true,
            local_transport_params: vec![1, 2, 3],
            peer_transport_params: vec![4, 5, 6, 7],
            next_pkt_num: 42,
            largest_tx_pkt_num: Some(41),
            largest_rx_pkt_num: 17,
            largest_rx_non_probing_pkt_num: 17,
            recv_pkt_need_ack: vec![(0, 5), (9, 18)],
            recv_pkt_num_window: (3, 0xdead_beef),
            scids: vec![HandoffCid {
                cid: vec![9; 17],
                seq: 0,
                reset_token: Some(0x1234_5678_9abc_def0),
            }],
            dcids: vec![HandoffCid {
                cid: vec![7; 16],
                seq: 0,
                reset_token: None,
            }],
            active_scid_seq: Some(0),
            active_dcid_seq: Some(0),
            next_scid_seq: 1,
            retire_prior_to: 0,
            largest_peer_retire_prior_to: 0,
            largest_destination_seq: 0,
            source_conn_id_limit: 4,
            zero_length_dcid: false,
            local_addr: "10.0.0.1:443".parse().unwrap(),
            peer_addr: "203.0.113.7:51234".parse().unwrap(),
            max_tx_data: 1_000_000,
            peer_max_streams_bidi: 100,
            peer_max_streams_uni: 3,
            rx_data: 128,
            streams: vec![HandoffStream {
                id: 2,
                data: b"SETTINGS".to_vec(),
                fin: false,
            }],
            recv_count: 6,
            sent_count: 5,
            app_data: b"principal=abc".to_vec(),
        }
    }

    /// The snapshot has to cross a control channel, so its size is a design
    /// constraint rather than an implementation detail. This pins it: the
    /// crypto portion is two traffic secrets and an algorithm byte, and the
    /// whole blob for a just-handshaken connection stays comfortably inside a
    /// single datagram.
    #[test]
    fn snapshot_is_small() {
        let mut config = edge_config();
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();

        pipe.handshake().unwrap();
        quiesce(&mut pipe);

        let state = pipe.server.handoff_export().unwrap();
        let bytes = state.to_bytes().unwrap();

        println!(
            "handoff blob: {} bytes total; secrets {}+{}; local tp {}; peer tp {}; \
             {} scids, {} dcids; {} early streams",
            bytes.len(),
            state.open_secret.len(),
            state.seal_secret.len(),
            state.local_transport_params.len(),
            state.peer_transport_params.len(),
            state.scids.len(),
            state.dcids.len(),
            state.streams.len(),
        );

        assert!(bytes.len() < 1200, "blob grew to {} bytes", bytes.len());
    }

    #[test]
    fn codec_roundtrip() {
        let state = sample_state();
        let bytes = state.to_bytes().unwrap();

        assert_eq!(HandoffState::from_bytes(&bytes).unwrap(), state);
    }

    #[test]
    fn codec_rejects_malformed_input() {
        let state = sample_state();
        let bytes = state.to_bytes().unwrap();

        // Wrong magic.
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(HandoffState::from_bytes(&bad), Err(Error::InvalidState));

        // Unknown version: refused outright rather than best-effort parsed, so
        // a future layout change can never be silently misread.
        let mut bad = bytes.clone();
        bad[5] = 0xff;
        assert_eq!(HandoffState::from_bytes(&bad), Err(Error::InvalidState));

        // Truncated.
        assert_eq!(
            HandoffState::from_bytes(&bytes[..bytes.len() - 1]),
            Err(Error::BufferTooShort)
        );

        // Trailing junk.
        let mut bad = bytes.clone();
        bad.push(0);
        assert_eq!(HandoffState::from_bytes(&bad), Err(Error::InvalidState));
    }

    #[test]
    fn handoff_ready_refuses_before_the_handshake() {
        let mut config = edge_config();
        let pipe = test_utils::Pipe::with_config(&mut config).unwrap();

        assert_eq!(
            pipe.server.handoff_ready(),
            Err(HandoffBlocked::HandshakeNotConfirmed)
        );

        // The client is not a server connection and can never be handed off.
        assert_eq!(pipe.client.handoff_ready(), Err(HandoffBlocked::NotServer));
    }

    #[test]
    fn export_poisons_the_exporter() {
        let mut config = edge_config();
        let mut backend = backend_config();
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();

        pipe.handshake().unwrap();
        quiesce(&mut pipe);

        let state = pipe.server.handoff_export().unwrap();

        // One packet number space, one writer. The exporting side must be
        // physically unable to emit again, whatever the caller does next.
        let mut buf = [0; 1500];
        assert_eq!(pipe.server.send(&mut buf), Err(Error::Done));
        assert_eq!(
            pipe.server.handoff_ready(),
            Err(HandoffBlocked::Closing)
        );

        // ...and the exported state still imports fine.
        assert!(accept_handoff(&state, &mut backend).is_ok());
    }

    #[test]
    fn imported_connection_serves_streams() {
        let mut config = edge_config();
        let mut backend = backend_config();
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();

        pipe.handshake().unwrap();
        quiesce(&mut pipe);
        handoff(&mut pipe, &mut backend);

        assert!(pipe.server.is_established());
        assert_eq!(pipe.server.application_proto(), b"h3");

        // The client opens a stream against the *imported* server.
        pipe.client.stream_send(4, b"hello backend", true).unwrap();
        pipe.advance().unwrap();

        let mut buf = [0; 64];
        let (len, fin) = pipe.server.stream_recv(4, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello backend");
        assert!(fin);

        // ...and answers on it.
        pipe.server.stream_send(4, b"hello client", true).unwrap();
        pipe.advance().unwrap();

        let (len, fin) = pipe.client.stream_recv(4, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"hello client");
        assert!(fin);
    }

    #[test]
    fn handoff_carries_early_client_streams() {
        let mut config = edge_config();
        let mut backend = backend_config();
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();

        pipe.handshake().unwrap();

        // The client sends application data before the handoff — as a real
        // HTTP/3 client does with SETTINGS. The exporting side acks it, so it
        // will never be retransmitted: if the snapshot dropped it, the bytes
        // would be gone for good.
        pipe.client.stream_send(4, b"sent before handoff", false).unwrap();
        pipe.advance().unwrap();

        quiesce(&mut pipe);

        let state = pipe.server.handoff_export().unwrap();
        assert_eq!(state.streams.len(), 1);
        assert_eq!(state.streams[0].id, 4);
        assert_eq!(state.streams[0].data, b"sent before handoff");
        assert!(!state.streams[0].fin);

        let bytes = state.to_bytes().unwrap();
        pipe.server =
            accept_handoff(&HandoffState::from_bytes(&bytes).unwrap(), &mut backend)
                .unwrap();

        // The backend reads what the client sent to the edge.
        let mut buf = [0; 64];
        let (len, fin) = pipe.server.stream_recv(4, &mut buf).unwrap();
        assert_eq!(&buf[..len], b"sent before handoff");
        assert!(!fin);

        // ...and the stream keeps working across the seam.
        pipe.client.stream_send(4, b" and after", true).unwrap();
        pipe.advance().unwrap();

        let (len, fin) = pipe.server.stream_recv(4, &mut buf).unwrap();
        assert_eq!(&buf[..len], b" and after");
        assert!(fin);
    }

    #[test]
    fn close_after_import_reaches_the_peer() {
        let mut config = edge_config();
        let mut backend = backend_config();
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();

        pipe.handshake().unwrap();
        quiesce(&mut pipe);
        handoff(&mut pipe, &mut backend);

        // A transport-level close on an imported connection has to be built for
        // the Application epoch. The TLS stub still reports the Initial write
        // level, so without the `write_pkt_type` patch this CONNECTION_CLOSE
        // would be encrypted under keys that do not exist and never leave the
        // host — the client would hang until its idle timeout instead.
        pipe.server.close(false, 0x1, b"bye").unwrap();
        pipe.advance().ok();

        assert!(pipe.client.is_closed() || pipe.client.peer_error().is_some());
        let err = pipe.client.peer_error().expect("client saw no close");
        assert_eq!(err.error_code, 0x1);
        assert_eq!(&err.reason, b"bye");
    }

    #[test]
    fn handoff_h3_end_to_end() {
        let mut config = edge_config();
        let mut backend = backend_config();
        let mut pipe = test_utils::Pipe::with_config(&mut config).unwrap();

        pipe.handshake().unwrap();

        // A stock HTTP/3 client: creating the h3 layer immediately queues the
        // control stream, SETTINGS and the QPACK streams, which reach the edge
        // before it has decided anything about the connection.
        let h3_config = crate::h3::Config::new().unwrap();
        let mut h3_client =
            crate::h3::Connection::with_transport(&mut pipe.client, &h3_config)
                .unwrap();
        pipe.advance().unwrap();

        // The edge never creates an h3 layer of its own — it hands the whole
        // connection to the backend instead.
        quiesce(&mut pipe);
        handoff(&mut pipe, &mut backend);

        let mut h3_server =
            crate::h3::Connection::with_transport(&mut pipe.server, &h3_config)
                .unwrap();
        pipe.advance().unwrap();

        let req = vec![
            crate::h3::Header::new(b":method", b"GET"),
            crate::h3::Header::new(b":scheme", b"https"),
            crate::h3::Header::new(b":authority", b"quic.tech"),
            crate::h3::Header::new(b":path", b"/"),
        ];

        let stream_id = h3_client
            .send_request(&mut pipe.client, &req, true)
            .unwrap();
        pipe.advance().unwrap();

        // The backend sees the request the client made of the edge.
        let (got_stream, event) = h3_server.poll(&mut pipe.server).unwrap();
        assert_eq!(got_stream, stream_id);
        assert!(matches!(event, crate::h3::Event::Headers { .. }));
        assert!(matches!(
            h3_server.poll(&mut pipe.server),
            Ok((_, crate::h3::Event::Finished))
        ));

        let resp = vec![
            crate::h3::Header::new(b":status", b"200"),
            crate::h3::Header::new(b"content-length", b"12"),
        ];
        h3_server
            .send_response(&mut pipe.server, stream_id, &resp, false)
            .unwrap();
        h3_server
            .send_body(&mut pipe.server, stream_id, b"hello world!", true)
            .unwrap();
        pipe.advance().unwrap();

        // ...and the client, which knows nothing of any of this, gets it.
        assert!(matches!(
            h3_client.poll(&mut pipe.client),
            Ok((_, crate::h3::Event::Headers { .. }))
        ));
        assert!(matches!(
            h3_client.poll(&mut pipe.client),
            Ok((_, crate::h3::Event::Data))
        ));

        let mut body = [0; 32];
        let len = h3_client
            .recv_body(&mut pipe.client, stream_id, &mut body)
            .unwrap();
        assert_eq!(&body[..len], b"hello world!");
    }
}
