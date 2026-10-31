# Vendored: quiche

Cloudflare **quiche** (QUIC + HTTP/3 + QPACK), vendored so tk-link can add
**connection handoff**: exporting an established server connection so another
host continues serving it. Everything that has to move — traffic secrets, packet
number state, connection IDs, transport parameters — lives in private fields of
`quiche::Connection` with no accessors and no serialization, so the feature is
not expressible from outside the crate. That is the entire reason this is
vendored rather than used from crates.io.

## Provenance

| Field | Value |
|---|---|
| Upstream | crates.io `quiche` **0.24.6** (the exact version previously resolved) |
| Upstream repo | https://github.com/cloudflare/quiche |
| License | BSD-2-Clause (see `COPYING`, retained unchanged) |
| Obtained via | the cargo registry source cache, i.e. the published crate tarball — *not* a git checkout, so this tree matches what we were already building byte for byte apart from the patches below |
| Omitted | `deps/boringssl/` (~19 MB), `Cargo.toml.orig`, `.cargo_vcs_info.json`, upstream `Cargo.lock` |

`deps/boringssl` is deliberately absent: `native/quichex_nif/Cargo.toml` builds
quiche with `default-features = false, features = ["boringssl-boring-crate"]`,
under which `src/build.rs` skips the vendored-cmake branch entirely and
BoringSSL comes from the `boring` crate instead. Keeping the directory would
vendor 19 MB that nothing compiles.

Wired in as a Cargo patch rather than by editing the dependency line, so the
diff against upstream quichex stays minimal — see `[patch.crates-io]` in
`vendor/quichex/Cargo.toml`. Cargo still enforces that this tree really is
0.24.6.

## Upgrading

Re-vendor from the registry cache, then re-apply the patches below. Every one is
marked `// PATCH(tk-link)` at its site, so `grep -rn "PATCH(tk-link)" src/` is
the authoritative list. Patch 6 is the only one that changes existing behaviour;
the rest are additive. `cargo test --no-default-features --features
boringssl-boring-crate --lib` must stay green — it runs upstream's ~960 tests
alongside ours.

## Local patches

### 1. `src/handoff.rs` — the feature (new file)
The whole handoff implementation: `HandoffState` and its versioned wire codec,
`Connection::handoff_ready`, `Connection::handoff_export`, and
`quiche::handoff::accept_handoff`. Declared as a child module of the crate root
(`pub mod handoff;` in `src/lib.rs`) specifically so it can reach `Connection`'s
private state without widening anything there. Carries its own test module,
including an end-to-end HTTP/3 acceptance test.

### 2. `src/crypto/mod.rs` — `Open::secret()` / `Seal::secret()`
Expose the raw TLS traffic secret, which both types already retain in a private
field in order to derive the next generation on key update. The inverse
(`from_secret`) was already public, so this is the only missing half of a
round trip.

### 3. `src/packet.rs` — `PktNumWindow::as_parts()` / `from_parts()`
Serialize and restore the replay-detection window. This state must transfer
verbatim: `contains()` treats everything below `lower` as a duplicate, so a
fabricated window would silently discard genuinely-new reordered packets, and a
zeroed one would re-process replays.

### 4. `src/cid.rs` — `ConnectionIdentifiers::restore()`, entry iterators, counters
`new()` cannot be reused for an imported connection: it always numbers the
initial SCID 0 and starts `next_scid_seq` at 1, whereas the peer already knows
specific sequence numbers and reset tokens and validates
NEW_CONNECTION_ID/RETIRE_CONNECTION_ID against them. The existing
`scids_iter`/`dcids_iter` yield only the ID, dropping exactly the metadata that
has to survive, hence `scid_entries`/`dcid_entries`/`snapshot_counters`.

### 5. `src/stream/mod.rs`, `src/stream/recv_buf.rs`
`StreamMap::peer_max_streams_bidi()/uni()` read the peer's *current* limits for
export — they start at its transport parameters but a MAX_STREAMS frame may have
raised them since, and the imported connection must not offer less credit than
the peer was already granted. (`peer_streams_left_*` cannot substitute: it
subtracts locally-opened streams.) `RecvBuf::is_contiguous()` reports whether
buffered data forms one run from `off`, which is what lets the export gate
refuse while a hole is still outstanding.

### 6. `src/lib.rs` — `write_pkt_type` epoch selection ⚠ behaviour change
An imported connection carries its TLS state as a never-driven stub, so
`handshake.write_level()` still answers `Initial` even though the handshake
completed on the exporting host. Without this, a transport-level
CONNECTION_CLOSE would be built for an epoch whose keys do not exist, never
leave the host, and hang the peer until its idle timeout. Guarded on
`handshake_confirmed`, which makes it behaviour-preserving upstream: once the
handshake is confirmed the write level is always OneRTT anyway. Regression test:
`handoff::tests::close_after_import_reaches_the_peer` (verified to fail when
this hunk is reverted).

### 7. `Cargo.toml` — packaging only
Dropped the `include` list (it referenced the un-vendored `deps/boringssl`, and
a path dependency is never published) and set `crate-type = ["lib", "staticlib"]`.

`lib` is the rlib the quichex NIF links — the backbone side. `staticlib` is the
archive the Go SDK links through cgo — the backend side. **The same handoff code,
one implementation, two callers**, which is the entire reason quiche is vendored
rather than reimplemented: a second implementation of the import path would be a
second place to get wrong the invariants quiche never writes down.

Cost: one extra archive step per build. The expensive part, BoringSSL, is shared.

### 8. `src/ffi_handoff.rs` + `include/tklink_handoff.h` — the C ABI (new files)
The handoff API is ours, not upstream's, so it is not in `quiche.h`. This is its
C surface, gated by the same `ffi` feature and following upstream's conventions
exactly (NULL for a failed constructor, negative `Error::to_c()` codes,
`sockaddr_storage` + length for addresses).

Three entry points, and deliberately no more:

| | |
|---|---|
| `quiche_handoff_accept` | adopt a connection the backbone handshook |
| `quiche_handoff_peek_addrs` | the snapshot's local (VIP) and peer addresses, without importing |
| `quiche_handoff_peek_app_data` | the opaque identity blob, without importing |

**Export is not exposed.** A backend adopts connections and never hands one on,
and the snapshot export produces carries the connection's 1-RTT traffic secrets.

Connection-ID helpers are not exposed either: advertising a supplied CID is
upstream's `quiche_conn_new_scid` and asking how many more the peer will take is
`quiche_conn_scids_left`. Both already exist; adding our own would have been
duplicate symbols (and was, on the first attempt).

Two supporting one-line widenings: `handoff::WIRE_VERSION` (so the C ABI can
report the snapshot version) and `ffi::std_addr_to_c` from private to
`pub(crate)` (so the sibling module renders addresses identically). Neither
changes behaviour.

### Optional preferred endpoint for adopted connections

`quiche/src/preferred.rs` adds the RFC 9000 `preferred_address` codec, reserves
its CID at sequence 1, and exposes a bounded Initial-CRYPTO/ClientHello gate so
the application can select an anchor before TLS emits transport parameters.
`lib.rs` captures reassembled ClientHello bytes only while this gate is enabled
and registers a received preferred CID for clients. `tls/mod.rs` expands the
transport-parameter scratch buffer to 512 bytes. The existing handoff snapshot
carries the parameter and reserved CID without changing its wire version.
`ffi_handoff.rs` / `include/tklink_handoff.h` expose the advertised endpoint to
adopting Go backends so they can preserve distinct direct and VIP path addresses.
Client migration remains an explicit application decision; merely decoding the
parameter does not automatically move a quiche client.

The direct CID demultiplexer also exercises upstream's C source-ID iterator.
`ffi.rs` fixes its returned pointer to borrow the iterator's retained CID,
instead of pointing into a temporary clone dropped before C can copy it.
`sdk/go/quic/preferred_test.go` checks exact CID bytes across that boundary.
