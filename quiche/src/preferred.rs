// PATCH(tk-link): RFC 9000 preferred_address plus a bounded ClientHello gate.
use crate::{Connection, ConnectionId, Error, Result};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

/// An alternative server endpoint, authenticated by the TLS handshake.
#[derive(Clone, Debug, PartialEq)]
pub struct PreferredAddress {
    /// IPv4 endpoint; zero when absent.
    pub ipv4: std::net::SocketAddrV4,
    /// IPv6 endpoint; zero when absent.
    pub ipv6: std::net::SocketAddrV6,
    /// Connection ID reserved at sequence 1.
    pub cid: ConnectionId<'static>,
    /// Stateless reset token for that ID.
    pub reset_token: u128,
}

impl PreferredAddress {
    pub(crate) fn decode(b: &[u8]) -> Result<Self> {
        if b.len() < 42 {
            return Err(Error::InvalidTransportParam);
        }
        let n = b[24] as usize;
        if !(1..=20).contains(&n) || b.len() != 41 + n {
            return Err(Error::InvalidTransportParam);
        }
        let v4 = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
        let v6 = Ipv6Addr::from(<[u8; 16]>::try_from(&b[6..22]).unwrap());
        let p4 = u16::from_be_bytes([b[4], b[5]]);
        let p6 = u16::from_be_bytes([b[22], b[23]]);
        if v4.is_unspecified() != (p4 == 0)
            || v6.is_unspecified() != (p6 == 0)
            || (p4 == 0 && p6 == 0)
        {
            return Err(Error::InvalidTransportParam);
        }
        Ok(Self {
            ipv4: std::net::SocketAddrV4::new(v4, p4),
            ipv6: std::net::SocketAddrV6::new(v6, p6, 0, 0),
            cid: b[25..25 + n].to_vec().into(),
            reset_token: u128::from_be_bytes(b[25 + n..].try_into().unwrap()),
        })
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(61);
        b.extend_from_slice(&self.ipv4.ip().octets());
        b.extend_from_slice(&self.ipv4.port().to_be_bytes());
        b.extend_from_slice(&self.ipv6.ip().octets());
        b.extend_from_slice(&self.ipv6.port().to_be_bytes());
        b.push(self.cid.len() as u8);
        b.extend_from_slice(&self.cid);
        b.extend_from_slice(&self.reset_token.to_be_bytes());
        b
    }
}

impl Connection {
    /// Preferred endpoint advertised by this server, or received by this client.
    pub fn preferred_address(&self) -> Option<SocketAddr> {
        let tp = if self.is_server {
            &self.local_transport_params
        } else {
            &self.peer_transport_params
        };
        let p = tp.preferred_address.as_ref()?;
        Some(if p.ipv4.port() != 0 {
            SocketAddr::V4(p.ipv4)
        } else {
            SocketAddr::V6(p.ipv6)
        })
    }

    /// Pause TLS before processing ClientHello. Only valid before the first recv.
    pub fn defer_server_hello(&mut self) -> Result<()> {
        if !self.is_server || self.recv_count != 0 || self.sent_count != 0 {
            return Err(Error::InvalidState);
        }
        self.deferred_hello = Some(Vec::new());
        Ok(())
    }

    /// Complete TLS ClientHello bytes, including its handshake header.
    pub fn deferred_client_hello(&self) -> Option<&[u8]> {
        let b = self.deferred_hello.as_ref()?;
        if b.len() < 4 {
            return None;
        }
        let len =
            ((b[1] as usize) << 16) | ((b[2] as usize) << 8) | b[3] as usize;
        if b.len() >= len + 4 {
            Some(&b[..len + 4])
        } else {
            None
        }
    }

    /// Release the gate. TLS is driven by the next recv/send as usual.
    pub fn resume_server_hello(&mut self) {
        self.deferred_hello = None;
    }

    /// Reserve sequence 1 and advertise it in the handshake, never in a
    /// NEW_CONNECTION_ID frame. Must run before TLS processes ClientHello.
    pub fn set_preferred_address(
        &mut self, address: SocketAddr, cid: &ConnectionId, token: u128,
    ) -> Result<()> {
        if !self.is_server
            || self.deferred_hello.is_none()
            || cid.is_empty()
            || cid.len() > 20
            || address.port() == 0
            || address.ip().is_unspecified()
            || self.ids.active_source_cids() != 1
        {
            return Err(Error::InvalidState);
        }
        let mut preferred = PreferredAddress {
            ipv4: "0.0.0.0:0".parse().unwrap(),
            ipv6: "[::]:0".parse().unwrap(),
            cid: cid.to_vec().into(),
            reset_token: token,
        };
        match address {
            SocketAddr::V4(a) => preferred.ipv4 = a,
            SocketAddr::V6(a) => preferred.ipv6 = a,
        }
        self.ids.new_scid(
            cid.to_vec().into(),
            Some(token),
            false,
            None,
            false,
        )?;
        self.local_transport_params.preferred_address = Some(preferred);
        self.encode_transport_params()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferred_parameter_roundtrips_and_rejects_malformed_values() {
        let p = PreferredAddress {
            ipv4: "203.0.113.5:54321".parse().unwrap(),
            ipv6: "[2001:db8::5]:54322".parse().unwrap(),
            cid: vec![5; 17].into(),
            reset_token: 123,
        };
        let encoded = p.encode();
        assert_eq!(PreferredAddress::decode(&encoded), Ok(p.clone()));
        for n in 0..encoded.len() {
            assert!(PreferredAddress::decode(&encoded[..n]).is_err());
        }
        let mut bad = encoded.clone();
        bad[24] = 0;
        assert!(PreferredAddress::decode(&bad).is_err());
        let mut bad = encoded.clone();
        bad.extend_from_slice(&[0]);
        assert!(PreferredAddress::decode(&bad).is_err());
        let mut bad = encoded;
        bad[4..6].fill(0);
        assert!(PreferredAddress::decode(&bad).is_err());

        let mut tp = crate::TransportParams::default();
        tp.preferred_address = Some(p);
        let mut out = [0; 512];
        let wire = crate::TransportParams::encode(&tp, true, &mut out).unwrap();
        assert!(crate::TransportParams::decode(wire, true, None).is_err());
        assert_eq!(
            crate::TransportParams::decode(wire, false, None).unwrap(),
            tp
        );
    }

    #[test]
    fn partial_client_hello_does_not_slice_past_the_buffer() {
        let mut pipe = crate::test_utils::Pipe::new("cubic").unwrap();
        pipe.server.deferred_hello = Some(vec![1, 0, 1, 0, 42]);
        assert_eq!(pipe.server.deferred_client_hello(), None);
    }

    #[test]
    fn gate_advertises_before_tls_and_survives_snapshot_adoption() {
        let mut pipe = crate::test_utils::Pipe::new("cubic").unwrap();
        pipe.server.defer_server_hello().unwrap();
        let mut packet = [0; 1500];
        let (n, info) = pipe.client.send(&mut packet).unwrap();
        pipe.server
            .recv(
                &mut packet[..n],
                crate::RecvInfo {
                    from: info.from,
                    to: info.to,
                },
            )
            .unwrap();
        let hello = pipe.server.deferred_client_hello().unwrap();
        assert_eq!(hello[0], 1);
        assert!(!pipe.server.is_established());
        let preferred = "127.0.0.1:55555".parse().unwrap();
        let cid = ConnectionId::from_ref(&[7; 17]);
        pipe.server
            .set_preferred_address(preferred, &cid, 123)
            .unwrap();
        pipe.server.resume_server_hello();
        pipe.advance().unwrap();
        assert_eq!(pipe.client.preferred_address(), Some(preferred));
        for _ in 0..16 {
            if pipe.server.handoff_ready().is_ok() {
                break;
            }
            pipe.advance().unwrap();
        }
        let snapshot = pipe.server.handoff_export().unwrap();
        let snapshot = crate::handoff::HandoffState::from_bytes(
            &snapshot.to_bytes().unwrap(),
        )
        .unwrap();
        let mut config = crate::Config::new(crate::PROTOCOL_VERSION).unwrap();
        let backend =
            crate::handoff::accept_handoff(&snapshot, &mut config).unwrap();
        assert_eq!(backend.preferred_address(), Some(preferred));
        assert!(backend.source_ids().any(|id| id == &cid));
        assert_eq!(
            snapshot
                .scids
                .iter()
                .find(|c| c.cid == cid.as_ref())
                .unwrap()
                .seq,
            1
        );
    }
}
