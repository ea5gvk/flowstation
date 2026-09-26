//! Debug UDP bearer: reach the gateway without a radio (`[wap] debug_udp_listen`).
//!
//! One helper thread owns the socket. It hands the datagrams of the allowed sources to the stack
//! through a bounded channel and sends what the stack gives back through another one, so the
//! stack thread never touches the socket. Both channels are bounded and never block the stack:
//! when one is full the datagram is dropped, which WTP recovers from.

use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
use std::time::Duration;

use crossbeam_channel::{Receiver, Sender, TryRecvError, bounded};
use tetra_config::bluestation::CfgWap;

/// Pause between two looks at the socket and the outgoing queue. The socket is non-blocking: a
/// receive timeout (SO_RCVTIMEO) can drop a datagram that arrives as it expires on Windows.
const POLL_INTERVAL: Duration = Duration::from_millis(5);
const QUEUE_LEN: usize = 64;
const MAX_DATAGRAM: usize = 2048;

pub struct DebugUdp {
    inbound: Receiver<(SocketAddrV4, Vec<u8>)>,
    outbound: Sender<(SocketAddrV4, Vec<u8>)>,
    local: SocketAddrV4,
}

impl DebugUdp {
    /// Bind `listen` and start the helper thread. Sources outside `allowed` are dropped there.
    pub fn spawn(listen: SocketAddrV4, cfg: &CfgWap) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(listen)?;
        socket.set_nonblocking(true)?;
        let local = match socket.local_addr()? {
            SocketAddr::V4(a) => a,
            SocketAddr::V6(_) => listen,
        };
        let (in_tx, in_rx) = bounded(QUEUE_LEN);
        let (out_tx, out_rx) = bounded(QUEUE_LEN * 4);
        let allowed = cfg.clone();
        std::thread::Builder::new().name("wap-debug-udp".to_string()).spawn(move || {
            super::leave_realtime_scheduling();
            run(socket, allowed, in_tx, out_rx)
        })?;
        tracing::info!("WAP: debug UDP bearer listening on {local}");
        Ok(Self {
            inbound: in_rx,
            outbound: out_tx,
            local,
        })
    }

    pub fn local_addr(&self) -> SocketAddrV4 {
        self.local
    }

    pub fn try_recv(&self) -> Option<(SocketAddrV4, Vec<u8>)> {
        self.inbound.try_recv().ok()
    }

    pub fn send(&self, to: SocketAddrV4, payload: Vec<u8>) {
        if self.outbound.try_send((to, payload)).is_err() {
            tracing::debug!("WAP: debug UDP send queue full, datagram to {to} dropped");
        }
    }
}

fn run(socket: UdpSocket, cfg: CfgWap, inbound: Sender<(SocketAddrV4, Vec<u8>)>, outbound: Receiver<(SocketAddrV4, Vec<u8>)>) {
    let mut buf = [0u8; MAX_DATAGRAM];
    let mut refused_logged = false;
    loop {
        loop {
            match outbound.try_recv() {
                Ok((to, payload)) => {
                    if let Err(e) = socket.send_to(&payload, to) {
                        tracing::debug!("WAP: debug UDP send to {to} failed: {e}");
                    }
                }
                Err(TryRecvError::Empty) => break,
                // The gateway is gone (station stopping or test over).
                Err(TryRecvError::Disconnected) => return,
            }
        }
        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, SocketAddr::V4(src))) if cfg.debug_source_allowed(*src.ip()) => {
                    let _ = inbound.try_send((src, buf[..n].to_vec()));
                }
                Ok((_, src)) => {
                    if !refused_logged {
                        tracing::warn!("WAP: debug UDP datagram from {src} refused (not in debug_udp_allowed_sources)");
                        refused_logged = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                // Windows reports an ICMP port unreachable from an earlier send as a receive error.
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
                Err(e) => {
                    tracing::warn!("WAP: debug UDP receive failed: {e}");
                    break;
                }
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Instant;

    fn recv_within(debug: &DebugUdp, wait: Duration) -> Option<(SocketAddrV4, Vec<u8>)> {
        let until = Instant::now() + wait;
        while Instant::now() < until {
            if let Some(d) = debug.try_recv() {
                return Some(d);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        None
    }

    #[test]
    fn debug_udp_rejects_unlisted_source() {
        let cfg = CfgWap {
            debug_udp_allowed_sources: vec![(Ipv4Addr::new(192, 0, 2, 1), 32)],
            ..Default::default()
        };
        let debug = DebugUdp::spawn(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &cfg).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.send_to(b"hi", debug.local_addr()).unwrap();
        assert_eq!(recv_within(&debug, Duration::from_millis(300)), None);
    }

    #[test]
    fn debug_udp_round_trip() {
        let cfg = CfgWap::default(); // 127.0.0.1/32 allowed
        let debug = DebugUdp::spawn(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0), &cfg).unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        client.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.send_to(b"ping", debug.local_addr()).unwrap();
        let (src, payload) = recv_within(&debug, Duration::from_secs(2)).expect("datagram reaches the stack side");
        assert_eq!(payload, b"ping");
        debug.send(src, b"pong".to_vec());
        let mut buf = [0u8; 16];
        let (n, _) = client.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pong");
    }
}
