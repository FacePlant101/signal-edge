//! Sans-IO TLS client for talking to Signal's servers from a Cloudflare Worker.
//!
//! Signal's servers present certificates from Signal's private root CA, which
//! Workers' `fetch()` rejects (HTTP 526). The Worker therefore opens a raw TCP
//! socket and runs TLS here: JS feeds received bytes in and writes our output
//! bytes to the socket. Only Signal's two roots are trusted, as in libsignal
//! (`rust/net/src/certs.rs`).

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::time_provider::TimeProvider;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use wasm_bindgen::prelude::*;

/// From libsignal `rust/net/res/`: RSA root (valid to 2032-01-24) and Ed25519 root (to 2036-06-16).
const SIGNAL_ROOTS: [&[u8]; 2] = [
    include_bytes!("../res/signal.cer"),
    include_bytes!("../res/signal-ed25519.cer"),
];

/// wasm32-unknown-unknown has no system clock; certificate validity uses JS `Date.now()`.
#[derive(Debug)]
struct JsClock;

impl TimeProvider for JsClock {
    fn current_time(&self) -> Option<UnixTime> {
        let ms = js_sys::Date::now();
        Some(UnixTime::since_unix_epoch(Duration::from_millis(ms as u64)))
    }
}

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen]
pub struct TlsClient {
    conn: ClientConnection,
    peer_closed: bool,
}

impl TlsClient {
    /// A client trusting exactly `roots`, with `time` for certificate validity (tests use a test root
    /// and the system clock; the JS constructor uses Signal's roots and the JS clock).
    fn build(roots: RootCertStore, time: Arc<dyn TimeProvider>, server_name: &str) -> Result<TlsClient, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_details(provider, time)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(server_name.to_owned()).map_err(|e| e.to_string())?;
        let conn = ClientConnection::new(Arc::new(config), name).map_err(|e| e.to_string())?;
        Ok(TlsClient { conn, peer_closed: false })
    }
}

#[wasm_bindgen]
impl TlsClient {
    /// Starts a TLS 1.3 handshake to `server_name`. Call `outgoing()` to get the ClientHello.
    #[wasm_bindgen(constructor)]
    pub fn new(server_name: &str) -> Result<TlsClient, JsError> {
        let mut roots = RootCertStore::empty();
        for der in SIGNAL_ROOTS {
            roots.add(CertificateDer::from(der)).map_err(js_err)?;
        }
        TlsClient::build(roots, Arc::new(JsClock), server_name).map_err(js_err)
    }

    /// Feeds bytes read from the socket. Returns any application plaintext they decrypted to.
    /// On error, still call `outgoing()` and send it: it may hold a TLS alert for the peer.
    /// Bytes after the peer's close_notify are ignored: the connection is over.
    pub fn receive(&mut self, mut data: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut plaintext = Vec::new();
        // After close_notify rustls takes no more input (read_tls returns 0 without consuming), so
        // looping on `data` alone would never end.
        while !data.is_empty() && !self.peer_closed {
            let taken = self.conn.read_tls(&mut data).map_err(js_err)?;
            self.conn.process_new_packets().map_err(js_err)?;
            // Drain every round: rustls refuses more input once its plaintext buffer is full.
            match self.conn.reader().read_to_end(&mut plaintext) {
                Ok(_) => self.peer_closed = true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(js_err(e)),
            }
            if taken == 0 {
                break;
            }
        }
        Ok(plaintext)
    }

    /// Queues as much application plaintext as rustls will buffer (64 KiB by default) and
    /// returns how many bytes it took. Call `outgoing()`, send that, then pass the rest.
    pub fn send(&mut self, data: &[u8]) -> Result<usize, JsError> {
        self.conn.writer().write(data).map_err(js_err)
    }

    /// Bytes to write to the socket (handshake records, ciphertext, alerts).
    pub fn outgoing(&mut self) -> Result<Vec<u8>, JsError> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            self.conn.write_tls(&mut out).map_err(js_err)?;
        }
        Ok(out)
    }

    /// Queues a close_notify alert. Call `outgoing()` afterwards.
    pub fn close(&mut self) {
        self.conn.send_close_notify();
    }

    #[wasm_bindgen(getter)]
    pub fn handshaking(&self) -> bool {
        self.conn.is_handshaking()
    }

    /// True once the peer sent close_notify.
    #[wasm_bindgen(getter)]
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ServerConfig, ServerConnection};
    use std::sync::mpsc;
    use std::thread;

    /// A self-signed P-256 certificate for example.test (tests/data), standing in for Signal's roots.
    const CERT: &[u8] = include_bytes!("../tests/data/cert.der");
    const KEY: &[u8] = include_bytes!("../tests/data/key.der");

    fn pair() -> (TlsClient, ServerConnection) {
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(CERT)).unwrap();
        let client = TlsClient::build(roots, Arc::new(rustls::time_provider::DefaultTimeProvider), "example.test").unwrap();
        let config = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![CertificateDer::from(CERT)], PrivateKeyDer::Pkcs8(KEY.to_vec().into()))
            .unwrap();
        (client, ServerConnection::new(Arc::new(config)).unwrap())
    }

    fn server_out(server: &mut ServerConnection) -> Vec<u8> {
        let mut out = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut out).unwrap();
        }
        out
    }

    fn handshake(client: &mut TlsClient, server: &mut ServerConnection) {
        for _ in 0..10 {
            let to_server = client.outgoing().unwrap();
            server.read_tls(&mut &to_server[..]).unwrap();
            server.process_new_packets().unwrap();
            let to_client = server_out(server);
            client.receive(&to_client).unwrap();
            if !client.handshaking() && !server.is_handshaking() {
                return;
            }
        }
        panic!("handshake did not finish");
    }

    /// Runs `f` on its own thread and fails if it doesn't finish promptly (the bug was a busy loop).
    fn within_a_second<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || tx.send(f()).unwrap());
        rx.recv_timeout(Duration::from_secs(1)).expect("receive() did not return: it is spinning")
    }

    #[test]
    fn bytes_after_close_notify_end_the_connection_instead_of_spinning() {
        within_a_second(|| {
            let (mut client, mut server) = pair();
            handshake(&mut client, &mut server);
            server.writer().write_all(b"hello").unwrap();
            server.send_close_notify();
            let mut wire = server_out(&mut server);
            // Anyone on the path can append bytes after the authentic close_notify.
            wire.extend_from_slice(b"\x17\x03\x03\x00\x05junk!");
            assert_eq!(client.receive(&wire).unwrap(), b"hello");
            assert!(client.peer_closed());
            // Later bytes are ignored too.
            assert_eq!(client.receive(b"more junk").unwrap(), b"");
        });
    }

    #[test]
    fn data_and_close_notify_split_across_reads() {
        within_a_second(|| {
            let (mut client, mut server) = pair();
            handshake(&mut client, &mut server);
            server.writer().write_all(b"part one").unwrap();
            let first = server_out(&mut server);
            assert_eq!(client.receive(&first).unwrap(), b"part one");
            assert!(!client.peer_closed());
            server.send_close_notify();
            let second = server_out(&mut server);
            assert_eq!(client.receive(&second).unwrap(), b"");
            assert!(client.peer_closed());
        });
    }
}
