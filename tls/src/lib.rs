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

#[wasm_bindgen]
impl TlsClient {
    /// Starts a TLS 1.3 handshake to `server_name`. Call `outgoing()` to get the ClientHello.
    #[wasm_bindgen(constructor)]
    pub fn new(server_name: &str) -> Result<TlsClient, JsError> {
        let mut roots = RootCertStore::empty();
        for der in SIGNAL_ROOTS {
            roots.add(CertificateDer::from(der)).map_err(js_err)?;
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ClientConfig::builder_with_details(provider, Arc::new(JsClock))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(js_err)?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(server_name.to_owned()).map_err(js_err)?;
        let conn = ClientConnection::new(Arc::new(config), name).map_err(js_err)?;
        Ok(TlsClient { conn, peer_closed: false })
    }

    /// Feeds bytes read from the socket. Returns any application plaintext they decrypted to.
    /// On error, still call `outgoing()` and send it: it may hold a TLS alert for the peer.
    pub fn receive(&mut self, mut data: &[u8]) -> Result<Vec<u8>, JsError> {
        let mut plaintext = Vec::new();
        while !data.is_empty() {
            self.conn.read_tls(&mut data).map_err(js_err)?;
            self.conn.process_new_packets().map_err(js_err)?;
            // Drain every round: rustls refuses more input once its plaintext buffer is full.
            match self.conn.reader().read_to_end(&mut plaintext) {
                Ok(_) => self.peer_closed = true,
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => return Err(js_err(e)),
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
