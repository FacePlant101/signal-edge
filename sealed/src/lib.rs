//! Sealed-sender unwrap for the Worker, from libsignal's own `libsignal-protocol`.
//!
//! Most Signal envelopes arrive as UNIDENTIFIED_SENDER: an outer layer that hides
//! the sender. This removes that layer with our identity key and validates the
//! sender certificate against Signal's trust roots, the first half of libsignal's
//! `sealed_sender_decrypt`. The inner message (PreKey/Whisper/SenderKey/Plaintext)
//! is then decrypted by signal-wasm with the persisted session stores.

use futures_util::FutureExt;
use libsignal_protocol::{
    sealed_sender_decrypt_to_usmc, IdentityKeyPair, InMemIdentityKeyStore, PublicKey, Timestamp,
};
use wasm_bindgen::prelude::*;

mod send;
mod zk;

/// Sealed-sender trust roots from Signal-Desktop `config/production.json` `serverTrustRoots`.
/// The second is libsignal's known production root (`KNOWN_SERVER_CERTIFICATES`, id 3).
const TRUST_ROOTS: [[u8; 33]; 2] = [
    hex33("057bba408295cf9300f20b2dcdf3a04501aac8ba8ec0d2872fa20d92fdc81d6305"),
    hex33("054918d08fbdfa83e00c29f8f8073a22ef35df2bea903aff81af03ccbc45c6e93a"),
];

const fn hex33(s: &str) -> [u8; 33] {
    let b = s.as_bytes();
    let mut out = [0u8; 33];
    let mut i = 0;
    while i < 33 {
        out[i] = (nibble(b[2 * i]) << 4) | nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex"),
    }
}

fn js_err(e: impl std::fmt::Display) -> JsError {
    JsError::new(&e.to_string())
}

#[wasm_bindgen(getter_with_clone)]
pub struct Unsealed {
    pub sender_aci: String,
    pub sender_e164: Option<String>,
    pub sender_device: u32,
    /// CiphertextMessageType: 2 Whisper, 3 PreKey, 7 SenderKey, 8 Plaintext.
    pub msg_type: u8,
    pub contents: Vec<u8>,
    pub group_id: Option<Vec<u8>>,
    pub content_hint: u32,
}

/// Removes the sealed-sender layer addressed to `identity_key_pair` (libsignal IdentityKeyPair
/// serialization). Rejects certificates not signed via Signal's trust roots, expired at
/// `timestamp_ms`, or sent by this very device.
#[wasm_bindgen]
pub fn unseal(
    ciphertext: &[u8],
    identity_key_pair: &[u8],
    timestamp_ms: f64,
    local_aci: &str,
    local_device: u32,
) -> Result<Unsealed, JsError> {
    let roots = TRUST_ROOTS
        .iter()
        .map(|r| PublicKey::deserialize(r))
        .collect::<Result<Vec<_>, _>>()
        .map_err(js_err)?;
    unseal_with_roots(ciphertext, identity_key_pair, timestamp_ms, local_aci, local_device, &roots)
}

pub(crate) fn unseal_with_roots(
    ciphertext: &[u8],
    identity_key_pair: &[u8],
    timestamp_ms: f64,
    local_aci: &str,
    local_device: u32,
    roots: &[PublicKey],
) -> Result<Unsealed, JsError> {
    let pair = IdentityKeyPair::try_from(identity_key_pair).map_err(js_err)?;
    let store = InMemIdentityKeyStore::new(pair, 0);
    let usmc = sealed_sender_decrypt_to_usmc(ciphertext, &store)
        .now_or_never()
        .ok_or_else(|| JsError::new("sealed sender: in-memory store did not complete synchronously"))?
        .map_err(js_err)?;

    let cert = usmc.sender().map_err(js_err)?;
    let valid = cert
        .validate_with_trust_roots(roots, Timestamp::from_epoch_millis(timestamp_ms as u64))
        .map_err(js_err)?;
    if !valid {
        return Err(JsError::new("sealed sender: certificate failed trust-root or expiry validation"));
    }

    let sender_aci = cert.sender_uuid().map_err(js_err)?.to_owned();
    let sender_device = u32::from(cert.sender_device_id().map_err(js_err)?);
    if sender_aci == local_aci && sender_device == local_device {
        return Err(JsError::new("sealed sender: message from this device"));
    }

    Ok(Unsealed {
        sender_aci,
        sender_e164: cert.sender_e164().map_err(js_err)?.map(str::to_owned),
        sender_device,
        msg_type: usmc.msg_type().map_err(js_err)? as u8,
        contents: usmc.contents().map_err(js_err)?.to_vec(),
        group_id: usmc.group_id().map_err(js_err)?.map(<[u8]>::to_vec),
        content_hint: u32::from(usmc.content_hint().map_err(js_err)?),
    })
}
