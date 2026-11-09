//! Sealed-sender sending: wraps a 1:1 ciphertext that signal-wasm already produced (with our
//! persisted sessions) in the sealed-sender layer, libsignal's `sealed_sender_encrypt_from_usmc`.
//! The server then delivers it without learning who sent it; the recipient checks our sender
//! certificate. Mirrors Signal-Desktop `ts/textsecure/OutgoingMessage.preload.ts` (sealedSenderEncrypt).

use futures_util::FutureExt;
use libsignal_protocol::{
    sealed_sender_encrypt_from_usmc, sealed_sender_multi_recipient_encrypt, CiphertextMessageType,
    ContentHint, DeviceId, IdentityKey, IdentityKeyPair, IdentityKeyStore, InMemIdentityKeyStore,
    PrivateKey, ProtocolAddress, SenderCertificate, ServerCertificate, SessionRecord, Timestamp,
    UnidentifiedSenderMessageContent,
};
use rand::TryRngCore as _;
use wasm_bindgen::prelude::*;

use crate::{js_err, unseal_with_roots, Unsealed};

fn device(id: u32) -> Result<DeviceId, JsError> {
    DeviceId::try_from(id).map_err(|_| JsError::new("invalid device id"))
}

/// Seals `contents` (a CiphertextMessage of type `msg_type`: 2 Whisper, 3 PreKey, 7 SenderKey,
/// 8 Plaintext) for `destination_aci`.`destination_device`, whose identity key is
/// `destination_identity_key` (33 bytes), from us (`identity_key_pair`, libsignal serialization)
/// with our `sender_certificate` from `GET /v1/certificate/delivery`.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn seal(
    destination_aci: &str,
    destination_device: u32,
    destination_identity_key: &[u8],
    identity_key_pair: &[u8],
    sender_certificate: &[u8],
    msg_type: u8,
    contents: &[u8],
    content_hint: u32,
    group_id: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let pair = IdentityKeyPair::try_from(identity_key_pair).map_err(js_err)?;
    let destination = ProtocolAddress::new(destination_aci.to_owned(), device(destination_device)?);
    let their_key = IdentityKey::decode(destination_identity_key).map_err(js_err)?;
    let mut store = InMemIdentityKeyStore::new(pair, 0);
    store
        .save_identity(&destination, &their_key)
        .now_or_never()
        .ok_or_else(|| JsError::new("sealed sender: in-memory store did not complete synchronously"))?
        .map_err(js_err)?;

    let cert = SenderCertificate::deserialize(sender_certificate).map_err(js_err)?;
    let msg_type = CiphertextMessageType::try_from(msg_type).map_err(|_| JsError::new("unknown ciphertext message type"))?;
    let usmc = UnidentifiedSenderMessageContent::new(msg_type, cert, contents.to_vec(), ContentHint::from(content_hint), group_id)
        .map_err(js_err)?;
    let mut rng = rand::rngs::OsRng.unwrap_err();
    sealed_sender_encrypt_from_usmc(&destination, &usmc, &store, &mut rng)
        .now_or_never()
        .ok_or_else(|| JsError::new("sealed sender: in-memory store did not complete synchronously"))?
        .map_err(js_err)
}

/// Expiry of a sender certificate, in epoch milliseconds (refetch before it passes).
#[wasm_bindgen]
pub fn sender_certificate_expiration(sender_certificate: &[u8]) -> Result<f64, JsError> {
    let cert = SenderCertificate::deserialize(sender_certificate).map_err(js_err)?;
    Ok(cert.expiration().map_err(js_err)?.epoch_millis() as f64)
}

// --- for the receiver self-test only: Signal's real certificates can't be made outside its servers ---

/// A sender certificate chained to a test trust root (`trust_root_private`, 32 bytes) instead of Signal's.
#[wasm_bindgen]
pub fn test_sender_certificate(
    trust_root_private: &[u8],
    sender_aci: &str,
    sender_device: u32,
    sender_identity_public: &[u8],
    expiration_ms: f64,
) -> Result<Vec<u8>, JsError> {
    let mut rng = rand::rngs::OsRng.unwrap_err();
    let root = PrivateKey::deserialize(trust_root_private).map_err(js_err)?;
    let server_key = libsignal_protocol::KeyPair::generate(&mut rng);
    let server_cert = ServerCertificate::new(1, server_key.public_key, &root, &mut rng).map_err(js_err)?;
    let identity = IdentityKey::decode(sender_identity_public).map_err(js_err)?;
    let cert = SenderCertificate::new(
        sender_aci.to_owned(),
        None,
        *identity.public_key(),
        device(sender_device)?,
        Timestamp::from_epoch_millis(expiration_ms as u64),
        server_cert,
        &server_key.private_key,
        &mut rng,
    )
    .map_err(js_err)?;
    Ok(cert.serialized().map_err(js_err)?.to_vec())
}

/// `unseal`, but validating against a test trust root (`trust_root_public`, 33 bytes).
#[wasm_bindgen]
pub fn unseal_for_test(
    ciphertext: &[u8],
    identity_key_pair: &[u8],
    timestamp_ms: f64,
    local_aci: &str,
    local_device: u32,
    trust_root_public: &[u8],
) -> Result<Unsealed, JsError> {
    unseal_for_test_inner(ciphertext, identity_key_pair, timestamp_ms, local_aci, local_device, trust_root_public)
}

fn unseal_for_test_inner(
    ciphertext: &[u8],
    identity_key_pair: &[u8],
    timestamp_ms: f64,
    local_aci: &str,
    local_device: u32,
    trust_root_public: &[u8],
) -> Result<Unsealed, JsError> {
    let root = libsignal_protocol::PublicKey::deserialize(trust_root_public).map_err(js_err)?;
    unseal_with_roots(ciphertext, identity_key_pair, timestamp_ms, local_aci, local_device, &[root])
}

/// Sealed sender v2 for a group message (libsignal `sealed_sender_multi_recipient_encrypt`): one
/// `SenderKeyMessage` sealed for every recipient device, as the body of `PUT /v1/messages/multi_recipient`.
/// Destinations come as parallel lists, `names[i]`.`devices[i]`, grouped by name; `identity_keys` holds
/// each destination's 33-byte identity key in the same order, and `sessions` their serialized
/// SessionRecords back to back (`session_lens[i]` bytes each; the session supplies the registration id).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn seal_multi_recipient(
    names: Vec<String>,
    devices: Vec<u32>,
    identity_keys: &[u8],
    sessions: &[u8],
    session_lens: Vec<u32>,
    identity_key_pair: &[u8],
    sender_certificate: &[u8],
    sender_key_message: &[u8],
    content_hint: u32,
    group_id: Option<Vec<u8>>,
) -> Result<Vec<u8>, JsError> {
    let n = names.len();
    if devices.len() != n || session_lens.len() != n || identity_keys.len() != 33 * n {
        return Err(JsError::new("seal_multi_recipient: destination lists differ in length"));
    }
    let pair = IdentityKeyPair::try_from(identity_key_pair).map_err(js_err)?;
    let mut store = InMemIdentityKeyStore::new(pair, 0);
    let mut addresses = Vec::with_capacity(n);
    let mut records = Vec::with_capacity(n);
    let mut offset = 0usize;
    for i in 0..n {
        let address = ProtocolAddress::new(names[i].clone(), device(devices[i])?);
        let key = IdentityKey::decode(&identity_keys[33 * i..33 * (i + 1)]).map_err(js_err)?;
        store
            .save_identity(&address, &key)
            .now_or_never()
            .ok_or_else(|| JsError::new("sealed sender: in-memory store did not complete synchronously"))?
            .map_err(js_err)?;
        let len = session_lens[i] as usize;
        let bytes = sessions.get(offset..offset + len).ok_or_else(|| JsError::new("seal_multi_recipient: session bytes too short"))?;
        records.push(SessionRecord::deserialize(bytes).map_err(js_err)?);
        offset += len;
        addresses.push(address);
    }
    let cert = SenderCertificate::deserialize(sender_certificate).map_err(js_err)?;
    let usmc = UnidentifiedSenderMessageContent::new(
        CiphertextMessageType::SenderKey,
        cert,
        sender_key_message.to_vec(),
        ContentHint::from(content_hint),
        group_id,
    )
    .map_err(js_err)?;
    let address_refs: Vec<&ProtocolAddress> = addresses.iter().collect();
    let record_refs: Vec<&SessionRecord> = records.iter().collect();
    let mut rng = rand::rngs::OsRng.unwrap_err();
    sealed_sender_multi_recipient_encrypt(&address_refs, &record_refs, Vec::<libsignal_core::ServiceId>::new(), &usmc, &store, &mut rng)
        .now_or_never()
        .ok_or_else(|| JsError::new("sealed sender: in-memory store did not complete synchronously"))?
        .map_err(js_err)
}

/// For the receiver self-test: opens one recipient's part of a multi-recipient message the way the
/// server and the recipient do (libsignal `SealedSenderV2SentMessage` + `sealed_sender_decrypt_to_usmc`).
#[wasm_bindgen]
pub fn unseal_multi_recipient_for_test(
    sent: &[u8],
    recipient_aci: &str,
    recipient_device: u32,
    identity_key_pair: &[u8],
    timestamp_ms: f64,
    trust_root_public: &[u8],
) -> Result<Unsealed, JsError> {
    use libsignal_protocol::SealedSenderV2SentMessage;
    let parsed = SealedSenderV2SentMessage::parse(sent).map_err(js_err)?;
    let aci = libsignal_core::Aci::parse_from_service_id_string(recipient_aci).ok_or_else(|| JsError::new("not an ACI"))?;
    let recipient = parsed
        .recipients
        .get(&libsignal_core::ServiceId::from(aci))
        .ok_or_else(|| JsError::new("recipient not in message"))?;
    if !recipient.devices.iter().any(|(d, _)| u32::from(*d) == recipient_device) {
        return Err(JsError::new("device not in message"));
    }
    let received = parsed.received_message_parts_for_recipient(recipient).as_ref().concat();
    unseal_for_test_inner(&received, identity_key_pair, timestamp_ms, recipient_aci, recipient_device, trust_root_public)
}

/// The other side's identity key (33 bytes) from a serialized session record, or None when the
/// record has no current session. Sessions made before we recorded identity keys still carry the
/// key libsignal trusted for them, so a sealed send can use it.
#[wasm_bindgen]
pub fn session_remote_identity(session: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
    let record = SessionRecord::deserialize(session).map_err(js_err)?;
    Ok(record.remote_identity_key_bytes().unwrap_or(None))
}
