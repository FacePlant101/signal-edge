//! Group (zkgroup) operations from libsignal's own `zkgroup` crate, for reading group state:
//! derive group params from a master key, turn the server's auth credential responses into
//! credentials, present them to the groups server, and decrypt group attributes and members.
//! Mirrors Signal-Desktop `ts/util/zkgroup.node.ts` and `ts/services/groupCredentialFetcher`.

use libsignal_account_keys::AccountEntropyPool;
use libsignal_core::{Aci, Pni, ServiceId};
use wasm_bindgen::prelude::*;
use zkgroup::auth::{AuthCredentialWithPni, AuthCredentialWithPniResponse};
use zkgroup::groups::{GroupMasterKey, GroupSecretParams, ProfileKeyCiphertext, UuidCiphertext};
use zkgroup::profiles::ProfileKey;
use zkgroup::{ServerPublicParams, Timestamp};

use crate::js_err;

#[wasm_bindgen(getter_with_clone)]
pub struct GroupParams {
    /// Serialized GroupSecretParams: keep secret, pass back to the functions below.
    pub secret_params: Vec<u8>,
    /// Serialized GroupPublicParams: the username half of the groups-server Basic auth (hex).
    pub public_params: Vec<u8>,
    /// Group identifier (32 bytes), as used in `group:<base64>` chat ids.
    pub group_id: Vec<u8>,
}

fn server_params(bytes: &[u8]) -> Result<ServerPublicParams, JsError> {
    zkgroup::deserialize::<ServerPublicParams>(bytes).map_err(js_err)
}

fn secret_params(bytes: &[u8]) -> Result<GroupSecretParams, JsError> {
    zkgroup::deserialize::<GroupSecretParams>(bytes).map_err(js_err)
}

#[wasm_bindgen]
pub fn group_params(master_key: &[u8]) -> Result<GroupParams, JsError> {
    let key: [u8; 32] = master_key.try_into().map_err(|_| JsError::new("group master key must be 32 bytes"))?;
    let params = GroupSecretParams::derive_from_master_key(GroupMasterKey::new(key));
    Ok(GroupParams {
        secret_params: zkgroup::serialize(&params),
        public_params: zkgroup::serialize(&params.get_public_params()),
        group_id: params.get_group_identifier().to_vec(),
    })
}

/// One entry of `GET /v1/certificate/auth/group`: verifies the response for our ACI and PNI
/// and returns the serialized AuthCredentialWithPni for that redemption day.
#[wasm_bindgen]
pub fn receive_auth_credential(
    server_public_params: &[u8],
    aci: &str,
    pni: &str,
    redemption_time_secs: f64,
    response: &[u8],
) -> Result<Vec<u8>, JsError> {
    let params = server_params(server_public_params)?;
    let aci = Aci::parse_from_service_id_string(aci).ok_or_else(|| JsError::new("invalid ACI"))?;
    let tagged = if pni.starts_with("PNI:") { pni.to_owned() } else { format!("PNI:{pni}") };
    let pni = Pni::parse_from_service_id_string(&tagged).ok_or_else(|| JsError::new("invalid PNI"))?;
    let response = AuthCredentialWithPniResponse::new(response).map_err(js_err)?;
    let credential = response
        .receive(&params, aci, pni, Timestamp::from_epoch_seconds(redemption_time_secs as u64))
        .map_err(js_err)?;
    Ok(zkgroup::serialize(&credential))
}

/// Fresh presentation of `credential` for one group: the password half of the groups-server
/// Basic auth (hex).
#[wasm_bindgen]
pub fn auth_presentation(server_public_params: &[u8], group_secret_params: &[u8], credential: &[u8]) -> Result<Vec<u8>, JsError> {
    let params = server_params(server_public_params)?;
    let group = secret_params(group_secret_params)?;
    let credential = AuthCredentialWithPni::new(credential).map_err(js_err)?;
    let mut randomness = [0u8; 32];
    getrandom::fill(&mut randomness).map_err(js_err)?;
    Ok(zkgroup::serialize(&credential.present(&params, &group, randomness)))
}

/// Group attribute blobs (title, description, timer): returns the GroupAttributeBlob protobuf.
#[wasm_bindgen]
pub fn decrypt_blob(group_secret_params: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, JsError> {
    secret_params(group_secret_params)?.decrypt_blob_with_padding(ciphertext).map_err(js_err)
}

/// Member user ids: returns the service id string (plain UUID for an ACI, `PNI:<uuid>` for a PNI).
#[wasm_bindgen]
pub fn decrypt_service_id(group_secret_params: &[u8], ciphertext: &[u8]) -> Result<String, JsError> {
    let ciphertext = zkgroup::deserialize::<UuidCiphertext>(ciphertext).map_err(js_err)?;
    let id: ServiceId = secret_params(group_secret_params)?.decrypt_service_id(ciphertext).map_err(js_err)?;
    Ok(id.service_id_string())
}

/// A member's profile key from group state (Member.profileKey, a ProfileKeyCiphertext), for `aci`.
#[wasm_bindgen]
pub fn decrypt_profile_key(group_secret_params: &[u8], ciphertext: &[u8], aci: &str) -> Result<Vec<u8>, JsError> {
    let ciphertext = zkgroup::deserialize::<ProfileKeyCiphertext>(ciphertext).map_err(js_err)?;
    let aci = Aci::parse_from_service_id_string(aci).ok_or_else(|| JsError::new("not an ACI"))?;
    let key = secret_params(group_secret_params)?.decrypt_profile_key(ciphertext, aci).map_err(js_err)?;
    Ok(key.get_bytes().to_vec())
}

/// Unidentified-access key for sealed-sender sends to the owner of `profile_key` (32 bytes).
#[wasm_bindgen]
pub fn derive_access_key(profile_key: &[u8]) -> Result<Vec<u8>, JsError> {
    let bytes: [u8; 32] = profile_key.try_into().map_err(|_| JsError::new("profile key must be 32 bytes"))?;
    Ok(ProfileKey::create(bytes).derive_access_key().to_vec())
}

/// Master key (SVR key) from the account entropy pool, as Desktop `deriveMasterKey`.
#[wasm_bindgen]
pub fn master_key_from_entropy_pool(pool: &str) -> Result<Vec<u8>, JsError> {
    let pool: AccountEntropyPool = pool.parse().map_err(|_| JsError::new("invalid account entropy pool"))?;
    Ok(pool.derive_svr_key().to_vec())
}
