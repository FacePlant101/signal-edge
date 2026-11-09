/* @ts-self-types="./signal_sealed.d.ts" */

export class GroupParams {
    static __wrap(ptr) {
        const obj = Object.create(GroupParams.prototype);
        obj.__wbg_ptr = ptr;
        GroupParamsFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        GroupParamsFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_groupparams_free(ptr, 0);
    }
    /**
     * Group identifier (32 bytes), as used in `group:<base64>` chat ids.
     * @returns {Uint8Array}
     */
    get group_id() {
        const ret = wasm.__wbg_get_groupparams_group_id(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Serialized GroupPublicParams: the username half of the groups-server Basic auth (hex).
     * @returns {Uint8Array}
     */
    get public_params() {
        const ret = wasm.__wbg_get_groupparams_public_params(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Serialized GroupSecretParams: keep secret, pass back to the functions below.
     * @returns {Uint8Array}
     */
    get secret_params() {
        const ret = wasm.__wbg_get_groupparams_secret_params(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Group identifier (32 bytes), as used in `group:<base64>` chat ids.
     * @param {Uint8Array | number[]} arg0
     */
    set group_id(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_groupparams_group_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Serialized GroupPublicParams: the username half of the groups-server Basic auth (hex).
     * @param {Uint8Array | number[]} arg0
     */
    set public_params(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_groupparams_public_params(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * Serialized GroupSecretParams: keep secret, pass back to the functions below.
     * @param {Uint8Array | number[]} arg0
     */
    set secret_params(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_groupparams_secret_params(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) GroupParams.prototype[Symbol.dispose] = GroupParams.prototype.free;

export class Unsealed {
    static __wrap(ptr) {
        const obj = Object.create(Unsealed.prototype);
        obj.__wbg_ptr = ptr;
        UnsealedFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        UnsealedFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_unsealed_free(ptr, 0);
    }
    /**
     * @returns {number}
     */
    get content_hint() {
        const ret = wasm.__wbg_get_unsealed_content_hint(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {Uint8Array}
     */
    get contents() {
        const ret = wasm.__wbg_get_unsealed_contents(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array | undefined}
     */
    get group_id() {
        const ret = wasm.__wbg_get_unsealed_group_id(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * CiphertextMessageType: 2 Whisper, 3 PreKey, 7 SenderKey, 8 Plaintext.
     * @returns {number}
     */
    get msg_type() {
        const ret = wasm.__wbg_get_unsealed_msg_type(this.__wbg_ptr);
        return ret;
    }
    /**
     * @returns {string}
     */
    get sender_aci() {
        let deferred1_0;
        let deferred1_1;
        try {
            const ret = wasm.__wbg_get_unsealed_sender_aci(this.__wbg_ptr);
            deferred1_0 = ret[0];
            deferred1_1 = ret[1];
            return getStringFromWasm0(ret[0], ret[1]);
        } finally {
            wasm.__wbindgen_free(deferred1_0, deferred1_1, 1);
        }
    }
    /**
     * @returns {number}
     */
    get sender_device() {
        const ret = wasm.__wbg_get_unsealed_sender_device(this.__wbg_ptr);
        return ret >>> 0;
    }
    /**
     * @returns {string | undefined}
     */
    get sender_e164() {
        const ret = wasm.__wbg_get_unsealed_sender_e164(this.__wbg_ptr);
        let v1;
        if (ret[0] !== 0) {
            v1 = getStringFromWasm0(ret[0], ret[1]);
            wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        }
        return v1;
    }
    /**
     * @param {number} arg0
     */
    set content_hint(arg0) {
        wasm.__wbg_set_unsealed_content_hint(this.__wbg_ptr, arg0);
    }
    /**
     * @param {Uint8Array | number[]} arg0
     */
    set contents(arg0) {
        const ptr0 = passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_unsealed_contents(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {Uint8Array | number[] | null} [arg0]
     */
    set group_id(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passArray8ToWasm0(arg0, wasm.__wbindgen_malloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_unsealed_group_id(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * CiphertextMessageType: 2 Whisper, 3 PreKey, 7 SenderKey, 8 Plaintext.
     * @param {number} arg0
     */
    set msg_type(arg0) {
        wasm.__wbg_set_unsealed_msg_type(this.__wbg_ptr, arg0);
    }
    /**
     * @param {string} arg0
     */
    set sender_aci(arg0) {
        const ptr0 = passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_unsealed_sender_aci(this.__wbg_ptr, ptr0, len0);
    }
    /**
     * @param {number} arg0
     */
    set sender_device(arg0) {
        wasm.__wbg_set_unsealed_sender_device(this.__wbg_ptr, arg0);
    }
    /**
     * @param {string | null} [arg0]
     */
    set sender_e164(arg0) {
        var ptr0 = isLikeNone(arg0) ? 0 : passStringToWasm0(arg0, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        var len0 = WASM_VECTOR_LEN;
        wasm.__wbg_set_unsealed_sender_e164(this.__wbg_ptr, ptr0, len0);
    }
}
if (Symbol.dispose) Unsealed.prototype[Symbol.dispose] = Unsealed.prototype.free;

/**
 * Fresh presentation of `credential` for one group: the password half of the groups-server
 * Basic auth (hex).
 * @param {Uint8Array | number[]} server_public_params
 * @param {Uint8Array | number[]} group_secret_params
 * @param {Uint8Array | number[]} credential
 * @returns {Uint8Array}
 */
export function auth_presentation(server_public_params, group_secret_params, credential) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(server_public_params, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(group_secret_params, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(credential, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.auth_presentation(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Group attribute blobs (title, description, timer): returns the GroupAttributeBlob protobuf.
 * @param {Uint8Array | number[]} group_secret_params
 * @param {Uint8Array | number[]} ciphertext
 * @returns {Uint8Array}
 */
export function decrypt_blob(group_secret_params, ciphertext) {
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(group_secret_params, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.decrypt_blob(ptr0, len0, ptr1, len1);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v3;
}

/**
 * A member's profile key from group state (Member.profileKey, a ProfileKeyCiphertext), for `aci`.
 * @param {Uint8Array | number[]} group_secret_params
 * @param {Uint8Array | number[]} ciphertext
 * @param {string} aci
 * @returns {Uint8Array}
 */
export function decrypt_profile_key(group_secret_params, ciphertext, aci) {
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(group_secret_params, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passStringToWasm0(aci, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.decrypt_profile_key(ptr0, len0, ptr1, len1, ptr2, len2);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v4 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v4;
}

/**
 * Member user ids: returns the service id string (plain UUID for an ACI, `PNI:<uuid>` for a PNI).
 * @param {Uint8Array | number[]} group_secret_params
 * @param {Uint8Array | number[]} ciphertext
 * @returns {string}
 */
export function decrypt_service_id(group_secret_params, ciphertext) {
    let deferred4_0;
    let deferred4_1;
    try {
        let ptr0, len0, ptr1, len1;
        try {
            ptr0 = passArray8ToWasm0(group_secret_params, wasm.__wbindgen_malloc);
            len0 = WASM_VECTOR_LEN;
            ptr1 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
            len1 = WASM_VECTOR_LEN;
        } catch (e) {
            if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
            if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
            throw e;
        }
        const ret = wasm.decrypt_service_id(ptr0, len0, ptr1, len1);
        var ptr3 = ret[0];
        var len3 = ret[1];
        if (ret[3]) {
            ptr3 = 0; len3 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred4_0 = ptr3;
        deferred4_1 = len3;
        return getStringFromWasm0(ptr3, len3);
    } finally {
        wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
    }
}

/**
 * Unidentified-access key for sealed-sender sends to the owner of `profile_key` (32 bytes).
 * @param {Uint8Array | number[]} profile_key
 * @returns {Uint8Array}
 */
export function derive_access_key(profile_key) {
    const ptr0 = passArray8ToWasm0(profile_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.derive_access_key(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * @param {Uint8Array | number[]} master_key
 * @returns {GroupParams}
 */
export function group_params(master_key) {
    const ptr0 = passArray8ToWasm0(master_key, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.group_params(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return GroupParams.__wrap(ret[0]);
}

/**
 * Expiration of the endorsements in a response, in epoch seconds.
 * @param {Uint8Array | number[]} response
 * @returns {number}
 */
export function group_send_endorsements_expiration(response) {
    const ptr0 = passArray8ToWasm0(response, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.group_send_endorsements_expiration(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0];
}

/**
 * `Group-Send-Token` for a set of recipients: their endorsements (`count` of them, back to back, as
 * stored from `receive_group_send_endorsements`) combined, turned into a token for this group and
 * bound to the response's expiration (Desktop `GroupSendEndorsementState.buildToken`).
 * @param {Uint8Array | number[]} endorsements
 * @param {number} count
 * @param {Uint8Array | number[]} group_secret_params
 * @param {number} expiration_seconds
 * @returns {Uint8Array}
 */
export function group_send_full_token(endorsements, count, group_secret_params, expiration_seconds) {
    const val3 = +count;
    const val4 = +expiration_seconds;
    let ptr0, len0, ptr1, len1;
    try {
        ptr0 = passArray8ToWasm0(endorsements, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(group_secret_params, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.group_send_full_token(ptr0, len0, val3, ptr1, len1, val4);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v5;
}

/**
 * Master key (SVR key) from the account entropy pool, as Desktop `deriveMasterKey`.
 * @param {string} pool
 * @returns {Uint8Array}
 */
export function master_key_from_entropy_pool(pool) {
    const ptr0 = passStringToWasm0(pool, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.master_key_from_entropy_pool(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v2;
}

/**
 * One entry of `GET /v1/certificate/auth/group`: verifies the response for our ACI and PNI
 * and returns the serialized AuthCredentialWithPni for that redemption day.
 * @param {Uint8Array | number[]} server_public_params
 * @param {string} aci
 * @param {string} pni
 * @param {number} redemption_time_secs
 * @param {Uint8Array | number[]} response
 * @returns {Uint8Array}
 */
export function receive_auth_credential(server_public_params, aci, pni, redemption_time_secs, response) {
    const val5 = +redemption_time_secs;
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
    try {
        ptr0 = passArray8ToWasm0(server_public_params, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(aci, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passStringToWasm0(pni, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(response, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.receive_auth_credential(ptr0, len0, ptr1, len1, ptr2, len2, val5, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v6 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v6;
}

/**
 * The same for an account without a phone number (Signal Login): the server binds the credential
 * to a PNI derived from our ACI and the account's auth credential salt (in the response to
 * `POST /v1/registration` and `GET /v1/accounts/whoami`) instead of a real PNI.
 * @param {Uint8Array | number[]} server_public_params
 * @param {string} aci
 * @param {Uint8Array | number[]} auth_credential_salt
 * @param {number} redemption_time_secs
 * @param {Uint8Array | number[]} response
 * @returns {Uint8Array}
 */
export function receive_auth_credential_without_pni(server_public_params, aci, auth_credential_salt, redemption_time_secs, response) {
    const val5 = +redemption_time_secs;
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
    try {
        ptr0 = passArray8ToWasm0(server_public_params, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(aci, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(auth_credential_salt, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(response, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.receive_auth_credential_without_pni(ptr0, len0, ptr1, len1, ptr2, len2, val5, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v6 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v6;
}

/**
 * Verifies `GroupResponse.group_send_endorsements_response` for the group's full member list
 * (`member_acis`, our own ACI included, as Desktop `receiveWithServiceIds`) and returns one
 * serialized endorsement per member, in that order, back to back.
 * @param {Uint8Array | number[]} response
 * @param {string[]} member_acis
 * @param {number} now_seconds
 * @param {Uint8Array | number[]} group_secret_params
 * @param {Uint8Array | number[]} server_public_params
 * @returns {Uint8Array}
 */
export function receive_group_send_endorsements(response, member_acis, now_seconds, group_secret_params, server_public_params) {
    const val5 = +now_seconds;
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
    try {
        ptr0 = passArray8ToWasm0(response, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArrayJsValueToWasm0(member_acis, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(group_secret_params, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(server_public_params, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__externref_drop_slice(ptr1, len1); wasm.__wbindgen_free(ptr1, len1 * 4, 4); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.receive_group_send_endorsements(ptr0, len0, ptr1, len1, val5, ptr2, len2, ptr3, len3);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v6 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v6;
}

/**
 * Seals `contents` (a CiphertextMessage of type `msg_type`: 2 Whisper, 3 PreKey, 7 SenderKey,
 * 8 Plaintext) for `destination_aci`.`destination_device`, whose identity key is
 * `destination_identity_key` (33 bytes), from us (`identity_key_pair`, libsignal serialization)
 * with our `sender_certificate` from `GET /v1/certificate/delivery`.
 * @param {string} destination_aci
 * @param {number} destination_device
 * @param {Uint8Array | number[]} destination_identity_key
 * @param {Uint8Array | number[]} identity_key_pair
 * @param {Uint8Array | number[]} sender_certificate
 * @param {number} msg_type
 * @param {Uint8Array | number[]} contents
 * @param {number} content_hint
 * @param {Uint8Array | number[] | null} [group_id]
 * @returns {Uint8Array}
 */
export function seal(destination_aci, destination_device, destination_identity_key, identity_key_pair, sender_certificate, msg_type, contents, content_hint, group_id) {
    const val7 = +destination_device;
    const val8 = +msg_type;
    const val9 = +content_hint;
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5;
    try {
        ptr0 = passStringToWasm0(destination_aci, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(destination_identity_key, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(identity_key_pair, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(sender_certificate, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
        ptr4 = passArray8ToWasm0(contents, wasm.__wbindgen_malloc);
        len4 = WASM_VECTOR_LEN;
        ptr5 = isLikeNone(group_id) ? 0 : passArray8ToWasm0(group_id, wasm.__wbindgen_malloc);
        len5 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr5) { wasm.__wbindgen_free(ptr5, len5 * 1, 1); }
        if (ptr4) { wasm.__wbindgen_free(ptr4, len4 * 1, 1); }
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.seal(ptr0, len0, val7, ptr1, len1, ptr2, len2, ptr3, len3, val8, ptr4, len4, val9, ptr5, len5);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v10 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v10;
}

/**
 * Sealed sender v2 for a group message (libsignal `sealed_sender_multi_recipient_encrypt`): one
 * `SenderKeyMessage` sealed for every recipient device, as the body of `PUT /v1/messages/multi_recipient`.
 * Destinations come as parallel lists, `names[i]`.`devices[i]`, grouped by name; `identity_keys` holds
 * each destination's 33-byte identity key in the same order, and `sessions` their serialized
 * SessionRecords back to back (`session_lens[i]` bytes each; the session supplies the registration id).
 * @param {string[]} names
 * @param {Uint32Array | number[]} devices
 * @param {Uint8Array | number[]} identity_keys
 * @param {Uint8Array | number[]} sessions
 * @param {Uint32Array | number[]} session_lens
 * @param {Uint8Array | number[]} identity_key_pair
 * @param {Uint8Array | number[]} sender_certificate
 * @param {Uint8Array | number[]} sender_key_message
 * @param {number} content_hint
 * @param {Uint8Array | number[] | null} [group_id]
 * @returns {Uint8Array}
 */
export function seal_multi_recipient(names, devices, identity_keys, sessions, session_lens, identity_key_pair, sender_certificate, sender_key_message, content_hint, group_id) {
    const val10 = +content_hint;
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, ptr8, len8;
    try {
        ptr0 = passArrayJsValueToWasm0(names, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray32ToWasm0(devices, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(identity_keys, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(sessions, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
        ptr4 = passArray32ToWasm0(session_lens, wasm.__wbindgen_malloc);
        len4 = WASM_VECTOR_LEN;
        ptr5 = passArray8ToWasm0(identity_key_pair, wasm.__wbindgen_malloc);
        len5 = WASM_VECTOR_LEN;
        ptr6 = passArray8ToWasm0(sender_certificate, wasm.__wbindgen_malloc);
        len6 = WASM_VECTOR_LEN;
        ptr7 = passArray8ToWasm0(sender_key_message, wasm.__wbindgen_malloc);
        len7 = WASM_VECTOR_LEN;
        ptr8 = isLikeNone(group_id) ? 0 : passArray8ToWasm0(group_id, wasm.__wbindgen_malloc);
        len8 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr8) { wasm.__wbindgen_free(ptr8, len8 * 1, 1); }
        if (ptr7) { wasm.__wbindgen_free(ptr7, len7 * 1, 1); }
        if (ptr6) { wasm.__wbindgen_free(ptr6, len6 * 1, 1); }
        if (ptr5) { wasm.__wbindgen_free(ptr5, len5 * 1, 1); }
        if (ptr4) { wasm.__wbindgen_free(ptr4, len4 * 4, 4); }
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 4, 4); }
        if (ptr0) { wasm.__externref_drop_slice(ptr0, len0); wasm.__wbindgen_free(ptr0, len0 * 4, 4); }
        throw e;
    }
    const ret = wasm.seal_multi_recipient(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, val10, ptr8, len8);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v11 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v11;
}

/**
 * Expiry of a sender certificate, in epoch milliseconds (refetch before it passes).
 * @param {Uint8Array | number[]} sender_certificate
 * @returns {number}
 */
export function sender_certificate_expiration(sender_certificate) {
    const ptr0 = passArray8ToWasm0(sender_certificate, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.sender_certificate_expiration(ptr0, len0);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return ret[0];
}

/**
 * The other side's identity key (33 bytes) from a serialized session record, or None when the
 * record has no current session. Sessions made before we recorded identity keys still carry the
 * key libsignal trusted for them, so a sealed send can use it.
 * @param {Uint8Array | number[]} session
 * @returns {Uint8Array | undefined}
 */
export function session_remote_identity(session) {
    const ptr0 = passArray8ToWasm0(session, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.session_remote_identity(ptr0, len0);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    let v2;
    if (ret[0] !== 0) {
        v2 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    }
    return v2;
}

/**
 * A sender certificate chained to a test trust root (`trust_root_private`, 32 bytes) instead of Signal's.
 * @param {Uint8Array | number[]} trust_root_private
 * @param {string} sender_aci
 * @param {number} sender_device
 * @param {Uint8Array | number[]} sender_identity_public
 * @param {number} expiration_ms
 * @returns {Uint8Array}
 */
export function test_sender_certificate(trust_root_private, sender_aci, sender_device, sender_identity_public, expiration_ms) {
    const val4 = +sender_device;
    const val5 = +expiration_ms;
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(trust_root_private, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(sender_aci, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(sender_identity_public, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.test_sender_certificate(ptr0, len0, ptr1, len1, val4, ptr2, len2, val5);
    if (ret[3]) {
        throw takeFromExternrefTable0(ret[2]);
    }
    var v6 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
    wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
    return v6;
}

/**
 * Removes the sealed-sender layer addressed to `identity_key_pair` (libsignal IdentityKeyPair
 * serialization). Rejects certificates not signed via Signal's trust roots, expired at
 * `timestamp_ms`, or sent by this very device.
 * @param {Uint8Array | number[]} ciphertext
 * @param {Uint8Array | number[]} identity_key_pair
 * @param {number} timestamp_ms
 * @param {string} local_aci
 * @param {number} local_device
 * @returns {Unsealed}
 */
export function unseal(ciphertext, identity_key_pair, timestamp_ms, local_aci, local_device) {
    const val4 = +timestamp_ms;
    const val5 = +local_device;
    let ptr0, len0, ptr1, len1, ptr2, len2;
    try {
        ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(identity_key_pair, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passStringToWasm0(local_aci, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len2 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.unseal(ptr0, len0, ptr1, len1, val4, ptr2, len2, val5);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return Unsealed.__wrap(ret[0]);
}

/**
 * `unseal`, but validating against a test trust root (`trust_root_public`, 33 bytes).
 * @param {Uint8Array | number[]} ciphertext
 * @param {Uint8Array | number[]} identity_key_pair
 * @param {number} timestamp_ms
 * @param {string} local_aci
 * @param {number} local_device
 * @param {Uint8Array | number[]} trust_root_public
 * @returns {Unsealed}
 */
export function unseal_for_test(ciphertext, identity_key_pair, timestamp_ms, local_aci, local_device, trust_root_public) {
    const val5 = +timestamp_ms;
    const val6 = +local_device;
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
    try {
        ptr0 = passArray8ToWasm0(ciphertext, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passArray8ToWasm0(identity_key_pair, wasm.__wbindgen_malloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passStringToWasm0(local_aci, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(trust_root_public, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.unseal_for_test(ptr0, len0, ptr1, len1, val5, ptr2, len2, val6, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return Unsealed.__wrap(ret[0]);
}

/**
 * For the receiver self-test: opens one recipient's part of a multi-recipient message the way the
 * server and the recipient do (libsignal `SealedSenderV2SentMessage` + `sealed_sender_decrypt_to_usmc`).
 * @param {Uint8Array | number[]} sent
 * @param {string} recipient_aci
 * @param {number} recipient_device
 * @param {Uint8Array | number[]} identity_key_pair
 * @param {number} timestamp_ms
 * @param {Uint8Array | number[]} trust_root_public
 * @returns {Unsealed}
 */
export function unseal_multi_recipient_for_test(sent, recipient_aci, recipient_device, identity_key_pair, timestamp_ms, trust_root_public) {
    const val5 = +recipient_device;
    const val6 = +timestamp_ms;
    let ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3;
    try {
        ptr0 = passArray8ToWasm0(sent, wasm.__wbindgen_malloc);
        len0 = WASM_VECTOR_LEN;
        ptr1 = passStringToWasm0(recipient_aci, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        len1 = WASM_VECTOR_LEN;
        ptr2 = passArray8ToWasm0(identity_key_pair, wasm.__wbindgen_malloc);
        len2 = WASM_VECTOR_LEN;
        ptr3 = passArray8ToWasm0(trust_root_public, wasm.__wbindgen_malloc);
        len3 = WASM_VECTOR_LEN;
    } catch (e) {
        if (ptr3) { wasm.__wbindgen_free(ptr3, len3 * 1, 1); }
        if (ptr2) { wasm.__wbindgen_free(ptr2, len2 * 1, 1); }
        if (ptr1) { wasm.__wbindgen_free(ptr1, len1 * 1, 1); }
        if (ptr0) { wasm.__wbindgen_free(ptr0, len0 * 1, 1); }
        throw e;
    }
    const ret = wasm.unseal_multi_recipient_for_test(ptr0, len0, ptr1, len1, val5, ptr2, len2, val6, ptr3, len3);
    if (ret[2]) {
        throw takeFromExternrefTable0(ret[1]);
    }
    return Unsealed.__wrap(ret[0]);
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_Error_208446807d0d1e30: function(arg0, arg1) {
            const ret = Error(getStringFromWasm0(arg0, arg1));
            return ret;
        },
        __wbg___wbindgen_string_get_7ce8eee7fd327545: function(arg0, arg1) {
            const obj = arg1;
            const ret = typeof(obj) === 'string' ? obj : undefined;
            var ptr1 = isLikeNone(ret) ? 0 : passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            var len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 1, len1, true);
            getDataViewMemory0().setInt32((arg0 >>> 0) + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_throw_4c88d8bf264fd984: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_getRandomValues_5d8c030b527203a6: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            table.set(0, undefined);
            table.set(1024, undefined);
            table.set(1025, null);
            table.set(1026, true);
            table.set(1027, false);
        },
    };
    return {
        __proto__: null,
        "./signal_sealed_bg.js": import0,
    };
}

const GroupParamsFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_groupparams_free(ptr, 1));
const UnsealedFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_unsealed_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return decodeText(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

let cachedUint32ArrayMemory0 = null;
function getUint32ArrayMemory0() {
    if (cachedUint32ArrayMemory0 === null || cachedUint32ArrayMemory0.byteLength === 0) {
        cachedUint32ArrayMemory0 = new Uint32Array(wasm.memory.buffer);
    }
    return cachedUint32ArrayMemory0;
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function passArray32ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 4, 4) >>> 0;
    getUint32ArrayMemory0().set(arg, ptr / 4);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(bytes) {
    numBytesDecoded += bytes.length;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true });
        cachedTextDecoder.decode();
        numBytesDecoded = bytes.length;
    }
    return cachedTextDecoder.decode(bytes);
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint32ArrayMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (!module.ok) {
            throw new Error(`failed to fetch Wasm: ${module.status} ${module.statusText} fetching '${module.url}'`);
        }

        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

let __wbg_init_promise;
async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;
    if (__wbg_init_promise === undefined) {
        __wbg_init_promise = __wbg_init_once(module_or_path);
        __wbg_init_promise.catch(() => { __wbg_init_promise = undefined; });
    }
    return __wbg_init_promise;
}

async function __wbg_init_once(module_or_path) {

    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('signal_sealed_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
