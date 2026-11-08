/**
 * signal-edge: a Signal linked-device client for WASM runtimes. Runtime-neutral entry point; on
 * Cloudflare Workers import "signal-edge/workers" instead (it also sets up sockets and WASM).
 */

// The client
export {
	SignalClient,
	SIGNAL_TABLES,
	type SignalClientOptions,
	type LinkState,
	type ReceiveState,
	type KeyRefreshResult,
	type DirectorySync,
	type DirectSendResult,
	type GroupSendResult,
	type OutgoingFile,
	type MessageExtras,
	type Chat,
	type GroupInfo,
} from "./client.js";

// Host plumbing
export { configure, type Runtime, type Connect, type RawSocket, type WasmModules, type WasmSource } from "./runtime.js";
export { type SqlDatabase, type SqlValue } from "./sql.js";
export { Sealer } from "./util/sealer.js";

// Network: HTTPS and WebSockets to Signal hosts over TLS pinned to Signal's roots
export { signalFetch, type HttpResponse } from "./net/http.js";
export { TlsSocket } from "./net/tls.js";
export { WsClient, type WsHandlers } from "./net/websocket.js";
export { SignalSocket, CHAT_HOST, type SignalSocketHandlers } from "./protocol/socket.js";

// Protocol building blocks, for callers that drive the protocol themselves
export { ProtocolStore, createStoreSchema, type OurIdentity } from "./protocol/store.js";
export { IdentityLog, createIdentitySchema, type IdentityCheck } from "./protocol/identities.js";
export { MessageStore, createMessageSchema, type StoredMessage, type Conversation } from "./protocol/messages.js";
export { receiveEnvelope, type Self, type ReceiveResult } from "./protocol/receiver.js";
export { sendToServiceId, dataMessage, contentWithData, contentWithSentTranscript, padMessage, type SendContext, type SendOptions } from "./protocol/sender.js";
export {
	decodeEnvelope,
	parseContent,
	unpad,
	extractMentions,
	ACI_PATTERN,
	ENVELOPE,
	CIPHERTEXT,
	type Envelope,
	type MessageRecord,
	type Attachment,
	type Mention,
	type ParsedContent,
} from "./protocol/content.js";
export { ChatTimers, createTimerSchema, type Expiry, type TimerSeen } from "./protocol/timers.js";
export { sendWithSenderKey, senderKeyUsable, SenderKeyShares, createSenderKeySchema } from "./protocol/sender-keys.js";
export { Counters, createCounterSchema, describeCounters, FEATURE_COUNTERS, type LastingCounter, type LastError } from "./counters.js";
export { DecryptFailure, SendLog, SeenEnvelopes, createRetrySchema, type FailedMessage } from "./protocol/retry.js";
export { Directory, createDirectorySchema, groupIdFromMasterKey, fetchGroupState, fetchCredentials, type GroupRecord, type GroupMember, type Contact } from "./protocol/groups.js";
export { readStorage, STORAGE_HOST, type StorageSnapshot, type StorageContact, type StorageGroup } from "./protocol/storage-service.js";
export { downloadAttachment, decryptAttachment, uploadAttachment, attachmentPointer, LONG_TEXT_TYPE, type AttachmentPointer } from "./protocol/attachments.js";
export { accessKey, unseal, libsignalExtra, CONTENT_HINT } from "./protocol/sealed.js";
export { signal } from "./protocol/wasm.js";
export { encode as encodeProto, Decoded as ProtoDecoded } from "./protocol/proto.js";
export { fromBase64, toBase64, randomBytes } from "./util/bytes.js";
