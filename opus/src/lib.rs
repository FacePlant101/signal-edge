//! libopus for signal-edge's calls: a 48 kHz mono encoder and decoder behind wasm-bindgen, plus the
//! handful of C runtime functions the fixed-point build needs on wasm32-unknown-unknown.

use std::alloc::{Layout, alloc, alloc_zeroed, dealloc, realloc as re_alloc};
use std::ffi::{c_int, c_void};
use wasm_bindgen::prelude::*;

const OPUS_OK: c_int = 0;
const OPUS_APPLICATION_VOIP: c_int = 2048;
const OPUS_SET_BITRATE_REQUEST: c_int = 4002;
const OPUS_SET_VBR_REQUEST: c_int = 4006;
const OPUS_SET_COMPLEXITY_REQUEST: c_int = 4010;
const OPUS_SET_INBAND_FEC_REQUEST: c_int = 4012;
const OPUS_SET_PACKET_LOSS_PERC_REQUEST: c_int = 4014;
const OPUS_SET_DTX_REQUEST: c_int = 4016;
const OPUS_SET_SIGNAL_REQUEST: c_int = 4024;
const OPUS_SIGNAL_VOICE: c_int = 3001;
const SAMPLE_RATE: i32 = 48_000;
/// 120 ms at 48 kHz: the longest packet Opus has.
const MAX_FRAME: usize = 5_760;
/// Enough for any packet at the bitrates we allow (RFC 6716 caps a frame at 1275 bytes).
const MAX_PACKET: usize = 4_000;

unsafe extern "C" {
    fn opus_encoder_get_size(channels: c_int) -> c_int;
    fn opus_encoder_init(st: *mut c_void, fs: i32, channels: c_int, application: c_int) -> c_int;
    fn opus_encode(st: *mut c_void, pcm: *const i16, frame_size: c_int, data: *mut u8, max_data_bytes: i32) -> i32;
    fn opus_encoder_ctl(st: *mut c_void, request: c_int, ...) -> c_int;
    fn opus_decoder_get_size(channels: c_int) -> c_int;
    fn opus_decoder_init(st: *mut c_void, fs: i32, channels: c_int) -> c_int;
    fn opus_decode(st: *mut c_void, data: *const u8, len: i32, pcm: *mut i16, frame_size: c_int, decode_fec: c_int) -> c_int;
    fn opus_strerror(error: c_int) -> *const u8;
}

fn error(code: c_int) -> JsError {
    // opus_strerror returns a static NUL-terminated string.
    let msg = unsafe {
        let p = opus_strerror(code);
        let mut n = 0;
        while *p.add(n) != 0 {
            n += 1;
        }
        String::from_utf8_lossy(std::slice::from_raw_parts(p, n)).into_owned()
    };
    JsError::new(&format!("opus: {msg}"))
}

/// State memory for libopus, 16-byte aligned (as malloc's would be).
struct State {
    ptr: *mut u8,
    layout: Layout,
}

impl State {
    fn new(size: c_int) -> State {
        let layout = Layout::from_size_align(size.max(1) as usize, 16).unwrap();
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "opus: out of memory");
        State { ptr, layout }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        unsafe { dealloc(self.ptr, self.layout) }
    }
}

/// A 48 kHz mono VoIP encoder, set up as RingRTC sets up Opus for 1:1 calls (CBR, in-band FEC, DTX).
#[wasm_bindgen]
pub struct OpusEncoder {
    st: State,
}

#[wasm_bindgen]
impl OpusEncoder {
    /// `bitrate` in bits per second (RingRTC: 32000 at most for 1:1 calls).
    #[wasm_bindgen(constructor)]
    pub fn new(bitrate: i32) -> Result<OpusEncoder, JsError> {
        let st = State::new(unsafe { opus_encoder_get_size(1) });
        let p = st.ptr as *mut c_void;
        let rc = unsafe { opus_encoder_init(p, SAMPLE_RATE, 1, OPUS_APPLICATION_VOIP) };
        if rc != OPUS_OK {
            return Err(error(rc));
        }
        for (request, value) in [
            (OPUS_SET_BITRATE_REQUEST, bitrate.clamp(6_000, 64_000)),
            (OPUS_SET_VBR_REQUEST, 0),
            (OPUS_SET_COMPLEXITY_REQUEST, 9),
            (OPUS_SET_INBAND_FEC_REQUEST, 1),
            (OPUS_SET_PACKET_LOSS_PERC_REQUEST, 10),
            (OPUS_SET_DTX_REQUEST, 1),
            (OPUS_SET_SIGNAL_REQUEST, OPUS_SIGNAL_VOICE),
        ] {
            let rc = unsafe { opus_encoder_ctl(p, request, value) };
            if rc != OPUS_OK {
                return Err(error(rc));
            }
        }
        Ok(OpusEncoder { st })
    }

    /// One frame (2.5, 5, 10, 20, 40 or 60 ms of 48 kHz mono samples) → one Opus packet.
    pub fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>, JsError> {
        if !matches!(pcm.len(), 120 | 240 | 480 | 960 | 1920 | 2880) {
            return Err(JsError::new("opus: a frame is 2.5, 5, 10, 20, 40 or 60 ms of 48 kHz audio"));
        }
        let mut out = vec![0u8; MAX_PACKET];
        let n = unsafe { opus_encode(self.st.ptr as *mut c_void, pcm.as_ptr(), pcm.len() as c_int, out.as_mut_ptr(), MAX_PACKET as i32) };
        if n < 0 {
            return Err(error(n));
        }
        out.truncate(n as usize);
        Ok(out)
    }
}

/// A 48 kHz mono decoder.
#[wasm_bindgen]
pub struct OpusDecoder {
    st: State,
}

#[wasm_bindgen]
impl OpusDecoder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<OpusDecoder, JsError> {
        let st = State::new(unsafe { opus_decoder_get_size(1) });
        let rc = unsafe { opus_decoder_init(st.ptr as *mut c_void, SAMPLE_RATE, 1) };
        if rc != OPUS_OK {
            return Err(error(rc));
        }
        Ok(OpusDecoder { st })
    }

    /// One packet → its samples (stereo packets are mixed down to mono by libopus).
    pub fn decode(&mut self, packet: &[u8]) -> Result<Vec<i16>, JsError> {
        self.run(packet.as_ptr(), packet.len() as i32, MAX_FRAME, 0)
    }

    /// Concealment for `samples` of lost audio (a multiple of 2.5 ms); with `fec_packet` (the packet
    /// after the gap) the loss is rebuilt from its in-band FEC data where it carries some.
    pub fn conceal(&mut self, samples: usize, fec_packet: Option<Vec<u8>>) -> Result<Vec<i16>, JsError> {
        let samples = samples.min(MAX_FRAME);
        match fec_packet {
            Some(p) if !p.is_empty() => self.run(p.as_ptr(), p.len() as i32, samples, 1),
            _ => self.run(std::ptr::null(), 0, samples, 0),
        }
    }

    fn run(&mut self, data: *const u8, len: i32, frame: usize, fec: c_int) -> Result<Vec<i16>, JsError> {
        let mut pcm = vec![0i16; frame];
        let n = unsafe { opus_decode(self.st.ptr as *mut c_void, data, len, pcm.as_mut_ptr(), frame as c_int, fec) };
        if n < 0 {
            return Err(error(n));
        }
        pcm.truncate(n as usize);
        Ok(pcm)
    }
}

// --- C runtime for libopus (no libc on wasm32-unknown-unknown) ---
// libopus only allocates in its *_create functions, which we don't call; these exist so that the
// object files link, and work if anything does call them. Each block remembers its size.

const HEADER: usize = 16;

#[unsafe(no_mangle)]
pub extern "C" fn malloc(n: usize) -> *mut c_void {
    unsafe { raw_alloc(n, false) }
}

#[unsafe(no_mangle)]
pub extern "C" fn calloc(count: usize, n: usize) -> *mut c_void {
    match count.checked_mul(n) {
        Some(total) => unsafe { raw_alloc(total, true) },
        None => std::ptr::null_mut(),
    }
}

unsafe fn raw_alloc(n: usize, zeroed: bool) -> *mut c_void {
    let Ok(layout) = Layout::from_size_align(n + HEADER, HEADER) else { return std::ptr::null_mut() };
    unsafe {
        let base = if zeroed { alloc_zeroed(layout) } else { alloc(layout) };
        if base.is_null() {
            return std::ptr::null_mut();
        }
        (base as *mut usize).write(n);
        base.add(HEADER) as *mut c_void
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn realloc(p: *mut c_void, n: usize) -> *mut c_void {
    if p.is_null() {
        return malloc(n);
    }
    unsafe {
        let base = (p as *mut u8).sub(HEADER);
        let old = (base as *const usize).read();
        let Ok(layout) = Layout::from_size_align(old + HEADER, HEADER) else { return std::ptr::null_mut() };
        let base = re_alloc(base, layout, n + HEADER);
        if base.is_null() {
            return std::ptr::null_mut();
        }
        (base as *mut usize).write(n);
        base.add(HEADER) as *mut c_void
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn free(p: *mut c_void) {
    if p.is_null() {
        return;
    }
    unsafe {
        let base = (p as *mut u8).sub(HEADER);
        let n = (base as *const usize).read();
        dealloc(base, Layout::from_size_align_unchecked(n + HEADER, HEADER));
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn abort() -> ! {
    std::process::abort()
}
