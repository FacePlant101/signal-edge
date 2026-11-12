// Compiles libopus (fetched by scripts/build-opus.sh into opus/libopus at a pinned commit) for
// wasm32-unknown-unknown: the fixed-point build without the float API, the DNN features (deep PLC,
// DRED, OSCE) or any CPU-specific code, against the libc shims in opus/shim/. The source lists are
// libopus's own (celt_sources.mk, silk_sources.mk, opus_sources.mk).

use std::{env, fs, path::PathBuf};

fn sources(mk: &PathBuf, var: &str) -> Vec<String> {
    let text = fs::read_to_string(mk).unwrap_or_else(|e| panic!("{}: {e}", mk.display()));
    let mut out = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if !inside {
            if line == format!("{var} = \\") {
                inside = true;
            }
            continue;
        }
        let file = line.trim_end_matches('\\').trim();
        if !file.is_empty() {
            out.push(file.to_string());
        }
        if !line.ends_with('\\') {
            break;
        }
    }
    assert!(!out.is_empty(), "{var} not found in {}", mk.display());
    out
}

fn main() {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let src = root.join("libopus");
    if !src.join("opus_sources.mk").exists() {
        panic!("opus/libopus is missing: run scripts/build-opus.sh, which fetches libopus at the pinned commit");
    }
    let mut files = Vec::new();
    files.extend(sources(&src.join("celt_sources.mk"), "CELT_SOURCES"));
    files.extend(sources(&src.join("silk_sources.mk"), "SILK_SOURCES"));
    files.extend(sources(&src.join("silk_sources.mk"), "SILK_SOURCES_FIXED"));
    // Only the single-stream API (the encoder uses the repacketizer): multistream and projection aren't used.
    files.extend(sources(&src.join("opus_sources.mk"), "OPUS_SOURCES").into_iter().filter(|f| {
        matches!(f.as_str(), "src/opus.c" | "src/opus_decoder.c" | "src/opus_encoder.c" | "src/extensions.c" | "src/repacketizer.c")
    }));

    let mut build = cc::Build::new();
    build
        .files(files.iter().map(|f| src.join(f)))
        .include(root.join("shim"))
        .include(src.join("include"))
        .include(src.join("celt"))
        .include(src.join("silk"))
        .include(src.join("silk/fixed"))
        .include(src.join("src"))
        .define("OPUS_BUILD", None)
        .define("FIXED_POINT", "1")
        .define("DISABLE_FLOAT_API", None)
        .define("VAR_ARRAYS", "1")
        .define("HAVE_LRINT", "1")
        .define("HAVE_LRINTF", "1")
        .define("PACKAGE_VERSION", "\"1.5.2\"")
        .flag("-nostdinc")
        .flag(&format!("-isystem{}", clang_resource_include()))
        .flag("-fno-math-errno")
        .warnings(false)
        .opt_level(3);
    build.compile("opus");
    println!("cargo:rerun-if-changed=shim");
    println!("cargo:rerun-if-changed=libopus");
}

/// clang's own headers (stddef.h, stdint.h, stdarg.h, limits.h): freestanding, no libc.
fn clang_resource_include() -> String {
    let cc = env::var("CC_wasm32_unknown_unknown").or_else(|_| env::var("CC")).unwrap_or_else(|_| "clang".into());
    let out = std::process::Command::new(&cc).arg("-print-resource-dir").output().expect("clang -print-resource-dir");
    let dir = String::from_utf8(out.stdout).unwrap().trim().to_string();
    format!("{dir}/include")
}
