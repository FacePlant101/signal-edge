#!/usr/bin/env python3
"""Writes THIRD_PARTY_LICENSES.txt: the Rust crates compiled into src/vendor/ (tls/, sealed/ and opus/)
with their license files, taken from each crate as published on crates.io, and the C library opus/
compiles (libopus, its license file kept in opus/LICENSE-libopus).

Run after changing a Cargo.lock or the libopus version:  python3 scripts/third-party-licenses.py
Needs cargo (crates.io index) and network access to static.crates.io. Downloads are cached in
$CRATE_LICENSE_CACHE (default: a temp dir).
"""
import concurrent.futures as cf
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE = os.environ.get("CRATE_LICENSE_CACHE") or os.path.join(tempfile.gettempdir(), "signal-edge-crate-licenses")
LICENSE_FILE = re.compile(r"^(LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICENSE)", re.I)
# Crates whose published package has no license file get the standard text of their declared license.
# Apache-2.0 and MPL-2.0 texts name no copyright holder, so they are taken from a crate that ships the
# unmodified text; MIT names one, so it is filled in with the crate's own authors.
STANDARD_TEXT = {
    "Apache-2.0": ("hashbrown", "0.15.2", "LICENSE-APACHE"),
    "MPL-2.0": ("option-ext", "0.2.0", "LICENSE.txt"),
}
MIT_TEXT = """MIT License

Copyright (c) {holders}

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE."""
CRATES = {"tls": "TLS 1.3 client (src/vendor/signal-tls)", "sealed": "sealed sender and zkgroup (src/vendor/signal-sealed)", "opus": "Opus codec for calls (src/vendor/signal-opus)"}
# C libraries compiled in, not from crates.io: (name, version, where, source, license, license file).
C_LIBRARIES = [("libopus", "1.5.2", "opus", "https://github.com/xiph/opus (tag v1.5.2, fetched by scripts/build-opus.sh)", "BSD-3-Clause", "opus/LICENSE-libopus")]


def linked_crates(crate: str) -> list[dict]:
    """Normal dependencies reachable from the root for wasm32 (no build scripts or dev-dependencies)."""
    meta = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--locked", "--filter-platform", "wasm32-unknown-unknown"], cwd=os.path.join(ROOT, crate)))
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    root = meta["resolve"]["root"]
    seen, todo = set(), [root]
    while todo:
        i = todo.pop()
        if i in seen:
            continue
        seen.add(i)
        todo += [d["pkg"] for d in nodes[i]["deps"] if any(k["kind"] is None for k in d["dep_kinds"])]
    seen.discard(root)
    return [packages[i] for i in seen]


def license_files(name: str, version: str) -> dict[str, str]:
    dest = os.path.join(CACHE, f"{name}-{version}")
    if not os.path.isdir(dest):
        data = urllib.request.urlopen(f"https://static.crates.io/crates/{name}/{name}-{version}.crate", timeout=60).read()
        tmp = dest + ".tmp"
        os.makedirs(tmp, exist_ok=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
            for m in t.getmembers():
                parts = m.name.split("/")
                if len(parts) == 2 and m.isfile() and LICENSE_FILE.match(parts[1]):
                    with open(os.path.join(tmp, parts[1]), "wb") as f:
                        f.write(t.extractfile(m).read())
        os.rename(tmp, dest)
    return {f: open(os.path.join(dest, f), encoding="utf-8", errors="replace").read() for f in sorted(os.listdir(dest))}


def main() -> None:
    os.makedirs(CACHE, exist_ok=True)
    used: dict[tuple[str, str], dict] = {}
    for crate in CRATES:
        for p in linked_crates(crate):
            entry = used.setdefault((p["name"], p["version"]), {"pkg": p, "in": []})
            entry["in"].append(crate)
    registry = [k for k, v in used.items() if (v["pkg"]["source"] or "").startswith("registry")]
    with cf.ThreadPoolExecutor(8) as ex:
        files = dict(zip(registry, ex.map(lambda k: license_files(*k), registry)))
    standard = {lic: license_files(crate, version)[fname] for lic, (crate, version, fname) in STANDARD_TEXT.items()}

    # Group identical license texts so each is printed once, followed by the crates it covers.
    texts: dict[str, dict] = {}
    rows = []
    for key in sorted(used):
        name, version = key
        p = used[key]["pkg"]
        lic = p.get("license") or "(see license file)"
        where = "+".join(sorted(used[key]["in"]))
        if not (p["source"] or "").startswith("registry"):
            rows.append((name, version, lic, where, "libsignal (git), Signal Messenger, LLC: see LICENSE (AGPL-3.0)"))
            continue
        found = files[key]
        if not found:
            found = {}
            for part in re.split(r"\s+(?:OR|AND)\s+|[()/]", lic):
                part = part.strip()
                label = f"{part}, standard text: the published crate has no license file"
                if part in standard:
                    found[label] = standard[part]
                elif part == "AGPL-3.0-only":
                    found[label] = "GNU Affero General Public License v3.0 only: the full text is this repository's LICENSE file."
                elif part == "MIT":
                    found[label] = MIT_TEXT.format(holders=", ".join(p.get("authors") or []) or f"the {name} authors")
            if not found:
                sys.exit(f"{name} {version}: no license file and no standard text for {lic!r}")
        for fname, text in found.items():
            h = hashlib.sha256(text.strip().encode()).hexdigest()
            texts.setdefault(h, {"text": text.strip(), "crates": []})["crates"].append(f"{name} {version} ({fname})")
        authors = ", ".join(p.get("authors") or []) or "see repository"
        rows.append((name, version, lic, where, p.get("repository") or "", authors))

    out = [
        "THIRD-PARTY LICENSES",
        "",
        "The WebAssembly in src/vendor/ (and dist/vendor/ in the package) is compiled from this repository's",
        "tls/, sealed/ and opus/ crates together with the C library and Rust crates below. Each crate is",
        "listed with its declared license, followed by the license files from the crate as published on",
        "crates.io. The libsignal crates come from github.com/signalapp/libsignal and are AGPL-3.0-only,",
        "Copyright Signal Messenger, LLC (see LICENSE and NOTICE). Generated by",
        "scripts/third-party-licenses.py from tls/Cargo.lock, sealed/Cargo.lock and opus/Cargo.lock; in =",
        "which WASM module includes it.",
        "",
        "=" * 100,
        "C LIBRARIES",
        "=" * 100,
        "",
    ]
    for name, version, where, source, lic, fname in C_LIBRARIES:
        out += [f"{name} {version}  [{lic}]  in: {where}", f"    {source}"]
        text = open(os.path.join(ROOT, fname), encoding="utf-8").read().strip()
        h = hashlib.sha256(text.encode()).hexdigest()
        texts.setdefault(h, {"text": text, "crates": []})["crates"].insert(0, f"{name} {version} ({fname})")
    out += ["", "=" * 100, "CRATES", "=" * 100, ""]
    for r in rows:
        name, version, lic, where = r[:4]
        out.append(f"{name} {version}  [{lic}]  in: {where}")
        if len(r) == 5:
            out.append(f"    {r[4]}")
        else:
            out.append(f"    {r[4]}" if r[4] else "    (no repository listed)")
            out.append(f"    authors: {r[5]}")
    for t in sorted(texts.values(), key=lambda t: t["crates"][0]):
        out += ["", "=" * 100, "Applies to: " + ", ".join(t["crates"]), "=" * 100, "", t["text"]]
    path = os.path.join(ROOT, "THIRD_PARTY_LICENSES.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    missing = [f"{n} {v}" for (n, v) in registry if not files[(n, v)]]
    print(f"{len(used)} crates, {len(texts)} distinct license texts -> {os.path.relpath(path, ROOT)}")
    if missing:
        print("no license file in the published crate (standard text used):", ", ".join(missing))


if __name__ == "__main__":
    sys.exit(main())
