#!/usr/bin/env python3
"""warpgate-notices.py -- writes the static Warpgate package's THIRD-PARTY-NOTICES.txt.

warpgate-build-static.yml runs it in a CLEAN container of its own that never
runs the fork's code (warpgate-notices-run.sh: the fork's tree as data, every
.cargo entry and toolchain file removed, our pinned nightly, a fresh
CARGO_HOME), on the JSON that `cargo about generate --format json` printed for
the release's own Cargo.lock, the `warpgate` package, one musl target
(x86_64-unknown-linux-musl, or aarch64-unknown-linux-musl for its own file: the
two link different crate sets, so each target has its own notices) and the
feature set the binary is built with. cargo-about decides WHICH crates
are linked and under WHICH licence each is taken; this file checks that answer
is whole and lays it out. It reads no network and runs none of the fork's code.

THE LICENCE POLICY LIVES HERE, IN RUNCOVE: WARPGATE_ACCEPTED and the reviewed
lists below. The accepted list was copied from the fork's deny.toml when this
file was written; deny.toml is never read at build time, and a change to it
changes nothing here until a reviewed runcove change does.

THE ENGINE IS CLOUD HYPERVISOR'S. ch-ci/scripts/third-party-notices.py (the
static Cloud Hypervisor build's writer) holds the hardened parts: the SPDX
reading, the one-open-file reads that refuse a symlink, a FIFO, a non-UTF-8
or an oversized file, the native-code search and the toolchain page's
conversion to text. This file loads it by path (--engine) and uses those
parts unchanged; what is Warpgate's -- its own crates, the crates it carries
in its tree, the native code audit, the accepted licences and the layout --
is here.

THE FILE, in order (plain UTF-8, LF, no dates, no absolute paths, sorted, so
the same Cargo.lock and toolchain give the same bytes):
  1. Warpgate itself: its licence, its own crates in the binary, then the
     fork's LICENSE, verbatim;
  2. every other linked crate (from crates.io, or carried in the fork's tree
     under IN_TREE): name, version, where it came from, the licence it
     declares and the licence texts (by number) it is taken under;
  3. the notice and copyright files those crates ship (NOTICE*, COPYRIGHT*),
     and the licence files of the crates in VERBATIM;
  4. the licence texts, each once, with the crates it applies to;
  5. the licence files of native (C, assembly) code crates bundle and compile
     in, from NATIVE_CODE below;
  6. the Rust standard library's notices and licence texts, from the
     toolchain's share/doc/rust, and the musl C library's, compiler runtime's
     and unwinder's, from the zig the build links with.

IT REFUSES (exit 1, naming every reason, writing nothing) when:
  * a linked crate that is not one of Warpgate's own has no licence
    cargo-about could determine, or no licence text, or texts that do not
    satisfy the licence it declares;
  * a crate's only text for a licence is the generic one cargo-about supplies
    and the licence is one whose text carries the copyright line (anything
    but GENERIC_TEXT_IS_WHOLE), unless VERBATIM lists that crate and version
    (its own files are then laid out whole in part 3), or NO_LICENCE_FILE
    does AND its package really holds no licence file (then its authors and
    repository from Cargo.toml are named beside the text);
  * a crate with no registry or git source is neither in OWN_CRATES nor in
    IN_TREE, each in its own directory of the source tree;
  * a crate that may carry native code has no NATIVE_CODE entry for exactly
    that version from crates.io, or a file its entry names is not there;
  * a crate is taken under MPL-2.0 from anywhere but crates.io (MPL-2.0
    section 3.2: its entry in part 2 names where its source is, a crates.io
    URL of the exact version);
  * a crate is taken under a licence not on ACCEPTED (the workflow's
    cargo-about config holds the same list; this is the second reading);
  * any file it would copy in is not a plain, readable UTF-8 file inside the
    tree it belongs to, or the toolchain's notices are missing or not what
    they should be.

PART 7 FROM ANOTHER TARGET'S FILE. The web interface is the same for every target,
so the aarch64 file's part 7 is the x86_64 file's, byte for byte:
`--base <aarch64 parts 1 to 6> --part7-from <the x86_64 final file>
--part7-after-sha256 <the sha256 of the x86_64 parts 1 to 6>` writes the base
followed by the bytes of that file after its parts 1 to 6. The cut is where the
part 7 heading starts AND the bytes before it hash to the given digest; no such
place, or more than one, is refused.

Usage: warpgate-notices.py --engine FILE --about-json FILE --src DIR
           --rust-doc DIR --rustc-version TEXT --zig-dir DIR --zig-version TEXT
           --out FILE [--target x86_64-unknown-linux-musl|aarch64-unknown-linux-musl]
Exit: 0 written; 1 refused (the reasons are on stderr); 2 bad usage.
"""

import argparse
import base64
import gzip
import hashlib
import http.client
import importlib.util
import io
import json
import os
import pathlib
import re
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.request
import zlib

ROOT_CRATE = "warpgate"
MUSL = "x86_64-unknown-linux-musl"
MUSL_ARM = "aarch64-unknown-linux-musl"
MUSL_TARGETS = (MUSL, MUSL_ARM)
DARWIN = "aarch64-apple-darwin"
OWN_FILES = ("LICENSE",)
# Warpgate's own crates that this binary links, each in the source tree's
# directory of the same name. A crate with no registry or git source that is
# neither here nor in IN_TREE fails the build: review it, then add it in a
# reviewed change.
WARPGATE_OWN_CRATES = frozenset((
    "warpgate", "warpgate-admin", "warpgate-aws", "warpgate-ca", "warpgate-common", "warpgate-common-cache",
    "warpgate-common-http", "warpgate-core", "warpgate-db-entities", "warpgate-db-migrations",
    "warpgate-desktop-auth", "warpgate-desktop-ui", "warpgate-ldap", "warpgate-protocol-http",
    "warpgate-protocol-kubernetes", "warpgate-protocol-mysql", "warpgate-protocol-postgres",
    "warpgate-protocol-rdp", "warpgate-protocol-ssh", "warpgate-protocol-vnc", "warpgate-secrets-vault",
    "warpgate-sso", "warpgate-tls", "warpgate-version", "warpgate-web", "warpgate-web-clients-common",
    "warpgate-web-desktop", "warpgate-web-ssh"))
# Other people's code the fork carries in its own tree (no registry source):
# laid out with the third-party crates, under their own licence texts. The
# directory, relative to the tree, and what it is.
IN_TREE = {
    "warpgate-database-protocols": ("warpgate-database-protocols", "derived from SQLx's database protocol code"),
    "ironrdp-async": ("vendor/ironrdp-async", "a patched copy of the crates.io crate"),
    "ironrdp-connector": ("vendor/ironrdp-connector", "a patched copy of the crates.io crate"),
    "ironrdp-dvc": ("vendor/ironrdp-dvc", "a patched copy of the crates.io crate"),
    "ironrdp-egfx": ("vendor/ironrdp-egfx", "a patched copy of the crates.io crate"),
    "ironrdp-graphics": ("vendor/ironrdp-graphics", "a patched copy of the crates.io crate"),
    "ironrdp-pdu": ("vendor/ironrdp-pdu", "a patched copy of the crates.io crate"),
    "ironrdp-server": ("vendor/ironrdp-server", "a patched copy of the crates.io crate"),
    "ironrdp-session": ("vendor/ironrdp-session", "a patched copy of the crates.io crate"),
    "picky": ("vendor/picky", "a patched copy of the crates.io crate"),
    "russh": ("vendor/russh", "a patched copy of the crates.io crate"),
    "sspi": ("vendor/sspi", "a patched copy of the crates.io crate"),
    "vnc-rs": ("vendor/vnc-rs", "a patched copy of the crates.io crate"),
}
# The licences a release may carry, in the order one is chosen when a crate
# offers several: the `accepted` list of warpgate-notices-run.sh's cargo-about
# config, read a second time here (test_warpgate_notices.py holds the two
# equal). RUNCOVE'S POLICY: copied on 17 Oct 2026 from the fork's deny.toml
# [licenses] allow list, which is never read at build time, and measured
# against v0.29.1-cove.26's graph for this target and these features: each
# one is the only choice of at least one linked crate.
WARPGATE_ACCEPTED = ("Apache-2.0", "MIT", "BSD-3-Clause", "ISC", "MPL-2.0", "Unicode-3.0", "Unicode-DFS-2016",
                     "BSD-2-Clause", "Zlib", "CC0-1.0", "CDLA-Permissive-2.0", "Unlicense", "WTFPL", "IJG")
# Licences whose text names no copyright holder, so the generic text is the
# whole of what the licence asks to be reproduced (the engine's own list).
GENERIC_TEXT_IS_WHOLE = ("Apache-2.0", "MPL-2.0")
# Crates that ship NO licence file at all in their package, so the generic
# text, with the authors their Cargo.toml names, is all there is to carry.
# Each entry speaks for one version from crates.io: the ones v0.29.1-cove.26's
# graph needed with cargo-about 0.9.2 (17 Oct 2026), and rustify_derive 0.5.5,
# which v0.30.0 brings in (its package holds only Cargo.toml, Cargo.lock,
# README.md and src/; 20 Oct 2026). Another version fails the build until it
# is looked at again (does it ship a licence file now?).
NO_LICENCE_FILE = frozenset((
    ("base64-simd", "0.8.0"), ("dotenv", "0.15.0"), ("governor", "0.10.4"), ("lazy-regex-proc_macros", "3.6.0"),
    ("phf", "0.8.0"), ("phf_shared", "0.8.0"), ("rustify_derive", "0.5.5"), ("sea-bae", "0.2.1"),
    ("seahash", "4.1.0"), ("vsimd", "0.8.0"), ("vtparse", "0.6.2"), ("wezterm-input-types", "0.1.0")))
# Crates whose own licence file cargo-about cannot match to the licence they
# declare (a combined file, extra notices, a narrower layout, another text),
# so it supplies the generic text: their files are laid out VERBATIM in part
# 3, which is what carries their copyright lines, and the generic text is
# then accepted beside them. One version from crates.io each, measured on
# v0.29.1-cove.26's graph with cargo-about 0.9.2 (17 Oct 2026); aws-lc-rs and
# aws-lc-sys moved to v0.30.0's versions, whose LICENSE files are byte for
# byte the earlier ones' (20 Oct 2026), and again to v0.30.2-cove.5's
# (aws-lc-rs 1.19.0, aws-lc-sys 0.47.0; 30 Oct 2026), the same files again.
VERBATIM = {
    "async-stream": ("0.3.6", ("LICENSE",), "its MIT text, laid out in narrower lines"),
    "async-stream-impl": ("0.3.6", ("LICENSE",), "its MIT text, laid out in narrower lines"),
    "aws-lc-rs": ("1.19.0", ("LICENSE",), "one file holding its Apache-2.0 and ISC texts"),
    "aws-lc-sys": ("0.47.0", ("LICENSE",), "one file describing each part of AWS-LC and the licences of each"),
    "curve25519-dalek": ("4.1.3", ("LICENSE",), "its BSD-3-Clause text with the project's own notices"),
    "finl_unicode": ("1.4.0", ("LICENSE-UNICODE",), "it declares Unicode-DFS-2016; its file is the Unicode "
                                                    "License V3"),
    "jpeg-encoder": ("0.7.1", ("LICENSE-IJG",), "the crate's own statement of its IJG terms"),
    "libm": ("0.2.16", ("LICENSE.txt",), "its MIT text with the notices of the code it is derived from"),
    "wezterm-bidi": ("0.2.3", ("LICENSE.md",), "its MIT text and the Unicode data notice in one file"),
}
LICENCE_FILE = re.compile(r"(LICEN[CS]E|COPYING|UNLICENSE)([-._][A-Za-z0-9._-]*)?", re.I)
# NATIVE CODE CRATES BUNDLE, as the engine's own table: every linked crate
# that MAY carry native code (a `links` key, a -sys name, a C, C++ or
# assembly file, or a symlink in its package) is listed with each VERSION
# that was looked at, the licence files that cover what it bundles (or none)
# and why. Measured on v0.29.1-cove.26's graph from the crates.io packages
# (17 Oct 2026); ring and zstd-sys are the Cloud Hypervisor build's entries.
# aws-lc-rs and aws-lc-sys moved to v0.30.0's versions (20 Oct 2026): the same
# licence files, byte for byte, and the same kind of package. They and
# libz-sys (1.1.31) moved to v0.30.2-cove.5's versions (30 Oct 2026): the same
# licence files, byte for byte, and the same package layout.
# The four macOS-only -sys crates (21 Oct 2026, the first darwin notices run,
# 22625): bindings to Apple's system frameworks, checked against the fork
# lockfile's checksums at v0.30.0 -- no C, C++ or assembly in any of them.
NATIVE_CODE = {
    "aws-lc-rs": (("1.19.0", (), "a `links` key only; the C it uses is aws-lc-sys's"),),
    # AWS-LC: BoringSSL- and OpenSSL-derived C and assembly, fiat-crypto,
    # s2n-bignum and others, compiled by its build script. aws-lc/LICENSE
    # describes each part (the s2n-bignum and jitterentropy licence files it
    # points to are not in the crates.io package).
    # The crate's own LICENSE is in VERBATIM (part 3).
    "aws-lc-sys": (("0.47.0", ("aws-lc/LICENSE", "aws-lc/third_party/fiat/LICENSE"),
                    "AWS-LC's C and assembly, compiled by its build script"),),
    "core-foundation-sys": (("0.8.7", (), "a -sys name only: Rust declarations of CoreFoundation's C API; "
                                          "no build script, no C"),),
    "crc-fast": (("1.10.0", (), "libcrc_fast.h declares the crate's own C API for other programs; no C is compiled"),),
    "cryptoki-sys": (("0.5.0", (), "vendor/pkcs11.h (public domain) only feeds bindgen; no C is compiled"),),
    "fancy-regex": (("0.11.0", (), "the C under tests/ is a test fixture, never compiled in"),),
    "fsevent-sys": (("4.1.0", (), "a -sys name only: Rust declarations of CoreServices' FSEvents API; "
                                  "no build script, no C"),),
    "inotify-sys": (("0.1.5", (), "a -sys name only: Rust declarations of the C library's inotify calls"),),
    "libloading": (("0.8.9", (), "the DLLs under tests/ are test fixtures, never linked"),),
    "libsqlite3-sys": (("0.30.1", (), "the bundled SQLite amalgamation, compiled by its build script, is in the "
                                     "public domain and carries no licence file"),),
    "libz-sys": (("1.1.31", ("src/zlib/LICENSE",), "the zlib C library, compiled by its build script"),),
    "linux-raw-sys": (("0.12.1", (), "a -sys name only: Rust bindings generated from Linux's headers"),),
    "nix": (("0.29.0", (), "the C under test/ is a test kernel module, never compiled in"),
            ("0.30.1", (), "the C under test/ is a test kernel module, never compiled in"),
            ("0.31.3", (), "the C under test/ is a test kernel module, never compiled in")),
    "pgwire": (("0.40.7", (), "the C under tests-integration/ is a test client, never compiled in"),),
    "rayon-core": (("1.13.0", (), "a `links` key only, to keep one copy of the crate; no C"),),
    "ring": (("0.17.14",
              ("LICENSE", "LICENSE-BoringSSL", "LICENSE-other-bits", "third_party/fiat/LICENSE",
               "src/polyfill/once_cell/LICENSE-APACHE", "src/polyfill/once_cell/LICENSE-MIT"),
              "BoringSSL and fiat-crypto C and assembly, compiled by its build script"),),
    "security-framework-sys": (("2.17.0", (), "a -sys name only: Rust declarations of the Security "
                                             "framework's C API; no build script, no C"),),
    "signal-hook": (("0.3.18", (), "src/low_level/extract.c is the crate's own code, under the crate's licence"),),
    "system-configuration-sys": (("0.6.0", (), "a -sys name only: Rust declarations of the "
                                               "SystemConfiguration framework; its build script only links it"),),
    "walkdir": (("2.5.0", (), "compare/nftw.c is a benchmark comparison, never compiled in"),),
    # jemalloc (runcove-adcaz.36): the static build's allocator candidate. The C
    # under jemalloc/ is compiled by the build script; jemalloc/COPYING is its
    # BSD-2-Clause licence. The crate's own licence files cover the Rust part.
    "tikv-jemalloc-sys": (("0.6.1+5.3.0-1-ge13ca993e8ccb9ba9847cc330696e02839f328f7", ("jemalloc/COPYING",),
                           "jemalloc's C, compiled by its build script, under jemalloc/COPYING (BSD-2-Clause)"),),
    # 2.1.2 (26 Oct 2026, v0.30.0-cove.10's zstd fix, fork #68): the same zstd C
    # library and zstd/LICENSE byte for byte; LICENSE.BSD-3-Clause now names
    # Meta, and the crate's own licence moved to BSD-3-Clause (its LICENSE).
    # wasm-shim/ holds C headers for wasm targets only, never compiled here.
    "zstd-sys": (("2.0.16+zstd.1.5.7", ("LICENSE.BSD-3-Clause", "zstd/LICENSE"),
                  "the zstd C library, compiled by its build script, taken under BSD-3-Clause"),
                 ("2.1.2+zstd.1.5.7", ("LICENSE.BSD-3-Clause", "zstd/LICENSE"),
                  "the zstd C library, compiled by its build script, taken under BSD-3-Clause")),
}
# The nightly the fork pins ships a 1.5 MB COPYRIGHT-library.html (measured,
# nightly-2026-07-09), over the engine's 1 MiB cap; every file read here may
# be up to this size instead.
MAX_FILE_BYTES = 4 * 1024 * 1024
WITH = re.compile(r"\s+WITH\s+")
# ---- part 7: the web interface's npm packages ----
# The licences an npm package in the web bundle may be taken under: RUNCOVE'S
# POLICY for npm, a list of its own (the cargo one above is for crates). A
# `WITH` exception is never accepted, nor is a copyleft licence: the web
# interface is compiled into the binary, so an AGPL or GPL package in it would
# be Warpgate's to answer for. An SPDX expression is met when its AND/OR
# structure is (engine.satisfied).
NPM_ACCEPTED = ("MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause", "0BSD", "Apache-2.0", "OFL-1.1", "CC-BY-4.0",
                "CC0-1.0", "Unlicense", "Python-2.0", "BlueOak-1.0.0")
# Packages whose tarball holds no licence text, each reviewed by a person and
# given a text of ours to carry instead: "name@version" -> (the file, in the
# reviewed directory (--npm-reviewed, warpgate-ci/npm-licences), its sha256 as
# the engine reads it (LF, one final newline: `sha256sum` of a file already in
# that shape), the licence it must be declared under, and why). A package whose
# package.json declares no licence needs an entry too, and is taken under the
# entry's licence: the lockfile is the fork's, and never supplies one. One version
# each: another version fails the build until it is looked at again (does its
# tarball carry a licence now?).
NPM_REVIEWED = {
    "to-data-view@1.1.0": (
        "to-data-view-1.1.0.txt", "d52986229054795e6869aab189ccd3ca801335835b7f8e61ad0d199967a9fb1e", "MIT",
        "its tarball and its repository (github.com/LinusU/to-data-view) hold no licence file; package.json "
        "declares MIT and names no copyright holder, so the standard MIT text is carried, saying so"),
}
# Packages taken under one permissive alternative of a dual licence (an OR
# with a copyleft licence) whose licence file names the copyleft one: each
# reviewed by a person. "name@version" -> (the licence expression it must
# declare, exactly, and why). Only these may have such a text; one version each.
NPM_DUAL = {}
NPM_REGISTRY = "registry.npmjs.org"
# A name (and a scope) never starts with a dot, so "." and ".." are not names.
NPM_NAME = re.compile(r"(@[A-Za-z0-9_~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9_~-][A-Za-z0-9._~-]*")
NPM_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+-]{0,99}")
# The files of a package that carry its licence: LICENSE, LICENCE, COPYING,
# UNLICENSE, NOTICE and COPYRIGHT files (any suffix but a code one, and a word
# before it, as in MIT-LICENSE), and the files of a licence-named directory one
# level down (pagefind ships LICENSE/). NOTICE and COPYRIGHT files are carried
# but do not count as the licence text: NPM_LICENCE_TEXT says which do.
NPM_TEXT_FILE = re.compile(r"([A-Za-z0-9]+[-_])?(LICEN[CS]ES?|COPYING|UNLICENSE|NOTICE|COPYRIGHT)"
                           r"([-._][A-Za-z0-9._-]*)?", re.I)
NPM_LICENCE_TEXT = re.compile(r"([A-Za-z0-9]+[-_])?(LICEN[CS]ES?|COPYING|UNLICENSE)([-._/][A-Za-z0-9._/-]*)?", re.I)
NPM_TEXT_DIR = re.compile(r"LICEN[CS]ES?", re.I)
# Each part of a licence file's path, as it goes into a `---- name@ver: file ----` header.
NPM_PATH_PART = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]*")
NPM_CODE_SUFFIX = frozenset(("js", "mjs", "cjs", "ts", "mts", "cts", "json", "map", "html", "css", "py", "sh"))
# A copyleft licence named in a text of a package taken under an accepted
# licence, by its title or a versioned id: the text and the declared licence
# disagree, so it is refused. A bare "GPL" is not one (Font Awesome's licence
# calls it "GPL friendly").
NPM_COPYLEFT = re.compile(r"GNU\s+(?:Affero\s+|Lesser\s+|Library\s+)?General\s+Public\s+Licen[cs]e"
                          r"|\b(?:A|L)?GPL(?:-|\s*v(?:ersion)?\s*)?[0-9]", re.I)
NPM_MAX_TARBALL = 64 * 1024 * 1024      # compressed, as downloaded
NPM_FETCH_DEADLINE = 300                # seconds for one tarball, every try included
NPM_MAX_UNPACKED = 256 * 1024 * 1024    # what the tarball may unpack to while it is read
NPM_MAX_MEMBER = 64 * 1024 * 1024       # one entry of it
NPM_MAX_MEMBERS = 50_000
NPM_MAX_MAP_BYTES = 64 * 1024 * 1024    # a source map of the bundle (the engine's cap is for licence files)
NPM_MAX_BASE_BYTES = 256 * 1024 * 1024  # the notices file parts 1 to 6 were written to


def load_engine(path):
    spec = importlib.util.spec_from_file_location("third_party_notices_engine", path)
    if spec is None or spec.loader is None:
        raise OSError(f"cannot load the engine {path}")
    engine = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(engine)
    engine.MAX_FILE_BYTES = MAX_FILE_BYTES
    return engine


def satisfied(engine, expression, have):
    """The engine's SPDX reading, with `A WITH B` read as one licence id
    (`A+WITH+B`): an expression such as rustix's `Apache-2.0 WITH
    LLVM-exception OR Apache-2.0 OR MIT` is met by its plain alternatives."""
    return engine.satisfied(WITH.sub("+WITH+", expression), {WITH.sub("+WITH+", h) for h in have})


def build(engine, about, src, rust_doc, rustc_version, zig_dir, zig_version, target=MUSL):
    """Parts 1 to 6 of the file, or engine.Refused with every reason. For the
    darwin target there is no zig: libSystem is the operating system's."""
    problems = []
    musl = target in MUSL_TARGETS
    arch = "aarch64" if target == MUSL_ARM else "x86_64"
    src = pathlib.Path(src).resolve()
    read = engine.read_inside

    own_texts = [(rel, read(src, rel, problems, f"Warpgate's own {rel}")) for rel in OWN_FILES]

    # ---- what the toolchain links in (the engine's checks, unchanged) ----
    for label, value in (("rustc", rustc_version),) + ((("zig", zig_version),) if musl else ()):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,99}", value or ""):
            problems.append(f"the {label} version {value!r} is not one plain line")
    toolchain = []
    page = read(rust_doc, engine.RUST_COPYRIGHT, problems, f"the Rust toolchain's {engine.RUST_COPYRIGHT}")
    if page is not None:
        text, unknown = engine.html_text(page)
        if unknown:
            problems.append(f"the Rust toolchain's {engine.RUST_COPYRIGHT} uses {', '.join(unknown)}, which this "
                            "does not know how to turn into text")
        if "Copyright notices for The Rust Standard Library" not in text:
            problems.append(f"the Rust toolchain's {engine.RUST_COPYRIGHT} is not the standard library's "
                            "copyright page")
        in_tree = text.partition("## In-tree files")[2].partition("## Out-of-tree dependencies")[0]
        named = set(re.findall(r"[A-Za-z0-9.+-]+", " ".join(re.findall(r"^License: (.*)$", in_tree, re.M))))
        unlisted = sorted(named - {"AND", "OR", "WITH"} - set(engine.RUST_LICENCES))
        if unlisted or not named:
            problems.append(f"the Rust standard library's own tree names the licences {unlisted or 'none'}, "
                            f"whose text RUST_LICENCES in third-party-notices.py does not carry")
        toolchain.append((f"Rust standard library ({rustc_version}): {engine.RUST_COPYRIGHT}, as text", text))
    for lid in engine.RUST_LICENCES:
        body = read(rust_doc, f"licenses/{lid}.txt", problems, f"the Rust toolchain's licenses/{lid}.txt")
        toolchain.append((f"Rust standard library ({rustc_version}): licenses/{lid}.txt", body))
    for rel, label in engine.ZIG_FILES if musl else ():
        body = read(zig_dir, rel, problems, f"zig's {rel}")
        toolchain.append((f"{label.replace('static binaries are', 'static binary is')}, from zig {zig_version}: "
                          f"{rel}", body))

    crates = {}
    for entry in about.get("crates", []):
        pkg = entry["package"]
        key = (pkg["name"], pkg["version"], pkg.get("source") or "")
        for field in key[:2] + (key[2] or "-", entry.get("license") or "-"):
            if not isinstance(field, str) or not engine.PLAIN.fullmatch(field):
                problems.append(f"a crate's name, version, source or licence is not one plain line: {field!r}")
        if key in crates:
            problems.append(f"{key[0]} {key[1]} is listed twice")
        authors = pkg.get("authors") or []
        if not isinstance(authors, list) or not all(isinstance(a, str) and engine.PLAIN.fullmatch(a)
                                                    for a in authors):
            problems.append(f"{key[0]} {key[1]}: its authors are not plain lines")
            authors = []
        repository = pkg.get("repository") or ""
        if not isinstance(repository, str) or (repository and not engine.PLAIN.fullmatch(repository)):
            problems.append(f"{key[0]} {key[1]}: its repository is not one plain line")
            repository = ""
        crates[key] = {"declared": entry.get("license") or "", "ids": {}, "generic": set(),
                       "links": pkg.get("links"), "authors": sorted(authors), "repository": repository,
                       "dir": pathlib.Path(pkg["manifest_path"]).resolve().parent}

    texts = {}
    for lic in about.get("licenses", []):
        if not isinstance(lic.get("id"), str) or not engine.PLAIN.fullmatch(lic["id"]):
            problems.append(f"a licence id is not one plain line: {lic.get('id')!r}")
            continue
        text = engine.clean(lic.get("text") or "")
        for use in lic.get("used_by", []):
            c = use["crate"]
            key = (c["name"], c["version"], c.get("source") or "")
            if key not in crates:
                problems.append(f"{key[0]} {key[1]} has a licence text but is not in the crate list")
                continue
            if not text.strip():
                problems.append(f"{key[0]} {key[1]}: the {lic['id']} text is empty")
                continue
            crates[key]["ids"].setdefault(lic["id"], set()).add(text)
            if not lic.get("source_path"):
                crates[key]["generic"].add((lic["id"], text))
            texts.setdefault((lic["id"], text), set()).add(key)

    own, third, bare = [], [], set()
    for key in sorted(crates):
        name, version, source = key
        rec = crates[key]
        label = f"{name} {version}"
        if not source:
            if name in WARPGATE_OWN_CRATES and rec["dir"] == src / name:
                own.append(key)
                continue
            if name not in IN_TREE or rec["dir"] != src / IN_TREE[name][0]:
                problems.append(f"{label} has no registry or git source and is neither one of Warpgate's own "
                                f"crates nor a crate the fork carries, in its own directory: review it, then add "
                                f"it to WARPGATE_OWN_CRATES or IN_TREE in warpgate-notices.py")
                continue
        third.append(key)
        if not rec["ids"]:
            problems.append(f"{label}: no licence text (declares {rec['declared'] or 'nothing'!r})")
            continue
        try:
            if not satisfied(engine, rec["declared"], set(rec["ids"])):
                problems.append(f"{label}: declares {rec['declared']!r} but only has text for "
                                + ", ".join(sorted(rec["ids"])))
        except ValueError as e:
            problems.append(f"{label}: {e}")
        for lid, found in sorted(rec["ids"].items()):
            if lid not in WARPGATE_ACCEPTED:
                problems.append(f"{label}: taken under {lid}, which is not on WARPGATE_ACCEPTED in "
                                "warpgate-notices.py")
            if lid == "MPL-2.0" and engine.origin(source) != "crates.io":
                problems.append(f"{label}: taken under MPL-2.0 but from {engine.origin(source) or 'the fork tree'}, "
                                "not crates.io, so no source link can be given for it (MPL-2.0 section 3.2): "
                                "review it")
            generic = {t for i, t in rec["generic"] if i == lid}
            if found != generic or lid in GENERIC_TEXT_IS_WHOLE:
                continue
            kept = VERBATIM.get(name)
            if kept is not None and kept[0] == version and engine.origin(source) == "crates.io":
                continue
            if (name, version) not in NO_LICENCE_FILE or engine.origin(source) != "crates.io":
                problems.append(f"{label}: ships no {lid} text of its own, and a generic {lid} text would drop "
                                "its copyright notice (if its package really has no licence file, list it in "
                                "NO_LICENCE_FILE in warpgate-notices.py)")
                continue
            try:
                held = sorted(n for n in os.listdir(rec["dir"]) if LICENCE_FILE.fullmatch(n))
            except OSError as e:
                problems.append(f"{label}: its package could not be listed ({e.__class__.__name__})")
                continue
            if held:
                problems.append(f"{label}: NO_LICENCE_FILE in warpgate-notices.py lists it, but its package "
                                f"holds {', '.join(held)}: cargo-about did not take its text from it; look again")
            elif not rec["authors"] and not rec["repository"]:
                problems.append(f"{label}: ships no licence file and names no authors and no repository")
            else:
                bare.add(key)

    roots = [k for k in own if k[0] == ROOT_CRATE]
    if len(roots) != 1:
        problems.append(f"expected exactly one {ROOT_CRATE} crate in the source tree, found {len(roots)}")
    elif not crates[roots[0]]["declared"] or crates[roots[0]]["declared"] == "Unknown":
        problems.append(f"{ROOT_CRATE} declares no licence")
    if not third:
        problems.append("no third-party crate at all: the crate list is not the binary's")
    if problems:
        raise engine.Refused(problems)

    used = {k: v & set(third) for k, v in texts.items()}
    used = {k: v for k, v in used.items() if v}
    order = sorted(used, key=lambda k: (k[0], min(used[k]), hashlib.sha256(k[1].encode()).hexdigest()))
    number = {k: f"T{i:03d}" for i, k in enumerate(order, 1)}

    extras, native = [], []
    for key in third:
        d, label = crates[key]["dir"], f"{key[0]} {key[1]}"
        kept = VERBATIM.get(key[0])
        if kept is not None and kept[0] == key[1] and engine.origin(key[2]) == "crates.io":
            for rel in kept[1]:
                body = read(d, rel, problems, f"{label}: {rel}")
                if body is not None:
                    extras.append((key, f"{rel} ({kept[2]})", body))
        for name in sorted(os.listdir(d)) if d.is_dir() else []:
            if engine.EXTRA_FILE.fullmatch(name):
                body = read(d, name, problems, f"{label}: {name}", may_be_empty=True)
                if body is not None and body.strip():
                    extras.append((key, name, body))
        try:
            held = engine.may_hold_native_code(d)
        except OSError as e:
            problems.append(f"{label}: its package could not be searched for native code ({e.__class__.__name__})")
            continue
        flagged = ([f"a `links` key, {crates[key]['links']}"] if crates[key]["links"] else []) \
            + (["a -sys name"] if key[0].endswith("-sys") else []) + ([held] if held else [])
        if not flagged:
            continue
        entries = NATIVE_CODE.get(key[0], ())
        audited = next((e for e in entries if e[0] == key[1]), None)
        if audited is None or engine.origin(key[2]) != "crates.io":
            was = (f"its entries are for {', '.join(e[0] for e in entries)} from crates.io, not this"
                   if entries else "it has no entry")
            problems.append(f"{label} from {engine.origin(key[2]) if key[2] else 'the fork tree'} may bundle native "
                            f"code ({'; '.join(flagged)}) and NATIVE_CODE in warpgate-notices.py does not speak "
                            f"for it ({was}): look at what this version compiles in, then list its licence files, "
                            f"or none and why")
            continue
        _, files, why = audited
        found = [(rel, read(d, rel, problems, f"{label}: {rel}")) for rel in files]
        if files:
            native.append((key, why, found))
    if problems:
        raise engine.Refused(problems)

    def came_from(key):
        if key[2]:
            return engine.origin(key[2])
        where, what = IN_TREE[key[0]]
        return f"the Warpgate source tree, {where} ({what})"

    out = []
    w = out.append
    rule = engine.RULE
    w("THIRD-PARTY NOTICES")
    w("")
    if musl:
        w(f"warpgate-static: Warpgate as one static {arch} Linux binary (musl). It")
        w("contains Warpgate, the Rust crates listed here and the web interface's")
        w("npm packages, compiled in.")
    else:
        w("warpgate-macos: Warpgate as one aarch64 macOS binary. It contains Warpgate,")
        w("the Rust crates listed here and the web interface's npm packages, compiled in.")
    w("")
    w("  1. Warpgate")
    w(f"  2. Crates compiled into the binary ({len(third)})")
    w(f"  3. Licence, notice and copyright files shipped by those crates ({len(extras)})")
    w(f"  4. Licence texts ({len(order)})")
    w(f"  5. Native code bundled by those crates ({len(native)})")
    w("  6. The Rust standard library and the C library" if musl else "  6. The Rust standard library")
    w("  7. The web interface's npm packages")
    w("")
    w(rule)
    w("1. WARPGATE")
    w(rule)
    w("")
    w(f"Licence: {crates[roots[0]]['declared']}")
    w("Its own crates in this binary:")
    for name, version, _ in own:
        w(f"  {name} {version} ({crates[(name, version, '')]['declared'] or 'no licence of its own'})")
    for rel, body in own_texts:
        w("")
        w(f"---- {rel} ----")
        w("")
        w(body.rstrip("\n"))
    w("")
    w(rule)
    w(f"2. CRATES COMPILED INTO THE BINARY ({len(third)})")
    w(rule)
    for key in third:
        name, version, _ = key
        rec = crates[key]
        under = []
        for lid in sorted(rec["ids"]):
            refs = sorted(number[(lid, t)] for t in rec["ids"][lid])
            under.append(f"{lid} [{', '.join(refs)}]")
        w("")
        w(f"{name} {version}")
        w(f"  from: {came_from(key)}")
        w(f"  declares: {rec['declared']}")
        w(f"  taken under: {'; '.join(under)}")
        if "MPL-2.0" in rec["ids"]:
            w(f"  source code: https://crates.io/crates/{name}/{version}")
        kept = VERBATIM.get(name)
        if kept is not None and kept[0] == version and key[2]:
            w(f"  its own licence files, verbatim in part 3: {', '.join(kept[1])}")
        if key in bare:
            w("  ships no licence file; the standard text is given, with:")
            for a in rec["authors"]:
                w(f"    author: {a}")
            if rec["repository"]:
                w(f"    repository: {rec['repository']}")
    w("")
    w(rule)
    w(f"3. LICENCE, NOTICE AND COPYRIGHT FILES SHIPPED BY THOSE CRATES ({len(extras)})")
    w(rule)
    for key, name, body in extras:
        w("")
        w(f"---- {key[0]} {key[1]}: {name} ----")
        w("")
        w(body.rstrip("\n"))
    w("")
    w(rule)
    w(f"4. LICENCE TEXTS ({len(order)})")
    w(rule)
    for k in order:
        w("")
        w(f"---- [{number[k]}] {k[0]} ----")
        w("Applies to: " + ", ".join(f"{n} {v}" for n, v, _ in sorted(used[k])))
        w("")
        w(k[1].rstrip("\n"))
    w("")
    w(rule)
    w(f"5. NATIVE CODE BUNDLED BY THOSE CRATES ({len(native)})")
    w(rule)
    w("")
    w("These crates carry C or assembly that is compiled into the binary. The")
    w("licence files below are theirs, verbatim.")
    for key, why, found in native:
        for rel, body in found:
            w("")
            w(f"---- {key[0]} {key[1]}: {rel} ----")
            w(f"({why})")
            w("")
            w(body.rstrip("\n"))
    w("")
    w(rule)
    if musl:
        w("6. THE RUST STANDARD LIBRARY AND THE C LIBRARY")
        w(rule)
        w("")
        w("The binary is statically linked: the Rust standard library and the C")
        w("library are inside it. These notices are the ones the build's own")
        w(f"toolchain ships: {rustc_version}, and zig {zig_version}, which links the")
        w("binary and supplies the musl C library.")
    else:
        w("6. THE RUST STANDARD LIBRARY")
        w(rule)
        w("")
        w("The Rust standard library is inside the binary. These notices are the")
        w(f"ones the build's own toolchain ships: {rustc_version}. The C library")
        w("(libSystem) is the operating system's and is not part of this package.")
    for heading, body in toolchain:
        w("")
        w(f"---- {heading} ----")
        w("")
        w(body.rstrip("\n"))
    return "\n".join(out) + "\n", len(third), len(order)


# ---------------------------------------------------------------------------
# PART 7. The manifest the fork's build writes (warpgate-web/dist-licenses/
# bundle-licenses.json) is UNTRUSTED -- the fork's code and npm produced it --
# so it is used for one thing only: the SET of name@version pairs. Every
# licence text comes from the npm tarball the fork's package-lock.json pins,
# fetched here, checked against the lockfile's sha512 integrity before a byte
# of it is read, and read in memory (nothing is extracted, so no path in it
# can land anywhere and no link in it is ever followed).
# ---------------------------------------------------------------------------

def read_with_cap(engine, root, rel, cap, problems, what):
    """engine.read_inside with a cap of its own for this one read."""
    was = engine.MAX_FILE_BYTES
    engine.MAX_FILE_BYTES = cap
    try:
        return engine.read_inside(root, rel, problems, what)
    finally:
        engine.MAX_FILE_BYTES = was


def read_file(engine, path, cap, problems, what):
    path = pathlib.Path(path)
    return read_with_cap(engine, path.parent, path.name, cap, problems, what)


def read_raw(path, cap, problems, what):
    """The bytes of the regular file `path` (not a link, a FIFO or over `cap`),
    which must be UTF-8, as they are: part 7 is appended to them, never to a
    rewrite of them."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{what} is not a regular file")
            return None
        raw = b""
        while len(raw) <= cap:
            chunk = os.read(fd, cap + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
        if len(raw) > cap:
            problems.append(f"{what} is over the {cap} bytes this reads")
            return None
        raw.decode("utf-8")
    except UnicodeDecodeError:
        problems.append(f"{what} is not UTF-8")
        return None
    except OSError as e:
        problems.append(f"{what} could not be read ({e.__class__.__name__}: a link, or missing)")
        return None
    finally:
        if fd is not None:
            os.close(fd)
    if not raw.strip():
        problems.append(f"{what} is empty")
        return None
    return raw


def read_json(engine, path, problems, what):
    text = read_file(engine, path, NPM_MAX_MAP_BYTES, problems, what)
    if text is None:
        return None
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as e:
        problems.append(f"{what} is not JSON ({e.__class__.__name__})")
        return None


def strip_brackets(expression):
    """`(A AND B)` as `A AND B`: one pair of outer brackets that wraps the whole."""
    e = re.sub(r"\s+", " ", expression.strip())
    while e.startswith("(") and e.endswith(")"):
        depth = 0
        for n, ch in enumerate(e):
            depth += (ch == "(") - (ch == ")")
            if depth == 0 and n < len(e) - 1:
                return e
        e = e[1:-1].strip()
    return e


def package_json_licence(meta):
    """The licence a package.json declares: `license` as an SPDX string or an
    old `{type}` object, else the old `licenses` list as an OR; None if none."""
    lic = meta.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    if isinstance(lic, str) and lic.strip():
        return lic.strip()
    many = meta.get("licenses")
    if isinstance(many, list) and many:
        types = [m.get("type") if isinstance(m, dict) else m for m in many]
        if all(isinstance(t, str) and t.strip() for t in types):
            return " OR ".join(t.strip() for t in types)
    return None


def lock_entries(lock, problems):
    """{(name, version): {(resolved, integrity, licence)}} from a lockfile
    (version 2 or 3: the `packages` table; a package nested under another's
    node_modules is found by its own last segment)."""
    table = lock.get("packages") if isinstance(lock, dict) else None
    if not isinstance(table, dict) or not table:
        problems.append("the lockfile has no `packages` table (lockfileVersion 2 or 3 is read)")
        return {}
    found = {}
    for key, entry in table.items():
        # A bundled dependency's files are in its parent's tarball, and it has no tarball of its own.
        if not isinstance(entry, dict) or "node_modules/" not in key or entry.get("link") or entry.get("inBundle"):
            continue
        name = entry.get("name") if isinstance(entry.get("name"), str) else key.rpartition("node_modules/")[2]
        version = entry.get("version")
        if isinstance(version, str):
            # A list or an object would be unhashable: stand it in by its type, which fails the checks by name.
            resolved, integrity = (v if isinstance(v, str) or v is None else f"<a JSON {type(v).__name__}>"
                                   for v in (entry.get("resolved"), entry.get("integrity")))
            lic = entry.get("license")
            lic = package_json_licence({"licenses": lic} if isinstance(lic, list) else {"license": lic})
            found.setdefault((name, version), set()).add((resolved, integrity, lic))
    return found


def manifest_set(manifest, problems):
    """The set of (name, version) the manifest names, or None."""
    if not isinstance(manifest, dict) or manifest.get("schema") != 1 or isinstance(manifest.get("schema"), bool):
        problems.append("the bundle manifest is not schema 1")
        return None
    packages = manifest.get("packages")
    if not isinstance(packages, list) or not packages:
        problems.append("the bundle manifest names no packages: the web interface is not packages-free")
        return None
    pairs = set()
    for p in packages:
        name, version = (p.get("name"), p.get("version")) if isinstance(p, dict) else (None, None)
        if not (isinstance(name, str) and isinstance(version, str)
                and NPM_NAME.fullmatch(name) and NPM_VERSION.fullmatch(version)):
            problems.append(f"the bundle manifest has an entry that is not a package name and version: "
                            f"{(name, version)!r}"[:200])
            continue
        pairs.add((name, version))
    return pairs


def source_package_paths(engine, maps_dir, problems):
    """Every package directory that source maps in `maps_dir` name, as its
    lockfile key (`node_modules/a/node_modules/@s/b`: the whole chain, so a
    nested second version is its own entry), or None when there is nothing to
    check."""
    maps_dir = pathlib.Path(maps_dir)
    files = []
    for dirpath, dirnames, filenames in os.walk(maps_dir, followlinks=False):
        for n in list(dirnames):
            if os.path.islink(os.path.join(dirpath, n)):
                problems.append(f"the source maps hold a symlink, {n}: refused")
                dirnames.remove(n)
        files += [os.path.relpath(os.path.join(dirpath, n), maps_dir) for n in filenames if n.endswith(".map")]
    if not files:
        problems.append("the build left no source maps to check the manifest against: the cross-check cannot run")
        return None
    paths, named = set(), 0
    for rel in sorted(files):
        doc = read_json(engine, maps_dir / rel, problems, "a source map")
        sources = doc.get("sources") if isinstance(doc, dict) else None
        if not isinstance(sources, list):
            problems.append(f"the source map {rel[:80]!r} has no `sources` list")
            continue
        for src in sources:
            if not isinstance(src, str) or "node_modules/" not in src:
                continue
            named += 1
            parts = src[src.index("node_modules/"):].split("/")
            chain, n = [], 0
            while n + 1 < len(parts) and parts[n] == "node_modules":
                width = 2 if parts[n + 1].startswith("@") else 1
                chain += parts[n:n + 1 + width]
                n += 1 + width
            # .vite/deps and the like are the bundler's, not packages
            if chain and not any(p.startswith(".") or not p for p in chain):
                paths.add("/".join(chain))
    if named and not paths:
        # pnpm's node_modules/.pnpm/... layout, say: every path would be dropped and nothing checked
        problems.append(f"the source maps name {named} paths under node_modules/ and none of them is a package "
                        "directory this reads (a dotted layout?): the cross-check cannot run")
        return None
    return paths


class _Capped:
    """A reader that refuses to deliver more than `limit` bytes: a gzip bomb
    is stopped while it is being read, not after."""

    def __init__(self, fh, limit):
        self.fh, self.left = fh, limit

    def read(self, n=-1):
        data = self.fh.read(n)
        self.left -= len(data)
        if self.left < 0:
            raise OSError("it unpacks to more than the cap")
        return data


def tarball_texts(engine, data, name, version, label, problems):
    """(package.json's dict, [(file name, text)]) from a verified npm tarball,
    read in memory. Everything must sit under package/; the licence-named
    entries must be plain files (a link there is refused, never followed)."""
    meta, texts, bad = None, [], []
    members = 0
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data)) as gz, \
                tarfile.open(fileobj=_Capped(gz, NPM_MAX_UNPACKED), mode="r|") as tar:
            for member in tar:
                members += 1
                if members > NPM_MAX_MEMBERS:
                    bad.append(f"it holds more than {NPM_MAX_MEMBERS} entries")
                    break
                if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
                    bad.append(f"an entry is a device, a FIFO or another special file ({member.name[:60]!r})")
                    continue
                if member.size > NPM_MAX_MEMBER:
                    bad.append(f"an entry is {member.size} bytes, over the {NPM_MAX_MEMBER} one entry may be")
                    break
                if member.isdir():
                    continue
                raw = member.name
                parts = raw.split("/")
                if raw.startswith("/") or "\\" in raw or "\0" in raw or ".." in parts or parts[0] != "package":
                    bad.append(f"an entry is not under package/ ({raw[:60]!r})")
                    continue
                rel = [p for p in parts[1:] if p]
                if not rel:
                    continue
                top = rel[0]
                is_text = (len(rel) == 1 and NPM_TEXT_FILE.fullmatch(top)
                           and top.rpartition(".")[2].lower() not in NPM_CODE_SUFFIX) or \
                          (len(rel) == 2 and NPM_TEXT_DIR.fullmatch(top)
                           and rel[1].rpartition(".")[2].lower() not in NPM_CODE_SUFFIX)
                wants = is_text or rel == ["package.json"]
                licence_dir = len(rel) == 1 and NPM_TEXT_DIR.fullmatch(top)
                if not (wants or licence_dir):
                    continue
                if not member.isreg():
                    bad.append(f"{'/'.join(rel)} is a link or not a plain file: refused, never followed")
                    continue
                if not wants:
                    continue
                if not all(NPM_PATH_PART.fullmatch(p) for p in rel):
                    bad.append(f"a licence file's path is not plain letters, digits, '.', '_' and '-' "
                               f"({'/'.join(rel)[:60]!r})")
                    continue
                if member.size > engine.MAX_FILE_BYTES:
                    bad.append(f"{'/'.join(rel)} is {member.size} bytes, over the {engine.MAX_FILE_BYTES} "
                               "this copies in")
                    continue
                body = tar.extractfile(member).read(engine.MAX_FILE_BYTES + 1)
                try:
                    text = body.decode("utf-8").lstrip("﻿")
                except UnicodeDecodeError:
                    bad.append(f"{'/'.join(rel)} is not UTF-8")
                    continue
                if rel == ["package.json"]:
                    try:
                        meta = json.loads(text)
                    except (ValueError, RecursionError):
                        bad.append("package.json is not JSON")
                elif text.strip():
                    texts.append(("/".join(rel), engine.clean(text)))
    except (tarfile.TarError, EOFError, OSError, zlib.error) as e:
        bad.append(f"it could not be read as a gzipped tar ({e.__class__.__name__}: {str(e)[:80]!r})")
    for b in sorted(set(bad)):
        problems.append(f"{label}: {b}")
    if not isinstance(meta, dict):
        if not bad:
            problems.append(f"{label}: package/package.json is missing or not a JSON object")
        return None, []
    if meta.get("name") != name or meta.get("version") != version:
        problems.append(f"{label}: its package.json says {meta.get('name')!r} {meta.get('version')!r}, "
                        "not what the lockfile pinned")
    return meta, sorted(texts)


def tarball_url_ok(name, version, url):
    base = name.rpartition("/")[2]
    return url == f"https://{NPM_REGISTRY}/{name}/-/{base}-{version}.tgz"


def integrity_ok(data, integrity):
    """The sha512 entry of an SRI string that `data` matches, or None."""
    got = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")
    return got if got in (integrity or "").split() else None


class FetchDeadline(OSError):
    """The overall deadline for one tarball passed: not tried again."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def fetch_https(url):
    """The bytes at an https URL, no redirects followed, at most
    NPM_MAX_TARBALL of them, within NPM_FETCH_DEADLINE seconds; a few tries
    for a flaky network or a registry asking us to slow down (429)."""
    opener = urllib.request.build_opener(_NoRedirect)
    deadline = time.monotonic() + NPM_FETCH_DEADLINE
    last = None
    for attempt in range(3):
        try:
            with opener.open(urllib.request.Request(url, headers={"User-Agent": "warpgate-notices"}),
                             timeout=60) as r:
                data = b""
                while len(data) <= NPM_MAX_TARBALL:
                    if time.monotonic() > deadline:
                        raise FetchDeadline(f"not fetched within {NPM_FETCH_DEADLINE} s")
                    chunk = r.read(min(1024 * 1024, NPM_MAX_TARBALL + 1 - len(data)))
                    if not chunk:
                        break
                    data += chunk
            if len(data) > NPM_MAX_TARBALL:
                raise ValueError(f"over {NPM_MAX_TARBALL} bytes")
            return data
        except urllib.error.HTTPError as e:
            if e.code < 500 and e.code != 429:
                raise
            last = e
        except FetchDeadline:
            raise
        except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
            # HTTPException: a body cut short (IncompleteRead) or a garbled reply
            last = e
        if time.monotonic() + 2 * (attempt + 1) > deadline:
            break
        time.sleep(2 * (attempt + 1))
    raise last


def part7_of(engine, donor, base_sha256):
    """The bytes of `donor` (another target's final notices) from its part 7 on, or
    engine.Refused. Part 7 starts at the heading npm_part writes; the place is
    accepted only when the bytes before it hash to `base_sha256`, so a licence text
    that happens to contain the heading cannot move the cut."""
    marker = ("\n" + engine.RULE + "\n7. THE WEB INTERFACE'S NPM PACKAGES (").encode("utf-8")
    cuts, at = [], donor.find(marker)
    while at != -1:
        if hashlib.sha256(donor[:at]).hexdigest() == base_sha256:
            cuts.append(at)
        at = donor.find(marker, at + 1)
    if len(cuts) != 1:
        raise engine.Refused([f"the file part 7 is taken from has {len(cuts)} places where part 7 starts after "
                              f"bytes of sha256 {base_sha256}; it must have exactly one"])
    return donor[cuts[0]:]


def npm_part(engine, manifest_path, maps_dir, lockfile, reviewed_dir, fetch=None):
    """Part 7's text and the number of packages, or engine.Refused with every
    reason. `fetch(url)` returns the bytes at a URL."""
    fetch = fetch or fetch_https
    problems = []
    manifest = read_json(engine, manifest_path, problems, "the bundle manifest")
    lock = read_json(engine, lockfile, problems, "the web interface's package-lock.json")
    pairs = manifest_set(manifest, problems) if manifest is not None else None
    in_lock = lock_entries(lock, problems) if lock is not None else {}
    mapped = source_package_paths(engine, maps_dir, problems)
    table = lock.get("packages") if isinstance(lock, dict) else None
    if pairs is not None and mapped is not None and isinstance(table, dict):
        # Each directory a map names resolves, through the lockfile, to one name@version the manifest must list.
        for path in sorted(mapped):
            entry = table.get(path)
            if not isinstance(entry, dict) or entry.get("link") or entry.get("inBundle"):
                problems.append(f"{path[:120]!r}: the source maps name it, and the lockfile has no package of its "
                                "own there (no entry, a link or a bundled dependency)")
                continue
            name = entry.get("name") if isinstance(entry.get("name"), str) else path.rpartition("node_modules/")[2]
            if (name, entry.get("version")) not in pairs:
                problems.append(f"{name[:80]!r} {str(entry.get('version'))[:40]!r} ({path[:120]}): the source maps "
                                "name it, and the bundle manifest does not list that version")

    reviewed_root = pathlib.Path(reviewed_dir)
    found = []
    for name, version in sorted(pairs or ()):
        label = f"{name}@{version}"
        pins = in_lock.get((name, version))
        if not pins:
            problems.append(f"{label}: the manifest lists it, and the lockfile has no such package at that "
                            "exact version")
            continue
        # Copies of one version must come from one tarball; their licence fields may differ in form.
        if len({(r, i) for r, i, _ in pins}) > 1:
            problems.append(f"{label}: the lockfile pins it more than once, to different tarballs")
            continue
        resolved, integrity, _ = next(iter(pins))
        lock_licence = next((lic for _, _, lic in sorted(pins, key=str) if isinstance(lic, str) and lic.strip()), None)
        if not (isinstance(resolved, str) and tarball_url_ok(name, version, resolved)):
            problems.append(f"{label}: its lockfile `resolved` is not https://{NPM_REGISTRY}/<name>/-/"
                            f"<name>-<version>.tgz ({str(resolved)[:100]!r})")
            continue
        if not (isinstance(integrity, str) and any(t.startswith("sha512-") for t in integrity.split())):
            problems.append(f"{label}: the lockfile gives it no sha512 integrity")
            continue
        try:
            data = fetch(resolved)
        except (OSError, ValueError, urllib.error.URLError, http.client.HTTPException) as e:
            problems.append(f"{label}: its tarball could not be fetched ({e.__class__.__name__}: {str(e)[:80]})")
            continue
        matched = integrity_ok(data, integrity)
        if not matched:
            problems.append(f"{label}: its tarball does not match the lockfile's integrity {integrity[:30]}...")
            continue
        meta, texts = tarball_texts(engine, data, name, version, label, problems)
        if meta is None:
            continue
        # The licence comes from the verified package.json, or from our own NPM_REVIEWED entry when it
        # declares none; the lockfile is the fork's, so it is only a cross-check.
        declared_json = package_json_licence(meta)
        entry = NPM_REVIEWED.get(label)
        if declared_json:
            declared, said = strip_brackets(declared_json), f"its package.json {declared_json!r}"
        elif entry is not None:
            declared, said = strip_brackets(entry[2]), f"NPM_REVIEWED {entry[2]!r}"
        else:
            problems.append(f"{label}: its package.json declares no licence (the lockfile's is never taken), "
                            "and NPM_REVIEWED in warpgate-notices.py has no entry for exactly this version: "
                            "review it, then add one")
            continue
        if lock_licence and strip_brackets(lock_licence) != declared:
            problems.append(f"{label}: the lockfile says {lock_licence!r}, {said}")
            continue
        if not engine.PLAIN.fullmatch(declared):
            problems.append(f"{label}: its licence is not one plain line")
            continue
        try:
            if not engine.satisfied(declared, set(NPM_ACCEPTED)):
                problems.append(f"{label}: {declared!r} is not met by NPM_ACCEPTED in warpgate-notices.py")
                continue
        except ValueError as e:
            problems.append(f"{label}: {e}")
            continue
        copyleft = [f for f, body in texts if NPM_COPYLEFT.search(body)]
        dual = NPM_DUAL.get(label)
        if copyleft and dual is not None and " OR " in declared and strip_brackets(dual[0]) == declared:
            copyleft = []
        else:
            dual = None
        if copyleft:
            problems.append(f"{label}: {', '.join(copyleft)[:120]} names a copyleft licence (GPL, LGPL, AGPL), "
                            f"and it is taken under {declared!r}: the text and the licence disagree")
            continue
        reviewed = None
        has_text = any(NPM_LICENCE_TEXT.fullmatch(f) for f, _ in texts)
        if not has_text or not declared_json:
            if entry is None:
                problems.append(f"{label}: its tarball holds no licence text (a NOTICE or COPYRIGHT file "
                                "alone is not one), and NPM_REVIEWED in "
                                "warpgate-notices.py has no entry for exactly this version: review it, then add one")
                continue
            rel, sha, lic, why = entry
            if strip_brackets(lic) != declared:
                problems.append(f"{label}: NPM_REVIEWED speaks for {lic!r}, it now declares {declared!r}")
                continue
            body = read_with_cap(engine, reviewed_root, rel, engine.MAX_FILE_BYTES, problems,
                                 f"{label}: the reviewed text {rel}")
            if body is None:
                continue
            if hashlib.sha256(body.encode("utf-8")).hexdigest() != sha:
                problems.append(f"{label}: the reviewed text {rel} is not the one NPM_REVIEWED pins (sha256 {sha})")
                continue
            reviewed = ("ships no licence file; the reviewed text below is given instead:" if not has_text else
                        "its package.json declares no licence; it is taken under the reviewed licence below:",
                        why, sha)
            texts = [(f"{rel} (reviewed in runcove)", body)] + texts
        found.append((name, version, declared, resolved, matched, reviewed, dual, texts))
    if problems:
        raise engine.Refused(problems)

    rule = engine.RULE
    out = ["", rule, f"7. THE WEB INTERFACE'S NPM PACKAGES ({len(found)})", rule, "",
           "The web interface is built from these npm packages and is compiled into the",
           "binary. Each entry names the package, the licence it is taken under, the npm",
           "tarball it was read from (checked against the integrity the interface's",
           "package-lock.json pins) and the licence and notice files of that tarball,",
           "verbatim."]
    for name, version, declared, resolved, integrity, reviewed, dual, texts in found:
        out += ["", f"{name}@{version}", f"  licence: {declared}",
                f"  from: the npm tarball {resolved} (integrity {integrity})"]
        if reviewed:
            out += [f"  {reviewed[0]}", f"    {reviewed[1]}"]
        if dual:
            out += ["  its licence file names a copyleft licence; it is taken under a permissive alternative, reviewed:",
                    f"    {dual[1]}"]
        for fname, body in texts:
            out += ["", f"---- {name}@{version}: {fname} ----", "", body.rstrip("\n")]
    return "\n".join(out) + "\n", len(found)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--engine", required=True, help="ch-ci/scripts/third-party-notices.py")
    ap.add_argument("--target", default=MUSL, choices=(MUSL, MUSL_ARM, DARWIN))
    cargo = ap.add_argument_group("parts 1 to 6 (from cargo-about)")
    cargo.add_argument("--about-json")
    cargo.add_argument("--src")
    cargo.add_argument("--rust-doc", help="the toolchain's share/doc/rust")
    cargo.add_argument("--rustc-version", help="`rustc -V`, its first two words")
    cargo.add_argument("--zig-dir", help="the unpacked zig release (the musl target only)")
    cargo.add_argument("--zig-version", help="`zig version` (the musl target only)")
    ap.add_argument("--base", help="parts 1 to 6, already written: part 7 is appended to them")
    ap.add_argument("--part7-from", help="another target's final file: its part 7 (the bytes after its parts 1 to 6) "
                                         "is appended to --base instead of a part 7 written from --npm-*")
    ap.add_argument("--part7-after-sha256", help="the sha256 of that file's parts 1 to 6, which says where part 7 starts")
    npm = ap.add_argument_group("part 7 (the web interface's npm packages)")
    npm.add_argument("--npm-manifest", help="warpgate-web/dist-licenses/bundle-licenses.json of the build")
    npm.add_argument("--npm-maps", help="a directory of the build's dist/**/*.map")
    npm.add_argument("--npm-lockfile", help="warpgate-web/package-lock.json of the decided commit")
    npm.add_argument("--npm-reviewed", help="warpgate-ci/npm-licences")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    musl = args.target in MUSL_TARGETS
    cargo_args = [args.about_json, args.src, args.rust_doc, args.rustc_version]
    if args.base is None:
        if not all(cargo_args):
            ap.error("--about-json, --src, --rust-doc and --rustc-version are required (or --base)")
        if (bool(args.zig_dir) + bool(args.zig_version)) != (2 if musl else 0):
            ap.error("--zig-dir and --zig-version go with the musl targets, and only with them")
    elif any(cargo_args + [args.zig_dir, args.zig_version]):
        ap.error("--base takes part 7 only: it goes with none of the cargo-about arguments")
    npm_args = [args.npm_manifest, args.npm_maps, args.npm_lockfile, args.npm_reviewed]
    if any(npm_args) and not all(npm_args):
        ap.error("--npm-manifest, --npm-maps, --npm-lockfile and --npm-reviewed go together")
    borrowed = args.part7_from is not None or args.part7_after_sha256 is not None
    if borrowed:
        if args.base is None or args.part7_from is None or args.part7_after_sha256 is None or any(npm_args):
            ap.error("--part7-from and --part7-after-sha256 go together, with --base and none of the --npm-* arguments")
        if not re.fullmatch(r"[0-9a-f]{64}", args.part7_after_sha256):
            ap.error("--part7-after-sha256 is not a 64-hex sha256")
    elif args.base is not None and not all(npm_args):
        ap.error("--base adds part 7, so it needs the --npm-* arguments (or --part7-from)")
    if not musl and not all(npm_args):
        ap.error(f"{DARWIN} has part 7 in its contents, so it needs the --npm-* arguments")
    try:
        engine = load_engine(args.engine)
    except (OSError, SyntaxError, ImportError) as e:
        print(f"warpgate-notices: REFUSED -- the engine {args.engine} could not be loaded "
              f"({e.__class__.__name__}: {e}); nothing written.", file=sys.stderr)
        return 1
    summary = []
    try:
        head, text = b"", ""
        if args.base is not None:
            problems = []
            head = read_raw(args.base, NPM_MAX_BASE_BYTES, problems, "the notices parts 1 to 6 are in")
            if head is None:
                raise engine.Refused(problems)
        else:
            try:
                with open(args.about_json, encoding="utf-8") as fh:
                    about = json.load(fh)
                if not isinstance(about, dict):
                    raise ValueError("not a JSON object")
                text, crates, texts = build(engine, about, args.src, args.rust_doc, args.rustc_version,
                                            args.zig_dir, args.zig_version, args.target)
            except (OSError, ValueError, KeyError, TypeError) as e:
                print(f"warpgate-notices: REFUSED -- cargo-about's JSON could not be read "
                      f"({e.__class__.__name__}: {e}); nothing written.", file=sys.stderr)
                return 1
            summary.append(f"{crates} crates, {texts} licence texts")
        if borrowed:
            problems = []
            donor = read_raw(args.part7_from, NPM_MAX_BASE_BYTES * 2, problems, "the file part 7 is taken from")
            if donor is None:
                raise engine.Refused(problems)
            tail = part7_of(engine, donor, args.part7_after_sha256)
            text += tail.decode("utf-8")
            summary.append(f"part 7 taken from {len(donor)} bytes of another target's file ({len(tail)} bytes)")
        elif all(npm_args):
            part, packages = npm_part(engine, args.npm_manifest, args.npm_maps, args.npm_lockfile, args.npm_reviewed,
                                      fetch_https)
            text += part
            summary.append(f"{packages} npm packages")
    except engine.Refused as e:
        for p in e.args[0]:
            print(f"warpgate-notices: {p}", file=sys.stderr)
        print(f"warpgate-notices: REFUSED -- {len(e.args[0])} problem(s) above; nothing written.", file=sys.stderr)
        return 1
    data = head + text.encode("utf-8")
    with open(args.out, "wb") as fh:
        fh.write(data)
    print(f"warpgate-notices: wrote {args.out}: {len(data)} bytes, {', '.join(summary)}.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
