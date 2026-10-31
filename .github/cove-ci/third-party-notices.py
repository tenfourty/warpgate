#!/usr/bin/env python3
"""third-party-notices.py -- writes a release's THIRD-PARTY-NOTICES.txt.

build-static.sh runs it inside the compile container, on the JSON that
`cargo about generate --format json` printed for the release's own Cargo.lock,
the two musl targets and the one feature set the binaries are built with.
cargo-about decides WHICH crates are linked and under WHICH licence each is
taken; this file checks that answer is whole and lays it out. It reads no
network and runs none of the fork's code.

THE FILE, in order (plain UTF-8, LF, no dates, no absolute paths, everything
sorted, so the same Cargo.lock and toolchain give the same bytes):
  1. Cloud Hypervisor itself: its licence, its own crates in the binaries,
     then the fork's LICENSES/Apache-2.0.txt, LICENSES/BSD-3-Clause.txt and
     CREDITS.md, verbatim;
  2. every other linked crate: name, version, where it came from, the licence
     it declares and the licence texts (by number) it is taken under;
  3. the notice and copyright files those crates ship (NOTICE*, COPYRIGHT*);
  4. the licence texts, each once, with the crates it applies to;
  5. the licence files of native (C, assembly) code crates bundle and compile
     in, from NATIVE_CODE below;
  6. what the toolchain links in: the Rust standard library's own copyright
     notices and licence texts, from the toolchain's share/doc/rust, and the
     notices of the musl C library, compiler runtime and unwinder, from the
     zig the build links with. Both are named by version.

IT REFUSES (exit 1, naming every crate, writing nothing) rather than write a
partial file, when:
  * a linked crate that is not one of Cloud Hypervisor's own has no licence
    cargo-about could determine, or no licence text;
  * the texts found for a crate do not satisfy the licence it declares (an
    `A AND B` crate with only A's text);
  * a crate's only text for a licence is the generic one cargo-about supplies
    when the crate ships none it recognises, and that licence's text is where
    the copyright notice lives (anything but GENERIC_TEXT_IS_WHOLE below);
  * a crate with no registry or git source is not on OWN_CRATES, in its own
    directory of the source tree (so a `[patch]` to a vendored copy of someone
    else's crate cannot pass as Cloud Hypervisor's code);
  * a crate that may carry native code (a `links` key, a `-sys` name, or a
    C, C++ or assembly source, header, object or library, or a symlink, in
    its package) has no NATIVE_CODE entry for exactly that version from
    crates.io, or a file its entry names is not there;
  * a crate is taken under MPL-2.0 from anywhere but crates.io (MPL-2.0
    section 3.2: its entry in part 2 names where its source is, a crates.io
    URL of the exact version);
  * a crate is taken under a licence that is not on ACCEPTED (the recipe's
    cargo-about config holds the same list; this is the second reading);
  * any file it would copy in is a symlink, reached through one, not a
    regular file, not UTF-8, empty where it must not be, or over
    MAX_FILE_BYTES (the file that was checked is the file that is read: it is
    opened once, without following links, and checked through that handle);
  * a name, version, source or licence in cargo-about's answer is not one
    plain line (it would be laid out as lines of this file);
  * the toolchain's notices are missing, or its HTML uses a tag or a
    construct this does not know how to turn into text.

Cloud Hypervisor's own crates mostly declare no licence in their Cargo.toml
(cargo-about reports them as Unknown, which is why it cannot run with --fail
here); they are the project's code, under the project's licences in part 1.

Usage: third-party-notices.py --about-json FILE --src DIR --rust-doc DIR
           --rustc-version TEXT --zig-dir DIR --zig-version TEXT --out FILE
Exit: 0 written; 1 refused (the reasons are on stderr); 2 bad usage.
"""

import argparse
import hashlib
import html.parser
import json
import os
import pathlib
import re
import stat
import sys

ROOT_CRATE = "cloud-hypervisor"
OWN_FILES = ("LICENSES/Apache-2.0.txt", "LICENSES/BSD-3-Clause.txt", "CREDITS.md")
# Cloud Hypervisor's own crates that these binaries link, each in the source
# tree's directory of the same name. A crate with no registry or git source
# that is not here fails the build: review it (is it the project's code, or a
# vendored copy of someone else's?) and add it in a reviewed change.
OWN_CRATES = frozenset((
    "api_client", "arch", "block", "cloud-hypervisor", "devices", "event_monitor", "hypervisor",
    "net_util", "option_parser", "pci", "rate_limiter", "serial_buffer", "tpm", "tracer",
    "virtio-devices", "vm-allocator", "vm-device", "vm-migration", "vm-virtio", "vmm"))
# Licences whose text names no copyright holder, so the generic text is the
# whole of what the licence asks to be reproduced. For every other licence
# (MIT, BSD-*, ISC ...) the crate's own file carries its copyright line.
GENERIC_TEXT_IS_WHOLE = ("Apache-2.0", "MPL-2.0")
# The licences a release may carry: the `accepted` list of the recipe's
# cargo-about config, read a second time here so the file never depends on
# which config cargo-about happened to be run with (ch-ci/tests holds the two
# lists equal). Exact SPDX ids as cargo-about writes them.
ACCEPTED = ("Apache-2.0", "MIT", "BSD-3-Clause", "ISC", "MPL-2.0", "Unicode-3.0")
EXTRA_FILE = re.compile(r"(NOTICE|COPYRIGHT)(-[A-Za-z0-9-]+)?(\.(txt|md))?", re.I)
PLAIN = re.compile(r"[^\x00-\x1f\x7f-\x9f\u2028\u2029]{1,300}")
MAX_FILE_BYTES = 1024 * 1024
# NATIVE CODE CRATES BUNDLE. cargo-about reads a crate's declared licence; C
# and assembly a crate carries and compiles into the binary can be someone
# else's, under another licence, which no Cargo.toml says. So every linked
# crate that MAY carry such code -- it has a `links` key, is named *-sys, or
# its package holds a file with one of NATIVE_FILE's endings or a symlink
# (which this does not look through, and a compiler would) -- must be listed
# here, with each VERSION that was looked at: the licence files (relative to
# the crate) that cover what it bundles, or none, and why. An entry speaks for
# its one version from crates.io, whose contents Cargo.lock's checksum fixes:
# another version, or the same name from git or a path, fails the build until
# someone has looked at it and added an entry.
NATIVE_FILE = (".c", ".cc", ".cpp", ".cxx", ".c++", ".h", ".hh", ".hpp", ".hxx", ".s", ".asm", ".nasm",
               ".o", ".obj", ".a", ".lib", ".so", ".dll", ".dylib")
NATIVE_CODE = {
    # BoringSSL-derived C and assembly, fiat-crypto field arithmetic, and
    # once_cell-derived Rust; LICENSE says which file is under which.
    "ring": (("0.17.14",
              ("LICENSE", "LICENSE-BoringSSL", "LICENSE-other-bits", "third_party/fiat/LICENSE",
               "src/polyfill/once_cell/LICENSE-APACHE", "src/polyfill/once_cell/LICENSE-MIT"),
              "BoringSSL and fiat-crypto C and assembly, compiled by its build script"),),
    # The zstd C library (zstd/), compiled by its build script: BSD-3-Clause
    # OR GPL-2.0-only, taken under BSD-3-Clause.
    "zstd-sys": (("2.0.16+zstd.1.5.7", ("LICENSE.BSD-3-Clause", "zstd/LICENSE"),
                  "the zstd C library, compiled by its build script, taken under BSD-3-Clause"),
                 ("2.1.0+zstd.1.5.7", ("LICENSE.BSD-3-Clause", "zstd/LICENSE"),
                  "the zstd C library, compiled by its build script, taken under BSD-3-Clause"),
                 ("2.1.2+zstd.1.5.7", ("LICENSE.BSD-3-Clause", "zstd/LICENSE"),
                  "the zstd C library, compiled by its build script, taken under BSD-3-Clause")),
    "signal-hook": (("0.4.4", (), "src/low_level/extract.c is the crate's own code, under the crate's licence"),
                    ("0.4.5", (), "src/low_level/extract.c is the crate's own code, under the crate's licence")),
    "linux-loader": (("0.13.2", (), "the C++ under docs/ writes test fixtures and is never compiled in"),
                     ("0.14.0", (), "the C++ under docs/ writes test fixtures and is never compiled in")),
}
# The toolchain's own notices. The Rust standard library's are one HTML page
# in the toolchain (it names every crate std is built from, with its notices);
# RUST_LICENCES are the texts that page refers to by name for std's own tree.
RUST_COPYRIGHT = "COPYRIGHT-library.html"
RUST_LICENCES = ("Apache-2.0", "MIT", "BSD-2-Clause", "Unicode-3.0")
# From the zig the build links with (cargo-zigbuild): the musl C library, and
# zig's compiler runtime and LLVM's unwinder, which a static link may pull in.
ZIG_FILES = (("lib/libc/musl/COPYRIGHT", "musl libc (the C library the static binaries are linked with)"),
             ("LICENSE", "zig (its compiler runtime, compiler-rt, may be linked)"),
             ("lib/libunwind/LICENSE.TXT", "LLVM libunwind (may be linked)"))
RULE = "=" * 78


class Refused(Exception):
    pass


def satisfied(expression, have):
    """Whether the SPDX `expression` is met by the licence ids in `have`.
    AND binds tighter than OR; `/` is cargo's old spelling of OR. Anything
    this does not understand (WITH, a stray token) raises ValueError."""
    tokens = re.findall(r"\(|\)|/|[A-Za-z0-9.+-]+", expression)
    if "".join(tokens) != re.sub(r"\s+", "", expression) or not tokens:
        raise ValueError(f"cannot read the licence expression {expression!r}")
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def term():
        nonlocal pos
        tok = peek()
        if tok == "(":
            pos += 1
            value = either()
            if peek() != ")":
                raise ValueError(f"unbalanced brackets in {expression!r}")
            pos += 1
            return value
        if tok is None or tok in (")", "/", "AND", "OR", "WITH"):
            raise ValueError(f"cannot read the licence expression {expression!r}")
        pos += 1
        if peek() == "WITH":
            raise ValueError(f"{expression!r} uses WITH, which this does not handle")
        return tok in have

    def both():
        nonlocal pos
        value = term()
        while peek() == "AND":
            pos += 1
            value = term() and value
        return value

    def either():
        nonlocal pos
        value = both()
        while peek() in ("OR", "/"):
            pos += 1
            value = both() or value
        return value

    result = either()
    if pos != len(tokens):
        raise ValueError(f"cannot read the licence expression {expression!r}")
    return result


def clean(text):
    """LF line ends, no trailing blank lines, one final newline."""
    return text.replace("\r\n", "\n").replace("\r", "\n").strip("\n") + "\n"


def read_inside(root, rel, problems, what, may_be_empty=False):
    """The text of the regular file `rel` under `root`, or None with the
    reason appended to `problems`. Nothing on the way to it may be a symlink:
    a tree can plant one that points at any file this process can read.

    What is checked is what is read. Each part of `rel` is opened from the
    directory before it WITHOUT following a link, and type, size and bytes
    all come from that one open file -- never a path looked up a second time,
    which could name something else by then. O_NONBLOCK, so a FIFO planted
    under the name is refused instead of waited on for ever."""
    parts = pathlib.PurePosixPath(rel).parts
    if not parts or any(part in ("", ".", "..", "/") or "/" in part for part in parts):
        problems.append(f"{what}: {rel!r} is not a plain relative path")
        return None
    fd = None
    try:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        for n, part in enumerate(parts):
            last = n == len(parts) - 1
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | (os.O_NONBLOCK if last else os.O_DIRECTORY)
            try:
                nxt = os.open(part, flags, dir_fd=fd)
            except OSError as e:
                if stat.S_ISLNK(os.lstat(part, dir_fd=fd).st_mode):
                    problems.append(f"{what} is a symlink or is reached through one")
                    return None
                raise e
            os.close(fd)
            fd = nxt
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            problems.append(f"{what} is not a regular file")
            return None
        if st.st_size > MAX_FILE_BYTES:
            problems.append(f"{what} is {st.st_size} bytes, over the {MAX_FILE_BYTES} this copies in")
            return None
        raw = b""
        while len(raw) <= MAX_FILE_BYTES:
            chunk = os.read(fd, MAX_FILE_BYTES + 1 - len(raw))
            if not chunk:
                break
            raw += chunk
        if len(raw) > MAX_FILE_BYTES:
            problems.append(f"{what} grew past the {MAX_FILE_BYTES} bytes this copies in while it was read")
            return None
        body = raw.decode("utf-8")
    except UnicodeDecodeError:
        problems.append(f"{what} is not UTF-8")
        return None
    except OSError as e:
        problems.append(f"{what} could not be read ({e.__class__.__name__})")
        return None
    finally:
        if fd is not None:
            os.close(fd)
    if not body.strip() and not may_be_empty:
        problems.append(f"{what} is empty")
        return None
    return clean(body)


def may_hold_native_code(directory):
    """Why the crate's package may hold native code -- the first native file
    or symlink found, by name -- or None. A directory that cannot be listed
    is an OSError, never "nothing found"."""
    def unreadable(error):
        raise error
    for where, dirs, files in os.walk(directory, onerror=unreadable):
        for name in sorted(dirs + files):
            path = os.path.join(where, name)
            if os.path.islink(path):
                return f"a symlink, {os.path.relpath(path, directory)}"
            if name in files and name.lower().endswith(NATIVE_FILE):
                return f"a native file, {os.path.relpath(path, directory)}"
    return None


class _Text(html.parser.HTMLParser):
    """The toolchain's copyright page as plain text: headings, paragraphs and
    list items one per line, <pre> blocks (the notices themselves) verbatim.
    A tag it was not written for is an error, never silently dropped text."""

    BLOCK = ("p", "div", "ul", "li", "details", "summary", "h1", "h2", "h3", "body", "html")
    INLINE = ("a", "b", "code")
    SKIPPED = ("head", "title", "meta")

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.lines, self.run, self.pre, self.skip, self.unknown = [], [], False, 0, set()
        self.heads = 0

    def flush(self, heading=False):
        text = " ".join("".join(self.run).split())
        self.run = []
        if text:
            self.lines += ["", ("## " if heading else "") + text]

    def handle_starttag(self, tag, attrs):
        if self.pre:
            self.unknown.add(f"{tag} inside pre")
        elif tag in ("head", "title"):
            # The one <head> is the page's title, which its <h1> repeats. A
            # second one, or one never closed, would drop real text unseen.
            self.skip += 1
            self.heads += tag == "head"
            if self.heads > 1 or self.lines or self.skip > 2:
                self.unknown.add("a second or late head")
        elif tag == "pre":
            self.flush()
            self.pre = True
            self.lines.append("")
        elif tag in self.BLOCK:
            self.flush()
        elif tag not in self.INLINE and tag not in self.SKIPPED:
            self.unknown.add(tag)

    def handle_endtag(self, tag):
        if tag in ("head", "title"):
            self.skip -= 1
        elif tag == "pre":
            self.lines += "".join(self.run).strip("\n").split("\n")
            self.run, self.pre = [], False
        elif tag in self.BLOCK:
            self.flush(heading=tag in ("h1", "h2", "h3"))

    def handle_data(self, data):
        if not self.skip:
            self.run.append(data)

    def handle_pi(self, data):
        self.unknown.add("a processing instruction")

    def unknown_decl(self, data):
        self.unknown.add("a marked section")

    def finish(self):
        self.close()
        if self.skip or self.pre:
            self.unknown.add("a head, title or pre that is never closed")
        self.flush()


def html_text(page):
    """(text, unknown tags) of the toolchain's copyright page."""
    parser = _Text()
    parser.feed(page)
    parser.finish()
    return clean("\n".join(line.rstrip() for line in parser.lines)), sorted(parser.unknown)


def origin(source):
    if source.startswith("registry+https://github.com/rust-lang/crates.io-index"):
        return "crates.io"
    return source


def build(about, src, rust_doc, rustc_version, zig_dir, zig_version):
    """The file's text, or Refused with every reason."""
    problems = []
    src = pathlib.Path(src).resolve()

    own_texts = []
    for rel in OWN_FILES:
        body = read_inside(src, rel, problems, f"Cloud Hypervisor's own {rel}")
        own_texts.append((rel, body))

    # ---- what the toolchain links in ------------------------------------
    for label, value in (("rustc", rustc_version), ("zig", zig_version)):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,99}", value or ""):
            problems.append(f"the {label} version {value!r} is not one plain line")
    toolchain = []    # (heading, text)
    page = read_inside(rust_doc, RUST_COPYRIGHT, problems, f"the Rust toolchain's {RUST_COPYRIGHT}")
    if page is not None:
        text, unknown = html_text(page)
        if unknown:
            problems.append(f"the Rust toolchain's {RUST_COPYRIGHT} uses {', '.join(unknown)}, which this "
                            "does not know how to turn into text")
        if "Copyright notices for The Rust Standard Library" not in text:
            problems.append(f"the Rust toolchain's {RUST_COPYRIGHT} is not the standard library's copyright page")
        in_tree = text.partition("## In-tree files")[2].partition("## Out-of-tree dependencies")[0]
        named = set(re.findall(r"[A-Za-z0-9.+-]+", " ".join(re.findall(r"^License: (.*)$", in_tree, re.M))))
        unlisted = sorted(named - {"AND", "OR", "WITH"} - set(RUST_LICENCES))
        if unlisted or not named:
            problems.append(f"the Rust standard library's own tree names the licences {unlisted or 'none'}, "
                            f"whose text RUST_LICENCES in third-party-notices.py does not carry")
        toolchain.append((f"Rust standard library ({rustc_version}): {RUST_COPYRIGHT}, as text", text))
    for lid in RUST_LICENCES:
        body = read_inside(rust_doc, f"licenses/{lid}.txt", problems, f"the Rust toolchain's licenses/{lid}.txt")
        toolchain.append((f"Rust standard library ({rustc_version}): licenses/{lid}.txt", body))
    for rel, label in ZIG_FILES:
        body = read_inside(zig_dir, rel, problems, f"zig's {rel}")
        toolchain.append((f"{label}, from zig {zig_version}: {rel}", body))

    crates = {}       # (name, version, source) -> record
    for entry in about.get("crates", []):
        pkg = entry["package"]
        key = (pkg["name"], pkg["version"], pkg.get("source") or "")
        for field in key[:2] + (key[2] or "-", entry.get("license") or "-"):
            if not isinstance(field, str) or not PLAIN.fullmatch(field):
                problems.append(f"a crate's name, version, source or licence is not one plain line: {field!r}")
        if key in crates:
            problems.append(f"{key[0]} {key[1]} is listed twice")
        crates[key] = {"declared": entry.get("license") or "", "ids": {}, "generic": set(),
                       "links": pkg.get("links"),
                       "dir": pathlib.Path(pkg["manifest_path"]).resolve().parent}

    texts = {}        # (licence id, text) -> set of crate keys
    for lic in about.get("licenses", []):
        if not isinstance(lic.get("id"), str) or not PLAIN.fullmatch(lic["id"]):
            problems.append(f"a licence id is not one plain line: {lic.get('id')!r}")
            continue
        text = clean(lic.get("text") or "")
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

    own, third = [], []
    for key in sorted(crates):
        name, version, source = key
        rec = crates[key]
        if not source:
            if name in OWN_CRATES and rec["dir"] == src / name:
                own.append(key)
            else:
                problems.append(f"{name} {version} has no registry or git source and is not one of Cloud "
                                f"Hypervisor's own crates in its own directory: review it, then add it to "
                                f"OWN_CRATES in third-party-notices.py")
            continue
        third.append(key)
        label = f"{name} {version}"
        if not rec["ids"]:
            problems.append(f"{label}: no licence text (declares {rec['declared'] or 'nothing'!r})")
            continue
        try:
            if not satisfied(rec["declared"], set(rec["ids"])):
                problems.append(f"{label}: declares {rec['declared']!r} but only has text for "
                                + ", ".join(sorted(rec["ids"])))
        except ValueError as e:
            problems.append(f"{label}: {e}")
        for lid, found in sorted(rec["ids"].items()):
            if lid not in ACCEPTED:
                problems.append(f"{label}: taken under {lid}, which is not on ACCEPTED in third-party-notices.py")
            if lid == "MPL-2.0" and origin(source) != "crates.io":
                problems.append(f"{label}: taken under MPL-2.0 but from {source}, not crates.io, so no source link "
                                "can be given for it (MPL-2.0 section 3.2): review it")
            generic = {t for i, t in rec["generic"] if i == lid}
            if found == generic and lid not in GENERIC_TEXT_IS_WHOLE:
                problems.append(f"{label}: ships no {lid} text of its own, and a generic {lid} text "
                                "would drop its copyright notice")

    roots = [k for k in own if k[0] == ROOT_CRATE]
    if len(roots) != 1:
        problems.append(f"expected exactly one {ROOT_CRATE} crate in the source tree, found {len(roots)}")
    elif not crates[roots[0]]["declared"] or crates[roots[0]]["declared"] == "Unknown":
        problems.append(f"{ROOT_CRATE} declares no licence")
    if not third:
        problems.append("no third-party crate at all: the crate list is not the binary's")
    if problems:
        raise Refused(problems)

    # Texts no third-party crate uses (Cloud Hypervisor's own crates' generic
    # ones) are left out: part 1 carries the project's real files.
    used = {k: v & set(third) for k, v in texts.items()}
    used = {k: v for k, v in used.items() if v}
    order = sorted(used, key=lambda k: (k[0], min(used[k]), hashlib.sha256(k[1].encode()).hexdigest()))
    number = {k: f"T{i:03d}" for i, k in enumerate(order, 1)}

    extras = []       # (crate key, file name, text)
    native = []       # (crate key, why, [(file, text)])
    for key in third:
        d, label = crates[key]["dir"], f"{key[0]} {key[1]}"
        for name in sorted(os.listdir(d)) if d.is_dir() else []:
            if EXTRA_FILE.fullmatch(name):
                body = read_inside(d, name, problems, f"{label}: {name}", may_be_empty=True)
                if body is not None and body.strip():
                    extras.append((key, name, body))
        try:
            held = may_hold_native_code(d)
        except OSError as e:
            problems.append(f"{label}: its package could not be searched for native code ({e.__class__.__name__})")
            continue
        flagged = ([f"a `links` key, {crates[key]['links']}"] if crates[key]["links"] else []) \
            + (["a -sys name"] if key[0].endswith("-sys") else []) + ([held] if held else [])
        if flagged:
            entries = NATIVE_CODE.get(key[0], ())
            audited = next((e for e in entries if e[0] == key[1]), None)
            if audited is None or origin(key[2]) != "crates.io":
                was = (f"its entries are for {', '.join(e[0] for e in entries)} from crates.io, not this"
                       if entries else "it has no entry")
                problems.append(f"{label} from {origin(key[2])} may bundle native code ({'; '.join(flagged)}) and "
                                f"NATIVE_CODE in third-party-notices.py does not speak for it ({was}): look at "
                                f"what this version compiles in, then list its licence files, or none and why")
                continue
            _, files, why = audited
            found = [(rel, read_inside(d, rel, problems, f"{label}: {rel}")) for rel in files]
            if files:
                native.append((key, why, found))
    if problems:
        raise Refused(problems)

    out = []
    w = out.append
    w("THIRD-PARTY NOTICES")
    w("")
    w("cloud-hypervisor-static: Cloud Hypervisor as one static binary per")
    w("architecture (x86_64 and aarch64, musl). Each binary contains Cloud")
    w("Hypervisor and the Rust crates listed here, compiled in. This file covers")
    w("both binaries: a crate used by either is listed.")
    w("")
    w("  1. Cloud Hypervisor")
    w(f"  2. Crates compiled into the binaries ({len(third)})")
    w(f"  3. Notice and copyright files shipped by those crates ({len(extras)})")
    w(f"  4. Licence texts ({len(order)})")
    w(f"  5. Native code bundled by those crates ({len(native)})")
    w("  6. The Rust standard library and the C library")
    w("")
    w(RULE)
    w("1. CLOUD HYPERVISOR")
    w(RULE)
    w("")
    w(f"Licence: {crates[roots[0]]['declared']}")
    w("Its own crates in these binaries:")
    for name, version, _ in own:
        w(f"  {name} {version}")
    for rel, body in own_texts:
        w("")
        w(f"---- {rel} ----")
        w("")
        w(body.rstrip("\n"))
    w("")
    w(RULE)
    w(f"2. CRATES COMPILED INTO THE BINARIES ({len(third)})")
    w(RULE)
    for key in third:
        name, version, source = key
        rec = crates[key]
        under = []
        for lid in sorted(rec["ids"]):
            refs = sorted(number[(lid, t)] for t in rec["ids"][lid])
            under.append(f"{lid} [{', '.join(refs)}]")
        w("")
        w(f"{name} {version}")
        w(f"  from: {origin(source)}")
        w(f"  declares: {rec['declared']}")
        w(f"  taken under: {'; '.join(under)}")
        if "MPL-2.0" in rec["ids"]:
            w(f"  source code: https://crates.io/crates/{name}/{version}")
    w("")
    w(RULE)
    w(f"3. NOTICE AND COPYRIGHT FILES SHIPPED BY THOSE CRATES ({len(extras)})")
    w(RULE)
    for key, name, body in extras:
        w("")
        w(f"---- {key[0]} {key[1]}: {name} ----")
        w("")
        w(body.rstrip("\n"))
    w("")
    w(RULE)
    w(f"4. LICENCE TEXTS ({len(order)})")
    w(RULE)
    for k in order:
        w("")
        w(f"---- [{number[k]}] {k[0]} ----")
        w("Applies to: " + ", ".join(f"{n} {v}" for n, v, _ in sorted(used[k])))
        w("")
        w(k[1].rstrip("\n"))
    w("")
    w(RULE)
    w(f"5. NATIVE CODE BUNDLED BY THOSE CRATES ({len(native)})")
    w(RULE)
    w("")
    w("These crates carry C or assembly that is compiled into the binaries. The")
    w("licence files below are theirs, verbatim.")
    for key, why, found in native:
        for rel, body in found:
            w("")
            w(f"---- {key[0]} {key[1]}: {rel} ----")
            w(f"({why})")
            w("")
            w(body.rstrip("\n"))
    w("")
    w(RULE)
    w("6. THE RUST STANDARD LIBRARY AND THE C LIBRARY")
    w(RULE)
    w("")
    w("The binaries are statically linked: the Rust standard library and the C")
    w("library are inside them. These notices are the ones the build's own")
    w(f"toolchain ships: {rustc_version}, and zig {zig_version}, which links the")
    w("binaries and supplies the musl C library.")
    for heading, body in toolchain:
        w("")
        w(f"---- {heading} ----")
        w("")
        w(body.rstrip("\n"))
    return "\n".join(out) + "\n", len(third), len(order)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--about-json", required=True)
    ap.add_argument("--src", required=True)
    ap.add_argument("--rust-doc", required=True, help="the toolchain's share/doc/rust")
    ap.add_argument("--rustc-version", required=True, help="`rustc -V`")
    ap.add_argument("--zig-dir", required=True, help="the unpacked zig release")
    ap.add_argument("--zig-version", required=True, help="`zig version`")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    try:
        with open(args.about_json, encoding="utf-8") as fh:
            about = json.load(fh)
        if not isinstance(about, dict):
            raise ValueError("not a JSON object")
        text, crates, texts = build(about, args.src, args.rust_doc, args.rustc_version,
                                    args.zig_dir, args.zig_version)
    except Refused as e:
        for p in e.args[0]:
            print(f"third-party-notices: {p}", file=sys.stderr)
        print(f"third-party-notices: REFUSED -- {len(e.args[0])} problem(s) above; nothing written.", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"third-party-notices: REFUSED -- cargo-about's JSON could not be read "
              f"({e.__class__.__name__}: {e}); nothing written.", file=sys.stderr)
        return 1
    data = text.encode("utf-8")
    with open(args.out, "wb") as fh:
        fh.write(data)
    print(f"third-party-notices: wrote {args.out}: {len(data)} bytes, {crates} crates, {texts} licence texts.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
