#!/usr/bin/env bash
# warpgate-notices-run.sh -- the static Warpgate package's THIRD-PARTY-NOTICES.txt,
# written in a CLEAN container that never runs the fork's code (runcove-adcaz.11).
#
# warpgate-build-static.yml's `build` job runs this as the command of its own
# container (BUILD_IMAGE, behind sandbox-exec.sh), on the job's dind, BEFORE
# the compile container exists. Nothing of the fork runs here: the fork's
# tree is read as DATA.
#
#   * The tree is a `git archive` of the decided commit (/notices-src.tar),
#     unpacked under /notices/src, and clean_tree (below) takes out every
#     place in it that could choose a program for cargo or rustup to run:
#     every `.cargo` entry at any depth (its config.toml or config could name
#     `[build] rustc`/`rustc-wrapper`, a runner, a credential provider, or a
#     `[source]` replacement that would swap the crates whose licences are
#     read) and every rust-toolchain / rust-toolchain.toml. A toolchain file
#     that names a `path` (a toolchain from the tree) is REFUSED, never
#     dropped quietly; the root one must name exactly the channel we pinned,
#     so the Rust standard library notices describe the toolchain the binary
#     is built with.
#   * cargo runs from /notices/src, with no cargo config above it (/ and
#     /notices are checked), a fresh empty CARGO_HOME, and RUSTUP_TOOLCHAIN
#     set by the workflow from OUR pin (the toolchain image's), never from
#     the fork's file. Every other CARGO* and RUST* variable is unset, and
#     RUSTC_WRAPPER and CARGO_BUILD_RUSTC_WRAPPER are set empty, which cargo
#     reads as "no wrapper" whatever a config says.
#   * The container's network is open (the dind's bridge): it fetches apt
#     packages, cargo-about from GitHub and zig from ziglang.org (both checked
#     by sha256), rustup's toolchain, the crates from crates.io's index (no
#     source replacement is left to name another) and the git dependencies
#     from their hosts. `--locked` holds every crate to Cargo.lock.
#   * cargo-about runs `cargo metadata` and reads the crates' files; it runs
#     no build script and no proc macro. Its config is OURS (written below),
#     never an about.toml from the tree.
#   * warpgate-notices.py (runcove's own licence policy, on ch-ci's engine)
#     checks the answer and writes /out/THIRD-PARTY-NOTICES.txt; its sha256
#     is printed the moment it is written.
#
# THREE TARGETS. x86_64-unknown-linux-musl (the static build, BEFORE its compile
# container exists) writes parts 1 to 6 to /out/THIRD-PARTY-NOTICES.txt and needs
# zig, whose musl, compiler runtime and unwinder notices part 6 carries.
# aarch64-unknown-linux-musl (the static build's aarch64 job, the same way) writes
# its own parts 1 to 6 to /out/THIRD-PARTY-NOTICES-aarch64-unknown-linux-musl.txt:
# it links a different crate set (curve25519-dalek-derive is x86-only), so it has
# a notices file of its own and the two are never compared. aarch64-apple-darwin (the macOS
# build, AFTER its compile container) needs no zig -- libSystem is the
# operating system's -- and also writes part 7, the web interface's npm
# packages, from /web-evidence (the build's bundle manifest and source maps, as
# data) and /npm-licences (our reviewed texts); it is the one place both
# halves are written in a single run. The static build appends part 7 later,
# in warpgate-notices-npm-run.sh, once its compile has produced the evidence.
#
# Env (all required): RUSTUP_TOOLCHAIN CARGO_ABOUT_VERSION CARGO_ABOUT_SHA256
#   TARGET FEATURES, and for the musl target ZIG_VERSION ZIG_SHA256
# Files: /notices-src.tar, /warpgate-notices.py, /third-party-notices.py, and
#   for the darwin target /web-evidence (bundle-licenses.json, maps/) and /npm-licences
# Out: exactly one file in /out, named for the target (NOTICES_FILE below).
# Exit: 0 written; 1 refused or failed (the reason is named).
set -euo pipefail
export LC_ALL=C

fail() { echo "warpgate-notices-run: FAILED -- $*" >&2; exit 1; }

# >>> clean-tree (test_warpgate_notices.py runs this exact text)
# clean_tree <root> <pinned channel>: 0 with the tree cleaned; 1 and the
# reasons on stderr, the tree then not to be used.
clean_tree() {
  local root=$1 pin=$2 f bad=0 channel
  # Every toolchain file first, before anything is removed: one that names a
  # `path` is a toolchain from the tree, refused rather than dropped.
  while IFS= read -r -d '' f; do
    if [ -L "$f" ] || [ ! -f "$f" ]; then
      echo "clean-tree: ${f#"$root"/} is not a plain file" >&2; bad=1; continue
    fi
    if grep -Eq '^[[:space:]]*path[[:space:]]*=' "$f"; then
      echo "clean-tree: ${f#"$root"/} names a toolchain \`path\`: a toolchain from the tree is refused" >&2; bad=1
    fi
  done < <(find "$root" \( -name rust-toolchain -o -name rust-toolchain.toml \) -print0)
  # The root's own file must name exactly OUR pinned channel (the build
  # compiles with the one it names).
  if [ ! -f "$root/rust-toolchain.toml" ] && [ ! -f "$root/rust-toolchain" ]; then
    echo "clean-tree: the tree names no toolchain at its root, so the build's is not the pinned $pin" >&2; bad=1
  fi
  for f in "$root/rust-toolchain.toml" "$root/rust-toolchain"; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    channel=$(python3 -I -c '
import sys, tomllib
text = open(sys.argv[1], encoding="utf-8").read()
try:
    print(tomllib.loads(text)["toolchain"]["channel"])
except (tomllib.TOMLDecodeError, KeyError, TypeError):
    print(text.strip())
' "$f") || channel=""
    if [ "$channel" != "$pin" ]; then
      echo "clean-tree: ${f#"$root"/} names '$channel', not the pinned $pin: the notices would describe another toolchain" >&2
      bad=1
    fi
    break
  done
  [ "$bad" = 0 ] || return 1
  find "$root" \( -name .cargo -o -name rust-toolchain -o -name rust-toolchain.toml \) -prune -exec rm -rf {} + \
    || { echo "clean-tree: could not remove the tree's .cargo and toolchain entries" >&2; return 1; }
  if [ -n "$(find "$root" \( -name .cargo -o -name rust-toolchain -o -name rust-toolchain.toml \) -print -quit)" ]; then
    echo "clean-tree: a .cargo or toolchain entry is still in the tree" >&2; return 1
  fi
  return 0
}
# <<< clean-tree

for v in RUSTUP_TOOLCHAIN CARGO_ABOUT_VERSION CARGO_ABOUT_SHA256 TARGET FEATURES; do
  [ -n "${!v:-}" ] || fail "$v is not set"
done
[[ "$CARGO_ABOUT_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "CARGO_ABOUT_SHA256 is not a 64-hex sha256"
case "$TARGET" in
  x86_64-unknown-linux-musl|aarch64-unknown-linux-musl)
    for v in ZIG_VERSION ZIG_SHA256; do
      [ -n "${!v:-}" ] || fail "$v is not set"
    done
    [[ "$ZIG_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "ZIG_SHA256 is not a 64-hex sha256" ;;
  aarch64-apple-darwin)
    [ -d /web-evidence ] && [ -d /npm-licences ] || fail "/web-evidence and /npm-licences were not copied in (part 7 needs them)" ;;
  *) fail "TARGET '$TARGET' is none of x86_64-unknown-linux-musl, aarch64-unknown-linux-musl and aarch64-apple-darwin" ;;
esac
# The one file this writes: the aarch64 musl target's has its own name, so it can
# never be taken for the x86_64 one.
case "$TARGET" in
  aarch64-unknown-linux-musl) NOTICES_FILE=THIRD-PARTY-NOTICES-aarch64-unknown-linux-musl.txt ;;
  *) NOTICES_FILE=THIRD-PARTY-NOTICES.txt ;;
esac
[[ "$RUSTUP_TOOLCHAIN" =~ ^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || fail "RUSTUP_TOOLCHAIN '$RUSTUP_TOOLCHAIN' is not a dated nightly"
for f in /notices-src.tar /warpgate-notices.py /third-party-notices.py; do
  [ -r "$f" ] || fail "$f was not copied in"
done
command -v python3 >/dev/null || fail "the image has no python3"

# The image's own CARGO_HOME holds rustup itself: rustup refuses to run with a
# CARGO_HOME it isn't installed in (run 10221: "rustup is not installed at
# '/notices/cargo-home'"). Kept only for the two rustup calls below, which run
# before the tree is unpacked, so nothing from the tree can reach them.
IMAGE_CARGO_HOME=${CARGO_HOME:-}
[ -n "$IMAGE_CARGO_HOME" ] && [ -x "$IMAGE_CARGO_HOME/bin/rustup" ] \
  || fail "the image's CARGO_HOME ('$IMAGE_CARGO_HOME') holds no rustup"
# What the environment may not choose: every CARGO* and RUST* variable but
# these is unset; CARGO_HOME is set fresh below.
KEEP_ENV=" RUSTUP_HOME RUSTUP_TOOLCHAIN CARGO_ABOUT_VERSION CARGO_ABOUT_SHA256 "
while IFS= read -r env_name; do
  [[ "$env_name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
  case "$env_name" in
    CARGO*|RUST*) case "$KEEP_ENV" in *" $env_name "*) ;; *) unset "$env_name" ;; esac ;;
  esac
done < <(compgen -e)
export RUSTC_WRAPPER="" CARGO_BUILD_RUSTC_WRAPPER=""
[ ! -e /notices/cargo-home ] || fail "/notices/cargo-home exists before it was made: it is not fresh"
mkdir -p /notices/cargo-home /notices/src /out
export CARGO_HOME=/notices/cargo-home
for d in / /notices; do
  [ ! -e "${d%/}/.cargo" ] || fail "${d%/}/.cargo exists: cargo would read a config above the tree"
done

echo "---- tools ----"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends xz-utils >/dev/null
mkdir -p /tmp/dl
fetch() { # <url> <sha256> <dest>
  curl -fsSL --retry 5 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - || fail "sha256 of $1 is not the pinned $2"
}
fetch "https://github.com/EmbarkStudios/cargo-about/releases/download/${CARGO_ABOUT_VERSION}/cargo-about-${CARGO_ABOUT_VERSION}-x86_64-unknown-linux-musl.tar.gz" "$CARGO_ABOUT_SHA256" /tmp/dl/about.tar.gz
tar -xzf /tmp/dl/about.tar.gz -C /usr/local/bin --strip-components=1 "cargo-about-${CARGO_ABOUT_VERSION}-x86_64-unknown-linux-musl/cargo-about"
ZIG_ARGS=(--target "$TARGET")
ZIG_NOTE=""
if [ "$TARGET" != aarch64-apple-darwin ]; then
  # zig runs on this x86_64 container for both musl targets and cross-compiles to either.
  fetch "https://ziglang.org/download/${ZIG_VERSION}/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" "$ZIG_SHA256" /tmp/dl/zig.tar.xz
  tar -xJf /tmp/dl/zig.tar.xz -C /opt
  ZIG_DIR="/opt/zig-x86_64-linux-${ZIG_VERSION}"
  ZIG_ARGS+=(--zig-dir "$ZIG_DIR" --zig-version "$("$ZIG_DIR/zig" version)")
  ZIG_NOTE="; zig $("$ZIG_DIR/zig" version)"
fi
rm -rf /tmp/dl
# OUR pinned nightly (rustup's own download, checked by rustup), never one the tree names.
CARGO_HOME="$IMAGE_CARGO_HOME" rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal
# The image's cargo and rustc are rustup proxies, which look for rustup under
# CARGO_HOME and so refuse the fresh one. Put the pinned toolchain's own
# binaries first on PATH instead: cargo-about runs `cargo` from PATH, and it is
# then that toolchain's real cargo, which needs no rustup.
TC_CARGO=$(CARGO_HOME="$IMAGE_CARGO_HOME" rustup which --toolchain "$RUSTUP_TOOLCHAIN" cargo) \
  || fail "rustup cannot name $RUSTUP_TOOLCHAIN's cargo"
TC_BIN=$(dirname "$TC_CARGO")
[ -x "$TC_BIN/cargo" ] && [ -x "$TC_BIN/rustc" ] && [ ! -L "$TC_BIN/cargo" ] \
  || fail "$TC_BIN does not hold $RUSTUP_TOOLCHAIN's own cargo and rustc"
export PATH="$TC_BIN:$PATH"
[ "$(command -v cargo)" = "$TC_BIN/cargo" ] || fail "cargo on PATH is not $RUSTUP_TOOLCHAIN's own"
echo "cargo-about $(cargo-about --version); $(rustc -V)$ZIG_NOTE; $(python3 --version)"

echo "---- the tree, as data ----"
tar -xf /notices-src.tar -C /notices/src
clean_tree /notices/src "$RUSTUP_TOOLCHAIN" || fail "the tree cannot be read safely; every reason is named above"
cd /notices/src

echo "---- third-party notices (cargo about; no code from the tree runs) ----"
# The crates LINKED INTO the binary: the zigbuild's own package, target and
# features, without crates that are only build- or dev-dependencies. OUR
# config: `accepted` is runcove's licence policy (warpgate-notices.py holds
# the same list), in the order one is chosen when a crate offers several.
# webpki 0.22.4 declares only a licence file (ISC terms, measured): the
# clarification is pinned to that file's sha256.
cat >/notices/warpgate-about.toml <<'TOML'
accepted = ["Apache-2.0", "MIT", "BSD-3-Clause", "ISC", "MPL-2.0", "Unicode-3.0", "Unicode-DFS-2016", "BSD-2-Clause", "Zlib", "CC0-1.0", "CDLA-Permissive-2.0", "Unlicense", "WTFPL", "IJG"]
ignore-build-dependencies = true
ignore-dev-dependencies = true

[webpki.clarify]
license = "ISC"
[[webpki.clarify.files]]
path = "LICENSE"
license = "ISC"
checksum = "5b698ca13897be3afdb7174256fa1574f8c6892b8bea1a66dd6469d3fe27885a"
TOML
cargo about generate --config /notices/warpgate-about.toml --format json --locked \
  --manifest-path /notices/src/warpgate/Cargo.toml --target "$TARGET" --features "$FEATURES" \
  --output-file /notices/about.json \
  || fail "cargo about could not list the linked crates and their licences (the error is above)"
RUSTC_NAME=$(rustc -V | cut -d' ' -f1,2) || fail "rustc -V failed"
# Part 7 (darwin only): the build's manifest and maps are data, the lockfile is
# the decided commit's own, the tarballs are fetched and checked by the writer.
NPM_ARGS=()
if [ "$TARGET" = aarch64-apple-darwin ]; then
  NPM_ARGS=(--npm-manifest /web-evidence/bundle-licenses.json --npm-maps /web-evidence/maps
            --npm-lockfile /notices/src/warpgate-web/package-lock.json --npm-reviewed /npm-licences)
fi
python3 -I /warpgate-notices.py --engine /third-party-notices.py --about-json /notices/about.json \
  --src /notices/src --rust-doc "$(rustc --print sysroot)/share/doc/rust" --rustc-version "$RUSTC_NAME" \
  "${ZIG_ARGS[@]}" "${NPM_ARGS[@]}" \
  --out "/out/$NOTICES_FILE" \
  || fail "$NOTICES_FILE was not written; every reason is named above"
[ -s "/out/$NOTICES_FILE" ] || fail "$NOTICES_FILE is empty"

echo "$NOTICES_FILE sha256 $(sha256sum < "/out/$NOTICES_FILE" | cut -d' ' -f1) (written in the clean container; $RUSTC_NAME$ZIG_NOTE, cargo-about $CARGO_ABOUT_VERSION)"
