#!/usr/bin/env bash
# build-in-container.sh -- the compile and the smoke of cove-release.yml, run as
# the command of the sandboxed compile container (behind sandbox-exec.sh).
#
# This is the script runcove's warpgate-build-static.yml wrote into the
# container with a heredoc, once for x86_64 and once for aarch64, now one file
# for both. It is NOT one of the byte-identical copies of runcove's scripts:
# it is this repository's own. The two differences in behaviour are the
# target (TARGET, and ZIG_ARCH for the zig and cargo-zigbuild downloads) and
# that BOTH targets now RUN the binary: each build job runs on a runner of its
# own architecture, so the smoke is the same for both.
#
# Env (all required): TARGET ZIG_ARCH FEATURES LTO VERSION IS_RELEASE FORK_SHA
#   REF RUN_ID BUILD_IMAGE ZIG_VERSION ZIG_SHA256 CARGO_ZIGBUILD_VERSION
#   CARGO_ZIGBUILD_SHA256
# Optional: CARGO_ZIGBUILD_TRIPLE (the release asset's triple; default <ZIG_ARCH>-unknown-linux-musl)
# Out: /out (binary, BUILDINFO, SHA256SUMS; the aarch64 target's BUILDINFO and
#   SHA256SUMS carry the target in their names) and /web-evidence (the web
#   build's licence evidence, data for the clean npm notices step).
set -euo pipefail
export LC_ALL=C
# Memory on the way out, pass or fail: peak, OOM events, and anon versus file
# (page cache counts in the peak but is reclaimable).
trap 'echo "---- cgroup memory ----"; cat /sys/fs/cgroup/memory.peak /sys/fs/cgroup/memory.events 2>/dev/null; grep -E "^(anon|file|shmem|kernel) " /sys/fs/cgroup/memory.stat 2>/dev/null || true' EXIT
fail() { echo "build-static: FAILED -- $*" >&2; exit 1; }
T0=$(date +%s)

for v in TARGET ZIG_ARCH FEATURES LTO VERSION IS_RELEASE FORK_SHA REF RUN_ID BUILD_IMAGE ZIG_VERSION ZIG_SHA256 CARGO_ZIGBUILD_VERSION CARGO_ZIGBUILD_SHA256; do
  [ -n "${!v:-}" ] || fail "$v is not set"
done
[[ "$ZIG_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "ZIG_SHA256 is not a 64-hex sha256 ('$ZIG_SHA256'): the pin for $ZIG_ARCH has not been filled in"
[[ "$CARGO_ZIGBUILD_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "CARGO_ZIGBUILD_SHA256 is not a 64-hex sha256 ('$CARGO_ZIGBUILD_SHA256'): the pin for $ZIG_ARCH has not been filled in"

# Which target this is, and the machine it must be. The container is of the
# runner's architecture, so the binary can be run below.
case "$TARGET" in
  x86_64-unknown-linux-musl)
    WANT_ARCH=x86_64; FILE_MACHINE="x86-64"; READELF_MACHINE='Advanced Micro Devices X86-64'
    INFO=BUILDINFO; SUMS=SHA256SUMS ;;
  aarch64-unknown-linux-musl)
    WANT_ARCH=aarch64; FILE_MACHINE="ARM aarch64"; READELF_MACHINE='AArch64'
    INFO="BUILDINFO-$TARGET"; SUMS="SHA256SUMS-$TARGET" ;;
  *) fail "TARGET '$TARGET' is neither x86_64-unknown-linux-musl nor aarch64-unknown-linux-musl" ;;
esac
[ "$ZIG_ARCH" = "$WANT_ARCH" ] || fail "ZIG_ARCH '$ZIG_ARCH' is not $WANT_ARCH, the architecture of $TARGET"
[ "$(uname -m)" = "$WANT_ARCH" ] || fail "this container is $(uname -m), not $WANT_ARCH: the binary could not be run in the smoke"

export DEBIAN_FRONTEND=noninteractive
git config --global --add safe.directory '*'
echo "---- tools ----"
curl -fsSL https://deb.nodesource.com/setup_24.x | bash - >/dev/null
apt-get update -qq
apt-get install -y -qq --no-install-recommends ca-certificates-java nodejs openjdk-17-jre-headless file binutils xz-utils >/dev/null
mkdir -p /tmp/dl
# Which cargo-zigbuild release asset: musl by default; the release publishes no
# aarch64 musl asset, so the aarch64 job names the gnu one (a host tool in a
# Debian container; it does not touch what is compiled).
CZB_TRIPLE="${CARGO_ZIGBUILD_TRIPLE:-${ZIG_ARCH}-unknown-linux-musl}"
curl -fsSL --retry 5 -o /tmp/dl/zig.tar.xz "https://ziglang.org/download/${ZIG_VERSION}/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz"
echo "${ZIG_SHA256}  /tmp/dl/zig.tar.xz" | sha256sum -c -
tar -xJf /tmp/dl/zig.tar.xz -C /opt && ln -s "/opt/zig-${ZIG_ARCH}-linux-${ZIG_VERSION}/zig" /usr/local/bin/zig
curl -fsSL --retry 5 -o /tmp/dl/czb.tar.xz "https://github.com/rust-cross/cargo-zigbuild/releases/download/v${CARGO_ZIGBUILD_VERSION}/cargo-zigbuild-${CZB_TRIPLE}.tar.xz"
echo "${CARGO_ZIGBUILD_SHA256}  /tmp/dl/czb.tar.xz" | sha256sum -c -
tar -xJf /tmp/dl/czb.tar.xz -C /usr/local/bin --strip-components=1 "cargo-zigbuild-${CZB_TRIPLE}/cargo-zigbuild"
rm -rf /tmp/dl
node --version; java -version 2>&1 | head -1; zig version; cargo-zigbuild --version
cd /src
[ "$(git rev-parse HEAD)" = "$FORK_SHA" ] || fail "HEAD is $(git rev-parse HEAD), the build was decided on $FORK_SHA"
cargo --version   # installs the rust-toolchain.toml nightly, as Dockerfile.cove does
rustup target add "$TARGET"
echo "---- web assets (the macOS build's sequence; RustEmbed puts them in the binary) ----"
( cd warpgate-web && npm ci --ignore-scripts )
( cd warpgate-web && npm run openapi:client:admin && npm run openapi:client:gateway )
( cd warpgate-web && npm run build )
echo "---- the web build's licence evidence (data for the clean npm step, never trusted) ----"
mkdir -p /web-evidence/maps
if [ -f warpgate-web/dist-licenses/bundle-licenses.json ] && [ ! -L warpgate-web/dist-licenses/bundle-licenses.json ]; then
  cp warpgate-web/dist-licenses/bundle-licenses.json /web-evidence/bundle-licenses.json
fi
( cd warpgate-web/dist && find . -name '*.map' -type f -exec cp --parents {} /web-evidence/maps/ \; )
echo "---- cargo zigbuild ($TARGET, $VERSION, features=$FEATURES, lto=$LTO) ----"
export CARGO_PROFILE_RELEASE_LTO="$LTO"
export CARGO_PROFILE_RELEASE_DEBUG=0
t0=$(date +%s)
cargo zigbuild -p warpgate --release --locked --target "$TARGET" --features "$FEATURES"
took=$(( $(date +%s) - t0 ))
BIN="target/$TARGET/release/warpgate"
echo "---- smoke (in the build container) ----"
desc=$(file -b "$BIN")
echo "file: $desc"
[[ "$desc" == "ELF 64-bit LSB"* ]] || fail "not a 64-bit little-endian ELF: $desc"
[[ "$desc" == *"$FILE_MACHINE"* ]] || fail "not $FILE_MACHINE: $desc"
[[ "$desc" == *"statically linked"* || "$desc" == *"static-pie linked"* ]] || fail "not statically linked: $desc"
# Through files, not pipes: under pipefail a grep -q that stops reading early
# can turn a hit into a miss.
readelf -hW "$BIN" > /tmp/elf.h; readelf -lW "$BIN" > /tmp/elf.l; readelf -dW "$BIN" > /tmp/elf.d 2>&1 || true
grep -Eq "^ +Machine: +${READELF_MACHINE}\$" /tmp/elf.h || fail "the ELF header's machine is not $READELF_MACHINE"
if grep -q 'INTERP' /tmp/elf.l; then fail "it has a program interpreter"; fi
if grep -q '(NEEDED)' /tmp/elf.d; then fail "it has NEEDED shared libraries"; fi
echo "ldd: $(ldd "$BIN" 2>&1 || true)"
# What the binary must print: the git-describe string the build embedded
# (warpgate-version's git_describe!: --tags --always --dirty=-modified --match
# v[0-9]*), never -modified, and on a release exactly the tag.
EXPECT=$(git describe --tags --always --dirty=-modified --match 'v[0-9]*')
case "$EXPECT" in *-modified) fail "the tree is modified after the build ($EXPECT): the binary would not be the commit" ;; esac
[ "$IS_RELEASE" != true ] || [ "$EXPECT" = "$VERSION" ] || fail "git describe says '$EXPECT', the release is '$VERSION'"
got=$("$BIN" version) || fail "warpgate version exited non-zero"
[ "$got" = "warpgate $EXPECT" ] || fail "warpgate version printed '$got', wanted 'warpgate $EXPECT'"
echo "warpgate version: $got"
# ... and alone: chrooted into a directory holding nothing but the binary (no
# libc, no loader, no /etc, no /proc), so nothing on this image's filesystem
# can have helped it. Inside the sandboxed container, so the fork's binary
# never runs outside it.
# chroot is resolved BEFORE `env -i` clears PATH: under an empty environment
# env searches only /bin:/usr/bin, and Debian keeps chroot in /usr/sbin (proof
# run 8885 failed on exactly that).
CHROOT=$(command -v chroot || true)
[ -n "$CHROOT" ] || CHROOT=/usr/sbin/chroot
[ -x "$CHROOT" ] || fail "no chroot program in the build image (not on PATH, not at /usr/sbin/chroot): the alone-run could not be tried; the binary did not run"
# A fixed path in this throwaway container (TMPDIR only moves it for the test).
ALONE="${TMPDIR:-/tmp}/alone"
rm -rf "$ALONE" "$ALONE.err" && mkdir "$ALONE" && cp "$BIN" "$ALONE/warpgate"
alone_rc=0
alone=$(env -i "$CHROOT" "$ALONE" /warpgate version 2>"$ALONE.err") || alone_rc=$?
if [ "$alone_rc" -eq 125 ]; then
  # coreutils chroot exits 125 when it fails ITSELF, before the command
  # starts: almost always no CAP_SYS_CHROOT in the container.
  sed 's/^/  /' "$ALONE.err" >&2
  fail "chroot itself could not change root (exit 125, most likely no CAP_SYS_CHROOT in the build container): the harness failed, the binary never ran"
elif [ "$alone_rc" -ne 0 ]; then
  sed 's/^/  /' "$ALONE.err" >&2
  fail "warpgate version failed chrooted alone into an empty directory (exit $alone_rc)"
fi
[ "$alone" = "$got" ] || fail "alone in an empty directory it printed '$alone', not '$got'"
rm -rf "$ALONE" "$ALONE.err"
echo "alone in an empty directory (no libc, no loader): $alone"
mkdir -p /out
OUTBIN="warpgate-$VERSION-$TARGET"
cp "$BIN" "/out/$OUTBIN"
{
  echo "warpgate-static $VERSION"
  echo "target: $TARGET"
  echo "release: $IS_RELEASE"
  echo "fork: runcove/warpgate"
  echo "commit: $FORK_SHA"
  echo "ref: $REF"
  echo "build run: $RUN_ID"
  echo "version printed: $got"
  echo "features: $FEATURES (sqlite by default)  lto: $LTO  profile: release, --locked"
  echo "build image: $BUILD_IMAGE"
  echo "zig: $(zig version) (sha256 $ZIG_SHA256)  cargo-zigbuild: $CARGO_ZIGBUILD_VERSION (sha256 $CARGO_ZIGBUILD_SHA256)"
  echo "rustc: $(rustc -V)"
  echo "SOURCE_DATE_EPOCH: ${SOURCE_DATE_EPOCH:-unset}"
  echo "cargo zigbuild seconds: $took (cold, no compiler cache); whole script $(( $(date +%s) - T0 ))"
  echo "size: $(stat -c %s "/out/$OUTBIN") bytes"
  echo "file: $(file -b "/out/$OUTBIN")"
  echo "program interpreter: none; NEEDED: none; runs chrooted alone in an empty directory"
} > "/out/$INFO"
( cd /out && sha256sum "$OUTBIN" "$INFO" > "$SUMS" )
# Indented, so no line of it can be read as a workflow command.
sed 's/^/  /' "/out/$INFO" "/out/$SUMS"
