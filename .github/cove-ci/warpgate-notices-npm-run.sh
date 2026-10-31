#!/usr/bin/env bash
# warpgate-notices-npm-run.sh -- part 7 of the static Warpgate package's
# THIRD-PARTY-NOTICES.txt: the web interface's npm packages, appended to parts
# 1 to 6 in a CLEAN container that runs none of the fork's code.
#
# warpgate-build-static.yml's `build` job runs this as the command of a
# container of its own (BUILD_IMAGE, behind sandbox-exec.sh) AFTER the compile
# container has run: only then does the build's list of the npm packages it
# bundled exist. That list, and the source maps beside it, were written by the
# fork's code and npm, so they are DATA here -- untrusted, used for the SET of
# name@version pairs and for the source-map cross-check, never for a licence
# text. The texts come from the npm tarballs the fork's package-lock.json pins,
# fetched by warpgate-notices.py over this container's open network, checked
# against the lockfile's sha512 integrity and read in memory.
#
#   * /notices-src.tar is the decided commit's `git archive` (the same file the
#     parts 1 to 6 container read); only warpgate-web/package-lock.json is
#     taken out of it, as data. If that is a link, the writer refuses it.
#   * /notices-base/THIRD-PARTY-NOTICES.txt is parts 1 to 6, as the first clean
#     container wrote them, before the compile container existed. The output
#     is those bytes plus part 7, never a rewrite (the workflow checks).
#   * /web-evidence holds bundle-licenses.json and maps/ (dist/**/*.map),
#     copied out of the compile container through sandbox-copy-out.sh.
#   * /npm-licences are runcove's reviewed texts for packages that ship none.
#
# Files: /notices-src.tar, /warpgate-notices.py, /third-party-notices.py,
#   /notices-base/THIRD-PARTY-NOTICES.txt, /web-evidence, /npm-licences
# Exit: 0 written to /out/THIRD-PARTY-NOTICES.txt; 1 refused or failed (named).
set -euo pipefail
export LC_ALL=C

fail() { echo "warpgate-notices-npm-run: FAILED -- $*" >&2; exit 1; }

for f in /notices-src.tar /warpgate-notices.py /third-party-notices.py /notices-base/THIRD-PARTY-NOTICES.txt; do
  [ -r "$f" ] || fail "$f was not copied in"
done
for d in /web-evidence /npm-licences; do
  [ -d "$d" ] || fail "$d was not copied in"
done
command -v python3 >/dev/null || fail "the image has no python3"

mkdir -p /npm/src /out
tar -xf /notices-src.tar -C /npm/src warpgate-web/package-lock.json \
  || fail "the decided commit holds no warpgate-web/package-lock.json"
echo "$(python3 --version); part 7 of the notices (no code from the tree runs)"
python3 -I /warpgate-notices.py --engine /third-party-notices.py \
  --base /notices-base/THIRD-PARTY-NOTICES.txt \
  --npm-manifest /web-evidence/bundle-licenses.json --npm-maps /web-evidence/maps \
  --npm-lockfile /npm/src/warpgate-web/package-lock.json --npm-reviewed /npm-licences \
  --out /out/THIRD-PARTY-NOTICES.txt \
  || fail "part 7 was not written; every reason is named above"
[ -s /out/THIRD-PARTY-NOTICES.txt ] || fail "THIRD-PARTY-NOTICES.txt is empty"
echo "THIRD-PARTY-NOTICES.txt sha256 $(sha256sum < /out/THIRD-PARTY-NOTICES.txt | cut -d' ' -f1) (parts 1 to 6 as written before the compile, then part 7)"
