#!/usr/bin/env python3
"""Print the release branch: cove-patches-<upstream_tag>, from checks.yaml.

The one place a workflow learns which branch is the release branch, so cutting
a new version is one edit (`upstream_tag:` in checks.yaml) rather than one edit
plus every workflow that spelled the branch out.

STDLIB ONLY, ON PURPOSE, AND THAT IS A DECISION WORTH DEFENDING. The house rule
is that YAML is parsed by PyYAML (checks_lib), never by hand. But the build and
poll runners do not carry PyYAML -- warpgate-ci.yml has to apt-get it -- and
installing it on the publish path would spend network and seconds on every
build to read one line. So this reads exactly ONE top-level scalar from a file
we own, and is strict rather than clever: anything that is not a single line of
the form `upstream_tag: v<version>` REFUSES (93). It never guesses. A test
(test_release_branch.py) pins this reader to agree with checks_lib's PyYAML
reading of the real checks.yaml, so the two cannot drift silently.

The failure mode is therefore a refused build with a message naming checks.yaml,
never a build of the wrong branch -- which matters, because the wip guards and
the publish steps key off the branch name.

Usage: release_branch.py [path/to/checks.yaml]   (default: ../checks.yaml)
Exit:  0 printed the branch; 93 could not establish it (nothing printed).
"""

import pathlib
import re
import sys

PREFIX = "cove-patches-"
DEFAULT_CHECKS = pathlib.Path(__file__).resolve().parent.parent / "checks.yaml"

# Top-level key only (no indentation), a bare version starting with `v`, and
# nothing after it but whitespace. Quoted values, anchors, flow syntax or a
# trailing comment are all refused rather than interpreted.
LINE = re.compile(r"^upstream_tag: (v[0-9][0-9A-Za-z._-]*)[ \t]*$")
KEYISH = re.compile(r"^\s*upstream_tag\s*:")


def upstream_tag(text):
    """Return the tag, or raise ValueError saying why it could not."""
    candidates = [l for l in text.splitlines() if KEYISH.match(l)]
    if not candidates:
        raise ValueError("no `upstream_tag:` line")
    if len(candidates) > 1:
        raise ValueError(f"{len(candidates)} `upstream_tag:` lines; exactly one is allowed")
    m = LINE.match(candidates[0])
    if not m:
        raise ValueError(
            f"`{candidates[0].strip()}` is not of the strict form "
            "`upstream_tag: v<version>` at the top level with nothing after it")
    return m.group(1)


def release_branch(text):
    return PREFIX + upstream_tag(text)


def main(argv):
    path = pathlib.Path(argv[1]) if len(argv) > 1 else DEFAULT_CHECKS
    try:
        text = path.read_text()
    except OSError as exc:
        print(f"release_branch: REFUSED -- cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(93)
    try:
        branch = release_branch(text)
    except ValueError as exc:
        print(f"release_branch: REFUSED -- {path}: {exc}. Fix upstream_tag in "
              "checks.yaml; no branch was guessed.", file=sys.stderr)
        sys.exit(93)
    print(branch)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
