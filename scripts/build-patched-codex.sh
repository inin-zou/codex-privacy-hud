#!/bin/sh
# Build a Codex binary with patches/privacy-status-line.patch applied.
#
# The same script runs on a laptop and in CI (.github/workflows), so the
# artifact a contributor builds by hand and the one a release publishes come
# out of one code path and carry one name:
#
#     <out>/codex-privacy-<ver>-<triple>.tar.gz   (+ .sha256)
#
# The tarball holds exactly one file, `codex`, so install.sh can unpack it
# anywhere without a --strip-components guess.
#
# usage: build-patched-codex.sh <codex-version> [--target <triple>]
#                              [--out <dir>] [--src <dir>] [--dry-run]
#
# --dry-run prints the plan -- tag, patch, target, artifact -- and stops
# before the clone and the compile. That is what tests/test_build_script.py
# exercises: argument handling and file naming are worth testing, and a
# 20-minute cargo build is not something a test suite should start.
set -eu

usage() {
  echo "usage: $0 <codex-version> [--target <triple>] [--out <dir>] [--dry-run] [--src <dir>]" >&2
  exit 2
}

[ $# -ge 1 ] || usage
VER="$1"; shift
# Exactly x.y.z. A tag like "latest" would silently build something other than
# the version the artifact name claims.
echo "$VER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || usage

TARGET=""; OUT="dist"; DRY=0; SRC=""
while [ $# -gt 0 ]; do
  case "$1" in
    --target) [ $# -ge 2 ] || usage; TARGET="$2"; shift 2 ;;
    --out)    [ $# -ge 2 ] || usage; OUT="$2"; shift 2 ;;
    --src)    [ $# -ge 2 ] || usage; SRC="$2"; shift 2 ;;
    --dry-run) DRY=1; shift ;;
    *) usage ;;
  esac
done

# Lazily: the CI job calls this before rustup is on PATH, and asking a missing
# rustc for the host triple there would abort a build that already knows its
# target. Only consult rustc when --target was not given.
if [ -z "$TARGET" ]; then
  TARGET="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
fi
[ -n "$TARGET" ] || { echo "cannot determine target; pass --target" >&2; exit 2; }

HERE="$(cd "$(dirname "$0")/.." && pwd)"
PATCH="$HERE/patches/privacy-status-line.patch"
TAG="rust-v$VER"
ARTIFACT="codex-privacy-$VER-$TARGET.tar.gz"
case "$OUT" in
  /*) OUTDIR="$OUT" ;;
  *)  OUTDIR="$HERE/$OUT" ;;
esac
if [ -z "$SRC" ]; then
  TMP="${TMPDIR:-/tmp}"
  SRC="${TMP%/}/codex-src-$VER"
fi

echo "tag:      $TAG"
echo "patch:    patches/privacy-status-line.patch"
echo "target:   $TARGET"
echo "source:   $SRC"
echo "artifact: $OUTDIR/$ARTIFACT"
if [ "$DRY" -eq 1 ]; then
  exit 0
fi

[ -f "$PATCH" ] || { echo "missing $PATCH" >&2; exit 1; }
if [ ! -d "$SRC/.git" ]; then
  git clone --depth 1 --branch "$TAG" https://github.com/openai/codex "$SRC"
fi
cd "$SRC"
# Re-runs are normal (a failed build, a changed patch), so start from the tag's
# tree every time rather than applying the patch on top of itself.
git checkout -q -- .
git clean -qfd codex-rs
# --check first: a patch that no longer applies must say so before anything is
# written, so a half-patched tree never reaches cargo.
git apply --check "$PATCH"
git apply "$PATCH"

cd codex-rs
cargo build --release -p codex-cli --target "$TARGET"
BIN="target/$TARGET/release/codex"
[ -x "$BIN" ] || { echo "no binary at $BIN" >&2; exit 1; }
# The tag and the binary must agree: cargo happily reuses a stale target/ dir
# from another checkout, and an artifact named 0.154.0 that reports something
# else is exactly the failure install.sh cannot detect.
"$BIN" --version | grep -q "$VER" || {
  echo "built binary reports the wrong version" >&2
  exit 1
}

mkdir -p "$OUTDIR"
tar -C "$(dirname "$BIN")" -czf "$OUTDIR/$ARTIFACT" codex
( cd "$OUTDIR" && shasum -a 256 "$ARTIFACT" > "$ARTIFACT.sha256" )
echo "built $OUTDIR/$ARTIFACT"
