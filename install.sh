#!/bin/sh
# Codex Privacy HUD — one-command install / uninstall for macOS.
# Spec: docs/superpowers/specs/2026-09-15-patched-codex-status-line-design.md §5.6
set -eu

REPO="inin-zou/codex-privacy-hud"
BASE_URL="${PRIVACY_HUD_RELEASE_BASE_URL:-https://github.com/$REPO/releases/download}"
SHARE="$HOME/.local/share/codex-privacy-hud"
BIN="$HOME/.local/bin"
FWD="$BIN/codex"
MANIFEST="$SHARE/manifest.json"
MARK="# codex-privacy-hud"
YES=0; NO_MODEL=0; UNINSTALL=0; PURGE=0; REPAIR=0; PD_ARG=""

# The bundle this script is part of. #66: first-party code is loaded from
# the selected plugin bundle and from nowhere else, and the installer's own
# location is the one thing it knows for certain about which bundle that is
# -- not a cache listing, not a newest directory, not an installed
# distribution's metadata.
BUNDLE="$(cd "$(dirname "$0")" && pwd)"

log() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
usage() {
  echo "usage: install.sh [--yes] [--no-model] [--release-base-url URL]" >&2
  echo "       install.sh --repair-runtime --plugin-data DIR --yes [--no-model]" >&2
  echo "       install.sh --uninstall [--purge]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;;
    --no-model) NO_MODEL=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    --repair-runtime) REPAIR=1 ;;
    --plugin-data) [ $# -ge 2 ] || usage; PD_ARG="$2"; shift ;;
    # Same shape as scripts/build-patched-codex.sh's flag handling: a flag
    # that takes a value must have one. Without the check, `$2` under `set -u`
    # aborts with a shell error about an unbound variable instead of the
    # usage line the user needs.
    --release-base-url) [ $# -ge 2 ] || usage; BASE_URL="$2"; shift ;;
    *) usage ;;
  esac
  shift
done

if [ "$PURGE" -eq 1 ] && [ "$UNINSTALL" -eq 0 ]; then
  echo "usage: --purge requires --uninstall" >&2
  exit 2
fi

target() {
  [ -n "${PRIVACY_HUD_TARGET:-}" ] && { echo "$PRIVACY_HUD_TARGET"; return; }
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) echo aarch64-apple-darwin ;;
    Darwin-x86_64) echo x86_64-apple-darwin ;;
    *) die "unsupported platform $(uname -s)-$(uname -m); macOS only" ;;
  esac
}

first_codex_on_path() {
  # `command -v -a` is not POSIX (and /bin/sh on macOS rejects it); walk PATH.
  # $1 is a path to skip, or empty to skip nothing: the same walk answers two
  # questions -- "where is the official binary" (skip our forwarder) and
  # "which codex would the user's shell actually run" (skip nothing).
  skip="${1:-}"
  saved_ifs="$IFS"; IFS=:
  for d in $PATH; do
    [ -n "$d" ] && [ -x "$d/codex" ] && [ "$d/codex" != "$skip" ] && { IFS="$saved_ifs"; echo "$d/codex"; return 0; }
  done
  IFS="$saved_ifs"; return 1
}

official_codex() { first_codex_on_path "$FWD"; }

# Follow symlinks to the real file, in POSIX sh (macOS ships `readlink -f`
# only since 12.3, and python3 is not something the FAKE test path can rely on).
real_path() {
  p="$1"; n=0
  while [ -L "$p" ] && [ "$n" -lt 20 ]; do
    t="$(readlink "$p")"
    case "$t" in /*) p="$t" ;; *) p="$(dirname "$p")/$t" ;; esac
    n=$((n + 1))
  done
  printf '%s\n' "$p"
}

# The patched tarball carries only `codex`. Codex 0.154 also expects a sibling
# `codex-code-mode-host` and fails Code Mode closed without it. That host cannot
# be built by our release job: it links the `v8` crate, whose build script
# downloads a prebuilt V8 that is not published for every target. It contains
# no TUI, so the official binary of the same version is exactly right -- link
# it in next to the patched `codex`, which is where Codex's own lookup checks.
link_official_host() {
  dest="$1/codex-code-mode-host"
  real="$(real_path "$OFFICIAL")"
  host=""
  cand="$(dirname "$real")/codex-code-mode-host"
  [ -x "$cand" ] && host="$cand"
  if [ -z "$host" ]; then
    case "$real" in
      */bin/codex.js)
        # npm/bun/pnpm layout: the launcher script lives in the package root's
        # bin/, the binaries in a platform package's vendor/<triple>/bin/.
        pkgroot="$(dirname "$(dirname "$real")")"
        case "$TRIPLE" in
          aarch64-apple-darwin) plat=codex-darwin-arm64 ;;
          x86_64-apple-darwin) plat=codex-darwin-x64 ;;
          *) plat="" ;;
        esac
        for cand in "$pkgroot/node_modules/@openai/$plat/vendor/$TRIPLE/bin/codex-code-mode-host" \
                    "$pkgroot/vendor/$TRIPLE/bin/codex-code-mode-host"; do
          [ -n "$plat" ] && [ -x "$cand" ] && { host="$cand"; break; }
        done ;;
    esac
  fi
  if [ -n "$host" ]; then
    ln -sfn "$host" "$dest"
    log "linked codex-code-mode-host from $host"
  else
    log "!! no codex-code-mode-host found beside the official codex; Code Mode"
    log "!! will be unavailable in the patched build (everything else works)."
  fi
}

rc_file() {
  case "${SHELL:-}" in */zsh) echo "$HOME/.zshrc" ;; */bash) echo "$HOME/.bash_profile" ;; *) echo "$HOME/.profile" ;; esac
}

# ------------------------------------------------------- runtime interpreter
# An interpreter is usable when it is new enough AND can import the bundled
# first-party code. Both halves matter: a 3.9 that cannot parse the package,
# and a 3.12 with no dependency environment behind it, fail the same way at
# the first hook and look healthy until then.
usable_python() {
  [ -n "${1:-}" ] && [ -x "$1" ] || return 1
  "$1" -I -B -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1 || return 1
  PRIVACY_HUD_BUNDLE_SRC="$BUNDLE/src" "$1" -I -B -c 'import os, sys; sys.path.insert(0, os.environ["PRIVACY_HUD_BUNDLE_SRC"]); import privacy_hud' >/dev/null 2>&1 || return 1
  return 0
}

# The newest suitable python3 on PATH, for building an installer-owned
# environment. Named versions first: plain `python3` on macOS is 3.9.
host_python() {
  for n in python3.14 python3.13 python3.12 python3.11 python3; do
    c="$(command -v "$n" 2>/dev/null)" || continue
    [ -n "$c" ] || continue
    "$c" -I -B -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  return 1
}

# The interpreter the receipt in $1 records, if any. Read with sed rather
# than with python, because this runs in exactly the states where no python
# is yet known to work.
recorded_python() {
  [ -f "$1/runtime.json" ] || return 1
  sed -n 's/.*"python": *"\([^"]*\)".*/\1/p' "$1/runtime.json" | head -1
}

# Dependencies only, from the SELECTED LOCAL BUNDLE's declared extras. Not
# "privacy-hud[...] @ git+https://...": an unpinned application install from
# a branch is exactly the stale-first-party-code hazard #66 exists to
# remove, and the application now runs from the bundle.
install_bundle_extras() {
  _py="$1"; _pip="$2"
  _specs="$("$_py" - "$BUNDLE/pyproject.toml" <<'EXTRAS'
import sys, tomllib
with open(sys.argv[1], "rb") as handle:
    data = tomllib.load(handle)
project = data.get("project", {})
extras = project.get("optional-dependencies", {})
specs = list(project.get("dependencies", []))
for name in ("detectors", "mcp"):
    specs.extend(extras.get(name, []))
print("\n".join(specs))
EXTRAS
)" || return 1
  [ -n "$_specs" ] || return 0
  printf '%s\n' "$_specs" | while IFS= read -r spec; do
    [ -n "$spec" ] && "$_pip" -q install "$spec"
  done
}

# Console wrappers that dispatch through the bundled bootstrap, which is
# what applies the runtime checks. A wrapper never imports the package
# itself and never resolves a bundle of its own.
install_wrappers() {
  _cand="$1"; _pd="$2"
  mkdir -p "$SHARE/bin"
  for name in doctor ambient ui mcp daemon; do
    cat > "$SHARE/bin/privacy-hud-$name" <<WRAP
#!/bin/sh
# codex-privacy-hud managed wrapper -- remove with: install.sh --uninstall
exec "$_cand" "$BUNDLE/scripts/runtime.py" --plugin-data "$_pd" $name "\$@"
WRAP
    chmod +x "$SHARE/bin/privacy-hud-$name"
  done
}

# Stop the runtime this installation owns, through the bundle's own
# bootstrap. Never pkill, never a name match: the bootstrap identifies
# holders by the files they have open and by their validated identity, and
# refuses rather than signalling anything it does not recognize.
stop_owned_runtime() {
  _pd="$1"
  [ -n "$_pd" ] && [ -f "$BUNDLE/scripts/runtime.py" ] || return 1
  _rec="$(recorded_python "$_pd" 2>/dev/null || true)"
  _host="$(host_python 2>/dev/null || true)"
  for c in "$_rec" "$SHARE/runtime/bin/python" "$SHARE/venv/bin/python" "$_host"; do
    if usable_python "$c"; then
      if "$c" "$BUNDLE/scripts/runtime.py" --plugin-data "$_pd" repair --stop-runtime >/dev/null 2>&1; then
        return 0
      fi
      return 1
    fi
  done
  return 1
}

download_model() {
  # The one online step (I2's installation boundary): the offline flags are
  # turned off for this command only, never for this shell or the runtime.
  HF_HUB_OFFLINE=0 TRANSFORMERS_OFFLINE=0 HF_DATASETS_OFFLINE=0 HF_HUB_DISABLE_TELEMETRY=1 "$1" - <<'WEIGHTS'
from huggingface_hub import snapshot_download
snapshot_download('openai/privacy-filter', allow_patterns=[
    'config.json', 'model.safetensors', 'tokenizer.json',
    'tokenizer_config.json', 'viterbi_calibration.json'])
WEIGHTS
}

# ----------------------------------------------------------- repair runtime
# Repairs the runtime and nothing else. It does not install, replace or
# configure a patched Codex binary, does not touch config.toml, and does not
# edit PATH: a user running it to get monitoring back is not consenting to
# have their Codex installation changed.
if [ "$REPAIR" -eq 1 ]; then
  [ "$UNINSTALL" -eq 0 ] || usage
  [ -n "$PD_ARG" ] || die "--repair-runtime requires --plugin-data DIR"
  [ -d "$PD_ARG" ] || die "--plugin-data: no such directory: $PD_ARG"
  [ -f "$BUNDLE/scripts/runtime.py" ] || die "not a plugin bundle: $BUNDLE"
  PD="$(cd "$PD_ARG" && pwd)"
  CAND=""
  REC="$(recorded_python "$PD" 2>/dev/null || true)"
  if usable_python "$REC"; then
    CAND="$REC"
    log "reusing the recorded interpreter: $CAND"
  elif usable_python "$SHARE/runtime/bin/python"; then
    CAND="$SHARE/runtime/bin/python"
    log "reusing the installer-owned environment: $CAND"
  else
    # The recorded environment is unusable. It is NOT modified: it may be
    # one the user manages, and an installer that writes into it would be
    # taking a decision that is not its to take. A separate,
    # installer-owned environment is built beside the installation instead.
    BASE="$(host_python)" || die "python3 >= 3.11 required: brew install python@3.12"
    log "the recorded environment cannot run the bundled code; building $SHARE/runtime"
    mkdir -p "$SHARE"
    rm -rf "$SHARE/runtime"
    if [ "${PRIVACY_HUD_FAKE:-0}" = "1" ]; then
      "$BASE" -m venv --without-pip "$SHARE/runtime"
    else
      "$BASE" -m venv "$SHARE/runtime"
      "$SHARE/runtime/bin/pip" -q install --upgrade pip
      install_bundle_extras "$SHARE/runtime/bin/python" "$SHARE/runtime/bin/pip" \
        || log "!! some dependencies could not be installed; deep scan may be unavailable"
    fi
    CAND="$SHARE/runtime/bin/python"
    usable_python "$CAND" || die "the installer-owned environment cannot run the bundled code"
  fi
  install_wrappers "$CAND" "$PD"
  if [ "$NO_MODEL" -eq 0 ] && [ "${PRIVACY_HUD_FAKE:-0}" != "1" ]; then
    download_model "$CAND" || log "!! model weights were not downloaded; deep scan will be unavailable"
  fi
  ALLOW=""
  "$CAND" -I -B -c 'import transformers, torch' >/dev/null 2>&1 || ALLOW="--allow-degraded"
  "$CAND" "$BUNDLE/scripts/runtime.py" --plugin-data "$PD" setup --python "$CAND" $ALLOW
  exit $?
fi

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
  [ -f "$MANIFEST" ] || die "nothing to uninstall: $MANIFEST not found"
  if [ -f "$FWD" ]; then
    head -2 "$FWD" | grep -q "codex-privacy-hud forwarder" || die "$FWD is not ours; not removing it"
    rm -f "$FWD"; log "removed $FWD"
  fi
  # config.toml: only touch it when the manifest itself recorded an edit --
  # i.e. this install (or one it inherited the marker from) is what put
  # "privacy" there. A user-authored status_line that happens to already
  # contain "privacy" is left alone (spec: uninstall reverses exactly what
  # the manifest lists, nothing else).
  CFG="$HOME/.codex/config.toml"
  CFG_EDIT="$(sed -n 's/.*"config.toml": *"\([^"]*\)".*/\1/p' "$MANIFEST")"
  if [ -f "$CFG" ] && [ -n "$CFG_EDIT" ]; then
    case "$CFG_EDIT" in
      status_line:created-table)
        # Drop our status_line line; drop the [tui] header too, but only if
        # the table is now empty (a user may have added other keys under it
        # after we created it) -- header followed by EOF, a blank line, or
        # another "[" header counts as empty.
        awk '
          { lines[NR] = $0 }
          END {
            n = NR; m = 0
            for (i = 1; i <= n; i++) {
              if (lines[i] ~ /^status_line = .*"privacy".*$/) continue
              m++; out[m] = lines[i]
            }
            for (i = 1; i <= m; i++) {
              if (out[i] == "[tui]") {
                nxt = (i < m) ? out[i+1] : ""
                if (nxt == "" || nxt ~ /^\[/) continue
              }
              print out[i]
            }
          }
        ' "$CFG" > "$CFG.tmp" && mv "$CFG.tmp" "$CFG" || die "could not rewrite $CFG"
        log "removed privacy from status_line (and the [tui] table we added)"
        ;;
      status_line:created-key)
        sed -i '' -e '/^status_line = .*"privacy".*$/d' "$CFG"
        log "removed the status_line we added"
        ;;
      status_line:privacy)
        # Addressed to the status_line line, and only that line: an unanchored
        # substitution would strip the word "privacy" out of a comment, a
        # `notify` command, or any other string in the file.
        sed -i '' -e '/^[[:space:]]*status_line/s/, *"privacy"//' \
                  -e '/^[[:space:]]*status_line/s/"privacy", *//' "$CFG"
        log "removed privacy from status_line"
        ;;
    esac
  fi
  RC="$(rc_file)"
  if [ -f "$RC" ] && grep -q "$MARK" "$RC"; then
    sed -i '' "/$MARK/d" "$RC"; log "removed PATH line from $RC"
  fi
  # Stop the runtime before removing what runs it. Otherwise the
  # interpreter disappears underneath a live daemon that still holds the
  # ledger open, with its own executable and libraries gone.
  PD="$(sed -n 's/.*"plugin_data": *"\([^"]*\)".*/\1/p' "$MANIFEST")"
  if [ -n "$PD" ]; then
    if stop_owned_runtime "$PD"; then
      log "stopped the Privacy HUD runtime for $PD"
    else
      log "Uninstall is incomplete: Privacy HUD could not confirm that the runtime stopped."
      log "The runtime environment and uninstall manifest were preserved. Data and model purge were skipped."
      log "Some installer-managed shell or Codex configuration may already have been removed."
      exit 1
    fi
  fi
  if [ "$PURGE" -eq 1 ]; then
    MS="$(sed -n 's/.*"model_snapshot": *"\([^"]*\)".*/\1/p' "$MANIFEST")"
    [ -n "$PD" ] && [ -d "$PD" ] && rm -rf "$PD" && log "purged $PD"
    [ -n "$MS" ] && [ -d "$MS" ] && rm -rf "$MS" && log "purged $MS"
  fi
  rm -rf "$SHARE"; log "removed $SHARE"
  rmdir "$BIN" 2>/dev/null || true
  rmdir "$HOME/.local/share" 2>/dev/null || true
  rmdir "$HOME/.local" 2>/dev/null || true
  log "codex now resolves to: $(official_codex || echo '(none found)')"
  log "the plugin itself is separate: codex plugin remove codex-privacy-hud"
  exit 0
fi

# ------------------------------------------------------------------ install
OFFICIAL="$(official_codex)" || die "codex not found on PATH; install Codex CLI first"
VER="$("$OFFICIAL" --version | awk '{print $2}')"
echo "$VER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "cannot parse codex version from: $("$OFFICIAL" --version)"
TRIPLE="$(target)"
log "codex $VER at $OFFICIAL ($TRIPLE)"

# Contract C (spec §4.3). The manifest is written at the START of the install
# and rewritten after every step that creates or edits something, not once at
# the end: an install that aborts half way -- a failed download, a full disk,
# an interrupt -- used to leave a tree full of our files and no manifest at
# all, and `--uninstall` refuses to infer, so there was nothing it could act
# on. An incrementally written manifest always describes exactly what exists.
CREATED=""; EDITED=""
INSTALLED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PD="$HOME/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud"
MS="${HF_HUB_CACHE:-${HF_HOME:-$HOME/.cache/huggingface}/hub}/models--openai--privacy-filter"

# The config.toml edit gets its own slot rather than going through
# `add_edited`, because it is the one entry a re-install can *inherit*: if a
# previous install created the [tui] table, that fact has to survive a second
# run, and appending it again would put two "config.toml" keys in one JSON
# object. Read it before the first `write_manifest` below overwrites the file
# it comes from.
CFG_EDIT=""
if [ -f "$MANIFEST" ]; then
  CFG_EDIT="$(sed -n 's/.*"config.toml": *"\([^"]*\)".*/\1/p' "$MANIFEST")"
fi

write_manifest() {
  _edited="$EDITED"
  if [ -n "$CFG_EDIT" ]; then
    _edited="$_edited\"config.toml\": \"$CFG_EDIT\","
  fi
  cat > "$MANIFEST" <<EOF
{"v": 1, "installed_at": "$INSTALLED_AT", "codex_version": "$VER",
 "created": [${CREATED%,}],
 "edited": {${_edited%,}},
 "plugin_data": "$PD", "model_snapshot": "$MS"}
EOF
}
add_created() { CREATED="$CREATED\"$1\","; write_manifest; }
add_edited() { EDITED="$EDITED\"$1\": \"$2\","; write_manifest; }
set_cfg_edit() { CFG_EDIT="$1"; write_manifest; }

mkdir -p "$SHARE"
# $SHARE itself is deliberately not in `created`: --uninstall removes it
# unconditionally (it is ours by name), and listing it would make the
# manifest describe its own directory.
write_manifest
# $SHARE itself is deliberately not in `created`: --uninstall removes it
# unconditionally (it is ours by name), and listing it would make the
# manifest describe its own directory.
write_manifest
if [ "${PRIVACY_HUD_FAKE:-0}" != "1" ]; then
  command -v python3 >/dev/null || die "python3 >= 3.11 required: brew install python@3.12"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "python3 >= 3.11 required: brew install python@3.12"
  log "step 2/9: creating venv and installing dependencies (a few minutes)"
  BASE="$(host_python)" || die "python3 >= 3.11 required: brew install python@3.12"
  "$BASE" -m venv "$SHARE/venv"
  "$SHARE/venv/bin/pip" -q install --upgrade pip
  # Dependencies only, from this bundle's declared extras. The application
  # itself is no longer installed as a distribution: #66 loads first-party
  # code from the selected plugin bundle, and an unpinned
  # "privacy-hud @ git+https://..." install is precisely the stale copy
  # that would then be imported instead.
  install_bundle_extras "$SHARE/venv/bin/python" "$SHARE/venv/bin/pip"
  add_created "$SHARE/venv/"
  if [ "$NO_MODEL" -eq 0 ]; then
    if [ "$YES" -eq 0 ]; then
      # Piped installs (`curl ... | sh`) have no controlling terminal to
      # prompt on -- plain `read` there either reads the script's own bytes
      # off the pipe or hits EOF, and either way a bare failing `read` would
      # abort the whole script under `set -e` right after step 2 already
      # installed the venv. Only prompt when /dev/tty is actually usable,
      # and never let a failed read propagate out of this statement.
      if ans="$(printf 'step 3/9: download openai/privacy-filter weights (~2.8 GB, from Hugging Face; runtime never downloads weights)? [y/N] ' 2>/dev/null >/dev/tty && read -r a 2>/dev/null </dev/tty && echo "$a")" 2>/dev/null; then
        case "$ans" in y|Y) ;; *) NO_MODEL=1 ;; esac
      else
        log "no terminal to ask about the model download; skipping it -- rerun with --yes to fetch the weights"
        NO_MODEL=1
      fi
    fi
  fi
  if [ "$NO_MODEL" -eq 0 ]; then
    download_model "$SHARE/venv/bin/python"
  else
    log "skipping model weights: tier 3 (names, addresses) will be unavailable"
  fi
  log "step 4/9: installing the Codex plugin"
  codex plugin marketplace add "$REPO" >/dev/null 2>&1 || true
  codex plugin add "codex-privacy-hud@codex-privacy-hud" >/dev/null 2>&1 || true
  log "step 5/9: selecting the installed plugin bundle and recording the interpreter"
  # The bundle Codex actually runs is the copy in its own plugin cache, and
  # which copy that is has to be RESOLVED, not guessed: two cached copies
  # are an error here, never a newest-directory choice (#66).
  INSTALLED="$(PRIVACY_HUD_BUNDLE_SRC="$BUNDLE/src" "$SHARE/venv/bin/python" -I -B -c 'import os, sys
sys.path.insert(0, os.environ["PRIVACY_HUD_BUNDLE_SRC"])
from privacy_hud import runtime_contract, runtime_repair
sys.stdout.write(str(runtime_repair.resolve_installed_bundle(runtime_contract.RELEASE)))' 2>/dev/null)" \
    || die "could not resolve exactly one installed plugin bundle; run: codex plugin list"
  [ -n "$INSTALLED" ] && [ -f "$INSTALLED/scripts/runtime.py" ] \
    || die "could not resolve exactly one installed plugin bundle; run: codex plugin list"
  log "installed bundle: $INSTALLED"
  install_wrappers "$SHARE/venv/bin/python" "$PD"
  "$SHARE/venv/bin/python" "$INSTALLED/scripts/runtime.py" --plugin-data "$PD" \
    setup --python "$SHARE/venv/bin/python" $( [ "$NO_MODEL" -eq 1 ] && echo --allow-degraded )
fi

log "step 6/9: fetching patched Codex $VER"
ART="codex-privacy-$VER-$TRIPLE.tar.gz"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
# Two URLs, and the second one is the one that usually answers. The
# versioned URL resolves only if a release was tagged exactly
# `codex-<ver>-hud` for the version this machine's official binary reports
# -- which happens only when someone cut a release for that exact Codex
# point release. The rolling `latest` release is therefore load-bearing,
# not a convenience: it is what CI republishes every build to, and what
# makes an install work the day after Codex ships a version nobody has
# tagged a build for yet. If `latest` ever stops being published, most
# installs fall through to the no-build branch below.
if curl -fsSL "$BASE_URL/codex-$VER-hud/$ART" -o "$TMP/$ART" 2>/dev/null || curl -fsSL "$BASE_URL/latest/$ART" -o "$TMP/$ART" 2>/dev/null; then
  if ! { curl -fsSL "$BASE_URL/codex-$VER-hud/$ART.sha256" -o "$TMP/$ART.sha256" 2>/dev/null || curl -fsSL "$BASE_URL/latest/$ART.sha256" -o "$TMP/$ART.sha256" 2>/dev/null; }; then
    die "checksum file for $ART not found; not installing"
  fi
  EXPECT="$(awk '{print $1}' "$TMP/$ART.sha256")"
  ACTUAL="$(shasum -a 256 "$TMP/$ART" | awk '{print $1}')"
  [ "$EXPECT" = "$ACTUAL" ] || die "checksum mismatch for $ART; not installing"
  mkdir -p "$SHARE/$VER"
  tar -xzf "$TMP/$ART" -C "$SHARE/$VER"
  chmod +x "$SHARE/$VER/codex"
  xattr -d com.apple.quarantine "$SHARE/$VER/codex" 2>/dev/null || true
  add_created "$SHARE/$VER/"
  link_official_host "$SHARE/$VER"
  mkdir -p "$BIN"
  cat > "$FWD" <<'FWD'
#!/bin/sh
# codex-privacy-hud forwarder — remove with: install.sh --uninstall
self="$HOME/.local/bin/codex"
official=""
saved_ifs="$IFS"; IFS=:
for d in $PATH; do
  [ -n "$d" ] && [ -x "$d/codex" ] && [ "$d/codex" != "$self" ] && { official="$d/codex"; break; }
done
IFS="$saved_ifs"
[ -x "$official" ] || { echo "codex-privacy-hud: official codex not found" >&2; exit 127; }
ver="$("$official" --version | awk '{print $2}')"
# $ver comes from another program's stdout and is about to become a path
# segment. Exactly x.y.z, the same regex install.sh checks, or we do not
# build a path out of it at all -- just run the official binary.
printf '%s\n' "$ver" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || exec "$official" "$@"
patched="$HOME/.local/share/codex-privacy-hud/$ver/codex"
[ -x "$patched" ] && exec "$patched" "$@"
exec "$official" "$@"
FWD
  chmod +x "$FWD"; add_created "$FWD"
  log "step 7/9: forwarder at $FWD"
  # Test hook (tests/test_install_sh.py): abort here, with the forwarder and
  # the patched build on disk, to prove the incrementally written manifest
  # leaves --uninstall something to act on.
  if [ "${PRIVACY_HUD_FAKE_ABORT_AFTER:-}" = "forwarder" ]; then
    die "aborted after the forwarder (PRIVACY_HUD_FAKE_ABORT_AFTER)"
  fi
  # Installing the forwarder is not the same as winning: `~/.local/bin` may
  # already be on PATH but *after* the directory holding the official binary
  # (Homebrew's, typically), in which case everything below succeeds, the rc
  # file is not touched -- the `case` right after this only appends when the
  # directory is absent entirely -- and `codex` keeps running the official
  # build with no status item and no explanation. Say so, loudly.
  WINNER="$(first_codex_on_path '' || true)"
  if [ "$WINNER" != "$FWD" ]; then
    log ""
    log "!! PATH: '$WINNER' still comes before '$FWD', so typing 'codex' will"
    log "!! keep running the official binary and the privacy status item will"
    log "!! not appear. Put this line FIRST in $(rc_file), then open a new shell:"
    log "!!"
    log '!!     export PATH="$HOME/.local/bin:$PATH"'
    log ""
  fi
  case ":$PATH:" in *":$BIN:"*) ;; *)
    RC="$(rc_file)"; printf 'export PATH="$HOME/.local/bin:$PATH" %s\n' "$MARK" >> "$RC"
    add_edited "$RC" "path-line"; log "added $BIN to PATH in $RC (open a new shell)" ;;
  esac
  log "step 8/9: enabling the privacy status item"
  # `~/.codex` may not exist yet on a machine where Codex is installed but has
  # never been run; `touch` would fail and take the whole install with it.
  mkdir -p "$HOME/.codex"
  CFG="$HOME/.codex/config.toml"; touch "$CFG"
  # Codex's own default status line plus ours. Matching the defaults matters:
  # setting the key at all replaces the built-in list, so a shorter value here
  # would silently take items away from a user who never asked us to.
  DEFAULT_LINE='status_line = ["model-with-reasoning", "current-dir", "thread-name", "privacy"]'
  # Two detections, both deliberately WIDER than what the edits below can
  # handle, because the question they answer is "is there something here I
  # might break?", not "is there something here I can edit?". A key or a
  # header we can see but cannot edit exactly is a refusal, never a guess:
  # this file is the user's, and half-understood TOML rewritten by a regex is
  # how a config gets corrupted.
  HAS_KEY=0
  if grep -Eq '^[[:space:]]*status_line[[:space:]]*=' "$CFG"; then HAS_KEY=1; fi
  HAS_TUI=0
  if grep -Eq '^[[:space:]]*\[tui\][[:space:]]*(#.*)?$' "$CFG"; then HAS_TUI=1; fi
  cfg_refuse() {
    log ""
    log "!! config.toml: $1"
    log "!! Nothing was changed. Add \"privacy\" to [tui].status_line yourself:"
    log "!!     $DEFAULT_LINE"
    log ""
  }
  if [ "$HAS_KEY" -eq 1 ]; then
    if grep -q '"privacy"' "$CFG"; then
      # Already listed -- by us on an earlier run, or by the user. Either way
      # there is nothing to do, and $CFG_EDIT (read from the previous
      # manifest, above) already carries whatever we are entitled to reverse.
      log "status_line already lists privacy; leaving config.toml alone"
    elif grep -Eq '^status_line[[:space:]]*=[[:space:]]*\[' "$CFG"; then
      sed -i '' 's/^\(status_line *= *\[\)/\1"privacy", /' "$CFG"
      set_cfg_edit "status_line:privacy"
    else
      # Indented (so it belongs to some table we have not identified), or not
      # an inline array at all. The sed above is anchored at column 0 and
      # assumes a `[`; it would edit the wrong table or nothing.
      cfg_refuse "a status_line this installer cannot edit safely (indented, or not an inline array)"
    fi
  elif [ "$HAS_TUI" -eq 1 ]; then
    if grep -q '^\[tui\]$' "$CFG"; then
      # the table exists without the key: add only the key, right under the header
      sed -i '' "/^\\[tui\\]\$/a\\
$DEFAULT_LINE
" "$CFG"
      set_cfg_edit "status_line:created-key"
    else
      # A [tui] header spelled with a trailing space or a trailing comment.
      # The append path below would add a SECOND [tui] table, which TOML
      # rejects outright -- a config Codex then refuses to load at all.
      cfg_refuse "a [tui] header this installer cannot match exactly (trailing spaces or a comment)"
    fi
  else
    # Nothing to collide with. Keep the append from running into a last line
    # with no newline of its own.
    if [ -s "$CFG" ] && [ -n "$(tail -c 1 "$CFG")" ]; then
      printf '\n' >> "$CFG"
    fi
    printf '[tui]\n%s\n' "$DEFAULT_LINE" >> "$CFG"
    set_cfg_edit "status_line:created-table"
  fi
else
  log "no patched build published for codex $VER yet; skipping the status line."
  log "the fallback pane still works: $SHARE/bin/privacy-hud-ambient --watch"
fi

if [ "${PRIVACY_HUD_FAKE:-0}" != "1" ]; then
  log "step 9/9: doctor"
  # Through the managed wrapper, which dispatches to the selected bundle's
  # bootstrap with this installation's plugin-data directory already
  # supplied -- the value Codex assigns its hooks, and the one historical
  # misconfiguration this project has paid for most.
  "$SHARE/bin/privacy-hud-doctor" || true
fi

# Already written after every step that changed anything; this final call
# only matters when nothing did.
write_manifest
log "done. restart codex to load the installed plugin and PATH changes"
log "      the native Privacy item requires a snapshot-v2-compatible patched Codex build"
log "      matching Codex versions and successful installation do not establish snapshot compatibility"
log "      until compatibility is verified, use: $SHARE/bin/privacy-hud-ambient --watch"
log "      \$privacy shows the session audit"
