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
YES=0; NO_MODEL=0; UNINSTALL=0; PURGE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;;
    --no-model) NO_MODEL=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
    --release-base-url) BASE_URL="$2"; shift ;;
    *) echo "usage: install.sh [--yes] [--no-model] [--release-base-url URL] | --uninstall [--purge]" >&2; exit 2 ;;
  esac
  shift
done

log() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

target() {
  [ -n "${PRIVACY_HUD_TARGET:-}" ] && { echo "$PRIVACY_HUD_TARGET"; return; }
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) echo aarch64-apple-darwin ;;
    Darwin-x86_64) echo x86_64-apple-darwin ;;
    *) die "unsupported platform $(uname -s)-$(uname -m); macOS only" ;;
  esac
}

official_codex() {
  # `command -v -a` is not POSIX (and /bin/sh on macOS rejects it); walk PATH.
  saved_ifs="$IFS"; IFS=:
  for d in $PATH; do
    [ -n "$d" ] && [ -x "$d/codex" ] && [ "$d/codex" != "$FWD" ] && { IFS="$saved_ifs"; echo "$d/codex"; return 0; }
  done
  IFS="$saved_ifs"; return 1
}

rc_file() {
  case "${SHELL:-}" in */zsh) echo "$HOME/.zshrc" ;; */bash) echo "$HOME/.bash_profile" ;; *) echo "$HOME/.profile" ;; esac
}

# ---------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
  [ -f "$MANIFEST" ] || die "nothing to uninstall: $MANIFEST not found"
  if [ -f "$FWD" ]; then
    head -2 "$FWD" | grep -q "codex-privacy-hud forwarder" || die "$FWD is not ours; not removing it"
    rm -f "$FWD"; log "removed $FWD"
  fi
  # config.toml: remove "privacy" from status_line; drop the key if we created it
  CFG="$HOME/.codex/config.toml"
  if [ -f "$CFG" ] && grep -q '"privacy"' "$CFG"; then
    if grep -q '"config.toml": "status_line:created-table"' "$MANIFEST"; then
      sed -i '' -e '/^\[tui\]$/d' -e '/^status_line = .*"privacy".*$/d' "$CFG"
    elif grep -q '"config.toml": "status_line:created-key"' "$MANIFEST"; then
      sed -i '' -e '/^status_line = .*"privacy".*$/d' "$CFG"
    else
      sed -i '' -e 's/, *"privacy"//; s/"privacy", *//' "$CFG"
    fi
    log "removed privacy from status_line"
  fi
  RC="$(rc_file)"
  if [ -f "$RC" ] && grep -q "$MARK" "$RC"; then
    sed -i '' "/$MARK/d" "$RC"; log "removed PATH line from $RC"
  fi
  if [ "$PURGE" -eq 1 ]; then
    PD="$(sed -n 's/.*"plugin_data": *"\([^"]*\)".*/\1/p' "$MANIFEST")"
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

CREATED=""; EDITED=""
add_created() { CREATED="$CREATED\"$1\","; }
add_edited() { EDITED="$EDITED\"$1\": \"$2\","; }

mkdir -p "$SHARE"
if [ "${PRIVACY_HUD_FAKE:-0}" != "1" ]; then
  command -v python3 >/dev/null || die "python3 >= 3.11 required: brew install python@3.12"
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' || die "python3 >= 3.11 required: brew install python@3.12"
  log "step 2/9: creating venv and installing the plugin package (a few minutes)"
  python3 -m venv "$SHARE/venv"
  "$SHARE/venv/bin/pip" -q install --upgrade pip
  "$SHARE/venv/bin/pip" -q install "privacy-hud[detectors] @ git+https://github.com/$REPO"
  add_created "$SHARE/venv/"
  if [ "$NO_MODEL" -eq 0 ]; then
    if [ "$YES" -eq 0 ]; then
      printf 'step 3/9: download openai/privacy-filter weights (~2.8 GB, from Hugging Face, once; everything after is offline)? [y/N] '
      read -r ans; case "$ans" in y|Y) ;; *) NO_MODEL=1 ;; esac
    fi
  fi
  if [ "$NO_MODEL" -eq 0 ]; then
    "$SHARE/venv/bin/python" - <<'PY'
from huggingface_hub import snapshot_download
snapshot_download('openai/privacy-filter', allow_patterns=[
    'config.json', 'model.safetensors', 'tokenizer.json',
    'tokenizer_config.json', 'viterbi_calibration.json'])
PY
  else
    log "skipping model weights: tier 3 (names, addresses) will be unavailable"
  fi
  log "step 4/9: installing the Codex plugin"
  codex plugin marketplace add "$REPO" >/dev/null 2>&1 || true
  codex plugin add "codex-privacy-hud@codex-privacy-hud" >/dev/null 2>&1 || true
  log "step 5/9: recording the interpreter"
  "$SHARE/venv/bin/privacy-hud-setup" $( [ "$NO_MODEL" -eq 1 ] && echo --allow-degraded )
fi

log "step 6/9: fetching patched Codex $VER"
ART="codex-privacy-$VER-$TRIPLE.tar.gz"
TMP="$(mktemp -d)"
if curl -fsSL "$BASE_URL/codex-$VER-hud/$ART" -o "$TMP/$ART" 2>/dev/null || curl -fsSL "$BASE_URL/latest/$ART" -o "$TMP/$ART" 2>/dev/null; then
  curl -fsSL "$BASE_URL/codex-$VER-hud/$ART.sha256" -o "$TMP/$ART.sha256" 2>/dev/null || curl -fsSL "$BASE_URL/latest/$ART.sha256" -o "$TMP/$ART.sha256"
  EXPECT="$(awk '{print $1}' "$TMP/$ART.sha256")"
  ACTUAL="$(shasum -a 256 "$TMP/$ART" | awk '{print $1}')"
  [ "$EXPECT" = "$ACTUAL" ] || die "checksum mismatch for $ART; not installing"
  mkdir -p "$SHARE/$VER"
  tar -xzf "$TMP/$ART" -C "$SHARE/$VER"
  chmod +x "$SHARE/$VER/codex"
  xattr -d com.apple.quarantine "$SHARE/$VER/codex" 2>/dev/null || true
  add_created "$SHARE/$VER/"
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
patched="$HOME/.local/share/codex-privacy-hud/$ver/codex"
[ -x "$patched" ] && exec "$patched" "$@"
exec "$official" "$@"
FWD
  chmod +x "$FWD"; add_created "$FWD"
  log "step 7/9: forwarder at $FWD"
  case ":$PATH:" in *":$BIN:"*) ;; *)
    RC="$(rc_file)"; printf 'export PATH="$HOME/.local/bin:$PATH" %s\n' "$MARK" >> "$RC"
    add_edited "$RC" "path-line"; log "added $BIN to PATH in $RC (open a new shell)" ;;
  esac
  log "step 8/9: enabling the privacy status item"
  CFG="$HOME/.codex/config.toml"; touch "$CFG"
  if grep -q '^status_line *=' "$CFG"; then
    grep -q '"privacy"' "$CFG" || { sed -i '' 's/^\(status_line *= *\[\)/\1"privacy", /' "$CFG"; add_edited "config.toml" "status_line:privacy"; }
  elif grep -q '^\[tui\]$' "$CFG"; then
    # the table exists without the key: add only the key, right under the header
    sed -i '' '/^\[tui\]$/a\
status_line = ["model-with-reasoning", "current-dir", "privacy"]
' "$CFG"
    add_edited "config.toml" "status_line:created-key"
  else
    printf '[tui]\nstatus_line = ["model-with-reasoning", "current-dir", "privacy"]\n' >> "$CFG"
    add_edited "config.toml" "status_line:created-table"
  fi
else
  log "no patched build published for codex $VER yet; skipping the status line."
  log "the fallback pane still works: privacy-hud-ambient --watch"
fi
rm -rf "$TMP"

if [ "${PRIVACY_HUD_FAKE:-0}" != "1" ]; then
  log "step 9/9: doctor"
  "$SHARE/venv/bin/privacy-hud-doctor" || true
fi

PD="$HOME/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud"
MS="${HF_HUB_CACHE:-${HF_HOME:-$HOME/.cache/huggingface}/hub}/models--openai--privacy-filter"
cat > "$MANIFEST" <<EOF
{"v": 1, "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "codex_version": "$VER",
 "created": [${CREATED%,}],
 "edited": {${EDITED%,}},
 "plugin_data": "$PD", "model_snapshot": "$MS"}
EOF
log "done. run: codex   (then /statusline to toggle the privacy item)"
