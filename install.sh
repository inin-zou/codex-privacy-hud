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

log() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
usage() {
  echo "usage: install.sh [--yes] [--no-model] [--release-base-url URL] | --uninstall [--purge]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --yes) YES=1 ;;
    --no-model) NO_MODEL=1 ;;
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1 ;;
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
  log "step 2/9: creating venv and installing the plugin package (a few minutes)"
  python3 -m venv "$SHARE/venv"
  "$SHARE/venv/bin/pip" -q install --upgrade pip
  "$SHARE/venv/bin/pip" -q install "privacy-hud[detectors,mcp] @ git+https://github.com/$REPO"
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
    # The one online step (I2's installation boundary): the offline flags are
    # turned off for this command only, never for this shell or the runtime.
    HF_HUB_OFFLINE=0 TRANSFORMERS_OFFLINE=0 HF_DATASETS_OFFLINE=0 HF_HUB_DISABLE_TELEMETRY=1 "$SHARE/venv/bin/python" - <<'PY'
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
  log "the fallback pane still works: privacy-hud-ambient --watch"
fi

if [ "${PRIVACY_HUD_FAKE:-0}" != "1" ]; then
  log "step 9/9: doctor"
  # Codex sets PLUGIN_DATA for its hooks; doctor run from here would otherwise
  # report it unset and call the setup unusable, which it is not.
  PLUGIN_DATA="$HOME/.codex/plugins/data/codex-privacy-hud-codex-privacy-hud" \
    "$SHARE/venv/bin/privacy-hud-doctor" || true
fi

# Already written after every step that changed anything; this final call
# only matters when nothing did.
write_manifest
log "done. restart codex to pick up the patched build and the privacy status item"
log "      (then /statusline toggles the item; \$privacy shows the session audit)"
