from __future__ import annotations

import os
import signal
import subprocess
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
INSTALL = REPO / "install.sh"
MARKER = b"# codex-privacy-hud forwarder"

FUSE = """\
# Test-only containment; never installed by the product.
case "${PH_TEST_DEPTH:-0}" in
  0|1|2) PH_TEST_DEPTH=$((PH_TEST_DEPTH + 1)) ;;
  *)
    printf '%s\\n' 'TEST forwarder entry limit reached' >&2
    kill -s KILL -- "-$PH_TEST_PGID"
    exit 99
    ;;
esac
export PH_TEST_DEPTH
"""


def heredoc(source: str, tag: str) -> str:
    return source.split(f"<<'{tag}'\n", 1)[1].split(
        f"\n{tag}\n", 1
    )[0] + "\n"


def forwarder_source() -> str:
    source = INSTALL.read_text(encoding="utf-8")
    # The RED tree has the original single heredoc. GREEN uses three
    # literal sections; neither path executes installer code.
    if "<<'FWD'\n" in source:
        return heredoc(source, "FWD")
    return "".join(
        heredoc(source, tag)
        for tag in ("FWD_HEADER", "CODEX_PATH_HELPERS", "FWD_BODY")
    )


def executable(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)
    return path


def forwarder(path: Path) -> Path:
    return executable(path, forwarder_source())


def _instrument(text: str) -> str:
    lines = text.splitlines(keepends=True)
    index = 1
    while index < len(lines) and (
        lines[index].startswith("#") or not lines[index].strip()
    ):
        index += 1
    return "".join(lines[:index]) + FUSE + "".join(lines[index:])


def bounded_run(
    root: Path,
    argv: list[str],
    env: dict[str, str],
    *,
    forwarders: tuple[Path, ...] = (),
    cwd: Path | None = None,
    timeout: float = 5,
) -> subprocess.CompletedProcess[str]:
    root = root.resolve()
    work = (cwd or root).resolve()
    assert work.is_relative_to(root)
    assert Path(env["HOME"]).resolve().is_relative_to(root)

    # No inherited PATH and no interpreter-parent directory on PATH.
    system_dirs = {"/usr/bin", "/bin", "/usr/sbin", "/sbin"}
    for entry in env["PATH"].split(":"):
        candidate = Path(entry) if entry else work
        if not candidate.is_absolute():
            candidate = work / candidate
        assert (
            str(candidate) in system_dirs
            or candidate.resolve().is_relative_to(root)
        ), entry

    saved: dict[Path, tuple[bytes, bytes]] = {}
    process = None
    try:
        for item in forwarders:
            path = item.resolve(strict=True)
            assert path.is_relative_to(root)
            if path in saved:
                continue
            original = path.read_bytes()
            assert any(
                line.startswith(MARKER)
                for line in original[:512].splitlines()[:2]
            )
            instrumented = _instrument(
                original.decode("utf-8")
            ).encode("utf-8")
            saved[path] = original, instrumented
            path.write_bytes(instrumented)

        child_env = dict(env)
        child_env.pop("PH_TEST_PGID", None)
        child_env["PH_TEST_DEPTH"] = "0"
        process = subprocess.Popen(
            [
                "/bin/sh",
                "-c",
                'ulimit -t 2 || exit 125; '
                'PH_TEST_PGID=$$; export PH_TEST_PGID; '
                'exec "$0" "$@"',
                *argv,
            ],
            cwd=work,
            env=child_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate(timeout=2)
            raise
        return subprocess.CompletedProcess(
            argv, process.returncode, stdout, stderr
        )
    finally:
        # Restore only our instrumentation. An installer may have
        # legitimately replaced the fixture during this invocation.
        for path, (original, instrumented) in saved.items():
            if path.exists() and path.read_bytes() == instrumented:
                path.write_bytes(original)
