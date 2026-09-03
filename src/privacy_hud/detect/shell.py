"""Tier 2 — classify where a shell command sends data.

Fails closed: anything carrying a URL or host-looking argument that we cannot
prove is local is treated as external (Global Constraint I6).
"""
from __future__ import annotations

import re
import shlex

NET_BINARIES = {"curl", "wget", "scp", "rsync", "sftp", "ssh", "nc", "netcat",
                "telnet", "ftp", "http", "httpie"}
URL = re.compile(r"\b[a-z][a-z0-9+.-]*://([^\s/\"']+)")
SCP_TARGET = re.compile(r"\b[\w.-]+@([\w.-]+):")
DEV_TCP = re.compile(r"/dev/tcp/([\w.-]+)/\d+")

# A generic "dotted word" pattern (e.g. `^(?:[\w-]+\.)+[a-z]{2,}$`) can't tell
# a hostname from a local filename: `support.log` and `bar.txt` match it just
# as well as `evil.test` does. Anchor on a known-TLD suffix instead, so bare
# (schemeless) host-looking arguments are still caught without flagging every
# dotted filename as an exfil destination.
KNOWN_TLDS = {
    "com", "net", "org", "io", "dev", "app", "co", "ai", "me", "info", "biz",
    "gov", "edu", "mil", "xyz", "test", "cloud", "tech", "site", "online",
    "live", "tv", "local", "internal",
    "us", "uk", "de", "fr", "jp", "cn", "ru", "ca", "au", "nz", "in", "br",
    "es", "it", "nl",
}
BARE_HOST = re.compile(
    r"^(?:[\w-]+\.)+(?:" + "|".join(sorted(KNOWN_TLDS)) + r")$", re.I
)


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command)
    except ValueError:
        return command.split()


def destination_hosts(command: str) -> list[str]:
    hosts = [m.group(1) for m in URL.finditer(command)]
    hosts += [m.group(1) for m in SCP_TARGET.finditer(command)]
    hosts += [m.group(1) for m in DEV_TCP.finditer(command)]
    toks = _tokens(command)
    for i, t in enumerate(toks):
        base = t.rsplit("/", 1)[-1]
        if base in {"ssh", "nc", "netcat", "telnet"} and i + 1 < len(toks):
            hosts.append(toks[i + 1])
    if toks and toks[0] == "git" and "push" in toks:
        hosts.append("git-remote")
    return [h for h in hosts if h]


def extract_destinations(command: str) -> list[str]:
    try:
        toks = shlex.split(command)
    except ValueError:
        # Unbalanced quotes etc. — we cannot prove this command is local.
        # Fail closed rather than falling back to a lenient tokenization
        # that could read as "local" (Global Constraint I6).
        return ["external_net"]
    binaries = {t.rsplit("/", 1)[-1] for t in toks}
    if binaries & NET_BINARIES:
        return ["external_net"]
    if destination_hosts(command):
        return ["external_net"]
    for t in toks:
        if BARE_HOST.match(t) or URL.search(t):
            return ["external_net"]
    return ["local"]
