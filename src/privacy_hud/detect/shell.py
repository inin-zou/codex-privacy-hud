"""Tier 2 — classify where a shell command sends data.

Fails closed: anything carrying a URL or host-looking argument that we cannot
prove is local is treated as external (Global Constraint I6).
"""
from __future__ import annotations

import ipaddress
import re
import shlex

NET_BINARIES = {"curl", "wget", "scp", "rsync", "sftp", "ssh", "nc", "netcat",
                "telnet", "ftp", "http", "httpie"}
URL = re.compile(r"\b[a-z][a-z0-9+.-]*://([^\s/\"']+)")
SCP_TARGET = re.compile(r"\b[\w.-]+@([\w.-]+):")
DEV_TCP = re.compile(r"/dev/tcp/([\w.-]+)/\d+")

# Bracketed IPv6, with an optional :port suffix — e.g. "[::1]:8080".
_IPV6_BRACKETED = re.compile(r"^\[(?P<addr>[0-9A-Fa-f:]+)\](?::\d+)?$")
# IPv4 dotted quad, with an optional :port suffix — e.g. "10.0.0.9:9999".
_IPV4_WITH_PORT = re.compile(r"^(?P<addr>\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$")

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


def _ip_literal(tok: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse `tok` as a bare IP literal, if it is one.

    Accepts a plain IPv4 dotted quad, IPv4 with a `:port` suffix, bracketed
    IPv6 (`[::1]` or `[::1]:8080`), and bare IPv6 (`::1`, `2001:db8::5`).
    Returns the parsed address object (whose `.is_loopback` we use for the
    local/external decision) or None if `tok` isn't an IP literal at all.
    """
    m = _IPV6_BRACKETED.match(tok)
    if m:
        candidate = m.group("addr")
    else:
        m = _IPV4_WITH_PORT.match(tok)
        if m:
            candidate = m.group("addr")
        elif tok.count(":") >= 2:
            # Bare IPv6 needs at least two colons to avoid false-positiving
            # on things like a "12:30" argument. No :port support in this
            # form — that's what the bracketed form above is for.
            candidate = tok
        else:
            return None
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


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
    for t in toks:
        if _ip_literal(t) is not None:
            hosts.append(t)
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

    for host in destination_hosts(command):
        addr = _ip_literal(host)
        if addr is not None:
            # Loopback (127.0.0.0/8, ::1) never leaves this machine — that's
            # the one IP-literal case that's provably local. Everything else
            # that resolves as an IP — RFC1918 private ranges, link-local
            # (169.254.0.0/16, which includes the 169.254.169.254 cloud
            # metadata endpoint), and public addresses — does leave this
            # machine's network stack, so it fails closed as external_net.
            if addr.is_loopback:
                continue
            return ["external_net"]
        return ["external_net"]

    for t in toks:
        if BARE_HOST.match(t) or URL.search(t):
            return ["external_net"]
    return ["local"]
