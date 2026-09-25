"""Tier 2 — classify where a shell command sends data.

Fails closed: anything carrying a URL or host-looking argument that we cannot
prove is local is treated as external (Global Constraint I6).
"""
from __future__ import annotations

import ipaddress
import re
import shlex
import unicodedata

from .paths import PATTERNS, is_sensitive_path

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
        toks = _policy_words(command)
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


# -- intended network recipient (#54 Phase 4) --------------------------------
#
# A recipient identity names one endpoint, so unlike the classifier above it
# fails *unresolved*: a command outside this closed grammar gets no
# recipient at all, even when `extract_destinations` rightly calls it
# external. Nothing here consults DNS, the filesystem or the environment.

#: Characters a shell would act on outside quotes: expansion, globbing,
#: operators, redirection, comments, history and escapes.
_UNQUOTED_META = frozenset(";&|<>()$`\\*?[]{}~!#")
#: Inside double quotes the shell still expands these.
_DOUBLE_QUOTED_META = frozenset("$`\\!")
_DATA_OPTIONS = frozenset({"--data", "--data-raw", "-d"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_PORT = re.compile(r"[0-9]{1,5}\Z")


def _simple_words(command: str) -> list[str] | None:
    """Split `command` the way a POSIX shell would, or None when the shell
    would do anything but split it: expand, glob, redirect, chain, escape,
    or meet an unbalanced quote or a control character."""
    words: list[str] = []
    word: list[str] = []
    in_word = False
    quote = ""
    for char in command:
        if unicodedata.category(char) == "Cc" and char not in " \t":
            return None
        if quote == "'":
            if char == "'":
                quote = ""
            else:
                word.append(char)
            continue
        if quote == '"':
            if char == '"':
                quote = ""
            elif char in _DOUBLE_QUOTED_META:
                return None
            else:
                word.append(char)
            continue
        if char in " \t":
            if in_word:
                words.append("".join(word))
                word, in_word = [], False
            continue
        if char in _UNQUOTED_META:
            return None
        in_word = True
        if char in "'\"":
            quote = char
        else:
            word.append(char)
    if quote:
        return None
    if in_word:
        words.append("".join(word))
    return words


def _canonical_host(host: str) -> str | None:
    if host.startswith("["):
        if not host.endswith("]"):
            return None
        try:
            address = ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            return None  # includes a `%zone`: not one endpoint
        return f"[{address.compressed}]"
    if not host or not host.isascii() or len(host) > 253:
        return None
    host = host.lower()
    labels = host.split(".")
    if not all(_HOST_LABEL.match(label) for label in labels):
        return None
    if (labels[-1].isdigit()
            or re.fullmatch(r"0x[0-9a-f]+", labels[-1])):
        # Numeric hosts are read as IPv4 in more spellings than a dotted
        # quad (`127.1`); only the dotted quad is accepted.
        try:
            return str(ipaddress.IPv4Address(host))
        except ValueError:
            return None
    return host


def _canonical_endpoint(url: str) -> str | None:
    """`scheme://lowercase-host:effective-port`, discarding userinfo, path,
    query and fragment. Only http and https, whose ports are known."""
    scheme, separator, rest = url.partition("://")
    scheme = scheme.lower()
    if not separator or scheme not in _DEFAULT_PORTS:
        return None
    authority = rest
    for stop in "/?#":
        authority = authority.split(stop, 1)[0]
    # Curl expands URL globs even when shell quotes protect the URL.
    if (any(char in "{}" for char in rest)
            or any(char in "[]" for char in rest[len(authority):])
            or any(char in "[]" for char in authority.rpartition("@")[0])):
        return None
    if "%" in authority:
        return None
    authority = authority.rpartition("@")[2]
    if authority.startswith("["):
        close = authority.find("]")
        if close < 0:
            return None
        host, port_text = authority[:close + 1], authority[close + 1:]
        if port_text and not port_text.startswith(":"):
            return None
        port_text = port_text[1:] if port_text else ""
        has_port = bool(authority[close + 1:])
    else:
        host, has_colon, port_text = authority.partition(":")
        has_port = bool(has_colon)
    canonical = _canonical_host(host)
    if canonical is None:
        return None
    if has_port:
        if not _PORT.match(port_text):
            return None
        port = int(port_text)
        if not 0 < port <= 65535:
            return None
    else:
        port = _DEFAULT_PORTS[scheme]
    return f"{scheme}://{canonical}:{port}"


def intended_network_recipient(command: str) -> str | None:
    """The one endpoint a supported simple `curl` command addresses, or None.

    Exactly this grammar, in this order, and nothing else:

        curl [-X METHOD] [-H HEADER]* [--data VALUE | --data-raw VALUE |
             -d VALUE] URL

    No other flag, no second URL, no second data option, no `@file`
    value, no attached option values, and no shell expansion, globbing or
    operator anywhere in the command. The URL's userinfo, path, query and
    fragment never reach the result."""
    if not isinstance(command, str):
        return None
    words = _simple_words(command)
    if not words or words[0] != "curl":
        return None
    rest = words[1:]
    if rest[:1] == ["-X"]:
        if len(rest) < 2 or not rest[1] or rest[1].startswith("-"):
            return None
        rest = rest[2:]
    while rest[:1] == ["-H"]:
        if len(rest) < 2 or rest[1].startswith("@"):
            return None
        rest = rest[2:]
    if rest[:1] and rest[0] in _DATA_OPTIONS:
        if len(rest) < 2 or rest[1].startswith("@"):
            return None
        rest = rest[2:]
    if len(rest) != 1 or rest[0].startswith("-"):
        return None
    return _canonical_endpoint(rest[0])


# Policy recognition only. This is not a shell AST or identity evidence.
_PATH_FRAGMENTS = re.compile(r"""[\s"'`$(){}<>|;&=@,:\\]+""")


def _policy_words(command: str) -> list[str]:
    lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def network_file_rules(command: str) -> tuple[int, ...] | None:
    """Rules supporting a lexical network denial, or None.

    An empty tuple means a recognized network command could not be
    tokenized. Nonempty tuples contain indexes into paths.PATTERNS,
    deduplicated within this observation. No path survives this return.

    This deliberately checks co-occurrence, not payload data flow.
    Quotes do not establish that a filename-looking argument is harmless.
    Missing matches do not establish that a command sends no sensitive
    data: expansion, configuration and execution remain unobserved.
    """
    parse_failed = False
    try:
        words = _policy_words(command)
    except ValueError:
        # Recover only enough lexical evidence to decide whether this is
        # a recognized network command. Never evaluate or execute text.
        words = _PATH_FRAGMENTS.split(command)
        parse_failed = True

    if not any(word.rsplit("/", 1)[-1] in NET_BINARIES for word in words):
        return None

    matched: set[int] = set()
    for word in words:
        # curl's attached upload operand: -T.env. Other requested attached
        # forms expose their operand through @ or = below.
        candidate = word[2:] if word.startswith("-T") else word
        for fragment in _PATH_FRAGMENTS.split(candidate):
            if not is_sensitive_path(fragment):
                continue
            matched.update(
                index for index, pattern in enumerate(PATTERNS)
                if pattern.search(fragment)
            )

    if matched or parse_failed:
        return tuple(sorted(matched))
    return None
