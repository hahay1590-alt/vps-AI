# vps-AI

## VPS AI helper

`vps_ai.py --watch` is a keyless, rule-based Linux service monitor. It uses local
systemd checks, writes incidents and recent logs to the local system journal, and can
automatically restart explicitly allowlisted services. It does not need an API key,
download a model, or send data off the VPS. This mode is not AI: without an API key,
it cannot interpret arbitrary errors or invent safe repairs. The separate interactive
chat mode uses an OpenAI-compatible API and requires a key. The watcher can also
periodically syntax-check configured project directories without an API key.

### Run it

To use interactive AI chat, set your API credentials and run:

```sh
export OPENAI_API_KEY='your-provider-key'
export OPENAI_MODEL='gpt-4o-mini'
python3 vps_ai.py
```

Python 3.9+ and a Linux system with systemd are expected. The default API URL is
`https://api.openai.com/v1`. For another OpenAI-compatible provider, set
`OPENAI_BASE_URL` to its API base URL and set `OPENAI_MODEL` to a model that supports
tool calling. Keep the API key in your shell environment or a protected secret manager;
do not put it in this repository.

### Push and install on your VPS

From this workspace terminal, replace `YOUR_USER` and `YOUR_VPS_IP` with your SSH login
and server address. Copy the script and service unit to your VPS:

```sh
scp vps_ai.py vps-ai-watch.service YOUR_USER@YOUR_VPS_IP:/tmp/
ssh YOUR_USER@YOUR_VPS_IP
```

Then, in the SSH session, install the files. Check real service unit names with
`systemctl list-units --type=service --state=running` before configuring the watcher:

```sh
sudo install -d -m 0755 /opt/vps-ai
sudo install -m 0755 vps_ai.py /opt/vps-ai/vps_ai.py
sudo install -m 0644 vps-ai-watch.service /etc/systemd/system/vps-ai-watch.service
sudo touch /etc/vps-ai.env
sudo chmod 0600 /etc/vps-ai.env
sudoedit /etc/vps-ai.env
```

Put configuration like this in `/etc/vps-ai.env`, replacing the example services:

```ini
VPS_AI_WATCHLIST=nginx.service,myapp.service
VPS_AI_AUTO_RESTART_ALLOWLIST=myapp.service
VPS_AI_POLL_SECONDS=60
VPS_AI_VALIDATE_PATHS=/opt/myapp,/etc/myconfig
VPS_AI_VALIDATE_INTERVAL=300
```

Replace the examples with real paths and systemd unit names. `VPS_AI_WATCHLIST` is
optional if you only want project validation. Every watched service is monitored; it is
restarted only if it is also in the auto-restart list. Remove that setting to monitor
and log without changing anything. A restart can cause downtime, so do not allowlist
critical SSH, networking, or database services unless that risk is acceptable. Enable
it and view logs:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now vps-ai-watch.service
sudo journalctl -u vps-ai-watch.service -f
```

The watcher runs with a 128 MB RAM limit and 10% CPU quota. It checks once per minute
by default and attempts at most one restart per outage, waiting for the service to
recover before another attempt. On startup and every five minutes by default, it scans
configured directories for changed files, checking no more than 2,000 files of up to
2 MiB each per scan. It skips common dependency/build directories and does not execute
project code. Findings and cleared errors are written to the local system journal.

Syntax/config validators use Python's AST, JSON, TOML (Python 3.11+), YAML (if PyYAML
is installed), INI, XML, basic `.env` assignments, and installed tools for Bash,
JavaScript, PHP, Ruby, Lua, C/C++, Go, Rust, Java, and systemd units. Missing validator
tools and unsupported formats are reported rather than treated as valid. This is not
every language or every semantic/type checker; TypeScript, C#, Swift, and Kotlin are
currently not validated. Install toolchains separately only if you need them. The
watcher reports problems; it does not rewrite source or claim to automatically fix code.

`systemctl enable --now` keeps the watcher running after SSH/admin logout, restarts it
if the watcher process fails, and starts it again after VPS reboot. Stop it with
`sudo systemctl disable --now vps-ai-watch.service`. Keep `/etc/vps-ai.env` root-readable
only. Keyless mode keeps incident and validation logs on the VPS; the separate chat mode
requires an API key.

No tool can guarantee repair of every possible VPS problem. This assistant is designed
for low local resource usage and narrowly configured service recovery, not unrestricted
autonomous administration.