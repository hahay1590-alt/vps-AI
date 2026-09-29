# vps-AI

## VPS AI helper

`vps_ai.py --watch` uses local systemd and protocol checks and can use a small local
Ollama model to explain incidents without an API key or sending logs off the VPS. It can
automatically restart only explicitly allowlisted services. The local model is a compact
helper, not a guarantee of correct diagnosis or safe code/config edits. The optional
interactive chat can also use this local model; hosted API use remains optional.

### Modes

### Local model (no API key)

First run the `scp` and `ssh` commands in “Push and install on your VPS” below. Then,
in the VPS SSH session, install Ollama, install the copied model definition, and create
the small Qwen 0.5B model:

```sh
curl -fsSL https://ollama.com/install.sh | sh
sudo install -d -m 0755 /opt/vps-ai
sudo install -m 0644 /tmp/Modelfile /opt/vps-ai/Modelfile
ollama pull qwen2.5:0.5b
ollama create vps-ai-qwen -f /opt/vps-ai/Modelfile
```

Ollama normally runs as a local service. Limit parallel work and unload the model soon
after use:

```sh
sudo systemctl edit ollama.service
```

Add this override, then reload and restart Ollama:

```ini
[Service]
Environment="OLLAMA_NUM_PARALLEL=1"
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_KEEP_ALIVE=1m"
MemoryMax=1536M
CPUQuota=50%
```

```sh
sudo systemctl daemon-reload
sudo systemctl restart ollama.service
```

The model definition limits context to 2,048 tokens and replies to 256 tokens. Model
files need roughly 400 MB of disk; inference temporarily uses substantially more RAM
than the file size and CPU can be busy while generating. The Ollama unit cap is 1.5 GB
RAM and 50% CPU; adjust the cap if your VPS has less available memory. `OLLAMA_KEEP_ALIVE`
unloads the model after a minute without requests. Checks happen locally; with the
model installed, incidents are diagnosed locally. With no key and no Ollama service,
monitoring and automatic allowlisted restarts still run, but diagnosis is logged as
unavailable.

For interactive local chat from a shell, set:

```sh
export VPS_AI_LOCAL_LLM=1
export OPENAI_MODEL=vps-ai-qwen
python3 vps_ai.py
```

The local assistant can discuss details you provide, but does not get tools to inspect
the host or execute shell commands. The persistent watcher supplies its own bounded
diagnostic evidence to the local model.

### Optional hosted model

To use an OpenAI-compatible hosted model instead, set `OPENAI_API_KEY`, `OPENAI_MODEL`,
and optionally `OPENAI_BASE_URL`. Keep credentials in a protected environment file,
never in this repository. The keyless local mode is loopback-only and rejects remote
model URLs.

### Push and install on your VPS

From this workspace terminal, replace `YOUR_USER` and `YOUR_VPS_IP` with your SSH login
and server address. Copy the script and service unit to your VPS:

```sh
scp vps_ai.py vps-ai-watch.service Modelfile YOUR_USER@YOUR_VPS_IP:/tmp/
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
VPS_AI_LOCAL_LLM=1
OPENAI_MODEL=vps-ai-qwen
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

### VPN and port checks

VPN checks are opt-in; add only the setting for the VPN software actually installed.
Examples:

```ini
# WireGuard interface and optional fresh-handshake requirement
VPS_AI_WIREGUARD_INTERFACES=wg0
VPS_AI_WIREGUARD_MAX_HANDSHAKE_AGE=300

# OpenVPN systemd unit; also add it to VPS_AI_WATCHLIST for restart eligibility
VPS_AI_OPENVPN_UNITS=openvpn-client@client.service

# Require at least one active strongSwan IPsec security association
VPS_AI_IPSEC_MIN_SAS=1

# Optional local status checks for these VPN products
VPS_AI_TAILSCALE_CHECK=1
VPS_AI_ZEROTIER_NETWORK_IDS=0123456789abcdef
```

WireGuard checks the configured interface and can optionally require a recent peer handshake.
Only set `VPS_AI_WIREGUARD_MAX_HANDSHAKE_AGE` when peers send traffic or use persistent
keepalive; an idle peer may not handshake recently. OpenVPN checks the named systemd
units and recent journal lines for TLS/authentication/transport failures, with a later
successful initialization clearing an earlier log error. IPsec checks
the number of active strongSwan SAs against `VPS_AI_IPSEC_MIN_SAS`. Tailscale checks its
local backend/health status. ZeroTier checks each configured network ID. These use the
protocol's local status tool and do not send credentials or tunnel keys to the monitor.

`VPS_AI_EXPECT_LISTENING` checks local TCP/UDP sockets only; it cannot see a cloud
firewall, provider security group, or remote NAT. `VPS_AI_TCP_CHECKS` uses
`INTERFACE|HOST|PORT` entries to attempt a TCP connection, optionally bound to a VPN
interface. A successful TCP connect proves only that a TCP port answered, not that a
VPN or TLS handshake succeeded. Generic UDP reachability cannot prove a protocol
handshake; WireGuard uses its own latest-handshake status instead.

For the named SSH/proxy stacks, optional examples are:

```ini
# Verify an SSH server returns an SSH-2.0 banner
VPS_AI_SSH_CHECKS=127.0.0.1:22

# Check local TCP/UDP listeners, including an SSH, OpenVPN, or UDPGW port
VPS_AI_EXPECT_LISTENING=TCP:22,UDP:7300

# Perform a WebSocket Upgrade; wss:// also validates the TLS certificate
VPS_AI_WEBSOCKET_CHECKS=wss://proxy.example.com:443/ws

# Validate common proxy server configs with their installed native checkers
VPS_AI_PROXY_CONFIGS=xray|/etc/xray/config.json,v2ray|/etc/v2ray/config.json,sing-box|/etc/sing-box/config.json
VPS_AI_SSH_CONFIGS=/etc/ssh/sshd_config
```

Xray, V2Ray, and sing-box config tests cover configured inbounds such as Trojan,
VMess, VLESS, Shadowsocks, and WebSocket transports when those protocols are defined
in those configs. The checker does not create a client login or verify a credentialed
end-to-end proxy session. A standalone proxy implementation without a recognized
native config-test command is not automatically understood. OpenVPN, WireGuard,
strongSwan IPsec, Tailscale, and ZeroTier use their own local status interfaces as
described above. Add only checks matching software and ports actually in use; UDPGW is
checked as a configured local UDP listener, not as a VPN handshake.

New incidents and recoveries are written to the journal and sent with `wall` to logged-
in terminals. This is best-effort: a terminal with `mesg n`, no active login, or a
restricted `wall` command may not display the alert. Alerts are deduplicated until the
check recovers. Probes run at the configured poll interval (60 seconds by default), so
this is near-real-time polling, not packet-level detection. There is no universal checker
for every proprietary VPN or protocol; unconfigured protocols are not inferred or
claimed healthy.

`systemctl enable --now` keeps the watcher running after SSH/admin logout, restarts it
if the watcher process fails, and starts it again after VPS reboot. Stop it with
`sudo systemctl disable --now vps-ai-watch.service`. Keep `/etc/vps-ai.env` root-readable
only. Keyless mode keeps incident and validation logs on the VPS; the separate chat mode
requires an API key.

No tool can guarantee repair of every possible VPS problem. This assistant is designed
for low local resource usage and narrowly configured service recovery, not unrestricted
autonomous administration.