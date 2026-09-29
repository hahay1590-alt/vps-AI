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