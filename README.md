# Linux Firewall Manager (Python + UFW)

This project is a simple firewall management tool written in Python.  
It automates common UFW firewall commands on Linux systems and provides a small command-line interface to manage firewall rules.

The goal of this project was to practice Linux security basics, firewall configuration, and Python automation.

## Features

- Enable or disable the firewall
- Allow specific TCP ports
- Deny specific TCP ports
- Block IP addresses
- Allow IP addresses
- Reset firewall rules
- Show current firewall status
- Input validation for ports and IP addresses
- Basic logging of firewall actions

## Technologies Used

- Python
- Linux
- UFW (Uncomplicated Firewall)
- subprocess module

## How It Works

The script acts as a simple CLI tool.  
Instead of manually running UFW commands in the terminal, the program allows the user to manage firewall rules through a menu.

Example operations include:

- enabling the firewall
- opening or closing ports
- blocking suspicious IP addresses
- resetting firewall rules

The program also validates user input to avoid invalid ports or IP addresses.

## Example Usage

Run the script:

python3 firewall_manager.py

Then choose an option from the menu:

1 Enable Firewall  
2 Disable Firewall  
3 Allow Port  
4 Deny Port  
5 Show Status  
6 Block IP  
7 Allow IP  
8 Reset Firewall  
9 Exit

<img width="655" height="943" alt="Screenshot 2026-04-04 230738" src="https://github.com/user-attachments/assets/52295456-df50-4a8b-be72-4f68bf55b837" />

## Using it from SentinelAI (unattended)

`firewall_manager.py` stays a top-level module with a `FirewallManager` class.
SentinelAI config:

```yaml
firewall:
  adapter: python
  module: firewall_manager
  attribute: FirewallManager
  init_kwargs: {dry_run: true}      # remove dry_run for real blocking
```

Every public method (`block_ip`, `unblock_ip`, `temporary_block`,
`list_blocked`, `is_blocked`, `reap`) returns `False` (or `[]`) instead of
raising: invalid input, failed ufw command, inactive ufw, sudo that would
prompt, unwritable state/log file, lock timeout. Logging problems never change
a result. If the state file cannot be saved after a rule was applied, the rule
is removed again and the call returns `False`.

`list_blocked()` returns canonical strings (`203.0.113.5/32`, `2001:db8::/48`).
`is_blocked(ip)` is true when the address is inside any blocked range.

### Rule order

A plain `ufw deny from IP` is appended last, so an earlier `allow` can override
it. The deny rule is therefore placed first:

1. `ufw prepend deny from IP` (ufw >= 0.36, detected with `ufw version`).
2. Older or unparseable version: `ufw insert 1 deny from IP`.
3. Empty ruleset (`insert 1` fails with `Invalid position '1'`): plain
   `ufw deny from IP`.
4. IPv6 rule that ufw will not put before IPv4 rules: insert before the first
   existing IPv6 rule, or append when there is none.

Unblock runs `ufw delete deny from IP`.

### Honest success

ufw accepts rules while inactive, so success of the command proves nothing.
Before every new block the manager runs `ufw status numbered`; if the output
does not say `Status: active` it returns `False` and logs why. A custom
`runner` that returns a bare `bool` carries no output, so it cannot confirm an
active ufw and blocks are refused. Return `firewall_manager.CommandResult(ok,
stdout, stderr)` from a runner to provide output.

### Privilege (`sudo -n`)

All ufw calls are list-argument subprocesses with a timeout (15 s) and
`stdin=DEVNULL`. When not root, the command is `sudo -n /usr/sbin/ufw ...`;
if sudo would prompt, the call fails with a log line instead of hanging.

Use a dedicated low-privilege user and allow only the absolute path of ufw
(`command -v ufw`; pass another location with `ufw_path=`):

```
# /etc/sudoers.d/firewall-automation   (edit with: visudo -f ...)
fwblock ALL=(root) NOPASSWD: /usr/sbin/ufw
```

Check it with `visudo -cf /etc/sudoers.d/firewall-automation` and
`sudo -u fwblock sudo -n /usr/sbin/ufw status`.

**systemd hardening.** `sudo` is setuid, and `NoNewPrivileges=true` makes the
kernel ignore setuid, so `sudo -n` cannot work inside a unit that sets it.
SentinelAI's own unit sets it, and the `python` adapter runs this class inside
that process. Do not remove the hardening from SentinelAI to make this work.
Instead run the component that needs the privilege in a separate unit (for
example `User=fwblock` with the sudoers entry above, or `User=root`, and
without `NoNewPrivileges`), and call it from SentinelAI through a channel you
provide. This repository ships no such channel. If you do run it as a unit,
`ProtectSystem=strict` also blocks ufw's writes: add `ReadWritePaths=` for
ufw's directories (usually `/etc/ufw` and `/lib/ufw`; verify on your distro)
and for the state directory.

### Input checks

IPv4, IPv6 and CIDR are accepted and stored in canonical form
(`str(ipaddress.ip_network(x, strict=False))`, so `10.0.0.5/24` becomes
`10.0.0.0/24`). Rejected: whitespace and control characters, zone IDs (`%`),
IPv4-mapped IPv6, unspecified, multicast and reserved ranges, and prefixes
broader than `min_prefix_v4` (default 16) / `min_prefix_v6` (default 32).

Never blocked, by overlap and not only equality (a CIDR that contains a
protected address is refused): loopback, this host's interface addresses, the
default gateway (IPv4 from `/proc/net/route`, IPv6 from
`/proc/net/ipv6_route`), the client in `SSH_CONNECTION`, and anything in the
allowlist (`allowlist=[...]` or `FIREWALL_AUTOMATION_ALLOWLIST=a,b`).

**Fail closed:** if the gateway cannot be determined (for example
`/proc/net/route` is unreadable, or the host is not Linux), the block is
refused and logged. An unparseable `SSH_CONNECTION` or an invalid allowlist
entry also refuses blocks. Own-interface detection is best effort.
The checks also apply with `dry_run=True`. Unblocking is never refused.

### State and logging

| Setting | Order |
|---|---|
| State directory | `state_dir=` argument, then `FIREWALL_AUTOMATION_STATE_DIR`, then `~/.local/state/firewall-automation` |

The directory must be absolute. With `HOME` unset or unwritable the manager
still constructs and its methods return `False`. A relative `state_file` is
placed inside the state directory (default name `state.json`). The log is
`firewall.log` in the same directory unless `log_file=` is set. Log lines are
single-line: control characters and newlines in input are replaced by `?`.

A thread lock plus an `fcntl` lock on `<state>.lock` serialize writers, so
threads and processes can share one state file. Without `fcntl` (non-Linux)
only the thread lock applies. A corrupt state file is never overwritten; the
call fails and logs.

### Temporary blocks

`temporary_block(ip, seconds)` records an expiry. Expired blocks are removed
lazily by every call, and explicitly by `reap()`:

```
python3 firewall_manager.py --reap [--state-dir DIR] [--state-file FILE] [--dry-run]
```

Exit code 0 when no expired block is left, 1 otherwise. Use the same state
directory as SentinelAI. systemd timer:

```ini
# /etc/systemd/system/firewall-reap.service
[Service]
Type=oneshot
User=fwblock
Environment=FIREWALL_AUTOMATION_STATE_DIR=/var/lib/firewall-automation
ExecStart=/usr/bin/python3 /opt/linux-firewall-automation/firewall_manager.py --reap

# /etc/systemd/system/firewall-reap.timer
[Timer]
OnBootSec=1min
OnUnitActiveSec=1min
[Install]
WantedBy=timers.target
```

cron (`/etc/cron.d/firewall-reap`):

```
FIREWALL_AUTOMATION_STATE_DIR=/var/lib/firewall-automation
* * * * * fwblock /usr/bin/python3 /opt/linux-firewall-automation/firewall_manager.py --reap
```

An in-process reaper is available but opt-in: call `start_reaper(interval)`
yourself (and `stop_reaper()`); the constructor never starts a thread.

### Upgrade notes

- Stored and logged targets are canonical (`1.2.3.4` becomes `1.2.3.4/32`);
  old flat state files are read and rewritten in the new format.
- A relative `state_file` is no longer relative to the working directory.
- `sudo` is now `sudo -n`; the interactive menu still uses plain `sudo`.

## Tests

```
python -m pytest
```

Tests use an injected fake `runner` only: no real ufw, sudo or network. GitHub
Actions runs them on Linux (Python 3.9, 3.11, 3.13).

## Learning Outcome

This project helped reinforce several core concepts:

- basic firewall management on Linux
- understanding network ports and access control
- automating system commands with Python
- building simple CLI tools
- validating user input for security
