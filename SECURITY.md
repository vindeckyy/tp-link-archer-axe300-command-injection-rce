# Security Policy

## Status of this finding

Published publicly in this repository on **2026-10-24**, before the vendor was notified. Reported to TP-Link's Product Security Team at security@tp-link.com on **2026-10-26**. As of this update, TP-Link has published no fix, advisory, or CVE for this finding.

The Archer AXE300 does not appear in TP-Link's own command-injection advisory
([FAQ 4935](https://www.tp-link.com/us/support/faq/4935/)), and no CVE covers this model or
this code path.

## If you run the affected firmware

The vulnerable component is the ISP Speed Test, reached from **Advanced → Network → Internet →
Speed Test** on the admin page. The flaw is in how the router builds the shell command for
that test; it is triggered by the `spdt_server` value sent to
`/cgi-bin/luci/;stok=<token>/admin/speedtest?form=speedtest`.

Until a firmware update is available:

1. **Never expose the management interface to the internet.** Disable remote management and
   WAN-side administration.
2. **Keep admin access on the LAN only**, and use a long, unique admin password that is
   never reused elsewhere.
3. **Treat any compromise of that password as a root compromise of the router.** It is one.
4. **Do not run untrusted speed-test URLs** through the UI if you use the feature at all; the
   safest option is to leave the Speed Test disabled.
5. **Check for the indicators** in [README § Detection and incident
   response](README.md#detection-and-incident-response) if you suspect the device has been
   accessed by someone else.

## Reporting

This finding is already public and has been reported to TP-Link. If you have found the same issue independently, or want to
report a **different** issue in TP-Link firmware, contact the author through the repository's
issue tracker or GitHub profile.

**If you are the vendor or a researcher at the vendor:** the report in
[`REPORT.md`](REPORT.md) is complete enough to reproduce and to fix. The vulnerable code, the
exact request path, both proof methods, the negative results and the device cleanup record
are all included. The PoC in `poc/` implements the API handshake from scratch, so it does
not depend on the router's browser session. Assigning a CVE for the AXE300's ISP Speed Test
path would follow the pattern TP-Link already used for the equivalent issues on BE230,
BE3600, AXE75, AX73 and Deco BE25.

## Scope and authorisation

This research was performed on hardware the author owns, with the owner's explicit
permission and credential. Nothing in this repository was tested against a device the author
does not control. See [`DISCLAIMER.md`](DISCLAIMER.md) for the full terms of use.

## Reporting a vulnerability in this repository

The code and documentation in this repository are research artefacts, not a product with a
support commitment. If you find an issue with the PoC — a crash, an incorrect claim, a
missing redaction — open an issue or a pull request. If the issue concerns the *disclosure*
itself (status, timing, who has been told), contact the author directly rather than filing a
public issue.
