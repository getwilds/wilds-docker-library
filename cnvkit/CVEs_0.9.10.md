# Vulnerability Report for getwilds/cnvkit:0.9.10

Report generated on 2025-07-01 09:09:46 PST

<h2>:mag: Vulnerabilities of <code>getwilds/cnvkit:0.9.10</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/cnvkit:0.9.10</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:86eca5f4a05890efb2739e440eae1fbdecaa3f9c694a129f6ce81d463cc60898</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/medium-4-fbb552"/> <img alt="low: 4" src="https://img.shields.io/badge/low-4-fce1a9"/> <img alt="unspecified: 1" src="https://img.shields.io/badge/unspecified-1-lightgrey"/></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>3.4 GB</td></tr>
<tr><td>packages</td><td>223</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>shadow</strong> <code>1:4.13+dfsg1-1</code> (deb)</summary>

<small><code>pkg:deb/debian/shadow@1%3A4.13%2Bdfsg1-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-4641?s=debian&n=shadow&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1%3A4.13%2Bdfsg1-1%2Bdeb12u1"><img alt="medium : CVE--2023--4641" src="https://img.shields.io/badge/CVE--2023--4641-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:4.13+dfsg1-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1:4.13+dfsg1-1+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.015%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in shadow-utils. When asking for a new password, shadow-utils asks the password twice. If the password fails on the second attempt, shadow-utils fails in cleaning the buffer used to store the first entry. This may allow an attacker with enough access to retrieve the password from the memory.

---
- shadow 1:4.13+dfsg1-2 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1051062)
[bookworm] - shadow 1:4.13+dfsg1-1+deb12u1
[buster] - shadow <no-dsa> (Minor issue)
https://bugzilla.redhat.com/show_bug.cgi?id=2215945
https://github.com/shadow-maint/shadow/commit/65c88a43a23c2391dcc90c0abda3e839e9c57904 (4.14.0-rc1)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-29383?s=debian&n=shadow&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1%3A4.13%2Bdfsg1-1%2Bdeb12u1"><img alt="low : CVE--2023--29383" src="https://img.shields.io/badge/CVE--2023--29383-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:4.13+dfsg1-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1:4.13+dfsg1-1+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Shadow 4.13, it is possible to inject control characters into fields provided to the SUID program chfn (change finger). Although it is not possible to exploit this directly (e.g., adding a new user fails because \n is in the block list), it is possible to misrepresent the /etc/passwd file when viewed. Use of \r manipulations and Unicode characters to work around blocking of the : character make it possible to give the impression that a new user has been added. In other words, an adversary may be able to convince a system administrator to take the system offline (an indirect, social-engineered denial of service) by demonstrating that "cat /etc/passwd" shows a rogue user account.

---
- shadow 1:4.13+dfsg1-2 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1034482)
[bookworm] - shadow 1:4.13+dfsg1-1+deb12u1
[buster] - shadow <no-dsa> (Minor issue)
https://github.com/shadow-maint/shadow/pull/687
Fixed by: https://github.com/shadow-maint/shadow/commit/e5905c4b84d4fb90aefcd96ee618411ebfac663d (4.14.0-rc1)
Regression fix: https://github.com/shadow-maint/shadow/commit/2eaea70111f65b16d55998386e4ceb4273c19eb4 (4.14.0-rc1)
https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=31797
https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/cve-2023-29383-abusing-linux-chfn-to-misrepresent-etc-passwd/

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>systemd</strong> <code>252.36-1~deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/systemd@252.36-1~deb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4598?s=debian&n=systemd&ns=debian&t=deb&osn=debian&osv=12&vr=%3C252.38-1%7Edeb12u1"><img alt="medium : CVE--2025--4598" src="https://img.shields.io/badge/CVE--2025--4598-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><252.38-1~deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>252.38-1~deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in systemd-coredump. This flaw allows an attacker to force a SUID process to crash and replace it with a non-SUID binary to access the original's privileged process coredump, allowing the attacker to read sensitive data, such as /etc/shadow content, loaded by the original process.  A SUID binary or process has a special type of permission, which allows the process to run with the file owner's permissions, regardless of the user executing the binary. This allows the process to access more restricted data than unprivileged users or processes would be able to. An attacker can leverage this flaw by forcing a SUID process to crash and force the Linux kernel to recycle the process PID before systemd-coredump can analyze the /proc/pid/auxv file. If the attacker wins the race condition, they gain access to the original's SUID process coredump file. They can read sensitive content loaded into memory by the original binary, affecting data confidentiality.

---
- systemd 257.6-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1106785)
https://www.qualys.com/2025/05/29/apport-coredump/apport-coredump.txt
For a comprehensive fix a kernel change is required (to hand a pidfd to the usermode
coredump helper):
https://git.kernel.org/linus/b5325b2a270fcaf7b2a9a0f23d422ca8a5a8bdea
Backports (src:linux):
https://lore.kernel.org/linux-fsdevel/CAMw=ZnT4KSk_+Z422mEZVzfAkTueKvzdw=r9ZB2JKg5-1t6BDw@mail.gmail.com/
Fixed by: https://github.com/systemd/systemd/commit/49f1f2d4a7612bbed5211a73d11d6a94fbe3bb69 (main)
Fixed by: https://github.com/systemd/systemd/commit/0c49e0049b7665bb7769a13ef346fef92e1ad4d6 (main)
Fixed by: https://github.com/systemd/systemd/commit/8fc7b2a211eb13ef1a94250b28e1c79cab8bdcb9 (main)
Follow up (optional): https://github.com/systemd/systemd/commit/13902e025321242b1d95c6d8b4e482b37f58cdef (main)
Follow up (optional): https://github.com/systemd/systemd/commit/868d95577ec9f862580ad365726515459be582fc (main)
Follow up (optional): https://github.com/systemd/systemd/commit/e6a8687b939ab21854f12f59a3cce703e32768cf (main)
Follow up (optional): https://github.com/systemd/systemd/commit/76e0ab49c47965877c19772a2b3bf55f6417ca39 (main)
Follow up (optional): https://github.com/systemd/systemd/commit/9ce8e3e449def92c75ada41b7d10c5bc3946be77 (main)
Fixed by: https://github.com/systemd/systemd/commit/0c49e0049b7665bb7769a13ef346fef92e1ad4d6 (v258)
Fixed by: https://github.com/systemd/systemd/commit/868d95577ec9f862580ad365726515459be582fc (v258)
Fixed by: https://github.com/systemd/systemd/commit/c58a8a6ec9817275bb4babaa2c08e0e35090d4e3 (v257.6)
Fixed by: https://github.com/systemd/systemd/commit/61556694affa290c0a16d48717b3892b85622d96 (v257.6)
Fixed by: https://github.com/systemd/systemd/commit/19d439189ab85dd7222bdd59fd442bbcc8ea99a7 (v256.16)
Fixed by: https://github.com/systemd/systemd-stable/commit/254ab8d2a7866679cee006d844d078774cbac3c9 (v255.21)
Fixed by: https://github.com/systemd/systemd-stable/commit/7fc7aa5a4d28d7768dfd1eb85be385c3ea949168 (v254.26)
Fixed by: https://github.com/systemd/systemd-stable/commit/19b228662e0fcc6596c0395a0af8486a4b3f1627 (v253.33)
Fixed by: https://github.com/systemd/systemd-stable/commit/2eb46dce078334805c547cbcf5e6462cf9d2f9f0 (v252.38)
Issue relates to race condition exploitable while checking if a user should
be allowed to read a core file or not via the grant_user_access() function,
which was introduced as part of the fix for CVE-2022-4415.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libcap2</strong> <code>1:2.66-4</code> (deb)</summary>

<small><code>pkg:deb/debian/libcap2@1%3A2.66-4?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-1390?s=debian&n=libcap2&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1%3A2.66-4%2Bdeb12u1"><img alt="medium : CVE--2025--1390" src="https://img.shields.io/badge/CVE--2025--1390-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:2.66-4+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1:2.66-4+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The PAM module pam_cap.so of libcap configuration supports group names starting with “@”, during actual parsing, configurations not starting with “@” are incorrectly recognized as group names. This may result in nonintended users being granted an inherited capability set, potentially leading to security risks. Attackers can exploit this vulnerability to achieve local privilege escalation on systems where /etc/security/capability.conf is used to configure user inherited privileges by constructing specific usernames.

---
- libcap2 1:2.73-4 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1098318)
[bookworm] - libcap2 1:2.66-4+deb12u1
https://bugzilla.openanolis.cn/show_bug.cgi?id=18804
Fixed by: https://git.kernel.org/pub/scm/libs/libcap/libcap.git/commit/?id=1ad42b66c3567481cc5fa22fc1ba1556a316d878 (cap/v1.2.74-rc4)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>openssl</strong> <code>3.0.15-1~deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/openssl@3.0.15-1~deb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-13176?s=debian&n=openssl&ns=debian&t=deb&osn=debian&osv=12&vr=%3C3.0.16-1%7Edeb12u1"><img alt="medium : CVE--2024--13176" src="https://img.shields.io/badge/CVE--2024--13176-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.0.16-1~deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.16-1~deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.069%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: A timing side-channel which could potentially allow recovering the private key exists in the ECDSA signature computation.  Impact summary: A timing side-channel in ECDSA signature computations could allow recovering the private key by an attacker. However, measuring the timing would require either local access to the signing application or a very fast network connection with low latency.  There is a timing signal of around 300 nanoseconds when the top word of the inverted ECDSA nonce value is zero. This can happen with significant probability only for some of the supported elliptic curves. In particular the NIST P-521 curve is affected. To be able to measure this leak, the attacker process must either be located in the same physical computer or must have a very fast network connection with low latency. For that reason the severity of this vulnerability is Low.  The FIPS modules in 3.4, 3.3, 3.2, 3.1 and 3.0 are affected by this issue.

---
- openssl 3.4.1-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1094027)
[bookworm] - openssl 3.0.16-1~deb12u1
https://openssl-library.org/news/secadv/20250120.txt
https://github.com/openssl/openssl/commit/77c608f4c8857e63e98e66444e2e761c9627916f (openssl-3.4.1)
https://github.com/openssl/openssl/commit/392dcb336405a0c94486aa6655057f59fd3a0902 (openssl-3.3.3)
https://github.com/openssl/openssl/commit/4b1cb94a734a7d4ec363ac0a215a25c181e11f65 (openssl-3.2.4)
https://github.com/openssl/openssl/commit/2af62e74fb59bc469506bc37eb2990ea408d9467 (openssl-3.1.8)
https://github.com/openssl/openssl/commit/07272b05b04836a762b4baa874958af51d513844 (openssl-3.0.16)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <img alt="unspecified: 1" src="https://img.shields.io/badge/U-1-lightgrey"/><strong>krb5</strong> <code>1.20.1-2+deb12u2</code> (deb)</summary>

<small><code>pkg:deb/debian/krb5@1.20.1-2%2Bdeb12u2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-26462?s=debian&n=krb5&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.20.1-2%2Bdeb12u3"><img alt="low : CVE--2024--26462" src="https://img.shields.io/badge/CVE--2024--26462-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.20.1-2+deb12u3</code></td></tr>
<tr><td>Fixed version</td><td><code>1.20.1-2+deb12u3</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/kdc/ndr.c.

---
- krb5 1.21.3-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1064965)
[bookworm] - krb5 1.20.1-2+deb12u3
[bullseye] - krb5 <not-affected> (Vulnerable code introduced later)
[buster] - krb5 <not-affected> (Vulnerable code introduced later)
https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_3.md
Introduced by: https://github.com/krb5/krb5/commit/c85894cfb784257a6acb4d77d8c75137d2508f5e (krb5-1.20-beta1)
Fixed by: https://github.com/krb5/krb5/commit/7d0d85bf99caf60c0afd4dcf91b0c4c683b983fe (master)
Fixed by: https://github.com/krb5/krb5/commit/0c2de238b5bf1ea4578e3933a604c7850905b8be (krb5-1.21.3-final)
https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-24528?s=debian&n=krb5&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.20.1-2%2Bdeb12u3"><img alt="unspecified : CVE--2025--24528" src="https://img.shields.io/badge/CVE--2025--24528-lightgrey?label=unspecified%20&labelColor=lightgrey"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.20.1-2+deb12u3</code></td></tr>
<tr><td>Fixed version</td><td><code>1.20.1-2+deb12u3</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

- krb5 1.21.3-5 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1094730)
[bookworm] - krb5 1.20.1-2+deb12u3
https://bugzilla.redhat.com/show_bug.cgi?id=2342796
Fixed by: https://github.com/krb5/krb5/commit/78ceba024b64d49612375be4a12d1c066b0bfbd0

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>gcc-12</strong> <code>12.2.0-14</code> (deb)</summary>

<small><code>pkg:deb/debian/gcc-12@12.2.0-14?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-4039?s=debian&n=gcc-12&ns=debian&t=deb&osn=debian&osv=12&vr=%3C12.2.0-14%2Bdeb12u1"><img alt="low : CVE--2023--4039" src="https://img.shields.io/badge/CVE--2023--4039-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><12.2.0-14+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>12.2.0-14+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.149%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

**DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains  that target AArch64 allows an attacker to exploit an existing buffer  overflow in dynamically-sized local variables in your application  without this being detected. This stack-protector failure only applies  to C99-style dynamically-sized local variables or those created using  alloca(). The stack-protector operates as intended for statically-sized  local variables.  The default behavior when the stack-protector  detects an overflow is to terminate your application, resulting in  controlled loss of availability. An attacker who can exploit a buffer  overflow without triggering the stack-protector might be able to change  program flow control to cause an uncontrolled loss of availability or to  go further and affect confidentiality or integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by itself.

---
- gcc-13 13.2.0-4 (unimportant)
- gcc-12 12.3.0-9 (unimportant)
[bookworm] - gcc-12 12.2.0-14+deb12u1
- gcc-11 11.4.0-4 (unimportant)
- gcc-10 10.5.0-3 (unimportant)
- gcc-9 9.5.0-6 (unimportant)
- gcc-8 <removed> (unimportant)
- gcc-7 <removed> (unimportant)
https://github.com/metaredteam/external-disclosures/security/advisories/GHSA-x7ch-h5rf-w2mf
Not considered a security issue by GCC upstream
https://developer.arm.com/Arm%20Security%20Center/GCC%20Stack%20Protector%20Vulnerability%20AArch64

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>torch</strong> <code>2.7.0</code> (pypi)</summary>

<small><code>pkg:pypi/torch@2.7.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-2953?s=github&n=torch&t=pypi&vr=%3C2.7.1-rc1"><img alt="low 1.9: CVE--2025--2953" src="https://img.shields.io/badge/CVE--2025--2953-lightgrey?label=low%201.9&labelColor=fce1a9"/></a> <i>Improper Resource Shutdown or Release</i>

<table>
<tr><td>Affected range</td><td><code><2.7.1-rc1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.7.1-rc1</code></td></tr>
<tr><td>CVSS Score</td><td><code>1.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N/E:P</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability, which was classified as problematic, has been found in PyTorch 2.6.0+cu124. Affected by this issue is the function torch.mkldnn_max_pool2d. The manipulation leads to denial of service. An attack has to be approached locally. The exploit has been disclosed to the public and may be used.

</blockquote>
</details>
</details></td></tr>
</table>