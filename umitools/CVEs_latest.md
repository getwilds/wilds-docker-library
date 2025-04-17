# Vulnerability Report for getwilds/umitools:latest

Report generated on 2025-04-17 19:57:25 PST

<h2>:mag: Vulnerabilities of <code>getwilds/umitools:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/umitools:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:0a17dd42930be4c0a6b3cca0c30d4bb52faacf9ae27c3756178cf5d4338698d8</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 1" src="https://img.shields.io/badge/critical-1-8b1924"/> <img alt="high: 8" src="https://img.shields.io/badge/high-8-e25d68"/> <img alt="medium: 7" src="https://img.shields.io/badge/medium-7-fbb552"/> <img alt="low: 135" src="https://img.shields.io/badge/low-135-fce1a9"/> <img alt="unspecified: 4" src="https://img.shields.io/badge/unspecified-4-lightgrey"/></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>531 MB</td></tr>
<tr><td>packages</td><td>612</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>wget</strong> <code>1.21.3-1+b2</code> (deb)</summary>

<small><code>pkg:deb/debian/wget@1.21.3-1%2Bb2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-38428?s=debian&n=wget&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.21.3-1%2Bdeb12u1"><img alt="critical : CVE--2024--38428" src="https://img.shields.io/badge/CVE--2024--38428-lightgrey?label=critical%20&labelColor=8b1924"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.21.3-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.21.3-1+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.251%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>48th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

url.c in GNU Wget through 1.24.5 mishandles semicolons in the userinfo subcomponent of a URI, and thus there may be insecure behavior in which data that was supposed to be in the userinfo subcomponent is misinterpreted to be part of the host subcomponent.

---
- wget 1.24.5-2 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1073523)
[bookworm] - wget 1.21.3-1+deb12u1
[bullseye] - wget <no-dsa> (Minor issue)
[buster] - wget <postponed> (Minor issue, infoleak in limited conditions)
https://lists.gnu.org/archive/html/bug-wget/2024-06/msg00005.html
Fixed by: https://git.savannah.gnu.org/cgit/wget.git/commit/?id=ed0c7c7e0e8f7298352646b2fd6e06a11e242ace

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 3" src="https://img.shields.io/badge/H-3-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>libxml2</strong> <code>2.9.14+dfsg-1.3~deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/libxml2@2.9.14%2Bdfsg-1.3~deb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-49043?s=debian&n=libxml2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.9.14%2Bdfsg-1.3%7Edeb12u1"><img alt="high : CVE--2022--49043" src="https://img.shields.io/badge/CVE--2022--49043-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.9.14+dfsg-1.3~deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

xmlXIncludeAddNode in xinclude.c in libxml2 before 2.11.0 has a use-after-free.

---
[experimental] - libxml2 2.12.3+dfsg-0exp1
- libxml2 2.12.7+dfsg+really2.9.14-0.4 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1094238)
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/5a19e21605398cef6a8b1452477a8705cb41562b (v2.11.0)
https://github.com/php/php-src/issues/17467

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-24928?s=debian&n=libxml2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.9.14%2Bdfsg-1.3%7Edeb12u1"><img alt="high : CVE--2025--24928" src="https://img.shields.io/badge/CVE--2025--24928-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.9.14+dfsg-1.3~deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.007%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a stack-based buffer overflow in xmlSnprintfElements in valid.c. To exploit this, DTD validation must occur for an untrusted document or untrusted DTD. NOTE: this is similar to CVE-2017-9047.

---
- libxml2 2.12.7+dfsg+really2.9.14-0.4 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1098321)
https://gitlab.gnome.org/GNOME/libxml2/-/issues/847
https://www.openwall.com/lists/oss-security/2025/02/18/2
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/8c8753ad5280ee13aee5eec9b0f6eee2ed920f57
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/858ca26c0689161a6b903a6682cc8a1cc10a0ea8 (v2.12.10)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56171?s=debian&n=libxml2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.9.14%2Bdfsg-1.3%7Edeb12u1"><img alt="high : CVE--2024--56171" src="https://img.shields.io/badge/CVE--2024--56171-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.9.14+dfsg-1.3~deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.006%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a use-after-free in xmlSchemaIDCFillNodeTables and xmlSchemaBubbleIDCNodeTables in xmlschemas.c. To exploit this, a crafted XML document must be validated against an XML schema with certain identity constraints, or a crafted XML schema must be used.

---
- libxml2 2.12.7+dfsg+really2.9.14-0.4 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1098320)
https://gitlab.gnome.org/GNOME/libxml2/-/issues/828
https://www.openwall.com/lists/oss-security/2025/02/18/2
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/5880a9a6bd97c0f9ac8fc4f30110fe023f484746
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/245b70d7d2768572ae1b05b3668ca858b9ec4ed4 (v2.12.10)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-27113?s=debian&n=libxml2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.9.14%2Bdfsg-1.3%7Edeb12u1"><img alt="low : CVE--2025--27113" src="https://img.shields.io/badge/CVE--2025--27113-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.9.14+dfsg-1.3~deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libxml2 before 2.12.10 and 2.13.x before 2.13.6 has a NULL pointer dereference in xmlPatMatch in pattern.c.

---
- libxml2 2.12.7+dfsg+really2.9.14-0.4 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1098322)
https://gitlab.gnome.org/GNOME/libxml2/-/issues/861
https://www.openwall.com/lists/oss-security/2025/02/18/2
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/6c716d491dd2e67f08066f4dc0619efeb49e43e6
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/503f788e84f1c1f1d769c2c7258d77faee94b5a3 (v2.12.10)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-34459?s=debian&n=libxml2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.9.14%2Bdfsg-1.3%7Edeb12u1"><img alt="low : CVE--2024--34459" src="https://img.shields.io/badge/CVE--2024--34459-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.9.14+dfsg-1.3~deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.139%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in xmllint (from libxml2) before 2.11.8 and 2.12.x before 2.12.7. Formatting error messages with xmllint --htmlout can result in a buffer over-read in xmlHTMLPrintFileContext in xmllint.c.

---
- libxml2 2.12.7+dfsg+really2.9.14-0.4 (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1071162)
https://gitlab.gnome.org/GNOME/libxml2/-/issues/720
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/8ddc7f13337c9fe7c6b6e616f404b0fffb8a5145 (v2.11.8)
Fixed by: https://gitlab.gnome.org/GNOME/libxml2/-/commit/2876ac5392a4e891b81e40e592c3ac6cb46016ce (v2.12.7)
Crash in CLI tool, no security impact

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libxslt</strong> <code>1.1.35-1</code> (deb)</summary>

<small><code>pkg:deb/debian/libxslt@1.1.35-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-24855?s=debian&n=libxslt&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.1.35-1%2Bdeb12u1"><img alt="high : CVE--2025--24855" src="https://img.shields.io/badge/CVE--2025--24855-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.1.35-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.1.35-1+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

numbers.c in libxslt before 1.1.43 has a use-after-free because, in nested XPath evaluations, an XPath context node can be modified but never restored. This is related to xsltNumberFormatGetValue, xsltEvalXPathPredicate, xsltEvalXPathStringNs, and xsltComputeSortResultInternal.

---
- libxslt 1.1.35-1.2 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1100566)
https://gitlab.gnome.org/GNOME/libxslt/-/issues/128
Fixed by: https://gitlab.gnome.org/GNOME/libxslt/-/commit/c7c7f1f78dd202a053996fcefe57eb994aec8ef2 (v1.1.43)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-55549?s=debian&n=libxslt&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.1.35-1%2Bdeb12u1"><img alt="high : CVE--2024--55549" src="https://img.shields.io/badge/CVE--2024--55549-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.1.35-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.1.35-1+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

xsltGetInheritedNsList in libxslt before 1.1.43 has a use-after-free issue related to exclusion of result prefixes.

---
- libxslt 1.1.35-1.2 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1100565)
https://gitlab.gnome.org/GNOME/libxslt/-/issues/127
Fixed by: https://gitlab.gnome.org/GNOME/libxslt/-/commit/46041b65f2fbddf5c284ee1a1332fa2c515c0515 (v1.1.43)
https://project-zero.issues.chromium.org/issues/382015274

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2015-9019?s=debian&n=libxslt&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.1.35-1"><img alt="low : CVE--2015--9019" src="https://img.shields.io/badge/CVE--2015--9019-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.1.35-1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.978%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>75th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In libxslt 1.1.29 and earlier, the EXSLT math.random function was not initialized with a random seed during startup, which could cause usage of this function to produce predictable outputs.

---
- libxslt <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=859796)
https://bugzilla.gnome.org/show_bug.cgi?id=758400
https://bugzilla.suse.com/show_bug.cgi?id=934119
There's no indication that math.random() in intended to ensure cryptographic
randomness requirements. Proper seeding needs to happen in the application
using libxslt.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>postgresql-15</strong> <code>15.10-0+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/postgresql-15@15.10-0%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-1094?s=debian&n=postgresql-15&ns=debian&t=deb&osn=debian&osv=12&vr=%3C15.11-0%2Bdeb12u1"><img alt="high : CVE--2025--1094" src="https://img.shields.io/badge/CVE--2025--1094-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><15.11-0+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>15.11-0+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>84.091%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper neutralization of quoting syntax in PostgreSQL libpq functions PQescapeLiteral(), PQescapeIdentifier(), PQescapeString(), and PQescapeStringConn() allows a database input provider to achieve SQL injection in certain usage patterns.  Specifically, SQL injection requires the application to use the function result to construct input to psql, the PostgreSQL interactive terminal.  Similarly, improper neutralization of quoting syntax in PostgreSQL command line utility programs allows a source of command line arguments to achieve SQL injection when client_encoding is BIG5 and server_encoding is one of EUC_TW or MULE_INTERNAL.  Versions before PostgreSQL 17.3, 16.7, 15.11, 14.16, and 13.19 are affected.

---
- postgresql-17 17.3-1
- postgresql-15 <removed>
[bookworm] - postgresql-15 15.11-0+deb12u1
- postgresql-13 <removed>
https://www.postgresql.org/support/security/CVE-2025-1094/
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=7d43ca6fe068015b403ffa1762f4df4efdf68b69 (REL_17_3)
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=61ad93cdd48ecc8c6edf943f4d888a9325b66882 (REL_17_3)
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=43a77239d412db194a69b18b7850580e3b78218f (REL_17_3)
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=02d4d87ac20e2698b5375b347c451c55045e388d (REL_17_3)
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=dd3c1eb38e9add293f8be59b6aec7574e8584bdb (REL_17_3)
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=05abb0f8303a78921f7113bee1d72586142df99e (REL_17_3)
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=85c1fcc6563843d7ee7ae6f81f29ef813e77a4b6 (REL_17_3)
Regression: https://www.openwall.com/lists/oss-security/2025/02/16/3
https://www.postgresql.org/about/news/postgresql-174-168-1512-1417-and-1320-released-3018/

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>freetype</strong> <code>2.12.1+dfsg-5+deb12u3</code> (deb)</summary>

<small><code>pkg:deb/debian/freetype@2.12.1%2Bdfsg-5%2Bdeb12u3?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-27363?s=debian&n=freetype&ns=debian&t=deb&osn=debian&osv=12&vr=%3C2.12.1%2Bdfsg-5%2Bdeb12u4"><img alt="high : CVE--2025--27363" src="https://img.shields.io/badge/CVE--2025--27363-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.12.1+dfsg-5+deb12u4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.12.1+dfsg-5+deb12u4</code></td></tr>
<tr><td>EPSS Score</td><td><code>9.488%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>92nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out of bounds write exists in FreeType versions 2.13.0 and below (newer versions of FreeType are not vulnerable) when attempting to parse font subglyph structures related to TrueType GX and variable font files. The vulnerable code assigns a signed short value to an unsigned long and then adds a static value causing it to wrap around and allocate too small of a heap buffer. The code then writes up to 6 signed long integers out of bounds relative to this buffer. This may result in arbitrary code execution. This vulnerability may have been exploited in the wild.

---
- freetype 2.13.1+dfsg-1
https://www.facebook.com/security/advisories/cve-2025-27363
https://gitlab.freedesktop.org/freetype/freetype/-/issues/1322
Requisite (macro fixup for FT_Q(RE)NEW_ARRAY): https://gitlab.freedesktop.org/freetype/freetype/-/commit/c71eb22dde1a3101891a865fdac20a6de814267d (VER-2-11-1)
Fixed by: https://gitlab.freedesktop.org/freetype/freetype/-/commit/ef636696524b081f1b8819eb0c6a0b932d35757d (VER-2-13-1)
Followup: https://gitlab.freedesktop.org/freetype/freetype/-/commit/73720c7c9958e87b3d134a7574d1720ad2d24442 (VER-2-13-3)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>glibc</strong> <code>2.36-9+deb12u9</code> (deb)</summary>

<small><code>pkg:deb/debian/glibc@2.36-9%2Bdeb12u9?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-0395?s=debian&n=glibc&ns=debian&t=deb&osn=debian&osv=12&vr=%3C2.36-9%2Bdeb12u10"><img alt="high : CVE--2025--0395" src="https://img.shields.io/badge/CVE--2025--0395-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.36-9+deb12u10</code></td></tr>
<tr><td>Fixed version</td><td><code>2.36-9+deb12u10</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.136%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When the assert() function in the GNU C Library versions 2.13 to 2.40 fails, it does not allocate enough space for the assertion failure message string and size information, which may lead to a buffer overflow if the message string size aligns to page size.

---
- glibc 2.40-6
[bookworm] - glibc 2.36-9+deb12u10
[bullseye] - glibc <postponed> (Minor issue; can be fixed in next update)
https://sourceware.org/bugzilla/show_bug.cgi?id=32582
https://www.openwall.com/lists/oss-security/2025/01/22/4
Fixed by: https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=7d4b6bcae91f29d7b4daf15bab06b66cf1d2217c (2.40-branch)
Fixed by: https://sourceware.org/git/gitweb.cgi?p=glibc.git;h=7971add7ee4171fdd8dfd17e7c04c4ed77a18845 (2.36-branch)
https://sourceware.org/git/?p=glibc.git;a=blob;f=advisories/GLIBC-SA-2025-0001
https://sourceware.org/pipermail/libc-announce/2025/000044.html

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>libwmf</strong> <code>0.2.12-5.1</code> (deb)</summary>

<small><code>pkg:deb/debian/libwmf@0.2.12-5.1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2009-3546?s=debian&n=libwmf&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.2.12-5.1"><img alt="medium : CVE--2009--3546" src="https://img.shields.io/badge/CVE--2009--3546-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.2.12-5.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>3.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>86th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The _gdGetColors function in gd_gd.c in PHP 5.2.11 and 5.3.x before 5.3.1, and the GD Graphics Library 2.x, does not properly verify a certain colorsTotal structure member, which might allow remote attackers to conduct buffer overflow or buffer over-read attacks via a crafted GD file, a different vulnerability than CVE-2009-3293. NOTE: some of these details are obtained from third party information.

---
- libwmf <unfixed> (unimportant)
- racket 5.0.2-1 (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=601525)
Only present in one of the sample pl-scheme packages (plot)
- libgd2 2.0.36~rc1~dfsg-3.1 (medium; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=552534)
- php5 <not-affected> (the php packages use the system libgd2)
http://svn.php.net/viewvc?view=revision&revision=289557
<20091015173822.084de220@redhat.com> in OSS-sec

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2007-3996?s=debian&n=libwmf&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.2.12-5.1"><img alt="medium : CVE--2007--3996" src="https://img.shields.io/badge/CVE--2007--3996-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.2.12-5.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>6.959%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Multiple integer overflows in libgd in PHP before 5.2.4 allow remote attackers to cause a denial of service (application crash) and possibly execute arbitrary code via a large (1) srcW or (2) srcH value to the (a) gdImageCopyResized function, or a large (3) sy (height) or (4) sx (width) value to the (b) gdImageCreate or the (c) gdImageCreateTrueColor function.

---
- libgd2 2.0.35.dfsg-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=443456; medium)
- libwmf <unfixed> (unimportant)
- racket 5.0.2-1 (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=601525)
Only present in one of the sample pl-scheme packages (plot)
Debian's PHP packages are linked dynamically against libgd
see http://www.php.net/releases/5_2_4.php

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2007-3477?s=debian&n=libwmf&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.2.12-5.1"><img alt="low : CVE--2007--3477" src="https://img.shields.io/badge/CVE--2007--3477-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.2.12-5.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>6.743%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The (a) imagearc and (b) imagefilledarc functions in GD Graphics Library (libgd) before 2.0.35 allow attackers to cause a denial of service (CPU consumption) via a large (1) start or (2) end angle degree value.

---
- libgd2 2.0.35.dfsg-1 (low)
- libwmf <unfixed> (unimportant)
- racket 5.0.2-1 (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=601525)
Only present in one of the sample pl-scheme packages (plot)
CPU consumption DoS

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2007-3476?s=debian&n=libwmf&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.2.12-5.1"><img alt="low : CVE--2007--3476" src="https://img.shields.io/badge/CVE--2007--3476-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.2.12-5.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>5.183%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Array index error in gd_gif_in.c in the GD Graphics Library (libgd) before 2.0.35 allows user-assisted remote attackers to cause a denial of service (crash and heap corruption) via large color index values in crafted image data, which results in a segmentation fault.

---
- libgd2 2.0.35.dfsg-1 (low)
- libwmf <unfixed> (unimportant)
- racket 5.0.2-1 (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=601525)
Only present in one of the sample pl-scheme packages (plot)
can write a 0 to a 4k window in heap, very unlikely to be controllable.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>mariadb</strong> <code>1:10.11.6-0+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/mariadb@1%3A10.11.6-0%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-21490?s=debian&n=mariadb&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1%3A10.11.11-0%2Bdeb12u1"><img alt="medium : CVE--2025--21490" src="https://img.shields.io/badge/CVE--2025--21490-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:10.11.11-0+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1:10.11.11-0+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.059%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB).  Supported versions that are affected are 8.0.40 and prior, 8.4.3 and prior and  9.1.0 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H).

---
- mysql-8.0 8.0.41-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1093877)
- mariadb 1:11.4.5-1
[bookworm] - mariadb 1:10.11.11-0+deb12u1
- mariadb-10.5 <removed>
Fixed in MariaDB 11.7.2, 11.4.5, 10.11.11, 10.6.21, 10.5.28

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-21096?s=debian&n=mariadb&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1%3A10.11.11-0%2Bdeb12u1"><img alt="medium : CVE--2024--21096" src="https://img.shields.io/badge/CVE--2024--21096-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:10.11.11-0+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1:10.11.11-0+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.075%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the MySQL Server product of Oracle MySQL (component: Client: mysqldump).  Supported versions that are affected are 8.0.36 and prior and  8.3.0 and prior. Difficult to exploit vulnerability allows unauthenticated attacker with logon to the infrastructure where MySQL Server executes to compromise MySQL Server.  Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of MySQL Server accessible data as well as  unauthorized read access to a subset of MySQL Server accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of MySQL Server. CVSS 3.1 Base Score 4.9 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L).

---
- mysql-8.0 8.0.37-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1069189)
- mariadb 1:10.11.8-1
[bookworm] - mariadb 1:10.11.11-0+deb12u1
- mariadb-10.5 <removed>
[bullseye] - mariadb-10.5 <no-dsa> (Minor issue)
- mariadb-10.3 <removed>
MariaDB: Fixed in 11.2.4, 11.1.5, 11.0.6, 10.11.8, 10.6.18 and 10.5.25
MariaDB Bug: https://jira.mariadb.org/browse/MDEV-33727
Regression: https://jira.mariadb.org/browse/MDEV-34339
Regression: https://jira.mariadb.org/browse/MDEV-34183
Regression: https://jira.mariadb.org/browse/MDEV-34203
Regression: https://jira.mariadb.org/browse/MDEV-34318
https://mariadb.org/mariadb-dump-file-compatibility-change/
https://ddev.com/blog/mariadb-dump-breaking-change/
MariaDB commit [1/2]: https://github.com/MariaDB/server/commit/13663cb5c4558383e9dab96e501d72ceb7a0a158 (mariadb-10.5.25)
MariaDB commit [2/2]: https://github.com/MariaDB/server/commit/1c425a8d854061d1987ad4ea352c7270652e31c4 (mariadb-10.5.25)
MariaDB partial regression fix [1/3]: https://github.com/MariaDB/server/commit/77c4c0f256f3c268d3f72625b04240d24a70513c (mariadb-10.5.26)
MariaDB partial regression fix [2/3]: https://github.com/MariaDB/server/commit/d60f5c11ea9008fa57444327526e3d2c8633ba06 (mariadb-10.5.26)
MariaDB partial regression fix [3/3]: https://github.com/MariaDB/server/commit/d20518168aff435a4843eebb108e5b9df24c19fb (mariadb-10.5.26)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 3" src="https://img.shields.io/badge/L-3-fce1a9"/> <!-- unspecified: 0 --><strong>krb5</strong> <code>1.20.1-2+deb12u2</code> (deb)</summary>

<small><code>pkg:deb/debian/krb5@1.20.1-2%2Bdeb12u2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-3576?s=debian&n=krb5&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.20.1-2%2Bdeb12u2"><img alt="medium : CVE--2025--3576" src="https://img.shields.io/badge/CVE--2025--3576-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.20.1-2+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.012%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the MIT Kerberos implementation allows GSSAPI-protected messages using RC4-HMAC-MD5 to be spoofed due to weaknesses in the MD5 checksum design. If RC4 is preferred over stronger encryption types, an attacker could exploit MD5 collisions to forge message integrity codes. This may lead to unauthorized message tampering.

---
- krb5 <unfixed>
https://bugzilla.redhat.com/show_bug.cgi?id=2359465
TODO: check upstream details

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26461?s=debian&n=krb5&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.20.1-2%2Bdeb12u2"><img alt="low : CVE--2024--26461" src="https://img.shields.io/badge/CVE--2024--26461-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.20.1-2+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

---
- krb5 <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1098754; unimportant)
https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_2.md
Fixed by: https://github.com/krb5/krb5/commit/c5f9c816107f70139de11b38aa02db2f1774ee0d
Codepath cannot be triggered via API calls, negligible security impact
https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26458?s=debian&n=krb5&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.20.1-2%2Bdeb12u2"><img alt="low : CVE--2024--26458" src="https://img.shields.io/badge/CVE--2024--26458-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.20.1-2+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.106%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

---
- krb5 <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1098754; unimportant)
https://github.com/LuMingYinDetect/krb5_defects/blob/main/krb5_detect_1.md
Fixed by: https://github.com/krb5/krb5/commit/c5f9c816107f70139de11b38aa02db2f1774ee0d
Unused codepath, negligible security impact
https://mailman.mit.edu/pipermail/kerberos/2024-March/023095.html

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-5709?s=debian&n=krb5&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.20.1-2%2Bdeb12u2"><img alt="low : CVE--2018--5709" src="https://img.shields.io/badge/CVE--2018--5709-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.20.1-2+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.865%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>74th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in MIT Kerberos 5 (aka krb5) through 1.16. There is a variable "dbentry->n_key_data" in kadmin/dbutil/dump.c that can store 16-bit data but unknowingly the developer has assigned a "u4" variable to it, which is for 32-bit data. An attacker can use this vulnerability to affect other artifacts of the database as we know that a Kerberos database dump file contains trusted data.

---
- krb5 <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=889684)
https://github.com/poojamnit/Kerberos-V5-1.16-Vulnerabilities/tree/master/Integer%20Overflow
non-issue, codepath is only run on trusted input, potential integer
overflow is non-issue

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>curl</strong> <code>7.88.1-10+deb12u8</code> (deb)</summary>

<small><code>pkg:deb/debian/curl@7.88.1-10%2Bdeb12u8?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-9681?s=debian&n=curl&ns=debian&t=deb&osn=debian&osv=12&vr=%3C7.88.1-10%2Bdeb12u9"><img alt="medium : CVE--2024--9681" src="https://img.shields.io/badge/CVE--2024--9681-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><7.88.1-10+deb12u9</code></td></tr>
<tr><td>Fixed version</td><td><code>7.88.1-10+deb12u9</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.261%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>49th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When curl is asked to use HSTS, the expiry time for a subdomain might overwrite a parent domain's cache entry, making it end sooner or later than otherwise intended.  This affects curl using applications that enable HSTS and use URLs with the insecure `HTTP://` scheme and perform transfers with hosts like `x.example.com` as well as `example.com` where the first host is a subdomain of the second host.  (The HSTS cache either needs to have been populated manually or there needs to have been previous HTTPS accesses done as the cache needs to have entries for the domains involved to trigger this problem.)  When `x.example.com` responds with `Strict-Transport-Security:` headers, this bug can make the subdomain's expiry timeout *bleed over* and get set for the parent domain `example.com` in curl's HSTS cache.  The result of a triggered bug is that HTTP accesses to `example.com` get converted to HTTPS for a different period of time than what was asked for by the origin server. If `example.com` for example stops supporting HTTPS at its expiry time, curl might then fail to access `http://example.com` until the (wrongly set) timeout expires. This bug can also expire the parent's entry *earlier*, thus making curl inadvertently switch back to insecure HTTP earlier than otherwise intended.

---
- curl 8.11.0-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1086804)
[bookworm] - curl 7.88.1-10+deb12u9
[bullseye] - curl <ignored> (curl is not built with HSTS support)
https://curl.se/docs/CVE-2024-9681.html
Introduced by: https://github.com/curl/curl/commit/7385610d0c74c6a254fea5e4cd6e1d559d848c8c (curl-7_74_0)
Fixed by: https://github.com/curl/curl/commit/a94973805df96269bf3f3bf0a20ccb9887313316 (curl-8_11_0)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-0167?s=debian&n=curl&ns=debian&t=deb&osn=debian&osv=12&vr=%3C7.88.1-10%2Bdeb12u11"><img alt="low : CVE--2025--0167" src="https://img.shields.io/badge/CVE--2025--0167-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><7.88.1-10+deb12u11</code></td></tr>
<tr><td>Fixed version</td><td><code>7.88.1-10+deb12u11</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.062%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When asked to use a `.netrc` file for credentials **and** to follow HTTP redirects, curl could leak the password used for the first host to the followed-to host under certain circumstances.  This flaw only manifests itself if the netrc file has a `default` entry that omits both login and password. A rare circumstance.

---
- curl 8.12.0+git20250209.89ed161+ds-1
[bookworm] - curl 7.88.1-10+deb12u11
[bullseye] - curl <not-affected> (Vulnerable code introduced later)
https://curl.se/docs/CVE-2025-0167.html
Introduced with: https://github.com/curl/curl/commit/46620b97431e19c53ce82e55055c85830f088cf4 (curl-7_76_0)
Fixed by: https://github.com/curl/curl/commit/0e120c5b925e8ca75d5319e319e5ce4b8080d8eb (curl-8_12_0)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-11053?s=debian&n=curl&ns=debian&t=deb&osn=debian&osv=12&vr=%3C7.88.1-10%2Bdeb12u10"><img alt="low : CVE--2024--11053" src="https://img.shields.io/badge/CVE--2024--11053-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><7.88.1-10+deb12u10</code></td></tr>
<tr><td>Fixed version</td><td><code>7.88.1-10+deb12u10</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.154%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>37th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When asked to both use a `.netrc` file for credentials and to follow HTTP redirects, curl could leak the password used for the first host to the followed-to host under certain circumstances.  This flaw only manifests itself if the netrc file has an entry that matches the redirect target hostname but the entry either omits just the password or omits both login and password.

---
- curl 8.11.1-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1089682)
[bookworm] - curl 7.88.1-10+deb12u10
[bullseye] - curl <not-affected> (Vulnerable code only introduced in 7.76.0)
https://curl.se/docs/CVE-2024-11053.html
Introduced by: https://github.com/curl/curl/commit/46620b97431e19c53ce82e55055c85830f088cf4 (curl-7_76_0)
Fixed by: https://github.com/curl/curl/commit/e9b9bbac22c26cf67316fa8e6c6b9e831af31949 (curl-8_11_1)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>mercurial</strong> <code>6.3.2-1</code> (deb)</summary>

<small><code>pkg:deb/debian/mercurial@6.3.2-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-2361?s=debian&n=mercurial&ns=debian&t=deb&osn=debian&osv=12&vr=%3C6.3.2-1%2Bdeb12u1"><img alt="medium : CVE--2025--2361" src="https://img.shields.io/badge/CVE--2025--2361-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.3.2-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>6.3.2-1+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.075%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in Mercurial SCM 4.5.3/71.19.145.211. It has been declared as problematic. This vulnerability affects unknown code of the component Web Interface. The manipulation of the argument cmd leads to cross site scripting. The attack can be initiated remotely. The exploit has been disclosed to the public and may be used. The vendor was contacted early about this disclosure but did not respond in any way.

---
- mercurial 6.9.4-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1100899)
https://lists.mercurial-scm.org/pipermail/mercurial-packaging/2025-March/000754.html
Fixed by: https://foss.heptapod.net/mercurial/mercurial-devel/-/commit/a5c72ed2929341d97b11968211c880854803f003 (6.9.4)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 23" src="https://img.shields.io/badge/L-23-fce1a9"/> <!-- unspecified: 0 --><strong>binutils</strong> <code>2.40-2</code> (deb)</summary>

<small><code>pkg:deb/debian/binutils@2.40-2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-3198?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--3198" src="https://img.shields.io/badge/CVE--2025--3198-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability has been found in GNU Binutils 2.43/2.44 and classified as problematic. Affected by this vulnerability is the function display_info of the file binutils/bucomm.c of the component objdump. The manipulation leads to memory leak. An attack has to be approached locally. The exploit has been disclosed to the public and may be used. The patch is named ba6ad3a18cb26b79e0e3b84c39f707535bbc344d. It is recommended to apply a patch to fix this issue.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32716
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=ba6ad3a18cb26b79e0e3b84c39f707535bbc344d
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1182?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1182" src="https://img.shields.io/badge/CVE--2025--1182-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.086%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability, which was classified as critical, was found in GNU Binutils 2.43. Affected is the function bfd_elf_reloc_symbol_deleted_p of the file bfd/elflink.c of the component ld. The manipulation leads to memory corruption. It is possible to launch the attack remotely. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. The patch is identified as b425859021d17adf62f06fb904797cf8642986ad. It is recommended to apply a patch to fix this issue.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32644
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=b425859021d17adf62f06fb904797cf8642986ad
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1181?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1181" src="https://img.shields.io/badge/CVE--2025--1181-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.086%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability classified as critical was found in GNU Binutils 2.43. This vulnerability affects the function _bfd_elf_gc_mark_rsec of the file bfd/elflink.c of the component ld. The manipulation leads to memory corruption. The attack can be initiated remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The name of the patch is 931494c9a89558acb36a03a340c01726545eef24. It is recommended to apply a patch to fix this issue.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32643
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=931494c9a89558acb36a03a340c01726545eef24
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1180?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1180" src="https://img.shields.io/badge/CVE--2025--1180-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.085%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability classified as problematic has been found in GNU Binutils 2.43. This affects the function _bfd_elf_write_section_eh_frame of the file bfd/elf-eh-frame.c of the component ld. The manipulation leads to memory corruption. It is possible to initiate the attack remotely. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32642
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1179?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1179" src="https://img.shields.io/badge/CVE--2025--1179-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.092%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GNU Binutils 2.43. It has been rated as critical. Affected by this issue is the function bfd_putl64 of the file bfd/libbfd.c of the component ld. The manipulation leads to memory corruption. The attack may be launched remotely. The complexity of an attack is rather high. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used. Upgrading to version 2.44 is able to address this issue. It is recommended to upgrade the affected component. The code maintainer explains, that "[t]his bug has been fixed at some point between the 2.43 and 2.44 releases".

---
- binutils 2.44-1 (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32640
binutils not covered by security support
No exact commits pinpointed, but upstream confirms this fixed in 2.44

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1178?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1178" src="https://img.shields.io/badge/CVE--2025--1178-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.132%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>34th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GNU Binutils 2.43. It has been declared as problematic. Affected by this vulnerability is the function bfd_putl64 of the file libbfd.c of the component ld. The manipulation leads to memory corruption. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The identifier of the patch is 75086e9de1707281172cc77f178e7949a4414ed0. It is recommended to apply a patch to fix this issue.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32638
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=75086e9de1707281172cc77f178e7949a4414ed0
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1176?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1176" src="https://img.shields.io/badge/CVE--2025--1176-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.093%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GNU Binutils 2.43 and classified as critical. This issue affects the function _bfd_elf_gc_mark_rsec of the file elflink.c of the component ld. The manipulation leads to heap-based buffer overflow. The attack may be initiated remotely. The complexity of an attack is rather high. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used. The patch is named f9978defb6fab0bd8583942d97c112b0932ac814. It is recommended to apply a patch to fix this issue.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32636
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=f9978defb6fab0bd8583942d97c112b0932ac814
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1153?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1153" src="https://img.shields.io/badge/CVE--2025--1153-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.109%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability classified as problematic was found in GNU Binutils 2.43/2.44. Affected by this vulnerability is the function bfd_set_format of the file format.c. The manipulation leads to memory corruption. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. Upgrading to version 2.45 is able to address this issue. The identifier of the patch is 8d97c1a53f3dc9fd8e1ccdb039b8a33d50133150. It is recommended to upgrade the affected component.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32603
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=8d97c1a53f3dc9fd8e1ccdb039b8a33d50133150
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1152?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1152" src="https://img.shields.io/badge/CVE--2025--1152-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.051%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability classified as problematic has been found in GNU Binutils 2.43. Affected is the function xstrdup of the file xstrdup.c of the component ld. The manipulation leads to memory leak. It is possible to launch the attack remotely. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue. The code maintainer explains: "I'm not going to commit some of the leak fixes I've been working on to the 2.44 branch due to concern that would destabilise ld. All of the reported leaks in this bugzilla have been fixed on binutils master."

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32576
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1151?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1151" src="https://img.shields.io/badge/CVE--2025--1151-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.051%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GNU Binutils 2.43. It has been rated as problematic. This issue affects the function xmemdup of the file xmemdup.c of the component ld. The manipulation leads to memory leak. The attack may be initiated remotely. The complexity of an attack is rather high. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue. The code maintainer explains: "I'm not going to commit some of the leak fixes I've been working on to the 2.44 branch due to concern that would destabilise ld. All of the reported leaks in this bugzilla have been fixed on binutils master."

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32576
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1150?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1150" src="https://img.shields.io/badge/CVE--2025--1150-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.051%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GNU Binutils 2.43. It has been declared as problematic. This vulnerability affects the function bfd_malloc of the file libbfd.c of the component ld. The manipulation leads to memory leak. The attack can be initiated remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue. The code maintainer explains: "I'm not going to commit some of the leak fixes I've been working on to the 2.44 branch due to concern that would destabilise ld. All of the reported leaks in this bugzilla have been fixed on binutils master."

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32576
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1149?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1149" src="https://img.shields.io/badge/CVE--2025--1149-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.051%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GNU Binutils 2.43. It has been classified as problematic. This affects the function xstrdup of the file libiberty/xmalloc.c of the component ld. The manipulation leads to memory leak. It is possible to initiate the attack remotely. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue. The code maintainer explains: "I'm not going to commit some of the leak fixes I've been working on to the 2.44 branch due to concern that would destabilise ld. All of the reported leaks in this bugzilla have been fixed on binutils master."

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32576
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1148?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1148" src="https://img.shields.io/badge/CVE--2025--1148-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.115%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>31st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GNU Binutils 2.43 and classified as problematic. Affected by this issue is the function link_order_scan of the file ld/ldelfgen.c of the component ld. The manipulation leads to memory leak. The attack may be launched remotely. The complexity of an attack is rather high. The exploitation is known to be difficult. The exploit has been disclosed to the public and may be used. It is recommended to apply a patch to fix this issue. The code maintainer explains: "I'm not going to commit some of the leak fixes I've been working on to the 2.44 branch due to concern that would destabilise ld. All of the reported leaks in this bugzilla have been fixed on binutils master."

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32576
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1147?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--1147" src="https://img.shields.io/badge/CVE--2025--1147-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.107%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability has been found in GNU Binutils 2.43 and classified as problematic. Affected by this vulnerability is the function __sanitizer::internal_strlen of the file binutils/nm.c of the component nm. The manipulation of the argument const leads to buffer overflow. The attack can be launched remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32556
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-0840?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2025--0840" src="https://img.shields.io/badge/CVE--2025--0840-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.093%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability, which was classified as problematic, was found in GNU Binutils up to 2.43. This affects the function disassemble_bytes of the file binutils/objdump.c. The manipulation of the argument buf leads to stack-based buffer overflow. It is possible to initiate the attack remotely. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. Upgrading to version 2.44 is able to address this issue. The identifier of the patch is baac6c221e9d69335bf41366a1c7d87d8ab2f893. It is recommended to upgrade the affected component.

---
- binutils 2.43.90.20250122-1 (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32560
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=baac6c221e9d69335bf41366a1c7d87d8ab2f893
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57360?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2024--57360" src="https://img.shields.io/badge/CVE--2024--57360-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

https://www.gnu.org/software/binutils/ nm >=2.43 is affected by: Incorrect Access Control. The type of exploitation is: local. The component is: `nm --without-symbol-version` function.

---
- binutils 2.43.50.20241221-1 (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32467
Fixed by: https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=5f8987d3999edb26e757115fe87be55787d510b9
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53589?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2024--53589" src="https://img.shields.io/badge/CVE--2024--53589-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GNU objdump 2.43 is vulnerable to Buffer Overflow in the BFD (Binary File Descriptor) library's handling of tekhex format files.

---
- binutils 2.44-1 (unimportant)
https://bushido-sec.com/index.php/2024/12/05/binutils-objdump-tekhex-buffer-overflow/
https://sourceware.org/git/gitweb.cgi?p=binutils-gdb.git;h=e0323071916878e0634a6e24d8250e4faff67e88 (binutils-2_44)
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-1972?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2023--1972" src="https://img.shields.io/badge/CVE--2023--1972-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A potential heap based buffer overflow was found in _bfd_elf_slurp_version_tables() in bfd/elf.c. This may lead to loss of availability.

---
- binutils 2.41-1 (unimportant)
https://sourceware.org/git/?p=binutils-gdb.git;a=blobdiff;f=bfd/elf.c;h=185028cbd97ae0901c4276c8a4787b12bb75875a;hp=027d01437352555bc4ac0717cb0486c751a7775d;hb=c22d38baefc5a7a1e1f5cdc9dbb556b1f0ec5c57;hpb=f2f9bde5cde7ff34ed0a4c4682a211d402aa1086
https://sourceware.org/bugzilla/show_bug.cgi?id=30285
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-32256?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2021--32256" src="https://img.shields.io/badge/CVE--2021--32256-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.115%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>32nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in GNU libiberty, as distributed in GNU Binutils 2.36. It is a stack-overflow issue in demangle_type in rust-demangle.c.

---
- binutils <unfixed> (unimportant)
https://bugs.launchpad.net/ubuntu/+source/binutils/+bug/1927070
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-9996?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2018--9996" src="https://img.shields.io/badge/CVE--2018--9996-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.385%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>59th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30. Stack Exhaustion occurs in the C++ demangling functions provided by libiberty, and there are recursive stack frames: demangle_template_value_parm, demangle_integral_value, and demangle_expression.

---
- binutils <unfixed> (unimportant)
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=85304
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-20712?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2018--20712" src="https://img.shields.io/badge/CVE--2018--20712-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>1.070%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>77th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-based buffer over-read exists in the function d_expression_1 in cp-demangle.c in GNU libiberty, as distributed in GNU Binutils 2.31.1. A crafted input can cause segmentation faults, leading to denial-of-service, as demonstrated by c++filt.

---
- binutils <unfixed> (unimportant)
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=88629
https://sourceware.org/bugzilla/show_bug.cgi?id=24043
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-20673?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2018--20673" src="https://img.shields.io/badge/CVE--2018--20673-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.100%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>29th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The demangle_template function in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.31.1, contains an integer overflow vulnerability (for "Create an array for saving the template argument values") that can trigger a heap-based buffer overflow, as demonstrated by nm.

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=24039
binutils not covered by security support

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-13716?s=debian&n=binutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.40-2"><img alt="low : CVE--2017--13716" src="https://img.shields.io/badge/CVE--2017--13716-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.40-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.255%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>49th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The C++ symbol demangler routine in cplus-dem.c in libiberty, as distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (excessive memory allocation and application crash) via a crafted file, as demonstrated by a call from the Binary File Descriptor (BFD) library (aka libbfd).

---
- binutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=22009
Underlying bug is though in the C++ demangler part of libiberty, but MITRE
has assigned it specifically to the issue as raised within binutils.
binutils not covered by security support

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 12" src="https://img.shields.io/badge/L-12-fce1a9"/> <!-- unspecified: 0 --><strong>openjpeg2</strong> <code>2.5.0-2+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/openjpeg2@2.5.0-2%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-20846?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2018--20846" src="https://img.shields.io/badge/CVE--2018--20846-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.313%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>54th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Out-of-bounds accesses in the functions pi_next_lrcp, pi_next_rlcp, pi_next_rpcl, pi_next_pcrl, pi_next_rpcl, and pi_next_cprl in openmj2/pi.c in OpenJPEG through 2.3.0 allow remote attackers to cause a denial of service (application crash).

---
- openjpeg2 <unfixed> (unimportant)
https://github.com/uclouvain/openjpeg/commit/c277159986c80142180fbe5efb256bbf3bdf3edc
Debian binary packages built with BUILD_MJ2:BOOL=OFF

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-16376?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2018--16376" src="https://img.shields.io/badge/CVE--2018--16376-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>3.078%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>86th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in OpenJPEG 2.3.0. A heap-based buffer overflow was discovered in the function t2_encode_packet in lib/openmj2/t2.c. The vulnerability causes an out-of-bounds write, which may lead to remote denial of service or possibly unspecified other impact.

---
- openjpeg2 <unfixed> (unimportant)
https://github.com/uclouvain/openjpeg/issues/1127
We build with -DBUILD_MJ2:BOOL=OFF

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-16375?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2018--16375" src="https://img.shields.io/badge/CVE--2018--16375-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.235%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>46th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in OpenJPEG 2.3.0. Missing checks for header_info.height and header_info.width in the function pnmtoimage in bin/jpwl/convert.c can lead to a heap-based buffer overflow.

---
- openjpeg2 <unfixed> (unimportant)
https://github.com/uclouvain/openjpeg/issues/1126
We build with -DBUILD_JPWL:BOOL=OFF

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-17479?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2017--17479" src="https://img.shields.io/badge/CVE--2017--17479-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>5.385%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In OpenJPEG 2.3.0, a stack-based buffer overflow was discovered in the pgxtoimage function in jpwl/convert.c. The vulnerability causes an out-of-bounds write, which may lead to remote denial of service or possibly remote code execution.

---
- openjpeg2 <unfixed> (unimportant)
https://github.com/uclouvain/openjpeg/issues/1044
Debian packaging does not build JPWL, has BUILD_JPWL:BOOL=OFF

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9581?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2016--9581" src="https://img.shields.io/badge/CVE--2016--9581-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.435%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>62nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An infinite loop vulnerability in tiftoimage that results in heap buffer overflow in convert_32s_C1P1 was found in openjpeg 2.1.2.

---
- openjpeg2 <unfixed> (unimportant)
https://github.com/uclouvain/openjpeg/issues/872
Fixed by: https://github.com/szukw000/openjpeg/commit/cadff5fb6e73398de26a92e96d3d7cac893af255
not built into the binary packages

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9580?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2016--9580" src="https://img.shields.io/badge/CVE--2016--9580-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.360%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>57th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An integer overflow vulnerability was found in tiftoimage function in openjpeg 2.1.2, resulting in heap buffer overflow.

---
- openjpeg2 <unfixed> (unimportant)
https://github.com/uclouvain/openjpeg/issues/871
Fixed by: https://github.com/szukw000/openjpeg/commit/cadff5fb6e73398de26a92e96d3d7cac893af255
not built into the binary packages

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9117?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2016--9117" src="https://img.shields.io/badge/CVE--2016--9117-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.357%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>57th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

NULL Pointer Access in function imagetopnm of convert.c(jp2):1289 in OpenJPEG 2.1.2. Impact is Denial of Service. Someone must open a crafted j2k file.

---
- openjpeg2 <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=844556)
https://github.com/uclouvain/openjpeg/issues/860
No code injection, function only exposed in the CLI tool

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9116?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2016--9116" src="https://img.shields.io/badge/CVE--2016--9116-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.357%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>57th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

NULL Pointer Access in function imagetopnm of convert.c:2226(jp2) in OpenJPEG 2.1.2. Impact is Denial of Service. Someone must open a crafted j2k file.

---
- openjpeg2 <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=844555)
https://github.com/uclouvain/openjpeg/issues/859
No code injection, function only exposed in the CLI tool

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9115?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2016--9115" src="https://img.shields.io/badge/CVE--2016--9115-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.374%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>58th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap Buffer Over-read in function imagetotga of convert.c(jp2):942 in OpenJPEG 2.1.2. Impact is Denial of Service. Someone must open a crafted j2k file.

---
- openjpeg2 <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=844554)
https://github.com/uclouvain/openjpeg/issues/858
No code injection, function only exposed in the CLI tool

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9114?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2016--9114" src="https://img.shields.io/badge/CVE--2016--9114-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.607%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>68th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

There is a NULL Pointer Access in function imagetopnm of convert.c:1943(jp2) of OpenJPEG 2.1.2. image->comps[compno].data is not assigned a value after initialization(NULL). Impact is Denial of Service.

---
- openjpeg2 <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=844553)
https://github.com/uclouvain/openjpeg/issues/857
No code injection, function only exposed in the CLI tool

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9113?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2016--9113" src="https://img.shields.io/badge/CVE--2016--9113-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.478%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>64th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

There is a NULL pointer dereference in function imagetobmp of convertbmp.c:980 of OpenJPEG 2.1.2. image->comps[0].data is not assigned a value after initialization(NULL). Impact is Denial of Service.

---
- openjpeg2 <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=844552)
https://github.com/uclouvain/openjpeg/issues/856
No code injection, function only exposed in the CLI tool

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-10505?s=debian&n=openjpeg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-2%2Bdeb12u1"><img alt="low : CVE--2016--10505" src="https://img.shields.io/badge/CVE--2016--10505-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.454%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>63rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

NULL pointer dereference vulnerabilities in the imagetopnm function in convert.c, sycc444_to_rgb function in color.c, color_esycc_to_rgb function in color.c, and sycc422_to_rgb function in color.c in OpenJPEG before 2.2.0 allow remote attackers to cause a denial of service (application crash) via crafted j2k files.

---
- openjpeg2 <unfixed> (unimportant)
https://github.com/uclouvain/openjpeg/issues/776
https://github.com/uclouvain/openjpeg/issues/784
https://github.com/uclouvain/openjpeg/issues/785
https://github.com/uclouvain/openjpeg/issues/792

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 10" src="https://img.shields.io/badge/L-10-fce1a9"/> <img alt="unspecified: 2" src="https://img.shields.io/badge/U-2-lightgrey"/><strong>tiff</strong> <code>4.5.0-6+deb12u2</code> (deb)</summary>

<small><code>pkg:deb/debian/tiff@4.5.0-6%2Bdeb12u2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-6716?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u1"><img alt="low : CVE--2024--6716" src="https://img.shields.io/badge/CVE--2024--6716-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

REJECTED

---
REJECTED

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6228?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2023--6228" src="https://img.shields.io/badge/CVE--2023--6228-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.015%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was found in the tiffcp utility distributed by the libtiff package where a crafted TIFF file on processing may cause a heap-based buffer overflow leads to an application crash.

---
- tiff <unfixed> (unimportant)
https://gitlab.com/libtiff/libtiff/-/issues/606
Fixed by: https://gitlab.com/libtiff/libtiff/-/commit/1e7d217a323eac701b134afc4ae39b6bdfdbc96a
Crash in CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-3164?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2023--3164" src="https://img.shields.io/badge/CVE--2023--3164-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.010%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-buffer-overflow vulnerability was found in LibTIFF, in extractImageSection() at tools/tiffcrop.c:7916 and tools/tiffcrop.c:7801. This flaw allows attackers to cause a denial of service via a crafted tiff file.

---
- tiff <unfixed> (unimportant)
https://gitlab.com/libtiff/libtiff/-/issues/542
Crash in CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-1916?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2023--1916" src="https://img.shields.io/badge/CVE--2023--1916-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in tiffcrop, a program distributed by the libtiff package. A specially crafted tiff file can lead to an out-of-bounds read in the extractImageSection function in tools/tiffcrop.c, resulting in a denial of service and limited information disclosure. This issue affects libtiff versions 4.x.

---
- tiff <unfixed> (unimportant)
https://gitlab.com/libtiff/libtiff/-/issues/536
https://gitlab.com/libtiff/libtiff/-/issues/537
Crash in CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-1210?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2022--1210" src="https://img.shields.io/badge/CVE--2022--1210-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability classified as problematic was found in LibTIFF 4.3.0. Affected by this vulnerability is the TIFF File Handler of tiff2ps. Opening a malicious file leads to a denial of service. The attack can be launched remotely but requires user interaction. The exploit has been disclosed to the public and may be used.

---
- tiff <unfixed> (unimportant)
[bullseye] - tiff <no-dsa> (Minor issue)
[buster] - tiff <no-dsa> (Minor issue)
https://gitlab.com/libtiff/libtiff/-/issues/402
Crash in CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-10126?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2018--10126" src="https://img.shields.io/badge/CVE--2018--10126-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.185%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>41st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ijg-libjpeg before 9d, as used in tiff2pdf (from LibTIFF) and other products, does not check for a NULL pointer at a certain place in jpeg_fdct_16x16 in jfdctint.c.

---
- tiff <unfixed> (unimportant)
http://bugzilla.maptools.org/show_bug.cgi?id=2786
Crash in CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-9117?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2017--9117" src="https://img.shields.io/badge/CVE--2017--9117-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.072%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In LibTIFF 4.0.6 and possibly other versions, the program processes BMP images without verifying that biWidth and biHeight in the bitmap-information header match the actual input, as demonstrated by a heap-based buffer over-read in bmp2tiff. NOTE: mentioning bmp2tiff does not imply that the activation point is in the bmp2tiff.c file (which was removed before the 4.0.7 release).

---
- tiff <unfixed> (unimportant)
- tiff3 <not-affected> (Does not ship libtiff-tools)
http://bugzilla.maptools.org/show_bug.cgi?id=2690
bmp2tiff utility removed in 4.0.6-3 and 4.0.3-12.3+deb8u2

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-5563?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2017--5563" src="https://img.shields.io/badge/CVE--2017--5563-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.457%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>63rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

LibTIFF version 4.0.7 is vulnerable to a heap-based buffer over-read in tif_lzw.c resulting in DoS or code execution via a crafted bmp image to tools/bmp2tiff.

---
- tiff <unfixed> (unimportant)
http://bugzilla.maptools.org/show_bug.cgi?id=2664
bmp2tiff utility removed in 4.0.6-3 and 4.0.3-12.3+deb8u2

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-17973?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2017--17973" src="https://img.shields.io/badge/CVE--2017--17973-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.614%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>69th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In LibTIFF 4.0.8, there is a heap-based use-after-free in the t2p_writeproc function in tiff2pdf.c. NOTE: there is a third-party report of inability to reproduce this issue

---
- tiff <unfixed> (unimportant)
- tiff3 <removed> (unimportant)
http://bugzilla.maptools.org/show_bug.cgi?id=2769
Details on the issue are not confirmed by the reporter after several attempts
and this does like a non-issue. More reprodicibly reports are from SUSE in
https://bugzilla.suse.com/show_bug.cgi?id=1074318#c5 claiming this might be
a duplicate of CVE-2017-9935. Unless the reporter provides more details on
upstream report go and consider this as non-issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-16232?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6%2Bdeb12u2"><img alt="low : CVE--2017--16232" src="https://img.shields.io/badge/CVE--2017--16232-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>2.211%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>84th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

LibTIFF 4.0.8 has multiple memory leak vulnerabilities, which allow attackers to cause a denial of service (memory consumption), as demonstrated by tif_open.c, tif_lzw.c, and tif_aux.c. NOTE: Third parties were unable to reproduce the issue

---
- tiff <unfixed> (unimportant)
http://seclists.org/oss-sec/2017/q4/168
Related commit: https://gitlab.com/libtiff/libtiff/commit/25f9ffa56548c1846c4a1f19308b7f561f7b1ab0
This is actually only a partial fix, but upstream will not fix it completely.
The related commit is included in 4.0.9. The underlying memory-based DOS
would still be present.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38289?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6"><img alt="unspecified : CVE--2023--38289" src="https://img.shields.io/badge/CVE--2023--38289-lightgrey?label=unspecified%20&labelColor=lightgrey"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

REJECTED

---
REJECTED

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38288?s=debian&n=tiff&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D4.5.0-6"><img alt="unspecified : CVE--2023--38288" src="https://img.shields.io/badge/CVE--2023--38288-lightgrey?label=unspecified%20&labelColor=lightgrey"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=4.5.0-6</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

REJECTED

---
REJECTED

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 10" src="https://img.shields.io/badge/L-10-fce1a9"/> <!-- unspecified: 0 --><strong>bluez</strong> <code>5.66-1+deb12u2</code> (deb)</summary>

<small><code>pkg:deb/debian/bluez@5.66-1%2Bdeb12u2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2016-9918?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9918" src="https://img.shields.io/badge/CVE--2016--9918-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.489%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>64th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, an out-of-bounds read was identified in "packet_hexdump" function in "monitor/packet.c" source file. This issue can be triggered by processing a corrupted dump file and will result in btmon crash.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68898.html
Crash in btmon CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9917?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9917" src="https://img.shields.io/badge/CVE--2016--9917-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>1.124%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>77th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, a buffer overflow was observed in "read_n" function in "tools/hcidump.c" source file. This issue can be triggered by processing a corrupted dump file and will result in hcidump crash.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68892.html
Crash in hcidump CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9804?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9804" src="https://img.shields.io/badge/CVE--2016--9804-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.826%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>73rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, a buffer overflow was observed in "commands_dump" function in "tools/parser/csr.c" source file. The issue exists because "commands" array is overflowed by supplied parameter due to lack of boundary checks on size of the buffer from frame "frm->ptr" parameter. This issue can be triggered by processing a corrupted dump file and will result in hcidump crash.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68892.html
Crash in hcidump CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9803?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9803" src="https://img.shields.io/badge/CVE--2016--9803-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.146%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, an out-of-bounds read was observed in "le_meta_ev_dump" function in "tools/parser/hci.c" source file. This issue exists because 'subevent' (which is used to read correct element from 'ev_le_meta_str' array) is overflowed.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68892.html
Crash in CLI tools, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9802?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9802" src="https://img.shields.io/badge/CVE--2016--9802-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.950%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>75th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, a buffer over-read was identified in "l2cap_packet" function in "monitor/packet.c" source file. This issue can be triggered by processing a corrupted dump file and will result in btmon crash.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68898.html
Crash in btmon CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9801?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9801" src="https://img.shields.io/badge/CVE--2016--9801-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.222%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, a buffer overflow was observed in "set_ext_ctrl" function in "tools/parser/l2cap.c" source file when processing corrupted dump file.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68892.html
Crash in CLI tools, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9800?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9800" src="https://img.shields.io/badge/CVE--2016--9800-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.510%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>65th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, a buffer overflow was observed in "pin_code_reply_dump" function in "tools/parser/hci.c" source file. The issue exists because "pin" array is overflowed by supplied parameter due to lack of boundary checks on size of the buffer from frame "pin_code_reply_cp *cp" parameter.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68892.html
Crash in CLI tools, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9799?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9799" src="https://img.shields.io/badge/CVE--2016--9799-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.881%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>74th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, a buffer overflow was observed in "pklg_read_hci" function in "btsnoop.c" source file. This issue can be triggered by processing a corrupted dump file and will result in btmon crash.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68898.html
Crash in btmon CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9798?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9798" src="https://img.shields.io/badge/CVE--2016--9798-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.567%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>67th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, a use-after-free was identified in "conf_opt" function in "tools/parser/l2cap.c" source file. This issue can be triggered by processing a corrupted dump file and will result in hcidump crash.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68892.html
Crash in hcidump CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-9797?s=debian&n=bluez&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.66-1%2Bdeb12u2"><img alt="low : CVE--2016--9797" src="https://img.shields.io/badge/CVE--2016--9797-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.66-1+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.275%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>51st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In BlueZ 5.42, a buffer over-read was observed in "l2cap_dump" function in "tools/parser/l2cap.c" source file. This issue can be triggered by processing a corrupted dump file and will result in hcidump crash.

---
- bluez <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=847837)
https://www.spinics.net/lists/linux-bluetooth/msg68892.html
Crash in hcidump CLI tool, no security impact

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 9" src="https://img.shields.io/badge/L-9-fce1a9"/> <!-- unspecified: 0 --><strong>openssh</strong> <code>1:9.2p1-2+deb12u5</code> (deb)</summary>

<small><code>pkg:deb/debian/openssh@1%3A9.2p1-2%2Bdeb12u5?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-51767?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2023--51767" src="https://img.shields.io/badge/CVE--2023--51767-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.006%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

OpenSSH through 9.6, when common types of DRAM are used, might allow row hammer attacks (for authentication bypass) because the integer value of authenticated in mm_answer_authpassword does not resist flips of a single bit. NOTE: this is applicable to a certain threat model of attacker-victim co-location in which the attacker has user privileges.

---
- openssh <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1059393; unimportant)
https://arxiv.org/abs/2309.02545
Upstream does not consider CVE-2023-51767 a bug underlying in OpenSSH and
does not intent to address it in OpenSSH. To todays knowledge (2024-03-13)
it has not been demonstrated that the issue is exploitable in any real
software configuration.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-15778?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2020--15778" src="https://img.shields.io/badge/CVE--2020--15778-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>66.112%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

scp in OpenSSH through 8.3p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. NOTE: the vendor reportedly has stated that they intentionally omit validation of "anomalous argument transfers" because that could "stand a great chance of breaking existing workflows."

---
- openssh <unfixed> (unimportant)
https://bugzilla.redhat.com/show_bug.cgi?id=1860487
https://github.com/cpandya2909/CVE-2020-15778
Negligible security impact, changing the scp protocol can have a good chance
of breaking existing workflows.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-14145?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2020--14145" src="https://img.shields.io/badge/CVE--2020--14145-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>1.254%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>78th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client). NOTE: some reports state that 8.5 and 8.6 are also affected.

---
- openssh <unfixed> (unimportant)
https://www.fzi.de/en/news/news/detail-en/artikel/fsa-2020-2-ausnutzung-eines-informationslecks-fuer-gezielte-mitm-angriffe-auf-ssh-clients/
https://www.fzi.de/fileadmin/user_upload/2020-06-26-FSA-2020-2.pdf
The OpenSSH project is not planning to change the behaviour of OpenSSH regarding
the issue, details in "3.1 OpenSSH" in the publication.
Partial mitigation: https://anongit.mindrot.org/openssh.git/commit/?id=b3855ff053f5078ec3d3c653cdaedefaa5fc362d (V_8_4_P1)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-6110?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2019--6110" src="https://img.shields.io/badge/CVE--2019--6110-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>54.872%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In OpenSSH 7.9, due to accepting and displaying arbitrary stderr output from the server, a malicious server (or Man-in-The-Middle attacker) can manipulate the client output, for example to use ANSI control codes to hide additional files being transferred.

---
- openssh <unfixed> (unimportant)
https://sintonen.fi/advisories/scp-client-multiple-vulnerabilities.txt
Not considered a vulnerability by upstream, cf.
https://lists.mindrot.org/pipermail/openssh-unix-dev/2019-January/037475.html

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-15919?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2018--15919" src="https://img.shields.io/badge/CVE--2018--15919-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>1.698%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>81st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Remotely observable behaviour in auth-gss2.c in OpenSSH through 7.8 could be used by remote attackers to detect existence of users on a target system when GSS2 is in use. NOTE: the discoverer states 'We understand that the OpenSSH developers do not want to treat such a username enumeration (or "oracle") as a vulnerability.'

---
- openssh <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=907503)
https://www.openwall.com/lists/oss-security/2018/08/27/2
Not treated as a security issue by upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-20012?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2016--20012" src="https://img.shields.io/badge/CVE--2016--20012-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>16.885%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>95th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

OpenSSH through 8.7 allows remote attackers, who have a suspicion that a certain combination of username and public key is known to an SSH server, to test whether this suspicion is correct. This occurs because a challenge is sent only when that combination could be valid for a login session. NOTE: the vendor does not recognize user enumeration as a vulnerability for this product

---
- openssh <unfixed> (unimportant)
https://github.com/openssh/openssh-portable/pull/270
Negligible impact, not treated as a security issue by upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2008-3234?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2008--3234" src="https://img.shields.io/badge/CVE--2008--3234-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>2.263%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>84th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

sshd in OpenSSH 4 on Debian GNU/Linux, and the 20070303 OpenSSH snapshot, allows remote authenticated users to obtain access to arbitrary SELinux roles by appending a :/ (colon slash) sequence, followed by the role name, to the username.

---
- openssh <unfixed> (unimportant)
this is by design

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2007-2768?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2007--2768" src="https://img.shields.io/badge/CVE--2007--2768-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.247%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>48th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

OpenSSH, when using OPIE (One-Time Passwords in Everything) for PAM, allows remote attackers to determine the existence of certain user accounts, which displays a different response if the user account exists and is configured to use one-time passwords (OTP), a similar issue to CVE-2007-2243.

---
- openssh <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=436571; unimportant)
[etch] - openssh <no-dsa> (Minor issue)
[sarge] - openssh <no-dsa> (Minor issue)
http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=112279

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2007-2243?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A9.2p1-2%2Bdeb12u5"><img alt="low : CVE--2007--2243" src="https://img.shields.io/badge/CVE--2007--2243-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:9.2p1-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.521%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>66th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

OpenSSH 4.6 and earlier, when ChallengeResponseAuthentication is enabled, allows remote attackers to determine the existence of user accounts by attempting to authenticate via S/KEY, which displays a different response if the user account exists, a similar issue to CVE-2001-1483.

---
- openssh <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=436571; unimportant)
[etch] - openssh <no-dsa> (Minor issue)
[sarge] - openssh <no-dsa> (Minor issue)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 9" src="https://img.shields.io/badge/L-9-fce1a9"/> <!-- unspecified: 0 --><strong>imagemagick</strong> <code>8:6.9.11.60+dfsg-1.6+deb12u2</code> (deb)</summary>

<small><code>pkg:deb/debian/imagemagick@8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-34152?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2023--34152" src="https://img.shields.io/badge/CVE--2023--34152-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>70.587%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in ImageMagick. This security flaw cause a remote code execution vulnerability in OpenBlob with --enable-pipes configured.

---
- imagemagick <unfixed> (unimportant)
https://github.com/ImageMagick/ImageMagick/issues/6339
Only an issue when configured with --enable-pipes. Enabling pipes are
a security risk per se and user needs to take precautions accordingly
when enabled.
https://github.com/ImageMagick/ImageMagick/issues/6339#issuecomment-1559698800
CVE might get rejected or disputed

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-20311?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2021--20311" src="https://img.shields.io/badge/CVE--2021--20311-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.099%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>29th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in ImageMagick in versions before 7.0.11, where a division by zero in sRGBTransformImage() in the MagickCore/colorspace.c may trigger undefined behavior via a crafted image file that is submitted by an attacker processed by an application using ImageMagick. The highest threat from this vulnerability is to system availability.

---
- imagemagick <unfixed> (unimportant)
https://github.com/ImageMagick/ImageMagick/commit/70aa86f5d5d8aa605a918ed51f7574f433a18482

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-15607?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2018--15607" src="https://img.shields.io/badge/CVE--2018--15607-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.518%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>65th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In ImageMagick 7.0.8-11 Q16, a tiny input file 0x50 0x36 0x36 0x36 0x36 0x4c 0x36 0x38 0x36 0x36 0x36 0x36 0x36 0x36 0x1f 0x35 0x50 0x00 can result in a hang of several minutes during which CPU and memory resources are consumed until ultimately an attempted large memory allocation fails. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted file.

---
- imagemagick <unfixed> (unimportant)
https://github.com/ImageMagick/ImageMagick/issues/1255
This is mitigated by the default policies, if anyone modifies those they need
be tuned to the deployment's memory buildout

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-7275?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2017--7275" src="https://img.shields.io/badge/CVE--2017--7275-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.187%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>41st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The ReadPCXImage function in coders/pcx.c in ImageMagick 7.0.4.9 allows remote attackers to cause a denial of service (attempted large memory allocation and application crash) via a crafted file. NOTE: this vulnerability exists because of an incomplete fix for CVE-2016-8862 and CVE-2016-8866.

---
- imagemagick <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=859025)
https://blogs.gentoo.org/ago/2017/03/27/imagemagick-memory-allocation-failure-in-acquiremagickmemory-memory-c-incomplete-fix-for-cve-2016-8862-and-cve-2016-8866/
https://github.com/ImageMagick/ImageMagick/issues/271
Furthermore: upstream is not able to reproduce the problem as well
The problem result in a memory allocation issue when compiled with ASAN
but unreproducible from unstream. Since no more details can be provided
and the issue not addressed, treat this as "non-issue" (and thus marked
unimportant). If in future details can be elaborated by the reporter
we might re-evaluate this entry.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-11755?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2017--11755" src="https://img.shields.io/badge/CVE--2017--11755-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.281%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>51st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The WritePICONImage function in coders/xpm.c in ImageMagick 7.0.6-4 allows remote attackers to cause a denial of service (memory leak) via a crafted file that is mishandled in an AcquireSemaphoreInfo call.

---
- imagemagick <unfixed> (unimportant)
https://github.com/ImageMagick/ImageMagick/issues/634
Possibly fixed by same commit as issue #631 upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-11754?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2017--11754" src="https://img.shields.io/badge/CVE--2017--11754-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.281%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>51st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The WritePICONImage function in coders/xpm.c in ImageMagick 7.0.6-4 allows remote attackers to cause a denial of service (memory leak) via a crafted file that is mishandled in an OpenPixelCache call.

---
- imagemagick <unfixed> (unimportant)
https://github.com/ImageMagick/ImageMagick/issues/633
ossibly fixed by same commit as issue #631 upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-8678?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2016--8678" src="https://img.shields.io/badge/CVE--2016--8678-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.212%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>44th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The IsPixelMonochrome function in MagickCore/pixel-accessor.h in ImageMagick 7.0.3.0 allows remote attackers to cause a denial of service (out-of-bounds read and crash) via a crafted file.  NOTE: the vendor says "This is a Q64 issue and we do not support Q64."

---
- imagemagick <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=845204)
https://blogs.gentoo.org/ago/2016/10/07/imagemagick-heap-based-buffer-overflow-in-ispixelmonochrome-pixel-accessor-h/
unimportant: Only an issue with a QuantumDepth=64 build, thus not affecting the binary packages
https://github.com/ImageMagick/ImageMagick/issues/272

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2008-3134?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2008--3134" src="https://img.shields.io/badge/CVE--2008--3134-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>1.621%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>81st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Multiple unspecified vulnerabilities in GraphicsMagick before 1.2.4 allow remote attackers to cause a denial of service (crash, infinite loop, or memory consumption) via (a) unspecified vectors in the (1) AVI, (2) AVS, (3) DCM, (4) EPT, (5) FITS, (6) MTV, (7) PALM, (8) RLA, and (9) TGA decoder readers; and (b) the GetImageCharacteristics function in magick/image.c, as reachable from a crafted (10) PNG, (11) JPEG, (12) BMP, or (13) TIFF file.

---
- graphicsmagick 1.2.4-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=491439)
- imagemagick <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=559775)
several DoS fixed in 1.2.4 according to upstream
http://sourceforge.net/project/shownotes.php?release_id=610253

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2005-0406?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2"><img alt="low : CVE--2005--0406" src="https://img.shields.io/badge/CVE--2005--0406-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8:6.9.11.60+dfsg-1.6+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.122%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A design flaw in image processing software that modifies JPEG images might not modify the original EXIF thumbnail, which could lead to an information leak of potentially sensitive visual information that had been removed from the main JPEG image.

---
- imagemagick <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=298051; unimportant)
<Maulkin> The EXIF spec says "if your app can't handle $foo, don't touch $foo"
<Piet> 'convert -strip' will remove exif data according to http://web.archive.org/web/20130922031724/http://www.imagemagick.org:80/pipermail/magick-users/2006-May/017538.html

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 7" src="https://img.shields.io/badge/L-7-fce1a9"/> <!-- unspecified: 0 --><strong>elfutils</strong> <code>0.188-2.1</code> (deb)</summary>

<small><code>pkg:deb/debian/elfutils@0.188-2.1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-1377?s=debian&n=elfutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.188-2.1"><img alt="low : CVE--2025--1377" src="https://img.shields.io/badge/CVE--2025--1377-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.188-2.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability, which was classified as problematic, has been found in GNU elfutils 0.192. This issue affects the function gelf_getsymshndx of the file strip.c of the component eu-strip. The manipulation leads to denial of service. The attack needs to be approached locally. The exploit has been disclosed to the public and may be used. The identifier of the patch is fbf1df9ca286de3323ae541973b08449f8d03aba. It is recommended to apply a patch to fix this issue.

---
- elfutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32673
https://sourceware.org/git/?p=elfutils.git;a=fbf1df9ca286de3323ae541973b08449f8d03aba
Crash in CLI tool, considered only to be a normal bug by upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1376?s=debian&n=elfutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.188-2.1"><img alt="low : CVE--2025--1376" src="https://img.shields.io/badge/CVE--2025--1376-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.188-2.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability classified as problematic was found in GNU elfutils 0.192. This vulnerability affects the function elf_strptr in the library /libelf/elf_strptr.c of the component eu-strip. The manipulation leads to denial of service. It is possible to launch the attack on the local host. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The name of the patch is b16f441cca0a4841050e3215a9f120a6d8aea918. It is recommended to apply a patch to fix this issue.

---
- elfutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32672
https://sourceware.org/git/?p=elfutils.git;a=commit;h=b16f441cca0a4841050e3215a9f120a6d8aea918
Crash in CLI tool, considered only to be a normal bug by upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1372?s=debian&n=elfutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.188-2.1"><img alt="low : CVE--2025--1372" src="https://img.shields.io/badge/CVE--2025--1372-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.188-2.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in GNU elfutils 0.192. It has been declared as critical. Affected by this vulnerability is the function dump_data_section/print_string_section of the file readelf.c of the component eu-readelf. The manipulation of the argument z/x leads to buffer overflow. An attack has to be approached locally. The exploit has been disclosed to the public and may be used. The identifier of the patch is 73db9d2021cab9e23fd734b0a76a612d52a6f1db. It is recommended to apply a patch to fix this issue.

---
- elfutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32656
https://sourceware.org/bugzilla/show_bug.cgi?id=32657
https://sourceware.org/git/?p=elfutils.git;a=commit;h=73db9d2021cab9e23fd734b0a76a612d52a6f1db
Crash in CLI tool, considered only to be a normal bug by upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1371?s=debian&n=elfutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.188-2.1"><img alt="low : CVE--2025--1371" src="https://img.shields.io/badge/CVE--2025--1371-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.188-2.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability has been found in GNU elfutils 0.192 and classified as problematic. This vulnerability affects the function handle_dynamic_symtab of the file readelf.c of the component eu-read. The manipulation leads to null pointer dereference. Attacking locally is a requirement. The exploit has been disclosed to the public and may be used. The patch is identified as b38e562a4c907e08171c76b8b2def8464d5a104a. It is recommended to apply a patch to fix this issue.

---
- elfutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32655
https://sourceware.org/git/?p=elfutils.git;a=commit;h=b38e562a4c907e08171c76b8b2def8464d5a104a
Crash in CLI tool, considered only to be a normal bug by upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1365?s=debian&n=elfutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.188-2.1"><img alt="low : CVE--2025--1365" src="https://img.shields.io/badge/CVE--2025--1365-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.188-2.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability, which was classified as critical, was found in GNU elfutils 0.192. This affects the function process_symtab of the file readelf.c of the component eu-readelf. The manipulation of the argument D/a leads to buffer overflow. Local access is required to approach this attack. The exploit has been disclosed to the public and may be used. The identifier of the patch is 5e5c0394d82c53e97750fe7b18023e6f84157b81. It is recommended to apply a patch to fix this issue.

---
- elfutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32654
https://sourceware.org/git/?p=elfutils.git;a=commit;h=5e5c0394d82c53e97750fe7b18023e6f84157b81
Crash in CLI tool, considered only to be a normal bug by upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1352?s=debian&n=elfutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.188-2.1"><img alt="low : CVE--2025--1352" src="https://img.shields.io/badge/CVE--2025--1352-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.188-2.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.086%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability has been found in GNU elfutils 0.192 and classified as critical. This vulnerability affects the function __libdw_thread_tail in the library libdw_alloc.c of the component eu-readelf. The manipulation of the argument w leads to memory corruption. The attack can be initiated remotely. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The name of the patch is 2636426a091bd6c6f7f02e49ab20d4cdc6bfc753. It is recommended to apply a patch to fix this issue.

---
- elfutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=32650
Fixed by: https://sourceware.org/git/?p=elfutils.git;a=2636426a091bd6c6f7f02e49ab20d4cdc6bfc753
Crash in CLI tool, considered only to be a normal bug by upstream

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-25260?s=debian&n=elfutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.188-2.1"><img alt="low : CVE--2024--25260" src="https://img.shields.io/badge/CVE--2024--25260-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.188-2.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

elfutils v0.189 was discovered to contain a NULL pointer dereference via the handle_verdef() function at readelf.c.

---
- elfutils <unfixed> (unimportant)
https://sourceware.org/bugzilla/show_bug.cgi?id=31058
https://sourceware.org/git/?p=elfutils.git;a=commit;h=373f5212677235fc3ca6068b887111554790f944
Crash in CLI tool, considered only to be a normal bug by upstream

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 4" src="https://img.shields.io/badge/L-4-fce1a9"/> <!-- unspecified: 0 --><strong>patch</strong> <code>2.7.6-7</code> (deb)</summary>

<small><code>pkg:deb/debian/patch@2.7.6-7?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-45261?s=debian&n=patch&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.7.6-7"><img alt="low : CVE--2021--45261" src="https://img.shields.io/badge/CVE--2021--45261-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.7.6-7</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.087%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An Invalid Pointer vulnerability exists in GNU patch 2.7 via the another_hunk function, which causes a Denial of Service.

---
- patch <unfixed> (unimportant)
https://savannah.gnu.org/bugs/?61685
Negligible security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-6952?s=debian&n=patch&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.7.6-7"><img alt="low : CVE--2018--6952" src="https://img.shields.io/badge/CVE--2018--6952-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.7.6-7</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>11.377%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A double free exists in the another_hunk function in pch.c in GNU patch through 2.7.6.

---
- patch <unfixed> (unimportant)
https://savannah.gnu.org/bugs/index.php?53133
https://git.savannah.gnu.org/cgit/patch.git/commit/?id=9c986353e420ead6e706262bf204d6e03322c300
When fixing this issue make sure to not apply only the incomplete fix,
and opening CVE-2019-20633, cf. https://savannah.gnu.org/bugs/index.php?56683
Crash in CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-6951?s=debian&n=patch&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.7.6-7"><img alt="low : CVE--2018--6951" src="https://img.shields.io/badge/CVE--2018--6951-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.7.6-7</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>23.554%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>96th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in GNU patch through 2.7.6. There is a segmentation fault, associated with a NULL pointer dereference, leading to a denial of service in the intuit_diff_type function in pch.c, aka a "mangled rename" issue.

---
- patch <unfixed> (unimportant)
https://git.savannah.gnu.org/cgit/patch.git/commit/?id=f290f48a621867084884bfff87f8093c15195e6a
https://savannah.gnu.org/bugs/index.php?53132
Crash in CLI tool, no security impact

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2010-4651?s=debian&n=patch&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.7.6-7"><img alt="low : CVE--2010--4651" src="https://img.shields.io/badge/CVE--2010--4651-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.7.6-7</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.912%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>75th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Directory traversal vulnerability in util.c in GNU patch 2.6.1 and earlier allows user-assisted remote attackers to create or overwrite arbitrary files via a filename that is specified with a .. (dot dot) or full pathname, a related issue to CVE-2010-1679.

---
- patch <unfixed> (unimportant)
Applying a patch blindly opens more severe security issues than only directory traversal...
openwall ships a fix
See https://bugzilla.redhat.com/show_bug.cgi?id=667529 for details

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 4" src="https://img.shields.io/badge/L-4-fce1a9"/> <!-- unspecified: 0 --><strong>openldap</strong> <code>2.5.13+dfsg-5</code> (deb)</summary>

<small><code>pkg:deb/debian/openldap@2.5.13%2Bdfsg-5?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2020-15719?s=debian&n=openldap&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.13%2Bdfsg-5"><img alt="low : CVE--2020--15719" src="https://img.shields.io/badge/CVE--2020--15719-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.13+dfsg-5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.414%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>60th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libldap in certain third-party OpenLDAP packages has a certificate-validation flaw when the third-party package is asserting RFC6125 support. It considers CN even when there is a non-matching subjectAltName (SAN). This is fixed in, for example, openldap-2.4.46-10.el8 in Red Hat Enterprise Linux.

---
- openldap <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=965184)
https://bugs.openldap.org/show_bug.cgi?id=9266
https://bugzilla.redhat.com/show_bug.cgi?id=1740070
RedHat/CentOS applied patch: https://git.centos.org/rpms/openldap/raw/67459960064be9d226d57c5f82aaba0929876813/f/SOURCES/openldap-tlso-dont-check-cn-when-bad-san.patch
OpenLDAP upstream did dispute the issue as beeing valid, as the current libldap
behaviour does conform with RFC4513. RFC6125 does not superseed the rules for
verifying service identity provided in specifications for existing application
protocols published prior to RFC6125, like RFC4513 for LDAP.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-17740?s=debian&n=openldap&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.13%2Bdfsg-5"><img alt="low : CVE--2017--17740" src="https://img.shields.io/badge/CVE--2017--17740-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.13+dfsg-5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>5.322%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

contrib/slapd-modules/nops/nops.c in OpenLDAP through 2.4.45, when both the nops module and the memberof overlay are enabled, attempts to free a buffer that was allocated on the stack, which allows remote attackers to cause a denial of service (slapd crash) via a member MODDN operation.

---
- openldap <unfixed> (unimportant)
http://www.openldap.org/its/index.cgi/Incoming?id=8759
nops slapd-module not built

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-14159?s=debian&n=openldap&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.13%2Bdfsg-5"><img alt="low : CVE--2017--14159" src="https://img.shields.io/badge/CVE--2017--14159-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.13+dfsg-5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.077%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

slapd in OpenLDAP 2.4.45 and earlier creates a PID file after dropping privileges to a non-root account, which might allow local users to kill arbitrary processes by leveraging access to this non-root account for PID file modification before a root script executes a "kill `cat /pathname`" command, as demonstrated by openldap-initscript.

---
- openldap <unfixed> (unimportant)
http://www.openldap.org/its/index.cgi?findid=8703
Negligible security impact, but filed #877512

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2015-3276?s=debian&n=openldap&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.13%2Bdfsg-5"><img alt="low : CVE--2015--3276" src="https://img.shields.io/badge/CVE--2015--3276-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.13+dfsg-5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>2.147%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The nss_parse_ciphers function in libraries/libldap/tls_m.c in OpenLDAP does not properly parse OpenSSL-style multi-keyword mode cipher strings, which might cause a weaker than intended cipher to be used and allow remote attackers to have unspecified impact via unknown vectors.

---
- openldap <unfixed> (unimportant)
Debian builds with GNUTLS, not NSS

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 3" src="https://img.shields.io/badge/L-3-fce1a9"/> <!-- unspecified: 0 --><strong>git</strong> <code>1:2.39.5-0+deb12u2</code> (deb)</summary>

<small><code>pkg:deb/debian/git@1%3A2.39.5-0%2Bdeb12u2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-52005?s=debian&n=git&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A2.39.5-0%2Bdeb12u2"><img alt="low : CVE--2024--52005" src="https://img.shields.io/badge/CVE--2024--52005-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:2.39.5-0+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Git is a source code management tool. When cloning from a server (or fetching, or pushing), informational or error messages are transported from the remote Git process to the client via the so-called "sideband channel". These messages will be prefixed with "remote:" and printed directly to the standard error output. Typically, this standard error output is connected to a terminal that understands ANSI escape sequences, which Git did not protect against. Most modern terminals support control sequences that can be used by a malicious actor to hide and misrepresent information, or to mislead the user into executing untrusted scripts. As requested on the git-security mailing list, the patches are under discussion on the public mailing list. Users are advised to update as soon as possible. Users unable to upgrade should avoid recursive clones unless they are from trusted sources.

---
- git <unfixed> (unimportant)
https://github.com/git/git/security/advisories/GHSA-7jjc-gg6m-3329
Terminal emulators need to perform proper escaping

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-24975?s=debian&n=git&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A2.39.5-0%2Bdeb12u2"><img alt="low : CVE--2022--24975" src="https://img.shields.io/badge/CVE--2022--24975-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:2.39.5-0+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.812%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>73rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The --mirror documentation for Git through 2.35.1 does not mention the availability of deleted content, aka the "GitBleed" issue. This could present a security risk if information-disclosure auditing processes rely on a clone operation without the --mirror option. Note: This has been disputed by multiple 3rd parties who believe this is an intended feature of the git binary and does not pose a security risk.

---
- git <unfixed> (unimportant)
https://wwws.nightwatchcybersecurity.com/2022/02/11/gitbleed/
CVE is specifically about --mirror documentation not mentioning the availability
of deleted content.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-1000021?s=debian&n=git&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A2.39.5-0%2Bdeb12u2"><img alt="low : CVE--2018--1000021" src="https://img.shields.io/badge/CVE--2018--1000021-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:2.39.5-0+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.384%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>59th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GIT version 2.15.1 and earlier contains a Input Validation Error vulnerability in Client that can result in problems including messing up terminal configuration to RCE. This attack appear to be exploitable via The user must interact with a malicious git server, (or have their traffic modified in a MITM attack).

---
- git <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=889680)
http://www.batterystapl.es/2018/01/security-implications-of-ansi-escape.html
Terminal emulators need to perform proper escaping

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 3" src="https://img.shields.io/badge/L-3-fce1a9"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.36.0-7+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/perl@5.36.0-7%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-56406?s=debian&n=perl&ns=debian&t=deb&osn=debian&osv=12&vr=%3C5.36.0-7%2Bdeb12u2"><img alt="low : CVE--2024--56406" src="https://img.shields.io/badge/CVE--2024--56406-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.36.0-7+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><code>5.36.0-7+deb12u2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap buffer overflow vulnerability was discovered in Perl.   Release branches 5.34, 5.36, 5.38 and 5.40 are affected, including development versions from 5.33.1 through 5.41.10.  When there are non-ASCII bytes in the left-hand-side of the `tr` operator, `S_do_trans_invmap` can overflow the destination pointer `d`.     $ perl -e '$_ = "\x{FF}" x 1000000; tr/\xFF/\x{100}/;'     Segmentation fault (core dumped)  It is believed that this vulnerability can enable Denial of Service and possibly Code Execution attacks on platforms that lack sufficient defenses.

---
- perl 5.40.1-3
[bullseye] - perl <not-affected> (Vulnerable code introduced later)
https://lists.security.metacpan.org/cve-announce/msg/28708725/
Introduced by: https://github.com/Perl/perl5/commit/a311ee08b6781f83a7785f578a26bbc21a7ae457 (v5.33.1)
Fixed by: https://github.com/Perl/perl5/commit/87f42aa0e0096e9a346c9672aa3a0bd3bef8c1dd

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-31486?s=debian&n=perl&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.36.0-7%2Bdeb12u1"><img alt="low : CVE--2023--31486" src="https://img.shields.io/badge/CVE--2023--31486-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.36.0-7+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.442%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>62nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

HTTP::Tiny before 0.083, a Perl core module since 5.13.9 and available standalone on CPAN, has an insecure default TLS configuration where users must opt in to verify certificates.

---
- libhttp-tiny-perl 0.088-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=962407; unimportant)
[experimental] - perl 5.38.0~rc2-1
- perl 5.38.2-2 (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=954089)
https://www.openwall.com/lists/oss-security/2023/04/18/14
https://github.com/chansen/p5-http-tiny/issues/134
https://blog.hackeriet.no/perl-http-tiny-insecure-tls-default-affects-cpan-modules/
https://hackeriet.github.io/cpan-http-tiny-overview/
Applications need to explicitly opt in to enable verification.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2011-4116?s=debian&n=perl&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D5.36.0-7%2Bdeb12u1"><img alt="low : CVE--2011--4116" src="https://img.shields.io/badge/CVE--2011--4116-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=5.36.0-7+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.815%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>73rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

_is_safe in the File::Temp module for Perl does not properly handle symlinks.

---
- perl <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=776268)
http://thread.gmane.org/gmane.comp.security.oss.general/6174/focus=6177
https://github.com/Perl-Toolchain-Gang/File-Temp/issues/14

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>gcc-12</strong> <code>12.2.0-14</code> (deb)</summary>

<small><code>pkg:deb/debian/gcc-12@12.2.0-14?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-4039?s=debian&n=gcc-12&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D12.2.0-14"><img alt="low : CVE--2023--4039" src="https://img.shields.io/badge/CVE--2023--4039-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=12.2.0-14</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.124%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

**DISPUTED**A failure in the -fstack-protector feature in GCC-based toolchains  that target AArch64 allows an attacker to exploit an existing buffer  overflow in dynamically-sized local variables in your application  without this being detected. This stack-protector failure only applies  to C99-style dynamically-sized local variables or those created using  alloca(). The stack-protector operates as intended for statically-sized  local variables.  The default behavior when the stack-protector  detects an overflow is to terminate your application, resulting in  controlled loss of availability. An attacker who can exploit a buffer  overflow without triggering the stack-protector might be able to change  program flow control to cause an uncontrolled loss of availability or to  go further and affect confidentiality or integrity. NOTE: The GCC project argues that this is a missed hardening bug and not a vulnerability by itself.

---
- gcc-13 13.2.0-4 (unimportant)
- gcc-12 12.3.0-9 (unimportant)
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

<a href="https://scout.docker.com/v/CVE-2022-27943?s=debian&n=gcc-12&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D12.2.0-14"><img alt="low : CVE--2022--27943" src="https://img.shields.io/badge/CVE--2022--27943-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=12.2.0-14</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libiberty/rust-demangle.c in GNU GCC 11.2 allows stack consumption in demangle_const, as demonstrated by nm-new.

---
- gcc-12 <unfixed> (unimportant)
Negligible security impact
https://gcc.gnu.org/bugzilla/show_bug.cgi?id=105039

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>lcms2</strong> <code>2.14-2</code> (deb)</summary>

<small><code>pkg:deb/debian/lcms2@2.14-2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-29070?s=debian&n=lcms2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.14-2"><img alt="low : CVE--2025--29070" src="https://img.shields.io/badge/CVE--2025--29070-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.14-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.127%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap buffer overflow vulnerability has been identified in thesmooth2() in cmsgamma.c in lcms2-2.16 which allows a remote attacker to cause a denial of service. NOTE: the Supplier disputes this because "this is not exploitable as this function is never called on normal color management, is there only as a helper for low-level programming and investigation."

---
- lcms2 <unfixed> (unimportant)
https://github.com/mm2/Little-CMS/issues/475
Fixed by: https://github.com/mm2/Little-CMS/commit/ec399d6879184e92a88c9099c60573f35e82e28b
Negligible security impact, affected fuction never called on normal color managment

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-29069?s=debian&n=lcms2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.14-2"><img alt="low : CVE--2025--29069" src="https://img.shields.io/badge/CVE--2025--29069-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.14-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap buffer overflow vulnerability has been identified in the lcms2-2.16. The vulnerability exists in the UnrollChunkyBytes function in cmspack.c, which is responsible for handling color space transformations.

---
https://github.com/mm2/Little-CMS/issues/476
Not considered an issue in src:lcms2 but in the fuzzer

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>libheif</strong> <code>1.15.1-1+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/libheif@1.15.1-1%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-25269?s=debian&n=libheif&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.15.1-1%2Bdeb12u1"><img alt="low : CVE--2024--25269" src="https://img.shields.io/badge/CVE--2024--25269-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.15.1-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.059%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libheif <= 1.17.6 contains a memory leak in the function JpegEncoder::Encode. This flaw allows an attacker to cause a denial of service attack.

---
- libheif 1.17.6-2 (unimportant)
https://github.com/strukturag/libheif/issues/1073
https://github.com/strukturag/libheif/pull/1074
https://github.com/strukturag/libheif/commit/877de6b398198bca387df791b9232922c5721c80
Memory leak in example code

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-49463?s=debian&n=libheif&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.15.1-1%2Bdeb12u1"><img alt="low : CVE--2023--49463" src="https://img.shields.io/badge/CVE--2023--49463-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.15.1-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.089%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libheif v1.17.5 was discovered to contain a segmentation violation via the function find_exif_tag at /libheif/exif.cc.

---
- libheif 1.17.6-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1059151; unimportant)
[buster] - libheif <not-affected> (Vulnerable code not present)
https://github.com/strukturag/libheif/issues/1042
https://github.com/strukturag/libheif/commit/26ec3953d46bb5756b97955661565bcbc6647abf (v1.17.6)
Crash in CLI tool, no security impact (only affects example tool shipped in libheif-examples)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>m4</strong> <code>1.4.19-3</code> (deb)</summary>

<small><code>pkg:deb/debian/m4@1.4.19-3?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2008-1688?s=debian&n=m4&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.4.19-3"><img alt="low : CVE--2008--1688" src="https://img.shields.io/badge/CVE--2008--1688-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.4.19-3</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>2.196%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Unspecified vulnerability in GNU m4 before 1.4.11 might allow context-dependent attackers to execute arbitrary code, related to improper handling of filenames specified with the -F option.  NOTE: it is not clear when this issue crosses privilege boundaries.

---
- m4 <unfixed> (unimportant)
The file name is passed through a cmdline argument and m4 doesn't run with
elevated privileges.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2008-1687?s=debian&n=m4&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.4.19-3"><img alt="low : CVE--2008--1687" src="https://img.shields.io/badge/CVE--2008--1687-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.4.19-3</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>2.727%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>85th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The (1) maketemp and (2) mkstemp builtin functions in GNU m4 before 1.4.11 do not quote their output when a file is created, which might allow context-dependent attackers to trigger a macro expansion, leading to unspecified use of an incorrect filename.

---
- m4 <unfixed> (unimportant)
This is more a generic bug and not a security issue: the random output would
need to match the name of an existing macro

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>expat</strong> <code>2.5.0-1+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/expat@2.5.0-1%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-28757?s=debian&n=expat&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-1%2Bdeb12u1"><img alt="low : CVE--2024--28757" src="https://img.shields.io/badge/CVE--2024--28757-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.228%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>46th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libexpat through 2.6.1 allows an XML Entity Expansion attack when there is isolated use of external parsers (created via XML_ExternalEntityParserCreate).

---
- expat 2.6.1-2 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1065868; unimportant)
https://github.com/libexpat/libexpat/pull/842
https://github.com/libexpat/libexpat/issues/839
Fixed by: https://github.com/libexpat/libexpat/commit/1d50b80cf31de87750103656f6eb693746854aa8
Tests: https://github.com/libexpat/libexpat/commit/072eca0b72373da103ce15f8f62d1d7b52695454
Expat provides API to mitigate expansion attacks, ultimately under control of the app using Expat
Cf. Billion laughs attack assessment for src:expat in CVE-2013-0340.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52426?s=debian&n=expat&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.5.0-1%2Bdeb12u1"><img alt="low : CVE--2023--52426" src="https://img.shields.io/badge/CVE--2023--52426-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.5.0-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libexpat through 2.5.0 allows recursive XML Entity Expansion if XML_DTD is undefined at compile time.

---
- expat 2.6.0-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1063240; unimportant)
https://github.com/libexpat/libexpat/pull/777
https://github.com/libexpat/libexpat/commit/0f075ec8ecb5e43f8fdca5182f8cca4703da0404
https://github.com/libexpat/libexpat/pull/777#issuecomment-1965172301
CVE is for fixing billion laughs attacks for users compiling *without* XML_DTD defined,
which is not the case for Debian.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libpng1.6</strong> <code>1.6.39-2</code> (deb)</summary>

<small><code>pkg:deb/debian/libpng1.6@1.6.39-2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-4214?s=debian&n=libpng1.6&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.6.39-2"><img alt="low : CVE--2021--4214" src="https://img.shields.io/badge/CVE--2021--4214-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.6.39-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap overflow flaw was found in libpngs' pngimage.c program. This flaw allows an attacker with local network access to pass a specially crafted PNG file to the pngimage utility, causing an application to crash, leading to a denial of service.

---
- libpng1.6 <unfixed> (unimportant)
https://github.com/glennrp/libpng/issues/302
Crash in CLI package, not shipped in binary packages

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>xz-utils</strong> <code>5.4.1-0.2</code> (deb)</summary>

<small><code>pkg:deb/debian/xz-utils@5.4.1-0.2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-31115?s=debian&n=xz-utils&ns=debian&t=deb&osn=debian&osv=12&vr=%3C5.4.1-1"><img alt="low : CVE--2025--31115" src="https://img.shields.io/badge/CVE--2025--31115-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.4.1-1</code></td></tr>
<tr><td>Fixed version</td><td><code>5.4.1-1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.117%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>32nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

XZ Utils provide a general-purpose data-compression library plus command-line tools. In XZ Utils 5.3.3alpha to 5.8.0, the multithreaded .xz decoder in liblzma has a bug where invalid input can at least result in a crash. The effects include heap use after free and writing to an address based on the null pointer plus an offset. Applications and libraries that use the lzma_stream_decoder_mt function are affected. The bug has been fixed in XZ Utils 5.8.1, and the fix has been committed to the v5.4, v5.6, v5.8, and master branches in the xz Git repository. No new release packages will be made from the old stable branches, but a standalone patch is available that applies to all affected releases.

---
- xz-utils 5.8.1-1
[bullseye] - xz-utils <not-affected> (Vulnerable code introduced later)
https://www.openwall.com/lists/oss-security/2025/04/03/1
https://tukaani.org/xz/threaded-decoder-early-free.html
https://github.com/tukaani-project/xz/security/advisories/GHSA-6cc8-p5mm-29w2

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>openexr</strong> <code>3.1.5-5</code> (deb)</summary>

<small><code>pkg:deb/debian/openexr@3.1.5-5?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2017-14988?s=debian&n=openexr&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D3.1.5-5"><img alt="low : CVE--2017--14988" src="https://img.shields.io/badge/CVE--2017--14988-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=3.1.5-5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.209%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>44th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Header::readfrom in IlmImf/ImfHeader.cpp in OpenEXR 2.2.0 allows remote attackers to cause a denial of service (excessive memory allocation) via a crafted file that is accessed with the ImfOpenInputFile function in IlmImf/ImfCRgbaFile.cpp. NOTE: The maintainer and multiple third parties believe that this vulnerability isn't valid

---
- openexr <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=878551; unimportant)
https://github.com/openexr/openexr/issues/248
Issue in the use of openexr via ImageMagick, no real security impact

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libgcrypt20</strong> <code>1.10.1-3</code> (deb)</summary>

<small><code>pkg:deb/debian/libgcrypt20@1.10.1-3?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-6829?s=debian&n=libgcrypt20&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.10.1-3"><img alt="low : CVE--2018--6829" src="https://img.shields.io/badge/CVE--2018--6829-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.10.1-3</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.841%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>73rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

cipher/elgamal.c in Libgcrypt through 1.8.2, when used to encrypt messages directly, improperly encodes plaintexts, which allows attackers to obtain sensitive information by reading ciphertext data (i.e., it does not have semantic security in face of a ciphertext-only attack). The Decisional Diffie-Hellman (DDH) assumption does not hold for Libgcrypt's ElGamal implementation.

---
- libgcrypt20 <unfixed> (unimportant)
- libgcrypt11 <removed> (unimportant)
- gnupg1 <unfixed> (unimportant)
- gnupg <removed> (unimportant)
https://github.com/weikengchen/attack-on-libgcrypt-elgamal
https://github.com/weikengchen/attack-on-libgcrypt-elgamal/wiki
https://lists.gnupg.org/pipermail/gcrypt-devel/2018-February/004394.html
GnuPG uses ElGamal in hybrid mode only.
This is not a vulnerability in libgcrypt, but in an application using
it in an insecure manner, see also
https://lists.gnupg.org/pipermail/gcrypt-devel/2018-February/004401.html

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>pixman</strong> <code>0.42.2-1</code> (deb)</summary>

<small><code>pkg:deb/debian/pixman@0.42.2-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-37769?s=debian&n=pixman&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.42.2-1"><img alt="low : CVE--2023--37769" src="https://img.shields.io/badge/CVE--2023--37769-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.42.2-1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

stress-test master commit e4c878 was discovered to contain a FPE vulnerability via the component combine_inner at /pixman-combine-float.c.

---
- pixman <unfixed> (unimportant)
https://gitlab.freedesktop.org/pixman/pixman/-/issues/76
Crash in test tool, no security impact

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.40.1-2+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/sqlite3@3.40.1-2%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-45346?s=debian&n=sqlite3&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D3.40.1-2%2Bdeb12u1"><img alt="low : CVE--2021--45346" src="https://img.shields.io/badge/CVE--2021--45346-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=3.40.1-2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.173%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>40th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Memory Leak vulnerability exists in SQLite Project SQLite3 3.35.1 and 3.37.0 via maliciously crafted SQL Queries (made via editing the Database File), it is possible to query a record, and leak subsequent bytes of memory that extend beyond the record, which could let a malicious user obtain sensitive information. NOTE: The developer disputes this as a vulnerability stating that If you give SQLite a corrupted database file and submit a query against the database, it might read parts of the database that you did not intend or expect.

---
- sqlite3 <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1005974)
- sqlite <removed> (unimportant)
https://github.com/guyinatuxedo/sqlite3_record_leaking
https://bugzilla.redhat.com/show_bug.cgi?id=2054793
https://sqlite.org/forum/forumpost/056d557c2f8c452ed5bb9c215414c802b215ce437be82be047726e521342161e
Negligible security impact

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>subversion</strong> <code>1.14.2-4</code> (deb)</summary>

<small><code>pkg:deb/debian/subversion@1.14.2-4?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-46901?s=debian&n=subversion&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.14.2-4%2Bdeb12u1"><img alt="low : CVE--2024--46901" src="https://img.shields.io/badge/CVE--2024--46901-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.14.2-4+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.14.2-4+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.486%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Insufficient validation of filenames against control characters in Apache Subversion repositories served via mod_dav_svn allows authenticated users with commit access to commit a corrupted revision, leading to disruption for users of the repository.  All versions of Subversion up to and including Subversion 1.14.4 are affected if serving repositories via mod_dav_svn. Users are recommended to upgrade to version 1.14.5, which fixes this issue.  Repositories served via other access methods are not affected.

---
- subversion 1.14.5-1
[bookworm] - subversion 1.14.2-4+deb12u1
https://subversion.apache.org/security/CVE-2024-46901-advisory.txt

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>coreutils</strong> <code>9.1-1</code> (deb)</summary>

<small><code>pkg:deb/debian/coreutils@9.1-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2017-18018?s=debian&n=coreutils&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D9.1-1"><img alt="low : CVE--2017--18018" src="https://img.shields.io/badge/CVE--2017--18018-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=9.1-1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In GNU Coreutils through 8.29, chown-core.c in chown and chgrp does not prevent replacement of a plain file with a symlink during use of the POSIX "-R -L" options, which allows local users to modify the ownership of arbitrary files by leveraging a race condition.

---
- coreutils <unfixed> (unimportant)
http://lists.gnu.org/archive/html/coreutils/2017-12/msg00045.html
https://www.openwall.com/lists/oss-security/2018/01/04/3
Documentation patches proposed:
https://lists.gnu.org/archive/html/coreutils/2017-12/msg00072.html
https://lists.gnu.org/archive/html/coreutils/2017-12/msg00073.html
Neutralised by kernel hardening

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>jbigkit</strong> <code>2.1-6.1</code> (deb)</summary>

<small><code>pkg:deb/debian/jbigkit@2.1-6.1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2017-9937?s=debian&n=jbigkit&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.1-6.1"><img alt="low : CVE--2017--9937" src="https://img.shields.io/badge/CVE--2017--9937-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.1-6.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.328%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>55th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In LibTIFF 4.0.8, there is a memory malloc failure in tif_jbig.c. A crafted TIFF document can lead to an abort resulting in a remote denial of service attack.

---
- jbigkit <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=869708)
http://bugzilla.maptools.org/show_bug.cgi?id=2707
The CVE was assigned for src:tiff by MITRE, but the issue actually lies
in jbigkit itself.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>openssl</strong> <code>3.0.15-1~deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/openssl@3.0.15-1~deb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2010-0928?s=debian&n=openssl&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D3.0.11-1%7Edeb12u2"><img alt="low : CVE--2010--0928" src="https://img.shields.io/badge/CVE--2010--0928-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=3.0.11-1~deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.098%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>29th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

OpenSSL 0.9.8i on the Gaisler Research LEON3 SoC on the Xilinx Virtex-II Pro FPGA uses a Fixed Width Exponentiation (FWE) algorithm for certain signature calculations, and does not verify the signature before providing it to a caller, which makes it easier for physically proximate attackers to determine the private key via a modified supply voltage for the microprocessor, related to a "fault-based attack."

---
http://www.eecs.umich.edu/~valeria/research/publications/DATE10RSA.pdf
https://github.com/openssl/openssl/discussions/24540
Fault injection based attacks are not within OpenSSLs threat model according
to the security policy: https://www.openssl.org/policies/general/security-policy.html

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>gnupg2</strong> <code>2.2.40-1.1</code> (deb)</summary>

<small><code>pkg:deb/debian/gnupg2@2.2.40-1.1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-3219?s=debian&n=gnupg2&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.2.40-1.1"><img alt="low : CVE--2022--3219" src="https://img.shields.io/badge/CVE--2022--3219-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.2.40-1.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.012%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

---
- gnupg2 <unfixed> (unimportant)
https://bugzilla.redhat.com/show_bug.cgi?id=2127010
https://dev.gnupg.org/D556
https://dev.gnupg.org/T5993
https://www.openwall.com/lists/oss-security/2022/07/04/8
GnuPG upstream is not implementing this change.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>tcl8.6</strong> <code>8.6.13+dfsg-2</code> (deb)</summary>

<small><code>pkg:deb/debian/tcl8.6@8.6.13%2Bdfsg-2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-35331?s=debian&n=tcl8.6&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D8.6.13%2Bdfsg-2"><img alt="low : CVE--2021--35331" src="https://img.shields.io/badge/CVE--2021--35331-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=8.6.13+dfsg-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.551%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>67th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Tcl 8.6.11, a format string vulnerability in nmakehlp.c might allow code execution via a crafted file. NOTE: multiple third parties dispute the significance of this finding

---
- tcl8.6 <unfixed> (unimportant)
https://core.tcl-lang.org/tcl/info/28ef6c0c741408a2
https://core.tcl-lang.org/tcl/info/bad6cc213dfe8280
https://github.com/tcltk/tcl/commit/4705dbdde2f32ff90420765cd93e7ac71d81a222
https://sqlite.org/forum/info/7dcd751996c93ec9
Various other sources would embedd a copy as well, but the security impact of
the issue tself for tcl is disputed in its significance.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>glib2.0</strong> <code>2.74.6-2+deb12u5</code> (deb)</summary>

<small><code>pkg:deb/debian/glib2.0@2.74.6-2%2Bdeb12u5?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2012-0039?s=debian&n=glib2.0&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.74.6-2%2Bdeb12u5"><img alt="low : CVE--2012--0039" src="https://img.shields.io/badge/CVE--2012--0039-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.74.6-2+deb12u5</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.489%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>64th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GLib 2.31.8 and earlier, when the g_str_hash function is used, computes hash values without restricting the ability to trigger hash collisions predictably, which allows context-dependent attackers to cause a denial of service (CPU consumption) via crafted input to an application that maintains a hash table. NOTE: this issue may be disputed by the vendor; the existence of the g_str_hash function is not a vulnerability in the library, because callers of g_hash_table_new and g_hash_table_new_full can specify an arbitrary hash function that is appropriate for the application.

---
- glib2.0 <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=655044)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.7.9-2+deb12u4</code> (deb)</summary>

<small><code>pkg:deb/debian/gnutls28@3.7.9-2%2Bdeb12u4?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2011-3389?s=debian&n=gnutls28&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D3.7.9-2%2Bdeb12u4"><img alt="low : CVE--2011--3389" src="https://img.shields.io/badge/CVE--2011--3389-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=3.7.9-2+deb12u4</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>5.423%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The SSL protocol, as used in certain configurations in Microsoft Windows and Microsoft Internet Explorer, Mozilla Firefox, Google Chrome, Opera, and other products, encrypts data by using CBC mode with chained initialization vectors, which allows man-in-the-middle attackers to obtain plaintext HTTP headers via a blockwise chosen-boundary attack (BCBA) on an HTTPS session, in conjunction with JavaScript code that uses (1) the HTML5 WebSocket API, (2) the Java URLConnection API, or (3) the Silverlight WebClient API, aka a "BEAST" attack.

---
- sun-java6 <removed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=645881)
[lenny] - sun-java6 <no-dsa> (Non-free not supported)
[squeeze] - sun-java6 <no-dsa> (Non-free not supported)
- openjdk-6 6b23~pre11-1
- openjdk-7 7~b147-2.0-1
- iceweasel <not-affected> (Vulnerable code not present)
http://blog.mozilla.com/security/2011/09/27/attack-against-tls-protected-communications/
- chromium-browser 15.0.874.106~r107270-1
[squeeze] - chromium-browser <end-of-life>
- lighttpd 1.4.30-1
strictly speaking this is no lighttpd issue, but lighttpd adds a workaround
- curl 7.24.0-1
http://curl.haxx.se/docs/adv_20120124B.html
- python2.6 2.6.8-0.1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=684511)
[squeeze] - python2.6 <no-dsa> (Minor issue)
- python2.7 2.7.3~rc1-1
- python3.1 <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=678998)
[squeeze] - python3.1 <no-dsa> (Minor issue)
- python3.2 3.2.3~rc1-1
http://bugs.python.org/issue13885
python3.1 is fixed starting 3.1.5
- cyassl <removed>
- gnutls26 <removed> (unimportant)
- gnutls28 <unfixed> (unimportant)
No mitigation for gnutls, it is recommended to use TLS 1.1 or 1.2 which is supported since 2.0.0
- haskell-tls <unfixed> (unimportant)
No mitigation for haskell-tls, it is recommended to use TLS 1.1, which is supported since 0.2
- matrixssl <removed> (low)
[squeeze] - matrixssl <no-dsa> (Minor issue)
[wheezy] - matrixssl <no-dsa> (Minor issue)
matrixssl fix this upstream in 3.2.2
- bouncycastle 1.49+dfsg-1
[squeeze] - bouncycastle <no-dsa> (Minor issue)
[wheezy] - bouncycastle <no-dsa> (Minor issue)
No mitigation for bouncycastle, it is recommended to use TLS 1.1, which is supported since 1.4.9
- nss 3.13.1.with.ckbi.1.88-1
https://bugzilla.mozilla.org/show_bug.cgi?id=665814
https://hg.mozilla.org/projects/nss/rev/7f7446fcc7ab
- polarssl <unfixed> (unimportant)
No mitigation for polarssl, it is recommended to use TLS 1.1, which is supported in all releases
- tlslite <removed>
[wheezy] - tlslite <no-dsa> (Minor issue)
- pound 2.6-2
Pound 2.6-2 added an anti_beast.patch to mitigate BEAST attacks.
- erlang 1:15.b-dfsg-1
[squeeze] - erlang <no-dsa> (Minor issue)
- asterisk 1:13.7.2~dfsg-1
[jessie] - asterisk 1:11.13.1~dfsg-2+deb8u1
[wheezy] - asterisk <no-dsa> (Minor issue)
[squeeze] - asterisk <end-of-life> (Not supported in Squeeze LTS)
http://downloads.digium.com/pub/security/AST-2016-001.html
https://issues.asterisk.org/jira/browse/ASTERISK-24972
patch for 11 (jessie): https://code.asterisk.org/code/changelog/asterisk?cs=f233bcd81d85626ce5bdd27b05bc95d131faf3e4
all versions vulnerable, backport required for wheezy

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>util-linux</strong> <code>2.38.1-5+deb12u3</code> (deb)</summary>

<small><code>pkg:deb/debian/util-linux@2.38.1-5%2Bdeb12u3?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-0563?s=debian&n=util-linux&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.38.1-5%2Bdeb12u3"><img alt="low : CVE--2022--0563" src="https://img.shields.io/badge/CVE--2022--0563-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.38.1-5+deb12u3</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The Readline library uses an "INPUTRC" environment variable to get a path to the library config file. When the library cannot parse the specified file, it prints an error message containing data from the file. This flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation. This flaw affects util-linux versions prior to 2.37.4.

---
- util-linux <unfixed> (unimportant)
https://bugzilla.redhat.com/show_bug.cgi?id=2053151
https://lore.kernel.org/util-linux/20220214110609.msiwlm457ngoic6w@ws.net.home/T/#u
https://github.com/util-linux/util-linux/commit/faa5a3a83ad0cb5e2c303edbfd8cd823c9d94c17
util-linux in Debian does build with readline support but chfn and chsh are provided
by src:shadow and util-linux is configured with --disable-chfn-chsh

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>jansson</strong> <code>2.14-2</code> (deb)</summary>

<small><code>pkg:deb/debian/jansson@2.14-2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2020-36325?s=debian&n=jansson&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.14-2"><img alt="low : CVE--2020--36325" src="https://img.shields.io/badge/CVE--2020--36325-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.14-2</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.412%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>60th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in Jansson through 2.13.1. Due to a parsing error in json_loads, there's an out-of-bounds read-access bug. NOTE: the vendor reports that this only occurs when a programmer fails to follow the API specification

---
- jansson <unfixed> (unimportant)
https://github.com/akheron/jansson/issues/548
Disputed security impact (only if programmer fails to follow API specifications)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>apt</strong> <code>2.6.1</code> (deb)</summary>

<small><code>pkg:deb/debian/apt@2.6.1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2011-3374?s=debian&n=apt&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D2.6.1"><img alt="low : CVE--2011--3374" src="https://img.shields.io/badge/CVE--2011--3374-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=2.6.1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>1.082%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>77th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

It was found that apt-key in apt, all versions, do not correctly validate gpg keys with the master keyring, leading to a potential man-in-the-middle attack.

---
- apt <unfixed> (unimportant; bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=642480)
Not exploitable in Debian, since no keyring URI is defined

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>shadow</strong> <code>1:4.13+dfsg1-1</code> (deb)</summary>

<small><code>pkg:deb/debian/shadow@1%3A4.13%2Bdfsg1-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2007-5686?s=debian&n=shadow&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1%3A4.13%2Bdfsg1-1"><img alt="low : CVE--2007--5686" src="https://img.shields.io/badge/CVE--2007--5686-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1:4.13+dfsg1-1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.225%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

initscripts in rPath Linux 1 sets insecure permissions for the /var/log/btmp file, which allows local users to obtain sensitive information regarding authentication attempts.  NOTE: because sshd detects the insecure permissions and does not log certain events, this also prevents sshd from logging failed authentication attempts by remote attackers.

---
- shadow <unfixed> (unimportant)
See #290803, on Debian LOG_UNKFAIL_ENAB in login.defs is set to no so
unknown usernames are not recorded on login failures

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>unzip</strong> <code>6.0-28</code> (deb)</summary>

<small><code>pkg:deb/debian/unzip@6.0-28?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-4217?s=debian&n=unzip&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D6.0-28"><img alt="low : CVE--2021--4217" src="https://img.shields.io/badge/CVE--2021--4217-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=6.0-28</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.125%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in unzip. The vulnerability occurs due to improper handling of Unicode strings, which can lead to a null pointer dereference. This flaw allows an attacker to input a specially crafted zip file, leading to a crash or code execution.

---
- unzip <unfixed> (unimportant)
https://bugzilla.redhat.com/show_bug.cgi?id=2044583
https://bugs.launchpad.net/ubuntu/+source/unzip/+bug/1957077
Crash in CLI tool, no security impact

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>subversion</strong> <code>1.14.2-4+b2</code> (deb)</summary>

<small><code>pkg:deb/debian/subversion@1.14.2-4%2Bb2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-46901?s=debian&n=subversion&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.14.2-4%2Bdeb12u1"><img alt="low : CVE--2024--46901" src="https://img.shields.io/badge/CVE--2024--46901-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.14.2-4+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.14.2-4+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.486%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Insufficient validation of filenames against control characters in Apache Subversion repositories served via mod_dav_svn allows authenticated users with commit access to commit a corrupted revision, leading to disruption for users of the repository.  All versions of Subversion up to and including Subversion 1.14.4 are affected if serving repositories via mod_dav_svn. Users are recommended to upgrade to version 1.14.5, which fixes this issue.  Repositories served via other access methods are not affected.

---
- subversion 1.14.5-1
[bookworm] - subversion 1.14.2-4+deb12u1
https://subversion.apache.org/security/CVE-2024-46901-advisory.txt

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>tar</strong> <code>1.34+dfsg-1.2+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/tar@1.34%2Bdfsg-1.2%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2005-2541?s=debian&n=tar&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D1.34%2Bdfsg-1.2%2Bdeb12u1"><img alt="low : CVE--2005--2541" src="https://img.shields.io/badge/CVE--2005--2541-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=1.34+dfsg-1.2+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>2.537%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>85th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Tar 1.15.1 does not properly warn the user when extracting setuid or setgid files, which may allow local users or remote attackers to gain privileges.

---
This is intended behaviour, after all tar is an archiving tool and you
need to give -p as a command line flag
- tar <unfixed> (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=328228; unimportant)

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <img alt="unspecified: 2" src="https://img.shields.io/badge/U-2-lightgrey"/><strong>libyaml</strong> <code>0.2.5-1</code> (deb)</summary>

<small><code>pkg:deb/debian/libyaml@0.2.5-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-35329?s=debian&n=libyaml&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.2.5-1"><img alt="unspecified : CVE--2024--35329" src="https://img.shields.io/badge/CVE--2024--35329-lightgrey?label=unspecified%20&labelColor=lightgrey"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.2.5-1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

libyaml 0.2.5 is vulnerable to a heap-based Buffer Overflow in yaml_document_add_sequence in api.c.

---
REJECTED

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-3205?s=debian&n=libyaml&ns=debian&t=deb&osn=debian&osv=12&vr=%3E%3D0.2.5-1"><img alt="unspecified : CVE--2024--3205" src="https://img.shields.io/badge/CVE--2024--3205-lightgrey?label=unspecified%20&labelColor=lightgrey"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.2.5-1</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in yaml libyaml up to 0.2.5 and classified as critical. Affected by this issue is the function yaml_emitter_emit_flow_sequence_item of the file /src/libyaml/src/emitter.c. The manipulation leads to heap-based buffer overflow. The attack may be launched remotely. The exploit has been disclosed to the public and may be used. The identifier of this vulnerability is VDB-259052. NOTE: The vendor was contacted early about this disclosure but did not respond in any way.

---
REJECTED

</blockquote>
</details>
</details></td></tr>
</table>