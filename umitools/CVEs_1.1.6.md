# Vulnerability Report for getwilds/umitools:1.1.6

Report generated on 2025-06-20 22:28:33 PST

<h2>:mag: Vulnerabilities of <code>getwilds/umitools:1.1.6</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/umitools:1.1.6</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:ca0a3fc5f476ae7424e47b86377f8cfd6a28f8878936e0ed996a0204699be1c1</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 1" src="https://img.shields.io/badge/critical-1-8b1924"/> <img alt="high: 6" src="https://img.shields.io/badge/high-6-e25d68"/> <img alt="medium: 11" src="https://img.shields.io/badge/medium-11-fbb552"/> <img alt="low: 12" src="https://img.shields.io/badge/low-12-fce1a9"/> <img alt="unspecified: 1" src="https://img.shields.io/badge/unspecified-1-lightgrey"/></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>531 MB</td></tr>
<tr><td>packages</td><td>607</td></tr>
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
<tr><td>EPSS Score</td><td><code>0.265%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>50th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

url.c in GNU Wget through 1.24.5 mishandles semicolons in the userinfo subcomponent of a URI, and thus there may be insecure behavior in which data that was supposed to be in the userinfo subcomponent is misinterpreted to be part of the host subcomponent.

---
- wget 1.24.5-2 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1073523)
[bookworm] - wget 1.21.3-1+deb12u1
[buster] - wget <postponed> (Minor issue, infoleak in limited conditions)
https://lists.gnu.org/archive/html/bug-wget/2024-06/msg00005.html
Fixed by: https://git.savannah.gnu.org/cgit/wget.git/commit/?id=ed0c7c7e0e8f7298352646b2fd6e06a11e242ace

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libxslt</strong> <code>1.1.35-1</code> (deb)</summary>

<small><code>pkg:deb/debian/libxslt@1.1.35-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-24855?s=debian&n=libxslt&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.1.35-1%2Bdeb12u1"><img alt="high : CVE--2025--24855" src="https://img.shields.io/badge/CVE--2025--24855-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.1.35-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.1.35-1+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.009%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.007%</code></td></tr>
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
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>postgresql-15</strong> <code>15.10-0+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/postgresql-15@15.10-0%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-1094?s=debian&n=postgresql-15&ns=debian&t=deb&osn=debian&osv=12&vr=%3C15.11-0%2Bdeb12u1"><img alt="high : CVE--2025--1094" src="https://img.shields.io/badge/CVE--2025--1094-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><15.11-0+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>15.11-0+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>83.630%</code></td></tr>
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

<a href="https://scout.docker.com/v/CVE-2025-4207?s=debian&n=postgresql-15&ns=debian&t=deb&osn=debian&osv=12&vr=%3C15.13-0%2Bdeb12u1"><img alt="medium : CVE--2025--4207" src="https://img.shields.io/badge/CVE--2025--4207-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><15.13-0+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>15.13-0+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.080%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Buffer over-read in PostgreSQL GB18030 encoding validation allows a database input provider to achieve temporary denial of service on platforms where a 1-byte over-read can elicit process termination.  This affects the database server and also libpq.  Versions before PostgreSQL 17.5, 16.9, 15.13, 14.18, and 13.21 are affected.

---
- postgresql-17 17.5-1
- postgresql-15 <removed>
[bookworm] - postgresql-15 15.13-0+deb12u1
- postgresql-13 <removed>
https://www.postgresql.org/about/news/postgresql-175-169-1513-1418-and-1321-released-3072/
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=ec5f89e8a29f32c7dbc4dd8734ed8406d771de2f (REL_17_5)
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=44ba3f55f552b56b2fbefae028fcf3ea5b53461d (REL_15_13)
https://git.postgresql.org/gitweb/?p=postgresql.git;a=commit;h=cbadeaca9271a1bade8ef9790bae09dc92e0ed30 (REL_13_21)

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
<tr><td>EPSS Score</td><td><code>73.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>setuptools</strong> <code>76.0.0</code> (pypi)</summary>

<small><code>pkg:pypi/setuptools@76.0.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-47273?s=github&n=setuptools&t=pypi&vr=%3C78.1.1"><img alt="high 7.7: CVE--2025--47273" src="https://img.shields.io/badge/CVE--2025--47273-lightgrey?label=high%207.7&labelColor=e25d68"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code><78.1.1</code></td></tr>
<tr><td>Fixed version</td><td><code>78.1.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:P</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.120%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>32nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary 
A path traversal vulnerability in `PackageIndex` was fixed in setuptools version 78.1.1

### Details
```
    def _download_url(self, url, tmpdir):
        # Determine download filename
        #
        name, _fragment = egg_info_for_url(url)
        if name:
            while '..' in name:
                name = name.replace('..', '.').replace('\\', '_')
        else:
            name = "__downloaded__"  # default if URL has no path contents

        if name.endswith('.[egg.zip](http://egg.zip/)'):
            name = name[:-4]  # strip the extra .zip before download

 -->       filename = os.path.join(tmpdir, name)
```

Here: https://github.com/pypa/setuptools/blob/6ead555c5fb29bc57fe6105b1bffc163f56fd558/setuptools/package_index.py#L810C1-L825C88

`os.path.join()` discards the first argument `tmpdir` if the second begins with a slash or drive letter.
`name` is derived from a URL without sufficient sanitization. While there is some attempt to sanitize by replacing instances of '..' with '.', it is insufficient.

### Risk Assessment
As easy_install and package_index are deprecated, the exploitation surface is reduced.
However, it seems this could be exploited in a similar fashion like https://github.com/advisories/GHSA-r9hx-vwmv-q579, and as described by POC 4 in https://github.com/advisories/GHSA-cx63-2mw6-8hw5 report: via malicious URLs present on the pages of a package index.

### Impact
An attacker would be allowed to write files to arbitrary locations on the filesystem with the permissions of the process running the Python code, which could escalate to RCE depending on the context.

### References
https://huntr.com/bounties/d6362117-ad57-4e83-951f-b8141c6e7ca5
https://github.com/pypa/setuptools/issues/4946

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
<tr><td>EPSS Score</td><td><code>0.219%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When the assert() function in the GNU C Library versions 2.13 to 2.40 fails, it does not allocate enough space for the assertion failure message string and size information, which may lead to a buffer overflow if the message string size aligns to page size.

---
- glibc 2.40-6
[bookworm] - glibc 2.36-9+deb12u10
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>mariadb</strong> <code>1:10.11.6-0+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/mariadb@1%3A10.11.6-0%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-21490?s=debian&n=mariadb&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1%3A10.11.11-0%2Bdeb12u1"><img alt="medium : CVE--2025--21490" src="https://img.shields.io/badge/CVE--2025--21490-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:10.11.11-0+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1:10.11.11-0+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.063%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
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
MariaDB Bug: https://jira.mariadb.org/browse/MDEV-29182
MariaDB Commit: https://github.com/MariaDB/server/commit/82310f926b7c6547f25dd80e4edf3f38b22913e5 (mariadb-10.5.28)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-21096?s=debian&n=mariadb&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1%3A10.11.11-0%2Bdeb12u1"><img alt="medium : CVE--2024--21096" src="https://img.shields.io/badge/CVE--2024--21096-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:10.11.11-0+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1:10.11.11-0+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>curl</strong> <code>7.88.1-10+deb12u8</code> (deb)</summary>

<small><code>pkg:deb/debian/curl@7.88.1-10%2Bdeb12u8?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-9681?s=debian&n=curl&ns=debian&t=deb&osn=debian&osv=12&vr=%3C7.88.1-10%2Bdeb12u9"><img alt="medium : CVE--2024--9681" src="https://img.shields.io/badge/CVE--2024--9681-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><7.88.1-10+deb12u9</code></td></tr>
<tr><td>Fixed version</td><td><code>7.88.1-10+deb12u9</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.249%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>48th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.089%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.145%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>python3.11</strong> <code>3.11.2-6+deb12u5</code> (deb)</summary>

<small><code>pkg:deb/debian/python3.11@3.11.2-6%2Bdeb12u5?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-0938?s=debian&n=python3.11&ns=debian&t=deb&osn=debian&osv=12&vr=%3C3.11.2-6%2Bdeb12u6"><img alt="medium : CVE--2025--0938" src="https://img.shields.io/badge/CVE--2025--0938-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.11.2-6+deb12u6</code></td></tr>
<tr><td>Fixed version</td><td><code>3.11.2-6+deb12u6</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>76th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Python standard library functions `urllib.parse.urlsplit` and `urlparse` accepted domain names that included square brackets which isn't valid according to RFC 3986. Square brackets are only meant to be used as delimiters for specifying IPv6 and IPvFuture hosts in URLs. This could result in differential parsing across the Python URL parser and other specification-compliant URL parsers.

---
- python3.13 3.13.2-1
- python3.12 3.12.9-1
- python3.11 <removed>
[bookworm] - python3.11 3.11.2-6+deb12u6
- python3.9 <removed>
- pypy3 7.3.18+dfsg-2
[bookworm] - pypy3 <no-dsa> (Minor issue)
[bullseye] - pypy3 <postponed> (Minor issue)
https://mail.python.org/archives/list/security-announce@python.org/thread/K4EUG6EKV6JYFIC24BASYOZS4M5XOQIB/
https://github.com/python/cpython/issues/105704
https://github.com/python/cpython/pull/129418
Fixed by: https://github.com/python/cpython/commit/d89a5f6a6e65511a5f6e0618c4c30a7aa5aba56a
Fixed by: https://github.com/python/cpython/commit/90e526ae67b172ed7c6c56e7edad36263b0f9403 (v3.13.2)
Fixed by: https://github.com/python/cpython/commit/a7084f6075c9595ba60119ce8c62f1496f50c568 (v3.12.9)
https://github.com/python/cpython/pull/129528 (3.11)
https://github.com/python/cpython/pull/129530 (3.9)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1795?s=debian&n=python3.11&ns=debian&t=deb&osn=debian&osv=12&vr=%3C3.11.2-6%2Bdeb12u6"><img alt="low : CVE--2025--1795" src="https://img.shields.io/badge/CVE--2025--1795-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.11.2-6+deb12u6</code></td></tr>
<tr><td>Fixed version</td><td><code>3.11.2-6+deb12u6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.167%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

During an address list folding when a separating comma ends up on a folded line and that line is to be unicode-encoded then the separator itself is also unicode-encoded. Expected behavior is that the separating comma remains a plan comma. This can result in the address header being misinterpreted by some mail servers.

---
- python3.13 3.13.0~b1-1
- python3.12 3.12.9-1
- python3.11 <removed>
[bookworm] - python3.11 3.11.2-6+deb12u6
- python3.9 <removed>
https://github.com/python/cpython/issues/100884
Regression issue: https://github.com/python/cpython/issues/118643
https://mail.python.org/archives/list/security-announce@python.org/thread/MB62IZMEC3UM6SGHP5LET5JX2Y7H4ZUR/
Fixed by: https://github.com/python/cpython/commit/09fab93c3d857496c0bd162797fab816c311ee48 (v3.13.0a5)
Regression fixed by: https://github.com/python/cpython/commit/6892b400dc8c95375ef31f6d716d62a6ff0c4cf2 (v3.13.0b2)
Fixed by: https://github.com/python/cpython/commit/9148b77e0af91cdacaa7fe3dfac09635c3fe9a74 (v3.12.3)
Regression fixed by: https://github.com/python/cpython/commit/8c96850161da23ad2b37551d2a89c7d4716fe024 (v3.12.4)
Fixed by: https://github.com/python/cpython/commit/70754d21c288535e86070ca7a6e90dcb670b8593 (v3.11.9)
Regression Fixed by: https://github.com/python/cpython/commit/4762b365406a8cf026a4a4ddcae34c28a41c3de9 (v3.11.10)
Introduced by: https://github.com/python/cpython/commit/0b6f6c82b51b7071d88f48abb3192bf3dc2a2d24 (v3.3.0a4)

</blockquote>
</details>
</details></td></tr>

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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>systemd</strong> <code>252.33-1~deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/systemd@252.33-1~deb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
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
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>mercurial</strong> <code>6.3.2-1</code> (deb)</summary>

<small><code>pkg:deb/debian/mercurial@6.3.2-1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-2361?s=debian&n=mercurial&ns=debian&t=deb&osn=debian&osv=12&vr=%3C6.3.2-1%2Bdeb12u1"><img alt="medium : CVE--2025--2361" src="https://img.shields.io/badge/CVE--2025--2361-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.3.2-1+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>6.3.2-1+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.079%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>openssl</strong> <code>3.0.15-1~deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/openssl@3.0.15-1~deb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-13176?s=debian&n=openssl&ns=debian&t=deb&osn=debian&osv=12&vr=%3C3.0.16-1%7Edeb12u1"><img alt="medium : CVE--2024--13176" src="https://img.shields.io/badge/CVE--2024--13176-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.0.16-1~deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.16-1~deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>openssh</strong> <code>1:9.2p1-2+deb12u5</code> (deb)</summary>

<small><code>pkg:deb/debian/openssh@1%3A9.2p1-2%2Bdeb12u5?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-32728?s=debian&n=openssh&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1%3A9.2p1-2%2Bdeb12u6"><img alt="medium : CVE--2025--32728" src="https://img.shields.io/badge/CVE--2025--32728-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:9.2p1-2+deb12u6</code></td></tr>
<tr><td>Fixed version</td><td><code>1:9.2p1-2+deb12u6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In sshd in OpenSSH before 10.0, the DisableForwarding directive does not adhere to the documentation stating that it disables X11 and agent forwarding.

---
- openssh 1:10.0p1-1 (bug https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=1102603)
[bookworm] - openssh 1:9.2p1-2+deb12u6
https://lists.mindrot.org/pipermail/openssh-unix-dev/2025-April/041879.html
Fixed by: https://github.com/openssh/openssh-portable/commit/fc86875e6acb36401dfc1dfb6b628a9d1460f367 (V_10_0_P1)

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
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>xz-utils</strong> <code>5.4.1-0.2</code> (deb)</summary>

<small><code>pkg:deb/debian/xz-utils@5.4.1-0.2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-31115?s=debian&n=xz-utils&ns=debian&t=deb&osn=debian&osv=12&vr=%3C5.4.1-1"><img alt="low : CVE--2025--31115" src="https://img.shields.io/badge/CVE--2025--31115-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.4.1-1</code></td></tr>
<tr><td>Fixed version</td><td><code>5.4.1-1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.095%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>gcc-12</strong> <code>12.2.0-14</code> (deb)</summary>

<small><code>pkg:deb/debian/gcc-12@12.2.0-14?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-4039?s=debian&n=gcc-12&ns=debian&t=deb&osn=debian&osv=12&vr=%3C12.2.0-14%2Bdeb12u1"><img alt="low : CVE--2023--4039" src="https://img.shields.io/badge/CVE--2023--4039-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><12.2.0-14+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>12.2.0-14+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.149%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>37th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>subversion</strong> <code>1.14.2-4</code> (deb)</summary>

<small><code>pkg:deb/debian/subversion@1.14.2-4?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-46901?s=debian&n=subversion&ns=debian&t=deb&osn=debian&osv=12&vr=%3C1.14.2-4%2Bdeb12u1"><img alt="low : CVE--2024--46901" src="https://img.shields.io/badge/CVE--2024--46901-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.14.2-4+deb12u1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.14.2-4+deb12u1</code></td></tr>
<tr><td>EPSS Score</td><td><code>5.579%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.36.0-7+deb12u1</code> (deb)</summary>

<small><code>pkg:deb/debian/perl@5.36.0-7%2Bdeb12u1?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-56406?s=debian&n=perl&ns=debian&t=deb&osn=debian&osv=12&vr=%3C5.36.0-7%2Bdeb12u2"><img alt="low : CVE--2024--56406" src="https://img.shields.io/badge/CVE--2024--56406-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.36.0-7+deb12u2</code></td></tr>
<tr><td>Fixed version</td><td><code>5.36.0-7+deb12u2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.175%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>40th percentile</code></td></tr>
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
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>imagemagick</strong> <code>8:6.9.11.60+dfsg-1.6+deb12u2</code> (deb)</summary>

<small><code>pkg:deb/debian/imagemagick@8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u2?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-43965?s=debian&n=imagemagick&ns=debian&t=deb&osn=debian&osv=12&vr=%3C8%3A6.9.11.60%2Bdfsg-1.6%2Bdeb12u3"><img alt="low : CVE--2025--43965" src="https://img.shields.io/badge/CVE--2025--43965-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><8:6.9.11.60+dfsg-1.6+deb12u3</code></td></tr>
<tr><td>Fixed version</td><td><code>8:6.9.11.60+dfsg-1.6+deb12u3</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In MIFF image processing in ImageMagick before 7.1.1-44, image depth is mishandled after SetQuantumFormat is used.

---
- imagemagick 8:7.1.1.46+dfsg1-1
[bookworm] - imagemagick 8:6.9.11.60+dfsg-1.6+deb12u3
Fixed by: https://github.com/ImageMagick/ImageMagick/commit/bac413a26073923d3ffb258adaab07fb3fe8fdc9 (7.1.1-44)
Fixed by: https://github.com/ImageMagick/ImageMagick6/commit/c99cbc8d8663248bf353cd9042b04d7936e7587a (6.9.13-22)

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
<tr><td>EPSS Score</td><td><code>5.579%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>glib2.0</strong> <code>2.74.6-2+deb12u5</code> (deb)</summary>

<small><code>pkg:deb/debian/glib2.0@2.74.6-2%2Bdeb12u5?os_distro=bookworm&os_name=debian&os_version=12</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-3360?s=debian&n=glib2.0&ns=debian&t=deb&osn=debian&osv=12&vr=%3C2.74.6-2%2Bdeb12u6"><img alt="low : CVE--2025--3360" src="https://img.shields.io/badge/CVE--2025--3360-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.74.6-2+deb12u6</code></td></tr>
<tr><td>Fixed version</td><td><code>2.74.6-2+deb12u6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.079%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GLib. An integer overflow and buffer under-read occur when parsing a long invalid ISO 8601 timestamp with the g_date_time_new_from_iso8601() function.

---
- glib2.0 2.84.1-1
[bookworm] - glib2.0 2.74.6-2+deb12u6
https://gitlab.gnome.org/GNOME/glib/-/issues/3647
https://gitlab.gnome.org/GNOME/glib/-/commit/8d60d7dc168aee73a15eb5edeb2deaf196d96114 (2.83.4)
https://gitlab.gnome.org/GNOME/glib/-/commit/2fa1e183613bf58d31151ecaceab91607ccc0c6d (2.83.4)
https://gitlab.gnome.org/GNOME/glib/-/commit/0b225e7cd80801aca6e627696064d1698aaa85e7 (2.83.4)
https://gitlab.gnome.org/GNOME/glib/-/commit/3672764a17c26341ab8224dcaddf3e7cad699443 (2.83.4)
https://gitlab.gnome.org/GNOME/glib/-/commit/0ffdbebd9ab3246958e14ab33bd0c65b6f05fd13 (2.83.4)
Introduced by https://gitlab.gnome.org/GNOME/glib/-/commit/491f835c17d200ede52c823ab1566c493479cdc1 (2.55.0)

</blockquote>
</details>
</details></td></tr>
</table>