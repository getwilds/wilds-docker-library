# Vulnerability Report for getwilds/rnaseqc:2.4.2

Report generated on 2025-07-01 09:54:33 PST

<h2>:mag: Vulnerabilities of <code>getwilds/rnaseqc:2.4.2</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/rnaseqc:2.4.2</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:548c5ee86ef9c5b9de51a1083e2c8a974c22fbb715619fb27ae5f8f97c886710</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 16" src="https://img.shields.io/badge/medium-16-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/low-0-lightgrey"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>342 MB</td></tr>
<tr><td>packages</td><td>432</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.46.1-1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/sqlite3@3.46.1-1?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-29087?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C3.46.1-1ubuntu0.2"><img alt="medium 7.5: CVE--2025--29087" src="https://img.shields.io/badge/CVE--2025--29087-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.46.1-1ubuntu0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>3.46.1-1ubuntu0.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In SQLite 3.44.0 through 3.49.0 before 3.49.1, the concat_ws() SQL function can cause memory to be written beyond the end of a malloc-allocated buffer. If the separator argument is attacker-controlled and has a large string (e.g., 2MB or more), an integer overflow occurs in calculating the size of the result buffer, and thus malloc may not allocate enough memory.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-3277?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C3.46.1-1ubuntu0.2"><img alt="medium : CVE--2025--3277" src="https://img.shields.io/badge/CVE--2025--3277-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.46.1-1ubuntu0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>3.46.1-1ubuntu0.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.089%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An integer overflow can be triggered in SQLite’s `concat_ws()` function. The resulting, truncated integer is then used to allocate a buffer. When SQLite then writes the resulting string to the buffer, it uses the original, untruncated size and thus a wild Heap Buffer overflow of size ~4GB can be triggered. This can result in arbitrary code execution.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-29088?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C3.46.1-1ubuntu0.2"><img alt="medium : CVE--2025--29088" src="https://img.shields.io/badge/CVE--2025--29088-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.46.1-1ubuntu0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>3.46.1-1ubuntu0.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In SQLite 3.49.0 before 3.49.1, certain argument values to sqlite3_db_config (in the C-language API) can cause a denial of service (application crash). An sz*nBig multiplication is not cast to a 64-bit integer, and consequently some memory allocations may be incorrect.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>openjdk-17</strong> <code>17.0.14+7-1~24.10</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openjdk-17@17.0.14%2B7-1~24.10?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-30698?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C17.0.15%2B6%7Eus1-0ubuntu1%7E24.10"><img alt="medium : CVE--2025--30698" src="https://img.shields.io/badge/CVE--2025--30698-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.15+6~us1-0ubuntu1~24.10</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.15+6~us1-0ubuntu1~24.10</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.063%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 2D).  Supported versions that are affected are Oracle Java SE: 8u441, 8u441-perf, 11.0.26, 17.0.14, 21.0.6, 24; Oracle GraalVM for JDK: 17.0.14, 21.0.6, 24; Oracle GraalVM Enterprise Edition: 20.3.17 and  21.3.13. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized read access to a subset of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.6 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-30691?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C17.0.15%2B6%7Eus1-0ubuntu1%7E24.10"><img alt="medium : CVE--2025--30691" src="https://img.shields.io/badge/CVE--2025--30691-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.15+6~us1-0ubuntu1~24.10</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.15+6~us1-0ubuntu1~24.10</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 21.0.6, 24; Oracle GraalVM for JDK: 21.0.6 and  24. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE.  Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE accessible data as well as  unauthorized read access to a subset of Oracle Java SE accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 4.8 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21587?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C17.0.15%2B6%7Eus1-0ubuntu1%7E24.10"><img alt="medium : CVE--2025--21587" src="https://img.shields.io/badge/CVE--2025--21587-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.15+6~us1-0ubuntu1~24.10</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.15+6~us1-0ubuntu1~24.10</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.070%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE:8u441, 8u441-perf, 11.0.26, 17.0.14, 21.0.6, 24; Oracle GraalVM for JDK:17.0.14, 21.0.6, 24; Oracle GraalVM Enterprise Edition:20.3.17 and  21.3.13. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 7.4 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>glibc</strong> <code>2.40-1ubuntu3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glibc@2.40-1ubuntu3?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-0395?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C2.40-1ubuntu3.1"><img alt="medium : CVE--2025--0395" src="https://img.shields.io/badge/CVE--2025--0395-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.40-1ubuntu3.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.40-1ubuntu3.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.191%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When the assert() function in the GNU C Library versions 2.13 to 2.40 fails, it does not allocate enough space for the assertion failure message string and size information, which may lead to a buffer overflow if the message string size aligns to page size.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnupg2</strong> <code>2.4.4-2ubuntu18</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnupg2@2.4.4-2ubuntu18?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-30258?s=ubuntu&n=gnupg2&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C2.4.4-2ubuntu18.2"><img alt="medium : CVE--2025--30258" src="https://img.shields.io/badge/CVE--2025--30258-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.4.4-2ubuntu18.2</code></td></tr>
<tr><td>Fixed version</td><td><code>2.4.4-2ubuntu18.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.012%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In GnuPG before 2.5.5, if a user chooses to import a certificate with certain crafted subkey data that lacks a valid backsig or that has incorrect usage flags, the user loses the ability to verify signatures made from certain other signing keys, aka a "verification DoS."

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.8.6-2ubuntu1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnutls28@3.8.6-2ubuntu1?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12243?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C3.8.6-2ubuntu1.1"><img alt="medium : CVE--2024--12243" src="https://img.shields.io/badge/CVE--2024--12243-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.8.6-2ubuntu1.1</code></td></tr>
<tr><td>Fixed version</td><td><code>3.8.6-2ubuntu1.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.623%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>69th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GnuTLS, which relies on libtasn1 for ASN.1 data processing. Due to an inefficient algorithm in libtasn1, decoding certain DER-encoded certificate data can take excessive time, leading to increased resource consumption. This flaw allows a remote attacker to send a specially crafted certificate, causing GnuTLS to become unresponsive or slow, resulting in a denial-of-service condition.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libcap2</strong> <code>1:2.66-5ubuntu3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libcap2@1%3A2.66-5ubuntu3?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-1390?s=ubuntu&n=libcap2&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C1%3A2.66-5ubuntu3.1"><img alt="medium : CVE--2025--1390" src="https://img.shields.io/badge/CVE--2025--1390-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:2.66-5ubuntu3.1</code></td></tr>
<tr><td>Fixed version</td><td><code>1:2.66-5ubuntu3.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The PAM module pam_cap.so of libcap configuration supports group names starting with “@”, during actual parsing, configurations not starting with “@” are incorrectly recognized as group names. This may result in nonintended users being granted an inherited capability set, potentially leading to security risks. Attackers can exploit this vulnerability to achieve local privilege escalation on systems where /etc/security/capability.conf is used to configure user inherited privileges by constructing specific usernames.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pam</strong> <code>1.5.3-7ubuntu2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pam@1.5.3-7ubuntu2?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6020?s=ubuntu&n=pam&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C1.5.3-7ubuntu2.3"><img alt="medium : CVE--2025--6020" src="https://img.shields.io/badge/CVE--2025--6020-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.5.3-7ubuntu2.3</code></td></tr>
<tr><td>Fixed version</td><td><code>1.5.3-7ubuntu2.3</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without proper protection, allowing local users to elevate their privileges to root via multiple symlink attacks and race conditions.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>systemd</strong> <code>256.5-2ubuntu3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/systemd@256.5-2ubuntu3?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4598?s=ubuntu&n=systemd&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C256.5-2ubuntu3.3"><img alt="medium : CVE--2025--4598" src="https://img.shields.io/badge/CVE--2025--4598-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><256.5-2ubuntu3.3</code></td></tr>
<tr><td>Fixed version</td><td><code>256.5-2ubuntu3.3</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in systemd-coredump. This flaw allows an attacker to force a SUID process to crash and replace it with a non-SUID binary to access the original's privileged process coredump, allowing the attacker to read sensitive data, such as /etc/shadow content, loaded by the original process.  A SUID binary or process has a special type of permission, which allows the process to run with the file owner's permissions, regardless of the user executing the binary. This allows the process to access more restricted data than unprivileged users or processes would be able to. An attacker can leverage this flaw by forcing a SUID process to crash and force the Linux kernel to recycle the process PID before systemd-coredump can analyze the /proc/pid/auxv file. If the attacker wins the race condition, they gain access to the original's SUID process coredump file. They can read sensitive content loaded into memory by the original binary, affecting data confidentiality.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>glib2.0</strong> <code>2.82.1-0ubuntu1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glib2.0@2.82.1-0ubuntu1?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4373?s=ubuntu&n=glib2.0&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C2.82.1-0ubuntu1.1"><img alt="medium : CVE--2025--4373" src="https://img.shields.io/badge/CVE--2025--4373-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.82.1-0ubuntu1.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.82.1-0ubuntu1.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GLib, which is vulnerable to an integer overflow in the g_string_insert_unichar() function. When the position at which to insert the character is large, the position will overflow, leading to a buffer underwrite.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.38.2-5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/perl@5.38.2-5?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-56406?s=ubuntu&n=perl&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C5.38.2-5ubuntu0.1"><img alt="medium : CVE--2024--56406" src="https://img.shields.io/badge/CVE--2024--56406-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.38.2-5ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>5.38.2-5ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.050%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap buffer overflow vulnerability was discovered in Perl.  Release branches 5.34, 5.36, 5.38 and 5.40 are affected, including development versions from 5.33.1 through 5.41.10.  When there are non-ASCII bytes in the left-hand-side of the `tr` operator, `S_do_trans_invmap` can overflow the destination pointer `d`.  $ perl -e '$_ = "\x{FF}" x 1000000; tr/\xFF/\x{100}/;' Segmentation fault (core dumped)  It is believed that this vulnerability can enable Denial of Service and possibly Code Execution attacks on platforms that lack sufficient defenses.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>xz-utils</strong> <code>5.6.2-2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/xz-utils@5.6.2-2?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-31115?s=ubuntu&n=xz-utils&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C5.6.2-2ubuntu0.2"><img alt="medium : CVE--2025--31115" src="https://img.shields.io/badge/CVE--2025--31115-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.6.2-2ubuntu0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>5.6.2-2ubuntu0.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.095%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

XZ Utils provide a general-purpose data-compression library plus command-line tools. In XZ Utils 5.3.3alpha to 5.8.0, the multithreaded .xz decoder in liblzma has a bug where invalid input can at least result in a crash. The effects include heap use after free and writing to an address based on the null pointer plus an offset. Applications and libraries that use the lzma_stream_decoder_mt function are affected. The bug has been fixed in XZ Utils 5.8.1, and the fix has been committed to the v5.4, v5.6, v5.8, and master branches in the xz Git repository. No new release packages will be made from the old stable branches, but a standalone patch is available that applies to all affected releases.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libtasn1-6</strong> <code>4.19.0-3build1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libtasn1-6@4.19.0-3build1?os_distro=oracular&os_name=ubuntu&os_version=24.10</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12133?s=ubuntu&n=libtasn1-6&ns=ubuntu&t=deb&osn=ubuntu&osv=24.10&vr=%3C4.19.0-3ubuntu0.24.10.1"><img alt="medium : CVE--2024--12133" src="https://img.shields.io/badge/CVE--2024--12133-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.19.0-3ubuntu0.24.10.1</code></td></tr>
<tr><td>Fixed version</td><td><code>4.19.0-3ubuntu0.24.10.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.271%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>50th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw in libtasn1 causes inefficient handling of specific certificate data. When processing a large number of elements in a certificate, libtasn1 takes much longer than expected, which can slow down or even crash the system. This flaw allows an attacker to send a specially crafted certificate, causing a denial of service attack.

</blockquote>
</details>
</details></td></tr>
</table>