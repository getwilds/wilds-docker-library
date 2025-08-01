# Vulnerability Report for getwilds/delly:latest

Report generated on 2025-08-01 08:08:16 PST

<h2>:mag: Vulnerabilities of <code>getwilds/delly:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/delly:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:5974decd65fb3bdc25102e3b7d7ac75e6a12f5e19fbd5771af3a22b8c88c2d0a</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 11" src="https://img.shields.io/badge/medium-11-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/low-0-lightgrey"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>37 MB</td></tr>
<tr><td>packages</td><td>168</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libssh</strong> <code>0.9.6-2ubuntu0.22.04.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libssh@0.9.6-2ubuntu0.22.04.3?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-5372?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.4"><img alt="medium : CVE--2025--5372" src="https://img.shields.io/badge/CVE--2025--5372-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in libssh versions built with OpenSSL versions older than 3.0, specifically in the ssh_kdf() function responsible for key derivation. Due to inconsistent interpretation of return values where OpenSSL uses 0 to indicate failure and libssh uses 0 for success—the function may mistakenly return a success status even when key derivation fails. This results in uninitialized cryptographic key buffers being used in subsequent communication, potentially compromising SSH sessions' confidentiality, integrity, and availability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-5318?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.4"><img alt="medium : CVE--2025--5318" src="https://img.shields.io/badge/CVE--2025--5318-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the libssh library. An out-of-bounds read can be triggered in the sftp_handle function due to an incorrect comparison check that permits the function to access memory beyond the valid handle list and to return an invalid pointer, which is used in further processing. This vulnerability allows an authenticated remote attacker to potentially read unintended memory regions, exposing sensitive information or affect service behavior.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4878?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.4"><img alt="medium : CVE--2025--4878" src="https://img.shields.io/badge/CVE--2025--4878-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in libssh, where an uninitialized variable exists under certain conditions in the privatekey_from_file() function. This flaw can be triggered if the file specified by the filename doesn't exist and may lead to possible signing failures or heap corruption.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4877?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.4"><img alt="medium : CVE--2025--4877" src="https://img.shields.io/badge/CVE--2025--4877-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.4</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Write beyond bounds in binary to base64 conversion functions

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.7.3-4ubuntu1.6</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnutls28@3.7.3-4ubuntu1.6?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6395?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.7"><img alt="medium : CVE--2025--6395" src="https://img.shields.io/badge/CVE--2025--6395-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A NULL pointer dereference flaw was found in the GnuTLS software in _gnutls_figure_common_ciphersuite(). When it reads certain settings from a template file, it can allow an attacker to cause an out-of-bounds (OOB) NULL pointer write, resulting in memory corruption and a denial of service (DoS) that could crash the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-32990?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.7"><img alt="medium : CVE--2025--32990" src="https://img.shields.io/badge/CVE--2025--32990-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.059%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-buffer-overflow (off-by-one) flaw was found in the GnuTLS software in the template parsing logic within the certtool utility. When it reads certain settings from a template file, it allows an attacker to cause an out-of-bounds (OOB) NULL pointer write, resulting in memory corruption and a denial-of-service (DoS) that could potentially crash the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-32989?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.7"><img alt="medium : CVE--2025--32989" src="https://img.shields.io/badge/CVE--2025--32989-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-buffer-overread vulnerability was found in GnuTLS in how it handles the Certificate Transparency (CT) Signed Certificate Timestamp (SCT) extension during X.509 certificate parsing. This flaw allows a malicious user to create a certificate containing a malformed SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) that contains sensitive data. This issue leads to the exposure of confidential information when GnuTLS verifies certificates from certain websites when the certificate (SCT) is not checked correctly.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-32988?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.7"><img alt="medium : CVE--2025--32988" src="https://img.shields.io/badge/CVE--2025--32988-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GnuTLS. A double-free vulnerability exists in GnuTLS due to incorrect ownership handling in the export logic of Subject Alternative Name (SAN) entries containing an otherName. If the type-id OID is invalid or malformed, GnuTLS will call asn1_delete_structure() on an ASN.1 node it does not own, leading to a double-free condition when the parent function or caller later attempts to free the same structure.  This vulnerability can be triggered using only public GnuTLS APIs and may result in denial of service or memory corruption, depending on allocator behavior.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.34.0-3ubuntu1.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/perl@5.34.0-3ubuntu1.4?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-40909?s=ubuntu&n=perl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.34.0-3ubuntu1.5"><img alt="medium : CVE--2025--40909" src="https://img.shields.io/badge/CVE--2025--40909-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.34.0-3ubuntu1.5</code></td></tr>
<tr><td>Fixed version</td><td><code>5.34.0-3ubuntu1.5</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.006%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Perl threads have a working directory race condition where file operations may target unintended paths.  If a directory handle is open at thread creation, the process-wide current working directory is temporarily changed in order to clone that handle for the new thread, which is visible from any third (or more) thread already running.  This may lead to unintended operations such as loading code or accessing files from unexpected locations, which a local attacker may be able to exploit.  The bug was introduced in commit 11a11ecf4bea72b17d250cfb43c897be1341861e and released in Perl version 5.13.6

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pam</strong> <code>1.4.0-11ubuntu2.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pam@1.4.0-11ubuntu2.5?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6020?s=ubuntu&n=pam&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.4.0-11ubuntu2.6"><img alt="medium : CVE--2025--6020" src="https://img.shields.io/badge/CVE--2025--6020-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.4.0-11ubuntu2.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1.4.0-11ubuntu2.6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without proper protection, allowing local users to elevate their privileges to root via multiple symlink attacks and race conditions.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>systemd</strong> <code>249.11-0ubuntu3.15</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/systemd@249.11-0ubuntu3.15?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4598?s=ubuntu&n=systemd&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C249.11-0ubuntu3.16"><img alt="medium : CVE--2025--4598" src="https://img.shields.io/badge/CVE--2025--4598-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><249.11-0ubuntu3.16</code></td></tr>
<tr><td>Fixed version</td><td><code>249.11-0ubuntu3.16</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in systemd-coredump. This flaw allows an attacker to force a SUID process to crash and replace it with a non-SUID binary to access the original's privileged process coredump, allowing the attacker to read sensitive data, such as /etc/shadow content, loaded by the original process.  A SUID binary or process has a special type of permission, which allows the process to run with the file owner's permissions, regardless of the user executing the binary. This allows the process to access more restricted data than unprivileged users or processes would be able to. An attacker can leverage this flaw by forcing a SUID process to crash and force the Linux kernel to recycle the process PID before systemd-coredump can analyze the /proc/pid/auxv file. If the attacker wins the race condition, they gain access to the original's SUID process coredump file. They can read sensitive content loaded into memory by the original binary, affecting data confidentiality.

</blockquote>
</details>
</details></td></tr>
</table>