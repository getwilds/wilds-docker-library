# Vulnerability Report for getwilds/sra-tools:latest

Report generated on 2025-08-01 08:19:33 PST

<h2>:mag: Vulnerabilities of <code>getwilds/sra-tools:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/sra-tools:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:23751f1a94fa53e38f2fa661e6166ad254ab351e11e0af6d3209679497dad124</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/high-1-e25d68"/> <img alt="medium: 15" src="https://img.shields.io/badge/medium-15-fbb552"/> <img alt="low: 5" src="https://img.shields.io/badge/low-5-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>598 MB</td></tr>
<tr><td>packages</td><td>239</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>setuptools</strong> <code>74.1.2</code> (pypi)</summary>

<small><code>pkg:pypi/setuptools@74.1.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-47273?s=github&n=setuptools&t=pypi&vr=%3C78.1.1"><img alt="high 7.7: CVE--2025--47273" src="https://img.shields.io/badge/CVE--2025--47273-lightgrey?label=high%207.7&labelColor=e25d68"/></a> <i>Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')</i>

<table>
<tr><td>Affected range</td><td><code><78.1.1</code></td></tr>
<tr><td>Fixed version</td><td><code>78.1.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:P</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.139%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>krb5</strong> <code>1.17-6ubuntu4.7</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/krb5@1.17-6ubuntu4.7?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-3596?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1.17-6ubuntu4.8"><img alt="medium 9.0: CVE--2024--3596" src="https://img.shields.io/badge/CVE--2024--3596-lightgrey?label=medium%209.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.17-6ubuntu4.8</code></td></tr>
<tr><td>Fixed version</td><td><code>1.17-6ubuntu4.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.736%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>72nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

RADIUS Protocol under RFC 2865 is susceptible to forgery attacks by a local attacker who can modify any valid Response (Access-Accept, Access-Reject, or Access-Challenge) to any other response using a chosen-prefix collision attack against MD5 Response Authenticator signature.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-3576?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1.17-6ubuntu4.11"><img alt="medium : CVE--2025--3576" src="https://img.shields.io/badge/CVE--2025--3576-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.17-6ubuntu4.11</code></td></tr>
<tr><td>Fixed version</td><td><code>1.17-6ubuntu4.11</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the MIT Kerberos implementation allows GSSAPI-protected messages using RC4-HMAC-MD5 to be spoofed due to weaknesses in the MD5 checksum design. If RC4 is preferred over stronger encryption types, an attacker could exploit MD5 collisions to forge message integrity codes. This may lead to unauthorized message tampering.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-24528?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1.17-6ubuntu4.9"><img alt="medium : CVE--2025--24528" src="https://img.shields.io/badge/CVE--2025--24528-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.17-6ubuntu4.9</code></td></tr>
<tr><td>Fixed version</td><td><code>1.17-6ubuntu4.9</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In MIT krb5 release 1.7 and later with incremental propagation enabled, an authenticated attacker can cause kadmind to write beyond the end of the mapped region for the iprop log file, likely causing a process crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26461?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1.17-6ubuntu4.9"><img alt="low : CVE--2024--26461" src="https://img.shields.io/badge/CVE--2024--26461-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.17-6ubuntu4.9</code></td></tr>
<tr><td>Fixed version</td><td><code>1.17-6ubuntu4.9</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.081%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak vulnerability in /krb5/src/lib/gssapi/krb5/k5sealv3.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26458?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1.17-6ubuntu4.9"><img alt="low : CVE--2024--26458" src="https://img.shields.io/badge/CVE--2024--26458-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.17-6ubuntu4.9</code></td></tr>
<tr><td>Fixed version</td><td><code>1.17-6ubuntu4.9</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.206%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>43rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Kerberos 5 (aka krb5) 1.21.2 contains a memory leak in /krb5/src/lib/rpc/pmap_rmt.c.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>git</strong> <code>1:2.25.1-1ubuntu3.13</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/git@1%3A2.25.1-1ubuntu3.13?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-52006?s=ubuntu&n=git&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1%3A2.25.1-1ubuntu3.14"><img alt="medium : CVE--2024--52006" src="https://img.shields.io/badge/CVE--2024--52006-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:2.25.1-1ubuntu3.14</code></td></tr>
<tr><td>Fixed version</td><td><code>1:2.25.1-1ubuntu3.14</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.178%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>40th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. Git defines a line-based protocol that is used to exchange information between Git and Git credential helpers. Some ecosystems (most notably, .NET and node.js) interpret single Carriage Return characters as newlines, which renders the protections against CVE-2020-5260 incomplete for credential helpers that treat Carriage Returns in this way. This issue has been addressed in commit `b01b9b8` which is included in release versions v2.48.1, v2.47.2, v2.46.3, v2.45.3, v2.44.3, v2.43.6, v2.42.4, v2.41.3, and v2.40.4. Users are advised to upgrade. Users unable to upgrade should avoid cloning from untrusted URLs, especially recursive clones.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50349?s=ubuntu&n=git&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1%3A2.25.1-1ubuntu3.14"><img alt="medium : CVE--2024--50349" src="https://img.shields.io/badge/CVE--2024--50349-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:2.25.1-1ubuntu3.14</code></td></tr>
<tr><td>Fixed version</td><td><code>1:2.25.1-1ubuntu3.14</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.097%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides both high-level operations and full access to internals. When Git asks for credentials via a terminal prompt (i.e. without using any credential helper), it prints out the host name for which the user is expected to provide a username and/or a password. At this stage, any URL-encoded parts have been decoded already, and are printed verbatim. This allows attackers to craft URLs that contain ANSI escape sequences that the terminal interpret to confuse users e.g. into providing passwords for trusted Git hosting sites when in fact they are then sent to untrusted sites that are under the attacker's control. This issue has been patch via commits `7725b81` and `c903985` which are included in release versions v2.48.1, v2.47.2, v2.46.3, v2.45.3, v2.44.3, v2.43.6, v2.42.4, v2.41.3, and v2.40.4. Users are advised to upgrade. Users unable to upgrade should avoid cloning from untrusted URLs, especially recursive clones.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>glibc</strong> <code>2.31-0ubuntu9.16</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glibc@2.31-0ubuntu9.16?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4802?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C2.31-0ubuntu9.18"><img alt="medium : CVE--2025--4802" src="https://img.shields.io/badge/CVE--2025--4802-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.31-0ubuntu9.18</code></td></tr>
<tr><td>Fixed version</td><td><code>2.31-0ubuntu9.18</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Untrusted LD_LIBRARY_PATH environment variable vulnerability in the GNU C Library version 2.27 to 2.38 allows attacker controlled loading of dynamically shared library in statically compiled setuid binaries that call dlopen (including internal dlopen calls after setlocale or calls to NSS functions such as getaddrinfo).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-0395?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C2.31-0ubuntu9.17"><img alt="medium : CVE--2025--0395" src="https://img.shields.io/badge/CVE--2025--0395-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.31-0ubuntu9.17</code></td></tr>
<tr><td>Fixed version</td><td><code>2.31-0ubuntu9.17</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.271%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>50th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When the assert() function in the GNU C Library versions 2.13 to 2.40 fails, it does not allocate enough space for the assertion failure message string and size information, which may lead to a buffer overflow if the message string size aligns to page size.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>urllib3</strong> <code>2.2.3</code> (pypi)</summary>

<small><code>pkg:pypi/urllib3@2.2.3</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-50182?s=github&n=urllib3&t=pypi&vr=%3E%3D2.2.0%2C%3C2.5.0"><img alt="medium 5.3: CVE--2025--50182" src="https://img.shields.io/badge/CVE--2025--50182-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>URL Redirection to Untrusted Site ('Open Redirect')</i>

<table>
<tr><td>Affected range</td><td><code>>=2.2.0<br/><2.5.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.5.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

urllib3 [supports](https://urllib3.readthedocs.io/en/2.4.0/reference/contrib/emscripten.html) being used in a Pyodide runtime utilizing the [JavaScript Fetch API](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API) or falling back on [XMLHttpRequest](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest). This means you can use Python libraries to make HTTP requests from your browser or Node.js. Additionally, urllib3 provides [a mechanism](https://urllib3.readthedocs.io/en/2.4.0/user-guide.html#retrying-requests) to control redirects.

However, the `retries` and `redirect` parameters are ignored with Pyodide; the runtime itself determines redirect behavior.


## Affected usages

Any code which relies on urllib3 to control the number of redirects for an HTTP request in a Pyodide runtime.


## Impact

Redirects are often used to exploit SSRF vulnerabilities. An application attempting to mitigate SSRF or open redirect vulnerabilities by disabling redirects may remain vulnerable if a Pyodide runtime redirect mechanism is unsuitable.


## Remediation

If you use urllib3 in Node.js, upgrade to a patched version of urllib3.

Unfortunately, browsers provide no suitable way which urllib3 can use: `XMLHttpRequest` provides no control over redirects, the Fetch API returns `opaqueredirect` responses lacking data when redirects are controlled manually. Expect default browser behavior for redirects.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-50181?s=github&n=urllib3&t=pypi&vr=%3C2.5.0"><img alt="medium 5.3: CVE--2025--50181" src="https://img.shields.io/badge/CVE--2025--50181-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>URL Redirection to Untrusted Site ('Open Redirect')</i>

<table>
<tr><td>Affected range</td><td><code><2.5.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.5.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

urllib3 handles redirects and retries using the same mechanism, which is controlled by the `Retry` object. The most common way to disable redirects is at the request level, as follows:

```python
resp = urllib3.request("GET", "https://httpbin.org/redirect/1", redirect=False)
print(resp.status)
# 302
```

However, it is also possible to disable redirects, for all requests, by instantiating a `PoolManager` and specifying `retries` in a way that disable redirects:

```python
import urllib3

http = urllib3.PoolManager(retries=0)  # should raise MaxRetryError on redirect
http = urllib3.PoolManager(retries=urllib3.Retry(redirect=0))  # equivalent to the above
http = urllib3.PoolManager(retries=False)  # should return the first response

resp = http.request("GET", "https://httpbin.org/redirect/1")
```

However, the `retries` parameter is currently ignored, which means all the above examples don't disable redirects.

## Affected usages

Passing `retries` on `PoolManager` instantiation to disable redirects or restrict their number.

By default, requests and botocore users are not affected.

## Impact

Redirects are often used to exploit SSRF vulnerabilities. An application attempting to mitigate SSRF or open redirect vulnerabilities by disabling redirects at the PoolManager level will remain vulnerable.

## Remediation

You can remediate this vulnerability with the following steps:

 * Upgrade to a patched version of urllib3. If your organization would benefit from the continued support of urllib3 1.x, please contact [sethmichaellarson@gmail.com](mailto:sethmichaellarson@gmail.com) to discuss sponsorship or contribution opportunities.
 * Disable redirects at the `request()` level instead of the `PoolManager()` level.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnupg2</strong> <code>2.2.19-3ubuntu2.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnupg2@2.2.19-3ubuntu2.2?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-30258?s=ubuntu&n=gnupg2&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C2.2.19-3ubuntu2.4"><img alt="medium : CVE--2025--30258" src="https://img.shields.io/badge/CVE--2025--30258-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.2.19-3ubuntu2.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.2.19-3ubuntu2.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In GnuPG before 2.5.5, if a user chooses to import a certificate with certain crafted subkey data that lacks a valid backsig or that has incorrect usage flags, the user loses the ability to verify signatures made from certain other signing keys, aka a "verification DoS."

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.6.13-2ubuntu1.11</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnutls28@3.6.13-2ubuntu1.11?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12243?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C3.6.13-2ubuntu1.12"><img alt="medium : CVE--2024--12243" src="https://img.shields.io/badge/CVE--2024--12243-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.6.13-2ubuntu1.12</code></td></tr>
<tr><td>Fixed version</td><td><code>3.6.13-2ubuntu1.12</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.745%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>72nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GnuTLS, which relies on libtasn1 for ASN.1 data processing. Due to an inefficient algorithm in libtasn1, decoding certain DER-encoded certificate data can take excessive time, leading to increased resource consumption. This flaw allows a remote attacker to send a specially crafted certificate, causing GnuTLS to become unresponsive or slow, resulting in a denial-of-service condition.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.31.1-4ubuntu0.6</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/sqlite3@3.31.1-4ubuntu0.6?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-29088?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C3.31.1-4ubuntu0.7"><img alt="medium : CVE--2025--29088" src="https://img.shields.io/badge/CVE--2025--29088-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.31.1-4ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.31.1-4ubuntu0.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In SQLite 3.49.0 before 3.49.1, certain argument values to sqlite3_db_config (in the C-language API) can cause a denial of service (application crash). An sz*nBig multiplication is not cast to a 64-bit integer, and consequently some memory allocations may be incorrect.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libtasn1-6</strong> <code>4.16.0-2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libtasn1-6@4.16.0-2?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12133?s=ubuntu&n=libtasn1-6&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C4.16.0-2ubuntu0.1"><img alt="medium : CVE--2024--12133" src="https://img.shields.io/badge/CVE--2024--12133-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.16.0-2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>4.16.0-2ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.324%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>55th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw in libtasn1 causes inefficient handling of specific certificate data. When processing a large number of elements in a certificate, libtasn1 takes much longer than expected, which can slow down or even crash the system. This flaw allows an attacker to send a specially crafted certificate, causing a denial of service attack.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>requests</strong> <code>2.32.3</code> (pypi)</summary>

<small><code>pkg:pypi/requests@2.32.3</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-47081?s=github&n=requests&t=pypi&vr=%3C2.32.4"><img alt="medium 5.3: CVE--2024--47081" src="https://img.shields.io/badge/CVE--2024--47081-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Insufficiently Protected Credentials</i>

<table>
<tr><td>Affected range</td><td><code><2.32.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.32.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>expat</strong> <code>2.2.9-1ubuntu0.7</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/expat@2.2.9-1ubuntu0.7?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-50602?s=ubuntu&n=expat&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C2.2.9-1ubuntu0.8"><img alt="medium : CVE--2024--50602" src="https://img.shields.io/badge/CVE--2024--50602-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.2.9-1ubuntu0.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.2.9-1ubuntu0.8</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.054%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in libexpat before 2.6.4. There is a crash within the XML_ResumeParser function because XML_StopParser can stop/suspend an unstarted parser.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>openssl</strong> <code>1.1.1f-1ubuntu2.23</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openssl@1.1.1f-1ubuntu2.23?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-9143?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1.1.1f-1ubuntu2.24"><img alt="low : CVE--2024--9143" src="https://img.shields.io/badge/CVE--2024--9143-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.1.1f-1ubuntu2.24</code></td></tr>
<tr><td>Fixed version</td><td><code>1.1.1f-1ubuntu2.24</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.652%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>70th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: Use of the low-level GF(2^m) elliptic curve APIs with untrusted explicit values for the field polynomial can lead to out-of-bounds memory reads or writes.  Impact summary: Out of bound memory writes can lead to an application crash or even a possibility of a remote code execution, however, in all the protocols involving Elliptic Curve Cryptography that we're aware of, either only "named curves" are supported, or, if explicit curve parameters are supported, they specify an X9.62 encoding of binary (GF(2^m)) curves that can't represent problematic input values. Thus the likelihood of existence of a vulnerable application is low.  In particular, the X9.62 encoding is used for ECC keys in X.509 certificates, so problematic inputs cannot occur in the context of processing X.509 certificates.  Any problematic use-cases would have to be using an "exotic" curve encoding.  The affected APIs include: EC_GROUP_new_curve_GF2m(), EC_GROUP_new_from_params(), and various supporting BN_GF2m_*() functions.  Applications working with "exotic" explicit binary (GF(2^m)) curve parameters, that make it possible to represent invalid field polynomials with a zero constant term, via the above or similar APIs, may terminate abruptly as a result of reading or writing outside of array bounds.  Remote code execution cannot easily be ruled out.  The FIPS modules in 3.3, 3.2, 3.1 and 3.0 are not affected by this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-13176?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C1.1.1f-1ubuntu2.24"><img alt="low : CVE--2024--13176" src="https://img.shields.io/badge/CVE--2024--13176-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.1.1f-1ubuntu2.24</code></td></tr>
<tr><td>Fixed version</td><td><code>1.1.1f-1ubuntu2.24</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Issue summary: A timing side-channel which could potentially allow recovering the private key exists in the ECDSA signature computation.  Impact summary: A timing side-channel in ECDSA signature computations could allow recovering the private key by an attacker. However, measuring the timing would require either local access to the signing application or a very fast network connection with low latency.  There is a timing signal of around 300 nanoseconds when the top word of the inverted ECDSA nonce value is zero. This can happen with significant probability only for some of the supported elliptic curves. In particular the NIST P-521 curve is affected. To be able to measure this leak, the attacker process must either be located in the same physical computer or must have a very fast network connection with low latency. For that reason the severity of this vulnerability is Low.  The FIPS modules in 3.4, 3.3, 3.2, 3.1 and 3.0 are affected by this issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>curl</strong> <code>7.68.0-1ubuntu2.24</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/curl@7.68.0-1ubuntu2.24?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-11053?s=ubuntu&n=curl&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C7.68.0-1ubuntu2.25"><img alt="low : CVE--2024--11053" src="https://img.shields.io/badge/CVE--2024--11053-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><7.68.0-1ubuntu2.25</code></td></tr>
<tr><td>Fixed version</td><td><code>7.68.0-1ubuntu2.25</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.227%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When asked to both use a `.netrc` file for credentials and to follow HTTP redirects, curl could leak the password used for the first host to the followed-to host under certain circumstances.  This flaw only manifests itself if the netrc file has an entry that matches the redirect target hostname but the entry either omits just the password or omits both login and password.

</blockquote>
</details>
</details></td></tr>
</table>