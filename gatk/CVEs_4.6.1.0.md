# Vulnerability Report for getwilds/gatk:4.6.1.0

Report generated on 2025-09-01 09:00:26 PST

<h2>:mag: Vulnerabilities of <code>getwilds/gatk:4.6.1.0</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/gatk:4.6.1.0</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:08efdb45ecc3ff32610be315439bb9d61ceea8376f6a6935d7ef561cfab3261e</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 1" src="https://img.shields.io/badge/critical-1-8b1924"/> <img alt="high: 15" src="https://img.shields.io/badge/high-15-e25d68"/> <img alt="medium: 104" src="https://img.shields.io/badge/medium-104-fbb552"/> <img alt="low: 6" src="https://img.shields.io/badge/low-6-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>1.2 GB</td></tr>
<tr><td>packages</td><td>765</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.kerby/kerb-admin</strong> <code>1.0.1</code> (maven)</summary>

<small><code>pkg:maven/org.apache.kerby/kerb-admin@1.0.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-25613?s=gitlab&n=kerb-admin&ns=org.apache.kerby&t=maven&vr=%3C2.0.3"><img alt="critical 9.8: CVE--2023--25613" src="https://img.shields.io/badge/CVE--2023--25613-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><2.0.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.0.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.127%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An LDAP Injection vulnerability exists in the LdapIdentityBackend of Apache Kerby before 2.0.3. 

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 4" src="https://img.shields.io/badge/H-4-e25d68"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.google.protobuf/protobuf-java</strong> <code>3.7.1</code> (maven)</summary>

<small><code>pkg:maven/com.google.protobuf/protobuf-java@3.7.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-7254?s=github&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.25.5"><img alt="high 8.7: CVE--2024--7254" src="https://img.shields.io/badge/CVE--2024--7254-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><3.25.5</code></td></tr>
<tr><td>Fixed version</td><td><code>3.25.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.189%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>41st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
When parsing unknown fields in the Protobuf Java Lite and Full library, a maliciously crafted message can cause a StackOverflow error and lead to a program crash.

Reporter: Alexis Challande, Trail of Bits Ecosystem Security Team <ecosystem@trailofbits.com>

Affected versions: This issue affects all versions of both the Java full and lite Protobuf runtimes, as well as Protobuf for Kotlin and JRuby, which themselves use the Java Protobuf runtime.

### Severity
[CVE-2024-7254](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-7254) **High** CVSS4.0 Score 8.7 (NOTE: there may be a delay in publication)
This is a potential Denial of Service. Parsing nested groups as unknown fields with DiscardUnknownFieldsParser or Java Protobuf Lite parser, or against Protobuf map fields, creates unbounded recursions that can be abused by an attacker.

### Proof of Concept
For reproduction details, please refer to the unit tests (Protobuf Java [LiteTest](https://github.com/protocolbuffers/protobuf/blob/a037f28ff81ee45ebe008c64ab632bf5372242ce/java/lite/src/test/java/com/google/protobuf/LiteTest.java) and [CodedInputStreamTest](https://github.com/protocolbuffers/protobuf/blob/a037f28ff81ee45ebe008c64ab632bf5372242ce/java/core/src/test/java/com/google/protobuf/CodedInputStreamTest.java)) that identify the specific inputs that exercise this parsing weakness.

### Remediation and Mitigation
We have been working diligently to address this issue and have released a mitigation that is available now. Please update to the latest available versions of the following packages:
* protobuf-java (3.25.5, 4.27.5, 4.28.2)
* protobuf-javalite (3.25.5, 4.27.5, 4.28.2)
* protobuf-kotlin (3.25.5, 4.27.5, 4.28.2)
* protobuf-kotlin-lite (3.25.5, 4.27.5, 4.28.2)
* com-protobuf [JRuby gem only] (3.25.5, 4.27.5, 4.28.2)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3510?s=gitlab&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.16.3"><img alt="high 7.5: CVE--2022--3510" src="https://img.shields.io/badge/CVE--2022--3510-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><3.16.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.16.3, 3.19.6, 3.20.3, 3.21.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A parsing issue similar to CVE-2022-3171, but with Message-Type Extensions in protobuf-java core and lite versions prior to 3.21.7, 3.20.3, 3.19.6 and 3.16.3 can lead to a denial of service attack. Inputs containing multiple instances of non-repeated embedded messages with repeated or unknown fields causes objects to be converted back-n-forth between mutable and immutable forms, resulting in potentially long garbage collection pauses. We recommend updating to the versions mentioned above.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3509?s=gitlab&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.16.3"><img alt="high 7.5: CVE--2022--3509" src="https://img.shields.io/badge/CVE--2022--3509-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><3.16.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.16.3, 3.19.6, 3.20.3, 3.21.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.102%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>29th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A parsing issue similar to CVE-2022-3171, but with textformat in protobuf-java core and lite versions prior to 3.21.7, 3.20.3, 3.19.6 and 3.16.3 can lead to a denial of service attack. Inputs containing multiple instances of non-repeated embedded messages with repeated or unknown fields causes objects to be converted back-n-forth between mutable and immutable forms, resulting in potentially long garbage collection pauses. We recommend updating to the versions mentioned above.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-22569?s=github&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.16.1"><img alt="high 7.5: CVE--2021--22569" src="https://img.shields.io/badge/CVE--2021--22569-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Incorrect Behavior Order</i>

<table>
<tr><td>Affected range</td><td><code><3.16.1</code></td></tr>
<tr><td>Fixed version</td><td><code>3.16.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.353%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>57th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary

A potential Denial of Service issue in protobuf-java was discovered in the parsing procedure for binary data.

Reporter: [OSS-Fuzz](https://github.com/google/oss-fuzz)

Affected versions: All versions of Java Protobufs (including Kotlin and JRuby) prior to the versions listed below. Protobuf "javalite" users (typically Android) are not affected.

## Severity

[CVE-2021-22569](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-22569) **High** - CVSS Score: 7.5,  An implementation weakness in how unknown fields are parsed in Java. A small (~800 KB) malicious payload can occupy the parser for several minutes by creating large numbers of short-lived objects that cause frequent, repeated GC pauses.

## Proof of Concept

For reproduction details, please refer to the oss-fuzz issue that identifies the specific inputs that exercise this parsing weakness.

## Remediation and Mitigation

Please update to the latest available versions of the following packages:

- protobuf-java (3.16.1, 3.18.2, 3.19.2) 
- protobuf-kotlin (3.18.2, 3.19.2)
- google-protobuf [JRuby  gem only] (3.19.2) 


</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3171?s=github&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.16.3"><img alt="medium 5.7: CVE--2022--3171" src="https://img.shields.io/badge/CVE--2022--3171-lightgrey?label=medium%205.7&labelColor=fbb552"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><3.16.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.16.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.064%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary
A potential Denial of Service issue in `protobuf-java` core and lite was discovered in the parsing procedure for binary and text format data. Input streams containing multiple instances of non-repeated [embedded messages](http://developers.google.com/protocol-buffers/docs/encoding#embedded) with repeated or unknown fields causes objects to be converted back-n-forth between mutable and immutable forms, resulting in potentially long garbage collection pauses. 

Reporter: [OSS Fuzz](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=48771)

Affected versions: This issue affects both the Java full and lite Protobuf runtimes, as well as Protobuf for Kotlin and JRuby, which themselves use the Java Protobuf runtime.

## Severity

[CVE-2022-3171](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-3171) Medium - CVSS Score: 5.7 (NOTE: there may be a delay in publication)

## Remediation and Mitigation

Please update to the latest available versions of the following packages:

protobuf-java (3.21.7, 3.20.3, 3.19.6, 3.16.3)
protobuf-javalite (3.21.7, 3.20.3, 3.19.6, 3.16.3)
protobuf-kotlin (3.21.7, 3.20.3, 3.19.6, 3.16.3)
protobuf-kotlin-lite (3.21.7, 3.20.3, 3.19.6, 3.16.3)
google-protobuf [JRuby gem only] (3.21.7, 3.20.3, 3.19.6)


</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-22570?s=gitlab&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.15.0"><img alt="medium 5.5: CVE--2021--22570" src="https://img.shields.io/badge/CVE--2021--22570-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><3.15.0</code></td></tr>
<tr><td>Fixed version</td><td><code>3.15.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.121%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>32nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Nullptr dereference when a null char is present in a proto symbol. The symbol is parsed incorrectly, leading to an unchecked call into the proto file's name during generation of the resulting error message. Since the symbol is incorrectly parsed, the file is nullptr.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>setuptools</strong> <code>68.1.2</code> (pypi)</summary>

<small><code>pkg:pypi/setuptools@68.1.2</code></small><br/>
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

<a href="https://scout.docker.com/v/CVE-2024-6345?s=github&n=setuptools&t=pypi&vr=%3C70.0.0"><img alt="high 7.5: CVE--2024--6345" src="https://img.shields.io/badge/CVE--2024--6345-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Control of Generation of Code ('Code Injection')</i>

<table>
<tr><td>Affected range</td><td><code><70.0.0</code></td></tr>
<tr><td>Fixed version</td><td><code>70.0.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>9.839%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the `package_index` module of pypa/setuptools versions up to 69.1.1 allows for remote code execution via its download functions. These functions, which are used to download packages from URLs provided by users or retrieved from package index servers, are susceptible to code injection. If these functions are exposed to user-controlled inputs, such as package URLs, they can execute arbitrary commands on the system. The issue is fixed in version 70.0.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>net.minidev/json-smart</strong> <code>1.3.2</code> (maven)</summary>

<small><code>pkg:maven/net.minidev/json-smart@1.3.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-1370?s=github&n=json-smart&ns=net.minidev&t=maven&vr=%3C2.4.9"><img alt="high 7.5: CVE--2023--1370" src="https://img.shields.io/badge/CVE--2023--1370-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Recursion</i>

<table>
<tr><td>Affected range</td><td><code><2.4.9</code></td></tr>
<tr><td>Fixed version</td><td><code>2.4.9</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact
Affected versions of [net.minidev:json-smart](https://github.com/netplex/json-smart-v1) are vulnerable to Denial of Service (DoS) due to a StackOverflowError when parsing a deeply nested JSON array or object.

When reaching a ‘[‘ or ‘{‘ character in the JSON input, the code parses an array or an object respectively. It was discovered that the 3PP does not have any limit to the nesting of such arrays or objects. Since the parsing of nested arrays and objects is done recursively, nesting too many of them can cause stack exhaustion (stack overflow) and crash the software.

### Patches
This vulnerability was fixed in json-smart version 2.4.9, but the maintainer recommends upgrading to 2.4.10, due to a remaining bug.

### Workarounds
N/A

### References
- https://www.cve.org/CVERecord?id=CVE-2023-1370
- https://nvd.nist.gov/vuln/detail/CVE-2023-1370
- https://security.snyk.io/vuln/SNYK-JAVA-NETMINIDEV-3369748

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-31684?s=github&n=json-smart&ns=net.minidev&t=maven&vr=%3E%3D1.3.0%2C%3C1.3.3"><img alt="high 7.5: CVE--2021--31684" src="https://img.shields.io/badge/CVE--2021--31684-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Out-of-bounds Read</i>

<table>
<tr><td>Affected range</td><td><code>>=1.3.0<br/><1.3.3</code></td></tr>
<tr><td>Fixed version</td><td><code>1.3.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.068%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was discovered in the indexOf function of JSONParserByteArray in JSON Smart versions prior to 1.3.3 and 2.4.5 which causes a denial of service (DOS) via a crafted web request.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 74" src="https://img.shields.io/badge/M-74-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>linux</strong> <code>6.8.0-64.67</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@6.8.0-64.67?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-21887?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-79.79"><img alt="high : CVE--2025--21887" src="https://img.shields.io/badge/CVE--2025--21887-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-79.79</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-79.79</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ovl: fix UAF in ovl_dentry_update_reval by moving dput() in ovl_link_up  The issue was caused by dput(upper) being called before ovl_dentry_update_reval(), while upper->d_flags was still accessed in ovl_dentry_remote().  Move dput(upper) after its last use to prevent use-after-free.  BUG: KASAN: slab-use-after-free in ovl_dentry_remote fs/overlayfs/util.c:162 [inline] BUG: KASAN: slab-use-after-free in ovl_dentry_update_reval+0xd2/0xf0 fs/overlayfs/util.c:167  Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:114 print_address_description mm/kasan/report.c:377 [inline] print_report+0xc3/0x620 mm/kasan/report.c:488 kasan_report+0xd9/0x110 mm/kasan/report.c:601 ovl_dentry_remote fs/overlayfs/util.c:162 [inline] ovl_dentry_update_reval+0xd2/0xf0 fs/overlayfs/util.c:167 ovl_link_up fs/overlayfs/copy_up.c:610 [inline] ovl_copy_up_one+0x2105/0x3490 fs/overlayfs/copy_up.c:1170 ovl_copy_up_flags+0x18d/0x200 fs/overlayfs/copy_up.c:1223 ovl_rename+0x39e/0x18c0 fs/overlayfs/dir.c:1136 vfs_rename+0xf84/0x20a0 fs/namei.c:4893 ... </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21863?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 7.8: CVE--2025--21863" src="https://img.shields.io/badge/CVE--2025--21863-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  io_uring: prevent opcode speculation  sqe->opcode is used for different tables, make sure we santitise it against speculations.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21858?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 7.8: CVE--2025--21858" src="https://img.shields.io/badge/CVE--2025--21858-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  geneve: Fix use-after-free in geneve_find_dev().  syzkaller reported a use-after-free in geneve_find_dev() [0] without repro.  geneve_configure() links struct geneve_dev.next to net_generic(net, geneve_net_id)->geneve_list.  The net here could differ from dev_net(dev) if IFLA_NET_NS_PID, IFLA_NET_NS_FD, or IFLA_TARGET_NETNSID is set.  When dev_net(dev) is dismantled, geneve_exit_batch_rtnl() finally calls unregister_netdevice_queue() for each dev in the netns, and later the dev is freed.  However, its geneve_dev.next is still linked to the backend UDP socket netns.  Then, use-after-free will occur when another geneve dev is created in the netns.  Let's call geneve_dellink() instead in geneve_destroy_tunnels().  [0]: BUG: KASAN: slab-use-after-free in geneve_find_dev drivers/net/geneve.c:1295 [inline] BUG: KASAN: slab-use-after-free in geneve_configure+0x234/0x858 drivers/net/geneve.c:1343 Read of size 2 at addr ffff000054d6ee24 by task syz.1.4029/13441  CPU: 1 UID: 0 PID: 13441 Comm: syz.1.4029 Not tainted 6.13.0-g0ad9617c78ac #24 dc35ca22c79fb82e8e7bc5c9c9adafea898b1e3d Hardware name: linux,dummy-virt (DT) Call trace: show_stack+0x38/0x50 arch/arm64/kernel/stacktrace.c:466 (C) __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0xbc/0x108 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x16c/0x6f0 mm/kasan/report.c:489 kasan_report+0xc0/0x120 mm/kasan/report.c:602 __asan_report_load2_noabort+0x20/0x30 mm/kasan/report_generic.c:379 geneve_find_dev drivers/net/geneve.c:1295 [inline] geneve_configure+0x234/0x858 drivers/net/geneve.c:1343 geneve_newlink+0xb8/0x128 drivers/net/geneve.c:1634 rtnl_newlink_create+0x23c/0x868 net/core/rtnetlink.c:3795 __rtnl_newlink net/core/rtnetlink.c:3906 [inline] rtnl_newlink+0x1054/0x1630 net/core/rtnetlink.c:4021 rtnetlink_rcv_msg+0x61c/0x918 net/core/rtnetlink.c:6911 netlink_rcv_skb+0x1dc/0x398 net/netlink/af_netlink.c:2543 rtnetlink_rcv+0x34/0x50 net/core/rtnetlink.c:6938 netlink_unicast_kernel net/netlink/af_netlink.c:1322 [inline] netlink_unicast+0x618/0x838 net/netlink/af_netlink.c:1348 netlink_sendmsg+0x5fc/0x8b0 net/netlink/af_netlink.c:1892 sock_sendmsg_nosec net/socket.c:713 [inline] __sock_sendmsg net/socket.c:728 [inline] ____sys_sendmsg+0x410/0x6f8 net/socket.c:2568 ___sys_sendmsg+0x178/0x1d8 net/socket.c:2622 __sys_sendmsg net/socket.c:2654 [inline] __do_sys_sendmsg net/socket.c:2659 [inline] __se_sys_sendmsg net/socket.c:2657 [inline] __arm64_sys_sendmsg+0x12c/0x1c8 net/socket.c:2657 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x90/0x278 arch/arm64/kernel/syscall.c:49 el0_svc_common+0x13c/0x250 arch/arm64/kernel/syscall.c:132 do_el0_svc+0x54/0x70 arch/arm64/kernel/syscall.c:151 el0_svc+0x4c/0xa8 arch/arm64/kernel/entry-common.c:744 el0t_64_sync_handler+0x78/0x108 arch/arm64/kernel/entry-common.c:762 el0t_64_sync+0x198/0x1a0 arch/arm64/kernel/entry.S:600  Allocated by task 13247: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x30/0x68 mm/kasan/common.c:68 kasan_save_alloc_info+0x44/0x58 mm/kasan/generic.c:568 poison_kmalloc_redzone mm/kasan/common.c:377 [inline] __kasan_kmalloc+0x84/0xa0 mm/kasan/common.c:394 kasan_kmalloc include/linux/kasan.h:260 [inline] __do_kmalloc_node mm/slub.c:4298 [inline] __kmalloc_node_noprof+0x2a0/0x560 mm/slub.c:4304 __kvmalloc_node_noprof+0x9c/0x230 mm/util.c:645 alloc_netdev_mqs+0xb8/0x11a0 net/core/dev.c:11470 rtnl_create_link+0x2b8/0xb50 net/core/rtnetlink.c:3604 rtnl_newlink_create+0x19c/0x868 net/core/rtnetlink.c:3780 __rtnl_newlink net/core/rtnetlink.c:3906 [inline] rtnl_newlink+0x1054/0x1630 net/core/rtnetlink.c:4021 rtnetlink_rcv_msg+0x61c/0x918 net/core/rtnetlink.c:6911 netlink_rcv_skb+0x1dc/0x398 net/netlink/af_netlink.c:2543 rtnetlink_rcv+0x34/0x50 net/core/rtnetlink.c:6938 netlink_unicast_kernel net/netlink/af_n ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21856?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 7.8: CVE--2025--21856" src="https://img.shields.io/badge/CVE--2025--21856-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  s390/ism: add release function for struct device  According to device_release() in /drivers/base/core.c, a device without a release function is a broken device and must be fixed.  The current code directly frees the device after calling device_add() without waiting for other kernel parts to release their references. Thus, a reference could still be held to a struct device, e.g., by sysfs, leading to potential use-after-free issues if a proper release function is not set.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21855?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 7.8: CVE--2025--21855" src="https://img.shields.io/badge/CVE--2025--21855-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ibmvnic: Don't reference skb after sending to VIOS  Previously, after successfully flushing the xmit buffer to VIOS, the tx_bytes stat was incremented by the length of the skb.  It is invalid to access the skb memory after sending the buffer to the VIOS because, at any point after sending, the VIOS can trigger an interrupt to free this memory. A race between reading skb->len and freeing the skb is possible (especially during LPM) and will result in use-after-free: ================================================================== BUG: KASAN: slab-use-after-free in ibmvnic_xmit+0x75c/0x1808 [ibmvnic] Read of size 4 at addr c00000024eb48a70 by task hxecom/14495 <...> Call Trace: [c000000118f66cf0] [c0000000018cba6c] dump_stack_lvl+0x84/0xe8 (unreliable) [c000000118f66d20] [c0000000006f0080] print_report+0x1a8/0x7f0 [c000000118f66df0] [c0000000006f08f0] kasan_report+0x128/0x1f8 [c000000118f66f00] [c0000000006f2868] __asan_load4+0xac/0xe0 [c000000118f66f20] [c0080000046eac84] ibmvnic_xmit+0x75c/0x1808 [ibmvnic] [c000000118f67340] [c0000000014be168] dev_hard_start_xmit+0x150/0x358 <...> Freed by task 0: kasan_save_stack+0x34/0x68 kasan_save_track+0x2c/0x50 kasan_save_free_info+0x64/0x108 __kasan_mempool_poison_object+0x148/0x2d4 napi_skb_cache_put+0x5c/0x194 net_tx_action+0x154/0x5b8 handle_softirqs+0x20c/0x60c do_softirq_own_stack+0x6c/0x88 <...> The buggy address belongs to the object at c00000024eb48a00 which belongs to the cache skbuff_head_cache of size 224 ==================================================================

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21791?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 7.8: CVE--2025--21791" src="https://img.shields.io/badge/CVE--2025--21791-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vrf: use RCU protection in l3mdev_l3_out()  l3mdev_l3_out() can be called without RCU being held:  raw_sendmsg() ip_push_pending_frames() ip_send_skb() ip_local_out() __ip_local_out() l3mdev_ip_out()  Add rcu_read_lock() / rcu_read_unlock() pair to avoid a potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21785?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 7.8: CVE--2025--21785" src="https://img.shields.io/badge/CVE--2025--21785-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  arm64: cacheinfo: Avoid out-of-bounds write to cacheinfo array  The loop that detects/populates cache information already has a bounds check on the array size but does not account for cache levels with separate data/instructions cache. Fix this by incrementing the index for any populated leaf (instead of any populated level).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21780?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 7.8: CVE--2025--21780" src="https://img.shields.io/badge/CVE--2025--21780-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu: avoid buffer overflow attach in smu_sys_set_pp_table()  It malicious user provides a small pptable through sysfs and then a bigger pptable, it may cause buffer overflow attack in function smu_sys_set_pp_table().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21782?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 7.1: CVE--2025--21782" src="https://img.shields.io/badge/CVE--2025--21782-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  orangefs: fix a oob in orangefs_debug_write  I got a syzbot report: slab-out-of-bounds Read in orangefs_debug_write... several people suggested fixes, I tested Al Viro's suggestion and made this patch.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21866?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21866" src="https://img.shields.io/badge/CVE--2025--21866-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  powerpc/code-patching: Fix KASAN hit by not flagging text patching area as VM_ALLOC  Erhard reported the following KASAN hit while booting his PowerMac G4 with a KASAN-enabled kernel 6.13-rc6:  BUG: KASAN: vmalloc-out-of-bounds in copy_to_kernel_nofault+0xd8/0x1c8 Write of size 8 at addr f1000000 by task chronyd/1293  CPU: 0 UID: 123 PID: 1293 Comm: chronyd Tainted: G        W 6.13.0-rc6-PMacG4 #2 Tainted: [W]=WARN Hardware name: PowerMac3,6 7455 0x80010303 PowerMac Call Trace: [c2437590] [c1631a84] dump_stack_lvl+0x70/0x8c (unreliable) [c24375b0] [c0504998] print_report+0xdc/0x504 [c2437610] [c050475c] kasan_report+0xf8/0x108 [c2437690] [c0505a3c] kasan_check_range+0x24/0x18c [c24376a0] [c03fb5e4] copy_to_kernel_nofault+0xd8/0x1c8 [c24376c0] [c004c014] patch_instructions+0x15c/0x16c [c2437710] [c00731a8] bpf_arch_text_copy+0x60/0x7c [c2437730] [c0281168] bpf_jit_binary_pack_finalize+0x50/0xac [c2437750] [c0073cf4] bpf_int_jit_compile+0xb30/0xdec [c2437880] [c0280394] bpf_prog_select_runtime+0x15c/0x478 [c24378d0] [c1263428] bpf_prepare_filter+0xbf8/0xc14 [c2437990] [c12677ec] bpf_prog_create_from_user+0x258/0x2b4 [c24379d0] [c027111c] do_seccomp+0x3dc/0x1890 [c2437ac0] [c001d8e0] system_call_exception+0x2dc/0x420 [c2437f30] [c00281ac] ret_from_syscall+0x0/0x2c --- interrupt: c00 at 0x5a1274 NIP:  005a1274 LR: 006a3b3c CTR: 005296c8 REGS: c2437f40 TRAP: 0c00   Tainted: G        W (6.13.0-rc6-PMacG4) MSR:  0200f932 <VEC,EE,PR,FP,ME,IR,DR,RI>  CR: 24004422  XER: 00000000  GPR00: 00000166 af8f3fa0 a7ee3540 00000001 00000000 013b6500 005a5858 0200f932 GPR08: 00000000 00001fe9 013d5fc8 005296c8 2822244c 00b2fcd8 00000000 af8f4b57 GPR16: 00000000 00000001 00000000 00000000 00000000 00000001 00000000 00000002 GPR24: 00afdbb0 00000000 00000000 00000000 006e0004 013ce060 006e7c1c 00000001 NIP [005a1274] 0x5a1274 LR [006a3b3c] 0x6a3b3c --- interrupt: c00  The buggy address belongs to the virtual mapping at [f1000000, f1002000) created by: text_area_cpu_up+0x20/0x190  The buggy address belongs to the physical page: page: refcount:1 mapcount:0 mapping:00000000 index:0x0 pfn:0x76e30 flags: 0x80000000(zone=2) raw: 80000000 00000000 00000122 00000000 00000000 00000000 ffffffff 00000001 raw: 00000000 page dumped because: kasan: bad access detected  Memory state around the buggy address: f0ffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f0ffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 >f1000000: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 ^ f1000080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f1000100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 ==================================================================  f8 corresponds to KASAN_VMALLOC_INVALID which means the area is not initialised hence not supposed to be used yet.  Powerpc text patching infrastructure allocates a virtual memory area using get_vm_area() and flags it as VM_ALLOC. But that flag is meant to be used for vmalloc() and vmalloc() allocated memory is not supposed to be used before a call to __vmalloc_node_range() which is never called for that area.  That went undetected until commit e4137f08816b ("mm, kasan, kmsan: instrument copy_from/to_kernel_nofault")  The area allocated by text_area_cpu_up() is not vmalloc memory, it is mapped directly on demand when needed by map_kernel_page(). There is no VM flag corresponding to such usage, so just pass no flag. That way the area will be unpoisonned and usable immediately.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21864?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21864" src="https://img.shields.io/badge/CVE--2025--21864-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tcp: drop secpath at the same time as we currently drop dst  Xiumei reported hitting the WARN in xfrm6_tunnel_net_exit while running tests that boil down to: - create a pair of netns - run a basic TCP test over ipcomp6 - delete the pair of netns  The xfrm_state found on spi_byaddr was not deleted at the time we delete the netns, because we still have a reference on it. This lingering reference comes from a secpath (which holds a ref on the xfrm_state), which is still attached to an skb. This skb is not leaked, it ends up on sk_receive_queue and then gets defer-free'd by skb_attempt_defer_free.  The problem happens when we defer freeing an skb (push it on one CPU's defer_list), and don't flush that list before the netns is deleted. In that case, we still have a reference on the xfrm_state that we don't expect at this point.  We already drop the skb's dst in the TCP receive path when it's no longer needed, so let's also drop the secpath. At this point, tcp_filter has already called into the LSM hooks that may require the secpath, so it should not be needed anymore. However, in some of those places, the MPTCP extension has just been attached to the skb, so we cannot simply drop all extensions.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21862?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21862" src="https://img.shields.io/badge/CVE--2025--21862-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drop_monitor: fix incorrect initialization order  Syzkaller reports the following bug:  BUG: spinlock bad magic on CPU#1, syz-executor.0/7995 lock: 0xffff88805303f3e0, .magic: 00000000, .owner: <none>/-1, .owner_cpu: 0 CPU: 1 PID: 7995 Comm: syz-executor.0 Tainted: G            E     5.10.209+ #1 Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 11/12/2020 Call Trace: __dump_stack lib/dump_stack.c:77 [inline] dump_stack+0x119/0x179 lib/dump_stack.c:118 debug_spin_lock_before kernel/locking/spinlock_debug.c:83 [inline] do_raw_spin_lock+0x1f6/0x270 kernel/locking/spinlock_debug.c:112 __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:117 [inline] _raw_spin_lock_irqsave+0x50/0x70 kernel/locking/spinlock.c:159 reset_per_cpu_data+0xe6/0x240 [drop_monitor] net_dm_cmd_trace+0x43d/0x17a0 [drop_monitor] genl_family_rcv_msg_doit+0x22f/0x330 net/netlink/genetlink.c:739 genl_family_rcv_msg net/netlink/genetlink.c:783 [inline] genl_rcv_msg+0x341/0x5a0 net/netlink/genetlink.c:800 netlink_rcv_skb+0x14d/0x440 net/netlink/af_netlink.c:2497 genl_rcv+0x29/0x40 net/netlink/genetlink.c:811 netlink_unicast_kernel net/netlink/af_netlink.c:1322 [inline] netlink_unicast+0x54b/0x800 net/netlink/af_netlink.c:1348 netlink_sendmsg+0x914/0xe00 net/netlink/af_netlink.c:1916 sock_sendmsg_nosec net/socket.c:651 [inline] __sock_sendmsg+0x157/0x190 net/socket.c:663 ____sys_sendmsg+0x712/0x870 net/socket.c:2378 ___sys_sendmsg+0xf8/0x170 net/socket.c:2432 __sys_sendmsg+0xea/0x1b0 net/socket.c:2461 do_syscall_64+0x30/0x40 arch/x86/entry/common.c:46 entry_SYSCALL_64_after_hwframe+0x62/0xc7 RIP: 0033:0x7f3f9815aee9 Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007f3f972bf0c8 EFLAGS: 00000246 ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX: 00007f3f9826d050 RCX: 00007f3f9815aee9 RDX: 0000000020000000 RSI: 0000000020001300 RDI: 0000000000000007 RBP: 00007f3f981b63bd R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000 R13: 000000000000006e R14: 00007f3f9826d050 R15: 00007ffe01ee6768  If drop_monitor is built as a kernel module, syzkaller may have time to send a netlink NET_DM_CMD_START message during the module loading. This will call the net_dm_monitor_start() function that uses a spinlock that has not yet been initialized.  To fix this, let's place resource initialization above the registration of a generic netlink family.  Found by InfoTeCS on behalf of Linux Verification Center (linuxtesting.org) with Syzkaller.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21861?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21861" src="https://img.shields.io/badge/CVE--2025--21861-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm/migrate_device: don't add folio to be freed to LRU in migrate_device_finalize()  If migration succeeded, we called folio_migrate_flags()->mem_cgroup_migrate() to migrate the memcg from the old to the new folio.  This will set memcg_data of the old folio to 0.  Similarly, if migration failed, memcg_data of the dst folio is left unset.  If we call folio_putback_lru() on such folios (memcg_data == 0), we will add the folio to be freed to the LRU, making memcg code unhappy.  Running the hmm selftests:  # ./hmm-tests ... #  RUN           hmm.hmm_device_private.migrate ... [  102.078007][T14893] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x7ff27d200 pfn:0x13cc00 [  102.079974][T14893] anon flags: 0x17ff00000020018(uptodate|dirty|swapbacked|node=0|zone=2|lastcpupid=0x7ff) [  102.082037][T14893] raw: 017ff00000020018 dead000000000100 dead000000000122 ffff8881353896c9 [  102.083687][T14893] raw: 00000007ff27d200 0000000000000000 00000001ffffffff 0000000000000000 [  102.085331][T14893] page dumped because: VM_WARN_ON_ONCE_FOLIO(!memcg && !mem_cgroup_disabled()) [  102.087230][T14893] ------------[ cut here ]------------ [  102.088279][T14893] WARNING: CPU: 0 PID: 14893 at ./include/linux/memcontrol.h:726 folio_lruvec_lock_irqsave+0x10e/0x170 [  102.090478][T14893] Modules linked in: [  102.091244][T14893] CPU: 0 UID: 0 PID: 14893 Comm: hmm-tests Not tainted 6.13.0-09623-g6c216bc522fd #151 [  102.093089][T14893] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-2.fc40 04/01/2014 [  102.094848][T14893] RIP: 0010:folio_lruvec_lock_irqsave+0x10e/0x170 [  102.096104][T14893] Code: ... [  102.099908][T14893] RSP: 0018:ffffc900236c37b0 EFLAGS: 00010293 [  102.101152][T14893] RAX: 0000000000000000 RBX: ffffea0004f30000 RCX: ffffffff8183f426 [  102.102684][T14893] RDX: ffff8881063cb880 RSI: ffffffff81b8117f RDI: ffff8881063cb880 [  102.104227][T14893] RBP: 0000000000000000 R08: 0000000000000005 R09: 0000000000000000 [  102.105757][T14893] R10: 0000000000000001 R11: 0000000000000002 R12: ffffc900236c37d8 [  102.107296][T14893] R13: ffff888277a2bcb0 R14: 000000000000001f R15: 0000000000000000 [  102.108830][T14893] FS:  00007ff27dbdd740(0000) GS:ffff888277a00000(0000) knlGS:0000000000000000 [  102.110643][T14893] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  102.111924][T14893] CR2: 00007ff27d400000 CR3: 000000010866e000 CR4: 0000000000750ef0 [  102.113478][T14893] PKRU: 55555554 [  102.114172][T14893] Call Trace: [  102.114805][T14893]  <TASK> [  102.115397][T14893]  ? folio_lruvec_lock_irqsave+0x10e/0x170 [  102.116547][T14893]  ? __warn.cold+0x110/0x210 [  102.117461][T14893]  ? folio_lruvec_lock_irqsave+0x10e/0x170 [  102.118667][T14893]  ? report_bug+0x1b9/0x320 [  102.119571][T14893]  ? handle_bug+0x54/0x90 [  102.120494][T14893]  ? exc_invalid_op+0x17/0x50 [  102.121433][T14893]  ? asm_exc_invalid_op+0x1a/0x20 [  102.122435][T14893]  ? __wake_up_klogd.part.0+0x76/0xd0 [  102.123506][T14893]  ? dump_page+0x4f/0x60 [  102.124352][T14893]  ? folio_lruvec_lock_irqsave+0x10e/0x170 [  102.125500][T14893]  folio_batch_move_lru+0xd4/0x200 [  102.126577][T14893]  ? __pfx_lru_add+0x10/0x10 [  102.127505][T14893]  __folio_batch_add_and_move+0x391/0x720 [  102.128633][T14893]  ? __pfx_lru_add+0x10/0x10 [  102.129550][T14893]  folio_putback_lru+0x16/0x80 [  102.130564][T14893]  migrate_device_finalize+0x9b/0x530 [  102.131640][T14893]  dmirror_migrate_to_device.constprop.0+0x7c5/0xad0 [  102.133047][T14893]  dmirror_fops_unlocked_ioctl+0x89b/0xc80  Likely, nothing else goes wrong: putting the last folio reference will remove the folio from the LRU again.  So besides memcg complaining, adding the folio to be freed to the LRU is just an unnecessary step.  The new flow resembles what we have in migrate_folio_move(): add the dst to the lru, rem ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21859?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21859" src="https://img.shields.io/badge/CVE--2025--21859-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  USB: gadget: f_midi: f_midi_complete to call queue_work  When using USB MIDI, a lock is attempted to be acquired twice through a re-entrant call to f_midi_transmit, causing a deadlock.  Fix it by using queue_work() to schedule the inner f_midi_transmit() via a high priority work queue from the completion handler.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21857?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21857" src="https://img.shields.io/badge/CVE--2025--21857-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/sched: cls_api: fix error handling causing NULL dereference  tcf_exts_miss_cookie_base_alloc() calls xa_alloc_cyclic() which can return 1 if the allocation succeeded after wrapping. This was treated as an error, with value 1 returned to caller tcf_exts_init_ex() which sets exts->actions to NULL and returns 1 to caller fl_change().  fl_change() treats err == 1 as success, calling tcf_exts_validate_ex() which calls tcf_action_init() with exts->actions as argument, where it is dereferenced.  Example trace:  BUG: kernel NULL pointer dereference, address: 0000000000000000 CPU: 114 PID: 16151 Comm: handler114 Kdump: loaded Not tainted 5.14.0-503.16.1.el9_5.x86_64 #1 RIP: 0010:tcf_action_init+0x1f8/0x2c0 Call Trace: tcf_action_init+0x1f8/0x2c0 tcf_exts_validate_ex+0x175/0x190 fl_change+0x537/0x1120 [cls_flower]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21854?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21854" src="https://img.shields.io/badge/CVE--2025--21854-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sockmap, vsock: For connectible sockets allow only connected  sockmap expects all vsocks to have a transport assigned, which is expressed in vsock_proto::psock_update_sk_prot(). However, there is an edge case where an unconnected (connectible) socket may lose its previously assigned transport. This is handled with a NULL check in the vsock/BPF recv path.  Another design detail is that listening vsocks are not supposed to have any transport assigned at all. Which implies they are not supported by the sockmap. But this is complicated by the fact that a socket, before switching to TCP_LISTEN, may have had some transport assigned during a failed connect() attempt. Hence, we may end up with a listening vsock in a sockmap, which blows up quickly:  KASAN: null-ptr-deref in range [0x0000000000000120-0x0000000000000127] CPU: 7 UID: 0 PID: 56 Comm: kworker/7:0 Not tainted 6.14.0-rc1+ Workqueue: vsock-loopback vsock_loopback_work RIP: 0010:vsock_read_skb+0x4b/0x90 Call Trace: sk_psock_verdict_data_ready+0xa4/0x2e0 virtio_transport_recv_pkt+0x1ca8/0x2acc vsock_loopback_work+0x27d/0x3f0 process_one_work+0x846/0x1420 worker_thread+0x5b3/0xf80 kthread+0x35a/0x700 ret_from_fork+0x2d/0x70 ret_from_fork_asm+0x1a/0x30  For connectible sockets, instead of relying solely on the state of vsk->transport, tell sockmap to only allow those representing established connections. This aligns with the behaviour for AF_INET and AF_UNIX.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21853?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21853" src="https://img.shields.io/badge/CVE--2025--21853-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: avoid holding freeze_mutex during mmap operation  We use map->freeze_mutex to prevent races between map_freeze() and memory mapping BPF map contents with writable permissions. The way we naively do this means we'll hold freeze_mutex for entire duration of all the mm and VMA manipulations, which is completely unnecessary. This can potentially also lead to deadlocks, as reported by syzbot in [0].  So, instead, hold freeze_mutex only during writeability checks, bump (proactively) "write active" count for the map, unlock the mutex and proceed with mmap logic. And only if something went wrong during mmap logic, then undo that "write active" counter increment.  [0] https://lore.kernel.org/bpf/678dcbc9.050a0220.303755.0066.GAE@google.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21848?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21848" src="https://img.shields.io/badge/CVE--2025--21848-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfp: bpf: Add check for nfp_app_ctrl_msg_alloc()  Add check for the return value of nfp_app_ctrl_msg_alloc() in nfp_bpf_cmsg_alloc() to prevent null pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21847?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21847" src="https://img.shields.io/badge/CVE--2025--21847-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: SOF: stream-ipc: Check for cstream nullity in sof_ipc_msg_data()  The nullity of sps->cstream should be checked similarly as it is done in sof_set_stream_data_offset() function. Assuming that it is not NULL if sps->stream is NULL is incorrect and can lead to NULL pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21846?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21846" src="https://img.shields.io/badge/CVE--2025--21846-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  acct: perform last write from workqueue  In [1] it was reported that the acct(2) system call can be used to trigger NULL deref in cases where it is set to write to a file that triggers an internal lookup. This can e.g., happen when pointing acc(2) to /sys/power/resume. At the point the where the write to this file happens the calling task has already exited and called exit_fs(). A lookup will thus trigger a NULL-deref when accessing current->fs.  Reorganize the code so that the the final write happens from the workqueue but with the caller's credentials. This preserves the (strange) permission model and has almost no regression risk.  This api should stop to exist though.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21844?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21844" src="https://img.shields.io/badge/CVE--2025--21844-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: Add check for next_buffer in receive_encrypted_standard()  Add check for the return value of cifs_buf_get() and cifs_small_buf_get() in receive_encrypted_standard() to prevent null pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21793?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21793" src="https://img.shields.io/badge/CVE--2025--21793-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  spi: sn-f-ospi: Fix division by zero  When there is no dummy cycle in the spi-nor commands, both dummy bus cycle bytes and width are zero. Because of the cpu's warning when divided by zero, the warning should be avoided. Return just zero to avoid such calculations.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21792?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21792" src="https://img.shields.io/badge/CVE--2025--21792-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ax25: Fix refcount leak caused by setting SO_BINDTODEVICE sockopt  If an AX25 device is bound to a socket by setting the SO_BINDTODEVICE socket option, a refcount leak will occur in ax25_release().  Commit 9fd75b66b8f6 ("ax25: Fix refcount leaks caused by ax25_cb_del()") added decrement of device refcounts in ax25_release(). In order for that to work correctly the refcounts must already be incremented when the device is bound to the socket. An AX25 device can be bound to a socket by either calling ax25_bind() or setting SO_BINDTODEVICE socket option. In both cases the refcounts should be incremented, but in fact it is done only in ax25_bind().  This bug leads to the following issue reported by Syzkaller:  ================================================================ refcount_t: decrement hit 0; leaking memory. WARNING: CPU: 1 PID: 5932 at lib/refcount.c:31 refcount_warn_saturate+0x1ed/0x210 lib/refcount.c:31 Modules linked in: CPU: 1 UID: 0 PID: 5932 Comm: syz-executor424 Not tainted 6.13.0-rc4-syzkaller-00110-g4099a71718b0 #0 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 RIP: 0010:refcount_warn_saturate+0x1ed/0x210 lib/refcount.c:31 Call Trace: <TASK> __refcount_dec include/linux/refcount.h:336 [inline] refcount_dec include/linux/refcount.h:351 [inline] ref_tracker_free+0x710/0x820 lib/ref_tracker.c:236 netdev_tracker_free include/linux/netdevice.h:4156 [inline] netdev_put include/linux/netdevice.h:4173 [inline] netdev_put include/linux/netdevice.h:4169 [inline] ax25_release+0x33f/0xa10 net/ax25/af_ax25.c:1069 __sock_release+0xb0/0x270 net/socket.c:640 sock_close+0x1c/0x30 net/socket.c:1408 ... do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f ... </TASK> ================================================================  Fix the implementation of ax25_setsockopt() by adding increment of refcounts for the new device bound, and decrement of refcounts for the old unbound device.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21790?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21790" src="https://img.shields.io/badge/CVE--2025--21790-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vxlan: check vxlan_vnigroup_init() return value  vxlan_init() must check vxlan_vnigroup_init() success otherwise a crash happens later, spotted by syzbot.  Oops: general protection fault, probably for non-canonical address 0xdffffc000000002c: 0000 [#1] PREEMPT SMP KASAN NOPTI KASAN: null-ptr-deref in range [0x0000000000000160-0x0000000000000167] CPU: 0 UID: 0 PID: 7313 Comm: syz-executor147 Not tainted 6.14.0-rc1-syzkaller-00276-g69b54314c975 #0 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 RIP: 0010:vxlan_vnigroup_uninit+0x89/0x500 drivers/net/vxlan/vxlan_vnifilter.c:912 Code: 00 48 8b 44 24 08 4c 8b b0 98 41 00 00 49 8d 86 60 01 00 00 48 89 c2 48 89 44 24 10 48 b8 00 00 00 00 00 fc ff df 48 c1 ea 03 <80> 3c 02 00 0f 85 4d 04 00 00 49 8b 86 60 01 00 00 48 ba 00 00 00 RSP: 0018:ffffc9000cc1eea8 EFLAGS: 00010202 RAX: dffffc0000000000 RBX: 0000000000000001 RCX: ffffffff8672effb RDX: 000000000000002c RSI: ffffffff8672ecb9 RDI: ffff8880461b4f18 RBP: ffff8880461b4ef4 R08: 0000000000000001 R09: 0000000000000000 R10: 0000000000000001 R11: 0000000000000000 R12: 0000000000020000 R13: ffff8880461b0d80 R14: 0000000000000000 R15: dffffc0000000000 FS:  00007fecfa95d6c0(0000) GS:ffff88806a600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fecfa95cfb8 CR3: 000000004472c000 CR4: 0000000000352ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> vxlan_uninit+0x1ab/0x200 drivers/net/vxlan/vxlan_core.c:2942 unregister_netdevice_many_notify+0x12d6/0x1f30 net/core/dev.c:11824 unregister_netdevice_many net/core/dev.c:11866 [inline] unregister_netdevice_queue+0x307/0x3f0 net/core/dev.c:11736 register_netdevice+0x1829/0x1eb0 net/core/dev.c:10901 __vxlan_dev_create+0x7c6/0xa30 drivers/net/vxlan/vxlan_core.c:3981 vxlan_newlink+0xd1/0x130 drivers/net/vxlan/vxlan_core.c:4407 rtnl_newlink_create net/core/rtnetlink.c:3795 [inline] __rtnl_newlink net/core/rtnetlink.c:3906 [inline]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21787?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21787" src="https://img.shields.io/badge/CVE--2025--21787-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  team: better TEAM_OPTION_TYPE_STRING validation  syzbot reported following splat [1]  Make sure user-provided data contains one nul byte.  [1] BUG: KMSAN: uninit-value in string_nocheck lib/vsprintf.c:633 [inline] BUG: KMSAN: uninit-value in string+0x3ec/0x5f0 lib/vsprintf.c:714 string_nocheck lib/vsprintf.c:633 [inline] string+0x3ec/0x5f0 lib/vsprintf.c:714 vsnprintf+0xa5d/0x1960 lib/vsprintf.c:2843 __request_module+0x252/0x9f0 kernel/module/kmod.c:149 team_mode_get drivers/net/team/team_core.c:480 [inline] team_change_mode drivers/net/team/team_core.c:607 [inline] team_mode_option_set+0x437/0x970 drivers/net/team/team_core.c:1401 team_option_set drivers/net/team/team_core.c:375 [inline] team_nl_options_set_doit+0x1339/0x1f90 drivers/net/team/team_core.c:2662 genl_family_rcv_msg_doit net/netlink/genetlink.c:1115 [inline] genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline] genl_rcv_msg+0x1214/0x12c0 net/netlink/genetlink.c:1210 netlink_rcv_skb+0x375/0x650 net/netlink/af_netlink.c:2543 genl_rcv+0x40/0x60 net/netlink/genetlink.c:1219 netlink_unicast_kernel net/netlink/af_netlink.c:1322 [inline] netlink_unicast+0xf52/0x1260 net/netlink/af_netlink.c:1348 netlink_sendmsg+0x10da/0x11e0 net/netlink/af_netlink.c:1892 sock_sendmsg_nosec net/socket.c:718 [inline] __sock_sendmsg+0x30f/0x380 net/socket.c:733 ____sys_sendmsg+0x877/0xb60 net/socket.c:2573 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2627 __sys_sendmsg net/socket.c:2659 [inline] __do_sys_sendmsg net/socket.c:2664 [inline] __se_sys_sendmsg net/socket.c:2662 [inline] __x64_sys_sendmsg+0x212/0x3c0 net/socket.c:2662 x64_sys_call+0x2ed6/0x3c30 arch/x86/include/generated/asm/syscalls_64.h:47 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21783?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21783" src="https://img.shields.io/badge/CVE--2025--21783-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gpiolib: Fix crash on error in gpiochip_get_ngpios()  The gpiochip_get_ngpios() uses chip_*() macros to print messages. However these macros rely on gpiodev to be initialised and set, which is not the case when called via bgpio_init(). In such a case the printing messages will crash on NULL pointer dereference. Replace chip_*() macros by the respective dev_*() ones to avoid such crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21779?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21779" src="https://img.shields.io/badge/CVE--2025--21779-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  KVM: x86: Reject Hyper-V's SEND_IPI hypercalls if local APIC isn't in-kernel  Advertise support for Hyper-V's SEND_IPI and SEND_IPI_EX hypercalls if and only if the local API is emulated/virtualized by KVM, and explicitly reject said hypercalls if the local APIC is emulated in userspace, i.e. don't rely on userspace to opt-in to KVM_CAP_HYPERV_ENFORCE_CPUID.  Rejecting SEND_IPI and SEND_IPI_EX fixes a NULL-pointer dereference if Hyper-V enlightenments are exposed to the guest without an in-kernel local APIC:  dump_stack+0xbe/0xfd __kasan_report.cold+0x34/0x84 kasan_report+0x3a/0x50 __apic_accept_irq+0x3a/0x5c0 kvm_hv_send_ipi.isra.0+0x34e/0x820 kvm_hv_hypercall+0x8d9/0x9d0 kvm_emulate_hypercall+0x506/0x7e0 __vmx_handle_exit+0x283/0xb60 vmx_handle_exit+0x1d/0xd0 vcpu_enter_guest+0x16b0/0x24c0 vcpu_run+0xc0/0x550 kvm_arch_vcpu_ioctl_run+0x170/0x6d0 kvm_vcpu_ioctl+0x413/0xb20 __se_sys_ioctl+0x111/0x160 do_syscal1_64+0x30/0x40 entry_SYSCALL_64_after_hwframe+0x67/0xd1  Note, checking the sending vCPU is sufficient, as the per-VM irqchip_mode can't be modified after vCPUs are created, i.e. if one vCPU has an in-kernel local APIC, then all vCPUs have an in-kernel local APIC.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21776?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21776" src="https://img.shields.io/badge/CVE--2025--21776-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  USB: hub: Ignore non-compliant devices with too many configs or interfaces  Robert Morris created a test program which can cause usb_hub_to_struct_hub() to dereference a NULL or inappropriate pointer:  Oops: general protection fault, probably for non-canonical address 0xcccccccccccccccc: 0000 [#1] SMP DEBUG_PAGEALLOC PTI CPU: 7 UID: 0 PID: 117 Comm: kworker/7:1 Not tainted 6.13.0-rc3-00017-gf44d154d6e3d #14 Hardware name: FreeBSD BHYVE/BHYVE, BIOS 14.0 10/17/2021 Workqueue: usb_hub_wq hub_event RIP: 0010:usb_hub_adjust_deviceremovable+0x78/0x110 ... Call Trace: <TASK> ? die_addr+0x31/0x80 ? exc_general_protection+0x1b4/0x3c0 ? asm_exc_general_protection+0x26/0x30 ? usb_hub_adjust_deviceremovable+0x78/0x110 hub_probe+0x7c7/0xab0 usb_probe_interface+0x14b/0x350 really_probe+0xd0/0x2d0 ? __pfx___device_attach_driver+0x10/0x10 __driver_probe_device+0x6e/0x110 driver_probe_device+0x1a/0x90 __device_attach_driver+0x7e/0xc0 bus_for_each_drv+0x7f/0xd0 __device_attach+0xaa/0x1a0 bus_probe_device+0x8b/0xa0 device_add+0x62e/0x810 usb_set_configuration+0x65d/0x990 usb_generic_driver_probe+0x4b/0x70 usb_probe_device+0x36/0xd0  The cause of this error is that the device has two interfaces, and the hub driver binds to interface 1 instead of interface 0, which is where usb_hub_to_struct_hub() looks.  We can prevent the problem from occurring by refusing to accept hub devices that violate the USB spec by having more than one configuration or interface.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21775?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21775" src="https://img.shields.io/badge/CVE--2025--21775-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  can: ctucanfd: handle skb allocation failure  If skb allocation fails, the pointer to struct can_frame is NULL. This is actually handled everywhere inside ctucan_err_interrupt() except for the only place.  Add the missed NULL check.  Found by Linux Verification Center (linuxtesting.org) with SVACE static analysis tool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21773?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2025--21773" src="https://img.shields.io/badge/CVE--2025--21773-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  can: etas_es58x: fix potential NULL pointer dereference on udev->serial  The driver assumed that es58x_dev->udev->serial could never be NULL. While this is true on commercially available devices, an attacker could spoof the device identity providing a NULL USB serial number. That would trigger a NULL pointer dereference.  Add a check on es58x_dev->udev->serial before accessing it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58088?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2024--58088" src="https://img.shields.io/badge/CVE--2024--58088-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Fix deadlock when freeing cgroup storage  The following commit bc235cdb423a ("bpf: Prevent deadlock from recursive bpf_task_storage_[get|delete]") first introduced deadlock prevention for fentry/fexit programs attaching on bpf_task_storage helpers. That commit also employed the logic in map free path in its v6 version.  Later bpf_cgrp_storage was first introduced in c4bcfb38a95e ("bpf: Implement cgroup storage available to non-cgroup-attached bpf progs") which faces the same issue as bpf_task_storage, instead of its busy counter, NULL was passed to bpf_local_storage_map_free() which opened a window to cause deadlock:  <TASK> (acquiring local_storage->lock) _raw_spin_lock_irqsave+0x3d/0x50 bpf_local_storage_update+0xd1/0x460 bpf_cgrp_storage_get+0x109/0x130 bpf_prog_a4d4a370ba857314_cgrp_ptr+0x139/0x170 ? __bpf_prog_enter_recur+0x16/0x80 bpf_trampoline_6442485186+0x43/0xa4 cgroup_storage_ptr+0x9/0x20 (holding local_storage->lock) bpf_selem_unlink_storage_nolock.constprop.0+0x135/0x160 bpf_selem_unlink_storage+0x6f/0x110 bpf_local_storage_map_free+0xa2/0x110 bpf_map_free_deferred+0x5b/0x90 process_one_work+0x17c/0x390 worker_thread+0x251/0x360 kthread+0xd2/0x100 ret_from_fork+0x34/0x50 ret_from_fork_asm+0x1a/0x30 </TASK>  Progs: - A: SEC("fentry/cgroup_storage_ptr") - cgid (BPF_MAP_TYPE_HASH) Record the id of the cgroup the current task belonging to in this hash map, using the address of the cgroup as the map key. - cgrpa (BPF_MAP_TYPE_CGRP_STORAGE) If current task is a kworker, lookup the above hash map using function parameter @owner as the key to get its corresponding cgroup id which is then used to get a trusted pointer to the cgroup through bpf_cgroup_from_id(). This trusted pointer can then be passed to bpf_cgrp_storage_get() to finally trigger the deadlock issue. - B: SEC("tp_btf/sys_enter") - cgrpb (BPF_MAP_TYPE_CGRP_STORAGE) The only purpose of this prog is to fill Prog A's hash map by calling bpf_cgrp_storage_get() for as many userspace tasks as possible.  Steps to reproduce: - Run A; - while (true) { Run B; Destroy B; }  Fix this issue by passing its busy counter to the free procedure so it can be properly incremented before storage/smap locking.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58020?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2024--58020" src="https://img.shields.io/badge/CVE--2024--58020-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.062%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  HID: multitouch: Add NULL check in mt_input_configured  devm_kasprintf() can return a NULL pointer on failure,but this returned value in mt_input_configured() is not checked. Add NULL check in mt_input_configured(), to handle kernel NULL pointer dereference error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57996?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-79.79"><img alt="medium 5.5: CVE--2024--57996" src="https://img.shields.io/badge/CVE--2024--57996-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-79.79</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-79.79</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: sch_sfq: don't allow 1 packet limit  The current implementation does not work correctly with a limit of 1. iproute2 actually checks for this and this patch adds the check in kernel as well.  This fixes the following syzkaller reported crash:  UBSAN: array-index-out-of-bounds in net/sched/sch_sfq.c:210:6 index 65535 is out of range for type 'struct sfq_head[128]' CPU: 0 PID: 2569 Comm: syz-executor101 Not tainted 5.10.0-smp-DEV #1 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Call Trace: __dump_stack lib/dump_stack.c:79 [inline] dump_stack+0x125/0x19f lib/dump_stack.c:120 ubsan_epilogue lib/ubsan.c:148 [inline] __ubsan_handle_out_of_bounds+0xed/0x120 lib/ubsan.c:347 sfq_link net/sched/sch_sfq.c:210 [inline] sfq_dec+0x528/0x600 net/sched/sch_sfq.c:238 sfq_dequeue+0x39b/0x9d0 net/sched/sch_sfq.c:500 sfq_reset+0x13/0x50 net/sched/sch_sfq.c:525 qdisc_reset+0xfe/0x510 net/sched/sch_generic.c:1026 tbf_reset+0x3d/0x100 net/sched/sch_tbf.c:319 qdisc_reset+0xfe/0x510 net/sched/sch_generic.c:1026 dev_reset_queue+0x8c/0x140 net/sched/sch_generic.c:1296 netdev_for_each_tx_queue include/linux/netdevice.h:2350 [inline] dev_deactivate_many+0x6dc/0xc20 net/sched/sch_generic.c:1362 __dev_close_many+0x214/0x350 net/core/dev.c:1468 dev_close_many+0x207/0x510 net/core/dev.c:1506 unregister_netdevice_many+0x40f/0x16b0 net/core/dev.c:10738 unregister_netdevice_queue+0x2be/0x310 net/core/dev.c:10695 unregister_netdevice include/linux/netdevice.h:2893 [inline] __tun_detach+0x6b6/0x1600 drivers/net/tun.c:689 tun_detach drivers/net/tun.c:705 [inline] tun_chr_close+0x104/0x1b0 drivers/net/tun.c:3640 __fput+0x203/0x840 fs/file_table.c:280 task_work_run+0x129/0x1b0 kernel/task_work.c:185 exit_task_work include/linux/task_work.h:33 [inline] do_exit+0x5ce/0x2200 kernel/exit.c:931 do_group_exit+0x144/0x310 kernel/exit.c:1046 __do_sys_exit_group kernel/exit.c:1057 [inline] __se_sys_exit_group kernel/exit.c:1055 [inline] __x64_sys_exit_group+0x3b/0x40 kernel/exit.c:1055 do_syscall_64+0x6c/0xd0 entry_SYSCALL_64_after_hwframe+0x61/0xcb RIP: 0033:0x7fe5e7b52479 Code: Unable to access opcode bytes at RIP 0x7fe5e7b5244f. RSP: 002b:00007ffd3c800398 EFLAGS: 00000246 ORIG_RAX: 00000000000000e7 RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fe5e7b52479 RDX: 000000000000003c RSI: 00000000000000e7 RDI: 0000000000000000 RBP: 00007fe5e7bcd2d0 R08: ffffffffffffffb8 R09: 0000000000000014 R10: 0000000000000000 R11: 0000000000000246 R12: 00007fe5e7bcd2d0 R13: 0000000000000000 R14: 00007fe5e7bcdd20 R15: 00007fe5e7b24270  The crash can be also be reproduced with the following (with a tc recompiled to allow for sfq limits of 1):  tc qdisc add dev dummy0 handle 1: root tbf rate 1Kbit burst 100b lat 1s ../iproute2-6.9.0/tc/tc qdisc add dev dummy0 handle 2: parent 1:10 sfq limit 1 ifconfig dummy0 up ping -I dummy0 -f -c2 -W0.1 8.8.8.8 sleep 1  Scenario that triggers the crash:  * the first packet is sent and queued in TBF and SFQ; qdisc qlen is 1  * TBF dequeues: it peeks from SFQ which moves the packet to the gso_skb list and keeps qdisc qlen set to 1. TBF is out of tokens so it schedules itself for later.  * the second packet is sent and TBF tries to queues it to SFQ. qdisc qlen is now 2 and because the SFQ limit is 1 the packet is dropped by SFQ. At this point qlen is 1, and all of the SFQ slots are empty, however q->tail is not NULL.  At this point, assuming no more packets are queued, when sch_dequeue runs again it will decrement the qlen for the current empty slot causing an underflow and the subsequent out of bounds access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57977?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2024--57977" src="https://img.shields.io/badge/CVE--2024--57977-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  memcg: fix soft lockup in the OOM process  A soft lockup issue was found in the product with about 56,000 tasks were in the OOM cgroup, it was traversing them when the soft lockup was triggered.  watchdog: BUG: soft lockup - CPU#2 stuck for 23s! [VM Thread:1503066] CPU: 2 PID: 1503066 Comm: VM Thread Kdump: loaded Tainted: G Hardware name: Huawei Cloud OpenStack Nova, BIOS RIP: 0010:console_unlock+0x343/0x540 RSP: 0000:ffffb751447db9a0 EFLAGS: 00000247 ORIG_RAX: ffffffffffffff13 RAX: 0000000000000001 RBX: 0000000000000000 RCX: 00000000ffffffff RDX: 0000000000000000 RSI: 0000000000000004 RDI: 0000000000000247 RBP: ffffffffafc71f90 R08: 0000000000000000 R09: 0000000000000040 R10: 0000000000000080 R11: 0000000000000000 R12: ffffffffafc74bd0 R13: ffffffffaf60a220 R14: 0000000000000247 R15: 0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f2fe6ad91f0 CR3: 00000004b2076003 CR4: 0000000000360ee0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: vprintk_emit+0x193/0x280 printk+0x52/0x6e dump_task+0x114/0x130 mem_cgroup_scan_tasks+0x76/0x100 dump_header+0x1fe/0x210 oom_kill_process+0xd1/0x100 out_of_memory+0x125/0x570 mem_cgroup_out_of_memory+0xb5/0xd0 try_charge+0x720/0x770 mem_cgroup_try_charge+0x86/0x180 mem_cgroup_try_charge_delay+0x1c/0x40 do_anonymous_page+0xb5/0x390 handle_mm_fault+0xc4/0x1f0  This is because thousands of processes are in the OOM cgroup, it takes a long time to traverse all of them.  As a result, this lead to soft lockup in the OOM process.  To fix this issue, call 'cond_resched' in the 'mem_cgroup_scan_tasks' function per 1000 iterations.  For global OOM, call 'touch_softlockup_watchdog' per 1000 iterations to avoid this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57834?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2024--57834" src="https://img.shields.io/badge/CVE--2024--57834-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: vidtv: Fix a null-ptr-deref in vidtv_mux_stop_thread  syzbot report a null-ptr-deref in vidtv_mux_stop_thread. [1]  If dvb->mux is not initialized successfully by vidtv_mux_init() in the vidtv_start_streaming(), it will trigger null pointer dereference about mux in vidtv_mux_stop_thread().  Adjust the timing of streaming initialization and check it before stopping it.  [1] KASAN: null-ptr-deref in range [0x0000000000000128-0x000000000000012f] CPU: 0 UID: 0 PID: 5842 Comm: syz-executor248 Not tainted 6.13.0-rc4-syzkaller-00012-g9b2ffa6148b1 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:vidtv_mux_stop_thread+0x26/0x80 drivers/media/test-drivers/vidtv/vidtv_mux.c:471 Code: 90 90 90 90 66 0f 1f 00 55 53 48 89 fb e8 82 2e c8 f9 48 8d bb 28 01 00 00 48 b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 <0f> b6 04 02 84 c0 74 02 7e 3b 0f b6 ab 28 01 00 00 31 ff 89 ee e8 RSP: 0018:ffffc90003f2faa8 EFLAGS: 00010202 RAX: dffffc0000000000 RBX: 0000000000000000 RCX: ffffffff87cfb125 RDX: 0000000000000025 RSI: ffffffff87d120ce RDI: 0000000000000128 RBP: ffff888029b8d220 R08: 0000000000000005 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000003 R12: ffff888029b8d188 R13: ffffffff8f590aa0 R14: ffffc9000581c5c8 R15: ffff888029a17710 FS:  00007f7eef5156c0(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f7eef5e635c CR3: 0000000076ca6000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> vidtv_stop_streaming drivers/media/test-drivers/vidtv/vidtv_bridge.c:209 [inline] vidtv_stop_feed+0x151/0x250 drivers/media/test-drivers/vidtv/vidtv_bridge.c:252 dmx_section_feed_stop_filtering+0x90/0x160 drivers/media/dvb-core/dvb_demux.c:1000 dvb_dmxdev_feed_stop.isra.0+0x1ee/0x270 drivers/media/dvb-core/dmxdev.c:486 dvb_dmxdev_filter_stop+0x22a/0x3a0 drivers/media/dvb-core/dmxdev.c:559 dvb_dmxdev_filter_free drivers/media/dvb-core/dmxdev.c:840 [inline] dvb_demux_release+0x92/0x550 drivers/media/dvb-core/dmxdev.c:1246 __fput+0x3f8/0xb60 fs/file_table.c:450 task_work_run+0x14e/0x250 kernel/task_work.c:239 get_signal+0x1d3/0x2610 kernel/signal.c:2790 arch_do_signal_or_restart+0x90/0x7e0 arch/x86/kernel/signal.c:337 exit_to_user_mode_loop kernel/entry/common.c:111 [inline] exit_to_user_mode_prepare include/linux/entry-common.h:329 [inline] __syscall_exit_to_user_mode_work kernel/entry/common.c:207 [inline] syscall_exit_to_user_mode+0x150/0x2a0 kernel/entry/common.c:218 do_syscall_64+0xda/0x250 arch/x86/entry/common.c:89 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-52559?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium 5.5: CVE--2024--52559" src="https://img.shields.io/badge/CVE--2024--52559-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/msm/gem: prevent integer overflow in msm_ioctl_gem_submit()  The "submit->cmd[i].size" and "submit->cmd[i].offset" variables are u32 values that come from the user via the submit_lookup_cmds() function. This addition could lead to an integer wrapping bug so use size_add() to prevent that.  Patchwork: https://patchwork.freedesktop.org/patch/624696/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38350?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-79.79"><img alt="medium : CVE--2025--38350" src="https://img.shields.io/badge/CVE--2025--38350-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-79.79</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-79.79</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/sched: Always pass notifications when child class becomes empty  Certain classful qdiscs may invoke their classes' dequeue handler on an enqueue operation. This may unexpectedly empty the child qdisc and thus make an in-flight class passive via qlen_notify(). Most qdiscs do not expect such behaviour at this point in time and may re-activate the class eventually anyways which will lead to a use-after-free.  The referenced fix commit attempted to fix this behavior for the HFSC case by moving the backlog accounting around, though this turned out to be incomplete since the parent's parent may run into the issue too. The following reproducer demonstrates this use-after-free:  tc qdisc add dev lo root handle 1: drr tc filter add dev lo parent 1: basic classid 1:1 tc class add dev lo parent 1: classid 1:1 drr tc qdisc add dev lo parent 1:1 handle 2: hfsc def 1 tc class add dev lo parent 2: classid 2:1 hfsc rt m1 8 d 1 m2 0 tc qdisc add dev lo parent 2:1 handle 3: netem tc qdisc add dev lo parent 3:1 handle 4: blackhole  echo 1 | socat -u STDIN UDP4-DATAGRAM:127.0.0.1:8888 tc class delete dev lo classid 1:1 echo 1 | socat -u STDIN UDP4-DATAGRAM:127.0.0.1:8888  Since backlog accounting issues leading to a use-after-frees on stale class pointers is a recurring pattern at this point, this patch takes a different approach. Instead of trying to fix the accounting, the patch ensures that qdisc_tree_reduce_backlog always calls qlen_notify when the child qdisc is empty. This solves the problem because deletion of qdiscs always involves a call to qdisc_reset() and / or qdisc_purge_queue() which ultimately resets its qlen to 0 thus causing the following qdisc_tree_reduce_backlog() to report to the parent. Note that this may call qlen_notify on passive classes multiple times. This is not a problem after the recent patch series that made all the classful qdiscs qlen_notify() handlers idempotent.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38083?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-71.71"><img alt="medium : CVE--2025--38083" src="https://img.shields.io/badge/CVE--2025--38083-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-71.71</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-71.71</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: prio: fix a race in prio_tune()  Gerrard Tai reported a race condition in PRIO, whenever SFQ perturb timer fires at the wrong time.  The race is as follows:  CPU 0                                 CPU 1 [1]: lock root [2]: qdisc_tree_flush_backlog() [3]: unlock root | |                                    [5]: lock root |                                    [6]: rehash |                                    [7]: qdisc_tree_reduce_backlog() | [4]: qdisc_put()  This can be abused to underflow a parent's qlen.  Calling qdisc_purge_queue() instead of qdisc_tree_flush_backlog() should fix the race, because all packets will be purged from the qdisc before releasing the lock.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37797?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-71.71"><img alt="medium : CVE--2025--37797" src="https://img.shields.io/badge/CVE--2025--37797-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-71.71</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-71.71</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: hfsc: Fix a UAF vulnerability in class handling  This patch fixes a Use-After-Free vulnerability in the HFSC qdisc class handling. The issue occurs due to a time-of-check/time-of-use condition in hfsc_change_class() when working with certain child qdiscs like netem or codel.  The vulnerability works as follows: 1. hfsc_change_class() checks if a class has packets (q.qlen != 0) 2. It then calls qdisc_peek_len(), which for certain qdiscs (e.g., codel, netem) might drop packets and empty the queue 3. The code continues assuming the queue is still non-empty, adding the class to vttree 4. This breaks HFSC scheduler assumptions that only non-empty classes are in vttree 5. Later, when the class is destroyed, this can lead to a Use-After-Free  The fix adds a second queue length check after qdisc_peek_len() to verify the queue wasn't emptied.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37752?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-79.79"><img alt="medium : CVE--2025--37752" src="https://img.shields.io/badge/CVE--2025--37752-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-79.79</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-79.79</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: sch_sfq: move the limit validation  It is not sufficient to directly validate the limit on the data that the user passes as it can be updated based on how the other parameters are changed.  Move the check at the end of the configuration update process to also catch scenarios where the limit is indirectly updated, for example with the following configurations:  tc qdisc add dev dummy0 handle 1: root sfq limit 2 flows 1 depth 1 tc qdisc add dev dummy0 handle 1: root sfq limit 2 flows 1 divisor 1  This fixes the following syzkaller reported crash:  ------------[ cut here ]------------ UBSAN: array-index-out-of-bounds in net/sched/sch_sfq.c:203:6 index 65535 is out of range for type 'struct sfq_head[128]' CPU: 1 UID: 0 PID: 3037 Comm: syz.2.16 Not tainted 6.14.0-rc2-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 12/27/2024 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x201/0x300 lib/dump_stack.c:120 ubsan_epilogue lib/ubsan.c:231 [inline] __ubsan_handle_out_of_bounds+0xf5/0x120 lib/ubsan.c:429 sfq_link net/sched/sch_sfq.c:203 [inline] sfq_dec+0x53c/0x610 net/sched/sch_sfq.c:231 sfq_dequeue+0x34e/0x8c0 net/sched/sch_sfq.c:493 sfq_reset+0x17/0x60 net/sched/sch_sfq.c:518 qdisc_reset+0x12e/0x600 net/sched/sch_generic.c:1035 tbf_reset+0x41/0x110 net/sched/sch_tbf.c:339 qdisc_reset+0x12e/0x600 net/sched/sch_generic.c:1035 dev_reset_queue+0x100/0x1b0 net/sched/sch_generic.c:1311 netdev_for_each_tx_queue include/linux/netdevice.h:2590 [inline] dev_deactivate_many+0x7e5/0xe70 net/sched/sch_generic.c:1375

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21871?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21871" src="https://img.shields.io/badge/CVE--2025--21871-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tee: optee: Fix supplicant wait loop  OP-TEE supplicant is a user-space daemon and it's possible for it be hung or crashed or killed in the middle of processing an OP-TEE RPC call. It becomes more complicated when there is incorrect shutdown ordering of the supplicant process vs the OP-TEE client application which can eventually lead to system hang-up waiting for the closure of the client application.  Allow the client process waiting in kernel for supplicant response to be killed rather than indefinitely waiting in an unkillable state. Also, a normal uninterruptible wait should not have resulted in the hung-task watchdog getting triggered, but the endless loop would.  This fixes issues observed during system reboot/shutdown when supplicant got hung for some reason or gets crashed/killed which lead to client getting hung in an unkillable state. It in turn lead to system being in hung up state requiring hard power off/on to recover.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21870?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21870" src="https://img.shields.io/badge/CVE--2025--21870-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: SOF: ipc4-topology: Harden loops for looking up ALH copiers  Other, non DAI copier widgets could have the same  stream name (sname) as the ALH copier and in that case the copier->data is NULL, no alh_data is attached, which could lead to NULL pointer dereference. We could check for this NULL pointer in sof_ipc4_prepare_copier_module() and avoid the crash, but a similar loop in sof_ipc4_widget_setup_comp_dai() will miscalculate the ALH device count, causing broken audio.  The correct fix is to harden the matching logic by making sure that the 1. widget is a DAI widget - so dai = w->private is valid 2. the dai (and thus the copier) is ALH copier

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21869?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21869" src="https://img.shields.io/badge/CVE--2025--21869-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  powerpc/code-patching: Disable KASAN report during patching via temporary mm  Erhard reports the following KASAN hit on Talos II (power9) with kernel 6.13:  [   12.028126] ================================================================== [   12.028198] BUG: KASAN: user-memory-access in copy_to_kernel_nofault+0x8c/0x1a0 [   12.028260] Write of size 8 at addr 0000187e458f2000 by task systemd/1  [   12.028346] CPU: 87 UID: 0 PID: 1 Comm: systemd Tainted: G T  6.13.0-P9-dirty #3 [   12.028408] Tainted: [T]=RANDSTRUCT [   12.028446] Hardware name: T2P9D01 REV 1.01 POWER9 0x4e1202 opal:skiboot-bc106a0 PowerNV [   12.028500] Call Trace: [   12.028536] [c000000008dbf3b0] [c000000001656a48] dump_stack_lvl+0xbc/0x110 (unreliable) [   12.028609] [c000000008dbf3f0] [c0000000006e2fc8] print_report+0x6b0/0x708 [   12.028666] [c000000008dbf4e0] [c0000000006e2454] kasan_report+0x164/0x300 [   12.028725] [c000000008dbf600] [c0000000006e54d4] kasan_check_range+0x314/0x370 [   12.028784] [c000000008dbf640] [c0000000006e6310] __kasan_check_write+0x20/0x40 [   12.028842] [c000000008dbf660] [c000000000578e8c] copy_to_kernel_nofault+0x8c/0x1a0 [   12.028902] [c000000008dbf6a0] [c0000000000acfe4] __patch_instructions+0x194/0x210 [   12.028965] [c000000008dbf6e0] [c0000000000ade80] patch_instructions+0x150/0x590 [   12.029026] [c000000008dbf7c0] [c0000000001159bc] bpf_arch_text_copy+0x6c/0xe0 [   12.029085] [c000000008dbf800] [c000000000424250] bpf_jit_binary_pack_finalize+0x40/0xc0 [   12.029147] [c000000008dbf830] [c000000000115dec] bpf_int_jit_compile+0x3bc/0x930 [   12.029206] [c000000008dbf990] [c000000000423720] bpf_prog_select_runtime+0x1f0/0x280 [   12.029266] [c000000008dbfa00] [c000000000434b18] bpf_prog_load+0xbb8/0x1370 [   12.029324] [c000000008dbfb70] [c000000000436ebc] __sys_bpf+0x5ac/0x2e00 [   12.029379] [c000000008dbfd00] [c00000000043a228] sys_bpf+0x28/0x40 [   12.029435] [c000000008dbfd20] [c000000000038eb4] system_call_exception+0x334/0x610 [   12.029497] [c000000008dbfe50] [c00000000000c270] system_call_vectored_common+0xf0/0x280 [   12.029561] --- interrupt: 3000 at 0x3fff82f5cfa8 [   12.029608] NIP:  00003fff82f5cfa8 LR: 00003fff82f5cfa8 CTR: 0000000000000000 [   12.029660] REGS: c000000008dbfe80 TRAP: 3000   Tainted: G T   (6.13.0-P9-dirty) [   12.029735] MSR:  900000000280f032 <SF,HV,VEC,VSX,EE,PR,FP,ME,IR,DR,RI> CR: 42004848  XER: 00000000 [   12.029855] IRQMASK: 0 GPR00: 0000000000000169 00003fffdcf789a0 00003fff83067100 0000000000000005 GPR04: 00003fffdcf78a98 0000000000000090 0000000000000000 0000000000000008 GPR08: 0000000000000000 0000000000000000 0000000000000000 0000000000000000 GPR12: 0000000000000000 00003fff836ff7e0 c000000000010678 0000000000000000 GPR16: 0000000000000000 0000000000000000 00003fffdcf78f28 00003fffdcf78f90 GPR20: 0000000000000000 0000000000000000 0000000000000000 00003fffdcf78f80 GPR24: 00003fffdcf78f70 00003fffdcf78d10 00003fff835c7239 00003fffdcf78bd8 GPR28: 00003fffdcf78a98 0000000000000000 0000000000000000 000000011f547580 [   12.030316] NIP [00003fff82f5cfa8] 0x3fff82f5cfa8 [   12.030361] LR [00003fff82f5cfa8] 0x3fff82f5cfa8 [   12.030405] --- interrupt: 3000 [   12.030444] ==================================================================  Commit c28c15b6d28a ("powerpc/code-patching: Use temporary mm for Radix MMU") is inspired from x86 but unlike x86 is doesn't disable KASAN reports during patching. This wasn't a problem at the begining because __patch_mem() is not instrumented.  Commit 465cabc97b42 ("powerpc/code-patching: introduce patch_instructions()") use copy_to_kernel_nofault() to copy several instructions at once. But when using temporary mm the destination is not regular kernel memory but a kind of kernel-like memory located in user address space. ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21868?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21868" src="https://img.shields.io/badge/CVE--2025--21868-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: allow small head cache usage with large MAX_SKB_FRAGS values  Sabrina reported the following splat:  WARNING: CPU: 0 PID: 1 at net/core/dev.c:6935 netif_napi_add_weight_locked+0x8f2/0xba0 Modules linked in: CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.14.0-rc1-net-00092-g011b03359038 #996 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Arch Linux 1.16.3-1-1 04/01/2014 RIP: 0010:netif_napi_add_weight_locked+0x8f2/0xba0 Code: e8 c3 e6 6a fe 48 83 c4 28 5b 5d 41 5c 41 5d 41 5e 41 5f c3 cc cc cc cc c7 44 24 10 ff ff ff ff e9 8f fb ff ff e8 9e e6 6a fe <0f> 0b e9 d3 fe ff ff e8 92 e6 6a fe 48 8b 04 24 be ff ff ff ff 48 RSP: 0000:ffffc9000001fc60 EFLAGS: 00010293 RAX: 0000000000000000 RBX: ffff88806ce48128 RCX: 1ffff11001664b9e RDX: ffff888008f00040 RSI: ffffffff8317ca42 RDI: ffff88800b325cb6 RBP: ffff88800b325c40 R08: 0000000000000001 R09: ffffed100167502c R10: ffff88800b3a8163 R11: 0000000000000000 R12: ffff88800ac1c168 R13: ffff88800ac1c168 R14: ffff88800ac1c168 R15: 0000000000000007 FS:  0000000000000000(0000) GS:ffff88806ce00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: ffff888008201000 CR3: 0000000004c94001 CR4: 0000000000370ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> gro_cells_init+0x1ba/0x270 xfrm_input_init+0x4b/0x2a0 xfrm_init+0x38/0x50 ip_rt_init+0x2d7/0x350 ip_init+0xf/0x20 inet_init+0x406/0x590 do_one_initcall+0x9d/0x2e0 do_initcalls+0x23b/0x280 kernel_init_freeable+0x445/0x490 kernel_init+0x20/0x1d0 ret_from_fork+0x46/0x80 ret_from_fork_asm+0x1a/0x30 </TASK> irq event stamp: 584330 hardirqs last  enabled at (584338): [<ffffffff8168bf87>] __up_console_sem+0x77/0xb0 hardirqs last disabled at (584345): [<ffffffff8168bf6c>] __up_console_sem+0x5c/0xb0 softirqs last  enabled at (583242): [<ffffffff833ee96d>] netlink_insert+0x14d/0x470 softirqs last disabled at (583754): [<ffffffff8317c8cd>] netif_napi_add_weight_locked+0x77d/0xba0  on kernel built with MAX_SKB_FRAGS=45, where SKB_WITH_OVERHEAD(1024) is smaller than GRO_MAX_HEAD.  Such built additionally contains the revert of the single page frag cache so that napi_get_frags() ends up using the page frag allocator, triggering the splat.  Note that the underlying issue is independent from the mentioned revert; address it ensuring that the small head cache will fit either TCP and GRO allocation and updating napi_alloc_skb() and __netdev_alloc_skb() to select kmalloc() usage for any allocation fitting such cache.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21867?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21867" src="https://img.shields.io/badge/CVE--2025--21867-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf, test_run: Fix use-after-free issue in eth_skb_pkt_type()  KMSAN reported a use-after-free issue in eth_skb_pkt_type()[1]. The cause of the issue was that eth_skb_pkt_type() accessed skb's data that didn't contain an Ethernet header. This occurs when bpf_prog_test_run_xdp() passes an invalid value as the user_data argument to bpf_test_init().  Fix this by returning an error when user_data is less than ETH_HLEN in bpf_test_init(). Additionally, remove the check for "if (user_size > size)" as it is unnecessary.  [1] BUG: KMSAN: use-after-free in eth_skb_pkt_type include/linux/etherdevice.h:627 [inline] BUG: KMSAN: use-after-free in eth_type_trans+0x4ee/0x980 net/ethernet/eth.c:165 eth_skb_pkt_type include/linux/etherdevice.h:627 [inline] eth_type_trans+0x4ee/0x980 net/ethernet/eth.c:165 __xdp_build_skb_from_frame+0x5a8/0xa50 net/core/xdp.c:635 xdp_recv_frames net/bpf/test_run.c:272 [inline] xdp_test_run_batch net/bpf/test_run.c:361 [inline] bpf_test_run_xdp_live+0x2954/0x3330 net/bpf/test_run.c:390 bpf_prog_test_run_xdp+0x148e/0x1b10 net/bpf/test_run.c:1318 bpf_prog_test_run+0x5b7/0xa30 kernel/bpf/syscall.c:4371 __sys_bpf+0x6a6/0xe20 kernel/bpf/syscall.c:5777 __do_sys_bpf kernel/bpf/syscall.c:5866 [inline] __se_sys_bpf kernel/bpf/syscall.c:5864 [inline] __x64_sys_bpf+0xa4/0xf0 kernel/bpf/syscall.c:5864 x64_sys_call+0x2ea0/0x3d90 arch/x86/include/generated/asm/syscalls_64.h:322 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xd9/0x1d0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  Uninit was created at: free_pages_prepare mm/page_alloc.c:1056 [inline] free_unref_page+0x156/0x1320 mm/page_alloc.c:2657 __free_pages+0xa3/0x1b0 mm/page_alloc.c:4838 bpf_ringbuf_free kernel/bpf/ringbuf.c:226 [inline] ringbuf_map_free+0xff/0x1e0 kernel/bpf/ringbuf.c:235 bpf_map_free kernel/bpf/syscall.c:838 [inline] bpf_map_free_deferred+0x17c/0x310 kernel/bpf/syscall.c:862 process_one_work kernel/workqueue.c:3229 [inline] process_scheduled_works+0xa2b/0x1b60 kernel/workqueue.c:3310 worker_thread+0xedf/0x1550 kernel/workqueue.c:3391 kthread+0x535/0x6b0 kernel/kthread.c:389 ret_from_fork+0x6e/0x90 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244  CPU: 1 UID: 0 PID: 17276 Comm: syz.1.16450 Not tainted 6.12.0-05490-g9bb88c659673 #8 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-3.fc41 04/01/2014

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21839?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21839" src="https://img.shields.io/badge/CVE--2025--21839-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.097%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  KVM: x86: Load DR6 with guest value only before entering .vcpu_run() loop  Move the conditional loading of hardware DR6 with the guest's DR6 value out of the core .vcpu_run() loop to fix a bug where KVM can load hardware with a stale vcpu->arch.dr6.  When the guest accesses a DR and host userspace isn't debugging the guest, KVM disables DR interception and loads the guest's values into hardware on VM-Enter and saves them on VM-Exit.  This allows the guest to access DRs at will, e.g. so that a sequence of DR accesses to configure a breakpoint only generates one VM-Exit.  For DR0-DR3, the logic/behavior is identical between VMX and SVM, and also identical between KVM_DEBUGREG_BP_ENABLED (userspace debugging the guest) and KVM_DEBUGREG_WONT_EXIT (guest using DRs), and so KVM handles loading DR0-DR3 in common code, _outside_ of the core kvm_x86_ops.vcpu_run() loop.  But for DR6, the guest's value doesn't need to be loaded into hardware for KVM_DEBUGREG_BP_ENABLED, and SVM provides a dedicated VMCB field whereas VMX requires software to manually load the guest value, and so loading the guest's value into DR6 is handled by {svm,vmx}_vcpu_run(), i.e. is done _inside_ the core run loop.  Unfortunately, saving the guest values on VM-Exit is initiated by common x86, again outside of the core run loop.  If the guest modifies DR6 (in hardware, when DR interception is disabled), and then the next VM-Exit is a fastpath VM-Exit, KVM will reload hardware DR6 with vcpu->arch.dr6 and clobber the guest's actual value.  The bug shows up primarily with nested VMX because KVM handles the VMX preemption timer in the fastpath, and the window between hardware DR6 being modified (in guest context) and DR6 being read by guest software is orders of magnitude larger in a nested setup.  E.g. in non-nested, the VMX preemption timer would need to fire precisely between #DB injection and the #DB handler's read of DR6, whereas with a KVM-on-KVM setup, the window where hardware DR6 is "dirty" extends all the way from L1 writing DR6 to VMRESUME (in L1).  L1's view: ========== <L1 disables DR interception> CPU 0/KVM-7289    [023] d....  2925.640961: kvm_entry: vcpu 0 A:  L1 Writes DR6 CPU 0/KVM-7289    [023] d....  2925.640963: <hack>: Set DRs, DR6 = 0xffff0ff1  B:        CPU 0/KVM-7289    [023] d....  2925.640967: kvm_exit: vcpu 0 reason EXTERNAL_INTERRUPT intr_info 0x800000ec  D: L1 reads DR6, arch.dr6 = 0 CPU 0/KVM-7289    [023] d....  2925.640969: <hack>: Sync DRs, DR6 = 0xffff0ff0  CPU 0/KVM-7289    [023] d....  2925.640976: kvm_entry: vcpu 0 L2 reads DR6, L1 disables DR interception CPU 0/KVM-7289    [023] d....  2925.640980: kvm_exit: vcpu 0 reason DR_ACCESS info1 0x0000000000000216 CPU 0/KVM-7289    [023] d....  2925.640983: kvm_entry: vcpu 0  CPU 0/KVM-7289    [023] d....  2925.640983: <hack>: Set DRs, DR6 = 0xffff0ff0  L2 detects failure CPU 0/KVM-7289    [023] d....  2925.640987: kvm_exit: vcpu 0 reason HLT L1 reads DR6 (confirms failure) CPU 0/KVM-7289    [023] d....  2925.640990: <hack>: Sync DRs, DR6 = 0xffff0ff0  L0's view: ========== L2 reads DR6, arch.dr6 = 0 CPU 23/KVM-5046    [001] d....  3410.005610: kvm_exit: vcpu 23 reason DR_ACCESS info1 0x0000000000000216 CPU 23/KVM-5046    [001] .....  3410.005610: kvm_nested_vmexit: vcpu 23 reason DR_ACCESS info1 0x0000000000000216  L2 => L1 nested VM-Exit CPU 23/KVM-5046    [001] .....  3410.005610: kvm_nested_vmexit_inject: reason: DR_ACCESS ext_inf1: 0x0000000000000216  CPU 23/KVM-5046    [001] d....  3410.005610: kvm_entry: vcpu 23 CPU 23/KVM-5046    [001] d....  3410.005611: kvm_exit: vcpu 23 reason VMREAD CPU 23/KVM-5046    [001] d....  3410.005611: kvm_entry: vcpu 23 CPU 23/KVM-5046    [001] d....  3410. ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21838?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21838" src="https://img.shields.io/badge/CVE--2025--21838-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.064%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: core: flush gadget workqueue after device removal  device_del() can lead to new work being scheduled in gadget->work workqueue. This is observed, for example, with the dwc3 driver with the following call stack: device_del() gadget_unbind_driver() usb_gadget_disconnect_locked() dwc3_gadget_pullup() dwc3_gadget_soft_disconnect() usb_gadget_set_state() schedule_work(&gadget->work)  Move flush_work() after device_del() to ensure the workqueue is cleaned up.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21836?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21836" src="https://img.shields.io/badge/CVE--2025--21836-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  io_uring/kbuf: reallocate buf lists on upgrade  IORING_REGISTER_PBUF_RING can reuse an old struct io_buffer_list if it was created for legacy selected buffer and has been emptied. It violates the requirement that most of the field should stay stable after publish. Always reallocate it instead.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21835?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21835" src="https://img.shields.io/badge/CVE--2025--21835-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.109%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: f_midi: fix MIDI Streaming descriptor lengths  While the MIDI jacks are configured correctly, and the MIDIStreaming endpoint descriptors are filled with the correct information, bNumEmbMIDIJack and bLength are set incorrectly in these descriptors.  This does not matter when the numbers of in and out ports are equal, but when they differ the host will receive broken descriptors with uninitialized stack memory leaking into the descriptor for whichever value is smaller.  The precise meaning of "in" and "out" in the port counts is not clearly defined and can be confusing.  But elsewhere the driver consistently uses this to match the USB meaning of IN and OUT viewed from the host, so that "in" ports send data to the host and "out" ports receive data from it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21823?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21823" src="https://img.shields.io/badge/CVE--2025--21823-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.109%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  batman-adv: Drop unmanaged ELP metric worker  The ELP worker needs to calculate new metric values for all neighbors "reachable" over an interface. Some of the used metric sources require locks which might need to sleep. This sleep is incompatible with the RCU list iterator used for the recorded neighbors. The initial approach to work around of this problem was to queue another work item per neighbor and then run this in a new context.  Even when this solved the RCU vs might_sleep() conflict, it has a major problems: Nothing was stopping the work item in case it is not needed anymore - for example because one of the related interfaces was removed or the batman-adv module was unloaded - resulting in potential invalid memory accesses.  Directly canceling the metric worker also has various problems:  * cancel_work_sync for a to-be-deactivated interface is called with rtnl_lock held. But the code in the ELP metric worker also tries to use rtnl_lock() - which will never return in this case. This also means that cancel_work_sync would never return because it is waiting for the worker to finish. * iterating over the neighbor list for the to-be-deactivated interface is currently done using the RCU specific methods. Which means that it is possible to miss items when iterating over it without the associated spinlock - a behaviour which is acceptable for a periodic metric check but not for a cleanup routine (which must "stop" all still running workers)  The better approch is to get rid of the per interface neighbor metric worker and handle everything in the interface worker. The original problems are solved by:  * creating a list of neighbors which require new metric information inside the RCU protected context, gathering the metric according to the new list outside the RCU protected context * only use rcu_trylock inside metric gathering code to avoid a deadlock when the cancel_delayed_work_sync is called in the interface removal code (which is called with the rtnl_lock held)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21821?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21821" src="https://img.shields.io/badge/CVE--2025--21821-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fbdev: omap: use threaded IRQ for LCD DMA  When using touchscreen and framebuffer, Nokia 770 crashes easily with:  BUG: scheduling while atomic: irq/144-ads7846/82/0x00010000 Modules linked in: usb_f_ecm g_ether usb_f_rndis u_ether libcomposite configfs omap_udc ohci_omap ohci_hcd CPU: 0 UID: 0 PID: 82 Comm: irq/144-ads7846 Not tainted 6.12.7-770 #2 Hardware name: Nokia 770 Call trace: unwind_backtrace from show_stack+0x10/0x14 show_stack from dump_stack_lvl+0x54/0x5c dump_stack_lvl from __schedule_bug+0x50/0x70 __schedule_bug from __schedule+0x4d4/0x5bc __schedule from schedule+0x34/0xa0 schedule from schedule_preempt_disabled+0xc/0x10 schedule_preempt_disabled from __mutex_lock.constprop.0+0x218/0x3b4 __mutex_lock.constprop.0 from clk_prepare_lock+0x38/0xe4 clk_prepare_lock from clk_set_rate+0x18/0x154 clk_set_rate from sossi_read_data+0x4c/0x168 sossi_read_data from hwa742_read_reg+0x5c/0x8c hwa742_read_reg from send_frame_handler+0xfc/0x300 send_frame_handler from process_pending_requests+0x74/0xd0 process_pending_requests from lcd_dma_irq_handler+0x50/0x74 lcd_dma_irq_handler from __handle_irq_event_percpu+0x44/0x130 __handle_irq_event_percpu from handle_irq_event+0x28/0x68 handle_irq_event from handle_level_irq+0x9c/0x170 handle_level_irq from generic_handle_domain_irq+0x2c/0x3c generic_handle_domain_irq from omap1_handle_irq+0x40/0x8c omap1_handle_irq from generic_handle_arch_irq+0x28/0x3c generic_handle_arch_irq from call_with_stack+0x1c/0x24 call_with_stack from __irq_svc+0x94/0xa8 Exception stack(0xc5255da0 to 0xc5255de8) 5da0: 00000001 c22fc620 00000000 00000000 c08384a8 c106fc00 00000000 c240c248 5dc0: c113a600 c3f6ec30 00000001 00000000 c22fc620 c5255df0 c22fc620 c0279a94 5de0: 60000013 ffffffff __irq_svc from clk_prepare_lock+0x4c/0xe4 clk_prepare_lock from clk_get_rate+0x10/0x74 clk_get_rate from uwire_setup_transfer+0x40/0x180 uwire_setup_transfer from spi_bitbang_transfer_one+0x2c/0x9c spi_bitbang_transfer_one from spi_transfer_one_message+0x2d0/0x664 spi_transfer_one_message from __spi_pump_transfer_message+0x29c/0x498 __spi_pump_transfer_message from __spi_sync+0x1f8/0x2e8 __spi_sync from spi_sync+0x24/0x40 spi_sync from ads7846_halfd_read_state+0x5c/0x1c0 ads7846_halfd_read_state from ads7846_irq+0x58/0x348 ads7846_irq from irq_thread_fn+0x1c/0x78 irq_thread_fn from irq_thread+0x120/0x228 irq_thread from kthread+0xc8/0xe8 kthread from ret_from_fork+0x14/0x28  As a quick fix, switch to a threaded IRQ which provides a stable system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21796?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21796" src="https://img.shields.io/badge/CVE--2025--21796-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfsd: clear acl_access/acl_default after releasing them  If getting acl_default fails, acl_access and acl_default will be released simultaneously. However, acl_access will still retain a pointer pointing to the released posix_acl, which will trigger a WARNING in nfs3svc_release_getacl like this:  ------------[ cut here ]------------ refcount_t: underflow; use-after-free. WARNING: CPU: 26 PID: 3199 at lib/refcount.c:28 refcount_warn_saturate+0xb5/0x170 Modules linked in: CPU: 26 UID: 0 PID: 3199 Comm: nfsd Not tainted 6.12.0-rc6-00079-g04ae226af01f-dirty #8 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.1-2.fc37 04/01/2014 RIP: 0010:refcount_warn_saturate+0xb5/0x170 Code: cc cc 0f b6 1d b3 20 a5 03 80 fb 01 0f 87 65 48 d8 00 83 e3 01 75 e4 48 c7 c7 c0 3b 9b 85 c6 05 97 20 a5 03 01 e8 fb 3e 30 ff <0f> 0b eb cd 0f b6 1d 8a3 RSP: 0018:ffffc90008637cd8 EFLAGS: 00010282 RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffffffff83904fde RDX: dffffc0000000000 RSI: 0000000000000008 RDI: ffff88871ed36380 RBP: ffff888158beeb40 R08: 0000000000000001 R09: fffff520010c6f56 R10: ffffc90008637ab7 R11: 0000000000000001 R12: 0000000000000001 R13: ffff888140e77400 R14: ffff888140e77408 R15: ffffffff858b42c0 FS:  0000000000000000(0000) GS:ffff88871ed00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000562384d32158 CR3: 000000055cc6a000 CR4: 00000000000006f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> ? refcount_warn_saturate+0xb5/0x170 ? __warn+0xa5/0x140 ? refcount_warn_saturate+0xb5/0x170 ? report_bug+0x1b1/0x1e0 ? handle_bug+0x53/0xa0 ? exc_invalid_op+0x17/0x40 ? asm_exc_invalid_op+0x1a/0x20 ? tick_nohz_tick_stopped+0x1e/0x40 ? refcount_warn_saturate+0xb5/0x170 ? refcount_warn_saturate+0xb5/0x170 nfs3svc_release_getacl+0xc9/0xe0 svc_process_common+0x5db/0xb60 ? __pfx_svc_process_common+0x10/0x10 ? __rcu_read_unlock+0x69/0xa0 ? __pfx_nfsd_dispatch+0x10/0x10 ? svc_xprt_received+0xa1/0x120 ? xdr_init_decode+0x11d/0x190 svc_process+0x2a7/0x330 svc_handle_xprt+0x69d/0x940 svc_recv+0x180/0x2d0 nfsd+0x168/0x200 ? __pfx_nfsd+0x10/0x10 kthread+0x1a2/0x1e0 ? kthread+0xf4/0x1e0 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x34/0x60 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1a/0x30 </TASK> Kernel panic - not syncing: kernel: panic_on_warn set ...  Clear acl_access/acl_default after posix_acl_release is called to prevent UAF from being triggered.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21795?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21795" src="https://img.shields.io/badge/CVE--2025--21795-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.099%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  NFSD: fix hang in nfsd4_shutdown_callback  If nfs4_client is in courtesy state then there is no point to send the callback. This causes nfsd4_shutdown_callback to hang since cl_cb_inflight is not 0. This hang lasts about 15 minutes until TCP notifies NFSD that the connection was dropped.  This patch modifies nfsd4_run_cb_work to skip the RPC call if nfs4_client is in courtesy state.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21786?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21786" src="https://img.shields.io/badge/CVE--2025--21786-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  workqueue: Put the pwq after detaching the rescuer from the pool  The commit 68f83057b913("workqueue: Reap workers via kthread_stop() and remove detach_completion") adds code to reap the normal workers but mistakenly does not handle the rescuer and also removes the code waiting for the rescuer in put_unbound_pool(), which caused a use-after-free bug reported by Cheung Wall.  To avoid the use-after-free bug, the pool’s reference must be held until the detachment is complete. Therefore, move the code that puts the pwq after detaching the rescuer from the pool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21784?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21784" src="https://img.shields.io/badge/CVE--2025--21784-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu: bail out when failed to load fw in psp_init_cap_microcode()  In function psp_init_cap_microcode(), it should bail out when failed to load firmware, otherwise it may cause invalid memory access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21781?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21781" src="https://img.shields.io/badge/CVE--2025--21781-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.109%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  batman-adv: fix panic during interface removal  Reference counting is used to ensure that batadv_hardif_neigh_node and batadv_hard_iface are not freed before/during batadv_v_elp_throughput_metric_update work is finished.  But there isn't a guarantee that the hard if will remain associated with a soft interface up until the work is finished.  This fixes a crash triggered by reboot that looks like this:  Call trace: batadv_v_mesh_free+0xd0/0x4dc [batman_adv] batadv_v_elp_throughput_metric_update+0x1c/0xa4 process_one_work+0x178/0x398 worker_thread+0x2e8/0x4d0 kthread+0xd8/0xdc ret_from_fork+0x10/0x20  (the batadv_v_mesh_free call is misleading, and does not actually happen)  I was able to make the issue happen more reliably by changing hardif_neigh->bat_v.metric_work work to be delayed work. This allowed me to track down and confirm the fix.  [sven@narfation.org: prevent entering batadv_v_elp_get_throughput without soft_iface]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21772?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21772" src="https://img.shields.io/badge/CVE--2025--21772-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.109%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  partitions: mac: fix handling of bogus partition table  Fix several issues in partition probing:  - The bailout for a bad partoffset must use put_dev_sector(), since the preceding read_part_sector() succeeded. - If the partition table claims a silly sector size like 0xfff bytes (which results in partition table entries straddling sector boundaries), bail out instead of accessing out-of-bounds memory. - We must not assume that the partition table contains proper NUL termination - use strnlen() and strncmp() instead of strlen() and strcmp().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21768?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21768" src="https://img.shields.io/badge/CVE--2025--21768-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: ipv6: fix dst ref loops in rpl, seg6 and ioam6 lwtunnels  Some lwtunnels have a dst cache for post-transformation dst. If the packet destination did not change we may end up recording a reference to the lwtunnel in its own cache, and the lwtunnel state will never be freed.  Discovered by the ioam6.sh test, kmemleak was recently fixed to catch per-cpu memory leaks. I'm not sure if rpl and seg6 can actually hit this, but in principle I don't see why not.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21767?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21767" src="https://img.shields.io/badge/CVE--2025--21767-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.099%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  clocksource: Use migrate_disable() to avoid calling get_random_u32() in atomic context  The following bug report happened with a PREEMPT_RT kernel:  BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48 in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 2012, name: kwatchdog preempt_count: 1, expected: 0 RCU nest depth: 0, expected: 0 get_random_u32+0x4f/0x110 clocksource_verify_choose_cpus+0xab/0x1a0 clocksource_verify_percpu.part.0+0x6b/0x330 clocksource_watchdog_kthread+0x193/0x1a0  It is due to the fact that clocksource_verify_choose_cpus() is invoked with preemption disabled.  This function invokes get_random_u32() to obtain random numbers for choosing CPUs.  The batched_entropy_32 local lock and/or the base_crng.lock spinlock in driver/char/random.c will be acquired during the call. In PREEMPT_RT kernel, they are both sleeping locks and so cannot be acquired in atomic context.  Fix this problem by using migrate_disable() to allow smp_processor_id() to be reliably used without introducing atomic context. preempt_disable() is then called after clocksource_verify_choose_cpus() but before the clocksource measurement is being run to avoid introducing unexpected latency.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21766?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21766" src="https://img.shields.io/badge/CVE--2025--21766-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.099%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv4: use RCU protection in __ip_rt_update_pmtu()  __ip_rt_update_pmtu() must use RCU protection to make sure the net structure it reads does not disappear.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21765?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21765" src="https://img.shields.io/badge/CVE--2025--21765-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.109%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: use RCU protection in ip6_default_advmss()  ip6_default_advmss() needs rcu protection to make sure the net structure it reads does not disappear.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21764?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21764" src="https://img.shields.io/badge/CVE--2025--21764-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ndisc: use RCU protection in ndisc_alloc_skb()  ndisc_alloc_skb() can be called without RTNL or RCU being held.  Add RCU protection to avoid possible UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21763?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21763" src="https://img.shields.io/badge/CVE--2025--21763-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  neighbour: use RCU protection in __neigh_notify()  __neigh_notify() can be called without RTNL or RCU protection.  Use RCU protection to avoid potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21762?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21762" src="https://img.shields.io/badge/CVE--2025--21762-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  arp: use RCU protection in arp_xmit()  arp_xmit() can be called without RTNL or RCU protection.  Use RCU protection to avoid potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21761?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21761" src="https://img.shields.io/badge/CVE--2025--21761-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  openvswitch: use RCU protection in ovs_vport_cmd_fill_info()  ovs_vport_cmd_fill_info() can be called without RTNL or RCU.  Use RCU protection and dev_net_rcu() to avoid potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21760?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21760" src="https://img.shields.io/badge/CVE--2025--21760-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ndisc: extend RCU protection in ndisc_send_skb()  ndisc_send_skb() can be called without RTNL or RCU held.  Acquire rcu_read_lock() earlier, so that we can use dev_net_rcu() and avoid a potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21759?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21759" src="https://img.shields.io/badge/CVE--2025--21759-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: mcast: extend RCU protection in igmp6_send()  igmp6_send() can be called without RTNL or RCU being held.  Extend RCU protection so that we can safely fetch the net pointer and avoid a potential UAF.  Note that we no longer can use sock_alloc_send_skb() because ipv6.igmp_sk uses GFP_KERNEL allocations which can sleep.  Instead use alloc_skb() and charge the net->ipv6.igmp_sk socket under RCU protection.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21758?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21758" src="https://img.shields.io/badge/CVE--2025--21758-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.113%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: mcast: add RCU protection to mld_newpack()  mld_newpack() can be called without RTNL or RCU being held.  Note that we no longer can use sock_alloc_send_skb() because ipv6.igmp_sk uses GFP_KERNEL allocations which can sleep.  Instead use alloc_skb() and charge the net->ipv6.igmp_sk socket under RCU protection.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21746?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21746" src="https://img.shields.io/badge/CVE--2025--21746-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Input: synaptics - fix crash when enabling pass-through port  When enabling a pass-through port an interrupt might come before psmouse driver binds to the pass-through port. However synaptics sub-driver tries to access psmouse instance presumably associated with the pass-through port to figure out if only 1 byte of response or entire protocol packet needs to be forwarded to the pass-through port and may crash if psmouse instance has not been attached to the port yet.  Fix the crash by introducing open() and close() methods for the port and check if the port is open before trying to access psmouse instance. Because psmouse calls serio_open() only after attaching psmouse instance to serio port instance this prevents the potential crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21712?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21712" src="https://img.shields.io/badge/CVE--2025--21712-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.064%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  md/md-bitmap: Synchronize bitmap_get_stats() with bitmap lifetime  After commit ec6bb299c7c3 ("md/md-bitmap: add 'sync_size' into struct md_bitmap_stats"), following panic is reported:  Oops: general protection fault, probably for non-canonical address RIP: 0010:bitmap_get_stats+0x2b/0xa0 Call Trace: <TASK> md_seq_show+0x2d2/0x5b0 seq_read_iter+0x2b9/0x470 seq_read+0x12f/0x180 proc_reg_read+0x57/0xb0 vfs_read+0xf6/0x380 ksys_read+0x6c/0xf0 do_syscall_64+0x82/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Root cause is that bitmap_get_stats() can be called at anytime if mddev is still there, even if bitmap is destroyed, or not fully initialized. Deferenceing bitmap in this case can crash the kernel. Meanwhile, the above commit start to deferencing bitmap->storage, make the problem easier to trigger.  Fix the problem by protecting bitmap_get_stats() with bitmap_info.mutex.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21706?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21706" src="https://img.shields.io/badge/CVE--2025--21706-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.064%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: pm: only set fullmesh for subflow endp  With the in-kernel path-manager, it is possible to change the 'fullmesh' flag. The code in mptcp_pm_nl_fullmesh() expects to change it only on 'subflow' endpoints, to recreate more or less subflows using the linked address.  Unfortunately, the set_flags() hook was a bit more permissive, and allowed 'implicit' endpoints to get the 'fullmesh' flag while it is not allowed before.  That's what syzbot found, triggering the following warning:  WARNING: CPU: 0 PID: 6499 at net/mptcp/pm_netlink.c:1496 __mark_subflow_endp_available net/mptcp/pm_netlink.c:1496 [inline] WARNING: CPU: 0 PID: 6499 at net/mptcp/pm_netlink.c:1496 mptcp_pm_nl_fullmesh net/mptcp/pm_netlink.c:1980 [inline] WARNING: CPU: 0 PID: 6499 at net/mptcp/pm_netlink.c:1496 mptcp_nl_set_flags net/mptcp/pm_netlink.c:2003 [inline] WARNING: CPU: 0 PID: 6499 at net/mptcp/pm_netlink.c:1496 mptcp_pm_nl_set_flags+0x974/0xdc0 net/mptcp/pm_netlink.c:2064 Modules linked in: CPU: 0 UID: 0 PID: 6499 Comm: syz.1.413 Not tainted 6.13.0-rc5-syzkaller-00172-gd1bf27c4e176 #0 Hardware name: Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:__mark_subflow_endp_available net/mptcp/pm_netlink.c:1496 [inline] RIP: 0010:mptcp_pm_nl_fullmesh net/mptcp/pm_netlink.c:1980 [inline] RIP: 0010:mptcp_nl_set_flags net/mptcp/pm_netlink.c:2003 [inline] RIP: 0010:mptcp_pm_nl_set_flags+0x974/0xdc0 net/mptcp/pm_netlink.c:2064 Code: 01 00 00 49 89 c5 e8 fb 45 e8 f5 e9 b8 fc ff ff e8 f1 45 e8 f5 4c 89 f7 be 03 00 00 00 e8 44 1d 0b f9 eb a0 e8 dd 45 e8 f5 90 <0f> 0b 90 e9 17 ff ff ff 89 d9 80 e1 07 38 c1 0f 8c c9 fc ff ff 48 RSP: 0018:ffffc9000d307240 EFLAGS: 00010293 RAX: ffffffff8bb72e03 RBX: 0000000000000000 RCX: ffff88807da88000 RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000 RBP: ffffc9000d307430 R08: ffffffff8bb72cf0 R09: 1ffff1100b842a5e R10: dffffc0000000000 R11: ffffed100b842a5f R12: ffff88801e2e5ac0 R13: ffff88805c214800 R14: ffff88805c2152e8 R15: 1ffff1100b842a5d FS:  00005555619f6500(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000020002840 CR3: 00000000247e6000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> genl_family_rcv_msg_doit net/netlink/genetlink.c:1115 [inline] genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline] genl_rcv_msg+0xb14/0xec0 net/netlink/genetlink.c:1210 netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2542 genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219 netlink_unicast_kernel net/netlink/af_netlink.c:1321 [inline] netlink_unicast+0x7f6/0x990 net/netlink/af_netlink.c:1347 netlink_sendmsg+0x8e4/0xcb0 net/netlink/af_netlink.c:1891 sock_sendmsg_nosec net/socket.c:711 [inline] __sock_sendmsg+0x221/0x270 net/socket.c:726 ____sys_sendmsg+0x52a/0x7e0 net/socket.c:2583 ___sys_sendmsg net/socket.c:2637 [inline] __sys_sendmsg+0x269/0x350 net/socket.c:2669 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7f5fe8785d29 Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 a8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007fff571f5558 EFLAGS: 00000246 ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX: 00007f5fe8975fa0 RCX: 00007f5fe8785d29 RDX: 0000000000000000 RSI: 0000000020000480 RDI: 0000000000000007 RBP: 00007f5fe8801b08 R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000 R13: 00007f5fe8975fa0 R14: 00007f5fe8975fa0 R15: 000000 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21704?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2025--21704" src="https://img.shields.io/badge/CVE--2025--21704-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.148%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: cdc-acm: Check control transfer buffer size before access  If the first fragment is shorter than struct usb_cdc_notification, we can't calculate an expected_size. Log an error and discard the notification instead of reading lengths from memory outside the received data, which can lead to memory corruption when the expected_size decreases between fragments, causing `expected_size - acm->nb_index` to wrap.  This issue has been present since the beginning of git history; however, it only leads to memory corruption since commit ea2583529cd1 ("cdc-acm: reassemble fragmented notifications").  A mitigating factor is that acm_ctrl_irq() can only execute after userspace has opened /dev/ttyACM*; but if ModemManager is running, ModemManager will do that automatically depending on the USB device's vendor/product IDs and its other interfaces.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58086?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2024--58086" src="https://img.shields.io/badge/CVE--2024--58086-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.099%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/v3d: Stop active perfmon if it is being destroyed  If the active performance monitor (`v3d->active_perfmon`) is being destroyed, stop it first. Currently, the active perfmon is not stopped during destruction, leaving the `v3d->active_perfmon` pointer stale. This can lead to undefined behavior and instability.  This patch ensures that the active perfmon is stopped before being destroyed, aligning with the behavior introduced in commit 7d1fd3638ee3 ("drm/v3d: Stop the active perfmon before being destroyed").

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54458?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2024--54458" src="https://img.shields.io/badge/CVE--2024--54458-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: ufs: bsg: Set bsg_queue to NULL after removal  Currently, this does not cause any issues, but I believe it is necessary to set bsg_queue to NULL after removing it to prevent potential use-after-free (UAF) access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54456?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="medium : CVE--2024--54456" src="https://img.shields.io/badge/CVE--2024--54456-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  NFS: Fix potential buffer overflowin nfs_sysfs_link_rpc_client()  name is char[64] where the size of clnt->cl_program->name remains unknown. Invoking strcat() directly will also lead to potential buffer overflow. Change them to strscpy() and strncat() to fix potential issues.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58093?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-78.78"><img alt="low : CVE--2024--58093" src="https://img.shields.io/badge/CVE--2024--58093-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-78.78</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-78.78</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  PCI/ASPM: Fix link state exit during switch upstream function removal  Before 456d8aa37d0f ("PCI/ASPM: Disable ASPM on MFD function removal to avoid use-after-free"), we would free the ASPM link only after the last function on the bus pertaining to the given link was removed.  That was too late. If function 0 is removed before sibling function, link->downstream would point to free'd memory after.  After above change, we freed the ASPM parent link state upon any function removal on the bus pertaining to a given link.  That is too early. If the link is to a PCIe switch with MFD on the upstream port, then removing functions other than 0 first would free a link which still remains parent_link to the remaining downstream ports.  The resulting GPFs are especially frequent during hot-unplug, because pciehp removes devices on the link bus in reverse order.  On that switch, function 0 is the virtual P2P bridge to the internal bus. Free exactly when function 0 is removed -- before the parent link is obsolete, but after all subordinate links are gone.  [kwilczynski: commit log]

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.commons/commons-vfs2</strong> <code>2.9.0</code> (maven)</summary>

<small><code>pkg:maven/org.apache.commons/commons-vfs2@2.9.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-27553?s=github&n=commons-vfs2&ns=org.apache.commons&t=maven&vr=%3C2.10.0"><img alt="high 7.5: CVE--2025--27553" src="https://img.shields.io/badge/CVE--2025--27553-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Relative Path Traversal</i>

<table>
<tr><td>Affected range</td><td><code><2.10.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.10.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.148%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Relative Path Traversal vulnerability in Apache Commons VFS before 2.10.0.

The FileObject API in Commons VFS has a 'resolveFile' method that
takes a 'scope' parameter. Specifying 'NameScope.DESCENDENT' promises that "an exception is thrown if the resolved file is not a descendent of
the base file". However, when the path contains encoded ".."
characters (for example, "%2E%2E/bar.txt"), it might return file objects that are not
a descendent of the base file, without throwing an exception.
This issue affects Apache Commons VFS: before 2.10.0.

Users are recommended to upgrade to version 2.10.0, which fixes the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-30474?s=github&n=commons-vfs2&ns=org.apache.commons&t=maven&vr=%3C2.10.0"><img alt="medium 6.9: CVE--2025--30474" src="https://img.shields.io/badge/CVE--2025--30474-lightgrey?label=medium%206.9&labelColor=fbb552"/></a> <i>Exposure of Sensitive Information to an Unauthorized Actor</i>

<table>
<tr><td>Affected range</td><td><code><2.10.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.10.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.109%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Exposure of Sensitive Information to an Unauthorized Actor vulnerability in Apache Commons VFS.

The FtpFileObject class can throw an exception when a file is not found, revealing the original URI in its message, which may include a password. The fix is to mask the password in the exception message
This issue affects Apache Commons VFS: before 2.10.0.

Users are recommended to upgrade to version 2.10.0, which fixes the issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.eclipse.jetty/jetty-server</strong> <code>9.4.52.v20230823</code> (maven)</summary>

<small><code>pkg:maven/org.eclipse.jetty/jetty-server@9.4.52.v20230823</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-13009?s=github&n=jetty-server&ns=org.eclipse.jetty&t=maven&vr=%3E%3D9.4.0%2C%3C%3D9.4.56"><img alt="high 7.2: CVE--2024--13009" src="https://img.shields.io/badge/CVE--2024--13009-lightgrey?label=high%207.2&labelColor=e25d68"/></a> <i>Improper Resource Shutdown or Release</i>

<table>
<tr><td>Affected range</td><td><code>>=9.4.0<br/><=9.4.56</code></td></tr>
<tr><td>Fixed version</td><td><code>9.4.57.v20241219</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Eclipse Jetty versions 9.4.0 to 9.4.56 a buffer can be incorrectly released when confronted with a gzip error when inflating a request body. This can result in corrupted and/or inadvertent sharing of data between requests.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-8184?s=github&n=jetty-server&ns=org.eclipse.jetty&t=maven&vr=%3E%3D9.3.12%2C%3C%3D9.4.55"><img alt="medium 5.9: CVE--2024--8184" src="https://img.shields.io/badge/CVE--2024--8184-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=9.3.12<br/><=9.4.55</code></td></tr>
<tr><td>Fixed version</td><td><code>9.4.56</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.250%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>48th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact
Remote DOS attack can cause out of memory 

### Description
There exists a security vulnerability in Jetty's `ThreadLimitHandler.getRemote()` which
can be exploited by unauthorized users to cause remote denial-of-service (DoS) attack.  By
repeatedly sending crafted requests, attackers can trigger OutofMemory errors and exhaust the
server's memory.

### Affected Versions

* Jetty 12.0.0-12.0.8 (Supported)
* Jetty 11.0.0-11.0.23 (EOL)
* Jetty 10.0.0-10.0.23 (EOL)
* Jetty 9.3.12-9.4.55 (EOL)

### Patched Versions

* Jetty 12.0.9
* Jetty 11.0.24
* Jetty 10.0.24
* Jetty 9.4.56

### Workarounds

Do not use `ThreadLimitHandler`.  
Consider use of `QoSHandler` instead to artificially limit resource utilization.

### References

Jetty 12 - https://github.com/jetty/jetty.project/pull/11723

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.zookeeper/zookeeper</strong> <code>3.9.2</code> (maven)</summary>

<small><code>pkg:maven/org.apache.zookeeper/zookeeper@3.9.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-51504?s=github&n=zookeeper&ns=org.apache.zookeeper&t=maven&vr=%3E%3D3.9.0%2C%3C3.9.3"><img alt="high 8.8: CVE--2024--51504" src="https://img.shields.io/badge/CVE--2024--51504-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Authentication Bypass by Spoofing</i>

<table>
<tr><td>Affected range</td><td><code>>=3.9.0<br/><3.9.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.9.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.312%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>54th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When using IPAuthenticationProvider in ZooKeeper Admin Server there is a possibility of Authentication Bypass by Spoofing -- this only impacts IP based authentication implemented in ZooKeeper Admin Server. Default configuration of client's IP address detection in IPAuthenticationProvider, which uses HTTP request headers, is weak and allows an attacker to bypass authentication via spoofing client's IP address in request headers. Default configuration honors X-Forwarded-For HTTP header to read client's IP address. X-Forwarded-For request header is mainly used by proxy servers to identify the client and can be easily spoofed by an attacker pretending that the request comes from a different IP address. Admin Server commands, such as snapshot and restore arbitrarily can be executed on successful exploitation which could potentially lead to information leakage or service availability issues. Users are recommended to upgrade to version 3.9.3, which fixes this issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>io.netty/netty-codec-http2</strong> <code>4.1.114.Final</code> (maven)</summary>

<small><code>pkg:maven/io.netty/netty-codec-http2@4.1.114.Final</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-55163?s=github&n=netty-codec-http2&ns=io.netty&t=maven&vr=%3C%3D4.1.123.Final"><img alt="high 8.2: CVE--2025--55163" src="https://img.shields.io/badge/CVE--2025--55163-lightgrey?label=high%208.2&labelColor=e25d68"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code><=4.1.123.Final</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.124.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.055%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Below is a technical explanation of a newly discovered vulnerability in HTTP/2, which we refer to as “MadeYouReset.”

### MadeYouReset Vulnerability Summary
The MadeYouReset DDoS vulnerability is a logical vulnerability in the HTTP/2 protocol, that uses malformed HTTP/2 control frames in order to break the max concurrent streams limit - which results in resource exhaustion and distributed denial of service.

### Mechanism
The vulnerability uses malformed HTTP/2 control frames, or malformed flow, in order to make the server reset streams created by the client (using the RST_STREAM frame). 
The vulnerability could be triggered by several primitives, defined by the RFC of HTTP/2 (RFC 9113). The Primitives are:
1. WINDOW_UPDATE frame with an increment of 0 or an increment that makes the window exceed 2^31 - 1. (section 6.9 + 6.9.1)
2. HEADERS or DATA frames sent on a half-closed (remote) stream (which was closed using the END_STREAM flag). (note that for some implementations it's possible a CONTINUATION frame to trigger that as well - but it's very rare). (Section 5.1)
3. PRIORITY frame with a length other than 5. (section 6.3)
From our experience, the primitives are likely to exist in the decreasing order listed above.
Note that based on the implementation of the library, other primitives (which are not defined by the RFC) might exist - meaning scenarios in which RST_STREAM is not supposed to be sent, but in the implementation it does. On the other hand - some RFC-defined primitives might not work, even though they are defined by the RFC (as some implementations are not fully complying with RFC). For example, some implementations we’ve seen discard the PRIORITY frame - and thus does not return RST_STREAM, and some implementations send GO_AWAY when receiving a WINDOW_UPDATE frame with increment of 0.

The vulnerability takes advantage of a design flaw in the HTTP/2 protocol - While HTTP/2 has a limit on the number of concurrently active streams per connection (which is usually 100, and is set by the parameter SETTINGS_MAX_CONCURRENT_STREAMS), the number of active streams is not counted correctly - when a stream is reset, it is immediately considered not active, and thus unaccounted for in the active streams counter. 
While the protocol does not count those streams as active, the server’s backend logic still processes and handles the requests that were canceled.

Thus, the attacker can exploit this vulnerability to cause the server to handle an unbounded number of concurrent streams from a client on the same connection. The exploitation is very simple: the client issues a request in a stream, and then sends the control frame that causes the server to send a RST_STREAM.

### Attack Flow
For example, a possible attack scenario can be: 
1. Attacker opens an HTTP/2 connection to the server.
2. Attacker sends HEADERS frame with END_STREAM flag on a new stream X.  
3. Attacker sends WINDOW_UPDATE for stream X with flow-control window of 0.
4. The server receives the WINDOW_UPDATE and immediately sends RST_STREAM for stream X to the client (+ decreases the active streams counter by 1).

The attacker can repeat steps 2+3 as rapidly as it is capable, since the active streams counter never exceeds 1 and the attacker does not need to wait for the response from the server.
This leads to resource exhaustion and distributed denial of service vulnerabilities with an impact of: CPU overload and/or memory exhaustion (implementation dependent)

### Comparison to Rapid Reset
The vulnerability takes advantage of a design flow in the HTTP/2 protocol that was also used in the Rapid Reset vulnerability (CVE-2023-44487) which was exploited as a zero-day in the wild in August 2023 to October 2023, against multiple services and vendors.
The Rapid Reset vulnerability uses RST_STREAM frames sent from the client, in order to create an unbounded amount of concurrent streams - it was given a CVSS score of 7.5.
Rapid Reset was mostly mitigated by limiting the number/rate of RST_STREAM sent from the client, which does not mitigate the MadeYouReset attack - since it triggers the server to send a RST_STREAM.

### Suggested Mitigations for MadeYouReset
A quick and easy mitigation will be to limit the number/rate of RST_STREAMs sent from the server.
It is also possible to limit the number/rate of control frames sent by the client (e.g. WINDOW_UPDATE and PRIORITY), and treat protocol flow errors as a connection error.

As mentioned in our previous message, this is a protocol-level vulnerability that affects multiple vendors and implementations. Given its broad impact, it is the shared responsibility of all parties involved to handle the disclosure process carefully and coordinate mitigations effectively.


If you have any questions, we will be happy to clarify or schedule a Zoom call.

Gal, Anat and Yaniv.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>io.netty/netty-handler</strong> <code>4.1.114.Final</code> (maven)</summary>

<small><code>pkg:maven/io.netty/netty-handler@4.1.114.Final</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-24970?s=github&n=netty-handler&ns=io.netty&t=maven&vr=%3E%3D4.1.91.Final%2C%3C%3D4.1.117.Final"><img alt="high 7.5: CVE--2025--24970" src="https://img.shields.io/badge/CVE--2025--24970-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code>>=4.1.91.Final<br/><=4.1.117.Final</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.118.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.156%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>37th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact
When a special crafted packet is received via SslHandler it doesn't correctly handle validation of such a packet in all cases which can lead to a native crash.

### Workarounds
As workaround its possible to either disable the usage of the native SSLEngine or changing the code from:

```
SslContext context = ...;
SslHandler handler = context.newHandler(....);
```

to:

```
SslContext context = ...;
SSLEngine engine = context.newEngine(....);
SslHandler handler = new SslHandler(engine, ....);
```

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>commons-beanutils/commons-beanutils</strong> <code>1.9.4</code> (maven)</summary>

<small><code>pkg:maven/commons-beanutils/commons-beanutils@1.9.4</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-48734?s=github&n=commons-beanutils&ns=commons-beanutils&t=maven&vr=%3E%3D1.0%2C%3C%3D1.10.1"><img alt="high 8.8: CVE--2025--48734" src="https://img.shields.io/badge/CVE--2025--48734-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Improper Access Control</i>

<table>
<tr><td>Affected range</td><td><code>>=1.0<br/><=1.10.1</code></td></tr>
<tr><td>Fixed version</td><td><code>1.11.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper Access Control vulnerability in Apache Commons.



A special BeanIntrospector class was added in version 1.9.2. This can be used to stop attackers from using the declared class property of Java enum objects to get access to the classloader. However this protection was not enabled by default. PropertyUtilsBean (and consequently BeanUtilsBean) now disallows declared class level property access by default.





Releases 1.11.0 and 2.0.0-M2 address a potential security issue when accessing enum properties in an uncontrolled way. If an application using Commons BeanUtils passes property paths from an external source directly to the getProperty() method of PropertyUtilsBean, an attacker can access the enum’s class loader via the “declaredClass” property available on all Java “enum” objects. Accessing the enum’s “declaredClass” allows remote attackers to access the ClassLoader and execute arbitrary code. The same issue exists with PropertyUtilsBean.getNestedProperty().
Starting in versions 1.11.0 and 2.0.0-M2 a special BeanIntrospector suppresses the “declaredClass” property. Note that this new BeanIntrospector is enabled by default, but you can disable it to regain the old behavior; see section 2.5 of the user's guide and the unit tests.

This issue affects Apache Commons BeanUtils 1.x before 1.11.0, and 2.x before 2.0.0-M2.Users of the artifact commons-beanutils:commons-beanutils

 1.x are recommended to upgrade to version 1.11.0, which fixes the issue.


Users of the artifact org.apache.commons:commons-beanutils2

 2.x are recommended to upgrade to version 2.0.0-M2, which fixes the issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libxml2</strong> <code>2.9.14+dfsg-1.3ubuntu3.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libxml2@2.9.14%2Bdfsg-1.3ubuntu3.3?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6170?s=ubuntu&n=libxml2&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C2.9.14%2Bdfsg-1.3ubuntu3.4"><img alt="medium 2.5: CVE--2025--6170" src="https://img.shields.io/badge/CVE--2025--6170-lightgrey?label=medium%202.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.9.14+dfsg-1.3ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.14+dfsg-1.3ubuntu3.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>2.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the interactive shell of the xmllint command-line tool, used for parsing XML files. When a user inputs an overly long command, the program does not check the input size properly, which can cause it to crash. This issue might allow attackers to run harmful code in rare configurations without modern protections.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-6021?s=ubuntu&n=libxml2&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C2.9.14%2Bdfsg-1.3ubuntu3.4"><img alt="medium : CVE--2025--6021" src="https://img.shields.io/badge/CVE--2025--6021-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.9.14+dfsg-1.3ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.14+dfsg-1.3ubuntu3.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.089%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in libxml2's xmlBuildQName function, where integer overflows in buffer size calculations can lead to a stack-based buffer overflow. This issue can result in memory corruption or a denial of service when processing crafted input.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-49796?s=ubuntu&n=libxml2&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C2.9.14%2Bdfsg-1.3ubuntu3.4"><img alt="medium : CVE--2025--49796" src="https://img.shields.io/badge/CVE--2025--49796-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.9.14+dfsg-1.3ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.14+dfsg-1.3ubuntu3.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.200%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in libxml2. Processing certain sch:name elements from the input XML file can trigger a memory corruption issue. This flaw allows an attacker to craft a malicious XML input file that can lead libxml to crash, resulting in a denial of service or other possible undefined behavior due to sensitive data being corrupted in memory.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-49794?s=ubuntu&n=libxml2&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C2.9.14%2Bdfsg-1.3ubuntu3.4"><img alt="medium : CVE--2025--49794" src="https://img.shields.io/badge/CVE--2025--49794-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.9.14+dfsg-1.3ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.14+dfsg-1.3ubuntu3.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.202%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability was found in libxml2. This issue occurs when parsing XPath elements under certain circumstances when the XML schematron has the <sch:name path="..."/> schema elements. This flaw allows a malicious actor to craft a malicious XML document used as input for libxml, resulting in the program's crash using libxml or other possible undefined behaviors.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>openjdk-17</strong> <code>17.0.15+6~us1-0ubuntu1~24.04</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openjdk-17@17.0.15%2B6~us1-0ubuntu1~24.04?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-50106?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C17.0.16%2B8%7Eus1-0ubuntu1%7E24.04.1"><img alt="medium : CVE--2025--50106" src="https://img.shields.io/badge/CVE--2025--50106-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.16+8~us1-0ubuntu1~24.04.1</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.16+8~us1-0ubuntu1~24.04.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.174%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 2D).  Supported versions that are affected are Oracle Java SE: 8u451, 8u451-perf, 11.0.27, 17.0.15, 21.0.7, 24.0.1; Oracle GraalVM for JDK: 17.0.15, 21.0.7 and 24.0.1; Oracle GraalVM Enterprise Edition: 21.3.14. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-50059?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C17.0.16%2B8%7Eus1-0ubuntu1%7E24.04.1"><img alt="medium : CVE--2025--50059" src="https://img.shields.io/badge/CVE--2025--50059-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.16+8~us1-0ubuntu1~24.04.1</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.16+8~us1-0ubuntu1~24.04.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.054%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Networking). Supported versions that are affected are Oracle Java SE: 8u451-perf, 11.0.27, 17.0.15, 21.0.7, 24.0.1; Oracle GraalVM for JDK: 17.0.15, 21.0.7 and  24.0.1; Oracle GraalVM Enterprise Edition: 21.3.14. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  While the vulnerability is in Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition, attacks may significantly impact additional products (scope change).  Successful attacks of this vulnerability can result in  unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 8.6 (Confidentiality impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-30754?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C17.0.16%2B8%7Eus1-0ubuntu1%7E24.04.1"><img alt="medium : CVE--2025--30754" src="https://img.shields.io/badge/CVE--2025--30754-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.16+8~us1-0ubuntu1~24.04.1</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.16+8~us1-0ubuntu1~24.04.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u451, 8u451-perf, 11.0.27, 17.0.15, 21.0.7, 24.0.1; Oracle GraalVM for JDK: 17.0.15, 21.0.7 and 24.0.1; Oracle GraalVM Enterprise Edition: 21.3.14. Difficult to exploit vulnerability allows unauthenticated attacker with network access via TLS to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized read access to a subset of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 4.8 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-30749?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C17.0.16%2B8%7Eus1-0ubuntu1%7E24.04.1"><img alt="medium : CVE--2025--30749" src="https://img.shields.io/badge/CVE--2025--30749-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.16+8~us1-0ubuntu1~24.04.1</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.16+8~us1-0ubuntu1~24.04.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.174%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 2D).  Supported versions that are affected are Oracle Java SE: 8u451, 8u451-perf, 11.0.27, 17.0.15, 21.0.7, 24.0.1; Oracle GraalVM for JDK: 17.0.15, 21.0.7 and 24.0.1; Oracle GraalVM Enterprise Edition: 21.3.14. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>org.eclipse.jetty/jetty-webapp</strong> <code>9.4.43.v20210629</code> (maven)</summary>

<small><code>pkg:maven/org.eclipse.jetty/jetty-webapp@9.4.43.v20210629</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-40167?s=gitlab&n=jetty-webapp&ns=org.eclipse.jetty&t=maven&vr=%3E%3D9.0.0%2C%3C9.4.52"><img alt="medium 5.3: CVE--2023--40167" src="https://img.shields.io/badge/CVE--2023--40167-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.4.52</code></td></tr>
<tr><td>Fixed version</td><td><code>9.4.52.v20230823, 10.0.16, 11.0.16</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.542%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>85th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

Jetty accepts the '+' character proceeding the content-length value in a HTTP/1 header field. This is more permissive than allowed by the RFC and other servers routinely reject such requests with 400 responses. There is no known exploit scenario, but it is conceivable that request smuggling could result if jetty is used in combination with a server that does not close the connection after sending such a 400 response.

### Workarounds

There is no workaround as there is no known exploit scenario. 

### Original Report 

[RFC 9110 Secion 8.6](https://www.rfc-editor.org/rfc/rfc9110#section-8.6) defined the value of Content-Length header should be a string of 0-9 digits. However we found that Jetty accepts "+" prefixed Content-Length, which could lead to potential HTTP request smuggling.

Payload:

```
 POST / HTTP/1.1
 Host: a.com
 Content-Length: +16
 Connection: close
 ​
 0123456789abcdef
```

When sending this payload to Jetty, it can successfully parse and identify the length.

When sending this payload to NGINX, Apache HTTPd or other HTTP servers/parsers, they will return 400 bad request.

This behavior can lead to HTTP request smuggling and can be leveraged to bypass WAF or IDS.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-26049?s=gitlab&n=jetty-webapp&ns=org.eclipse.jetty&t=maven&vr=%3C9.4.51"><img alt="medium 5.3: CVE--2023--26049" src="https://img.shields.io/badge/CVE--2023--26049-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><9.4.51</code></td></tr>
<tr><td>Fixed version</td><td><code>9.4.51.v20230217, 10.0.14, 11.0.14</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.263%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>49th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Jetty is a java based web server and servlet engine. Nonstandard cookie parsing in Jetty may allow an attacker to smuggle cookies within other cookies, or otherwise perform unintended behavior by tampering with the cookie parsing mechanism. If Jetty sees a cookie VALUE that starts with `"` (double quote), it will continue to read the cookie string until it sees a closing quote -- even if a semicolon is encountered. So, a cookie header such as: `DISPLAY_LANGUAGE="b; JSESSIONID=1337; c=d"` will be parsed as one cookie, with the name DISPLAY_LANGUAGE and a value of b; JSESSIONID=1337; c=d instead of 3 separate cookies. This has security implications because if, say, JSESSIONID is an HttpOnly cookie, and the DISPLAY_LANGUAGE cookie value is rendered on the page, an attacker can smuggle the JSESSIONID cookie into the DISPLAY_LANGUAGE cookie and thereby exfiltrate it. This is significant when an intermediary is enacting some policy based on cookies, so a smuggled cookie can bypass that policy yet still be seen by the Jetty server or its logging system. This issue has been addressed in versions 9.4.51, 10.0.14, 11.0.14, and 12.0.0.beta0 and users are advised to upgrade. There are no known workarounds for this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-41900?s=gitlab&n=jetty-webapp&ns=org.eclipse.jetty&t=maven&vr=%3E%3D9.4.21%2C%3C9.4.52"><img alt="medium 4.3: CVE--2023--41900" src="https://img.shields.io/badge/CVE--2023--41900-lightgrey?label=medium%204.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.4.21<br/><9.4.52</code></td></tr>
<tr><td>Fixed version</td><td><code>9.4.52.v20230823, 10.0.16, 11.0.16</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.084%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

If a Jetty `OpenIdAuthenticator` uses the optional nested `LoginService`, and that `LoginService` decides to revoke an already authenticated user, then the current request will still treat the user as authenticated. The authentication is then cleared from the session and subsequent requests will not be treated as authenticated.

So a request on a previously authenticated session could be allowed to bypass authentication after it had been rejected by the `LoginService`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-36479?s=gitlab&n=jetty-webapp&ns=org.eclipse.jetty&t=maven&vr=%3E%3D9.0.0%2C%3C9.4.52"><img alt="low 3.5: CVE--2023--36479" src="https://img.shields.io/badge/CVE--2023--36479-lightgrey?label=low%203.5&labelColor=fce1a9"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.4.52</code></td></tr>
<tr><td>Fixed version</td><td><code>9.4.52.v20230823, 10.0.16, 11.0.16</code></td></tr>
<tr><td>CVSS Score</td><td><code>3.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.627%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>69th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

If a user sends a request to a `org.eclipse.jetty.servlets.CGI` Servlet for a binary with a space in its name, the servlet will escape the command by wrapping it in quotation marks. This wrapped command, plus an optional command prefix, will then be executed through a call to Runtime.exec. If the original binary name provided by the user contains a quotation mark followed by a space, the resulting command line will contain multiple tokens instead of one. For example, if a request references a binary called file” name “here, the escaping algorithm will generate the command line string “file” name “here”, which will invoke the binary named file, not the one that the user requested.

```java
if (execCmd.length() > 0 && execCmd.charAt(0) != '"' && execCmd.contains(" "))
execCmd = "\"" + execCmd + "\"";
```

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>tiff</strong> <code>4.5.1+git230720-4ubuntu2.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/tiff@4.5.1%2Bgit230720-4ubuntu2.2?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-8851?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C4.5.1%2Bgit230720-4ubuntu2.3"><img alt="medium : CVE--2025--8851" src="https://img.shields.io/badge/CVE--2025--8851-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.5.1+git230720-4ubuntu2.3</code></td></tr>
<tr><td>Fixed version</td><td><code>4.5.1+git230720-4ubuntu2.3</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was determined in LibTIFF up to 4.5.1. Affected by this issue is the function readSeparateStripsetoBuffer of the file tools/tiffcrop.c of the component tiffcrop. The manipulation leads to stack-based buffer overflow. Local access is required to approach this attack. The patch is identified as 8a7a48d7a645992ca83062b3a1873c951661e2b3. It is recommended to apply a patch to fix this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-8534?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C4.5.1%2Bgit230720-4ubuntu2.3"><img alt="medium : CVE--2025--8534" src="https://img.shields.io/badge/CVE--2025--8534-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.5.1+git230720-4ubuntu2.3</code></td></tr>
<tr><td>Fixed version</td><td><code>4.5.1+git230720-4ubuntu2.3</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability classified as problematic was found in libtiff 4.6.0. This vulnerability affects the function PS_Lvl2page of the file tools/tiff2ps.c of the component tiff2ps. The manipulation leads to null pointer dereference. It is possible to launch the attack on the local host. The complexity of an attack is rather high. The exploitation appears to be difficult. The exploit has been disclosed to the public and may be used. The name of the patch is 6ba36f159fd396ad11bf6b7874554197736ecc8b. It is recommended to apply a patch to fix this issue. One of the maintainers explains, that "[t]his error only occurs if DEFER_STRILE_LOAD (defer-strile-load:BOOL=ON) or TIFFOpen( .. "rD") option is used."

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-8176?s=ubuntu&n=tiff&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C4.5.1%2Bgit230720-4ubuntu2.3"><img alt="low : CVE--2025--8176" src="https://img.shields.io/badge/CVE--2025--8176-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.5.1+git230720-4ubuntu2.3</code></td></tr>
<tr><td>Fixed version</td><td><code>4.5.1+git230720-4ubuntu2.3</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in LibTIFF up to 4.7.0. It has been declared as critical. This vulnerability affects the function get_histogram of the file tools/tiffmedian.c. The manipulation leads to use after free. The attack needs to be approached locally. The exploit has been disclosed to the public and may be used. The patch is identified as fe10872e53efba9cc36c66ac4ab3b41a839d5172. It is recommended to apply a patch to fix this issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>io.netty/netty-common</strong> <code>4.1.114.Final</code> (maven)</summary>

<small><code>pkg:maven/io.netty/netty-common@4.1.114.Final</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-25193?s=github&n=netty-common&ns=io.netty&t=maven&vr=%3C4.1.118.Final"><img alt="medium 5.5: CVE--2025--25193" src="https://img.shields.io/badge/CVE--2025--25193-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><4.1.118.Final</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.118.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.113%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>31st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
An unsafe reading of environment file could potentially cause a denial of service in Netty.
When loaded on an Windows application, Netty attemps to load a file that does not exist. If an attacker creates such a large file, the Netty application crash.

### Details
A similar issue was previously reported in https://github.com/netty/netty/security/advisories/GHSA-xq3w-v528-46rv
This issue was fixed, but the fix was incomplete in that null-bytes were not counted against the input limit.


### PoC
The PoC is the same as for https://github.com/netty/netty/security/advisories/GHSA-xq3w-v528-46rv with the detail that the file should only contain null-bytes; 0x00.
When the null-bytes are encountered by the `InputStreamReader`, it will issue replacement characters in its charset decoding, which will fill up the line-buffer in the `BufferedReader.readLine()`, because the replacement character is not a line-break character.

### Impact
Impact is the same as https://github.com/netty/netty/security/advisories/GHSA-xq3w-v528-46rv

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-47535?s=github&n=netty-common&ns=io.netty&t=maven&vr=%3C%3D4.1.114.Final"><img alt="medium 5.4: CVE--2024--47535" src="https://img.shields.io/badge/CVE--2024--47535-lightgrey?label=medium%205.4&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><=4.1.114.Final</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.115.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:P</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary

An unsafe reading of environment file could potentially cause a denial of service in Netty.
When loaded on an Windows application, Netty attemps to load a file that does not exist. If an attacker creates such a large file, the Netty application crash.


### Details

When the library netty is loaded in a java windows application, the library tries to identify the system environnement in which it is executed.

At this stage, Netty tries to load both `/etc/os-release` and `/usr/lib/os-release` even though it is in a Windows environment. 

<img width="364" alt="1" src="https://github.com/user-attachments/assets/9466b181-9394-45a3-b0e3-1dcf105def59">

If netty finds this files, it reads them and loads them into memory.

By default :

- The JVM maximum memory size is set to 1 GB,
- A non-privileged user can create a directory at `C:\` and create files within it.

<img width="340" alt="2" src="https://github.com/user-attachments/assets/43b359a2-5871-4592-ae2b-ffc40ac76831">

<img width="523" alt="3" src="https://github.com/user-attachments/assets/ad5c6eed-451c-4513-92d5-ba0eee7715c1">

the source code identified :
https://github.com/netty/netty/blob/4.1/common/src/main/java/io/netty/util/internal/PlatformDependent.java

Despite the implementation of the function `normalizeOs()` the source code not verify the OS before reading `C:\etc\os-release` and `C:\usr\lib\os-release`.

### PoC

Create a file larger than 1 GB of data in `C:\etc\os-release` or `C:\usr\lib\os-release` on a Windows environnement and start your Netty application.

To observe what the application does with the file, the security analyst used "Process Monitor" from the "Windows SysInternals" suite. (https://learn.microsoft.com/en-us/sysinternals/)

```
cd C:\etc
fsutil file createnew os-release 3000000000
```

<img width="519" alt="4" src="https://github.com/user-attachments/assets/39df22a3-462b-4fd0-af9a-aa30077ec08f">

<img width="517" alt="5" src="https://github.com/user-attachments/assets/129dbd50-fc36-4da5-8eb1-582123fb528f">

The source code used is the Netty website code example : [Echo ‐ the very basic client and server](https://netty.io/4.1/xref/io/netty/example/echo/package-summary.html).

The vulnerability was tested on the 4.1.112.Final version.

The security analyst tried the same technique for `C:\proc\sys\net\core\somaxconn` with a lot of values to impact Netty but the only things that works is the "larger than 1 GB file" technique. https://github.com/netty/netty/blob/c0fdb8e9f8f256990e902fcfffbbe10754d0f3dd/common/src/main/java/io/netty/util/NetUtil.java#L186

### Impact

By loading the "file larger than 1 GB" into the memory, the Netty library exceeds the JVM memory limit and causes a crash in the java Windows application.

This behaviour occurs 100% of the time in both Server mode and Client mode if the large file exists.

Client mode :

<img width="449" alt="6" src="https://github.com/user-attachments/assets/f8fe1ed0-1a42-4490-b9ed-dbc9af7804be">

Server mode :

<img width="464" alt="7" src="https://github.com/user-attachments/assets/b34b42bd-4fbd-4170-b93a-d29ba87b88eb">

somaxconn :

<img width="532" alt="8" src="https://github.com/user-attachments/assets/0656b3bb-32c6-4ae2-bff7-d93babba08a3">

### Severity

- Attack vector : "Local" because the attacker needs to be on the system where the Netty application is running.
- Attack complexity : "Low" because the attacker only need to create a massive file (regardless of its contents).
- Privileges required : "Low" because the attacker requires a user account to exploit the vulnerability.
- User intercation : "None" because the administrator don't need to accidentally click anywhere to trigger the vulnerability. Furthermore, the exploitation works with defaults windows/AD settings.
- Scope : "Unchanged" because only Netty is affected by the vulnerability.
- Confidentiality : "None" because no data is exposed through exploiting the vulnerability.
- Integrity : "None" because the explotation of the vulnerability does not allow editing, deleting or adding data elsewhere.
- Availability : "High" because the exploitation of this vulnerability crashes the entire java application.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>python3.12</strong> <code>3.12.3-1ubuntu0.7</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/python3.12@3.12.3-1ubuntu0.7?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-8194?s=ubuntu&n=python3.12&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.12.3-1ubuntu0.8"><img alt="medium : CVE--2025--8194" src="https://img.shields.io/badge/CVE--2025--8194-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.12.3-1ubuntu0.8</code></td></tr>
<tr><td>Fixed version</td><td><code>3.12.3-1ubuntu0.8</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.096%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

There is a defect in the CPython “tarfile” module affecting the “TarFile” extraction and entry enumeration APIs. The tar implementation would process tar archives with negative offsets without error, resulting in an infinite loop and deadlock during the parsing of maliciously crafted tar archives.  This vulnerability can be mitigated by including the following patch after importing the “tarfile” module: https://gist.github.com/sethmlarson/1716ac5b82b73dbcbf23ad2eff8b33e1

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-6069?s=ubuntu&n=python3.12&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.12.3-1ubuntu0.8"><img alt="medium : CVE--2025--6069" src="https://img.shields.io/badge/CVE--2025--6069-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.12.3-1ubuntu0.8</code></td></tr>
<tr><td>Fixed version</td><td><code>3.12.3-1ubuntu0.8</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.090%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The html.parser.HTMLParser class had worse-case quadratic complexity when processing certain crafted malformed inputs potentially leading to amplified denial-of-service.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>ch.qos.logback/logback-core</strong> <code>1.4.14</code> (maven)</summary>

<small><code>pkg:maven/ch.qos.logback/logback-core@1.4.14</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12798?s=github&n=logback-core&ns=ch.qos.logback&t=maven&vr=%3E%3D1.4.0%2C%3C1.5.13"><img alt="medium 5.9: CVE--2024--12798" src="https://img.shields.io/badge/CVE--2024--12798-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')</i>

<table>
<tr><td>Affected range</td><td><code>>=1.4.0<br/><1.5.13</code></td></tr>
<tr><td>Fixed version</td><td><code>1.5.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:L/SI:H/SA:L/RE:L/U:Clear</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.175%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ACE vulnerability in JaninoEventEvaluator by QOS.CH logback-core up to and including version 1.5.12 in Java applications allows attackers to execute arbitrary code by compromising an existing logback configuration file or by injecting an environment variable before program execution.

Malicious logback configuration files can allow the attacker to execute arbitrary code using the JaninoEventEvaluator extension.

A successful attack requires the user to have write access to a configuration file. Alternatively, the attacker could inject a malicious environment variable pointing to a malicious configuration file. In both cases, the attack requires existing privilege.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-12801?s=github&n=logback-core&ns=ch.qos.logback&t=maven&vr=%3E%3D1.4.0%2C%3C1.5.13"><img alt="low 2.4: CVE--2024--12801" src="https://img.shields.io/badge/CVE--2024--12801-lightgrey?label=low%202.4&labelColor=fce1a9"/></a> <i>Server-Side Request Forgery (SSRF)</i>

<table>
<tr><td>Affected range</td><td><code>>=1.4.0<br/><1.5.13</code></td></tr>
<tr><td>Fixed version</td><td><code>1.5.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>2.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:L/VI:N/VA:L/SC:H/SI:H/SA:H/V:D/U:Clear</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Server-Side Request Forgery (SSRF) in SaxEventRecorder by QOS.CH logback version 1.5.12 on the Java platform, allows an attacker to forge requests by compromising logback configuration files in XML.
 
The attacks involves the modification of DOCTYPE declaration in  XML configuration files.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>commons-net/commons-net</strong> <code>3.6</code> (maven)</summary>

<small><code>pkg:maven/commons-net/commons-net@3.6</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-37533?s=github&n=commons-net&ns=commons-net&t=maven&vr=%3C3.9.0"><img alt="medium 6.5: CVE--2021--37533" src="https://img.shields.io/badge/CVE--2021--37533-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><3.9.0</code></td></tr>
<tr><td>Fixed version</td><td><code>3.9.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.178%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>40th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Prior to Apache Commons Net 3.9.0, Net's FTP client trusts the host from PASV response by default. A malicious server can redirect the Commons Net code to use a different host, but the user has to connect to the malicious server in the first place. This may lead to leakage of information about services running on the private network of the client.
The default in version 3.9.0 is now false to ignore such hosts, as cURL does. See https://issues.apache.org/jira/browse/NET-711.


</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.eclipse.jetty/jetty-servlets</strong> <code>9.4.52.v20230823</code> (maven)</summary>

<small><code>pkg:maven/org.eclipse.jetty/jetty-servlets@9.4.52.v20230823</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-9823?s=github&n=jetty-servlets&ns=org.eclipse.jetty&t=maven&vr=%3E%3D9.0.0%2C%3C9.4.54"><img alt="medium 5.3: CVE--2024--9823" src="https://img.shields.io/badge/CVE--2024--9823-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.4.54</code></td></tr>
<tr><td>Fixed version</td><td><code>9.4.54</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.803%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>73rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Description
There exists a security vulnerability in Jetty's DosFilter which can be exploited by unauthorized users to cause remote denial-of-service (DoS) attack on the server using DosFilter. By repeatedly sending crafted requests, attackers can trigger OutofMemory errors and exhaust the server's memory finally.


Vulnerability details
The Jetty DoSFilter (Denial of Service Filter) is a security filter designed to protect web applications against certain types of Denial of Service (DoS) attacks and other abusive behavior. It helps to mitigate excessive resource consumption by limiting the rate at which clients can make requests to the server.  The DoSFilter monitors and tracks client request patterns, including request rates, and can take actions such as blocking or delaying requests from clients that exceed predefined thresholds.  The internal tracking of requests in DoSFilter is the source of this OutOfMemory condition.


Impact
Users of the DoSFilter may be subject to DoS attacks that will ultimately exhaust the memory of the server if they have not configured session passivation or an aggressive session inactivation timeout.


Patches
The DoSFilter has been patched in all active releases to no longer support the session tracking mode, even if configured.


Patched releases:

  *  9.4.54
  *  10.0.18
  *  11.0.18
  *  12.0.3

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.38.2-3.2ubuntu0.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/perl@5.38.2-3.2ubuntu0.1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-40909?s=ubuntu&n=perl&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C5.38.2-3.2ubuntu0.2"><img alt="medium : CVE--2025--40909" src="https://img.shields.io/badge/CVE--2025--40909-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.38.2-3.2ubuntu0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>5.38.2-3.2ubuntu0.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.007%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Perl threads have a working directory race condition where file operations may target unintended paths.  If a directory handle is open at thread creation, the process-wide current working directory is temporarily changed in order to clone that handle for the new thread, which is visible from any third (or more) thread already running.  This may lead to unintended operations such as loading code or accessing files from unexpected locations, which a local attacker may be able to exploit.  The bug was introduced in commit 11a11ecf4bea72b17d250cfb43c897be1341861e and released in Perl version 5.13.6

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.commons/commons-lang3</strong> <code>3.14.0</code> (maven)</summary>

<small><code>pkg:maven/org.apache.commons/commons-lang3@3.14.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-48924?s=github&n=commons-lang3&ns=org.apache.commons&t=maven&vr=%3E%3D3.0%2C%3C3.18.0"><img alt="medium 6.5: CVE--2025--48924" src="https://img.shields.io/badge/CVE--2025--48924-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Uncontrolled Recursion</i>

<table>
<tr><td>Affected range</td><td><code>>=3.0<br/><3.18.0</code></td></tr>
<tr><td>Fixed version</td><td><code>3.18.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.309%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>54th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Uncontrolled Recursion vulnerability in Apache Commons Lang.

This issue affects Apache Commons Lang: Starting with commons-lang:commons-lang 2.0 to 2.6, and, from org.apache.commons:commons-lang3 3.0 before 3.18.0.

The methods ClassUtils.getClass(...) can throw StackOverflowError on very long inputs. Because an Error is usually not handled by applications and libraries, a StackOverflowError could cause an application to stop.

Users are recommended to upgrade to version 3.18.0, which fixes the issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.eclipse.jetty/jetty-http</strong> <code>9.4.52.v20230823</code> (maven)</summary>

<small><code>pkg:maven/org.eclipse.jetty/jetty-http@9.4.52.v20230823</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-6763?s=github&n=jetty-http&ns=org.eclipse.jetty&t=maven&vr=%3E%3D7.0.0%2C%3C%3D12.0.11"><img alt="medium 6.3: CVE--2024--6763" src="https://img.shields.io/badge/CVE--2024--6763-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>Improper Validation of Syntactic Correctness of Input</i>

<table>
<tr><td>Affected range</td><td><code>>=7.0.0<br/><=12.0.11</code></td></tr>
<tr><td>Fixed version</td><td><code>12.0.12</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.140%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## Summary

Eclipse Jetty is a lightweight, highly scalable, Java-based web server and Servlet engine . It includes a utility class, `HttpURI`, for URI/URL parsing.

The `HttpURI` class does insufficient validation on the authority segment of a URI.  However the behaviour of `HttpURI` differs from the common browsers in how it handles a URI that would be considered invalid if fully validated against the RRC.  Specifically `HttpURI` and the browser may differ on the value of the host extracted from an invalid URI and thus a combination of Jetty and a vulnerable browser may be vulnerable to a open redirect attack or to a SSRF attack if the URI is used after passing validation checks.

## Details

### Affected components

The vulnerable component is the `HttpURI` class when used as a utility class in an application.  The Jetty usage of the class is not vulnerable.

### Attack overview

The `HttpURI` class does not well validate the authority section of a URI. When presented with an illegal authority that may contain user info (eg username:password#@hostname:port), then the parsing of the URI is not failed.  Moreover, the interpretation of what part of the authority is the host name differs from a common browser in  that they also do not fail, but they select a different host name from the illegal URI.

### Attack scenario

A typical attack scenario is illustrated in the diagram below. The Validator checks whether the attacker-supplied URL is on the blocklist. If not, the URI is passed to the Requester for redirection. The Requester is responsible for sending requests to the hostname specified by the URI.

This attack occurs when the Validator is the `org.eclipse.jetty.http.HttpURI` class and the Requester is the `Browser` (include chrome, firefox and Safari). An attacker can send a malformed URI to the Validator (e.g., `http://browser.check%23%40vulndetector.com/` ). After validation, the Validator finds that the hostname is not on the blocklist. However, the Requester can still send requests to the domain with the hostname `vulndetector.com`.

## PoC

payloads:

```
http://browser.check &@vulndetector.com/
http://browser.check #@vulndetector.com/
http://browser.check?@vulndetector.com/
http://browser.check#@vulndetector.com/
http://vulndetector.com\\/
```

The problem of 302 redirect parsing in HTML tag scenarios. Below is a poc example. After clicking the button, the browser will open "browser.check", and jetty will parse this URL as "vulndetector.com".

```
<a href="http://browser.check#@vulndetector.com/"></a>
```
A comparison of the parsing differences between Jetty and chrome is shown in the table below (note that neither should accept the URI as valid).

| Invalid URI                                       | Jetty            | Chrome        |
| ---------------------------------------------- | ---------------- | ------------- |
| http://browser.check &@vulndetector.com/ | vulndetector.com | browser.check |
| http://browser.check #@vulndetector.com/ | vulndetector.com | browser.check |
| http://browser.check?@vulndetector.com/    | vulndetector.com | browser.check |
| http://browser.check#@vulndetector.com/    | vulndetector.com | browser.check |

The problem of 302 redirect parsing in HTTP 302 Location

| Input                    | Jetty          | Chrome        |
| ------------------------ | -------------- | ------------- |
| http://browser.check%5c/ | browser.check\ | browser.check |

It is noteworthy that Spring Web also faced similar security vulnerabilities, being affected by the aforementioned four types of payloads. These issues have since been resolved and have been assigned three CVE numbers [3-5].

## Impact

The impact of this vulnerability is limited to developers that use the Jetty HttpURI directly.  Example: your project implemented a blocklist to block on some hosts based on HttpURI's handling of authority section.  The vulnerability will help attackers bypass the protections that developers have set up for hosts. The vulnerability will lead to **SSRF**[1] and **URL Redirection**[2] vulnerabilities in several cases. 

## Mitigation

The attacks outlined above rely on decoded user data being passed to the `HttpURI` class. Application should not pass decoded user data as an encoded URI to any URI class/method, including `HttpURI`.  Such applications are likely to be vulnerable in other ways. 
The immediate solution is to upgrade to a version of the class that will fully validate the characters of the URI authority.  Ultimately, Jetty will deprecate and remove support for user info in the authority per [RFC9110 Section 4.2.4](https://datatracker.ietf.org/doc/html/rfc9110#section-4.2.4). 

Note that the Chrome (and other browsers) parse the invalid user info section improperly as well (due to flawed WhatWG URL parsing rules that do not apply outside of a Web Browser).

## Reference

[1] https://cwe.mitre.org/data/definitions/918.html
[2] https://cwe.mitre.org/data/definitions/601.html

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.nimbusds/nimbus-jose-jwt</strong> <code>9.41.2</code> (maven)</summary>

<small><code>pkg:maven/com.nimbusds/nimbus-jose-jwt@9.41.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-53864?s=gitlab&n=nimbus-jose-jwt&ns=com.nimbusds&t=maven&vr=%3C10.0.2"><img alt="medium 5.8: CVE--2025--53864" src="https://img.shields.io/badge/CVE--2025--53864-lightgrey?label=medium%205.8&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><10.0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>10.0.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Connect2id Nimbus JOSE + JWT before 10.0.2 allows a remote attacker to cause a denial of service via a deeply nested JSON object supplied in a JWT claim set, because of uncontrolled recursion. NOTE: this is independent of the Gson 2.11.0 issue because the Connect2id product could have checked the JSON object nesting depth, regardless of what limits (if any) were imposed by Gson.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.fasterxml.woodstox/woodstox-core</strong> <code>5.3.0</code> (maven)</summary>

<small><code>pkg:maven/com.fasterxml.woodstox/woodstox-core@5.3.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-40152?s=github&n=woodstox-core&ns=com.fasterxml.woodstox&t=maven&vr=%3C5.4.0"><img alt="medium 6.5: CVE--2022--40152" src="https://img.shields.io/badge/CVE--2022--40152-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Stack-based Buffer Overflow</i>

<table>
<tr><td>Affected range</td><td><code><5.4.0</code></td></tr>
<tr><td>Fixed version</td><td><code>5.4.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.567%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>68th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Those using FasterXML/woodstox to seralize XML data may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow. This effect may support a denial of service attack.

This vulnerability is only relevant for users making use of the DTD parsing functionality.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.45.1-1ubuntu2.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/sqlite3@3.45.1-1ubuntu2.3?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6965?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.45.1-1ubuntu2.4"><img alt="medium 9.8: CVE--2025--6965" src="https://img.shields.io/badge/CVE--2025--6965-lightgrey?label=medium%209.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.45.1-1ubuntu2.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.45.1-1ubuntu2.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.075%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

There exists a vulnerability in SQLite versions before 3.50.2 where the number of aggregate terms could exceed the number of columns available. This could lead to a memory corruption issue. We recommend upgrading to version 3.50.2 or above.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>org.apache.hadoop/hadoop-common</strong> <code>3.3.6</code> (maven)</summary>

<small><code>pkg:maven/org.apache.hadoop/hadoop-common@3.3.6</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-23454?s=github&n=hadoop-common&ns=org.apache.hadoop&t=maven&vr=%3C3.4.0"><img alt="low 2.0: CVE--2024--23454" src="https://img.shields.io/badge/CVE--2024--23454-lightgrey?label=low%202.0&labelColor=fce1a9"/></a> <i>Improper Privilege Management</i>

<table>
<tr><td>Affected range</td><td><code><3.4.0</code></td></tr>
<tr><td>Fixed version</td><td><code>3.4.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.070%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Apache Hadoop’s `RunJar.run()` does not set permissions for temporary directory by default. If sensitive data will be present in this file, all the other local users may be able to view the content. This is because, on unix-like systems, the system temporary directory is shared between all local users. As such, files written in this directory, without setting the correct posix permissions explicitly, may be viewable by all other local users.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>org.eclipse.jetty/jetty-xml</strong> <code>9.4.43.v20210629</code> (maven)</summary>

<small><code>pkg:maven/org.eclipse.jetty/jetty-xml@9.4.43.v20210629</code></small><br/>
<a href="https://scout.docker.com/v/GHSA-58qw-p7qm-5rvh?s=github&n=jetty-xml&ns=org.eclipse.jetty&t=maven&vr=%3C%3D9.4.51"><img alt="low 3.9: GHSA--58qw--p7qm--5rvh" src="https://img.shields.io/badge/GHSA--58qw--p7qm--5rvh-lightgrey?label=low%203.9&labelColor=fce1a9"/></a> <i>Improper Restriction of XML External Entity Reference</i>

<table>
<tr><td>Affected range</td><td><code><=9.4.51</code></td></tr>
<tr><td>Fixed version</td><td><code>9.4.52.v20230823</code></td></tr>
<tr><td>CVSS Score</td><td><code>3.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### From the reporter

> `XmlParser` is vulnerable to XML external entity (XXE) vulnerability.
>  XmlParser is being used when parsing Jetty’s xml configuration files. An attacker might exploit
> this vulnerability in order to achieve SSRF or cause a denial of service.
> One possible scenario is importing a (remote) malicious WAR into a Jetty’s server, while the
> WAR includes a malicious web.xml.

### Impact
There are no circumstances in a normally deployed Jetty server where potentially hostile XML is given to the XmlParser class without the attacker already having arbitrary access to the server. I.e. in order to exploit `XmlParser` the attacker would already have the ability to deploy and execute hostile code.  Specifically, Jetty has no protection against malicious web application and potentially hostile web applications should only be run on an isolated virtualisation.  

Thus this is not considered a vulnerability of the Jetty server itself, as any such usage of the jetty XmlParser is equally vulnerable as a direct usage of the JVM supplied SAX parser.  No CVE will be allocated to this advisory.

However, any direct usage of the `XmlParser` class by an application may be vulnerable.  The impact would greatly depend on how the application uses `XmlParser`, but it could be a denial of service due to large entity expansion, or possibly the revealing local files if the XML results are accessible remotely.

### Patches
Ability to configure the SAXParserFactory to fit the needs of your particular XML parser implementation have been merged as part of PR #10067

### Workarounds
Don't use `XmlParser` to parse data from users.




</blockquote>
</details>
</details></td></tr>
</table>