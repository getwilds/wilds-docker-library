# Vulnerability Report for getwilds/gatk:latest

Report generated on 2025-08-01 09:08:27 PST

<h2>:mag: Vulnerabilities of <code>getwilds/gatk:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/gatk:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:074caf850874d400514ad81aa6e629516ebe2b6b6d243f89b4d43a855001909d</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 1" src="https://img.shields.io/badge/critical-1-8b1924"/> <img alt="high: 14" src="https://img.shields.io/badge/high-14-e25d68"/> <img alt="medium: 19" src="https://img.shields.io/badge/medium-19-fbb552"/> <img alt="low: 4" src="https://img.shields.io/badge/low-4-fce1a9"/> <!-- unspecified: 0 --></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 5" src="https://img.shields.io/badge/H-5-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.google.protobuf/protobuf-java</strong> <code>3.7.1</code> (maven)</summary>

<small><code>pkg:maven/com.google.protobuf/protobuf-java@3.7.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-7254?s=github&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.25.5"><img alt="high 8.7: CVE--2024--7254" src="https://img.shields.io/badge/CVE--2024--7254-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><3.25.5</code></td></tr>
<tr><td>Fixed version</td><td><code>3.25.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.171%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
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

<a href="https://scout.docker.com/v/CVE-2021-22570?s=github&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.15.0"><img alt="high 8.7: CVE--2021--22570" src="https://img.shields.io/badge/CVE--2021--22570-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>NULL Pointer Dereference</i>

<table>
<tr><td>Affected range</td><td><code><3.15.0</code></td></tr>
<tr><td>Fixed version</td><td><code>3.15.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.121%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>32nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Nullptr dereference when a null char is present in a proto symbol. The symbol is parsed incorrectly, leading to an unchecked call into the proto file's name during generation of the resulting error message. Since the symbol is incorrectly parsed, the file is nullptr. We recommend upgrading to version 3.15.0 or greater.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3510?s=github&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.16.3"><img alt="high 7.5: CVE--2022--3510" src="https://img.shields.io/badge/CVE--2022--3510-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><3.16.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.16.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A parsing issue similar to CVE-2022-3171, but with Message-Type Extensions in protobuf-java core and lite versions prior to 3.21.7, 3.20.3, 3.19.6 and 3.16.3 can lead to a denial of service attack. Inputs containing multiple instances of non-repeated embedded messages with repeated or unknown fields causes objects to be converted back-n-forth between mutable and immutable forms, resulting in potentially long garbage collection pauses. We recommend updating to the versions mentioned above.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3509?s=github&n=protobuf-java&ns=com.google.protobuf&t=maven&vr=%3C3.16.3"><img alt="high 7.5: CVE--2022--3509" src="https://img.shields.io/badge/CVE--2022--3509-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><3.16.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.16.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.096%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.479%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>64th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.082%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was discovered in the indexOf function of JSONParserByteArray in JSON Smart versions prior to 1.3.3 and 2.4.5 which causes a denial of service (DOS) via a crafted web request.

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
<tr><td>EPSS Score</td><td><code>0.227%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>46th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the `package_index` module of pypa/setuptools versions up to 69.1.1 allows for remote code execution via its download functions. These functions, which are used to download packages from URLs provided by users or retrieved from package index servers, are susceptible to code injection. If these functions are exposed to user-controlled inputs, such as package URLs, they can execute arbitrary commands on the system. The issue is fixed in version 70.0.

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
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.213%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>44th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.commons/commons-vfs2</strong> <code>2.9.0</code> (maven)</summary>

<small><code>pkg:maven/org.apache.commons/commons-vfs2@2.9.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-27553?s=github&n=commons-vfs2&ns=org.apache.commons&t=maven&vr=%3C2.10.0"><img alt="high 7.5: CVE--2025--27553" src="https://img.shields.io/badge/CVE--2025--27553-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Relative Path Traversal</i>

<table>
<tr><td>Affected range</td><td><code><2.10.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.10.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.184%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>41st percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.142%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.212%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>44th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.zookeeper/zookeeper</strong> <code>3.9.2</code> (maven)</summary>

<small><code>pkg:maven/org.apache.zookeeper/zookeeper@3.9.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-51504?s=github&n=zookeeper&ns=org.apache.zookeeper&t=maven&vr=%3E%3D3.9.0%2C%3C3.9.3"><img alt="high 8.8: CVE--2024--51504" src="https://img.shields.io/badge/CVE--2024--51504-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Authentication Bypass by Spoofing</i>

<table>
<tr><td>Affected range</td><td><code>>=3.9.0<br/><3.9.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.9.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.308%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>54th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When using IPAuthenticationProvider in ZooKeeper Admin Server there is a possibility of Authentication Bypass by Spoofing -- this only impacts IP based authentication implemented in ZooKeeper Admin Server. Default configuration of client's IP address detection in IPAuthenticationProvider, which uses HTTP request headers, is weak and allows an attacker to bypass authentication via spoofing client's IP address in request headers. Default configuration honors X-Forwarded-For HTTP header to read client's IP address. X-Forwarded-For request header is mainly used by proxy servers to identify the client and can be easily spoofed by an attacker pretending that the request comes from a different IP address. Admin Server commands, such as snapshot and restore arbitrarily can be executed on successful exploitation which could potentially lead to information leakage or service availability issues. Users are recommended to upgrade to version 3.9.3, which fixes this issue.

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
<tr><td>EPSS Percentile</td><td><code>50th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.091%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>linux</strong> <code>6.8.0-64.67</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@6.8.0-64.67?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-38083?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-71.71"><img alt="medium : CVE--2025--38083" src="https://img.shields.io/badge/CVE--2025--38083-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-71.71</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-71.71</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.161%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Server-Side Request Forgery (SSRF) in SaxEventRecorder by QOS.CH logback version 1.5.12 on the Java platform, allows an attacker to forge requests by compromising logback configuration files in XML.
 
The attacks involves the modification of DOCTYPE declaration in  XML configuration files.

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
<tr><td>EPSS Score</td><td><code>0.684%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>71st percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.fasterxml.woodstox/woodstox-core</strong> <code>5.3.0</code> (maven)</summary>

<small><code>pkg:maven/com.fasterxml.woodstox/woodstox-core@5.3.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-40152?s=github&n=woodstox-core&ns=com.fasterxml.woodstox&t=maven&vr=%3C5.4.0"><img alt="medium 6.5: CVE--2022--40152" src="https://img.shields.io/badge/CVE--2022--40152-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Stack-based Buffer Overflow</i>

<table>
<tr><td>Affected range</td><td><code><5.4.0</code></td></tr>
<tr><td>Fixed version</td><td><code>5.4.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.552%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>67th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Those using FasterXML/woodstox to seralize XML data may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow. This effect may support a denial of service attack.

This vulnerability is only relevant for users making use of the DTD parsing functionality.

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
<tr><td>EPSS Score</td><td><code>0.162%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Prior to Apache Commons Net 3.9.0, Net's FTP client trusts the host from PASV response by default. A malicious server can redirect the Commons Net code to use a different host, but the user has to connect to the malicious server in the first place. This may lead to leakage of information about services running on the private network of the client.
The default in version 3.9.0 is now false to ignore such hosts, as cURL does. See https://issues.apache.org/jira/browse/NET-711.


</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.nimbusds/nimbus-jose-jwt</strong> <code>9.41.2</code> (maven)</summary>

<small><code>pkg:maven/com.nimbusds/nimbus-jose-jwt@9.41.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-53864?s=github&n=nimbus-jose-jwt&ns=com.nimbusds&t=maven&vr=%3C10.0.2"><img alt="medium 5.8: CVE--2025--53864" src="https://img.shields.io/badge/CVE--2025--53864-lightgrey?label=medium%205.8&labelColor=fbb552"/></a> <i>Uncontrolled Recursion</i>

<table>
<tr><td>Affected range</td><td><code><10.0.2</code></td></tr>
<tr><td>Fixed version</td><td><code>10.0.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.125%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Connect2id Nimbus JOSE + JWT before 10.0.2 allows a remote attacker to cause a denial of service via a deeply nested JSON object supplied in a JWT claim set, because of uncontrolled recursion. NOTE: this is independent of the Gson 2.11.0 issue because the Connect2id product could have checked the JSON object nesting depth, regardless of what limits (if any) were imposed by Gson.

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
<tr><td>EPSS Score</td><td><code>0.185%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>41st percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.135%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>34th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.45.1-1ubuntu2.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/sqlite3@3.45.1-1ubuntu2.3?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6965?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.45.1-1ubuntu2.4"><img alt="medium 9.8: CVE--2025--6965" src="https://img.shields.io/badge/CVE--2025--6965-lightgrey?label=medium%209.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.45.1-1ubuntu2.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.45.1-1ubuntu2.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
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