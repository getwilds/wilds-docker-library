# Vulnerability Report for getwilds/gatk:latest

Report generated on 2025-07-01 09:23:11 PST

<h2>:mag: Vulnerabilities of <code>getwilds/gatk:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/gatk:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:d711121e37093e80435adf05ed5d0ab4f2e452d96980835f4697790914825cf4</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 1" src="https://img.shields.io/badge/critical-1-8b1924"/> <img alt="high: 14" src="https://img.shields.io/badge/high-14-e25d68"/> <img alt="medium: 54" src="https://img.shields.io/badge/medium-54-fbb552"/> <img alt="low: 4" src="https://img.shields.io/badge/low-4-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>1.2 GB</td></tr>
<tr><td>packages</td><td>762</td></tr>
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
<tr><td>EPSS Score</td><td><code>0.166%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.150%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>37th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.142%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>setuptools</strong> <code>68.1.2</code> (pypi)</summary>

<small><code>pkg:pypi/setuptools@68.1.2</code></small><br/>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>net.minidev/json-smart</strong> <code>1.3.2</code> (maven)</summary>

<small><code>pkg:maven/net.minidev/json-smart@1.3.2</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-1370?s=github&n=json-smart&ns=net.minidev&t=maven&vr=%3C2.4.9"><img alt="high 7.5: CVE--2023--1370" src="https://img.shields.io/badge/CVE--2023--1370-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Recursion</i>

<table>
<tr><td>Affected range</td><td><code><2.4.9</code></td></tr>
<tr><td>Fixed version</td><td><code>2.4.9</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.commons/commons-vfs2</strong> <code>2.9.0</code> (maven)</summary>

<small><code>pkg:maven/org.apache.commons/commons-vfs2@2.9.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-27553?s=github&n=commons-vfs2&ns=org.apache.commons&t=maven&vr=%3C2.10.0"><img alt="high 7.5: CVE--2025--27553" src="https://img.shields.io/badge/CVE--2025--27553-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Relative Path Traversal</i>

<table>
<tr><td>Affected range</td><td><code><2.10.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.10.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.123%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>32nd percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.065%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.224%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>io.netty/netty-handler</strong> <code>4.1.114.Final</code> (maven)</summary>

<small><code>pkg:maven/io.netty/netty-handler@4.1.114.Final</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-24970?s=github&n=netty-handler&ns=io.netty&t=maven&vr=%3E%3D4.1.91.Final%2C%3C%3D4.1.117.Final"><img alt="high 7.5: CVE--2025--24970" src="https://img.shields.io/badge/CVE--2025--24970-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code>>=4.1.91.Final<br/><=4.1.117.Final</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.118.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.124%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.215%</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.228%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>46th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When using IPAuthenticationProvider in ZooKeeper Admin Server there is a possibility of Authentication Bypass by Spoofing -- this only impacts IP based authentication implemented in ZooKeeper Admin Server. Default configuration of client's IP address detection in IPAuthenticationProvider, which uses HTTP request headers, is weak and allows an attacker to bypass authentication via spoofing client's IP address in request headers. Default configuration honors X-Forwarded-For HTTP header to read client's IP address. X-Forwarded-For request header is mainly used by proxy servers to identify the client and can be easily spoofed by an attacker pretending that the request comes from a different IP address. Admin Server commands, such as snapshot and restore arbitrarily can be executed on successful exploitation which could potentially lead to information leakage or service availability issues. Users are recommended to upgrade to version 3.9.3, which fixes this issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 33" src="https://img.shields.io/badge/M-33-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>linux</strong> <code>6.8.0-60.63</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@6.8.0-60.63?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-21692?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 7.8: CVE--2025--21692" src="https://img.shields.io/badge/CVE--2025--21692-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: sched: fix ets qdisc OOB Indexing  Haowei Yan <g1042620637@gmail.com> found that ets_class_from_arg() can index an Out-Of-Bound class in ets_class_from_arg() when passed clid of 0. The overflow may cause local privilege escalation.  [   18.852298] ------------[ cut here ]------------ [   18.853271] UBSAN: array-index-out-of-bounds in net/sched/sch_ets.c:93:20 [   18.853743] index 18446744073709551615 is out of range for type 'ets_class [16]' [   18.854254] CPU: 0 UID: 0 PID: 1275 Comm: poc Not tainted 6.12.6-dirty #17 [   18.854821] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 [   18.856532] Call Trace: [   18.857441]  <TASK> [   18.858227]  dump_stack_lvl+0xc2/0xf0 [   18.859607]  dump_stack+0x10/0x20 [   18.860908]  __ubsan_handle_out_of_bounds+0xa7/0xf0 [   18.864022]  ets_class_change+0x3d6/0x3f0 [   18.864322]  tc_ctl_tclass+0x251/0x910 [   18.864587]  ? lock_acquire+0x5e/0x140 [   18.865113]  ? __mutex_lock+0x9c/0xe70 [   18.866009]  ? __mutex_lock+0xa34/0xe70 [   18.866401]  rtnetlink_rcv_msg+0x170/0x6f0 [   18.866806]  ? __lock_acquire+0x578/0xc10 [   18.867184]  ? __pfx_rtnetlink_rcv_msg+0x10/0x10 [   18.867503]  netlink_rcv_skb+0x59/0x110 [   18.867776]  rtnetlink_rcv+0x15/0x30 [   18.868159]  netlink_unicast+0x1c3/0x2b0 [   18.868440]  netlink_sendmsg+0x239/0x4b0 [   18.868721]  ____sys_sendmsg+0x3e2/0x410 [   18.869012]  ___sys_sendmsg+0x88/0xe0 [   18.869276]  ? rseq_ip_fixup+0x198/0x260 [   18.869563]  ? rseq_update_cpu_node_id+0x10a/0x190 [   18.869900]  ? trace_hardirqs_off+0x5a/0xd0 [   18.870196]  ? syscall_exit_to_user_mode+0xcc/0x220 [   18.870547]  ? do_syscall_64+0x93/0x150 [   18.870821]  ? __memcg_slab_free_hook+0x69/0x290 [   18.871157]  __sys_sendmsg+0x69/0xd0 [   18.871416]  __x64_sys_sendmsg+0x1d/0x30 [   18.871699]  x64_sys_call+0x9e2/0x2670 [   18.871979]  do_syscall_64+0x87/0x150 [   18.873280]  ? do_syscall_64+0x93/0x150 [   18.874742]  ? lock_release+0x7b/0x160 [   18.876157]  ? do_user_addr_fault+0x5ce/0x8f0 [   18.877833]  ? irqentry_exit_to_user_mode+0xc2/0x210 [   18.879608]  ? irqentry_exit+0x77/0xb0 [   18.879808]  ? clear_bhb_loop+0x15/0x70 [   18.880023]  ? clear_bhb_loop+0x15/0x70 [   18.880223]  ? clear_bhb_loop+0x15/0x70 [   18.880426]  entry_SYSCALL_64_after_hwframe+0x76/0x7e [   18.880683] RIP: 0033:0x44a957 [   18.880851] Code: ff ff e8 fc 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 90 f3 0f 1e fa 64 8b 04 25 18 00 00 00 85 c0 75 10 b8 2e 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 51 c3 48 83 ec 28 89 54 24 1c 48 8974 24 10 [   18.881766] RSP: 002b:00007ffcdd00fad8 EFLAGS: 00000246 ORIG_RAX: 000000000000002e [   18.882149] RAX: ffffffffffffffda RBX: 00007ffcdd010db8 RCX: 000000000044a957 [   18.882507] RDX: 0000000000000000 RSI: 00007ffcdd00fb70 RDI: 0000000000000003 [   18.885037] RBP: 00007ffcdd010bc0 R08: 000000000703c770 R09: 000000000703c7c0 [   18.887203] R10: 0000000000000080 R11: 0000000000000246 R12: 0000000000000001 [   18.888026] R13: 00007ffcdd010da8 R14: 00000000004ca7d0 R15: 0000000000000001 [   18.888395]  </TASK> [   18.888610] ---[ end trace ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21680?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 7.8: CVE--2025--21680" src="https://img.shields.io/badge/CVE--2025--21680-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pktgen: Avoid out-of-bounds access in get_imix_entries  Passing a sufficient amount of imix entries leads to invalid access to the pkt_dev->imix_entries array because of the incorrect boundary check.  UBSAN: array-index-out-of-bounds in net/core/pktgen.c:874:24 index 20 is out of range for type 'imix_pkt [20]' CPU: 2 PID: 1210 Comm: bash Not tainted 6.10.0-rc1 #121 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996) Call Trace: <TASK> dump_stack_lvl lib/dump_stack.c:117 __ubsan_handle_out_of_bounds lib/ubsan.c:429 get_imix_entries net/core/pktgen.c:874 pktgen_if_write net/core/pktgen.c:1063 pde_write fs/proc/inode.c:334 proc_reg_write fs/proc/inode.c:346 vfs_write fs/read_write.c:593 ksys_write fs/read_write.c:644 do_syscall_64 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe arch/x86/entry/entry_64.S:130  Found by Linux Verification Center (linuxtesting.org) with SVACE.  [ fp: allow to fill the array completely; minor changelog cleanup ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57951?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 7.8: CVE--2024--57951" src="https://img.shields.io/badge/CVE--2024--57951-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  hrtimers: Handle CPU state correctly on hotplug  Consider a scenario where a CPU transitions from CPUHP_ONLINE to halfway through a CPU hotunplug down to CPUHP_HRTIMERS_PREPARE, and then back to CPUHP_ONLINE:  Since hrtimers_prepare_cpu() does not run, cpu_base.hres_active remains set to 1 throughout. However, during a CPU unplug operation, the tick and the clockevents are shut down at CPUHP_AP_TICK_DYING. On return to the online state, for instance CFS incorrectly assumes that the hrtick is already active, and the chance of the clockevent device to transition to oneshot mode is also lost forever for the CPU, unless it goes back to a lower state than CPUHP_HRTIMERS_PREPARE once.  This round-trip reveals another issue; cpu_base.online is not set to 1 after the transition, which appears as a WARN_ON_ONCE in enqueue_hrtimer().  Aside of that, the bulk of the per CPU state is not reset either, which means there are dangling pointers in the worst case.  Address this by adding a corresponding startup() callback, which resets the stale per CPU state and sets the online flag.  [ tglx: Make the new callback unconditionally available, remove the online modification in the prepare() callback and clear the remaining state in the starting callback instead of the prepare callback ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21699?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21699" src="https://img.shields.io/badge/CVE--2025--21699-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gfs2: Truncate address space when flipping GFS2_DIF_JDATA flag  Truncate an inode's address space when flipping the GFS2_DIF_JDATA flag: depending on that flag, the pages in the address space will either use buffer heads or iomap_folio_state structs, and we cannot mix the two.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21697?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21697" src="https://img.shields.io/badge/CVE--2025--21697-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/v3d: Ensure job pointer is set to NULL after job completion  After a job completes, the corresponding pointer in the device must be set to NULL. Failing to do so triggers a warning when unloading the driver, as it appears the job is still active. To prevent this, assign the job pointer to NULL after completing the job, indicating the job has finished.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21694?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21694" src="https://img.shields.io/badge/CVE--2025--21694-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs/proc: fix softlockup in __read_vmcore (part 2)  Since commit 5cbcb62dddf5 ("fs/proc: fix softlockup in __read_vmcore") the number of softlockups in __read_vmcore at kdump time have gone down, but they still happen sometimes.  In a memory constrained environment like the kdump image, a softlockup is not just a harmless message, but it can interfere with things like RCU freeing memory, causing the crashdump to get stuck.  The second loop in __read_vmcore has a lot more opportunities for natural sleep points, like scheduling out while waiting for a data write to happen, but apparently that is not always enough.  Add a cond_resched() to the second loop in __read_vmcore to (hopefully) get rid of the softlockups.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21690?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21690" src="https://img.shields.io/badge/CVE--2025--21690-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: storvsc: Ratelimit warning logs to prevent VM denial of service  If there's a persistent error in the hypervisor, the SCSI warning for failed I/O can flood the kernel log and max out CPU utilization, preventing troubleshooting from the VM side. Ratelimit the warning so it doesn't DoS the VM.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21689?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21689" src="https://img.shields.io/badge/CVE--2025--21689-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  USB: serial: quatech2: fix null-ptr-deref in qt2_process_read_urb()  This patch addresses a null-ptr-deref in qt2_process_read_urb() due to an incorrect bounds check in the following:  if (newport > serial->num_ports) { dev_err(&port->dev, "%s - port change to invalid port: %i\n", __func__, newport); break; }  The condition doesn't account for the valid range of the serial->port buffer, which is from 0 to serial->num_ports - 1. When newport is equal to serial->num_ports, the assignment of "port" in the following code is out-of-bounds and NULL:  serial_priv->current_port = newport; port = serial->port[serial_priv->current_port];  The fix checks if newport is greater than or equal to serial->num_ports indicating it is out-of-bounds.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21684?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21684" src="https://img.shields.io/badge/CVE--2025--21684-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.009%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gpio: xilinx: Convert gpio_lock to raw spinlock  irq_chip functions may be called in raw spinlock context. Therefore, we must also use a raw spinlock for our own internal locking.  This fixes the following lockdep splat:  [    5.349336] ============================= [    5.353349] [ BUG: Invalid wait context ] [    5.357361] 6.13.0-rc5+ #69 Tainted: G        W [    5.363031] ----------------------------- [    5.367045] kworker/u17:1/44 is trying to lock: [    5.371587] ffffff88018b02c0 (&chip->gpio_lock){....}-{3:3}, at: xgpio_irq_unmask (drivers/gpio/gpio-xilinx.c:433 (discriminator 8)) [    5.380079] other info that might help us debug this: [    5.385138] context-{5:5} [    5.387762] 5 locks held by kworker/u17:1/44: [    5.392123] #0: ffffff8800014958 ((wq_completion)events_unbound){+.+.}-{0:0}, at: process_one_work (kernel/workqueue.c:3204) [    5.402260] #1: ffffffc082fcbdd8 (deferred_probe_work){+.+.}-{0:0}, at: process_one_work (kernel/workqueue.c:3205) [    5.411528] #2: ffffff880172c900 (&dev->mutex){....}-{4:4}, at: __device_attach (drivers/base/dd.c:1006) [    5.419929] #3: ffffff88039c8268 (request_class#2){+.+.}-{4:4}, at: __setup_irq (kernel/irq/internals.h:156 kernel/irq/manage.c:1596) [    5.428331] #4: ffffff88039c80c8 (lock_class#2){....}-{2:2}, at: __setup_irq (kernel/irq/manage.c:1614) [    5.436472] stack backtrace: [    5.439359] CPU: 2 UID: 0 PID: 44 Comm: kworker/u17:1 Tainted: G W          6.13.0-rc5+ #69 [    5.448690] Tainted: [W]=WARN [    5.451656] Hardware name: xlnx,zynqmp (DT) [    5.455845] Workqueue: events_unbound deferred_probe_work_func [    5.461699] Call trace: [    5.464147] show_stack+0x18/0x24 C [    5.467821] dump_stack_lvl (lib/dump_stack.c:123) [    5.471501] dump_stack (lib/dump_stack.c:130) [    5.474824] __lock_acquire (kernel/locking/lockdep.c:4828 kernel/locking/lockdep.c:4898 kernel/locking/lockdep.c:5176) [    5.478758] lock_acquire (arch/arm64/include/asm/percpu.h:40 kernel/locking/lockdep.c:467 kernel/locking/lockdep.c:5851 kernel/locking/lockdep.c:5814) [    5.482429] _raw_spin_lock_irqsave (include/linux/spinlock_api_smp.h:111 kernel/locking/spinlock.c:162) [    5.486797] xgpio_irq_unmask (drivers/gpio/gpio-xilinx.c:433 (discriminator 8)) [    5.490737] irq_enable (kernel/irq/internals.h:236 kernel/irq/chip.c:170 kernel/irq/chip.c:439 kernel/irq/chip.c:432 kernel/irq/chip.c:345) [    5.494060] __irq_startup (kernel/irq/internals.h:241 kernel/irq/chip.c:180 kernel/irq/chip.c:250) [    5.497645] irq_startup (kernel/irq/chip.c:270) [    5.501143] __setup_irq (kernel/irq/manage.c:1807) [    5.504728] request_threaded_irq (kernel/irq/manage.c:2208)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21683?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21683" src="https://img.shields.io/badge/CVE--2025--21683-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Fix bpf_sk_select_reuseport() memory leak  As pointed out in the original comment, lookup in sockmap can return a TCP ESTABLISHED socket. Such TCP socket may have had SO_ATTACH_REUSEPORT_EBPF set before it was ESTABLISHED. In other words, a non-NULL sk_reuseport_cb does not imply a non-refcounted socket.  Drop sk's reference in both error paths.  unreferenced object 0xffff888101911800 (size 2048): comm "test_progs", pid 44109, jiffies 4297131437 hex dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ 80 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ backtrace (crc 9336483b): __kmalloc_noprof+0x3bf/0x560 __reuseport_alloc+0x1d/0x40 reuseport_alloc+0xca/0x150 reuseport_attach_prog+0x87/0x140 sk_reuseport_attach_bpf+0xc8/0x100 sk_setsockopt+0x1181/0x1990 do_sock_setsockopt+0x12b/0x160 __sys_setsockopt+0x7b/0xc0 __x64_sys_setsockopt+0x1b/0x30 do_syscall_64+0x93/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21682?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21682" src="https://img.shields.io/badge/CVE--2025--21682-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  eth: bnxt: always recalculate features after XDP clearing, fix null-deref  Recalculate features when XDP is detached.  Before: # ip li set dev eth0 xdp obj xdp_dummy.bpf.o sec xdp # ip li set dev eth0 xdp off # ethtool -k eth0 | grep gro rx-gro-hw: off [requested on]  After: # ip li set dev eth0 xdp obj xdp_dummy.bpf.o sec xdp # ip li set dev eth0 xdp off # ethtool -k eth0 | grep gro rx-gro-hw: on  The fact that HW-GRO doesn't get re-enabled automatically is just a minor annoyance. The real issue is that the features will randomly come back during another reconfiguration which just happens to invoke netdev_update_features(). The driver doesn't handle reconfiguring two things at a time very robustly.  Starting with commit 98ba1d931f61 ("bnxt_en: Fix RSS logic in __bnxt_reserve_rings()") we only reconfigure the RSS hash table if the "effective" number of Rx rings has changed. If HW-GRO is enabled "effective" number of rings is 2x what user sees. So if we are in the bad state, with HW-GRO re-enablement "pending" after XDP off, and we lower the rings by / 2 - the HW-GRO rings doing 2x and the ethtool -L doing / 2 may cancel each other out, and the:  if (old_rx_rings != bp->hw_resc.resv_rx_rings &&  condition in __bnxt_reserve_rings() will be false. The RSS map won't get updated, and we'll crash with:  BUG: kernel NULL pointer dereference, address: 0000000000000168 RIP: 0010:__bnxt_hwrm_vnic_set_rss+0x13a/0x1a0 bnxt_hwrm_vnic_rss_cfg_p5+0x47/0x180 __bnxt_setup_vnic_p5+0x58/0x110 bnxt_init_nic+0xb72/0xf50 __bnxt_open_nic+0x40d/0xab0 bnxt_open_nic+0x2b/0x60 ethtool_set_channels+0x18c/0x1d0  As we try to access a freed ring.  The issue is present since XDP support was added, really, but prior to commit 98ba1d931f61 ("bnxt_en: Fix RSS logic in __bnxt_reserve_rings()") it wasn't causing major issues.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21681?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21681" src="https://img.shields.io/badge/CVE--2025--21681-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  openvswitch: fix lockup on tx to unregistering netdev with carrier  Commit in a fixes tag attempted to fix the issue in the following sequence of calls:  do_output -> ovs_vport_send -> dev_queue_xmit -> __dev_queue_xmit -> netdev_core_pick_tx -> skb_tx_hash  When device is unregistering, the 'dev->real_num_tx_queues' goes to zero and the 'while (unlikely(hash >= qcount))' loop inside the 'skb_tx_hash' becomes infinite, locking up the core forever.  But unfortunately, checking just the carrier status is not enough to fix the issue, because some devices may still be in unregistering state while reporting carrier status OK.  One example of such device is a net/dummy.  It sets carrier ON on start, but it doesn't implement .ndo_stop to set the carrier off. And it makes sense, because dummy doesn't really have a carrier. Therefore, while this device is unregistering, it's still easy to hit the infinite loop in the skb_tx_hash() from the OVS datapath.  There might be other drivers that do the same, but dummy by itself is important for the OVS ecosystem, because it is frequently used as a packet sink for tcpdump while debugging OVS deployments.  And when the issue is hit, the only way to recover is to reboot.  Fix that by also checking if the device is running.  The running state is handled by the net core during unregistering, so it covers unregistering case better, and we don't really need to send packets to devices that are not running anyway.  While only checking the running state might be enough, the carrier check is preserved.  The running and the carrier states seem disjoined throughout the code and different drivers.  And other core functions like __dev_direct_xmit() check both before attempting to transmit a packet.  So, it seems safer to check both flags in OVS as well.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21676?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21676" src="https://img.shields.io/badge/CVE--2025--21676-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fec: handle page_pool_dev_alloc_pages error  The fec_enet_update_cbd function calls page_pool_dev_alloc_pages but did not handle the case when it returned NULL. There was a WARN_ON(!new_page) but it would still proceed to use the NULL pointer and then crash.  This case does seem somewhat rare but when the system is under memory pressure it can happen. One case where I can duplicate this with some frequency is when writing over a smbd share to a SATA HDD attached to an imx6q.  Setting /proc/sys/vm/min_free_kbytes to higher values also seems to solve the problem for my test case. But it still seems wrong that the fec driver ignores the memory allocation error and can crash.  This commit handles the allocation error by dropping the current packet.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21675?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21675" src="https://img.shields.io/badge/CVE--2025--21675-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: Clear port select structure when fail to create  Clear the port select structure on error so no stale values left after definers are destroyed. That's because the mlx5_lag_destroy_definers() always try to destroy all lag definers in the tt_map, so in the flow below lag definers get double-destroyed and cause kernel crash:  mlx5_lag_port_sel_create() mlx5_lag_create_definers() mlx5_lag_create_definer()     <- Failed on tt 1 mlx5_lag_destroy_definers() <- definers[tt=0] gets destroyed mlx5_lag_port_sel_create() mlx5_lag_create_definers() mlx5_lag_create_definer()     <- Failed on tt 0 mlx5_lag_destroy_definers() <- definers[tt=0] gets double-destroyed  Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008 Mem abort info: ESR = 0x0000000096000005 EC = 0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x05: level 1 translation fault Data abort info: ISV = 0, ISS = 0x00000005, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess = 0 GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 user pgtable: 64k pages, 48-bit VAs, pgdp=0000000112ce2e00 [0000000000000008] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000 Internal error: Oops: 0000000096000005 [#1] PREEMPT SMP Modules linked in: iptable_raw bonding ip_gre ip6_gre gre ip6_tunnel tunnel6 geneve ip6_udp_tunnel udp_tunnel ipip tunnel4 ip_tunnel rdma_ucm(OE) rdma_cm(OE) iw_cm(OE) ib_ipoib(OE) ib_cm(OE) ib_umad(OE) mlx5_ib(OE) ib_uverbs(OE) mlx5_fwctl(OE) fwctl(OE) mlx5_core(OE) mlxdevm(OE) ib_core(OE) mlxfw(OE) memtrack(OE) mlx_compat(OE) openvswitch nsh nf_conncount psample xt_conntrack xt_MASQUERADE nf_conntrack_netlink nfnetlink xfrm_user xfrm_algo xt_addrtype iptable_filter iptable_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 br_netfilter bridge stp llc netconsole overlay efi_pstore sch_fq_codel zram ip_tables crct10dif_ce qemu_fw_cfg fuse ipv6 crc_ccitt [last unloaded: mlx_compat(OE)] CPU: 3 UID: 0 PID: 217 Comm: kworker/u53:2 Tainted: G           OE 6.11.0+ #2 Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE Hardware name: QEMU KVM Virtual Machine, BIOS 0.0.0 02/06/2015 Workqueue: mlx5_lag mlx5_do_bond_work [mlx5_core] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : mlx5_del_flow_rules+0x24/0x2c0 [mlx5_core] lr : mlx5_lag_destroy_definer+0x54/0x100 [mlx5_core] sp : ffff800085fafb00 x29: ffff800085fafb00 x28: ffff0000da0c8000 x27: 0000000000000000 x26: ffff0000da0c8000 x25: ffff0000da0c8000 x24: ffff0000da0c8000 x23: ffff0000c31f81a0 x22: 0400000000000000 x21: ffff0000da0c8000 x20: 0000000000000000 x19: 0000000000000001 x18: 0000000000000000 x17: 0000000000000000 x16: 0000000000000000 x15: 0000ffff8b0c9350 x14: 0000000000000000 x13: ffff800081390d18 x12: ffff800081dc3cc0 x11: 0000000000000001 x10: 0000000000000b10 x9 : ffff80007ab7304c x8 : ffff0000d00711f0 x7 : 0000000000000004 x6 : 0000000000000190 x5 : ffff00027edb3010 x4 : 0000000000000000 x3 : 0000000000000000 x2 : ffff0000d39b8000 x1 : ffff0000d39b8000 x0 : 0400000000000000 Call trace: mlx5_del_flow_rules+0x24/0x2c0 [mlx5_core] mlx5_lag_destroy_definer+0x54/0x100 [mlx5_core] mlx5_lag_destroy_definers+0xa0/0x108 [mlx5_core] mlx5_lag_port_sel_create+0x2d4/0x6f8 [mlx5_core] mlx5_activate_lag+0x60c/0x6f8 [mlx5_core] mlx5_do_bond_work+0x284/0x5c8 [mlx5_core] process_one_work+0x170/0x3e0 worker_thread+0x2d8/0x3e0 kthread+0x11c/0x128 ret_from_fork+0x10/0x20 Code: a9025bf5 aa0003f6 a90363f7 f90023f9 (f9400400) ---[ end trace 0000000000000000 ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21674?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21674" src="https://img.shields.io/badge/CVE--2025--21674-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5e: Fix inversion dependency warning while enabling IPsec tunnel  Attempt to enable IPsec packet offload in tunnel mode in debug kernel generates the following kernel panic, which is happening due to two issues: 1. In SA add section, the should be _bh() variant when marking SA mode. 2. There is not needed flush_workqueue in SA delete routine. It is not needed as at this stage as it is removed from SADB and the running work will be canceled later in SA free.  ===================================================== WARNING: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected 6.12.0+ #4 Not tainted ----------------------------------------------------- charon/1337 [HC0[0]:SC0[4]:HE1:SE0] is trying to acquire: ffff88810f365020 (&xa->xa_lock#24){+.+.}-{3:3}, at: mlx5e_xfrm_del_state+0xca/0x1e0 [mlx5_core]  and this task is already holding: ffff88813e0f0d48 (&x->lock){+.-.}-{3:3}, at: xfrm_state_delete+0x16/0x30 which would create a new lock dependency: (&x->lock){+.-.}-{3:3} -> (&xa->xa_lock#24){+.+.}-{3:3}  but this new dependency connects a SOFTIRQ-irq-safe lock: (&x->lock){+.-.}-{3:3}  ... which became SOFTIRQ-irq-safe at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_timer_handler+0x91/0xd70 __hrtimer_run_queues+0x1dd/0xa60 hrtimer_run_softirq+0x146/0x2e0 handle_softirqs+0x266/0x860 irq_exit_rcu+0x115/0x1a0 sysvec_apic_timer_interrupt+0x6e/0x90 asm_sysvec_apic_timer_interrupt+0x16/0x20 default_idle+0x13/0x20 default_idle_call+0x67/0xa0 do_idle+0x2da/0x320 cpu_startup_entry+0x50/0x60 start_secondary+0x213/0x2a0 common_startup_64+0x129/0x138  to a SOFTIRQ-irq-unsafe lock: (&xa->xa_lock#24){+.+.}-{3:3}  ... which became SOFTIRQ-irq-unsafe at: ... lock_acquire+0x1be/0x520 _raw_spin_lock+0x2c/0x40 xa_set_mark+0x70/0x110 mlx5e_xfrm_add_state+0xe48/0x2290 [mlx5_core] xfrm_dev_state_add+0x3bb/0xd70 xfrm_add_sa+0x2451/0x4a90 xfrm_user_rcv_msg+0x493/0x880 netlink_rcv_skb+0x12e/0x380 xfrm_netlink_rcv+0x6d/0x90 netlink_unicast+0x42f/0x740 netlink_sendmsg+0x745/0xbe0 __sock_sendmsg+0xc5/0x190 __sys_sendto+0x1fe/0x2c0 __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x6d/0x140 entry_SYSCALL_64_after_hwframe+0x4b/0x53  other info that might help us debug this:  Possible interrupt unsafe locking scenario:  CPU0                    CPU1 ----                    ---- lock(&xa->xa_lock#24); local_irq_disable(); lock(&x->lock); lock(&xa->xa_lock#24); <Interrupt> lock(&x->lock);  *** DEADLOCK ***  2 locks held by charon/1337: #0: ffffffff87f8f858 (&net->xfrm.xfrm_cfg_mutex){+.+.}-{4:4}, at: xfrm_netlink_rcv+0x5e/0x90 #1: ffff88813e0f0d48 (&x->lock){+.-.}-{3:3}, at: xfrm_state_delete+0x16/0x30  the dependencies between SOFTIRQ-irq-safe lock and the holding lock: -> (&x->lock){+.-.}-{3:3} ops: 29 { HARDIRQ-ON-W at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_alloc_spi+0xc0/0xe60 xfrm_alloc_userspi+0x5f6/0xbc0 xfrm_user_rcv_msg+0x493/0x880 netlink_rcv_skb+0x12e/0x380 xfrm_netlink_rcv+0x6d/0x90 netlink_unicast+0x42f/0x740 netlink_sendmsg+0x745/0xbe0 __sock_sendmsg+0xc5/0x190 __sys_sendto+0x1fe/0x2c0 __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x6d/0x140 entry_SYSCALL_64_after_hwframe+0x4b/0x53 IN-SOFTIRQ-W at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_timer_handler+0x91/0xd70 __hrtimer_run_queues+0x1dd/0xa60  ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21673?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21673" src="https://img.shields.io/badge/CVE--2025--21673-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix double free of TCP_Server_Info::hostname  When shutting down the server in cifs_put_tcp_session(), cifsd thread might be reconnecting to multiple DFS targets before it realizes it should exit the loop, so @server->hostname can't be freed as long as cifsd thread isn't done.  Otherwise the following can happen:  RIP: 0010:__slab_free+0x223/0x3c0 Code: 5e 41 5f c3 cc cc cc cc 4c 89 de 4c 89 cf 44 89 44 24 08 4c 89 1c 24 e8 fb cf 8e 00 44 8b 44 24 08 4c 8b 1c 24 e9 5f fe ff ff <0f> 0b 41 f7 45 08 00 0d 21 00 0f 85 2d ff ff ff e9 1f ff ff ff 80 RSP: 0018:ffffb26180dbfd08 EFLAGS: 00010246 RAX: ffff8ea34728e510 RBX: ffff8ea34728e500 RCX: 0000000000800068 RDX: 0000000000800068 RSI: 0000000000000000 RDI: ffff8ea340042400 RBP: ffffe112041ca380 R08: 0000000000000001 R09: 0000000000000000 R10: 6170732e31303000 R11: 70726f632e786563 R12: ffff8ea34728e500 R13: ffff8ea340042400 R14: ffff8ea34728e500 R15: 0000000000800068 FS: 0000000000000000(0000) GS:ffff8ea66fd80000(0000) 000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffc25376080 CR3: 000000012a2ba001 CR4: PKRU: 55555554 Call Trace: <TASK> ? show_trace_log_lvl+0x1c4/0x2df ? show_trace_log_lvl+0x1c4/0x2df ? __reconnect_target_unlocked+0x3e/0x160 [cifs] ? __die_body.cold+0x8/0xd ? die+0x2b/0x50 ? do_trap+0xce/0x120 ? __slab_free+0x223/0x3c0 ? do_error_trap+0x65/0x80 ? __slab_free+0x223/0x3c0 ? exc_invalid_op+0x4e/0x70 ? __slab_free+0x223/0x3c0 ? asm_exc_invalid_op+0x16/0x20 ? __slab_free+0x223/0x3c0 ? extract_hostname+0x5c/0xa0 [cifs] ? extract_hostname+0x5c/0xa0 [cifs] ? __kmalloc+0x4b/0x140 __reconnect_target_unlocked+0x3e/0x160 [cifs] reconnect_dfs_server+0x145/0x430 [cifs] cifs_handle_standard+0x1ad/0x1d0 [cifs] cifs_demultiplex_thread+0x592/0x730 [cifs] ? __pfx_cifs_demultiplex_thread+0x10/0x10 [cifs] kthread+0xdd/0x100 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x29/0x50 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21672?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21672" src="https://img.shields.io/badge/CVE--2025--21672-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  afs: Fix merge preference rule failure condition  syzbot reported a lock held when returning to userspace[1].  This is because if argc is less than 0 and the function returns directly, the held inode lock is not released.  Fix this by store the error in ret and jump to done to clean up instead of returning directly.  [dh: Modified Lizhi Xu's original patch to make it honour the error code from afs_split_string()]  [1] WARNING: lock held when returning to user space! 6.13.0-rc3-syzkaller-00209-g499551201b5f #0 Not tainted ------------------------------------------------ syz-executor133/5823 is leaving the kernel with locks still held! 1 lock held by syz-executor133/5823: #0: ffff888071cffc00 (&sb->s_type->i_mutex_key#9){++++}-{4:4}, at: inode_lock include/linux/fs.h:818 [inline] #0: ffff888071cffc00 (&sb->s_type->i_mutex_key#9){++++}-{4:4}, at: afs_proc_addr_prefs_write+0x2bb/0x14e0 fs/afs/addr_prefs.c:388

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21670?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21670" src="https://img.shields.io/badge/CVE--2025--21670-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock/bpf: return early if transport is not assigned  Some of the core functions can only be called if the transport has been assigned.  As Michal reported, a socket might have the transport at NULL, for example after a failed connect(), causing the following trace:  BUG: kernel NULL pointer dereference, address: 00000000000000a0 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD 12faf8067 P4D 12faf8067 PUD 113670067 PMD 0 Oops: Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 15 UID: 0 PID: 1198 Comm: a.out Not tainted 6.13.0-rc2+ RIP: 0010:vsock_connectible_has_data+0x1f/0x40 Call Trace: vsock_bpf_recvmsg+0xca/0x5e0 sock_recvmsg+0xb9/0xc0 __sys_recvfrom+0xb3/0x130 __x64_sys_recvfrom+0x20/0x30 do_syscall_64+0x93/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e  So we need to check the `vsk->transport` in vsock_bpf_recvmsg(), especially for connected sockets (stream/seqpacket) as we already do in __vsock_connectible_recvmsg().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21669?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21669" src="https://img.shields.io/badge/CVE--2025--21669-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock/virtio: discard packets if the transport changes  If the socket has been de-assigned or assigned to another transport, we must discard any packets received because they are not expected and would cause issues when we access vsk->transport.  A possible scenario is described by Hyunwoo Kim in the attached link, where after a first connect() interrupted by a signal, and a second connect() failed, we can find `vsk->transport` at NULL, leading to a NULL pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21667?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21667" src="https://img.shields.io/badge/CVE--2025--21667-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iomap: avoid avoid truncating 64-bit offset to 32 bits  on 32-bit kernels, iomap_write_delalloc_scan() was inadvertently using a 32-bit position due to folio_next_index() returning an unsigned long. This could lead to an infinite loop when writing to an xfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21666?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21666" src="https://img.shields.io/badge/CVE--2025--21666-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock: prevent null-ptr-deref in vsock_*[has_data|has_space]  Recent reports have shown how we sometimes call vsock_*_has_data() when a vsock socket has been de-assigned from a transport (see attached links), but we shouldn't.  Previous commits should have solved the real problems, but we may have more in the future, so to avoid null-ptr-deref, we can return 0 (no space, no data available) but with a warning.  This way the code should continue to run in a nearly consistent state and have a warning that allows us to debug future problems.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21665?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21665" src="https://img.shields.io/badge/CVE--2025--21665-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  filemap: avoid truncating 64-bit offset to 32 bits  On 32-bit kernels, folio_seek_hole_data() was inadvertently truncating a 64-bit value to 32 bits, leading to a possible infinite loop when writing to an xfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57952?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2024--57952" src="https://img.shields.io/badge/CVE--2024--57952-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Revert "libfs: fix infinite directory reads for offset dir"  The current directory offset allocator (based on mtree_alloc_cyclic) stores the next offset value to return in octx->next_offset. This mechanism typically returns values that increase monotonically over time. Eventually, though, the newly allocated offset value wraps back to a low number (say, 2) which is smaller than other already- allocated offset values.  Yu Kuai <yukuai3@huawei.com> reports that, after commit 64a7ce76fb90 ("libfs: fix infinite directory reads for offset dir"), if a directory's offset allocator wraps, existing entries are no longer visible via readdir/getdents because offset_readdir() stops listing entries once an entry's offset is larger than octx->next_offset. These entries vanish persistently -- they can be looked up, but will never again appear in readdir(3) output.  The reason for this is that the commit treats directory offsets as monotonically increasing integer values rather than opaque cookies, and introduces this comparison:  if (dentry2offset(dentry) >= last_index) {  On 64-bit platforms, the directory offset value upper bound is 2^63 - 1. Directory offsets will monotonically increase for millions of years without wrapping.  On 32-bit platforms, however, LONG_MAX is 2^31 - 1. The allocator can wrap after only a few weeks (at worst).  Revert commit 64a7ce76fb90 ("libfs: fix infinite directory reads for offset dir") to prepare for a fix that can work properly on 32-bit systems and might apply to recent LTS kernels where shmem employs the simple_offset mechanism.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57949?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2024--57949" src="https://img.shields.io/badge/CVE--2024--57949-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.007%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  irqchip/gic-v3-its: Don't enable interrupts in its_irq_set_vcpu_affinity()  The following call-chain leads to enabling interrupts in a nested interrupt disabled section:  irq_set_vcpu_affinity() irq_get_desc_lock() raw_spin_lock_irqsave()   <--- Disable interrupts its_irq_set_vcpu_affinity() guard(raw_spinlock_irq)   <--- Enables interrupts when leaving the guard() irq_put_desc_unlock()        <--- Warns because interrupts are enabled  This was broken in commit b97e8a2f7130, which replaced the original raw_spin_[un]lock() pair with guard(raw_spinlock_irq).  Fix the issue by using guard(raw_spinlock).  [ tglx: Massaged change log ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50157?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2024--50157" src="https://img.shields.io/badge/CVE--2024--50157-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/bnxt_re: Avoid CPU lockups due fifo occupancy check loop  Driver waits indefinitely for the fifo occupancy to go below a threshold as soon as the pacing interrupt is received. This can cause soft lockup on one of the processors, if the rate of DB is very high.  Add a loop count for FPGA and exit the __wait_for_fifo_occupancy_below_th if the loop is taking more time. Pacing will be continuing until the occupancy is below the threshold. This is ensured by the checks in bnxt_re_pacing_timer_exp and further scheduling the work for pacing based on the fifo occupancy.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21943?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 4.7: CVE--2025--21943" src="https://img.shields.io/badge/CVE--2025--21943-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gpio: aggregator: protect driver attr handlers against module unload  Both new_device_store and delete_device_store touch module global resources (e.g. gpio_aggregator_lock). To prevent race conditions with module unload, a reference needs to be held.  Add try_module_get() in these handlers.  For new_device_store, this eliminates what appears to be the most dangerous scenario: if an id is allocated from gpio_aggregator_idr but platform_device_register has not yet been called or completed, a concurrent module unload could fail to unregister/delete the device, leaving behind a dangling platform device/GPIO forwarder. This can result in various issues. The following simple reproducer demonstrates these problems:  #!/bin/bash while :; do # note: whether 'gpiochip0 0' exists or not does not matter. echo 'gpiochip0 0' > /sys/bus/platform/drivers/gpio-aggregator/new_device done & while :; do modprobe gpio-aggregator modprobe -r gpio-aggregator done & wait  Starting with the following warning, several kinds of warnings will appear and the system may become unstable:  ------------[ cut here ]------------ list_del corruption, ffff888103e2e980->next is LIST_POISON1 (dead000000000100) WARNING: CPU: 1 PID: 1327 at lib/list_debug.c:56 __list_del_entry_valid_or_report+0xa3/0x120 [...] RIP: 0010:__list_del_entry_valid_or_report+0xa3/0x120 [...] Call Trace: <TASK> ? __list_del_entry_valid_or_report+0xa3/0x120 ? __warn.cold+0x93/0xf2 ? __list_del_entry_valid_or_report+0xa3/0x120 ? report_bug+0xe6/0x170 ? __irq_work_queue_local+0x39/0xe0 ? handle_bug+0x58/0x90 ? exc_invalid_op+0x13/0x60 ? asm_exc_invalid_op+0x16/0x20 ? __list_del_entry_valid_or_report+0xa3/0x120 gpiod_remove_lookup_table+0x22/0x60 new_device_store+0x315/0x350 [gpio_aggregator] kernfs_fop_write_iter+0x137/0x1f0 vfs_write+0x262/0x430 ksys_write+0x60/0xd0 do_syscall_64+0x6c/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e [...] </TASK> ---[ end trace 0000000000000000 ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53124?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 4.7: CVE--2024--53124" src="https://img.shields.io/badge/CVE--2024--53124-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fix data-races around sk->sk_forward_alloc  Syzkaller reported this warning: ------------[ cut here ]------------ WARNING: CPU: 0 PID: 16 at net/ipv4/af_inet.c:156 inet_sock_destruct+0x1c5/0x1e0 Modules linked in: CPU: 0 UID: 0 PID: 16 Comm: ksoftirqd/0 Not tainted 6.12.0-rc5 #26 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 RIP: 0010:inet_sock_destruct+0x1c5/0x1e0 Code: 24 12 4c 89 e2 5b 48 c7 c7 98 ec bb 82 41 5c e9 d1 18 17 ff 4c 89 e6 5b 48 c7 c7 d0 ec bb 82 41 5c e9 bf 18 17 ff 0f 0b eb 83 <0f> 0b eb 97 0f 0b eb 87 0f 0b e9 68 ff ff ff 66 66 2e 0f 1f 84 00 RSP: 0018:ffffc9000008bd90 EFLAGS: 00010206 RAX: 0000000000000300 RBX: ffff88810b172a90 RCX: 0000000000000007 RDX: 0000000000000002 RSI: 0000000000000300 RDI: ffff88810b172a00 RBP: ffff88810b172a00 R08: ffff888104273c00 R09: 0000000000100007 R10: 0000000000020000 R11: 0000000000000006 R12: ffff88810b172a00 R13: 0000000000000004 R14: 0000000000000000 R15: ffff888237c31f78 FS:  0000000000000000(0000) GS:ffff888237c00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffc63fecac8 CR3: 000000000342e000 CR4: 00000000000006f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> ? __warn+0x88/0x130 ? inet_sock_destruct+0x1c5/0x1e0 ? report_bug+0x18e/0x1a0 ? handle_bug+0x53/0x90 ? exc_invalid_op+0x18/0x70 ? asm_exc_invalid_op+0x1a/0x20 ? inet_sock_destruct+0x1c5/0x1e0 __sk_destruct+0x2a/0x200 rcu_do_batch+0x1aa/0x530 ? rcu_do_batch+0x13b/0x530 rcu_core+0x159/0x2f0 handle_softirqs+0xd3/0x2b0 ? __pfx_smpboot_thread_fn+0x10/0x10 run_ksoftirqd+0x25/0x30 smpboot_thread_fn+0xdd/0x1d0 kthread+0xd3/0x100 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x34/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1a/0x30 </TASK> ---[ end trace 0000000000000000 ]---  Its possible that two threads call tcp_v6_do_rcv()/sk_forward_alloc_add() concurrently when sk->sk_state == TCP_LISTEN with sk->sk_lock unlocked, which triggers a data-race around sk->sk_forward_alloc: tcp_v6_rcv tcp_v6_do_rcv skb_clone_and_charge_r sk_rmem_schedule __sk_mem_schedule sk_forward_alloc_add() skb_set_owner_r sk_mem_charge sk_forward_alloc_add() __kfree_skb skb_release_all skb_release_head_state sock_rfree sk_mem_uncharge sk_forward_alloc_add() sk_mem_reclaim // set local var reclaimable __sk_mem_reclaim sk_forward_alloc_add()  In this syzkaller testcase, two threads call tcp_v6_do_rcv() with skb->truesize=768, the sk_forward_alloc changes like this: (cpu 1)             | (cpu 2)             | sk_forward_alloc ...                 | ...                 | 0 __sk_mem_schedule() |                     | +4096 = 4096 | __sk_mem_schedule() | +4096 = 8192 sk_mem_charge()     |                     | -768  = 7424 | sk_mem_charge()     | -768  = 6656 ...                 |    ...              | sk_mem_uncharge()   |                     | +768  = 7424 reclaimable=7424    |                     | | sk_mem_uncharge()   | +768  = 8192 | reclaimable=8192    | __sk_mem_reclaim()  |                     | -4096 = 4096 | __sk_mem_reclaim()  | -8192 = -4096 != 0  The skb_clone_and_charge_r() should not be called in tcp_v6_do_rcv() when sk->sk_state is TCP_LISTEN, it happens later in tcp_v6_syn_recv_sock(). Fix the same issue in dccp_v6_do_rcv().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-2312?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2025--2312" src="https://img.shields.io/badge/CVE--2025--2312-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in cifs-utils. When trying to obtain Kerberos credentials, the cifs.upcall program from the cifs-utils package makes an upcall to the wrong namespace in containerized environments. This issue may lead to disclosing sensitive data from the host's Kerberos credentials cache.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21691?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2025--21691" src="https://img.shields.io/badge/CVE--2025--21691-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cachestat: fix page cache statistics permission checking  When the 'cachestat()' system call was added in commit cf264e1329fb ("cachestat: implement cachestat syscall"), it was meant to be a much more convenient (and performant) version of mincore() that didn't need mapping things into the user virtual address space in order to work.  But it ended up missing the "check for writability or ownership" fix for mincore(), done in commit 134fca9063ad ("mm/mincore.c: make mincore() more conservative").  This just adds equivalent logic to 'cachestat()', modified for the file context (rather than vma).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21678?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2025--21678" src="https://img.shields.io/badge/CVE--2025--21678-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gtp: Destroy device along with udp socket's netns dismantle.  gtp_newlink() links the device to a list in dev_net(dev) instead of src_net, where a udp tunnel socket is created.  Even when src_net is removed, the device stays alive on dev_net(dev). Then, removing src_net triggers the splat below. [0]  In this example, gtp0 is created in ns2, and the udp socket is created in ns1.  ip netns add ns1 ip netns add ns2 ip -n ns1 link add netns ns2 name gtp0 type gtp role sgsn ip netns del ns1  Let's link the device to the socket's netns instead.  Now, gtp_net_exit_batch_rtnl() needs another netdev iteration to remove all gtp devices in the netns.  [0]: ref_tracker: net notrefcnt@000000003d6e7d05 has 1/2 users at sk_alloc (./include/net/net_namespace.h:345 net/core/sock.c:2236) inet_create (net/ipv4/af_inet.c:326 net/ipv4/af_inet.c:252) __sock_create (net/socket.c:1558) udp_sock_create4 (net/ipv4/udp_tunnel_core.c:18) gtp_create_sock (./include/net/udp_tunnel.h:59 drivers/net/gtp.c:1423) gtp_create_sockets (drivers/net/gtp.c:1447) gtp_newlink (drivers/net/gtp.c:1507) rtnl_newlink (net/core/rtnetlink.c:3786 net/core/rtnetlink.c:3897 net/core/rtnetlink.c:4012) rtnetlink_rcv_msg (net/core/rtnetlink.c:6922) netlink_rcv_skb (net/netlink/af_netlink.c:2542) netlink_unicast (net/netlink/af_netlink.c:1321 net/netlink/af_netlink.c:1347) netlink_sendmsg (net/netlink/af_netlink.c:1891) ____sys_sendmsg (net/socket.c:711 net/socket.c:726 net/socket.c:2583) ___sys_sendmsg (net/socket.c:2639) __sys_sendmsg (net/socket.c:2669) do_syscall_64 (arch/x86/entry/common.c:52 arch/x86/entry/common.c:83)  WARNING: CPU: 1 PID: 60 at lib/ref_tracker.c:179 ref_tracker_dir_exit (lib/ref_tracker.c:179) Modules linked in: CPU: 1 UID: 0 PID: 60 Comm: kworker/u16:2 Not tainted 6.13.0-rc5-00147-g4c1224501e9d #5 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 Workqueue: netns cleanup_net RIP: 0010:ref_tracker_dir_exit (lib/ref_tracker.c:179) Code: 00 00 00 fc ff df 4d 8b 26 49 bd 00 01 00 00 00 00 ad de 4c 39 f5 0f 85 df 00 00 00 48 8b 74 24 08 48 89 df e8 a5 cc 12 02 90 <0f> 0b 90 48 8d 6b 44 be 04 00 00 00 48 89 ef e8 80 de 67 ff 48 89 RSP: 0018:ff11000009a07b60 EFLAGS: 00010286 RAX: 0000000000002bd3 RBX: ff1100000f4e1aa0 RCX: 1ffffffff0e40ac6 RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8423ee3c RBP: ff1100000f4e1af0 R08: 0000000000000001 R09: fffffbfff0e395ae R10: 0000000000000001 R11: 0000000000036001 R12: ff1100000f4e1af0 R13: dead000000000100 R14: ff1100000f4e1af0 R15: dffffc0000000000 FS:  0000000000000000(0000) GS:ff1100006ce80000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f9b2464bd98 CR3: 0000000005286005 CR4: 0000000000771ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe07f0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> ? __warn (kernel/panic.c:748) ? ref_tracker_dir_exit (lib/ref_tracker.c:179) ? report_bug (lib/bug.c:201 lib/bug.c:219) ? handle_bug (arch/x86/kernel/traps.c:285) ? exc_invalid_op (arch/x86/kernel/traps.c:309 (discriminator 1)) ? asm_exc_invalid_op (./arch/x86/include/asm/idtentry.h:621) ? _raw_spin_unlock_irqrestore (./arch/x86/include/asm/irqflags.h:42 ./arch/x86/include/asm/irqflags.h:97 ./arch/x86/include/asm/irqflags.h:155 ./include/linux/spinlock_api_smp.h:151 kernel/locking/spinlock.c:194) ? ref_tracker_dir_exit (lib/ref_tracker.c:179) ? __pfx_ref_tracker_dir_exit (lib/ref_tracker.c:158) ? kfree (mm/slub.c:4613 mm/slub.c:4761) net_free (net/core/net_namespace.c:476 net/core/net_namespace.c:467) cleanup_net (net/core/net_namespace.c:664 (discriminator 3)) process_one_work (kernel/workqueue.c:3229) worker_thread (kernel/workqueue.c:3304 kernel/workqueue.c:3391 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21668?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2025--21668" src="https://img.shields.io/badge/CVE--2025--21668-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pmdomain: imx8mp-blk-ctrl: add missing loop break condition  Currently imx8mp_blk_ctrl_remove() will continue the for loop until an out-of-bounds exception occurs.  pstate: 60000005 (nZCv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : dev_pm_domain_detach+0x8/0x48 lr : imx8mp_blk_ctrl_shutdown+0x58/0x90 sp : ffffffc084f8bbf0 x29: ffffffc084f8bbf0 x28: ffffff80daf32ac0 x27: 0000000000000000 x26: ffffffc081658d78 x25: 0000000000000001 x24: ffffffc08201b028 x23: ffffff80d0db9490 x22: ffffffc082340a78 x21: 00000000000005b0 x20: ffffff80d19bc180 x19: 000000000000000a x18: ffffffffffffffff x17: ffffffc080a39e08 x16: ffffffc080a39c98 x15: 4f435f464f006c72 x14: 0000000000000004 x13: ffffff80d0172110 x12: 0000000000000000 x11: ffffff80d0537740 x10: ffffff80d05376c0 x9 : ffffffc0808ed2d8 x8 : ffffffc084f8bab0 x7 : 0000000000000000 x6 : 0000000000000000 x5 : ffffff80d19b9420 x4 : fffffffe03466e60 x3 : 0000000080800077 x2 : 0000000000000000 x1 : 0000000000000001 x0 : 0000000000000000 Call trace: dev_pm_domain_detach+0x8/0x48 platform_shutdown+0x2c/0x48 device_shutdown+0x158/0x268 kernel_restart_prepare+0x40/0x58 kernel_kexec+0x58/0xe8 __do_sys_reboot+0x198/0x258 __arm64_sys_reboot+0x2c/0x40 invoke_syscall+0x5c/0x138 el0_svc_common.constprop.0+0x48/0xf0 do_el0_svc+0x24/0x38 el0_svc+0x38/0xc8 el0t_64_sync_handler+0x120/0x130 el0t_64_sync+0x190/0x198 Code: 8128c2d0 ffffffc0 aa1e03e9 d503201f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57948?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2024--57948" src="https://img.shields.io/badge/CVE--2024--57948-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mac802154: check local interfaces before deleting sdata list  syzkaller reported a corrupted list in ieee802154_if_remove. [1]  Remove an IEEE 802.15.4 network interface after unregister an IEEE 802.15.4 hardware device from the system.  CPU0					CPU1 ====					==== genl_family_rcv_msg_doit		ieee802154_unregister_hw ieee802154_del_iface			ieee802154_remove_interfaces rdev_del_virtual_intf_deprecated	list_del(&sdata->list) ieee802154_if_remove list_del_rcu  The net device has been unregistered, since the rcu grace period, unregistration must be run before ieee802154_if_remove.  To avoid this issue, add a check for local->interfaces before deleting sdata list.  [1] kernel BUG at lib/list_debug.c:58! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 0 UID: 0 PID: 6277 Comm: syz-executor157 Not tainted 6.12.0-rc6-syzkaller-00005-g557329bcecc2 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:__list_del_entry_valid_or_report+0xf4/0x140 lib/list_debug.c:56 Code: e8 a1 7e 00 07 90 0f 0b 48 c7 c7 e0 37 60 8c 4c 89 fe e8 8f 7e 00 07 90 0f 0b 48 c7 c7 40 38 60 8c 4c 89 fe e8 7d 7e 00 07 90 <0f> 0b 48 c7 c7 a0 38 60 8c 4c 89 fe e8 6b 7e 00 07 90 0f 0b 48 c7 RSP: 0018:ffffc9000490f3d0 EFLAGS: 00010246 RAX: 000000000000004e RBX: dead000000000122 RCX: d211eee56bb28d00 RDX: 0000000000000000 RSI: 0000000080000000 RDI: 0000000000000000 RBP: ffff88805b278dd8 R08: ffffffff8174a12c R09: 1ffffffff2852f0d R10: dffffc0000000000 R11: fffffbfff2852f0e R12: dffffc0000000000 R13: dffffc0000000000 R14: dead000000000100 R15: ffff88805b278cc0 FS:  0000555572f94380(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000056262e4a3000 CR3: 0000000078496000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> __list_del_entry_valid include/linux/list.h:124 [inline] __list_del_entry include/linux/list.h:215 [inline] list_del_rcu include/linux/rculist.h:157 [inline] ieee802154_if_remove+0x86/0x1e0 net/mac802154/iface.c:687 rdev_del_virtual_intf_deprecated net/ieee802154/rdev-ops.h:24 [inline] ieee802154_del_iface+0x2c0/0x5c0 net/ieee802154/nl-phy.c:323 genl_family_rcv_msg_doit net/netlink/genetlink.c:1115 [inline] genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline] genl_rcv_msg+0xb14/0xec0 net/netlink/genetlink.c:1210 netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2551 genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219 netlink_unicast_kernel net/netlink/af_netlink.c:1331 [inline] netlink_unicast+0x7f6/0x990 net/netlink/af_netlink.c:1357 netlink_sendmsg+0x8e4/0xcb0 net/netlink/af_netlink.c:1901 sock_sendmsg_nosec net/socket.c:729 [inline] __sock_sendmsg+0x221/0x270 net/socket.c:744 ____sys_sendmsg+0x52a/0x7e0 net/socket.c:2607 ___sys_sendmsg net/socket.c:2661 [inline] __sys_sendmsg+0x292/0x380 net/socket.c:2690 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57924?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2024--57924" src="https://img.shields.io/badge/CVE--2024--57924-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs: relax assertions on failure to encode file handles  Encoding file handles is usually performed by a filesystem >encode_fh() method that may fail for various reasons.  The legacy users of exportfs_encode_fh(), namely, nfsd and name_to_handle_at(2) syscall are ready to cope with the possibility of failure to encode a file handle.  There are a few other users of exportfs_encode_{fh,fid}() that currently have a WARN_ON() assertion when ->encode_fh() fails. Relax those assertions because they are wrong.  The second linked bug report states commit 16aac5ad1fa9 ("ovl: support encoding non-decodable file handles") in v6.6 as the regressing commit, but this is not accurate.  The aforementioned commit only increases the chances of the assertion and allows triggering the assertion with the reproducer using overlayfs, inotify and drop_caches.  Triggering this assertion was always possible with other filesystems and other reasons of ->encode_fh() failures and more particularly, it was also possible with the exact same reproducer using overlayfs that is mounted with options index=on,nfs_export=on also on kernels < v6.6. Therefore, I am not listing the aforementioned commit as a Fixes commit.  Backport hint: this patch will have a trivial conflict applying to v6.6.y, and other trivial conflicts applying to stable kernels < v6.6.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 5" src="https://img.shields.io/badge/M-5-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>python3.12</strong> <code>3.12.3-1ubuntu0.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/python3.12@3.12.3-1ubuntu0.5?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4517?s=ubuntu&n=python3.12&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.12.3-1ubuntu0.7"><img alt="medium : CVE--2025--4517" src="https://img.shields.io/badge/CVE--2025--4517-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.095%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Allows arbitrary filesystem writes outside the extraction directory during extraction with filter="data".   You are affected by this vulnerability if using the tarfile module to extract untrusted tar archives using TarFile.extractall() or TarFile.extract() using the filter= parameter with a value of "data" or "tar". See the tarfile  extraction filters documentation https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter for more information.  Note that for Python 3.14 or later the default value of filter= changed from "no filtering" to `"data", so if you are relying on this new default behavior then your usage is also affected.  Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4435?s=ubuntu&n=python3.12&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.12.3-1ubuntu0.7"><img alt="medium : CVE--2025--4435" src="https://img.shields.io/badge/CVE--2025--4435-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.059%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When using a TarFile.errorlevel = 0 and extracting with a filter the documented behavior is that any filtered members would be skipped and not extracted. However the actual behavior of TarFile.errorlevel = 0 in affected versions is that the member would still be extracted and not skipped.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4330?s=ubuntu&n=python3.12&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.12.3-1ubuntu0.7"><img alt="medium : CVE--2025--4330" src="https://img.shields.io/badge/CVE--2025--4330-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.078%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Allows the extraction filter to be ignored, allowing symlink targets to point outside the destination directory, and the modification of some file metadata.   You are affected by this vulnerability if using the tarfile module to extract untrusted tar archives using TarFile.extractall() or TarFile.extract() using the filter= parameter with a value of "data" or "tar". See the tarfile  extraction filters documentation https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter for more information.  Note that for Python 3.14 or later the default value of filter= changed from "no filtering" to `"data", so if you are relying on this new default behavior then your usage is also affected.  Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4138?s=ubuntu&n=python3.12&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.12.3-1ubuntu0.7"><img alt="medium : CVE--2025--4138" src="https://img.shields.io/badge/CVE--2025--4138-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.088%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Allows the extraction filter to be ignored, allowing symlink targets to point outside the destination directory, and the modification of some file metadata.   You are affected by this vulnerability if using the tarfile module to extract untrusted tar archives using TarFile.extractall() or TarFile.extract() using the filter= parameter with a value of "data" or "tar". See the tarfile  extraction filters documentation https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter for more information.  Note that for Python 3.14 or later the default value of filter= changed from "no filtering" to `"data", so if you are relying on this new default behavior then your usage is also affected.  Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-12718?s=ubuntu&n=python3.12&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.12.3-1ubuntu0.7"><img alt="medium : CVE--2024--12718" src="https://img.shields.io/badge/CVE--2024--12718-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.12.3-1ubuntu0.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.063%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Allows modifying some file metadata (e.g. last modified) with filter="data" or file permissions (chmod) with filter="tar" of files outside the extraction directory. You are affected by this vulnerability if using the tarfile module to extract untrusted tar archives using TarFile.extractall() or TarFile.extract() using the filter= parameter with a value of "data" or "tar". See the tarfile  extraction filters documentation https://docs.python.org/3/library/tarfile.html#tarfile-extraction-filter for more information. Only Python versions 3.12 or later are affected by these vulnerabilities, earlier versions don't include the extraction filter feature.  Note that for Python 3.14 or later the default value of filter= changed from "no filtering" to `"data", so if you are relying on this new default behavior then your usage is also affected.  Note that none of these vulnerabilities significantly affect the installation of source distributions which are tar archives as source distributions already allow arbitrary code execution during the build process. However when evaluating source distributions it's important to avoid installing source distributions with suspicious links.

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
<tr><td>EPSS Score</td><td><code>3.921%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>88th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.322%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>55th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.143%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.862%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>74th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.103%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>29th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>ch.qos.logback/logback-core</strong> <code>1.4.14</code> (maven)</summary>

<small><code>pkg:maven/ch.qos.logback/logback-core@1.4.14</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12798?s=github&n=logback-core&ns=ch.qos.logback&t=maven&vr=%3E%3D1.4.0%2C%3C1.5.13"><img alt="medium 5.9: CVE--2024--12798" src="https://img.shields.io/badge/CVE--2024--12798-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')</i>

<table>
<tr><td>Affected range</td><td><code>>=1.4.0<br/><1.5.13</code></td></tr>
<tr><td>Fixed version</td><td><code>1.5.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:L/VI:H/VA:L/SC:L/SI:H/SA:L/RE:L/U:Clear</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.150%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>37th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Server-Side Request Forgery (SSRF) in SaxEventRecorder by QOS.CH logback version 1.5.12 on the Java platform, allows an attacker to forge requests by compromising logback configuration files in XML.
 
The attacks involves the modification of DOCTYPE declaration in  XML configuration files.

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
<tr><td>EPSS Score</td><td><code>0.145%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>commons-net/commons-net</strong> <code>3.6</code> (maven)</summary>

<small><code>pkg:maven/commons-net/commons-net@3.6</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-37533?s=github&n=commons-net&ns=commons-net&t=maven&vr=%3C3.9.0"><img alt="medium 6.5: CVE--2021--37533" src="https://img.shields.io/badge/CVE--2021--37533-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><3.9.0</code></td></tr>
<tr><td>Fixed version</td><td><code>3.9.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.197%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Prior to Apache Commons Net 3.9.0, Net's FTP client trusts the host from PASV response by default. A malicious server can redirect the Commons Net code to use a different host, but the user has to connect to the malicious server in the first place. This may lead to leakage of information about services running on the private network of the client.
The default in version 3.9.0 is now false to ignore such hosts, as cURL does. See https://issues.apache.org/jira/browse/NET-711.


</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>systemd</strong> <code>255.4-1ubuntu8.6</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/systemd@255.4-1ubuntu8.6?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4598?s=ubuntu&n=systemd&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C255.4-1ubuntu8.8"><img alt="medium : CVE--2025--4598" src="https://img.shields.io/badge/CVE--2025--4598-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><255.4-1ubuntu8.8</code></td></tr>
<tr><td>Fixed version</td><td><code>255.4-1ubuntu8.8</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pam</strong> <code>1.5.3-5ubuntu5.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pam@1.5.3-5ubuntu5.1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6020?s=ubuntu&n=pam&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C1.5.3-5ubuntu5.4"><img alt="medium : CVE--2025--6020" src="https://img.shields.io/badge/CVE--2025--6020-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.5.3-5ubuntu5.4</code></td></tr>
<tr><td>Fixed version</td><td><code>1.5.3-5ubuntu5.4</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>python-pip</strong> <code>24.0+dfsg-1ubuntu1.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/python-pip@24.0%2Bdfsg-1ubuntu1.1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-50181?s=ubuntu&n=python-pip&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C24.0%2Bdfsg-1ubuntu1.2"><img alt="medium : CVE--2025--50181" src="https://img.shields.io/badge/CVE--2025--50181-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><24.0+dfsg-1ubuntu1.2</code></td></tr>
<tr><td>Fixed version</td><td><code>24.0+dfsg-1ubuntu1.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

urllib3 is a user-friendly HTTP client library for Python. Prior to 2.5.0, it is possible to disable redirects for all requests by instantiating a PoolManager and specifying retries in a way that disable redirects. By default, requests and botocore users are not affected. An application attempting to mitigate SSRF or open redirect vulnerabilities by disabling redirects at the PoolManager level will remain vulnerable. This issue has been patched in version 2.5.0.

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
<tr><td>EPSS Score</td><td><code>0.279%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>51st percentile</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.fasterxml.woodstox/woodstox-core</strong> <code>5.3.0</code> (maven)</summary>

<small><code>pkg:maven/com.fasterxml.woodstox/woodstox-core@5.3.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-40152?s=github&n=woodstox-core&ns=com.fasterxml.woodstox&t=maven&vr=%3C5.4.0"><img alt="medium 6.5: CVE--2022--40152" src="https://img.shields.io/badge/CVE--2022--40152-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Stack-based Buffer Overflow</i>

<table>
<tr><td>Affected range</td><td><code><5.4.0</code></td></tr>
<tr><td>Fixed version</td><td><code>5.4.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.518%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>66th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Those using FasterXML/woodstox to seralize XML data may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow. This effect may support a denial of service attack.

This vulnerability is only relevant for users making use of the DTD parsing functionality.

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
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
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