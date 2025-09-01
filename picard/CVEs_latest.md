# Vulnerability Report for getwilds/picard:latest

Report generated on 2025-09-01 09:04:56 PST

<h2>:mag: Vulnerabilities of <code>getwilds/picard:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/picard:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:65839270a2e5a47ec377ef09d48d25f2caef6734c9015e43812689635a4e5345</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/high-2-e25d68"/> <img alt="medium: 39" src="https://img.shields.io/badge/medium-39-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/low-1-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>388 MB</td></tr>
<tr><td>packages</td><td>482</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.json/json</strong> <code>20230618</code> (maven)</summary>

<small><code>pkg:maven/org.json/json@20230618</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-5072?s=github&n=json&ns=org.json&t=maven&vr=%3C%3D20230618"><img alt="high 7.5: CVE--2023--5072" src="https://img.shields.io/badge/CVE--2023--5072-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improperly Implemented Security Check for Standard</i>

<table>
<tr><td>Affected range</td><td><code><=20230618</code></td></tr>
<tr><td>Fixed version</td><td><code>20231013</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.525%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>66th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
A denial of service vulnerability in JSON-Java was discovered by [ClusterFuzz](https://google.github.io/clusterfuzz/).  A bug in the parser means that an input string of modest size can lead to indefinite amounts of memory being used. There are two issues: (1) the parser bug can be used to circumvent a check that is supposed to prevent the key in a JSON object from itself being another JSON object; (2) if a key does end up being a JSON object then it gets converted into a string, using `\` to escape special characters, including `\` itself. So by nesting JSON objects, with a key that is a JSON object that has a key that is a JSON object, and so on, we can get an exponential number of `\` characters in the escaped string.

### Severity
High - Because this is an already-fixed DoS vulnerability, the only remaining impact possible is for existing binaries that have not been updated yet.

### Proof of Concept
```java
package orgjsonbug;

import org.json.JSONObject;

/**
 * Illustrates a bug in JSON-Java.
 */
public class Bug {
  private static String makeNested(int depth) {
    if (depth == 0) {
      return "{\"a\":1}";
    }
    return "{\"a\":1;\t\0" + makeNested(depth - 1) + ":1}";
  }

  public static void main(String[] args) {
    String input = makeNested(30);
    System.out.printf("Input string has length %d: %s\n", input.length(), input);
    JSONObject output = new JSONObject(input);
    System.out.printf("Output JSONObject has length %d: %s\n", output.toString().length(), output);
  }
}
```
When run, this reports that the input string has length 367. Then, after a long pause, the program crashes inside new JSONObject with OutOfMemoryError.

### Further Analysis
The issue is fixed by [this PR](https://github.com/stleary/JSON-java/pull/759).

### Timeline
**Date reported**: 07/14/2023
**Date fixed**: 
**Date disclosed**: 10/12/2023

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>commons-io/commons-io</strong> <code>2.11.0</code> (maven)</summary>

<small><code>pkg:maven/commons-io/commons-io@2.11.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-47554?s=github&n=commons-io&ns=commons-io&t=maven&vr=%3E%3D2.0%2C%3C2.14.0"><img alt="high 8.7: CVE--2024--47554" src="https://img.shields.io/badge/CVE--2024--47554-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0<br/><2.14.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.14.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.213%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>44th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Uncontrolled Resource Consumption vulnerability in Apache Commons IO.

The `org.apache.commons.io.input.XmlStreamReader` class may excessively consume CPU resources when processing maliciously crafted input.


This issue affects Apache Commons IO: from 2.0 before 2.14.0.

Users are recommended to upgrade to version 2.14.0 or later, which fixes the issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 7" src="https://img.shields.io/badge/M-7-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>openjdk-17</strong> <code>17.0.14+7-1~24.04</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openjdk-17@17.0.14%2B7-1~24.04?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
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

<a href="https://scout.docker.com/v/CVE-2025-30698?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C17.0.15%2B6%7Eus1-0ubuntu1%7E24.04"><img alt="medium : CVE--2025--30698" src="https://img.shields.io/badge/CVE--2025--30698-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.15+6~us1-0ubuntu1~24.04</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.15+6~us1-0ubuntu1~24.04</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.082%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 2D).  Supported versions that are affected are Oracle Java SE: 8u441, 8u441-perf, 11.0.26, 17.0.14, 21.0.6, 24; Oracle GraalVM for JDK: 17.0.14, 21.0.6, 24; Oracle GraalVM Enterprise Edition: 20.3.17 and  21.3.13. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized read access to a subset of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 5.6 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-30691?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C17.0.15%2B6%7Eus1-0ubuntu1%7E24.04"><img alt="medium : CVE--2025--30691" src="https://img.shields.io/badge/CVE--2025--30691-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.15+6~us1-0ubuntu1~24.04</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.15+6~us1-0ubuntu1~24.04</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.057%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in Oracle Java SE (component: Compiler).  Supported versions that are affected are Oracle Java SE: 21.0.6, 24; Oracle GraalVM for JDK: 21.0.6 and  24. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE.  Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE accessible data as well as  unauthorized read access to a subset of Oracle Java SE accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 4.8 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21587?s=ubuntu&n=openjdk-17&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C17.0.15%2B6%7Eus1-0ubuntu1%7E24.04"><img alt="medium : CVE--2025--21587" src="https://img.shields.io/badge/CVE--2025--21587-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><17.0.15+6~us1-0ubuntu1~24.04</code></td></tr>
<tr><td>Fixed version</td><td><code>17.0.15+6~us1-0ubuntu1~24.04</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.085%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE:8u441, 8u441-perf, 11.0.26, 17.0.14, 21.0.6, 24; Oracle GraalVM for JDK:17.0.14, 21.0.6, 24; Oracle GraalVM Enterprise Edition:20.3.17 and  21.3.13. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as unauthorized access to critical data or complete access to all Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 7.4 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 6" src="https://img.shields.io/badge/M-6-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libssh</strong> <code>0.10.6-2build2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libssh@0.10.6-2build2?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-5318?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C0.10.6-2ubuntu0.1"><img alt="medium 8.1: CVE--2025--5318" src="https://img.shields.io/badge/CVE--2025--5318-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.055%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the libssh library. An out-of-bounds read can be triggered in the sftp_handle function due to an incorrect comparison check that permits the function to access memory beyond the valid handle list and to return an invalid pointer, which is used in further processing. This vulnerability allows an authenticated remote attacker to potentially read unintended memory regions, exposing sensitive information or affect service behavior.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-5987?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C0.10.6-2ubuntu0.1"><img alt="medium : CVE--2025--5987" src="https://img.shields.io/badge/CVE--2025--5987-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.050%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in libssh when using the ChaCha20 cipher with the OpenSSL library. If an attacker manages to exhaust the heap space, this error is not detected and may lead to libssh using a partially initialized cipher context. This occurs because the OpenSSL error code returned aliases with the SSH_OK code, resulting in libssh not properly detecting the error returned by the OpenSSL library. This issue can lead to undefined behavior, including compromised data confidentiality and integrity or crashes.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-5372?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C0.10.6-2ubuntu0.1"><img alt="medium : CVE--2025--5372" src="https://img.shields.io/badge/CVE--2025--5372-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in libssh versions built with OpenSSL versions older than 3.0, specifically in the ssh_kdf() function responsible for key derivation. Due to inconsistent interpretation of return values where OpenSSL uses 0 to indicate failure and libssh uses 0 for success—the function may mistakenly return a success status even when key derivation fails. This results in uninitialized cryptographic key buffers being used in subsequent communication, potentially compromising SSH sessions' confidentiality, integrity, and availability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-5351?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C0.10.6-2ubuntu0.1"><img alt="medium : CVE--2025--5351" src="https://img.shields.io/badge/CVE--2025--5351-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the key export functionality of libssh. The issue occurs in the internal function responsible for converting cryptographic keys into serialized formats. During error handling, a memory structure is freed but not cleared, leading to a potential double free issue if an additional failure occurs later in the function. This condition may result in heap corruption or application instability in low-memory scenarios, posing a risk to system reliability where key export operations are performed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4878?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C0.10.6-2ubuntu0.1"><img alt="medium : CVE--2025--4878" src="https://img.shields.io/badge/CVE--2025--4878-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.015%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in libssh, where an uninitialized variable exists under certain conditions in the privatekey_from_file() function. This flaw can be triggered if the file specified by the filename doesn't exist and may lead to possible signing failures or heap corruption.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4877?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C0.10.6-2ubuntu0.1"><img alt="medium : CVE--2025--4877" src="https://img.shields.io/badge/CVE--2025--4877-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.10.6-2ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

There's a vulnerability in the libssh package where when a libssh consumer passes in an unexpectedly large input buffer to ssh_get_fingerprint_hash() function. In such cases the bin_to_base64() function can experience an integer overflow leading to a memory under allocation, when that happens it's possible that the program perform out of bounds write leading to a heap corruption. This issue affects only 32-bits builds of libssh.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.45.1-1ubuntu2.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/sqlite3@3.45.1-1ubuntu2.1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
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

<a href="https://scout.docker.com/v/CVE-2025-3277?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.45.1-1ubuntu2.3"><img alt="medium 9.8: CVE--2025--3277" src="https://img.shields.io/badge/CVE--2025--3277-lightgrey?label=medium%209.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.45.1-1ubuntu2.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.45.1-1ubuntu2.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.117%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>31st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An integer overflow can be triggered in SQLite’s `concat_ws()` function. The resulting, truncated integer is then used to allocate a buffer. When SQLite then writes the resulting string to the buffer, it uses the original, untruncated size and thus a wild Heap Buffer overflow of size ~4GB can be triggered. This can result in arbitrary code execution.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-29087?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.45.1-1ubuntu2.3"><img alt="medium 7.5: CVE--2025--29087" src="https://img.shields.io/badge/CVE--2025--29087-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.45.1-1ubuntu2.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.45.1-1ubuntu2.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.058%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In SQLite 3.44.0 through 3.49.0 before 3.49.1, the concat_ws() SQL function can cause memory to be written beyond the end of a malloc-allocated buffer. If the separator argument is attacker-controlled and has a large string (e.g., 2MB or more), an integer overflow occurs in calculating the size of the result buffer, and thus malloc may not allocate enough memory.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-29088?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.45.1-1ubuntu2.3"><img alt="medium : CVE--2025--29088" src="https://img.shields.io/badge/CVE--2025--29088-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.45.1-1ubuntu2.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.45.1-1ubuntu2.3</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In SQLite 3.49.0 before 3.49.1, certain argument values to sqlite3_db_config (in the C-language API) can cause a denial of service (application crash). An sz*nBig multiplication is not cast to a 64-bit integer, and consequently some memory allocations may be incorrect.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.8.3-1.1ubuntu3.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnutls28@3.8.3-1.1ubuntu3.3?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-32990?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.8.3-1.1ubuntu3.4"><img alt="medium 8.2: CVE--2025--32990" src="https://img.shields.io/badge/CVE--2025--32990-lightgrey?label=medium%208.2&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.8.3-1.1ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.8.3-1.1ubuntu3.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.072%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-buffer-overflow (off-by-one) flaw was found in the GnuTLS software in the template parsing logic within the certtool utility. When it reads certain settings from a template file, it allows an attacker to cause an out-of-bounds (OOB) NULL pointer write, resulting in memory corruption and a denial-of-service (DoS) that could potentially crash the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-6395?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.8.3-1.1ubuntu3.4"><img alt="medium : CVE--2025--6395" src="https://img.shields.io/badge/CVE--2025--6395-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.8.3-1.1ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.8.3-1.1ubuntu3.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.057%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A NULL pointer dereference flaw was found in the GnuTLS software in _gnutls_figure_common_ciphersuite(). When it reads certain settings from a template file, it can allow an attacker to cause an out-of-bounds (OOB) NULL pointer write, resulting in memory corruption and a denial of service (DoS) that could crash the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-32989?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.8.3-1.1ubuntu3.4"><img alt="medium : CVE--2025--32989" src="https://img.shields.io/badge/CVE--2025--32989-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.8.3-1.1ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.8.3-1.1ubuntu3.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-buffer-overread vulnerability was found in GnuTLS in how it handles the Certificate Transparency (CT) Signed Certificate Timestamp (SCT) extension during X.509 certificate parsing. This flaw allows a malicious user to create a certificate containing a malformed SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) that contains sensitive data. This issue leads to the exposure of confidential information when GnuTLS verifies certificates from certain websites when the certificate (SCT) is not checked correctly.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-32988?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.8.3-1.1ubuntu3.4"><img alt="medium : CVE--2025--32988" src="https://img.shields.io/badge/CVE--2025--32988-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.8.3-1.1ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>3.8.3-1.1ubuntu3.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GnuTLS. A double-free vulnerability exists in GnuTLS due to incorrect ownership handling in the export logic of Subject Alternative Name (SAN) entries containing an otherName. If the type-id OID is invalid or malformed, GnuTLS will call asn1_delete_structure() on an ASN.1 node it does not own, leading to a double-free condition when the parent function or caller later attempts to free the same structure.  This vulnerability can be triggered using only public GnuTLS APIs and may result in denial of service or memory corruption, depending on allocator behavior.

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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.commons/commons-compress</strong> <code>1.24.0</code> (maven)</summary>

<small><code>pkg:maven/org.apache.commons/commons-compress@1.24.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-26308?s=github&n=commons-compress&ns=org.apache.commons&t=maven&vr=%3E%3D1.21%2C%3C1.26.0"><img alt="medium 6.7: CVE--2024--26308" src="https://img.shields.io/badge/CVE--2024--26308-lightgrey?label=medium%206.7&labelColor=fbb552"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code>>=1.21<br/><1.26.0</code></td></tr>
<tr><td>Fixed version</td><td><code>1.26.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.430%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>62nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Allocation of Resources Without Limits or Throttling vulnerability in Apache Commons Compress. This issue affects Apache Commons Compress: from 1.21 before 1.26.

Users are recommended to upgrade to version 1.26, which fixes the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-25710?s=github&n=commons-compress&ns=org.apache.commons&t=maven&vr=%3E%3D1.3%2C%3C1.26.0"><img alt="medium 5.9: CVE--2024--25710" src="https://img.shields.io/badge/CVE--2024--25710-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Loop with Unreachable Exit Condition ('Infinite Loop')</i>

<table>
<tr><td>Affected range</td><td><code>>=1.3<br/><1.26.0</code></td></tr>
<tr><td>Fixed version</td><td><code>1.26.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:C/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.012%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Loop with Unreachable Exit Condition ('Infinite Loop') vulnerability in Apache Commons Compress. This issue affects Apache Commons Compress: from 1.3 through 1.25.0.

Users are recommended to upgrade to version 1.26.0 which fixes the issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.38.2-3.2build2.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/perl@5.38.2-3.2build2.1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
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

<a href="https://scout.docker.com/v/CVE-2024-56406?s=ubuntu&n=perl&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C5.38.2-3.2ubuntu0.1"><img alt="medium : CVE--2024--56406" src="https://img.shields.io/badge/CVE--2024--56406-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.38.2-3.2ubuntu0.1</code></td></tr>
<tr><td>Fixed version</td><td><code>5.38.2-3.2ubuntu0.1</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.059%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap buffer overflow vulnerability was discovered in Perl.  Release branches 5.34, 5.36, 5.38 and 5.40 are affected, including development versions from 5.33.1 through 5.41.10.  When there are non-ASCII bytes in the left-hand-side of the `tr` operator, `S_do_trans_invmap` can overflow the destination pointer `d`.  $ perl -e '$_ = "\x{FF}" x 1000000; tr/\xFF/\x{100}/;' Segmentation fault (core dumped)  It is believed that this vulnerability can enable Denial of Service and possibly Code Execution attacks on platforms that lack sufficient defenses.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gdk-pixbuf</strong> <code>2.42.10+dfsg-3ubuntu3.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gdk-pixbuf@2.42.10%2Bdfsg-3ubuntu3.1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6199?s=ubuntu&n=gdk-pixbuf&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C2.42.10%2Bdfsg-3ubuntu3.2"><img alt="medium 3.3: CVE--2025--6199" src="https://img.shields.io/badge/CVE--2025--6199-lightgrey?label=medium%203.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.42.10+dfsg-3ubuntu3.2</code></td></tr>
<tr><td>Fixed version</td><td><code>2.42.10+dfsg-3ubuntu3.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>3.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the GIF parser of GdkPixbuf’s LZW decoder. When an invalid symbol is encountered during decompression, the decoder sets the reported output size to the full buffer length rather than the actual number of written bytes. This logic error results in uninitialized sections of the buffer being included in the output, potentially leaking arbitrary memory contents in the processed image.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-7345?s=ubuntu&n=gdk-pixbuf&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C2.42.10%2Bdfsg-3ubuntu3.2"><img alt="medium : CVE--2025--7345" src="https://img.shields.io/badge/CVE--2025--7345-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.42.10+dfsg-3ubuntu3.2</code></td></tr>
<tr><td>Fixed version</td><td><code>2.42.10+dfsg-3ubuntu3.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.123%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>32nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw exists in gdk‑pixbuf within the gdk_pixbuf__jpeg_image_load_increment function (io-jpeg.c) and in glib’s g_base64_encode_step (glib/gbase64.c). When processing maliciously crafted JPEG images, a heap buffer overflow can occur during Base64 encoding, allowing out-of-bounds reads from heap memory, potentially causing application crashes or arbitrary code execution.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>krb5</strong> <code>1.20.1-6ubuntu2.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/krb5@1.20.1-6ubuntu2.5?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-3576?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C1.20.1-6ubuntu2.6"><img alt="medium : CVE--2025--3576" src="https://img.shields.io/badge/CVE--2025--3576-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.20.1-6ubuntu2.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1.20.1-6ubuntu2.6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.038%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the MIT Kerberos implementation allows GSSAPI-protected messages using RC4-HMAC-MD5 to be spoofed due to weaknesses in the MD5 checksum design. If RC4 is preferred over stronger encryption types, an attacker could exploit MD5 collisions to forge message integrity codes. This may lead to unauthorized message tampering.

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
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without proper protection, allowing local users to elevate their privileges to root via multiple symlink attacks and race conditions.

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
<tr><td>EPSS Score</td><td><code>0.037%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in systemd-coredump. This flaw allows an attacker to force a SUID process to crash and replace it with a non-SUID binary to access the original's privileged process coredump, allowing the attacker to read sensitive data, such as /etc/shadow content, loaded by the original process.  A SUID binary or process has a special type of permission, which allows the process to run with the file owner's permissions, regardless of the user executing the binary. This allows the process to access more restricted data than unprivileged users or processes would be able to. An attacker can leverage this flaw by forcing a SUID process to crash and force the Linux kernel to recycle the process PID before systemd-coredump can analyze the /proc/pid/auxv file. If the attacker wins the race condition, they gain access to the original's SUID process coredump file. They can read sensitive content loaded into memory by the original binary, affecting data confidentiality.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>glib2.0</strong> <code>2.80.0-6ubuntu3.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glib2.0@2.80.0-6ubuntu3.2?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4373?s=ubuntu&n=glib2.0&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C2.80.0-6ubuntu3.4"><img alt="medium : CVE--2025--4373" src="https://img.shields.io/badge/CVE--2025--4373-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.80.0-6ubuntu3.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.80.0-6ubuntu3.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.091%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GLib, which is vulnerable to an integer overflow in the g_string_insert_unichar() function. When the position at which to insert the character is large, the position will overflow, leading to a buffer underwrite.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>glibc</strong> <code>2.39-0ubuntu8.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glibc@2.39-0ubuntu8.4?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-5702?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C2.39-0ubuntu8.5"><img alt="medium : CVE--2025--5702" src="https://img.shields.io/badge/CVE--2025--5702-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.39-0ubuntu8.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.39-0ubuntu8.5</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.055%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The strcmp implementation optimized for the Power10 processor in the GNU C Library version 2.39 and later writes to vector registers v20 to v31 without saving contents from the caller (those registers are defined as non-volatile registers by the powerpc64le ABI), resulting in overwriting of its contents and potentially altering control flow of the caller, or leaking the input strings to the function to other parts of the program.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.commons/commons-lang3</strong> <code>3.12.0</code> (maven)</summary>

<small><code>pkg:maven/org.apache.commons/commons-lang3@3.12.0</code></small><br/>
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
</table>