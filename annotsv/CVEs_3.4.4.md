# Vulnerability Report for getwilds/annotsv:3.4.4

Report generated on 2025-06-24 04:52:59 PST

<h2>:mag: Vulnerabilities of <code>getwilds/annotsv:3.4.4</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/annotsv:3.4.4</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:4e0e8b17d00b0c2c23133907e3f675c3f28f73c1fd9d70b236918562b796c7bb</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 22" src="https://img.shields.io/badge/critical-22-8b1924"/> <img alt="high: 97" src="https://img.shields.io/badge/high-97-e25d68"/> <img alt="medium: 59" src="https://img.shields.io/badge/medium-59-fbb552"/> <img alt="low: 4" src="https://img.shields.io/badge/low-4-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>2.3 GB</td></tr>
<tr><td>packages</td><td>300</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 12" src="https://img.shields.io/badge/C-12-8b1924"/> <img alt="high: 39" src="https://img.shields.io/badge/H-39-e25d68"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.fasterxml.jackson.core/jackson-databind</strong> <code>2.9.8</code> (maven)</summary>

<small><code>pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2020-9548?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10.4"><img alt="critical 9.8: CVE--2020--9548" src="https://img.shields.io/badge/CVE--2020--9548-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>13.945%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>94th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4, 2.8.11.6, and 2.7.9.7 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPConfig (aka anteros-core).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-9547?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10.4"><img alt="critical 9.8: CVE--2020--9547" src="https://img.shields.io/badge/CVE--2020--9547-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.229%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4, 2.8.11.6, and 2.7.9.7 mishandles the interaction between serialization gadgets and typing, related to `com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig` (aka `ibatis-sqlmap`).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-9546?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="critical 9.8: CVE--2020--9546" src="https://img.shields.io/badge/CVE--2020--9546-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.327%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>84th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig (aka shaded hikari-config).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-8840?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.2"><img alt="critical 9.8: CVE--2020--8840" src="https://img.shields.io/badge/CVE--2020--8840-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.2</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>8.164%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>92nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.6.7.4, 2.7.x before 2.7.9.7, 2.8.x before 2.8.11.5 and 2.9.x before 2.9.10.2 lacks certain xbean-reflect/JNDI blocking, as demonstrated by org.apache.xbean.propertyeditor.JndiConverter.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-20330?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.1"><img alt="critical 9.8: CVE--2019--20330" src="https://img.shields.io/badge/CVE--2019--20330-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.997%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.6.7.4, 2.7.x before 2.7.9.7, 2.8.x before 2.8.11.5, and 2.9.x before 2.9.10.2 lacks certain `net.sf.ehcache` blocking.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-17531?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10.1"><img alt="critical 9.8: CVE--2019--17531" src="https://img.shields.io/badge/CVE--2019--17531-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.190%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>78th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 prior to 2.9.10.1, 2.8.11.5, and 2.6.7.3. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the apache-log4j-extra (version 1.2.x) jar in the classpath, and an attacker can provide a JNDI service to access, it is possible to make the service execute a malicious payload. 

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-17267?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10"><img alt="critical 9.8: CVE--2019--17267" src="https://img.shields.io/badge/CVE--2019--17267-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.357%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>79th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10 and 2.8.11.5. It is related to net.sf.ehcache.hibernate.EhcacheJtaTransactionManagerLookup.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-16943?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10.1"><img alt="critical 9.8: CVE--2019--16943" src="https://img.shields.io/badge/CVE--2019--16943-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.841%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>82nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 prior to 2.9.10.1, 2.8.11.5, and 2.6.7.3. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the p6spy (3.8.6) jar in the classpath, and an attacker can find an RMI service endpoint to access, it is possible to make the service execute a malicious payload. This issue exists because of com.p6spy.engine.spy.P6DataSource mishandling.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-16942?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10.1"><img alt="critical 9.8: CVE--2019--16942" src="https://img.shields.io/badge/CVE--2019--16942-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.438%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>62nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.0.0 through 2.9.10. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the commons-dbcp (1.4) jar in the classpath, and an attacker can find an RMI service endpoint to access, it is possible to make the service execute a malicious payload. This issue exists because of org.apache.commons.dbcp.datasources.SharedPoolDataSource and org.apache.commons.dbcp.datasources.PerUserPoolDataSource mishandling.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-16335?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10"><img alt="critical 9.8: CVE--2019--16335" src="https://img.shields.io/badge/CVE--2019--16335-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.651%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>70th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10, 2.8.11.5, and 2.6.7.3. It is related to com.zaxxer.hikari.HikariDataSource. This is a different vulnerability than CVE-2019-14540.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-14540?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10"><img alt="critical 9.8: CVE--2019--14540" src="https://img.shields.io/badge/CVE--2019--14540-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>7.082%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind before 2.9.10, 2.8.11.5, and 2.6.7.3. It is related to `com.zaxxer.hikari.HikariConfig`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-14379?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.9.2"><img alt="critical 9.8: CVE--2019--14379" src="https://img.shields.io/badge/CVE--2019--14379-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.9.2</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.9.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.455%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>80th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

SubTypeValidator.java in FasterXML jackson-databind before 2.9.9.2, 2.8.11.4, and 2.7.9.6 mishandles default typing when ehcache is used (because of net.sf.ehcache.transaction.manager.DefaultTransactionManagerLookup), leading to remote code execution.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-11113?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="high 8.8: CVE--2020--11113" src="https://img.shields.io/badge/CVE--2020--11113-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>58.820%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.openjpa.ee.WASRegistryManagedRuntime (aka openjpa).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-11112?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="high 8.8: CVE--2020--11112" src="https://img.shields.io/badge/CVE--2020--11112-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>11.418%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.proxy.provider.remoting.RmiProvider (aka apache/commons-proxy).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-11111?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="high 8.8: CVE--2020--11111" src="https://img.shields.io/badge/CVE--2020--11111-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.196%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>84th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.activemq.* (aka activemq-jms, activemq-core, activemq-pool, and activemq-pool-jms).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-10969?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="high 8.8: CVE--2020--10969" src="https://img.shields.io/badge/CVE--2020--10969-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.478%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>80th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to javax.swing.JEditorPane.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-10968?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="high 8.8: CVE--2020--10968" src="https://img.shields.io/badge/CVE--2020--10968-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.632%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.aoju.bus.proxy.provider.remoting.RmiProvider (aka bus-proxy).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-10673?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C2.9.10.4"><img alt="high 8.8: CVE--2020--10673" src="https://img.shields.io/badge/CVE--2020--10673-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><2.9.10.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>20.473%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>95th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 and 2.6.7.4 mishandles the interaction between serialization gadgets and typing, related to com.caucho.config.types.ResourceRef (aka caucho-quercus).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-10672?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="high 8.8: CVE--2020--10672" src="https://img.shields.io/badge/CVE--2020--10672-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>40.070%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>97th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory (aka aries.transaction.jms).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-42004?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3C2.12.7.1"><img alt="high 8.2: CVE--2022--42004" src="https://img.shields.io/badge/CVE--2022--42004-lightgrey?label=high%208.2&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><2.12.7.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.12.7.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.219%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>45th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In FasterXML jackson-databind before 2.12.7.1 and in 2.13.x before 2.13.4, resource exhaustion can occur because of a lack of a check in BeanDeserializer._deserializeFromArray to prevent use of deeply nested arrays. This issue can only happen when the `UNWRAP_SINGLE_VALUE_ARRAYS` feature is explicitly enabled.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-20190?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C2.9.10.7"><img alt="high 8.1: CVE--2021--20190" src="https://img.shields.io/badge/CVE--2021--20190-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><2.9.10.7</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.636%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>69th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in jackson-databind before 2.9.10.7 and 2.6.7.5. FasterXML mishandles the interaction between serialization gadgets and typing. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36189?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36189" src="https://img.shields.io/badge/CVE--2020--36189-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.635%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>85th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 an 2.6.7.5 mishandles the interaction between serialization gadgets and typing, related to com.newrelic.agent.deps.ch.qos.logback.core.db.DriverManagerConnectionSource.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36188?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36188" src="https://img.shields.io/badge/CVE--2020--36188-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.980%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 and 2.6.7.5 mishandles the interaction between serialization gadgets and typing, related to `com.newrelic.agent.deps.ch.qos.logback.core.db.JNDIConnectionSource`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36187?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36187" src="https://img.shields.io/badge/CVE--2020--36187-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp.datasources.SharedPoolDataSource.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36186?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36186" src="https://img.shields.io/badge/CVE--2020--36186-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to `org.apache.tomcat.dbcp.dbcp.datasources.PerUserPoolDataSource`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36185?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36185" src="https://img.shields.io/badge/CVE--2020--36185-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.957%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to `org.apache.tomcat.dbcp.dbcp2.datasources.SharedPoolDataSource`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36184?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36184" src="https://img.shields.io/badge/CVE--2020--36184-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>5.061%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.datasources.PerUserPoolDataSource.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36183?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.00%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36183" src="https://img.shields.io/badge/CVE--2020--36183-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.00<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.421%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>84th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 and 2.6.7.5 mishandles the interaction between serialization gadgets and typing, related to org.docx4j.org.apache.xalan.lib.sql.JNDIConnectionPool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36182?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36182" src="https://img.shields.io/badge/CVE--2020--36182-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.957%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 and 2.6.7.5 mishandles the interaction between serialization gadgets and typing, related to org.apache.tomcat.dbcp.dbcp2.cpdsadapter.DriverAdapterCPDS.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36181?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36181" src="https://img.shields.io/badge/CVE--2020--36181-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.306%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 and 2.6.7.5 mishandles the interaction between serialization gadgets and typing, related to `org.apache.tomcat.dbcp.dbcp.cpdsadapter.DriverAdapterCPDS`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36180?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36180" src="https://img.shields.io/badge/CVE--2020--36180-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.957%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 and 2.6.7.5 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.cpdsadapter.DriverAdapterCPDS.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36179?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C2.9.10.8"><img alt="high 8.1: CVE--2020--36179" src="https://img.shields.io/badge/CVE--2020--36179-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><2.9.10.8</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>61.296%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 and 2.6.7.5 mishandles the interaction between serialization gadgets and typing, related to `oadd.org.apache.commons.dbcp.cpdsadapter.DriverAdapterCPDS`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-35728?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C%3D2.9.10.7"><img alt="high 8.1: CVE--2020--35728" src="https://img.shields.io/badge/CVE--2020--35728-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><=2.9.10.7</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>41.431%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>97th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to com.oracle.wls.shaded.org.apache.xalan.lib.sql.JNDIConnectionPool (aka embedded Xalan in org.glassfish.web/javax.servlet.jsp.jstl).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-35491?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C%3D2.9.10.7"><img alt="high 8.1: CVE--2020--35491" src="https://img.shields.io/badge/CVE--2020--35491-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><=2.9.10.7</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.892%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.SharedPoolDataSource.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-35490?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C%3D2.9.10.7"><img alt="high 8.1: CVE--2020--35490" src="https://img.shields.io/badge/CVE--2020--35490-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><=2.9.10.7</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.8</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>4.749%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.8 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.dbcp2.datasources.PerUserPoolDataSource.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-24750?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0%2C%3C%3D2.9.10.5"><img alt="high 8.1: CVE--2020--24750" src="https://img.shields.io/badge/CVE--2020--24750-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0<br/><=2.9.10.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.107%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.6.7.5 and from 2.7.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to com.pastdev.httpcomponents.configuration.JndiConfiguration.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-24616?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C%3D2.9.10.5"><img alt="high 8.1: CVE--2020--24616" src="https://img.shields.io/badge/CVE--2020--24616-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><=2.9.10.5</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>3.783%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>88th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

This project contains the general-purpose data-binding functionality and tree-model for Jackson Data Processor. FasterXML jackson-databind 2.x before 2.9.10.6 mishandles the interaction between serialization gadgets and typing, related to br.com.anteros.dbcp.AnterosDBCPDataSource (aka Anteros-DBCP).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-14195?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.4"><img alt="high 8.1: CVE--2020--14195" src="https://img.shields.io/badge/CVE--2020--14195-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>9.511%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>92nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to org.jsecurity.realm.jndi.JndiRealmFactory (aka org.jsecurity).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-14062?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.4"><img alt="high 8.1: CVE--2020--14062" src="https://img.shields.io/badge/CVE--2020--14062-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>7.706%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>91st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to com.sun.org.apache.xalan.internal.lib.sql.JNDIConnectionPool (aka xalan2).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-14061?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.4"><img alt="high 8.1: CVE--2020--14061" src="https://img.shields.io/badge/CVE--2020--14061-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>6.150%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to oracle.jms.AQjmsQueueConnectionFactory, oracle.jms.AQjmsXATopicConnectionFactory, oracle.jms.AQjmsTopicConnectionFactory, oracle.jms.AQjmsXAQueueConnectionFactory, and oracle.jms.AQjmsXAConnectionFactory (aka weblogic/oracle-aqjms).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-14060?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.4"><img alt="high 8.1: CVE--2020--14060" src="https://img.shields.io/badge/CVE--2020--14060-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.5</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>8.718%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>92nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.5 mishandles the interaction between serialization gadgets and typing, related to oadd.org.apache.xalan.lib.sql.JNDIConnectionPool (aka apache/drill).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-11620?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="high 8.1: CVE--2020--11620" src="https://img.shields.io/badge/CVE--2020--11620-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.241%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>84th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.apache.commons.jelly.impl.Embedded (aka commons-jelly).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-11619?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C%3D2.9.10.3"><img alt="high 8.1: CVE--2020--11619" src="https://img.shields.io/badge/CVE--2020--11619-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.826%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>82nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.10.4 mishandles the interaction between serialization gadgets and typing, related to org.springframework.aop.config.MethodLocatingFactoryBean (aka spring-aop).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-10650?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3C%3D2.9.10.3"><img alt="high 8.1: CVE--2020--10650" src="https://img.shields.io/badge/CVE--2020--10650-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code><=2.9.10.3</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.4</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>5.253%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>90th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The com.fasterxml.jackson.core:jackson-databind library before version 2.9.10.4 is vulnerable to an Unsafe Deserialization vulnerability when handling interactions related to the class `ignite-jta`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-42003?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.4.0-rc1%2C%3C2.12.7.1"><img alt="high 7.5: CVE--2022--42003" src="https://img.shields.io/badge/CVE--2022--42003-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=2.4.0-rc1<br/><2.12.7.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.12.7.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.303%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>53rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In FasterXML jackson-databind 2.4.0-rc1 until 2.12.7.1 and in 2.13.x before 2.13.4.2 resource exhaustion can occur because of a lack of a check in primitive value deserializers to avoid deep wrapper array nesting, when the UNWRAP_SINGLE_VALUE_ARRAYS feature is enabled. This was patched in 2.12.7.1, 2.13.4.2, and 2.14.0.

Commits that introduced vulnerable code are 
https://github.com/FasterXML/jackson-databind/commit/d499f2e7bbc5ebd63af11e1f5cf1989fa323aa45, https://github.com/FasterXML/jackson-databind/commit/0e37a39502439ecbaa1a5b5188387c01bf7f7fa1, and https://github.com/FasterXML/jackson-databind/commit/7ba9ac5b87a9d6ac0d2815158ecbeb315ad4dcdc.

Fix commits are https://github.com/FasterXML/jackson-databind/commit/cd090979b7ea78c75e4de8a4aed04f7e9fa8deea and https://github.com/FasterXML/jackson-databind/commit/d78d00ee7b5245b93103fef3187f70543d67ca33.

The `2.13.4.1` release does fix this issue, however it also references a non-existent jackson-bom which causes build failures for gradle users. See https://github.com/FasterXML/jackson-databind/issues/3627#issuecomment-1277957548 for details. This is fixed in `2.13.4.2` which is listed in the advisory metadata so that users are not subjected to unnecessary build failures

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-36518?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3C%3D2.12.6.0"><img alt="high 7.5: CVE--2020--36518" src="https://img.shields.io/badge/CVE--2020--36518-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Out-of-bounds Write</i>

<table>
<tr><td>Affected range</td><td><code><=2.12.6.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.12.6.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.490%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>65th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

jackson-databind is a data-binding package for the Jackson Data Processor. jackson-databind allows a Java stack overflow exception and denial of service via a large depth of nested objects.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-25649?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.7.0.0%2C%3C%3D2.9.10.6"><img alt="high 7.5: CVE--2020--25649" src="https://img.shields.io/badge/CVE--2020--25649-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Restriction of XML External Entity Reference</i>

<table>
<tr><td>Affected range</td><td><code>>=2.7.0.0<br/><=2.9.10.6</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in FasterXML Jackson Databind, where it did not have entity expansion secured properly. This flaw allows vulnerability to XML external entity (XXE) attacks. The highest threat from this vulnerability is data integrity.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-14892?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10"><img alt="high 7.5: CVE--2019--14892" src="https://img.shields.io/badge/CVE--2019--14892-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Exposure of Sensitive Information to an Unauthorized Actor</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.873%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>74th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was discovered in jackson-databind in versions before 2.9.10, 2.8.11.5, and 2.6.7.3, where it would permit polymorphic deserialization of a malicious object using commons-configuration 1 and 2 JNDI classes. An attacker could use this flaw to execute arbitrary code.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-14439?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.9.2"><img alt="high 7.5: CVE--2019--14439" src="https://img.shields.io/badge/CVE--2019--14439-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.9.2</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.9.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>10.318%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9.2, 2.8.11.4, 2.7.9.6, and 2.6.7.3. This occurs when Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has the logback jar in the classpath.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-12086?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.9"><img alt="high 7.5: CVE--2019--12086" src="https://img.shields.io/badge/CVE--2019--12086-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.9</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.9</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>15.745%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>94th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x before 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint, the service has the mysql-connector-java jar (8.0.14 or earlier) in the classpath, and an attacker can host a crafted MySQL server reachable by the victim, an attacker can send a crafted JSON message that allows them to read arbitrary local files on the server. This occurs because of missing com.mysql.cj.jdbc.admin.MiniAdmin validation.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-14893?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.10"><img alt="high : CVE--2019--14893" src="https://img.shields.io/badge/CVE--2019--14893-lightgrey?label=high%20&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.10</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.10</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.698%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>71st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was discovered in FasterXML jackson-databind in all versions before 2.9.10 and 2.10.0, where it would permit polymorphic deserialization of malicious objects using the xalan JNDI gadget when used in conjunction with polymorphic type handling methods such as `enableDefaultTyping()` or when @JsonTypeInfo is using `Id.CLASS` or `Id.MINIMAL_CLASS` or in any other way which ObjectMapper.readValue might instantiate objects from unsafe sources. An attacker could use this flaw to execute arbitrary code.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-12814?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.9.1"><img alt="medium 5.9: CVE--2019--12814" src="https://img.shields.io/badge/CVE--2019--12814-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.9.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.9.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>19.277%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>95th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Polymorphic Typing issue was discovered in FasterXML jackson-databind 2.x through 2.9.9. When Default Typing is enabled (either globally or for a specific property) for an externally exposed JSON endpoint and the service has JDOM 1.x or 2.x jar in the classpath, an attacker can send a specifically crafted JSON message that allows them to read arbitrary local files on the server.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-12384?s=github&n=jackson-databind&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.9.0%2C%3C2.9.9.1"><img alt="medium 5.9: CVE--2019--12384" src="https://img.shields.io/badge/CVE--2019--12384-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=2.9.0<br/><2.9.9.1</code></td></tr>
<tr><td>Fixed version</td><td><code>2.9.9.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>51.675%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

FasterXML jackson-databind 2.x before 2.9.9.1 might allow attackers to have a variety of impacts by leveraging failure to block the logback-core class from polymorphic deserialization. Depending on the classpath content, remote code execution may be possible.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 3" src="https://img.shields.io/badge/C-3-8b1924"/> <img alt="high: 24" src="https://img.shields.io/badge/H-24-e25d68"/> <img alt="medium: 15" src="https://img.shields.io/badge/M-15-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>org.apache.tomcat.embed/tomcat-embed-core</strong> <code>9.0.16</code> (maven)</summary>

<small><code>pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@9.0.16</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2020-1938?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.31"><img alt="critical 9.8: CVE--2020--1938" src="https://img.shields.io/badge/CVE--2020--1938-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Improper Privilege Management</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.31</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.31</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>94.469%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP connection. If such connections are available to an attacker, they can be exploited in ways that may be surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected (and recommended in the security guide) that this Connector would be disabled if not required. This vulnerability report identified a mechanism that allowed: returning arbitrary files from anywhere in the web application, processing any file in the web application as a JSP Further, if the web application allowed file upload and stored those files within the web application (or the attacker was able to control the content of the web application by some other means) then this, along with the ability to process a file as a JSP, made remote code execution possible. It is important to note that mitigation is only required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-1745?s=gitlab&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.31"><img alt="critical 9.8: CVE--2020--1745" src="https://img.shields.io/badge/CVE--2020--1745-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.31</code></td></tr>
<tr><td>Fixed version</td><td><code>7.0.100, 8.5.51, 9.0.31</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A file inclusion vulnerability was found in the AJP connector enabled with a default AJP configuration port of in Undertow. A remote, unauthenticated attacker could exploit this vulnerability to read web application files from a vulnerable server. In instances where the vulnerable server allows file uploads, an attacker could upload malicious JavaServer Pages (JSP) code within a variety of file types and trigger this vulnerability to gain remote code execution.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-24813?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C9.0.99"><img alt="critical 9.2: CVE--2025--24813" src="https://img.shields.io/badge/CVE--2025--24813-lightgrey?label=critical%209.2&labelColor=8b1924"/></a> <i>Path Equivalence: 'file.name' (Internal Dot)</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><9.0.99</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.99</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>93.871%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Path Equivalence: 'file.Name' (Internal Dot) leading to Remote Code Execution and/or Information disclosure and/or malicious content added to uploaded files via write enabled Default Servlet in Apache Tomcat.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2, from 10.1.0-M1 through 10.1.34, from 9.0.0.M1 through 9.0.98.

If all of the following were true, a malicious user was able to view security sensitive files and/or inject content into those files:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- a target URL for security sensitive uploads that was a sub-directory of a target URL for public uploads
- attacker knowledge of the names of security sensitive files being uploaded
- the security sensitive files also being uploaded via partial PUT

If all of the following were true, a malicious user was able to perform remote code execution:
- writes enabled for the default servlet (disabled by default)
- support for partial PUT (enabled by default)
- application was using Tomcat's file based session persistence with the default storage location
- application included a library that may be leveraged in a deserialization attack

Users are recommended to upgrade to version 11.0.3, 10.1.35 or 9.0.99, which fixes the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-48988?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C%3D9.0.105"><img alt="high 8.7: CVE--2025--48988" src="https://img.shields.io/badge/CVE--2025--48988-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><=9.0.105</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.106</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Allocation of Resources Without Limits or Throttling vulnerability in Apache Tomcat.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.7, from 10.1.0-M1 through 10.1.41, from 9.0.0.M1 through 9.0.105.

Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-34750?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.90"><img alt="high 8.7: CVE--2024--34750" src="https://img.shields.io/badge/CVE--2024--34750-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.90</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.90</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>19.663%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>95th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper Handling of Exceptional Conditions, Uncontrolled Resource Consumption vulnerability in Apache Tomcat. When processing an HTTP/2 stream, Tomcat did not handle some cases of excessive HTTP headers correctly. This led to a miscounting of active HTTP/2 streams which in turn led to the use of an incorrect infinite timeout which allowed connections to remain open which should have been closed.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M20, from 10.1.0-M1 through 10.1.24, from 9.0.0-M1 through 9.0.89.

Users are recommended to upgrade to version 11.0.0-M21, 10.1.25 or 9.0.90, which fixes the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-25762?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0M1%2C%3C9.0.20"><img alt="high 8.6: CVE--2022--25762" src="https://img.shields.io/badge/CVE--2022--25762-lightgrey?label=high%208.6&labelColor=e25d68"/></a> <i>Improper Resource Shutdown or Release</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0M1<br/><9.0.20</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.20</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.366%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>58th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

If a web application sends a WebSocket message concurrently with the WebSocket connection closing when running on Apache Tomcat 8.5.0 to 8.5.75 or Apache Tomcat 9.0.0.M1 to 9.0.20, it is possible that the application will continue to use the socket after it has been closed. The error handling triggered in this case could cause the a pooled object to be placed in the pool twice. This could result in subsequent connections using the same object concurrently which could result in data being returned to the wrong use and/or other errors.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-0232?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C9.0.17"><img alt="high 8.1: CVE--2019--0232" src="https://img.shields.io/badge/CVE--2019--0232-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><9.0.17</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.17</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>94.225%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When running on Windows with enableCmdLineArguments enabled, the CGI Servlet in Apache Tomcat 9.0.0.M1 to 9.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 is vulnerable to Remote Code Execution due to a bug in the way the JRE passes command line arguments to Windows. The CGI Servlet is disabled by default. The CGI option enableCmdLineArguments is disable by default in Tomcat 9.0.x (and will be disabled by default in all versions in response to this vulnerability). For a detailed explanation of the JRE behaviour, see Markus Wulftange's blog (https://codewhitesec.blogspot.com/2016/02/java-and-command-line-injections-in-windows.html) and this archived MSDN blog (https://web.archive.org/web/20161228144344/https://blogs.msdn.microsoft.com/twistylittlepassagesallalike/2011/04/23/everyone-quotes-command-line-arguments-the-wrong-way/).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-8022?s=gitlab&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.35"><img alt="high 7.8: CVE--2020--8022" src="https://img.shields.io/badge/CVE--2020--8022-lightgrey?label=high%207.8&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.35</code></td></tr>
<tr><td>Fixed version</td><td><code>8.0.53, 9.0.35</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.204%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>43rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A Incorrect Default Permissions vulnerability in the packaging of tomcat on SUSE Enterprise Storage 5, SUSE Linux Enterprise Server 12-SP2-BCL, SUSE Linux Enterprise Server 12-SP2-LTSS, SUSE Linux Enterprise Server 12-SP3-BCL, SUSE Linux Enterprise Server 12-SP3-LTSS, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server 15-LTSS, SUSE Linux Enterprise Server for SAP 12-SP2, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 15, SUSE OpenStack Cloud 7, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud Crowbar 8 allows local attackers to escalate from group tomcat to root. This issue affects: SUSE Enterprise Storage 5 tomcat versions prior to 8.0.53-29.32.1. SUSE Linux Enterprise Server 12-SP2-BCL tomcat versions prior to 8.0.53-29.32.1. SUSE Linux Enterprise Server 12-SP2-LTSS tomcat versions prior to 8.0.53-29.32.1. SUSE Linux Enterprise Server 12-SP3-BCL tomcat versions prior to 8.0.53-29.32.1. SUSE Linux Enterprise Server 12-SP3-LTSS tomcat versions prior to 8.0.53-29.32.1. SUSE Linux Enterprise Server 12-SP4 tomcat versions prior to 9.0.35-3.39.1. SUSE Linux Enterprise Server 12-SP5 tomcat versions prior to 9.0.35-3.39.1. SUSE Linux Enterprise Server 15-LTSS tomcat versions prior to 9.0.35-3.57.3. SUSE Linux Enterprise Server for SAP 12-SP2 tomcat versions prior to 8.0.53-29.32.1. SUSE Linux Enterprise Server for SAP 12-SP3 tomcat versions prior to 8.0.53-29.32.1. SUSE Linux Enterprise Server for SAP 15 tomcat versions prior to 9.0.35-3.57.3. SUSE OpenStack Cloud 7 tomcat versions prior to 8.0.53-29.32.1. SUSE OpenStack Cloud 8 tomcat versions prior to 8.0.53-29.32.1. SUSE OpenStack Cloud Crowbar 8 tomcat versions prior to 8.0.53-29.32.1.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-46589?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.83"><img alt="high 7.5: CVE--2023--46589" src="https://img.shields.io/badge/CVE--2023--46589-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.83</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.83</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>45.383%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>97th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper Input Validation vulnerability in Apache Tomcat. Tomcat from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.1.15, from 9.0.0-M1 through 9.0.82, and from 8.5.0 through 8.5.95 did not correctly parse HTTP trailer headers. A trailer header that exceeded the header size limit could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

Users are recommended to upgrade to version 11.0.0-M11 onwards, 10.1.16 onwards, 9.0.83 onwards or 8.5.96 onwards, which fix the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-24998?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.71"><img alt="high 7.5: CVE--2023--24998" src="https://img.shields.io/badge/CVE--2023--24998-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.71</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.71</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>41.119%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>97th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Apache Commons FileUpload before 1.5 does not limit the number of request parts to be processed resulting in the possibility of an attacker triggering a DoS with a malicious upload or series of uploads. Note that, like all of the file upload limits, the new configuration option (FileUploadBase#setFileCountMax) is not enabled by default and must be explicitly configured.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-42252?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.68"><img alt="high 7.5: CVE--2022--42252" src="https://img.shields.io/badge/CVE--2022--42252-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.68</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.68</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.164%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

If Apache Tomcat 8.5.0 to 8.5.82, 9.0.0-M1 to 9.0.67, 10.0.0-M1 to 10.0.26 or 10.1.0-M1 to 10.1.0 was configured to ignore invalid HTTP headers via setting rejectIllegalHeader to false (the default for 8.5.x only), Tomcat did not reject a request containing an invalid Content-Length header making a request smuggling attack possible if Tomcat was located behind a reverse proxy that also failed to reject the request with the invalid header.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-29885?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.13%2C%3C9.0.63"><img alt="high 7.5: CVE--2022--29885" src="https://img.shields.io/badge/CVE--2022--29885-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.13<br/><9.0.63</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>66.148%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The documentation of Apache Tomcat 10.1.0-M1 to 10.1.0-M14, 10.0.0-M1 to 10.0.20, 9.0.13 to 9.0.62 and 8.5.38 to 8.5.78 for the EncryptInterceptor incorrectly stated it enabled Tomcat clustering to run over an untrusted network. This was not correct. While the EncryptInterceptor does provide confidentiality and integrity protection, it does not protect against all risks associated with running over any untrusted network, particularly DoS risks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-41079?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.44"><img alt="high 7.5: CVE--2021--41079" src="https://img.shields.io/badge/CVE--2021--41079-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.44</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.44</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Apache Tomcat 8.5.0 to 8.5.63, 9.0.0-M1 to 9.0.43 and 10.0.0-M1 to 10.0.2 did not properly validate incoming TLS packets. When Tomcat was configured to use NIO+OpenSSL or NIO2+OpenSSL for TLS, a specially crafted packet could be used to trigger an infinite loop resulting in a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-30639?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.45"><img alt="high 7.5: CVE--2021--30639" src="https://img.shields.io/badge/CVE--2021--30639-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Handling of Exceptional Conditions</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.45</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.45</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.344%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>56th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in Apache Tomcat allows an attacker to remotely trigger a denial of service. An error introduced as part of a change to improve error handling during non-blocking I/O meant that the error flag associated with the Request object was not reset between requests. This meant that once a non-blocking I/O error occurred, all future requests handled by that request object would fail. Users were able to trigger non-blocking I/O errors, e.g. by dropping a connection, thereby creating the possibility of triggering a DoS. Applications that do not use non-blocking I/O are not exposed to this vulnerability. This issue affects Apache Tomcat 10.0.3 to 10.0.4; 9.0.44; 8.5.64.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-25122?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.43"><img alt="high 7.5: CVE--2021--25122" src="https://img.shields.io/badge/CVE--2021--25122-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Exposure of Sensitive Information to an Unauthorized Actor</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.43</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.43</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.775%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>85th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When responding to new h2c connection requests, Apache Tomcat versions 10.0.0-M1 to 10.0.0, 9.0.0.M1 to 9.0.41 and 8.5.0 to 8.5.61 could duplicate request headers and a limited amount of request body from one request to another meaning user A and user B could both see the results of user A's request.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-17527?s=gitlab&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C%3D9.0.35"><img alt="high 7.5: CVE--2020--17527" src="https://img.shields.io/badge/CVE--2020--17527-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><=9.0.35</code></td></tr>
<tr><td>Fixed version</td><td><code>8.5.60, 9.0.40, 10.0.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>8.457%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>92nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

While investigating bug it was discovered that Apache Tomcat to to to could re-use an HTTP request header value from the previous stream received on an `HTTP/2` connection for the request associated with the subsequent stream. While this would most likely lead to an error and the closure of the `HTTP/2` connection, it is possible that information could leak between requests.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-13935?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C9.0.37"><img alt="high 7.5: CVE--2020--13935" src="https://img.shields.io/badge/CVE--2020--13935-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Loop with Unreachable Exit Condition ('Infinite Loop')</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><9.0.37</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.37</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>92.541%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to 7.0.104. Invalid payload lengths could trigger an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-13934?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M5%2C%3C9.0.36"><img alt="high 7.5: CVE--2020--13934" src="https://img.shields.io/badge/CVE--2020--13934-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Restriction of Operations within the Bounds of a Memory Buffer</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M5<br/><9.0.36</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.36</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>22.718%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>96th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An h2c direct connection to Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M5 to 9.0.36 and 8.5.1 to 8.5.56 did not release the HTTP/1.1 processor after the upgrade to HTTP/2. If a sufficient number of such requests were made, an OutOfMemoryException could occur leading to a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-11996?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C9.0.35"><img alt="high 7.5: CVE--2020--11996" src="https://img.shields.io/badge/CVE--2020--11996-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><9.0.35</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.35</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>37.402%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>97th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to 9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage for several seconds. If a sufficient number of such requests were made on concurrent HTTP/2 connections, the server could become unresponsive.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-17563?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.30"><img alt="high 7.5: CVE--2019--17563" src="https://img.shields.io/badge/CVE--2019--17563-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Session Fixation</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.30</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.30</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>3.258%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>87th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When using FORM authentication with Apache Tomcat 9.0.0.M1 to 9.0.29, 8.5.0 to 8.5.49 and 7.0.0 to 7.0.98 there was a narrow window where an attacker could perform a session fixation attack. The window was considered too narrow for an exploit to be practical but, erring on the side of caution, this issue has been treated as a security vulnerability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-10072?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C9.0.20"><img alt="high 7.5: CVE--2019--10072" src="https://img.shields.io/badge/CVE--2019--10072-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Locking</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><9.0.20</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.20</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>71.534%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The fix for CVE-2019-0199 was incomplete and did not address HTTP/2 connection window exhaustion on write in Apache Tomcat versions 9.0.0.M1 to 9.0.19 and 8.5.0 to 8.5.40 . By not sending WINDOW_UPDATE messages for the connection window (stream 0) clients were able to cause server-side threads to block eventually leading to thread exhaustion and a DoS.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56337?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C9.0.98"><img alt="high 7.2: CVE--2024--56337" src="https://img.shields.io/badge/CVE--2024--56337-lightgrey?label=high%207.2&labelColor=e25d68"/></a> <i>Time-of-check Time-of-use (TOCTOU) Race Condition</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><9.0.98</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.98</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U</code></td></tr>
<tr><td>EPSS Score</td><td><code>9.709%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability in Apache Tomcat.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.1, from 10.1.0-M1 through 10.1.33, from 9.0.0.M1 through 9.0.97.

The mitigation for CVE-2024-50379 was incomplete.

Users running Tomcat on a case insensitive file system with the default servlet write enabled (readonly initialisation 
parameter set to the non-default value of false) may need additional configuration to fully mitigate CVE-2024-50379 depending on which version of Java they are using with Tomcat:
- running on Java 8 or Java 11: the system property sun.io.useCanonCaches must be explicitly set to false (it defaults to true)
- running on Java 17: the system property sun.io.useCanonCaches, if set, must be set to false (it defaults to false)
- running on Java 21 onwards: no further configuration is required (the system property and the problematic cache have been removed)

Tomcat 11.0.3, 10.1.35 and 9.0.99 onwards will include checks that sun.io.useCanonCaches is set appropriately before allowing the default servlet to be write enabled on a case insensitive file system. Tomcat will also set sun.io.useCanonCaches to false by default where it can.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50379?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C9.0.98"><img alt="high 7.2: CVE--2024--50379" src="https://img.shields.io/badge/CVE--2024--50379-lightgrey?label=high%207.2&labelColor=e25d68"/></a> <i>Time-of-check Time-of-use (TOCTOU) Race Condition</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><9.0.98</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.98</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U</code></td></tr>
<tr><td>EPSS Score</td><td><code>89.324%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability during JSP compilation in Apache Tomcat permits an RCE on case insensitive file systems when the default servlet is enabled for write (non-default configuration).

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.1, from 10.1.0-M1 through 10.1.33, from 9.0.0.M1 through 9.0.97.

Users are recommended to upgrade to version 11.0.2, 10.1.34 or 9.0.98, which fixes the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-23181?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.58"><img alt="high 7.0: CVE--2022--23181" src="https://img.shields.io/badge/CVE--2022--23181-lightgrey?label=high%207.0&labelColor=e25d68"/></a> <i>Time-of-check Time-of-use (TOCTOU) Race Condition</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.58</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.58</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.150%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>37th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The fix for bug CVE-2020-9484 introduced a time of check time of use vulnerability into Apache Tomcat 10.1.0-M1 to 10.1.0-M8, 10.0.0-M5 to 10.0.14, 9.0.35 to 9.0.56 and 8.5.55 to 8.5.73 that allowed a local attacker to perform actions with the privileges of the user that the Tomcat process is using. This issue is only exploitable when Tomcat is configured to persist sessions using the FileStore.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-25329?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.41"><img alt="high 7.0: CVE--2021--25329" src="https://img.shields.io/badge/CVE--2021--25329-lightgrey?label=high%207.0&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.41</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.41</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>4.622%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The fix for CVE-2020-9484 was incomplete. When using Apache Tomcat 10.0.0-M1 to 10.0.0, 9.0.0.M1 to 9.0.41, 8.5.0 to 8.5.61 or 7.0.0. to 7.0.107 with a configuration edge case that was highly unlikely to be used, the Tomcat instance was still vulnerable to CVE-2020-9494. Note that both the previously published prerequisites for CVE-2020-9484 and the previously published mitigations for CVE-2020-9484 also apply to this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-9484?s=gitlab&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C%3D9.0.34"><img alt="high 7.0: CVE--2020--9484" src="https://img.shields.io/badge/CVE--2020--9484-lightgrey?label=high%207.0&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><=9.0.34</code></td></tr>
<tr><td>Fixed version</td><td><code>7.0.104, 8.5.55, 9.0.35, 10.0.0-M5</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>93.261%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When using Apache Tomcat, an attacker is able to control the contents and name of a file on the server.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-12418?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.29"><img alt="high 7.0: CVE--2019--12418" src="https://img.shields.io/badge/CVE--2019--12418-lightgrey?label=high%207.0&labelColor=e25d68"/></a> <i>Insufficiently Protected Credentials</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.29</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.29</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.556%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>67th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When Apache Tomcat 9.0.0.M1 to 9.0.28, 8.5.0 to 8.5.47, 7.0.0 and 7.0.97 is configured with the JMX Remote Lifecycle Listener, a local attacker without access to the Tomcat process or configuration files is able to manipulate the RMI registry to perform a man-in-the-middle attack to capture user names and passwords used to access the JMX interface. The attacker can then use these credentials to access the JMX interface and gain complete control over the Tomcat instance.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-44487?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.81"><img alt="medium 6.9: CVE--2023--44487" src="https://img.shields.io/badge/CVE--2023--44487-lightgrey?label=medium%206.9&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.81</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.81</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>94.437%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

## HTTP/2 Rapid reset attack
The HTTP/2 protocol allows clients to indicate to the server that a previous stream should be canceled by sending a RST_STREAM frame. The protocol does not require the client and server to coordinate the cancellation in any way, the client may do it unilaterally. The client may also assume that the cancellation will take effect immediately when the server receives the RST_STREAM frame, before any other data from that TCP connection is processed.

Abuse of this feature is called a Rapid Reset attack because it relies on the ability for an endpoint to send a RST_STREAM frame immediately after sending a request frame, which makes the other endpoint start working and then rapidly resets the request. The request is canceled, but leaves the HTTP/2 connection open. 

The HTTP/2 Rapid Reset attack built on this capability is simple: The client opens a large number of streams at once as in the standard HTTP/2 attack, but rather than waiting for a response to each request stream from the server or proxy, the client cancels each request immediately.

The ability to reset streams immediately allows each connection to have an indefinite number of requests in flight. By explicitly canceling the requests, the attacker never exceeds the limit on the number of concurrent open streams. The number of in-flight requests is no longer dependent on the round-trip time (RTT), but only on the available network bandwidth.

In a typical HTTP/2 server implementation, the server will still have to do significant amounts of work for canceled requests, such as allocating new stream data structures, parsing the query and doing header decompression, and mapping the URL to a resource. For reverse proxy implementations, the request may be proxied to the backend server before the RST_STREAM frame is processed. The client on the other hand paid almost no costs for sending the requests. This creates an exploitable cost asymmetry between the server and the client.

Multiple software artifacts implementing HTTP/2 are affected. This advisory was originally ingested from the `swift-nio-http2` repo advisory and their original conent follows.

## swift-nio-http2 specific advisory
swift-nio-http2 is vulnerable to a denial-of-service vulnerability in which a malicious client can create and then reset a large number of HTTP/2 streams in a short period of time. This causes swift-nio-http2 to commit to a large amount of expensive work which it then throws away, including creating entirely new `Channel`s to serve the traffic. This can easily overwhelm an `EventLoop` and prevent it from making forward progress.

swift-nio-http2 1.28 contains a remediation for this issue that applies reset counter using a sliding window. This constrains the number of stream resets that may occur in a given window of time. Clients violating this limit will have their connections torn down. This allows clients to continue to cancel streams for legitimate reasons, while constraining malicious actors.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-24549?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C%3D9.0.85"><img alt="medium 6.6: CVE--2024--24549" src="https://img.shields.io/badge/CVE--2024--24549-lightgrey?label=medium%206.6&labelColor=fbb552"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><=9.0.85</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.86</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:U</code></td></tr>
<tr><td>EPSS Score</td><td><code>55.100%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Denial of Service due to improper input validation vulnerability for HTTP/2 requests in Apache Tomcat. When processing an HTTP/2 request, if the request exceeded any of the configured limits for headers, the associated HTTP/2 stream was not reset until after all of the headers had been processed.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through 9.0.85, from 8.5.0 through 8.5.98.

Users are recommended to upgrade to version 11.0.0-M17, 10.1.19, 9.0.86 or 8.5.99 which fix the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-30640?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0M1%2C%3C9.0.45"><img alt="medium 6.5: CVE--2021--30640" src="https://img.shields.io/badge/CVE--2021--30640-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Improper Encoding or Escaping of Output</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0M1<br/><9.0.45</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.45</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.244%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>48th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the JNDI Realm of Apache Tomcat allows an attacker to authenticate using variations of a valid user name and/or to bypass some of the protection provided by the LockOut Realm. This issue affects Apache Tomcat 10.0.0-M1 to 10.0.5; 9.0.0.M1 to 9.0.45; 8.5.0 to 8.5.65.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-49125?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C%3D9.0.105"><img alt="medium 6.3: CVE--2025--49125" src="https://img.shields.io/badge/CVE--2025--49125-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>Authentication Bypass Using an Alternate Path or Channel</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><=9.0.105</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.106</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Authentication Bypass Using an Alternate Path or Channel vulnerability in Apache Tomcat.  When using PreResources or PostResources mounted other than at the root of the web application, it was possible to access those resources via an unexpected path. That path was likely not to be protected by the same security constraints as the expected path, allowing those security constraints to be bypassed.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.7, from 10.1.0-M1 through 10.1.41, from 9.0.0.M1 through 9.0.105.

Users are recommended to upgrade to version 11.0.8, 10.1.42 or 9.0.106, which fix the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-23672?s=gitlab&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.86"><img alt="medium 6.3: CVE--2024--23672" src="https://img.shields.io/badge/CVE--2024--23672-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.86</code></td></tr>
<tr><td>Fixed version</td><td><code>11.0.0-M17, 10.1.19, 9.0.86, 8.5.99</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.437%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>62nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Denial of Service via incomplete cleanup vulnerability in Apache Tomcat. It was possible for WebSocket clients to keep WebSocket connections open leading to increased resource consumption.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through 9.0.85, from 8.5.0 through 8.5.98.

Users are recommended to upgrade to version 11.0.0-M17, 10.1.19, 9.0.86 or 8.5.99 which fix the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-41080?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.80"><img alt="medium 6.1: CVE--2023--41080" src="https://img.shields.io/badge/CVE--2023--41080-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> <i>URL Redirection to Untrusted Site ('Open Redirect')</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.80</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.80</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>11.116%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

URL Redirection to Untrusted Site ('Open Redirect') vulnerability in FORM authentication feature Apache Tomcat. This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.0.12, from 9.0.0-M1 through 9.0.79 and from 8.5.0 through 8.5.92.

The vulnerability is limited to the ROOT (default) web application.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-0221?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.17"><img alt="medium 6.1: CVE--2019--0221" src="https://img.shields.io/badge/CVE--2019--0221-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> <i>Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.17</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.17</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>3.821%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>88th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The SSI printenv command in Apache Tomcat 9.0.0.M1 to 9.0.0.17, 8.5.0 to 8.5.39 and 7.0.0 to 7.0.93 echoes user provided data without escaping and is, therefore, vulnerable to XSS. SSI is disabled by default. The printenv command is intended for debugging and is unlikely to be present in a production website.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-24122?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.40"><img alt="medium 5.9: CVE--2021--24122" src="https://img.shields.io/badge/CVE--2021--24122-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Exposure of Sensitive Information to an Unauthorized Actor</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.40</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.40</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>59.872%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When serving resources from a network location using the NTFS file system, Apache Tomcat versions 10.0.0-M1 to 10.0.0-M9, 9.0.0.M1 to 9.0.39, 8.5.0 to 8.5.59 and 7.0.0 to 7.0.106 were susceptible to JSP source code disclosure in some configurations. The root cause was the unexpected behaviour of the JRE API File.getCanonicalPath() which in turn was caused by the inconsistent behaviour of the Windows API (FindFirstFileW) in some circumstances.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-21733?s=gitlab&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M11%2C%3C9.0.44"><img alt="medium 5.3: CVE--2024--21733" src="https://img.shields.io/badge/CVE--2024--21733-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M11<br/><9.0.44</code></td></tr>
<tr><td>Fixed version</td><td><code>8.5.64, 9.0.44</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>68.617%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Generation of Error Message Containing Sensitive Information vulnerability in Apache Tomcat. This issue affects Apache Tomcat: from 8.5.7 through 8.5.63, from 9.0.0-M11 through 9.0.43.

Users are recommended to upgrade to version 8.5.64 onwards or 9.0.44 onwards, which contain a fix for the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-45648?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.81"><img alt="medium 5.3: CVE--2023--45648" src="https://img.shields.io/badge/CVE--2023--45648-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.81</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.81</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.753%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>72nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper Input Validation vulnerability in Apache Tomcat.

Tomcat from 11.0.0-M1 through 11.0.0-M11, from 10.1.0-M1 through 10.1.13, from 9.0.0-M1 through 9.0.81 and from 8.5.0 through 8.5.93 did not correctly parse HTTP trailer headers. A specially crafted, invalid trailer header could cause Tomcat to treat a single 
request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

Users are recommended to upgrade to version 11.0.0-M12 onwards, 10.1.14 onwards, 9.0.81 onwards or 8.5.94 onwards, which fix the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-42795?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.81"><img alt="medium 5.3: CVE--2023--42795" src="https://img.shields.io/badge/CVE--2023--42795-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Incomplete Cleanup</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.81</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.81</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.525%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>66th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Incomplete Cleanup vulnerability in Apache Tomcat.

When recycling various internal objects in Apache Tomcat from 11.0.0-M1 through 11.0.0-M11, from 10.1.0-M1 through 10.1.13, from 9.0.0-M1 through 9.0.80 and from 8.5.0 through 8.5.93, an error could cause Tomcat to skip some parts of the recycling process leading to information leaking from the current request/response to the next.

Users are recommended to upgrade to version 11.0.0-M12 onwards, 10.1.14 onwards, 9.0.81 onwards or 8.5.94 onwards, which fixes the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-33037?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.48"><img alt="medium 5.3: CVE--2021--33037" src="https://img.shields.io/badge/CVE--2021--33037-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.48</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.48</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.607%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>85th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Apache Tomcat 10.0.0-M1 to 10.0.6, 9.0.0.M1 to 9.0.46 and 8.5.0 to 8.5.66 did not correctly parse the HTTP transfer-encoding request header in some circumstances leading to the possibility to request smuggling when used with a reverse proxy. Specifically: - Tomcat incorrectly ignored the transfer encoding header if the client declared it would only accept an HTTP/1.0 response; - Tomcat honoured the identify encoding; and - Tomcat did not ensure that, if present, the chunked encoding was the final encoding.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-1935?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.31"><img alt="medium 4.8: CVE--2020--1935" src="https://img.shields.io/badge/CVE--2020--1935-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> <i>Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.31</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.31</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>76th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99 the HTTP header parsing code used an approach to end-of-line parsing that allowed some invalid HTTP headers to be parsed as valid. This led to a possibility of HTTP Request Smuggling if Tomcat was located behind a reverse proxy that incorrectly handled the invalid Transfer-Encoding header in a particular manner. Such a reverse proxy is considered unlikely.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-28708?s=gitlab&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.72"><img alt="medium 4.3: CVE--2023--28708" src="https://img.shields.io/badge/CVE--2023--28708-lightgrey?label=medium%204.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.72</code></td></tr>
<tr><td>Fixed version</td><td><code>10.1.6, 11.0.0, 8.5.86, 9.0.72</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.148%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When using the RemoteIpFilter with requests received from a reverse proxy via HTTP that include the X-Forwarded-Proto header set to https, session cookies created by Apache Tomcat 11.0.0-M1 to 11.0.0.-M2, 10.1.0-M1 to 10.1.5, 9.0.0-M1 to 9.0.71 and 8.5.0 to 8.5.85 does not include the secure attribute. This could result in the user agent transmitting the session cookie over an insecure channel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-13943?s=gitlab&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.37"><img alt="medium 4.3: CVE--2020--13943" src="https://img.shields.io/badge/CVE--2020--13943-lightgrey?label=medium%204.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.37</code></td></tr>
<tr><td>Fixed version</td><td><code>10.0.0-M7, 10.0.0-M7, 10.0.0-M7, 8.5.57</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>9.572%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>92nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

If an HTTP/2 client connecting to Apache Tomcat 10.0.0-M1 to 10.0.0-M7, 9.0.0.M1 to 9.0.37 or 8.5.0 to 8.5.57 exceeded the agreed maximum number of concurrent streams for a connection (in violation of the HTTP/2 protocol), it was possible that a subsequent request made on that connection could contain HTTP headers - including HTTP/2 pseudo headers - from a previous request rather than the intended headers. This could lead to users seeing responses for unexpected resources.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-43980?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C9.0.62"><img alt="low 3.7: CVE--2021--43980" src="https://img.shields.io/badge/CVE--2021--43980-lightgrey?label=low%203.7&labelColor=fce1a9"/></a> <i>Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><9.0.62</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.62</code></td></tr>
<tr><td>CVSS Score</td><td><code>3.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.162%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The simplified implementation of blocking reads and writes introduced in Tomcat 10 and back-ported to Tomcat 9.0.47 onwards exposed a long standing (but extremely hard to trigger) concurrency bug in Apache Tomcat 10.1.0 to 10.1.0-M12, 10.0.0-M1 to 10.0.18, 9.0.0-M1 to 9.0.60 and 8.5.0 to 8.5.77 that could cause client connections to share an Http11Processor instance resulting in responses, or part responses, to be received by the wrong client.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-46701?s=github&n=tomcat-embed-core&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0.M1%2C%3C9.0.105"><img alt="low 1.7: CVE--2025--46701" src="https://img.shields.io/badge/CVE--2025--46701-lightgrey?label=low%201.7&labelColor=fce1a9"/></a> <i>Improper Handling of Case Sensitivity</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0.M1<br/><9.0.105</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.105</code></td></tr>
<tr><td>CVSS Score</td><td><code>1.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U/U:Clear</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper Handling of Case Sensitivity vulnerability in Apache Tomcat's GCI servlet allows security constraint bypass of security constraints that apply to the pathInfo component of a URI mapped to the CGI servlet.

This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.6, from 10.1.0-M1 through 10.1.40, from 9.0.0.M1 through 9.0.104.

Users are recommended to upgrade to version 11.0.7, 10.1.41 or 9.0.105, which fixes the issue.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 4" src="https://img.shields.io/badge/H-4-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework/spring-web</strong> <code>5.1.5.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework/spring-web@5.1.5.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2016-1000027?s=github&n=spring-web&ns=org.springframework&t=maven&vr=%3C6.0.0"><img alt="critical 9.8: CVE--2016--1000027" src="https://img.shields.io/badge/CVE--2016--1000027-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code><6.0.0</code></td></tr>
<tr><td>Fixed version</td><td><code>6.0.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>59.745%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Pivotal Spring Framework before 6.0.0 suffers from a potential remote code execution (RCE) issue if used for Java deserialization of untrusted data. Depending on how the library is implemented within a product, this issue may or not occur, and authentication may be required.

Maintainers recommend investigating alternative components or a potential mitigating control. Version 4.2.6 and 3.2.17 contain [enhanced documentation](https://github.com/spring-projects/spring-framework/commit/5cbe90b2cd91b866a5a9586e460f311860e11cfa) advising users to take precautions against unsafe Java deserialization, version 5.3.0 [deprecate the impacted classes](https://github.com/spring-projects/spring-framework/issues/25379) and version 6.0.0 [removed it entirely](https://github.com/spring-projects/spring-framework/issues/27422).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-5421?s=gitlab&n=spring-web&ns=org.springframework&t=maven&vr=%3E%3D5.1.0%2C%3C%3D5.1.17"><img alt="high 8.8: CVE--2020--5421" src="https://img.shields.io/badge/CVE--2020--5421-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=5.1.0<br/><=5.1.17</code></td></tr>
<tr><td>Fixed version</td><td><code>4.3.29.RELEASE, 5.0.19.RELEASE, 5.1.18.RELEASE, 5.2.9.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>68.606%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework the protections against RFD attacks from CVE-2015-5211 may be bypassed depending on the browser used through the use of a jsessionid path parameter.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-22262?s=github&n=spring-web&ns=org.springframework&t=maven&vr=%3C5.3.34"><img alt="high 8.1: CVE--2024--22262" src="https://img.shields.io/badge/CVE--2024--22262-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>URL Redirection to Untrusted Site ('Open Redirect')</i>

<table>
<tr><td>Affected range</td><td><code><5.3.34</code></td></tr>
<tr><td>Fixed version</td><td><code>5.3.34</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>4.703%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Applications that use UriComponentsBuilder to parse an externally provided URL (e.g. through a query parameter) AND perform validation checks on the host of the parsed URL may be vulnerable to a  open redirect https://cwe.mitre.org/data/definitions/601.html  attack or to a SSRF attack if the URL is used after passing validation checks.

This is the same as  CVE-2024-22259 https://spring.io/security/cve-2024-22259  and  CVE-2024-22243 https://spring.io/security/cve-2024-22243 , but with different input.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-22259?s=github&n=spring-web&ns=org.springframework&t=maven&vr=%3C5.3.33"><img alt="high 8.1: CVE--2024--22259" src="https://img.shields.io/badge/CVE--2024--22259-lightgrey?label=high%208.1&labelColor=e25d68"/></a> <i>URL Redirection to Untrusted Site ('Open Redirect')</i>

<table>
<tr><td>Affected range</td><td><code><5.3.33</code></td></tr>
<tr><td>Fixed version</td><td><code>5.3.33</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>24.873%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>96th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Applications that use UriComponentsBuilder in Spring Framework to parse an externally provided URL (e.g. through a query parameter) AND perform validation checks on the host of the parsed URL may be vulnerable to a  open redirect https://cwe.mitre.org/data/definitions/601.html  attack or to a SSRF attack if the URL is used after passing validation checks.

This is the same as  CVE-2024-22243 https://spring.io/security/cve-2024-22243, but with different input.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-5398?s=gitlab&n=spring-web&ns=org.springframework&t=maven&vr=%3E%3D5.1.0%2C%3C%3D5.1.13"><img alt="high 7.5: CVE--2020--5398" src="https://img.shields.io/badge/CVE--2020--5398-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=5.1.0<br/><=5.1.13</code></td></tr>
<tr><td>Fixed version</td><td><code>5.0.16.RELEASE, 5.1.14.RELEASE, 5.2.3.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>90.647%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework, an application is vulnerable to a reflected file download (RFD) attack when it sets a `Content-Disposition` header in the response where the filename attribute is derived from user supplied input.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38809?s=github&n=spring-web&ns=org.springframework&t=maven&vr=%3C5.3.38"><img alt="medium 5.3: CVE--2024--38809" src="https://img.shields.io/badge/CVE--2024--38809-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Inefficient Regular Expression Complexity</i>

<table>
<tr><td>Affected range</td><td><code><5.3.38</code></td></tr>
<tr><td>Fixed version</td><td><code>5.3.38</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.172%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Description
Applications that parse ETags from `If-Match` or `If-None-Match` request headers are vulnerable to DoS attack.

### Affected Spring Products and Versions
org.springframework:spring-web in versions 

6.1.0 through 6.1.11
6.0.0 through 6.0.22
5.3.0 through 5.3.37

Older, unsupported versions are also affected

### Mitigation
Users of affected versions should upgrade to the corresponding fixed version.
6.1.x -> 6.1.12
6.0.x -> 6.0.23
5.3.x -> 5.3.38
No other mitigation steps are necessary.

Users of older, unsupported versions could enforce a size limit on `If-Match` and `If-None-Match` headers, e.g. through a Filter.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework/spring-webmvc</strong> <code>5.1.5.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework/spring-webmvc@5.1.5.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-22965?s=github&n=spring-webmvc&ns=org.springframework&t=maven&vr=%3C5.2.20.RELEASE"><img alt="critical 9.8: CVE--2022--22965" src="https://img.shields.io/badge/CVE--2022--22965-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')</i>

<table>
<tr><td>Affected range</td><td><code><5.2.20.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.20.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>94.460%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Spring Framework prior to versions 5.2.20 and 5.3.18 contains a remote code execution vulnerability known as `Spring4Shell`. 

## Impact

A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

These are the prerequisites for the exploit:
- JDK 9 or higher
- Apache Tomcat as the Servlet container
- Packaged as WAR
- `spring-webmvc` or `spring-webflux` dependency

## Patches

- Spring Framework [5.3.18](https://github.com/spring-projects/spring-framework/releases/tag/v5.3.18) and [5.2.20](https://github.com/spring-projects/spring-framework/releases/tag/v5.2.20.RELEASE)
- Spring Boot [2.6.6](https://github.com/spring-projects/spring-boot/releases/tag/v2.6.6) and [2.5.12](https://github.com/spring-projects/spring-boot/releases/tag/v2.5.12)

## Workarounds

For those who are unable to upgrade, leaked reports recommend setting `disallowedFields` on `WebDataBinder` through an `@ControllerAdvice`. This works generally, but as a centrally applied workaround fix, may leave some loopholes, in particular if a controller sets `disallowedFields` locally through its own `@InitBinder` method, which overrides the global setting.

To apply the workaround in a more fail-safe way, applications could extend `RequestMappingHandlerAdapter` to update the `WebDataBinder` at the end after all other initialization. In order to do that, a Spring Boot application can declare a `WebMvcRegistrations` bean (Spring MVC) or a `WebFluxRegistrations` bean (Spring WebFlux).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-5421?s=gitlab&n=spring-webmvc&ns=org.springframework&t=maven&vr=%3E%3D5.1.0%2C%3C%3D5.1.17"><img alt="high 8.8: CVE--2020--5421" src="https://img.shields.io/badge/CVE--2020--5421-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=5.1.0<br/><=5.1.17</code></td></tr>
<tr><td>Fixed version</td><td><code>4.3.29.RELEASE, 5.0.19.RELEASE, 5.1.18.RELEASE, 5.2.9.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>68.606%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework the protections against RFD attacks from CVE-2015-5211 may be bypassed depending on the browser used through the use of a jsessionid path parameter.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-5398?s=github&n=spring-webmvc&ns=org.springframework&t=maven&vr=%3E%3D5.1.0.RELEASE%2C%3C5.1.13.RELEASE"><img alt="high 7.5: CVE--2020--5398" src="https://img.shields.io/badge/CVE--2020--5398-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Download of Code Without Integrity Check</i>

<table>
<tr><td>Affected range</td><td><code>>=5.1.0.RELEASE<br/><5.1.13.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.1.13.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>90.647%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework, versions 5.2.x prior to 5.2.3, versions 5.1.x prior to 5.1.13, and versions 5.0.x prior to 5.0.16, an application is vulnerable to a reflected file download (RFD) attack when it sets a "Content-Disposition" header in the response where the filename attribute is derived from user supplied input.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 6" src="https://img.shields.io/badge/M-6-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework/spring-core</strong> <code>5.1.5.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework/spring-core@5.1.5.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-22965?s=gitlab&n=spring-core&ns=org.springframework&t=maven&vr=%3C5.2.20"><img alt="critical 10.0: CVE--2022--22965" src="https://img.shields.io/badge/CVE--2022--22965-lightgrey?label=critical%2010.0&labelColor=8b1924"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><5.2.20</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.20, 5.3.18</code></td></tr>
<tr><td>CVSS Score</td><td><code>10</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>94.460%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection') in org.springframework:spring-core.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-5421?s=gitlab&n=spring-core&ns=org.springframework&t=maven&vr=%3E%3D5.1.0%2C%3C%3D5.1.17"><img alt="high 8.8: CVE--2020--5421" src="https://img.shields.io/badge/CVE--2020--5421-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=5.1.0<br/><=5.1.17</code></td></tr>
<tr><td>Fixed version</td><td><code>4.3.29.RELEASE, 5.0.19.RELEASE, 5.1.18.RELEASE, 5.2.9.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>68.606%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework the protections against RFD attacks from CVE-2015-5211 may be bypassed depending on the browser used through the use of a jsessionid path parameter.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-20863?s=gitlab&n=spring-core&ns=org.springframework&t=maven&vr=%3C5.2.24.RELEASE"><img alt="medium 6.5: CVE--2023--20863" src="https://img.shields.io/badge/CVE--2023--20863-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><5.2.24.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.3.27, 6.0.8, 5.2.24.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.756%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>72nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In spring framework versions prior to 5.2.24 release+,5.3.27+ and 6.0.8+, it is possible for a user to provide a specially crafted SpEL expression that may cause a denial-of-service (DoS) condition.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-20861?s=gitlab&n=spring-core&ns=org.springframework&t=maven&vr=%3C5.2.23.RELEASE"><img alt="medium 6.5: CVE--2023--20861" src="https://img.shields.io/badge/CVE--2023--20861-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><5.2.23.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.3.26, 6.0.7, 5.2.23.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.333%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>55th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework versions 6.0.0 - 6.0.6, 5.3.0 - 5.3.25, 5.2.0.RELEASE - 5.2.22.RELEASE, and older unsupported versions, it is possible for a user to provide a specially crafted SpEL expression that may cause a denial-of-service (DoS) condition.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-22971?s=gitlab&n=spring-core&ns=org.springframework&t=maven&vr=%3C%3D5.2.21.RELEASE"><img alt="medium 6.5: CVE--2022--22971" src="https://img.shields.io/badge/CVE--2022--22971-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><=5.2.21.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.22.RELEASE, 5.3.20</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.594%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>68th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In spring framework versions prior to 5.3.20+, 5.2.22+ and old unsupported versions, application with a STOMP over WebSocket endpoint is vulnerable to a denial of service attack by an authenticated user.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-22970?s=gitlab&n=spring-core&ns=org.springframework&t=maven&vr=%3C%3D5.2.21.RELEASE"><img alt="medium 5.3: CVE--2022--22970" src="https://img.shields.io/badge/CVE--2022--22970-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><=5.2.21.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.22.RELEASE, 5.3.20</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.288%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>52nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In spring framework versions prior to 5.3.20+, 5.2.22+ and old unsupported versions, applications that handle file uploads is vulnerable to DoS attack if they rely on data binding to set a MultipartFile or javax.servlet.Part to a field in a model object.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-22968?s=gitlab&n=spring-core&ns=org.springframework&t=maven&vr=%3C5.2.21"><img alt="medium 5.3: CVE--2022--22968" src="https://img.shields.io/badge/CVE--2022--22968-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><5.2.21</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.21, 5.3.19</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>22.751%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>96th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework versions 5.3.0 - 5.3.18, 5.2.0 - 5.2.20, and older unsupported versions, the patterns for disallowedFields on a DataBinder are case sensitive which means a field is not effectively protected unless it is listed with both upper and lower case for the first character of the field, including upper and lower case for the first character of all nested fields within the property path.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38827?s=gitlab&n=spring-core&ns=org.springframework&t=maven&vr=%3C6.1.14"><img alt="medium 4.8: CVE--2024--38827" src="https://img.shields.io/badge/CVE--2024--38827-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><6.1.14</code></td></tr>
<tr><td>Fixed version</td><td><code>6.1.14</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The usage of String.toLowerCase() and String.toUpperCase() has some Locale dependent exceptions that could potentially result in authorization rules not working properly.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework/spring-beans</strong> <code>5.1.5.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework/spring-beans@5.1.5.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-22965?s=github&n=spring-beans&ns=org.springframework&t=maven&vr=%3C5.2.20.RELEASE"><img alt="critical 9.8: CVE--2022--22965" src="https://img.shields.io/badge/CVE--2022--22965-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')</i>

<table>
<tr><td>Affected range</td><td><code><5.2.20.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.20.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>94.460%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Spring Framework prior to versions 5.2.20 and 5.3.18 contains a remote code execution vulnerability known as `Spring4Shell`. 

## Impact

A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

These are the prerequisites for the exploit:
- JDK 9 or higher
- Apache Tomcat as the Servlet container
- Packaged as WAR
- `spring-webmvc` or `spring-webflux` dependency

## Patches

- Spring Framework [5.3.18](https://github.com/spring-projects/spring-framework/releases/tag/v5.3.18) and [5.2.20](https://github.com/spring-projects/spring-framework/releases/tag/v5.2.20.RELEASE)
- Spring Boot [2.6.6](https://github.com/spring-projects/spring-boot/releases/tag/v2.6.6) and [2.5.12](https://github.com/spring-projects/spring-boot/releases/tag/v2.5.12)

## Workarounds

For those who are unable to upgrade, leaked reports recommend setting `disallowedFields` on `WebDataBinder` through an `@ControllerAdvice`. This works generally, but as a centrally applied workaround fix, may leave some loopholes, in particular if a controller sets `disallowedFields` locally through its own `@InitBinder` method, which overrides the global setting.

To apply the workaround in a more fail-safe way, applications could extend `RequestMappingHandlerAdapter` to update the `WebDataBinder` at the end after all other initialization. In order to do that, a Spring Boot application can declare a `WebMvcRegistrations` bean (Spring MVC) or a `WebFluxRegistrations` bean (Spring WebFlux).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-22970?s=github&n=spring-beans&ns=org.springframework&t=maven&vr=%3C%3D5.2.21.RELEASE"><img alt="high 7.5: CVE--2022--22970" src="https://img.shields.io/badge/CVE--2022--22970-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code><=5.2.21.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.22.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.288%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>52nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In spring framework versions prior to 5.3.20+ , 5.2.22+ and old unsupported versions, applications that handle file uploads are vulnerable to DoS attack if they rely on data binding to set a MultipartFile or javax.servlet.Part to a field in a model object.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38827?s=gitlab&n=spring-beans&ns=org.springframework&t=maven&vr=%3C6.1.14"><img alt="medium 4.8: CVE--2024--38827" src="https://img.shields.io/badge/CVE--2024--38827-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><6.1.14</code></td></tr>
<tr><td>Fixed version</td><td><code>6.1.14</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The usage of String.toLowerCase() and String.toUpperCase() has some Locale dependent exceptions that could potentially result in authorization rules not working properly.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.thymeleaf/thymeleaf-spring5</strong> <code>3.0.11.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.thymeleaf/thymeleaf-spring5@3.0.11.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-43466?s=github&n=thymeleaf-spring5&ns=org.thymeleaf&t=maven&vr=%3C%3D3.0.12.RELEASE"><img alt="critical 9.8: CVE--2021--43466" src="https://img.shields.io/badge/CVE--2021--43466-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Improper Control of Generation of Code ('Code Injection')</i>

<table>
<tr><td>Affected range</td><td><code><=3.0.12.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>3.0.13.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>4.468%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the thymeleaf-spring5:3.0.12 component, thymeleaf combined with specific scenarios in template injection may lead to remote code execution.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-38286?s=gitlab&n=thymeleaf-spring5&ns=org.thymeleaf&t=maven&vr=%3C%3D3.1.1"><img alt="high 7.5: CVE--2023--38286" src="https://img.shields.io/badge/CVE--2023--38286-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><=3.1.1</code></td></tr>
<tr><td>Fixed version</td><td><code>3.1.2.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.097%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Thymeleaf through 3.1.1.RELEASE, as used in spring-boot-admin (aka Spring Boot Admin) through 3.1.1 and other products, allows sandbox bypass via crafted HTML. This may be relevant for SSTI (Server Side Template Injection) and code execution in spring-boot-admin if MailNotifier is enabled and there is write access to environment variables via the UI.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework.boot/spring-boot-actuator-autoconfigure</strong> <code>2.1.3.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework.boot/spring-boot-actuator-autoconfigure@2.1.3.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-20873?s=github&n=spring-boot-actuator-autoconfigure&ns=org.springframework.boot&t=maven&vr=%3C2.5.15"><img alt="critical 9.8: CVE--2023--20873" src="https://img.shields.io/badge/CVE--2023--20873-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.5.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2.5.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.385%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>59th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Boot versions 3.0.0 - 3.0.5, 2.7.0 - 2.7.10, and older unsupported versions, an application that is deployed to Cloud Foundry could be susceptible to a security bypass. Users of affected versions should apply the following mitigation: 3.0.x users should upgrade to 3.0.6+. 2.7.x users should upgrade to 2.7.11+. Users of older, unsupported versions should upgrade to 3.0.6+ or 2.7.11+.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 1" src="https://img.shields.io/badge/C-1-8b1924"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework.boot/spring-boot-starter-web</strong> <code>2.1.3.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework.boot/spring-boot-starter-web@2.1.3.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-22965?s=github&n=spring-boot-starter-web&ns=org.springframework.boot&t=maven&vr=%3C2.5.12"><img alt="critical 9.8: CVE--2022--22965" src="https://img.shields.io/badge/CVE--2022--22965-lightgrey?label=critical%209.8&labelColor=8b1924"/></a> <i>Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')</i>

<table>
<tr><td>Affected range</td><td><code><2.5.12</code></td></tr>
<tr><td>Fixed version</td><td><code>2.5.12</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>94.460%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Spring Framework prior to versions 5.2.20 and 5.3.18 contains a remote code execution vulnerability known as `Spring4Shell`. 

## Impact

A Spring MVC or Spring WebFlux application running on JDK 9+ may be vulnerable to remote code execution (RCE) via data binding. The specific exploit requires the application to run on Tomcat as a WAR deployment. If the application is deployed as a Spring Boot executable jar, i.e. the default, it is not vulnerable to the exploit. However, the nature of the vulnerability is more general, and there may be other ways to exploit it.

These are the prerequisites for the exploit:
- JDK 9 or higher
- Apache Tomcat as the Servlet container
- Packaged as WAR
- `spring-webmvc` or `spring-webflux` dependency

## Patches

- Spring Framework [5.3.18](https://github.com/spring-projects/spring-framework/releases/tag/v5.3.18) and [5.2.20](https://github.com/spring-projects/spring-framework/releases/tag/v5.2.20.RELEASE)
- Spring Boot [2.6.6](https://github.com/spring-projects/spring-boot/releases/tag/v2.6.6) and [2.5.12](https://github.com/spring-projects/spring-boot/releases/tag/v2.5.12)

## Workarounds

For those who are unable to upgrade, leaked reports recommend setting `disallowedFields` on `WebDataBinder` through an `@ControllerAdvice`. This works generally, but as a centrally applied workaround fix, may leave some loopholes, in particular if a controller sets `disallowedFields` locally through its own `@InitBinder` method, which overrides the global setting.

To apply the workaround in a more fail-safe way, applications could extend `RequestMappingHandlerAdapter` to update the `WebDataBinder` at the end after all other initialization. In order to do that, a Spring Boot application can declare a `WebMvcRegistrations` bean (Spring MVC) or a `WebFluxRegistrations` bean (Spring WebFlux).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 5" src="https://img.shields.io/badge/H-5-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.google.protobuf/protobuf-java</strong> <code>3.7.0</code> (maven)</summary>

<small><code>pkg:maven/com.google.protobuf/protobuf-java@3.7.0</code></small><br/>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 4" src="https://img.shields.io/badge/H-4-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.commons/commons-compress</strong> <code>1.4.1</code> (maven)</summary>

<small><code>pkg:maven/org.apache.commons/commons-compress@1.4.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-36090?s=github&n=commons-compress&ns=org.apache.commons&t=maven&vr=%3C1.21"><img alt="high 7.5: CVE--2021--36090" src="https://img.shields.io/badge/CVE--2021--36090-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Handling of Length Parameter Inconsistency</i>

<table>
<tr><td>Affected range</td><td><code><1.21</code></td></tr>
<tr><td>Fixed version</td><td><code>1.21</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.287%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>52nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When reading a specially crafted ZIP archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' zip package.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-35517?s=github&n=commons-compress&ns=org.apache.commons&t=maven&vr=%3C1.21"><img alt="high 7.5: CVE--2021--35517" src="https://img.shields.io/badge/CVE--2021--35517-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Handling of Length Parameter Inconsistency</i>

<table>
<tr><td>Affected range</td><td><code><1.21</code></td></tr>
<tr><td>Fixed version</td><td><code>1.21</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.323%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>55th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When reading a specially crafted TAR archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' tar package.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-35516?s=github&n=commons-compress&ns=org.apache.commons&t=maven&vr=%3C1.21"><img alt="high 7.5: CVE--2021--35516" src="https://img.shields.io/badge/CVE--2021--35516-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Handling of Length Parameter Inconsistency</i>

<table>
<tr><td>Affected range</td><td><code><1.21</code></td></tr>
<tr><td>Fixed version</td><td><code>1.21</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.320%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>54th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When reading a specially crafted 7Z archive, Compress can be made to allocate large amounts of memory that finally leads to an out of memory error even for very small inputs. This could be used to mount a denial of service attack against services that use Compress' sevenz package.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-35515?s=github&n=commons-compress&ns=org.apache.commons&t=maven&vr=%3C1.21"><img alt="high 7.5: CVE--2021--35515" src="https://img.shields.io/badge/CVE--2021--35515-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Excessive Iteration</i>

<table>
<tr><td>Affected range</td><td><code><1.21</code></td></tr>
<tr><td>Fixed version</td><td><code>1.21</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.123%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When reading a specially crafted 7Z archive, the construction of the list of codecs that decompress an entry can result in an infinite loop. This could be used to mount a denial of service attack against services that use Compress' sevenz package.

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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 3" src="https://img.shields.io/badge/H-3-e25d68"/> <img alt="medium: 5" src="https://img.shields.io/badge/M-5-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.yaml/snakeyaml</strong> <code>1.23</code> (maven)</summary>

<small><code>pkg:maven/org.yaml/snakeyaml@1.23</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-1471?s=github&n=snakeyaml&ns=org.yaml&t=maven&vr=%3C%3D1.33"><img alt="high 8.3: CVE--2022--1471" src="https://img.shields.io/badge/CVE--2022--1471-lightgrey?label=high%208.3&labelColor=e25d68"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><=1.33</code></td></tr>
<tr><td>Fixed version</td><td><code>2.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>93.796%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
SnakeYaml's `Constructor` class, which inherits from `SafeConstructor`, allows
any type be deserialized given the following line:

new Yaml(new Constructor(TestDataClass.class)).load(yamlContent);

Types do not have to match the types of properties in the
target class. A `ConstructorException` is thrown, but only after a malicious
payload is deserialized.

### Severity
High, lack of type checks during deserialization allows remote code execution.

### Proof of Concept
Execute `bash run.sh`. The PoC uses Constructor to deserialize a payload
for RCE. RCE is demonstrated by using a payload which performs a http request to
http://127.0.0.1:8000.

Example output of successful run of proof of concept:

```
$ bash run.sh

[+] Downloading snakeyaml if needed
[+] Starting mock HTTP server on 127.0.0.1:8000 to demonstrate RCE
nc: no process found
[+] Compiling and running Proof of Concept, which a payload that sends a HTTP request to mock web server.
[+] An exception is expected.
Exception:
Cannot create property=payload for JavaBean=Main$TestDataClass@3cbbc1e0
 in 'string', line 1, column 1:
    payload: !!javax.script.ScriptEn ... 
    ^
Can not set java.lang.String field Main$TestDataClass.payload to javax.script.ScriptEngineManager
 in 'string', line 1, column 10:
    payload: !!javax.script.ScriptEngineManag ... 
             ^

	at org.yaml.snakeyaml.constructor.Constructor$ConstructMapping.constructJavaBean2ndStep(Constructor.java:291)
	at org.yaml.snakeyaml.constructor.Constructor$ConstructMapping.construct(Constructor.java:172)
	at org.yaml.snakeyaml.constructor.Constructor$ConstructYamlObject.construct(Constructor.java:332)
	at org.yaml.snakeyaml.constructor.BaseConstructor.constructObjectNoCheck(BaseConstructor.java:230)
	at org.yaml.snakeyaml.constructor.BaseConstructor.constructObject(BaseConstructor.java:220)
	at org.yaml.snakeyaml.constructor.BaseConstructor.constructDocument(BaseConstructor.java:174)
	at org.yaml.snakeyaml.constructor.BaseConstructor.getSingleData(BaseConstructor.java:158)
	at org.yaml.snakeyaml.Yaml.loadFromReader(Yaml.java:491)
	at org.yaml.snakeyaml.Yaml.load(Yaml.java:416)
	at Main.main(Main.java:37)
Caused by: java.lang.IllegalArgumentException: Can not set java.lang.String field Main$TestDataClass.payload to javax.script.ScriptEngineManager
	at java.base/jdk.internal.reflect.UnsafeFieldAccessorImpl.throwSetIllegalArgumentException(UnsafeFieldAccessorImpl.java:167)
	at java.base/jdk.internal.reflect.UnsafeFieldAccessorImpl.throwSetIllegalArgumentException(UnsafeFieldAccessorImpl.java:171)
	at java.base/jdk.internal.reflect.UnsafeObjectFieldAccessorImpl.set(UnsafeObjectFieldAccessorImpl.java:81)
	at java.base/java.lang.reflect.Field.set(Field.java:780)
	at org.yaml.snakeyaml.introspector.FieldProperty.set(FieldProperty.java:44)
	at org.yaml.snakeyaml.constructor.Constructor$ConstructMapping.constructJavaBean2ndStep(Constructor.java:286)
	... 9 more
[+] Dumping Received HTTP Request. Will not be empty if PoC worked
GET /proof-of-concept HTTP/1.1
User-Agent: Java/11.0.14
Host: localhost:8000
Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2
Connection: keep-alive
```

### Further Analysis
Potential mitigations include, leveraging SnakeYaml's SafeConstructor while parsing untrusted content.

See https://bitbucket.org/snakeyaml/snakeyaml/issues/561/cve-2022-1471-vulnerability-in#comment-64581479 for discussion on the subject.

### Timeline
**Date reported**: 4/11/2022
**Date fixed**:  [30/12/2022](https://bitbucket.org/snakeyaml/snakeyaml/pull-requests/44)
**Date disclosed**: 10/13/2022

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-25857?s=github&n=snakeyaml&ns=org.yaml&t=maven&vr=%3C1.31"><img alt="high 7.5: CVE--2022--25857" src="https://img.shields.io/badge/CVE--2022--25857-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><1.31</code></td></tr>
<tr><td>Fixed version</td><td><code>1.31</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.280%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>51st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The package org.yaml:snakeyaml from 0 and before 1.31 are vulnerable to Denial of Service (DoS) due missing to nested depth limitation for collections.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-18640?s=github&n=snakeyaml&ns=org.yaml&t=maven&vr=%3C1.26"><img alt="high 7.5: CVE--2017--18640" src="https://img.shields.io/badge/CVE--2017--18640-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Restriction of Recursive Entity References in DTDs ('XML Entity Expansion')</i>

<table>
<tr><td>Affected range</td><td><code><1.26</code></td></tr>
<tr><td>Fixed version</td><td><code>1.26</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.166%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>84th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Alias feature in SnakeYAML 1.18 allows entity expansion during a load operation, a related issue to CVE-2003-1564.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-41854?s=github&n=snakeyaml&ns=org.yaml&t=maven&vr=%3C1.32"><img alt="medium 6.5: CVE--2022--41854" src="https://img.shields.io/badge/CVE--2022--41854-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Stack-based Buffer Overflow</i>

<table>
<tr><td>Affected range</td><td><code><1.32</code></td></tr>
<tr><td>Fixed version</td><td><code>1.32</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Those using Snakeyaml to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stack overflow. This effect may support a denial of service attack.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-38752?s=github&n=snakeyaml&ns=org.yaml&t=maven&vr=%3C1.32"><img alt="medium 6.5: CVE--2022--38752" src="https://img.shields.io/badge/CVE--2022--38752-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Stack-based Buffer Overflow</i>

<table>
<tr><td>Affected range</td><td><code><1.32</code></td></tr>
<tr><td>Fixed version</td><td><code>1.32</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.167%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DoS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stack-overflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-38751?s=github&n=snakeyaml&ns=org.yaml&t=maven&vr=%3C1.31"><img alt="medium 6.5: CVE--2022--38751" src="https://img.shields.io/badge/CVE--2022--38751-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Stack-based Buffer Overflow</i>

<table>
<tr><td>Affected range</td><td><code><1.31</code></td></tr>
<tr><td>Fixed version</td><td><code>1.31</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.163%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-38749?s=github&n=snakeyaml&ns=org.yaml&t=maven&vr=%3C1.31"><img alt="medium 6.5: CVE--2022--38749" src="https://img.shields.io/badge/CVE--2022--38749-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Stack-based Buffer Overflow</i>

<table>
<tr><td>Affected range</td><td><code><1.31</code></td></tr>
<tr><td>Fixed version</td><td><code>1.31</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.543%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>67th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-38750?s=github&n=snakeyaml&ns=org.yaml&t=maven&vr=%3C1.31"><img alt="medium 5.5: CVE--2022--38750" src="https://img.shields.io/badge/CVE--2022--38750-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> <i>Stack-based Buffer Overflow</i>

<table>
<tr><td>Affected range</td><td><code><1.31</code></td></tr>
<tr><td>Fixed version</td><td><code>1.31</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.080%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Using snakeYAML to parse untrusted YAML files may be vulnerable to Denial of Service attacks (DOS). If the parser is running on user supplied input, an attacker may supply content that causes the parser to crash by stackoverflow.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 3" src="https://img.shields.io/badge/H-3-e25d68"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>io.netty/netty-all</strong> <code>4.1.33.Final</code> (maven)</summary>

<small><code>pkg:maven/io.netty/netty-all@4.1.33.Final</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-41881?s=gitlab&n=netty-all&ns=io.netty&t=maven&vr=%3C4.1.86"><img alt="high 7.5: CVE--2022--41881" src="https://img.shields.io/badge/CVE--2022--41881-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><4.1.86</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.86</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.077%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Netty project is an event-driven asynchronous network application framework. In versions prior to 4.1.86.Final, a StackOverflowError can be raised when parsing a malformed crafted message due to an infinite recursion. This issue is patched in version 4.1.86.Final. There is no workaround, except using a custom HaProxyMessageDecoder.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-37136?s=gitlab&n=netty-all&ns=io.netty&t=maven&vr=%3C4.1.68"><img alt="high 7.5: CVE--2021--37136" src="https://img.shields.io/badge/CVE--2021--37136-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><4.1.68</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.68</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.229%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>46th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Bzip2 decompression decoder function does not allow setting size restrictions on the decompressed output data (which affects the allocation size used during decompression). All users of Bzip2Decoder are affected. The malicious input can trigger an OOME and so a DoS attack

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-16869?s=github&n=netty-all&ns=io.netty&t=maven&vr=%3E%3D4.0.0.Alpha1%2C%3C4.1.42.Final"><img alt="high 7.5: CVE--2019--16869" src="https://img.shields.io/badge/CVE--2019--16869-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')</i>

<table>
<tr><td>Affected range</td><td><code>>=4.0.0.Alpha1<br/><4.1.42.Final</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.42.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.984%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Netty before 4.1.42.Final mishandles whitespace before the colon in HTTP headers (such as a "Transfer-Encoding : chunked" line), which leads to HTTP request smuggling.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-34462?s=gitlab&n=netty-all&ns=io.netty&t=maven&vr=%3C4.1.94"><img alt="medium 6.5: CVE--2023--34462" src="https://img.shields.io/badge/CVE--2023--34462-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><4.1.94</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.94.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.426%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>61st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Netty is an asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers & clients. The `SniHandler` can allocate up to 16MB of heap for each channel during the TLS handshake. When the handler or the channel does not have an idle timeout, it can be used to make a TCP server using the `SniHandler` to allocate 16MB of heap. The `SniHandler` class is a handler that waits for the TLS handshake to configure a `SslHandler` according to the indicated server name by the `ClientHello` record. For this matter it allocates a `ByteBuf` using the value defined in the `ClientHello` record. Normally the value of the packet should be smaller than the handshake packet but there are not checks done here and the way the code is written, it is possible to craft a packet that makes the `SslClientHelloHandler`. This vulnerability has been fixed in version 4.1.94.Final.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-21409?s=gitlab&n=netty-all&ns=io.netty&t=maven&vr=%3C4.1.61"><img alt="medium 5.9: CVE--2021--21409" src="https://img.shields.io/badge/CVE--2021--21409-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><4.1.61</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.61.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>5.113%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Netty is an open-source, asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers & clients. In Netty (io.netty:netty-codec-http2) before version 4.1.61.Final there is a vulnerability that enables request smuggling. The content-length header is not correctly validated if the request only uses a single Http2HeaderFrame with the endStream set to to true. This could lead to request smuggling if the request is proxied to a remote peer and translated to HTTP/1.1. This is a followup of GHSA-wm47-8v5p-wjpj/CVE-2021-21295 which did miss to fix this one case. This was fixed as part of 4.1.61.Final.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-21295?s=gitlab&n=netty-all&ns=io.netty&t=maven&vr=%3C4.1.61"><img alt="medium 5.9: CVE--2021--21295" src="https://img.shields.io/badge/CVE--2021--21295-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><4.1.61</code></td></tr>
<tr><td>Fixed version</td><td><code>4.1.61.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.300%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>79th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Netty is an open-source, asynchronous event-driven network application framework for rapid development of maintainable high performance protocol servers & clients. In Netty (io.netty:netty-codec-http2) before version 4.1.61.Final there is a vulnerability that enables request smuggling. The content-length header is not correctly validated if the request only uses a single Http2HeaderFrame with the endStream set to to true. This could lead to request smuggling if the request is proxied to a remote peer and translated to HTTP/1.1. This is a followup of GHSA-wm47-8v5p-wjpj/CVE-2021-21295 which did miss to fix this one case. This was fixed as part of 4.1.61.Final.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.apache.tomcat.embed/tomcat-embed-websocket</strong> <code>9.0.16</code> (maven)</summary>

<small><code>pkg:maven/org.apache.tomcat.embed/tomcat-embed-websocket@9.0.16</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-46589?s=gitlab&n=tomcat-embed-websocket&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C9.0.83"><img alt="high 7.5: CVE--2023--46589" src="https://img.shields.io/badge/CVE--2023--46589-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><9.0.83</code></td></tr>
<tr><td>Fixed version</td><td><code>8.5.96, 9.0.83, 10.1.16</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>45.383%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>97th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper Input Validation vulnerability in Apache Tomcat. Tomcat from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.1.15, from 9.0.0-M1 through 9.0.82, and from 8.5.0 through 8.5.95 did not correctly parse HTTP trailer headers. A trailer header that exceeded the header size limit could cause Tomcat to treat a single request as multiple requests leading to the possibility of request smuggling when behind a reverse proxy.

Users are recommended to upgrade to version 11.0.0-M11 onwards, 10.1.16 onwards, 9.0.83 onwards or 8.5.96 onwards, which fix the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-13935?s=gitlab&n=tomcat-embed-websocket&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C%3D9.0.36"><img alt="high 7.5: CVE--2020--13935" src="https://img.shields.io/badge/CVE--2020--13935-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><=9.0.36</code></td></tr>
<tr><td>Fixed version</td><td><code>7.0.105, 8.5.57, 9.0.37, 10.0.2</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>92.541%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>100th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to 7.0.104. Invalid payload lengths could trigger an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-23672?s=github&n=tomcat-embed-websocket&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0-M1%2C%3C%3D9.0.85"><img alt="medium 6.3: CVE--2024--23672" src="https://img.shields.io/badge/CVE--2024--23672-lightgrey?label=medium%206.3&labelColor=fbb552"/></a> <i>Incomplete Cleanup</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0-M1<br/><=9.0.85</code></td></tr>
<tr><td>Fixed version</td><td><code>9.0.86</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.437%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>62nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Denial of Service via incomplete cleanup vulnerability in Apache Tomcat. It was possible for WebSocket clients to keep WebSocket connections open leading to increased resource consumption.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M16, from 10.1.0-M1 through 10.1.18, from 9.0.0-M1 through 9.0.85, from 8.5.0 through 8.5.98.

Users are recommended to upgrade to version 11.0.0-M17, 10.1.19, 9.0.86 or 8.5.99 which fix the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-41080?s=gitlab&n=tomcat-embed-websocket&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C%3D9.0.79"><img alt="medium 6.1: CVE--2023--41080" src="https://img.shields.io/badge/CVE--2023--41080-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><=9.0.79</code></td></tr>
<tr><td>Fixed version</td><td><code>8.5.93, 9.0.80, 10.1.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>11.116%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

URL Redirection to Untrusted Site ('Open Redirect') vulnerability in FORM authentication feature Apache Tomcat.This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M10, from 10.1.0-M1 through 10.0.12, from 9.0.0-M1 through 9.0.79 and from 8.5.0 through 8.5.92.

The vulnerability is limited to the ROOT (default) web application.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-24122?s=gitlab&n=tomcat-embed-websocket&ns=org.apache.tomcat.embed&t=maven&vr=%3E%3D9.0.0%2C%3C%3D9.0.39"><img alt="medium 5.9: CVE--2021--24122" src="https://img.shields.io/badge/CVE--2021--24122-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code>>=9.0.0<br/><=9.0.39</code></td></tr>
<tr><td>Fixed version</td><td><code>10.0.0-M10, 9.0.40, 8.5.60, 7.0.107</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>59.872%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>98th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When serving resources from a network location using the NTFS file system, Apache Tomcat is susceptible to JSP source code disclosure in some configurations. The root cause is the unexpected behaviour of the JRE API `File.getCanonicalPath()` which in turn is caused by the inconsistent behaviour of the Windows API (`FindFirstFileW`) in some circumstances.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework/spring-expression</strong> <code>5.1.5.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework/spring-expression@5.1.5.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-20863?s=github&n=spring-expression&ns=org.springframework&t=maven&vr=%3C5.2.24.RELEASE"><img alt="high 7.5: CVE--2023--20863" src="https://img.shields.io/badge/CVE--2023--20863-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><5.2.24.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.24.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.756%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>72nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework versions prior to 5.2.24.release+ , 5.3.27+ and 6.0.8+ , it is possible for a user to provide a specially crafted Spring Expression Language (SpEL) expression that may cause a denial-of-service (DoS) condition.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-20861?s=github&n=spring-expression&ns=org.springframework&t=maven&vr=%3C5.2.23.RELEASE"><img alt="medium 6.5: CVE--2023--20861" src="https://img.shields.io/badge/CVE--2023--20861-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><5.2.23.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.23.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.333%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>55th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework versions 6.0.0 - 6.0.6, 5.3.0 - 5.3.25, 5.2.0.RELEASE - 5.2.22.RELEASE, and older unsupported versions, it is possible for a user to provide a specially crafted SpEL expression that may cause a denial-of-service (DoS) condition.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-22950?s=github&n=spring-expression&ns=org.springframework&t=maven&vr=%3C5.2.20.RELEASE"><img alt="medium 6.5: CVE--2022--22950" src="https://img.shields.io/badge/CVE--2022--22950-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code><5.2.20.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.20.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>4.547%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>89th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework versions 5.3.0 - 5.3.16, 5.2.0.RELEASE - 5.2.19.RELEASE, and older unsupported versions, it is possible for a user to provide a specially crafted SpEL expression that may cause a denial of service condition.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38808?s=github&n=spring-expression&ns=org.springframework&t=maven&vr=%3C5.3.39"><img alt="medium 5.1: CVE--2024--38808" src="https://img.shields.io/badge/CVE--2024--38808-lightgrey?label=medium%205.1&labelColor=fbb552"/></a> <i>Allocation of Resources Without Limits or Throttling</i>

<table>
<tr><td>Affected range</td><td><code><5.3.39</code></td></tr>
<tr><td>Fixed version</td><td><code>5.3.39</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.310%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>54th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework versions 5.3.0 - 5.3.38 and older unsupported versions, it is possible for a user to provide a specially crafted Spring Expression Language (SpEL) expression that may cause a denial of service (DoS) condition. Older, unsupported versions are also affected.

Specifically, an application is vulnerable when the following is true:

  *  The application evaluates user-supplied SpEL expressions.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38827?s=gitlab&n=spring-expression&ns=org.springframework&t=maven&vr=%3C6.1.14"><img alt="medium 4.8: CVE--2024--38827" src="https://img.shields.io/badge/CVE--2024--38827-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><6.1.14</code></td></tr>
<tr><td>Fixed version</td><td><code>6.1.14</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The usage of String.toLowerCase() and String.toUpperCase() has some Locale dependent exceptions that could potentially result in authorization rules not working properly.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>ch.qos.logback/logback-core</strong> <code>1.2.3</code> (maven)</summary>

<small><code>pkg:maven/ch.qos.logback/logback-core@1.2.3</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-6378?s=github&n=logback-core&ns=ch.qos.logback&t=maven&vr=%3C1.2.13"><img alt="high 7.1: CVE--2023--6378" src="https://img.shields.io/badge/CVE--2023--6378-lightgrey?label=high%207.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code><1.2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>1.2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.652%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>70th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A serialization vulnerability in logback receiver component part of logback allows an attacker to mount a Denial-Of-Service attack by sending poisoned data.

This is only exploitable if logback receiver component is deployed. See https://logback.qos.ch/manual/receivers.html

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-42550?s=github&n=logback-core&ns=ch.qos.logback&t=maven&vr=%3C1.2.9"><img alt="medium 6.6: CVE--2021--42550" src="https://img.shields.io/badge/CVE--2021--42550-lightgrey?label=medium%206.6&labelColor=fbb552"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code><1.2.9</code></td></tr>
<tr><td>Fixed version</td><td><code>1.2.9</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.989%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In logback version 1.2.7 and prior versions, an attacker with the required privileges to edit configurations files could craft a malicious configuration allowing to execute arbitrary code loaded from LDAP servers.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-12798?s=github&n=logback-core&ns=ch.qos.logback&t=maven&vr=%3C1.3.15"><img alt="medium 5.9: CVE--2024--12798" src="https://img.shields.io/badge/CVE--2024--12798-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Improper Neutralization of Special Elements used in an Expression Language Statement ('Expression Language Injection')</i>

<table>
<tr><td>Affected range</td><td><code><1.3.15</code></td></tr>
<tr><td>Fixed version</td><td><code>1.3.15</code></td></tr>
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

<a href="https://scout.docker.com/v/CVE-2024-12801?s=github&n=logback-core&ns=ch.qos.logback&t=maven&vr=%3C1.3.15"><img alt="low 2.4: CVE--2024--12801" src="https://img.shields.io/badge/CVE--2024--12801-lightgrey?label=low%202.4&labelColor=fce1a9"/></a> <i>Server-Side Request Forgery (SSRF)</i>

<table>
<tr><td>Affected range</td><td><code><1.3.15</code></td></tr>
<tr><td>Fixed version</td><td><code>1.3.15</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework.boot/spring-boot</strong> <code>2.1.3.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework.boot/spring-boot@2.1.3.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-27772?s=github&n=spring-boot&ns=org.springframework.boot&t=maven&vr=%3C%3D2.2.10.RELEASE"><img alt="high 7.8: CVE--2022--27772" src="https://img.shields.io/badge/CVE--2022--27772-lightgrey?label=high%207.8&labelColor=e25d68"/></a> <i>Insecure Temporary File</i>

<table>
<tr><td>Affected range</td><td><code><=2.2.10.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>2.2.11.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.058%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>77th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

spring-boot versions prior to version `v2.2.11.RELEASE` was vulnerable to temporary directory hijacking. This vulnerability impacted the `org.springframework.boot.web.server.AbstractConfigurableWebServerFactory.createTempDir` method.

The vulnerable method is used to create a work directory for embedded web servers such as Tomcat and Jetty. The directory contains configuration files, JSP/class files, etc. If a local attacker got the permission to write in this directory, they could completely take over the application (ie. local privilege escalation).

#### Impact Location

This vulnerability impacted the following source location:

```java
	/**
	 * Return the absolute temp dir for given web server.
	 * @param prefix server name
	 * @return the temp dir for given server.
	 */
	protected final File createTempDir(String prefix) {
		try {
			File tempDir = File.createTempFile(prefix + ".", "." + getPort());
			tempDir.delete();
			tempDir.mkdir();
			tempDir.deleteOnExit();
			return tempDir;
		}
```
\- https://github.com/spring-projects/spring-boot/blob/ce70e7d768977242a8ea6f93188388f273be5851/spring-boot-project/spring-boot/src/main/java/org/springframework/boot/web/server/AbstractConfigurableWebServerFactory.java#L165-L177

This vulnerability exists because `File.mkdir` returns `false` when it fails to create a directory, it does not throw an exception. As such, the following race condition exists:

```java
File tmpDir =File.createTempFile(prefix + ".", "." + getPort()); // Attacker knows the full path of the file that will be generated
// delete the file that was created
tmpDir.delete(); // Attacker sees file is deleted and begins a race to create their own directory before Jetty.
// and make a directory of the same name
// SECURITY VULNERABILITY: Race Condition! - Attacker beats java code and now owns this directory
tmpDir.mkdirs(); // This method returns 'false' because it was unable to create the directory. No exception is thrown.
// Attacker can write any new files to this directory that they wish.
// Attacker can read any files created by this process.
```

### Prerequisites

This vulnerability impacts Unix-like systems, and very old versions of Mac OSX and Windows as they all share the system temporary directory between all users.

### Patches

This vulnerability was inadvertently fixed as a part of this patch: https://github.com/spring-projects/spring-boot/commit/667ccdae84822072f9ea1a27ed5c77964c71002d

This vulnerability is patched in versions `v2.2.11.RELEASE` or later.

### Workarounds

Setting the `java.io.tmpdir` system environment variable to a directory that is exclusively owned by the executing user will fix this vulnerability for all operating systems.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-34055?s=gitlab&n=spring-boot&ns=org.springframework.boot&t=maven&vr=%3C2.7.18"><img alt="medium 5.3: CVE--2023--34055" src="https://img.shields.io/badge/CVE--2023--34055-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><2.7.18</code></td></tr>
<tr><td>Fixed version</td><td><code>2.7.18, 3.0.13, 3.1.6</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.282%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>51st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Boot versions 2.7.0 - 2.7.17, 3.0.0-3.0.12 and 3.1.0-3.1.5, it is possible for a user to provide specially crafted HTTP requests that may cause a denial-of-service (DoS) condition.

Specifically, an application is vulnerable when all of the following are true:

*  the application uses Spring MVC or Spring WebFlux
*  `org.springframework.boot:spring-boot-actuator` is on the classpath

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>commons-io/commons-io</strong> <code>2.4</code> (maven)</summary>

<small><code>pkg:maven/commons-io/commons-io@2.4</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-47554?s=github&n=commons-io&ns=commons-io&t=maven&vr=%3E%3D2.0%2C%3C2.14.0"><img alt="high 8.7: CVE--2024--47554" src="https://img.shields.io/badge/CVE--2024--47554-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0<br/><2.14.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.14.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Uncontrolled Resource Consumption vulnerability in Apache Commons IO.

The `org.apache.commons.io.input.XmlStreamReader` class may excessively consume CPU resources when processing maliciously crafted input.


This issue affects Apache Commons IO: from 2.0 before 2.14.0.

Users are recommended to upgrade to version 2.14.0 or later, which fixes the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-29425?s=github&n=commons-io&ns=commons-io&t=maven&vr=%3C2.7"><img alt="medium 4.8: CVE--2021--29425" src="https://img.shields.io/badge/CVE--2021--29425-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><2.7</code></td></tr>
<tr><td>Fixed version</td><td><code>2.7</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.357%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>57th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Apache Commons IO before 2.7, When invoking the method FileNameUtils.normalize with an improper input string, like "//../foo", or "\\..\foo", the result would be the same value, thus possibly providing access to files in the parent directory, but not further above (thus "limited" path traversal), if the calling code would use the result to construct a path value.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework/spring-context</strong> <code>5.1.5.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework/spring-context@5.1.5.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-22968?s=github&n=spring-context&ns=org.springframework&t=maven&vr=%3C5.2.21.RELEASE"><img alt="high 7.5: CVE--2022--22968" src="https://img.shields.io/badge/CVE--2022--22968-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Improper Handling of Case Sensitivity</i>

<table>
<tr><td>Affected range</td><td><code><5.2.21.RELEASE</code></td></tr>
<tr><td>Fixed version</td><td><code>5.2.21.RELEASE</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>22.751%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>96th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Framework versions 5.3.0 - 5.3.18, 5.2.0 - 5.2.20, and older unsupported versions, the patterns for disallowedFields on a DataBinder are case sensitive which means a field is not effectively protected unless it is listed with both upper and lower case for the first character of the field, including upper and lower case for the first character of all nested fields within the property path. Versions 5.3.19 and 5.2.21 contain a patch for this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38827?s=gitlab&n=spring-context&ns=org.springframework&t=maven&vr=%3C6.1.14"><img alt="medium 4.8: CVE--2024--38827" src="https://img.shields.io/badge/CVE--2024--38827-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><6.1.14</code></td></tr>
<tr><td>Fixed version</td><td><code>6.1.14</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The usage of String.toLowerCase() and String.toUpperCase() has some Locale dependent exceptions that could potentially result in authorization rules not working properly.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.google.code.gson/gson</strong> <code>2.8.5</code> (maven)</summary>

<small><code>pkg:maven/com.google.code.gson/gson@2.8.5</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-25647?s=github&n=gson&ns=com.google.code.gson&t=maven&vr=%3C2.8.9"><img alt="high 7.7: CVE--2022--25647" src="https://img.shields.io/badge/CVE--2022--25647-lightgrey?label=high%207.7&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code><2.8.9</code></td></tr>
<tr><td>Fixed version</td><td><code>2.8.9</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.149%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>83rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The package `com.google.code.gson:gson` before 2.8.9 is vulnerable to Deserialization of Untrusted Data via the `writeReplace()` method in internal classes, which may lead to denial of service attacks.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>ch.qos.logback/logback-classic</strong> <code>1.2.3</code> (maven)</summary>

<small><code>pkg:maven/ch.qos.logback/logback-classic@1.2.3</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-6378?s=github&n=logback-classic&ns=ch.qos.logback&t=maven&vr=%3C1.2.13"><img alt="high 7.1: CVE--2023--6378" src="https://img.shields.io/badge/CVE--2023--6378-lightgrey?label=high%207.1&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code><1.2.13</code></td></tr>
<tr><td>Fixed version</td><td><code>1.2.13</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.652%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>70th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A serialization vulnerability in logback receiver component part of logback allows an attacker to mount a Denial-Of-Service attack by sending poisoned data.

This is only exploitable if logback receiver component is deployed. See https://logback.qos.ch/manual/receivers.html

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework.boot/spring-boot-autoconfigure</strong> <code>2.1.3.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework.boot/spring-boot-autoconfigure@2.1.3.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-20883?s=github&n=spring-boot-autoconfigure&ns=org.springframework.boot&t=maven&vr=%3C2.5.15"><img alt="high 7.5: CVE--2023--20883" src="https://img.shields.io/badge/CVE--2023--20883-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Uncontrolled Resource Consumption</i>

<table>
<tr><td>Affected range</td><td><code><2.5.15</code></td></tr>
<tr><td>Fixed version</td><td><code>2.5.15</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.199%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Boot versions 3.0.0 - 3.0.6, 2.7.0 - 2.7.11, 2.6.0 - 2.6.14, 2.5.0 - 2.5.14 and older unsupported versions, there is potential for a denial-of-service (DoS) attack if Spring MVC is used together with a reverse proxy cache.

Specifically, an application is vulnerable if all of the conditions are true:

* The application has Spring MVC auto-configuration enabled. This is the case by default if Spring MVC is on the classpath.
* The application makes use of Spring Boot's welcome page support, either static or templated.
* Your application is deployed behind a proxy which caches 404 responses.

Your application is NOT vulnerable if any of the following are true:

* Spring MVC auto-configuration is disabled. This is true if WebMvcAutoConfiguration is explicitly excluded, if Spring MVC is not on the classpath, or if spring.main.web-application-type is set to a value other than SERVLET.
* The application does not use Spring Boot's welcome page support.
* You do not have a proxy which caches 404 responses.


Affected Spring Products and Versions

Spring Boot

3.0.0 to 3.0.6 2.7.0 to 2.7.11 2.6.0 to 2.6.14 2.5.0 to 2.5.14

Older, unsupported versions are also affected
Mitigation

Users of affected versions should apply the following mitigations:

* 3.0.x users should upgrade to 3.0.7+
* 2.7.x users should upgrade to 2.7.12+
* 2.6.x users should upgrade to 2.6.15+
* 2.5.x users should upgrade to 2.5.15+

Users of older, unsupported versions should upgrade to 3.0.7+ or 2.7.12+.

Workarounds: configure the reverse proxy not to cache 404 responses and/or not to cache responses to requests to the root (/) of the application.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.hibernate.validator/hibernate-validator</strong> <code>6.0.14.Final</code> (maven)</summary>

<small><code>pkg:maven/org.hibernate.validator/hibernate-validator@6.0.14.Final</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-35036?s=github&n=hibernate-validator&ns=org.hibernate.validator&t=maven&vr=%3C6.2.0.CR1"><img alt="medium 6.9: CVE--2025--35036" src="https://img.shields.io/badge/CVE--2025--35036-lightgrey?label=medium%206.9&labelColor=fbb552"/></a> <i>Improper Control of Generation of Code ('Code Injection')</i>

<table>
<tr><td>Affected range</td><td><code><6.2.0.CR1</code></td></tr>
<tr><td>Fixed version</td><td><code>6.2.0.CR1</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.079%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Hibernate Validator before 6.2.0 and 7.0.0, by default and depending how it is used, may interpolate user-supplied input in a constraint violation message with Expression Language. This could allow an attacker to access sensitive information or execute arbitrary Java code. Hibernate Validator as of 6.2.0 and 7.0.0 no longer interpolates custom constraint violation messages with Expression Language and strongly recommends not allowing user-supplied input in constraint violation messages. CVE-2020-5245 and CVE-2025-4428 are examples of related, downstream vulnerabilities involving Expression Language intepolation of user-supplied data.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-10219?s=gitlab&n=hibernate-validator&ns=org.hibernate.validator&t=maven&vr=%3C6.0.18"><img alt="medium 6.1: CVE--2019--10219" src="https://img.shields.io/badge/CVE--2019--10219-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><6.0.18</code></td></tr>
<tr><td>Fixed version</td><td><code>6.0.18, 6.1.0.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.337%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>79th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in Hibernate-Validator. The SafeHtml validator annotation fails to properly sanitize payloads consisting of potentially malicious code in HTML comments and instructions. This vulnerability can result in an XSS attack.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-1932?s=github&n=hibernate-validator&ns=org.hibernate.validator&t=maven&vr=%3C6.2.0.Final"><img alt="medium 5.3: CVE--2023--1932" src="https://img.shields.io/badge/CVE--2023--1932-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')</i>

<table>
<tr><td>Affected range</td><td><code><6.2.0.Final</code></td></tr>
<tr><td>Fixed version</td><td><code>6.2.0.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.038%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in hibernate-validator's 'isValid' method in the org.hibernate.validator.internal.constraintvalidators.hv.SafeHtmlValidator class, which can be bypassed by omitting the tag ending in a less-than character. Browsers may render an invalid html, allowing HTML injection or Cross-Site-Scripting (XSS) attacks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-10693?s=github&n=hibernate-validator&ns=org.hibernate.validator&t=maven&vr=%3C%3D6.0.19.Final"><img alt="medium 5.3: CVE--2020--10693" src="https://img.shields.io/badge/CVE--2020--10693-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> <i>Improper Input Validation</i>

<table>
<tr><td>Affected range</td><td><code><=6.0.19.Final</code></td></tr>
<tr><td>Fixed version</td><td><code>6.0.20.Final</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in Hibernate Validator version 6.1.2.Final. A bug in the message interpolation processor enables invalid EL expressions to be evaluated as if they were valid. This flaw allows attackers to bypass input sanitation (escaping, stripping) controls that developers may have put in place when handling user-controlled data in error messages.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>com.google.guava/guava</strong> <code>22.0</code> (maven)</summary>

<small><code>pkg:maven/com.google.guava/guava@22.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-10237?s=github&n=guava&ns=com.google.guava&t=maven&vr=%3E%3D11.0%2C%3C24.1.1-android"><img alt="medium 5.9: CVE--2018--10237" src="https://img.shields.io/badge/CVE--2018--10237-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=11.0<br/><24.1.1-android</code></td></tr>
<tr><td>Fixed version</td><td><code>24.1.1-android</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>3.259%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>87th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Unbounded memory allocation in Google Guava 11.0 through 24.x before 24.1.1 allows remote attackers to conduct denial of service attacks against servers that depend on this library and deserialize attacker-provided data, because the AtomicDoubleArray class (when serialized with Java serialization) and the CompoundOrdering class (when serialized with GWT serialization) perform eager allocation without appropriate checks on what a client has sent and whether the data size is reasonable.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-2976?s=github&n=guava&ns=com.google.guava&t=maven&vr=%3E%3D1.0%2C%3C32.0.0-android"><img alt="medium 5.5: CVE--2023--2976" src="https://img.shields.io/badge/CVE--2023--2976-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> <i>Creation of Temporary File in Directory with Insecure Permissions</i>

<table>
<tr><td>Affected range</td><td><code>>=1.0<br/><32.0.0-android</code></td></tr>
<tr><td>Fixed version</td><td><code>32.0.0-android</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Use of Java's default temporary directory for file creation in `FileBackedOutputStream` in Google Guava versions 1.0 to 31.1 on Unix systems and Android Ice Cream Sandwich allows other users and apps on the machine with access to the default Java temporary directory to be able to access the files created by the class.

Even though the security vulnerability is fixed in version 32.0.0, maintainers recommend using version 32.0.1 as version 32.0.0 breaks some functionality under Windows.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-8908?s=github&n=guava&ns=com.google.guava&t=maven&vr=%3C32.0.0-android"><img alt="low 3.3: CVE--2020--8908" src="https://img.shields.io/badge/CVE--2020--8908-lightgrey?label=low%203.3&labelColor=fce1a9"/></a> <i>Improper Handling of Alternate Encoding</i>

<table>
<tr><td>Affected range</td><td><code><32.0.0-android</code></td></tr>
<tr><td>Fixed version</td><td><code>32.0.0-android</code></td></tr>
<tr><td>CVSS Score</td><td><code>3.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A temp directory creation vulnerability exists in Guava prior to version 32.0.0 allowing an attacker with access to the machine to potentially access data in a temporary directory created by the Guava `com.google.common.io.Files.createTempDir()`. The permissions granted to the directory created default to the standard unix-like /tmp ones, leaving the files open. Maintainers recommend explicitly changing the permissions after the creation of the directory, or removing uses of the vulnerable method.


</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework/spring-jdbc</strong> <code>5.1.5.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework/spring-jdbc@5.1.5.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-38827?s=gitlab&n=spring-jdbc&ns=org.springframework&t=maven&vr=%3C6.1.14"><img alt="medium 4.8: CVE--2024--38827" src="https://img.shields.io/badge/CVE--2024--38827-lightgrey?label=medium%204.8&labelColor=fbb552"/></a> <i>OWASP Top Ten 2017 Category A9 - Using Components with Known Vulnerabilities</i>

<table>
<tr><td>Affected range</td><td><code><6.1.14</code></td></tr>
<tr><td>Fixed version</td><td><code>6.1.14</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The usage of String.toLowerCase() and String.toUpperCase() has some Locale dependent exceptions that could potentially result in authorization rules not working properly.

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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>commons-net/commons-net</strong> <code>3.3</code> (maven)</summary>

<small><code>pkg:maven/commons-net/commons-net@3.3</code></small><br/>
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

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>org.springframework.boot/spring-boot-actuator</strong> <code>2.1.3.RELEASE</code> (maven)</summary>

<small><code>pkg:maven/org.springframework.boot/spring-boot-actuator@2.1.3.RELEASE</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2023-34055?s=github&n=spring-boot-actuator&ns=org.springframework.boot&t=maven&vr=%3C2.7.18"><img alt="medium 5.3: CVE--2023--34055" src="https://img.shields.io/badge/CVE--2023--34055-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.7.18</code></td></tr>
<tr><td>Fixed version</td><td><code>2.7.18</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.282%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>51st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In Spring Boot versions 2.7.0 - 2.7.17, 3.0.0-3.0.12 and 3.1.0-3.1.5, it is possible for a user to provide specially crafted HTTP requests that may cause a denial-of-service (DoS) condition.

Specifically, an application is vulnerable when all of the following are true:

  *  the application uses Spring MVC or Spring WebFlux
  *  `org.springframework.boot:spring-boot-actuator` is on the classpath

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>com.fasterxml.jackson.core/jackson-core</strong> <code>2.9.8</code> (maven)</summary>

<small><code>pkg:maven/com.fasterxml.jackson.core/jackson-core@2.9.8</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-49128?s=github&n=jackson-core&ns=com.fasterxml.jackson.core&t=maven&vr=%3E%3D2.0.0%2C%3C2.13.0"><img alt="medium 4.0: CVE--2025--49128" src="https://img.shields.io/badge/CVE--2025--49128-lightgrey?label=medium%204.0&labelColor=fbb552"/></a> <i>Generation of Error Message Containing Sensitive Information</i>

<table>
<tr><td>Affected range</td><td><code>>=2.0.0<br/><2.13.0</code></td></tr>
<tr><td>Fixed version</td><td><code>2.13.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.005%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Overview

A flaw in Jackson-core's `JsonLocation._appendSourceDesc` method allows up to 500 bytes of unintended memory content to be included in exception messages. When parsing JSON from a byte array with an offset and length, the exception message incorrectly reads from the beginning of the array instead of the logical payload start. This results in possible **information disclosure** in systems using **pooled or reused buffers**, like Netty or Vert.x.

### Details

The vulnerability affects the creation of exception messages like:

```
JsonParseException: Unexpected character ... at [Source: (byte[])...]
```

When `JsonFactory.createParser(byte[] data, int offset, int len)` is used, and an error occurs while parsing, the exception message should include a snippet from the specified logical payload. However, the method `_appendSourceDesc` ignores the `offset`, and always starts reading from index `0`.

If the buffer contains residual sensitive data from a previous request, such as credentials or document contents, that data may be exposed if the exception is propagated to the client.

The issue particularly impacts server applications using:

* Pooled byte buffers (e.g., Netty)
* Frameworks that surface parse errors in HTTP responses
* Default Jackson settings (i.e., `INCLUDE_SOURCE_IN_LOCATION` is enabled)

A documented real-world example is [CVE-2021-22145](https://nvd.nist.gov/vuln/detail/CVE-2021-22145) in Elasticsearch, which stemmed from the same root cause.

### Attack Scenario

An attacker sends malformed JSON to a service using Jackson and pooled byte buffers (e.g., Netty-based HTTP servers). If the server reuses a buffer and includes the parser’s exception in its HTTP 400 response, the attacker may receive residual data from previous requests.

### Proof of Concept

```java
byte[] buffer = new byte[1000];
System.arraycopy("SECRET".getBytes(), 0, buffer, 0, 6);
System.arraycopy("{ \"bad\": }".getBytes(), 0, buffer, 700, 10);

JsonFactory factory = new JsonFactory();
JsonParser parser = factory.createParser(buffer, 700, 20);
parser.nextToken(); // throws exception

// Exception message will include "SECRET"
```

### Patches
This issue was silently fixed in jackson-core version 2.13.0, released on September 30, 2021, via [PR #652](https://github.com/FasterXML/jackson-core/pull/652).

All users should upgrade to version 2.13.0 or later.

### Workarounds
If upgrading is not immediately possible, applications can mitigate the issue by:

1. **Disabling exception message exposure to clients** — avoid returning parsing exception messages in HTTP responses.
2. **Disabling source inclusion in exceptions** by setting:

   ```java
   jsonFactory.disable(JsonFactory.Feature.INCLUDE_SOURCE_IN_LOCATION);
   ```

    This prevents Jackson from embedding any source content in exception messages, avoiding leakage.


### References
* [Pull Request #652 (Fix implementation)](https://github.com/FasterXML/jackson-core/pull/652)
* [CVE-2021-22145 (Elasticsearch exposure of this flaw)](https://nvd.nist.gov/vuln/detail/CVE-2021-22145)

</blockquote>
</details>
</details></td></tr>
</table>