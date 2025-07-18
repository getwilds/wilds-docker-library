# Vulnerability Report for getwilds/hmmcopy:latest

Report generated on 2025-07-15 23:26:15 PST

<h2>:mag: Vulnerabilities of <code>getwilds/hmmcopy:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/hmmcopy:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:7d3990ec4f2ebdeded6866112034573db5c9791c90386c58dc3068a0fb8178c6</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/medium-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/low-0-lightgrey"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>217 MB</td></tr>
<tr><td>packages</td><td>235</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>glibc</strong> <code>2.31-0ubuntu9.17</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glibc@2.31-0ubuntu9.17?os_distro=focal&os_name=ubuntu&os_version=20.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-4802?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=20.04&vr=%3C2.31-0ubuntu9.18"><img alt="medium : CVE--2025--4802" src="https://img.shields.io/badge/CVE--2025--4802-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.31-0ubuntu9.18</code></td></tr>
<tr><td>Fixed version</td><td><code>2.31-0ubuntu9.18</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.007%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Untrusted LD_LIBRARY_PATH environment variable vulnerability in the GNU C Library version 2.27 to 2.38 allows attacker controlled loading of dynamically shared library in statically compiled setuid binaries that call dlopen (including internal dlopen calls after setlocale or calls to NSS functions such as getaddrinfo).

</blockquote>
</details>
</details></td></tr>
</table>