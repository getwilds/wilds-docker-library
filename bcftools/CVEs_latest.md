# Vulnerability Report for getwilds/bcftools:latest

Report generated on 2025-08-01 08:40:13 PST

<h2>:mag: Vulnerabilities of <code>getwilds/bcftools:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/bcftools:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:ec8b131c6873bcbd54bc61cde1f758c87c2bec5369d35d10b66381f5480b8a88</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 3" src="https://img.shields.io/badge/medium-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/low-0-lightgrey"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>175 MB</td></tr>
<tr><td>packages</td><td>229</td></tr>
</table>
</details></table>
</details>

<table>
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
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: hfsc: Fix a UAF vulnerability in class handling  This patch fixes a Use-After-Free vulnerability in the HFSC qdisc class handling. The issue occurs due to a time-of-check/time-of-use condition in hfsc_change_class() when working with certain child qdiscs like netem or codel.  The vulnerability works as follows: 1. hfsc_change_class() checks if a class has packets (q.qlen != 0) 2. It then calls qdisc_peek_len(), which for certain qdiscs (e.g., codel, netem) might drop packets and empty the queue 3. The code continues assuming the queue is still non-empty, adding the class to vttree 4. This breaks HFSC scheduler assumptions that only non-empty classes are in vttree 5. Later, when the class is destroyed, this can lead to a Use-After-Free  The fix adds a second queue length check after qdisc_peek_len() to verify the queue wasn't emptied.

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
</table>