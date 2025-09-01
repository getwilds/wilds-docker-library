# Vulnerability Report for getwilds/samtools:1.19

Report generated on 2025-09-01 08:19:46 PST

<h2>:mag: Vulnerabilities of <code>getwilds/samtools:1.19</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/samtools:1.19</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:8d96a155d29125d0b0bbddb01da49bbace1e7618495285471d2fab9ecb9191c6</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/high-1-e25d68"/> <img alt="medium: 3" src="https://img.shields.io/badge/medium-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/low-0-lightgrey"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>194 MB</td></tr>
<tr><td>packages</td><td>229</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 3" src="https://img.shields.io/badge/M-3-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>linux</strong> <code>6.8.0-78.78</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@6.8.0-78.78?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
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
</details></td></tr>
</table>