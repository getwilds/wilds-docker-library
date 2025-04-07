# Vulnerability Report for getwilds/samtools:latest

Report generated on Mon Apr  7 12:09:56 PDT 2025

<h2>:mag: Vulnerabilities of <code>getwilds/samtools:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/samtools:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:026f720675b3b5054f450ebbcc6ea3c2c01228982e651e63b2e5217bdb722727</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 427" src="https://img.shields.io/badge/medium-427-fbb552"/> <img alt="low: 33" src="https://img.shields.io/badge/low-33-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>186 MB</td></tr>
<tr><td>packages</td><td>229</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 421" src="https://img.shields.io/badge/M-421-fbb552"/> <img alt="low: 23" src="https://img.shields.io/badge/L-23-fce1a9"/> <!-- unspecified: 0 --><strong>linux</strong> <code>6.8.0-56.58</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@6.8.0-56.58?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-21863?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21863" src="https://img.shields.io/badge/CVE--2025--21863-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  io_uring: prevent opcode speculation  sqe->opcode is used for different tables, make sure we santitise it against speculations.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21858?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21858" src="https://img.shields.io/badge/CVE--2025--21858-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  geneve: Fix use-after-free in geneve_find_dev().  syzkaller reported a use-after-free in geneve_find_dev() [0] without repro.  geneve_configure() links struct geneve_dev.next to net_generic(net, geneve_net_id)->geneve_list.  The net here could differ from dev_net(dev) if IFLA_NET_NS_PID, IFLA_NET_NS_FD, or IFLA_TARGET_NETNSID is set.  When dev_net(dev) is dismantled, geneve_exit_batch_rtnl() finally calls unregister_netdevice_queue() for each dev in the netns, and later the dev is freed.  However, its geneve_dev.next is still linked to the backend UDP socket netns.  Then, use-after-free will occur when another geneve dev is created in the netns.  Let's call geneve_dellink() instead in geneve_destroy_tunnels().  [0]: BUG: KASAN: slab-use-after-free in geneve_find_dev drivers/net/geneve.c:1295 [inline] BUG: KASAN: slab-use-after-free in geneve_configure+0x234/0x858 drivers/net/geneve.c:1343 Read of size 2 at addr ffff000054d6ee24 by task syz.1.4029/13441  CPU: 1 UID: 0 PID: 13441 Comm: syz.1.4029 Not tainted 6.13.0-g0ad9617c78ac #24 dc35ca22c79fb82e8e7bc5c9c9adafea898b1e3d Hardware name: linux,dummy-virt (DT) Call trace: show_stack+0x38/0x50 arch/arm64/kernel/stacktrace.c:466 (C) __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0xbc/0x108 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x16c/0x6f0 mm/kasan/report.c:489 kasan_report+0xc0/0x120 mm/kasan/report.c:602 __asan_report_load2_noabort+0x20/0x30 mm/kasan/report_generic.c:379 geneve_find_dev drivers/net/geneve.c:1295 [inline] geneve_configure+0x234/0x858 drivers/net/geneve.c:1343 geneve_newlink+0xb8/0x128 drivers/net/geneve.c:1634 rtnl_newlink_create+0x23c/0x868 net/core/rtnetlink.c:3795 __rtnl_newlink net/core/rtnetlink.c:3906 [inline] rtnl_newlink+0x1054/0x1630 net/core/rtnetlink.c:4021 rtnetlink_rcv_msg+0x61c/0x918 net/core/rtnetlink.c:6911 netlink_rcv_skb+0x1dc/0x398 net/netlink/af_netlink.c:2543 rtnetlink_rcv+0x34/0x50 net/core/rtnetlink.c:6938 netlink_unicast_kernel net/netlink/af_netlink.c:1322 [inline] netlink_unicast+0x618/0x838 net/netlink/af_netlink.c:1348 netlink_sendmsg+0x5fc/0x8b0 net/netlink/af_netlink.c:1892 sock_sendmsg_nosec net/socket.c:713 [inline] __sock_sendmsg net/socket.c:728 [inline] ____sys_sendmsg+0x410/0x6f8 net/socket.c:2568 ___sys_sendmsg+0x178/0x1d8 net/socket.c:2622 __sys_sendmsg net/socket.c:2654 [inline] __do_sys_sendmsg net/socket.c:2659 [inline] __se_sys_sendmsg net/socket.c:2657 [inline] __arm64_sys_sendmsg+0x12c/0x1c8 net/socket.c:2657 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x90/0x278 arch/arm64/kernel/syscall.c:49 el0_svc_common+0x13c/0x250 arch/arm64/kernel/syscall.c:132 do_el0_svc+0x54/0x70 arch/arm64/kernel/syscall.c:151 el0_svc+0x4c/0xa8 arch/arm64/kernel/entry-common.c:744 el0t_64_sync_handler+0x78/0x108 arch/arm64/kernel/entry-common.c:762 el0t_64_sync+0x198/0x1a0 arch/arm64/kernel/entry.S:600  Allocated by task 13247: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x30/0x68 mm/kasan/common.c:68 kasan_save_alloc_info+0x44/0x58 mm/kasan/generic.c:568 poison_kmalloc_redzone mm/kasan/common.c:377 [inline] __kasan_kmalloc+0x84/0xa0 mm/kasan/common.c:394 kasan_kmalloc include/linux/kasan.h:260 [inline] __do_kmalloc_node mm/slub.c:4298 [inline] __kmalloc_node_noprof+0x2a0/0x560 mm/slub.c:4304 __kvmalloc_node_noprof+0x9c/0x230 mm/util.c:645 alloc_netdev_mqs+0xb8/0x11a0 net/core/dev.c:11470 rtnl_create_link+0x2b8/0xb50 net/core/rtnetlink.c:3604 rtnl_newlink_create+0x19c/0x868 net/core/rtnetlink.c:3780 __rtnl_newlink net/core/rtnetlink.c:3906 [inline] rtnl_newlink+0x1054/0x1630 net/core/rtnetlink.c:4021 rtnetlink_rcv_msg+0x61c/0x918 net/core/rtnetlink.c:6911 netlink_rcv_skb+0x1dc/0x398 net/netlink/af_netlink.c:2543 rtnetlink_rcv+0x34/0x50 net/core/rtnetlink.c:6938 netlink_unicast_kernel net/netlink/af_n ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21856?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21856" src="https://img.shields.io/badge/CVE--2025--21856-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  s390/ism: add release function for struct device  According to device_release() in /drivers/base/core.c, a device without a release function is a broken device and must be fixed.  The current code directly frees the device after calling device_add() without waiting for other kernel parts to release their references. Thus, a reference could still be held to a struct device, e.g., by sysfs, leading to potential use-after-free issues if a proper release function is not set.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21855?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21855" src="https://img.shields.io/badge/CVE--2025--21855-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ibmvnic: Don't reference skb after sending to VIOS  Previously, after successfully flushing the xmit buffer to VIOS, the tx_bytes stat was incremented by the length of the skb.  It is invalid to access the skb memory after sending the buffer to the VIOS because, at any point after sending, the VIOS can trigger an interrupt to free this memory. A race between reading skb->len and freeing the skb is possible (especially during LPM) and will result in use-after-free: ================================================================== BUG: KASAN: slab-use-after-free in ibmvnic_xmit+0x75c/0x1808 [ibmvnic] Read of size 4 at addr c00000024eb48a70 by task hxecom/14495 <...> Call Trace: [c000000118f66cf0] [c0000000018cba6c] dump_stack_lvl+0x84/0xe8 (unreliable) [c000000118f66d20] [c0000000006f0080] print_report+0x1a8/0x7f0 [c000000118f66df0] [c0000000006f08f0] kasan_report+0x128/0x1f8 [c000000118f66f00] [c0000000006f2868] __asan_load4+0xac/0xe0 [c000000118f66f20] [c0080000046eac84] ibmvnic_xmit+0x75c/0x1808 [ibmvnic] [c000000118f67340] [c0000000014be168] dev_hard_start_xmit+0x150/0x358 <...> Freed by task 0: kasan_save_stack+0x34/0x68 kasan_save_track+0x2c/0x50 kasan_save_free_info+0x64/0x108 __kasan_mempool_poison_object+0x148/0x2d4 napi_skb_cache_put+0x5c/0x194 net_tx_action+0x154/0x5b8 handle_softirqs+0x20c/0x60c do_softirq_own_stack+0x6c/0x88 <...> The buggy address belongs to the object at c00000024eb48a00 which belongs to the cache skbuff_head_cache of size 224 ==================================================================

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21791?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21791" src="https://img.shields.io/badge/CVE--2025--21791-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vrf: use RCU protection in l3mdev_l3_out()  l3mdev_l3_out() can be called without RCU being held:  raw_sendmsg() ip_push_pending_frames() ip_send_skb() ip_local_out() __ip_local_out() l3mdev_ip_out()  Add rcu_read_lock() / rcu_read_unlock() pair to avoid a potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21785?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21785" src="https://img.shields.io/badge/CVE--2025--21785-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  arm64: cacheinfo: Avoid out-of-bounds write to cacheinfo array  The loop that detects/populates cache information already has a bounds check on the array size but does not account for cache levels with separate data/instructions cache. Fix this by incrementing the index for any populated leaf (instead of any populated level).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21780?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21780" src="https://img.shields.io/badge/CVE--2025--21780-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu: avoid buffer overflow attach in smu_sys_set_pp_table()  It malicious user provides a small pptable through sysfs and then a bigger pptable, it may cause buffer overflow attack in function smu_sys_set_pp_table().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21735?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21735" src="https://img.shields.io/badge/CVE--2025--21735-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  NFC: nci: Add bounds checking in nci_hci_create_pipe()  The "pipe" variable is a u8 which comes from the network.  If it's more than 127, then it results in memory corruption in the caller, nci_hci_connect_gate().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21692?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21692" src="https://img.shields.io/badge/CVE--2025--21692-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: sched: fix ets qdisc OOB Indexing  Haowei Yan <g1042620637@gmail.com> found that ets_class_from_arg() can index an Out-Of-Bound class in ets_class_from_arg() when passed clid of 0. The overflow may cause local privilege escalation.  [   18.852298] ------------[ cut here ]------------ [   18.853271] UBSAN: array-index-out-of-bounds in net/sched/sch_ets.c:93:20 [   18.853743] index 18446744073709551615 is out of range for type 'ets_class [16]' [   18.854254] CPU: 0 UID: 0 PID: 1275 Comm: poc Not tainted 6.12.6-dirty #17 [   18.854821] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 [   18.856532] Call Trace: [   18.857441]  <TASK> [   18.858227]  dump_stack_lvl+0xc2/0xf0 [   18.859607]  dump_stack+0x10/0x20 [   18.860908]  __ubsan_handle_out_of_bounds+0xa7/0xf0 [   18.864022]  ets_class_change+0x3d6/0x3f0 [   18.864322]  tc_ctl_tclass+0x251/0x910 [   18.864587]  ? lock_acquire+0x5e/0x140 [   18.865113]  ? __mutex_lock+0x9c/0xe70 [   18.866009]  ? __mutex_lock+0xa34/0xe70 [   18.866401]  rtnetlink_rcv_msg+0x170/0x6f0 [   18.866806]  ? __lock_acquire+0x578/0xc10 [   18.867184]  ? __pfx_rtnetlink_rcv_msg+0x10/0x10 [   18.867503]  netlink_rcv_skb+0x59/0x110 [   18.867776]  rtnetlink_rcv+0x15/0x30 [   18.868159]  netlink_unicast+0x1c3/0x2b0 [   18.868440]  netlink_sendmsg+0x239/0x4b0 [   18.868721]  ____sys_sendmsg+0x3e2/0x410 [   18.869012]  ___sys_sendmsg+0x88/0xe0 [   18.869276]  ? rseq_ip_fixup+0x198/0x260 [   18.869563]  ? rseq_update_cpu_node_id+0x10a/0x190 [   18.869900]  ? trace_hardirqs_off+0x5a/0xd0 [   18.870196]  ? syscall_exit_to_user_mode+0xcc/0x220 [   18.870547]  ? do_syscall_64+0x93/0x150 [   18.870821]  ? __memcg_slab_free_hook+0x69/0x290 [   18.871157]  __sys_sendmsg+0x69/0xd0 [   18.871416]  __x64_sys_sendmsg+0x1d/0x30 [   18.871699]  x64_sys_call+0x9e2/0x2670 [   18.871979]  do_syscall_64+0x87/0x150 [   18.873280]  ? do_syscall_64+0x93/0x150 [   18.874742]  ? lock_release+0x7b/0x160 [   18.876157]  ? do_user_addr_fault+0x5ce/0x8f0 [   18.877833]  ? irqentry_exit_to_user_mode+0xc2/0x210 [   18.879608]  ? irqentry_exit+0x77/0xb0 [   18.879808]  ? clear_bhb_loop+0x15/0x70 [   18.880023]  ? clear_bhb_loop+0x15/0x70 [   18.880223]  ? clear_bhb_loop+0x15/0x70 [   18.880426]  entry_SYSCALL_64_after_hwframe+0x76/0x7e [   18.880683] RIP: 0033:0x44a957 [   18.880851] Code: ff ff e8 fc 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 90 f3 0f 1e fa 64 8b 04 25 18 00 00 00 85 c0 75 10 b8 2e 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 51 c3 48 83 ec 28 89 54 24 1c 48 8974 24 10 [   18.881766] RSP: 002b:00007ffcdd00fad8 EFLAGS: 00000246 ORIG_RAX: 000000000000002e [   18.882149] RAX: ffffffffffffffda RBX: 00007ffcdd010db8 RCX: 000000000044a957 [   18.882507] RDX: 0000000000000000 RSI: 00007ffcdd00fb70 RDI: 0000000000000003 [   18.885037] RBP: 00007ffcdd010bc0 R08: 000000000703c770 R09: 000000000703c7c0 [   18.887203] R10: 0000000000000080 R11: 0000000000000246 R12: 0000000000000001 [   18.888026] R13: 00007ffcdd010da8 R14: 00000000004ca7d0 R15: 0000000000000001 [   18.888395]  </TASK> [   18.888610] ---[ end trace ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21687?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21687" src="https://img.shields.io/badge/CVE--2025--21687-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vfio/platform: check the bounds of read/write syscalls  count and offset are passed from user space and not checked, only offset is capped to 40 bits, which can be used to read/write out of bounds of the device.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21680?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21680" src="https://img.shields.io/badge/CVE--2025--21680-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
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

<a href="https://scout.docker.com/v/CVE-2025-21652?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21652" src="https://img.shields.io/badge/CVE--2025--21652-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipvlan: Fix use-after-free in ipvlan_get_iflink().  syzbot presented an use-after-free report [0] regarding ipvlan and linkwatch.  ipvlan does not hold a refcnt of the lower device unlike vlan and macvlan.  If the linkwatch work is triggered for the ipvlan dev, the lower dev might have already been freed, resulting in UAF of ipvlan->phy_dev in ipvlan_get_iflink().  We can delay the lower dev unregistration like vlan and macvlan by holding the lower dev's refcnt in dev->netdev_ops->ndo_init() and releasing it in dev->priv_destructor().  Jakub pointed out calling .ndo_XXX after unregister_netdevice() has returned is error prone and suggested [1] addressing this UAF in the core by taking commit 750e51603395 ("net: avoid potential UAF in default_operstate()") further.  Let's assume unregistering devices DOWN and use RCU protection in default_operstate() not to race with the device unregistration.  [0]: BUG: KASAN: slab-use-after-free in ipvlan_get_iflink+0x84/0x88 drivers/net/ipvlan/ipvlan_main.c:353 Read of size 4 at addr ffff0000d768c0e0 by task kworker/u8:35/6944  CPU: 0 UID: 0 PID: 6944 Comm: kworker/u8:35 Not tainted 6.13.0-rc2-g9bc5c9515b48 #12 4c3cb9e8b4565456f6a355f312ff91f4f29b3c47 Hardware name: linux,dummy-virt (DT) Workqueue: events_unbound linkwatch_event Call trace: show_stack+0x38/0x50 arch/arm64/kernel/stacktrace.c:484 (C) __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0xbc/0x108 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x16c/0x6f0 mm/kasan/report.c:489 kasan_report+0xc0/0x120 mm/kasan/report.c:602 __asan_report_load4_noabort+0x20/0x30 mm/kasan/report_generic.c:380 ipvlan_get_iflink+0x84/0x88 drivers/net/ipvlan/ipvlan_main.c:353 dev_get_iflink+0x7c/0xd8 net/core/dev.c:674 default_operstate net/core/link_watch.c:45 [inline] rfc2863_policy+0x144/0x360 net/core/link_watch.c:72 linkwatch_do_dev+0x60/0x228 net/core/link_watch.c:175 __linkwatch_run_queue+0x2f4/0x5b8 net/core/link_watch.c:239 linkwatch_event+0x64/0xa8 net/core/link_watch.c:282 process_one_work+0x700/0x1398 kernel/workqueue.c:3229 process_scheduled_works kernel/workqueue.c:3310 [inline] worker_thread+0x8c4/0xe10 kernel/workqueue.c:3391 kthread+0x2b0/0x360 kernel/kthread.c:389 ret_from_fork+0x10/0x20 arch/arm64/kernel/entry.S:862  Allocated by task 9303: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x30/0x68 mm/kasan/common.c:68 kasan_save_alloc_info+0x44/0x58 mm/kasan/generic.c:568 poison_kmalloc_redzone mm/kasan/common.c:377 [inline] __kasan_kmalloc+0x84/0xa0 mm/kasan/common.c:394 kasan_kmalloc include/linux/kasan.h:260 [inline] __do_kmalloc_node mm/slub.c:4283 [inline] __kmalloc_node_noprof+0x2a0/0x560 mm/slub.c:4289 __kvmalloc_node_noprof+0x9c/0x230 mm/util.c:650 alloc_netdev_mqs+0xb4/0x1118 net/core/dev.c:11209 rtnl_create_link+0x2b8/0xb60 net/core/rtnetlink.c:3595 rtnl_newlink_create+0x19c/0x868 net/core/rtnetlink.c:3771 __rtnl_newlink net/core/rtnetlink.c:3896 [inline] rtnl_newlink+0x122c/0x15c0 net/core/rtnetlink.c:4011 rtnetlink_rcv_msg+0x61c/0x918 net/core/rtnetlink.c:6901 netlink_rcv_skb+0x1dc/0x398 net/netlink/af_netlink.c:2542 rtnetlink_rcv+0x34/0x50 net/core/rtnetlink.c:6928 netlink_unicast_kernel net/netlink/af_netlink.c:1321 [inline] netlink_unicast+0x618/0x838 net/netlink/af_netlink.c:1347 netlink_sendmsg+0x5fc/0x8b0 net/netlink/af_netlink.c:1891 sock_sendmsg_nosec net/socket.c:711 [inline] __sock_sendmsg net/socket.c:726 [inline] __sys_sendto+0x2ec/0x438 net/socket.c:2197 __do_sys_sendto net/socket.c:2204 [inline] __se_sys_sendto net/socket.c:2200 [inline] __arm64_sys_sendto+0xe4/0x110 net/socket.c:2200 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x90/0x278 arch/arm64/kernel/syscall.c:49 el0_svc_common+0x13c/0x250 arch/arm64/kernel/syscall.c:132 do_el0_svc+0x54/0x70 arch/arm64/kernel/syscall.c:151 el ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21650?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21650" src="https://img.shields.io/badge/CVE--2025--21650-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hns3: fixed hclge_fetch_pf_reg accesses bar space out of bounds issue  The TQP BAR space is divided into two segments. TQPs 0-1023 and TQPs 1024-1279 are in different BAR space addresses. However, hclge_fetch_pf_reg does not distinguish the tqp space information when reading the tqp space information. When the number of TQPs is greater than 1024, access bar space overwriting occurs. The problem of different segments has been considered during the initialization of tqp.io_base. Therefore, tqp.io_base is directly used when the queue is read in hclge_fetch_pf_reg.  The error message:  Unable to handle kernel paging request at virtual address ffff800037200000 pc : hclge_fetch_pf_reg+0x138/0x250 [hclge] lr : hclge_get_regs+0x84/0x1d0 [hclge] Call trace: hclge_fetch_pf_reg+0x138/0x250 [hclge] hclge_get_regs+0x84/0x1d0 [hclge] hns3_get_regs+0x2c/0x50 [hns3] ethtool_get_regs+0xf4/0x270 dev_ethtool+0x674/0x8a0 dev_ioctl+0x270/0x36c sock_do_ioctl+0x110/0x2a0 sock_ioctl+0x2ac/0x530 __arm64_sys_ioctl+0xa8/0x100 invoke_syscall+0x4c/0x124 el0_svc_common.constprop.0+0x140/0x15c do_el0_svc+0x30/0xd0 el0_svc+0x1c/0x2c el0_sync_handler+0xb0/0xb4 el0_sync+0x168/0x180

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21631?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2025--21631" src="https://img.shields.io/badge/CVE--2025--21631-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  block, bfq: fix waker_bfqq UAF after bfq_split_bfqq()  Our syzkaller report a following UAF for v6.6:  BUG: KASAN: slab-use-after-free in bfq_init_rq+0x175d/0x17a0 block/bfq-iosched.c:6958 Read of size 8 at addr ffff8881b57147d8 by task fsstress/232726  CPU: 2 PID: 232726 Comm: fsstress Not tainted 6.6.0-g3629d1885222 #39 Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x91/0xf0 lib/dump_stack.c:106 print_address_description.constprop.0+0x66/0x300 mm/kasan/report.c:364 print_report+0x3e/0x70 mm/kasan/report.c:475 kasan_report+0xb8/0xf0 mm/kasan/report.c:588 hlist_add_head include/linux/list.h:1023 [inline] bfq_init_rq+0x175d/0x17a0 block/bfq-iosched.c:6958 bfq_insert_request.isra.0+0xe8/0xa20 block/bfq-iosched.c:6271 bfq_insert_requests+0x27f/0x390 block/bfq-iosched.c:6323 blk_mq_insert_request+0x290/0x8f0 block/blk-mq.c:2660 blk_mq_submit_bio+0x1021/0x15e0 block/blk-mq.c:3143 __submit_bio+0xa0/0x6b0 block/blk-core.c:639 __submit_bio_noacct_mq block/blk-core.c:718 [inline] submit_bio_noacct_nocheck+0x5b7/0x810 block/blk-core.c:747 submit_bio_noacct+0xca0/0x1990 block/blk-core.c:847 __ext4_read_bh fs/ext4/super.c:205 [inline] ext4_read_bh+0x15e/0x2e0 fs/ext4/super.c:230 __read_extent_tree_block+0x304/0x6f0 fs/ext4/extents.c:567 ext4_find_extent+0x479/0xd20 fs/ext4/extents.c:947 ext4_ext_map_blocks+0x1a3/0x2680 fs/ext4/extents.c:4182 ext4_map_blocks+0x929/0x15a0 fs/ext4/inode.c:660 ext4_iomap_begin_report+0x298/0x480 fs/ext4/inode.c:3569 iomap_iter+0x3dd/0x1010 fs/iomap/iter.c:91 iomap_fiemap+0x1f4/0x360 fs/iomap/fiemap.c:80 ext4_fiemap+0x181/0x210 fs/ext4/extents.c:5051 ioctl_fiemap.isra.0+0x1b4/0x290 fs/ioctl.c:220 do_vfs_ioctl+0x31c/0x11a0 fs/ioctl.c:811 __do_sys_ioctl fs/ioctl.c:869 [inline] __se_sys_ioctl+0xae/0x190 fs/ioctl.c:857 do_syscall_x64 arch/x86/entry/common.c:51 [inline] do_syscall_64+0x70/0x120 arch/x86/entry/common.c:81 entry_SYSCALL_64_after_hwframe+0x78/0xe2  Allocated by task 232719: kasan_save_stack+0x22/0x50 mm/kasan/common.c:45 kasan_set_track+0x25/0x30 mm/kasan/common.c:52 __kasan_slab_alloc+0x87/0x90 mm/kasan/common.c:328 kasan_slab_alloc include/linux/kasan.h:188 [inline] slab_post_alloc_hook mm/slab.h:768 [inline] slab_alloc_node mm/slub.c:3492 [inline] kmem_cache_alloc_node+0x1b8/0x6f0 mm/slub.c:3537 bfq_get_queue+0x215/0x1f00 block/bfq-iosched.c:5869 bfq_get_bfqq_handle_split+0x167/0x5f0 block/bfq-iosched.c:6776 bfq_init_rq+0x13a4/0x17a0 block/bfq-iosched.c:6938 bfq_insert_request.isra.0+0xe8/0xa20 block/bfq-iosched.c:6271 bfq_insert_requests+0x27f/0x390 block/bfq-iosched.c:6323 blk_mq_insert_request+0x290/0x8f0 block/blk-mq.c:2660 blk_mq_submit_bio+0x1021/0x15e0 block/blk-mq.c:3143 __submit_bio+0xa0/0x6b0 block/blk-core.c:639 __submit_bio_noacct_mq block/blk-core.c:718 [inline] submit_bio_noacct_nocheck+0x5b7/0x810 block/blk-core.c:747 submit_bio_noacct+0xca0/0x1990 block/blk-core.c:847 __ext4_read_bh fs/ext4/super.c:205 [inline] ext4_read_bh_nowait+0x15a/0x240 fs/ext4/super.c:217 ext4_read_bh_lock+0xac/0xd0 fs/ext4/super.c:242 ext4_bread_batch+0x268/0x500 fs/ext4/inode.c:958 __ext4_find_entry+0x448/0x10f0 fs/ext4/namei.c:1671 ext4_lookup_entry fs/ext4/namei.c:1774 [inline] ext4_lookup.part.0+0x359/0x6f0 fs/ext4/namei.c:1842 ext4_lookup+0x72/0x90 fs/ext4/namei.c:1839 __lookup_slow+0x257/0x480 fs/namei.c:1696 lookup_slow fs/namei.c:1713 [inline] walk_component+0x454/0x5c0 fs/namei.c:2004 link_path_walk.part.0+0x773/0xda0 fs/namei.c:2331 link_path_walk fs/namei.c:3826 [inline] path_openat+0x1b9/0x520 fs/namei.c:3826 do_filp_open+0x1b7/0x400 fs/namei.c:3857 do_sys_openat2+0x5dc/0x6e0 fs/open.c:1428 do_sys_open fs/open.c:1443 [inline] __do_sys_openat fs/open.c:1459 [inline] __se_sys_openat fs/open.c:1454 [inline] __x64_sys_openat+0x148/0x200 fs/open.c:1454 do_syscall_x64 arch/x86/entry/common.c:51 [inline] do_syscall_6 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58069?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--58069" src="https://img.shields.io/badge/CVE--2024--58069-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  rtc: pcf85063: fix potential OOB write in PCF85063 NVMEM read  The nvmem interface supports variable buffer sizes, while the regmap interface operates with fixed-size storage. If an nvmem client uses a buffer size less than 4 bytes, regmap_read will write out of bounds as it expects the buffer to point at an unsigned int.  Fix this by using an intermediary unsigned int to hold the value.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58055?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--58055" src="https://img.shields.io/badge/CVE--2024--58055-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: f_tcm: Don't free command immediately  Don't prematurely free the command. Wait for the status completion of the sense status. It can be freed then. Otherwise we will double-free the command.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58002?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--58002" src="https://img.shields.io/badge/CVE--2024--58002-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: uvcvideo: Remove dangling pointers  When an async control is written, we copy a pointer to the file handle that started the operation. That pointer will be used when the device is done. Which could be anytime in the future.  If the user closes that file descriptor, its structure will be freed, and there will be one dangling pointer per pending async control, that the driver will try to use.  Clean all the dangling pointers during release().  To avoid adding a performance penalty in the most common case (no async operation), a counter has been introduced with some logic to make sure that it is properly handled.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57990?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57990" src="https://img.shields.io/badge/CVE--2024--57990-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: mt76: mt7925: fix off by one in mt7925_load_clc()  This comparison should be >= instead of > to prevent an out of bounds read and write.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57980?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57980" src="https://img.shields.io/badge/CVE--2024--57980-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: uvcvideo: Fix double free in error path  If the uvc_status_init() function fails to allocate the int_urb, it will free the dev->status pointer but doesn't reset the pointer to NULL. This results in the kfree() call in uvc_status_cleanup() trying to double-free the memory. Fix it by resetting the dev->status pointer to NULL after freeing it.  Reviewed by: Ricardo Ribalda <ribalda@chromium.org>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57951?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57951" src="https://img.shields.io/badge/CVE--2024--57951-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  hrtimers: Handle CPU state correctly on hotplug  Consider a scenario where a CPU transitions from CPUHP_ONLINE to halfway through a CPU hotunplug down to CPUHP_HRTIMERS_PREPARE, and then back to CPUHP_ONLINE:  Since hrtimers_prepare_cpu() does not run, cpu_base.hres_active remains set to 1 throughout. However, during a CPU unplug operation, the tick and the clockevents are shut down at CPUHP_AP_TICK_DYING. On return to the online state, for instance CFS incorrectly assumes that the hrtick is already active, and the chance of the clockevent device to transition to oneshot mode is also lost forever for the CPU, unless it goes back to a lower state than CPUHP_HRTIMERS_PREPARE once.  This round-trip reveals another issue; cpu_base.online is not set to 1 after the transition, which appears as a WARN_ON_ONCE in enqueue_hrtimer().  Aside of that, the bulk of the per CPU state is not reset either, which means there are dangling pointers in the worst case.  Address this by adding a corresponding startup() callback, which resets the stale per CPU state and sets the online flag.  [ tglx: Make the new callback unconditionally available, remove the online modification in the prepare() callback and clear the remaining state in the starting callback instead of the prepare callback ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57926?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57926" src="https://img.shields.io/badge/CVE--2024--57926-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/mediatek: Set private->all_drm_private[i]->drm to NULL if mtk_drm_bind returns err  The pointer need to be set to NULL, otherwise KASAN complains about use-after-free. Because in mtk_drm_bind, all private's drm are set as follows.  private->all_drm_private[i]->drm = drm;  And drm will be released by drm_dev_put in case mtk_drm_kms_init returns failure. However, the shutdown path still accesses the previous allocated memory in drm_atomic_helper_shutdown.  [   84.874820] watchdog: watchdog0: watchdog did not stop! [   86.512054] ================================================================== [   86.513162] BUG: KASAN: use-after-free in drm_atomic_helper_shutdown+0x33c/0x378 [   86.514258] Read of size 8 at addr ffff0000d46fc068 by task shutdown/1 [   86.515213] [   86.515455] CPU: 1 UID: 0 PID: 1 Comm: shutdown Not tainted 6.13.0-rc1-mtk+gfa1a78e5d24b-dirty #55 [   86.516752] Hardware name: Unknown Product/Unknown Product, BIOS 2022.10 10/01/2022 [   86.517960] Call trace: [   86.518333]  show_stack+0x20/0x38 (C) [   86.518891]  dump_stack_lvl+0x90/0xd0 [   86.519443]  print_report+0xf8/0x5b0 [   86.519985]  kasan_report+0xb4/0x100 [   86.520526]  __asan_report_load8_noabort+0x20/0x30 [   86.521240]  drm_atomic_helper_shutdown+0x33c/0x378 [   86.521966]  mtk_drm_shutdown+0x54/0x80 [   86.522546]  platform_shutdown+0x64/0x90 [   86.523137]  device_shutdown+0x260/0x5b8 [   86.523728]  kernel_restart+0x78/0xf0 [   86.524282]  __do_sys_reboot+0x258/0x2f0 [   86.524871]  __arm64_sys_reboot+0x90/0xd8 [   86.525473]  invoke_syscall+0x74/0x268 [   86.526041]  el0_svc_common.constprop.0+0xb0/0x240 [   86.526751]  do_el0_svc+0x4c/0x70 [   86.527251]  el0_svc+0x4c/0xc0 [   86.527719]  el0t_64_sync_handler+0x144/0x168 [   86.528367]  el0t_64_sync+0x198/0x1a0 [   86.528920] [   86.529157] The buggy address belongs to the physical page: [   86.529972] page: refcount:0 mapcount:0 mapping:0000000000000000 index:0xffff0000d46fd4d0 pfn:0x1146fc [   86.531319] flags: 0xbfffc0000000000(node=0|zone=2|lastcpupid=0xffff) [   86.532267] raw: 0bfffc0000000000 0000000000000000 dead000000000122 0000000000000000 [   86.533390] raw: ffff0000d46fd4d0 0000000000000000 00000000ffffffff 0000000000000000 [   86.534511] page dumped because: kasan: bad access detected [   86.535323] [   86.535559] Memory state around the buggy address: [   86.536265]  ffff0000d46fbf00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.537314]  ffff0000d46fbf80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.538363] >ffff0000d46fc000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.544733]                                                           ^ [   86.551057]  ffff0000d46fc080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.557510]  ffff0000d46fc100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.563928] ================================================================== [   86.571093] Disabling lock debugging due to kernel taint [   86.577642] Unable to handle kernel paging request at virtual address e0e9c0920000000b [   86.581834] KASAN: maybe wild-memory-access in range [0x0752049000000058-0x075204900000005f] ...

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57900?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57900" src="https://img.shields.io/badge/CVE--2024--57900-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ila: serialize calls to nf_register_net_hooks()  syzbot found a race in ila_add_mapping() [1]  commit 031ae72825ce ("ila: call nf_unregister_net_hooks() sooner") attempted to fix a similar issue.  Looking at the syzbot repro, we have concurrent ILA_CMD_ADD commands.  Add a mutex to make sure at most one thread is calling nf_register_net_hooks().  [1] BUG: KASAN: slab-use-after-free in rht_key_hashfn include/linux/rhashtable.h:159 [inline] BUG: KASAN: slab-use-after-free in __rhashtable_lookup.constprop.0+0x426/0x550 include/linux/rhashtable.h:604 Read of size 4 at addr ffff888028f40008 by task dhcpcd/5501  CPU: 1 UID: 0 PID: 5501 Comm: dhcpcd Not tainted 6.13.0-rc4-syzkaller-00054-gd6ef8b40d075 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Call Trace: <IRQ> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0xc3/0x620 mm/kasan/report.c:489 kasan_report+0xd9/0x110 mm/kasan/report.c:602 rht_key_hashfn include/linux/rhashtable.h:159 [inline] __rhashtable_lookup.constprop.0+0x426/0x550 include/linux/rhashtable.h:604 rhashtable_lookup include/linux/rhashtable.h:646 [inline] rhashtable_lookup_fast include/linux/rhashtable.h:672 [inline] ila_lookup_wildcards net/ipv6/ila/ila_xlat.c:127 [inline] ila_xlat_addr net/ipv6/ila/ila_xlat.c:652 [inline] ila_nf_input+0x1ee/0x620 net/ipv6/ila/ila_xlat.c:185 nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline] nf_hook_slow+0xbb/0x200 net/netfilter/core.c:626 nf_hook.constprop.0+0x42e/0x750 include/linux/netfilter.h:269 NF_HOOK include/linux/netfilter.h:312 [inline] ipv6_rcv+0xa4/0x680 net/ipv6/ip6_input.c:309 __netif_receive_skb_one_core+0x12e/0x1e0 net/core/dev.c:5672 __netif_receive_skb+0x1d/0x160 net/core/dev.c:5785 process_backlog+0x443/0x15f0 net/core/dev.c:6117 __napi_poll.constprop.0+0xb7/0x550 net/core/dev.c:6883 napi_poll net/core/dev.c:6952 [inline] net_rx_action+0xa94/0x1010 net/core/dev.c:7074 handle_softirqs+0x213/0x8f0 kernel/softirq.c:561 __do_softirq kernel/softirq.c:595 [inline] invoke_softirq kernel/softirq.c:435 [inline] __irq_exit_rcu+0x109/0x170 kernel/softirq.c:662 irq_exit_rcu+0x9/0x30 kernel/softirq.c:678 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline] sysvec_apic_timer_interrupt+0xa4/0xc0 arch/x86/kernel/apic/apic.c:1049

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57896?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57896" src="https://img.shields.io/badge/CVE--2024--57896-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: flush delalloc workers queue before stopping cleaner kthread during unmount  During the unmount path, at close_ctree(), we first stop the cleaner kthread, using kthread_stop() which frees the associated task_struct, and then stop and destroy all the work queues. However after we stopped the cleaner we may still have a worker from the delalloc_workers queue running inode.c:submit_compressed_extents(), which calls btrfs_add_delayed_iput(), which in turn tries to wake up the cleaner kthread - which was already destroyed before, resulting in a use-after-free on the task_struct.  Syzbot reported this with the following stack traces:  BUG: KASAN: slab-use-after-free in __lock_acquire+0x78/0x2100 kernel/locking/lockdep.c:5089 Read of size 8 at addr ffff8880259d2818 by task kworker/u8:3/52  CPU: 1 UID: 0 PID: 52 Comm: kworker/u8:3 Not tainted 6.13.0-rc1-syzkaller-00002-gcdd30ebb1b9f #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Workqueue: btrfs-delalloc btrfs_work_helper Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x169/0x550 mm/kasan/report.c:489 kasan_report+0x143/0x180 mm/kasan/report.c:602 __lock_acquire+0x78/0x2100 kernel/locking/lockdep.c:5089 lock_acquire+0x1ed/0x550 kernel/locking/lockdep.c:5849 __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline] _raw_spin_lock_irqsave+0xd5/0x120 kernel/locking/spinlock.c:162 class_raw_spinlock_irqsave_constructor include/linux/spinlock.h:551 [inline] try_to_wake_up+0xc2/0x1470 kernel/sched/core.c:4205 submit_compressed_extents+0xdf/0x16e0 fs/btrfs/inode.c:1615 run_ordered_work fs/btrfs/async-thread.c:288 [inline] btrfs_work_helper+0x96f/0xc40 fs/btrfs/async-thread.c:324 process_one_work kernel/workqueue.c:3229 [inline] process_scheduled_works+0xa66/0x1840 kernel/workqueue.c:3310 worker_thread+0x870/0xd30 kernel/workqueue.c:3391 kthread+0x2f0/0x390 kernel/kthread.c:389 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK>  Allocated by task 2: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68 unpoison_slab_object mm/kasan/common.c:319 [inline] __kasan_slab_alloc+0x66/0x80 mm/kasan/common.c:345 kasan_slab_alloc include/linux/kasan.h:250 [inline] slab_post_alloc_hook mm/slub.c:4104 [inline] slab_alloc_node mm/slub.c:4153 [inline] kmem_cache_alloc_node_noprof+0x1d9/0x380 mm/slub.c:4205 alloc_task_struct_node kernel/fork.c:180 [inline] dup_task_struct+0x57/0x8c0 kernel/fork.c:1113 copy_process+0x5d1/0x3d50 kernel/fork.c:2225 kernel_clone+0x223/0x870 kernel/fork.c:2807 kernel_thread+0x1bc/0x240 kernel/fork.c:2869 create_kthread kernel/kthread.c:412 [inline] kthreadd+0x60d/0x810 kernel/kthread.c:767 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244  Freed by task 24: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68 kasan_save_free_info+0x40/0x50 mm/kasan/generic.c:582 poison_slab_object mm/kasan/common.c:247 [inline] __kasan_slab_free+0x59/0x70 mm/kasan/common.c:264 kasan_slab_free include/linux/kasan.h:233 [inline] slab_free_hook mm/slub.c:2338 [inline] slab_free mm/slub.c:4598 [inline] kmem_cache_free+0x195/0x410 mm/slub.c:4700 put_task_struct include/linux/sched/task.h:144 [inline] delayed_put_task_struct+0x125/0x300 kernel/exit.c:227 rcu_do_batch kernel/rcu/tree.c:2567 [inline] rcu_core+0xaaa/0x17a0 kernel/rcu/tree.c:2823 handle_softirqs+0x2d4/0x9b0 kernel/softirq.c:554 run_ksoftirqd+0xca/0x130 kernel/softirq.c:943  ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57892?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57892" src="https://img.shields.io/badge/CVE--2024--57892-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ocfs2: fix slab-use-after-free due to dangling pointer dqi_priv  When mounting ocfs2 and then remounting it as read-only, a slab-use-after-free occurs after the user uses a syscall to quota_getnextquota.  Specifically, sb_dqinfo(sb, type)->dqi_priv is the dangling pointer.  During the remounting process, the pointer dqi_priv is freed but is never set as null leaving it to be accessed.  Additionally, the read-only option for remounting sets the DQUOT_SUSPENDED flag instead of setting the DQUOT_USAGE_ENABLED flags.  Moreover, later in the process of getting the next quota, the function ocfs2_get_next_id is called and only checks the quota usage flags and not the quota suspended flags.  To fix this, I set dqi_priv to null when it is freed after remounting with read-only and put a check for DQUOT_SUSPENDED in ocfs2_get_next_id.  [akpm@linux-foundation.org: coding-style cleanups]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57887?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57887" src="https://img.shields.io/badge/CVE--2024--57887-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm: adv7511: Fix use-after-free in adv7533_attach_dsi()  The host_node pointer was assigned and freed in adv7533_parse_dt(), and later, adv7533_attach_dsi() uses the same. Fix this use-after-free issue by dropping of_node_put() in adv7533_parse_dt() and calling of_node_put() in error path of probe() and also in the remove().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57801?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--57801" src="https://img.shields.io/badge/CVE--2024--57801-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5e: Skip restore TC rules for vport rep without loaded flag  During driver unload, unregister_netdev is called after unloading vport rep. So, the mlx5e_rep_priv is already freed while trying to get rpriv->netdev, or walk rpriv->tc_ht, which results in use-after-free. So add the checking to make sure access the data of vport rep which is still loaded.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56784?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--56784" src="https://img.shields.io/badge/CVE--2024--56784-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Adding array index check to prevent memory corruption  [Why & How] Array indices out of bound caused memory corruption. Adding checks to ensure that array index stays in bound.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53179?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--53179" src="https://img.shields.io/badge/CVE--2024--53179-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix use-after-free of signing key  Customers have reported use-after-free in @ses->auth_key.response with SMB2.1 + sign mounts which occurs due to following race:  task A                         task B cifs_mount() dfs_mount_share() get_session() cifs_mount_get_session()    cifs_send_recv() cifs_get_smb_ses()          compound_send_recv() cifs_setup_session()        smb2_setup_request() kfree_sensitive()           smb2_calc_signature() crypto_shash_setkey() *UAF*  Fix this by ensuring that we have a valid @ses->auth_key.response by checking whether @ses->ses_status is SES_GOOD or SES_EXITING with @ses->ses_lock held.  After commit 24a9799aa8ef ("smb: client: fix UAF in smb2_reconnect_server()"), we made sure to call ->logoff() only when @ses was known to be good (e.g. valid ->auth_key.response), so it's safe to access signing key when @ses->ses_status == SES_EXITING.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53098?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--53098" src="https://img.shields.io/badge/CVE--2024--53098-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/xe/ufence: Prefetch ufence addr to catch bogus address  access_ok() only checks for addr overflow so also try to read the addr to catch invalid addr sent from userspace.  (cherry picked from commit 9408c4508483ffc60811e910a93d6425b8e63928)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50217?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--50217" src="https://img.shields.io/badge/CVE--2024--50217-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: fix use-after-free of block device file in __btrfs_free_extra_devids()  Mounting btrfs from two images (which have the same one fsid and two different dev_uuids) in certain executing order may trigger an UAF for variable 'device->bdev_file' in __btrfs_free_extra_devids(). And following are the details:  1. Attach image_1 to loop0, attach image_2 to loop1, and scan btrfs devices by ioctl(BTRFS_IOC_SCAN_DEV):  /  btrfs_device_1 ? loop0 fs_device \  btrfs_device_2 ? loop1 2. mount /dev/loop0 /mnt btrfs_open_devices btrfs_device_1->bdev_file = btrfs_get_bdev_and_sb(loop0) btrfs_device_2->bdev_file = btrfs_get_bdev_and_sb(loop1) btrfs_fill_super open_ctree fail: btrfs_close_devices // -ENOMEM btrfs_close_bdev(btrfs_device_1) fput(btrfs_device_1->bdev_file) // btrfs_device_1->bdev_file is freed btrfs_close_bdev(btrfs_device_2) fput(btrfs_device_2->bdev_file)  3. mount /dev/loop1 /mnt btrfs_open_devices btrfs_get_bdev_and_sb(&bdev_file) // EIO, btrfs_device_1->bdev_file is not assigned, // which points to a freed memory area btrfs_device_2->bdev_file = btrfs_get_bdev_and_sb(loop1) btrfs_fill_super open_ctree btrfs_free_extra_devids if (btrfs_device_1->bdev_file) fput(btrfs_device_1->bdev_file) // UAF !  Fix it by setting 'device->bdev_file' as 'NULL' after closing the btrfs_device in btrfs_close_one_device().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46833?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--46833" src="https://img.shields.io/badge/CVE--2024--46833-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hns3: void array out of bound when loop tnl_num  When query reg inf of SSU, it loops tnl_num times. However, tnl_num comes from hardware and the length of array is a fixed value. To void array out of bound, make sure the loop time is not greater than the length of array

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46820?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--46820" src="https://img.shields.io/badge/CVE--2024--46820-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu/vcn: remove irq disabling in vcn 5 suspend  We do not directly enable/disable VCN IRQ in vcn 5.0.0. And we do not handle the IRQ state as well. So the calls to disable IRQ and set state are removed. This effectively gets rid of the warining of "WARN_ON(!amdgpu_irq_enabled(adev, src, type))" in amdgpu_irq_put().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-44964?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--44964" src="https://img.shields.io/badge/CVE--2024--44964-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.054%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  idpf: fix memory leaks and crashes while performing a soft reset  The second tagged commit introduced a UAF, as it removed restoring q_vector->vport pointers after reinitializating the structures. This is due to that all queue allocation functions are performed here with the new temporary vport structure and those functions rewrite the backpointers to the vport. Then, this new struct is freed and the pointers start leading to nowhere.  But generally speaking, the current logic is very fragile. It claims to be more reliable when the system is low on memory, but in fact, it consumes two times more memory as at the moment of running this function, there are two vports allocated with their queues and vectors. Moreover, it claims to prevent the driver from running into "bad state", but in fact, any error during the rebuild leaves the old vport in the partially allocated state. Finally, if the interface is down when the function is called, it always allocates a new queue set, but when the user decides to enable the interface later on, vport_open() allocates them once again, IOW there's a clear memory leak here.  Just don't allocate a new queue set when performing a reset, that solves crashes and memory leaks. Readd the old queue number and reopen the interface on rollback - that solves limbo states when the device is left disabled and/or without HW queues enabled.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-44951?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--44951" src="https://img.shields.io/badge/CVE--2024--44951-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  serial: sc16is7xx: fix TX fifo corruption  Sometimes, when a packet is received on channel A at almost the same time as a packet is about to be transmitted on channel B, we observe with a logic analyzer that the received packet on channel A is transmitted on channel B. In other words, the Tx buffer data on channel B is corrupted with data from channel A.  The problem appeared since commit 4409df5866b7 ("serial: sc16is7xx: change EFR lock to operate on each channels"), which changed the EFR locking to operate on each channel instead of chip-wise.  This commit has introduced a regression, because the EFR lock is used not only to protect the EFR registers access, but also, in a very obscure and undocumented way, to protect access to the data buffer, which is shared by the Tx and Rx handlers, but also by each channel of the IC.  Fix this regression first by switching to kfifo_out_linear_ptr() in sc16is7xx_handle_tx() to eliminate the need for a shared Rx/Tx buffer.  Secondly, replace the chip-wise Rx buffer with a separate Rx buffer for each channel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-44932?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--44932" src="https://img.shields.io/badge/CVE--2024--44932-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.054%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  idpf: fix UAFs when destroying the queues  The second tagged commit started sometimes (very rarely, but possible) throwing WARNs from net/core/page_pool.c:page_pool_disable_direct_recycling(). Turned out idpf frees interrupt vectors with embedded NAPIs *before* freeing the queues making page_pools' NAPI pointers lead to freed memory before these pools are destroyed by libeth. It's not clear whether there are other accesses to the freed vectors when destroying the queues, but anyway, we usually free queue/interrupt vectors only when the queues are destroyed and the NAPIs are guaranteed to not be referenced anywhere.  Invert the allocation and freeing logic making queue/interrupt vectors be allocated first and freed last. Vectors don't require queues to be present, so this is safe. Additionally, this change allows to remove that useless queue->q_vector pointer cleanup, as vectors are still valid when freeing the queues (+ both are freed within one function, so it's not clear why nullify the pointers at all).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38581?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--38581" src="https://img.shields.io/badge/CVE--2024--38581-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.070%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: drm/amdgpu/mes: fix use-after-free issue Delete fence fallback timer to fix the ramdom use-after-free issue. v2: move to amdgpu_mes.c

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-27022?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2024--27022" src="https://img.shields.io/badge/CVE--2024--27022-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.090%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: fork: defer linking file vma until vma is fully initialized Thorvald reported a WARNING [1]. And the root cause is below race: CPU 1 CPU 2 fork hugetlbfs_fallocate dup_mmap hugetlbfs_punch_hole i_mmap_lock_write(mapping); vma_interval_tree_insert_after -- Child vma is visible through i_mmap tree. i_mmap_unlock_write(mapping); hugetlb_dup_vma_private -- Clear vma_lock outside i_mmap_rwsem! i_mmap_lock_write(mapping); hugetlb_vmdelete_list vma_interval_tree_foreach hugetlb_vma_trylock_write -- Vma_lock is cleared. tmp->vm_ops->open -- Alloc new vma_lock outside i_mmap_rwsem! hugetlb_vma_unlock_write -- Vma_lock is assigned!!! i_mmap_unlock_write(mapping); hugetlb_dup_vma_private() and hugetlb_vm_op_open() are called outside i_mmap_rwsem lock while vma lock can be used in the same time. Fix this by deferring linking file vma until vma is fully initialized. Those vmas should be initialized first before they can be used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-26242?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2023--26242" src="https://img.shields.io/badge/CVE--2023--26242-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

afu_mmio_region_get_by_offset in drivers/fpga/dfl-afu-region.c in the Linux kernel through 6.1.12 has an integer overflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-0030?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2023--0030" src="https://img.shields.io/badge/CVE--2023--0030-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in the Linux kernel’s nouveau driver in how a user triggers a memory overflow that causes the nvkm_vma_tail function to fail. This flaw allows a local user to crash or potentially escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-3238?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2022--3238" src="https://img.shields.io/badge/CVE--2022--3238-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A double-free flaw was found in the Linux kernel’s NTFS3 subsystem in how a user triggers remount and umount simultaneously. This flaw allows a local user to crash or potentially escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-14356?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.8: CVE--2020--14356" src="https://img.shields.io/badge/CVE--2020--14356-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.813%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>72nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw null pointer dereference in the Linux kernel cgroupv2 subsystem in versions before 5.7.10 was found in the way when reboot the system. A local user could use this flaw to crash the system or escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-25836?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.5: CVE--2022--25836" src="https://img.shields.io/badge/CVE--2022--25836-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.142%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>31st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Bluetooth® Low Energy Pairing in Bluetooth Core Specification v4.0 through v5.3 may permit an unauthenticated MITM to acquire credentials with two pairing devices via adjacent access when the MITM negotiates Legacy Passkey Pairing with the pairing Initiator and Secure Connections Passkey Pairing with the pairing Responder and brute forces the Passkey entered by the user into the Initiator. The MITM attacker can use the identified Passkey value to complete authentication with the Responder via Bluetooth pairing method confusion.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-0400?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.5: CVE--2022--0400" src="https://img.shields.io/badge/CVE--2022--0400-lightgrey?label=medium%207.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds read vulnerability was discovered in linux kernel in the smc protocol stack, causing remote dos.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21789?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2025--21789" src="https://img.shields.io/badge/CVE--2025--21789-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  LoongArch: csum: Fix OoB access in IP checksum code for negative lengths  Commit 69e3a6aa6be2 ("LoongArch: Add checksum optimization for 64-bit system") would cause an undefined shift and an out-of-bounds read.  Commit 8bd795fedb84 ("arm64: csum: Fix OoB access in IP checksum code for negative lengths") fixes the same issue on ARM64.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21782?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2025--21782" src="https://img.shields.io/badge/CVE--2025--21782-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  orangefs: fix a oob in orangefs_debug_write  I got a syzbot report: slab-out-of-bounds Read in orangefs_debug_write... several people suggested fixes, I tested Al Viro's suggestion and made this patch.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21743?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2025--21743" src="https://img.shields.io/badge/CVE--2025--21743-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usbnet: ipheth: fix possible overflow in DPE length check  Originally, it was possible for the DPE length check to overflow if wDatagramIndex + wDatagramLength > U16_MAX. This could lead to an OoB read.  Move the wDatagramIndex term to the other side of the inequality.  An existing condition ensures that wDatagramIndex < urb->actual_length.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21742?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2025--21742" src="https://img.shields.io/badge/CVE--2025--21742-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usbnet: ipheth: use static NDP16 location in URB  Original code allowed for the start of NDP16 to be anywhere within the URB based on the `wNdpIndex` value in NTH16. Only the start position of NDP16 was checked, so it was possible for even the fixed-length part of NDP16 to extend past the end of URB, leading to an out-of-bounds read.  On iOS devices, the NDP16 header always directly follows NTH16. Rely on and check for this specific format.  This, along with NCM-specific minimal URB length check that already exists, will ensure that the fixed-length part of NDP16 plus a set amount of DPEs fit within the URB.  Note that this commit alone does not fully address the OoB read. The limit on the amount of DPEs needs to be enforced separately.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21741?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2025--21741" src="https://img.shields.io/badge/CVE--2025--21741-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usbnet: ipheth: fix DPE OoB read  Fix an out-of-bounds DPE read, limit the number of processed DPEs to the amount that fits into the fixed-size NDP16 header.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58007?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--58007" src="https://img.shields.io/badge/CVE--2024--58007-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  soc: qcom: socinfo: Avoid out of bounds read of serial number  On MSM8916 devices, the serial number exposed in sysfs is constant and does not change across individual devices. It's always:  db410c:/sys/devices/soc0$ cat serial_number 2644893864  The firmware used on MSM8916 exposes SOCINFO_VERSION(0, 8), which does not have support for the serial_num field in the socinfo struct. There is an existing check to avoid exposing the serial number in that case, but it's not correct: When checking the item_size returned by SMEM, we need to make sure the *end* of the serial_num is within bounds, instead of comparing with the *start* offset. The serial_number currently exposed on MSM8916 devices is just an out of bounds read of whatever comes after the socinfo struct in SMEM.  Fix this by changing offsetof() to offsetofend(), so that the size of the field is also taken into account.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57982?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--57982" src="https://img.shields.io/badge/CVE--2024--57982-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  xfrm: state: fix out-of-bounds read during lookup  lookup and resize can run in parallel.  The xfrm_state_hash_generation seqlock ensures a retry, but the hash functions can observe a hmask value that is too large for the new hlist array.  rehash does: rcu_assign_pointer(net->xfrm.state_bydst, ndst) [..] net->xfrm.state_hmask = nhashmask;  While state lookup does: h = xfrm_dst_hash(net, daddr, saddr, tmpl->reqid, encap_family); hlist_for_each_entry_rcu(x, net->xfrm.state_bydst + h, bydst) {  This is only safe in case the update to state_bydst is larger than net->xfrm.xfrm_state_hmask (or if the lookup function gets serialized via state spinlock again).  Fix this by prefetching state_hmask and the associated pointers. The xfrm_state_hash_generation seqlock retry will ensure that the pointer and the hmask will be consistent.  The existing helpers, like xfrm_dst_hash(), are now unsafe for RCU side, add lockdep assertions to document that they are only safe for insert side.  xfrm_state_lookup_byaddr() uses the spinlock rather than RCU. AFAICS this is an oversight from back when state lookup was converted to RCU, this lock should be replaced with RCU in a future patch.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57925?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--57925" src="https://img.shields.io/badge/CVE--2024--57925-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: fix a missing return value check bug  In the smb2_send_interim_resp(), if ksmbd_alloc_work_struct() fails to allocate a node, it returns a NULL pointer to the in_work pointer. This can lead to an illegal memory write of in_work->response_buf when allocate_interim_rsp_buf() attempts to perform a kzalloc() on it.  To address this issue, incorporating a check for the return value of ksmbd_alloc_work_struct() ensures that the function returns immediately upon allocation failure, thereby preventing the aforementioned illegal memory access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57912?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--57912" src="https://img.shields.io/badge/CVE--2024--57912-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: pressure: zpa2326: fix information leak in triggered buffer  The 'sample' local struct is used to push data to user space from a triggered buffer, but it has a hole between the temperature and the timestamp (u32 pressure, u16 temperature, GAP, u64 timestamp). This hole is never initialized.  Initialize the struct to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57911?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--57911" src="https://img.shields.io/badge/CVE--2024--57911-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: dummy: iio_simply_dummy_buffer: fix information leak in triggered buffer  The 'data' array is allocated via kmalloc() and it is used to push data to user space from a triggered buffer, but it does not set values for inactive channels, as it only uses iio_for_each_active_channel() to assign new values.  Use kzalloc for the memory allocation to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57910?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--57910" src="https://img.shields.io/badge/CVE--2024--57910-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: light: vcnl4035: fix information leak in triggered buffer  The 'buffer' local array is used to push data to userspace from a triggered buffer, but it does not set an initial value for the single data element, which is an u16 aligned to 8 bytes. That leaves at least 4 bytes uninitialized even after writing an integer value with regmap_read().  Initialize the array to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57908?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--57908" src="https://img.shields.io/badge/CVE--2024--57908-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: imu: kmx61: fix information leak in triggered buffer  The 'buffer' local array is used to push data to user space from a triggered buffer, but it does not set values for inactive channels, as it only uses iio_for_each_active_channel() to assign new values.  Initialize the array to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57907?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--57907" src="https://img.shields.io/badge/CVE--2024--57907-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: adc: rockchip_saradc: fix information leak in triggered buffer  The 'data' local struct is used to push data to user space from a triggered buffer, but it does not set values for inactive channels, as it only uses iio_for_each_active_channel() to assign new values.  Initialize the struct to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57906?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.1: CVE--2024--57906" src="https://img.shields.io/badge/CVE--2024--57906-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: adc: ti-ads8688: fix information leak in triggered buffer  The 'buffer' local array is used to push data to user space from a triggered buffer, but it does not set values for inactive channels, as it only uses iio_for_each_active_channel() to assign new values.  Initialize the array to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21718?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2025--21718" src="https://img.shields.io/badge/CVE--2025--21718-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: rose: fix timer races against user threads  Rose timers only acquire the socket spinlock, without checking if the socket is owned by one user thread.  Add a check and rearm the timers if needed.  BUG: KASAN: slab-use-after-free in rose_timer_expiry+0x31d/0x360 net/rose/rose_timer.c:174 Read of size 2 at addr ffff88802f09b82a by task swapper/0/0  CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.13.0-rc5-syzkaller-00172-gd1bf27c4e176 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Call Trace: <IRQ> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x169/0x550 mm/kasan/report.c:489 kasan_report+0x143/0x180 mm/kasan/report.c:602 rose_timer_expiry+0x31d/0x360 net/rose/rose_timer.c:174 call_timer_fn+0x187/0x650 kernel/time/timer.c:1793 expire_timers kernel/time/timer.c:1844 [inline] __run_timers kernel/time/timer.c:2418 [inline] __run_timer_base+0x66a/0x8e0 kernel/time/timer.c:2430 run_timer_base kernel/time/timer.c:2439 [inline] run_timer_softirq+0xb7/0x170 kernel/time/timer.c:2449 handle_softirqs+0x2d4/0x9b0 kernel/softirq.c:561 __do_softirq kernel/softirq.c:595 [inline] invoke_softirq kernel/softirq.c:435 [inline] __irq_exit_rcu+0xf7/0x220 kernel/softirq.c:662 irq_exit_rcu+0x9/0x30 kernel/softirq.c:678 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline] sysvec_apic_timer_interrupt+0xa6/0xc0 arch/x86/kernel/apic/apic.c:1049 </IRQ>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50228?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2024--50228" src="https://img.shields.io/badge/CVE--2024--50228-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50106?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2024--50106" src="https://img.shields.io/badge/CVE--2024--50106-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.038%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfsd: fix race between laundromat and free_stateid  There is a race between laundromat handling of revoked delegations and a client sending free_stateid operation. Laundromat thread finds that delegation has expired and needs to be revoked so it marks the delegation stid revoked and it puts it on a reaper list but then it unlock the state lock and the actual delegation revocation happens without the lock. Once the stid is marked revoked a racing free_stateid processing thread does the following (1) it calls list_del_init() which removes it from the reaper list and (2) frees the delegation stid structure. The laundromat thread ends up not calling the revoke_delegation() function for this particular delegation but that means it will no release the lock lease that exists on the file.  Now, a new open for this file comes in and ends up finding that lease list isn't empty and calls nfsd_breaker_owns_lease() which ends up trying to derefence a freed delegation stateid. Leading to the followint use-after-free KASAN warning:  kernel: ================================================================== kernel: BUG: KASAN: slab-use-after-free in nfsd_breaker_owns_lease+0x140/0x160 [nfsd] kernel: Read of size 8 at addr ffff0000e73cd0c8 by task nfsd/6205 kernel: kernel: CPU: 2 UID: 0 PID: 6205 Comm: nfsd Kdump: loaded Not tainted 6.11.0-rc7+ #9 kernel: Hardware name: Apple Inc. Apple Virtualization Generic Platform, BIOS 2069.0.0.0.0 08/03/2024 kernel: Call trace: kernel: dump_backtrace+0x98/0x120 kernel: show_stack+0x1c/0x30 kernel: dump_stack_lvl+0x80/0xe8 kernel: print_address_description.constprop.0+0x84/0x390 kernel: print_report+0xa4/0x268 kernel: kasan_report+0xb4/0xf8 kernel: __asan_report_load8_noabort+0x1c/0x28 kernel: nfsd_breaker_owns_lease+0x140/0x160 [nfsd] kernel: nfsd_file_do_acquire+0xb3c/0x11d0 [nfsd] kernel: nfsd_file_acquire_opened+0x84/0x110 [nfsd] kernel: nfs4_get_vfs_file+0x634/0x958 [nfsd] kernel: nfsd4_process_open2+0xa40/0x1a40 [nfsd] kernel: nfsd4_open+0xa08/0xe80 [nfsd] kernel: nfsd4_proc_compound+0xb8c/0x2130 [nfsd] kernel: nfsd_dispatch+0x22c/0x718 [nfsd] kernel: svc_process_common+0x8e8/0x1960 [sunrpc] kernel: svc_process+0x3d4/0x7e0 [sunrpc] kernel: svc_handle_xprt+0x828/0xe10 [sunrpc] kernel: svc_recv+0x2cc/0x6a8 [sunrpc] kernel: nfsd+0x270/0x400 [nfsd] kernel: kthread+0x288/0x310 kernel: ret_from_fork+0x10/0x20  This patch proposes a fixed that's based on adding 2 new additional stid's sc_status values that help coordinate between the laundromat and other operations (nfsd4_free_stateid() and nfsd4_delegreturn()).  First to make sure, that once the stid is marked revoked, it is not removed by the nfsd4_free_stateid(), the laundromat take a reference on the stateid. Then, coordinating whether the stid has been put on the cl_revoked list or we are processing FREE_STATEID and need to make sure to remove it from the list, each check that state and act accordingly. If laundromat has added to the cl_revoke list before the arrival of FREE_STATEID, then nfsd4_free_stateid() knows to remove it from the list. If nfsd4_free_stateid() finds that operations arrived before laundromat has placed it on cl_revoke list, it marks the state freed and then laundromat will no longer add it to the list.  Also, for nfsd4_delegreturn() when looking for the specified stid, we need to access stid that are marked removed or freeable, it means the laundromat has started processing it but hasn't finished and this delegreturn needs to return nfserr_deleg_revoked and not nfserr_bad_stateid. The latter will not trigger a FREE_STATEID and the lack of it will leave this stid on the cl_revoked list indefinitely.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-2961?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2022--2961" src="https://img.shields.io/badge/CVE--2022--2961-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in the Linux kernel’s PLP Rose functionality in the way a user triggers a race condition by calling bind while simultaneously triggering the rose_bind() function. This flaw allows a local user to crash or potentially escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-1247?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2022--1247" src="https://img.shields.io/badge/CVE--2022--1247-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue found in linux-kernel that leads to a race condition in rose_connect(). The rose driver uses rose_neigh->use to represent how many objects are using the rose_neigh. When a user wants to delete a rose_route via rose_ioctl(), the rose driver calls rose_del_node() and removes neighbours only if their “count” and “use” are zero.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-3864?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.0: CVE--2021--3864" src="https://img.shields.io/badge/CVE--2021--3864-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.401%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>58th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the way the dumpable flag setting was handled when certain SUID binaries executed its descendants. The prerequisite is a SUID binary that sets real UID equal to effective UID, and real GID equal to effective GID. The descendant will then have a dumpable value set to 1. As a result, if the descendant process crashes and core_pattern is set to a relative value, its core dump is stored in the current directory with uid:gid permissions. An unprivileged local user with eligible root SUID binary could use this flaw to place core dumps into root-owned directories, potentially resulting in escalation of privileges.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-15794?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 6.7: CVE--2019--15794" src="https://img.shields.io/badge/CVE--2019--15794-lightgrey?label=medium%206.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.496%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>63rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Overlayfs in the Linux kernel and shiftfs, a non-upstream patch to the Linux kernel included in the Ubuntu 5.0 and 5.3 kernel series, both replace vma->vm_file in their mmap handlers. On error the original value is not restored, and the reference is put for the file to which vm_file points. On upstream kernels this is not an issue, as no callers dereference vm_file following after call_mmap() returns an error. However, the aufs patchs change mmap_region() to replace the fput() using a local variable with vma_fput(), which will fput() vm_file, leading to a refcount underflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-1193?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 6.5: CVE--2023--1193" src="https://img.shields.io/badge/CVE--2023--1193-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.123%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in setup_async_work in the KSMBD implementation of the in-kernel samba server and CIFS in the Linux kernel. This issue could allow an attacker to crash the system by accessing freed work.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2015-8553?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 6.5: CVE--2015--8553" src="https://img.shields.io/badge/CVE--2015--8553-lightgrey?label=medium%206.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.152%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>33rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Xen allows guest OS users to obtain sensitive information from uninitialized locations in host OS kernel memory by not enabling memory and I/O decoding control bits.  NOTE: this vulnerability exists because of an incomplete fix for CVE-2015-0777.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-3714?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.9: CVE--2021--3714" src="https://img.shields.io/badge/CVE--2021--3714-lightgrey?label=medium%205.9&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernels memory deduplication mechanism. Previous work has shown that memory deduplication can be attacked via a local exploitation mechanism. The same technique can be used if an attacker can upload page sized files and detect the change in access time from a networked service to determine if the page has been merged.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21866?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21866" src="https://img.shields.io/badge/CVE--2025--21866-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  powerpc/code-patching: Fix KASAN hit by not flagging text patching area as VM_ALLOC  Erhard reported the following KASAN hit while booting his PowerMac G4 with a KASAN-enabled kernel 6.13-rc6:  BUG: KASAN: vmalloc-out-of-bounds in copy_to_kernel_nofault+0xd8/0x1c8 Write of size 8 at addr f1000000 by task chronyd/1293  CPU: 0 UID: 123 PID: 1293 Comm: chronyd Tainted: G        W 6.13.0-rc6-PMacG4 #2 Tainted: [W]=WARN Hardware name: PowerMac3,6 7455 0x80010303 PowerMac Call Trace: [c2437590] [c1631a84] dump_stack_lvl+0x70/0x8c (unreliable) [c24375b0] [c0504998] print_report+0xdc/0x504 [c2437610] [c050475c] kasan_report+0xf8/0x108 [c2437690] [c0505a3c] kasan_check_range+0x24/0x18c [c24376a0] [c03fb5e4] copy_to_kernel_nofault+0xd8/0x1c8 [c24376c0] [c004c014] patch_instructions+0x15c/0x16c [c2437710] [c00731a8] bpf_arch_text_copy+0x60/0x7c [c2437730] [c0281168] bpf_jit_binary_pack_finalize+0x50/0xac [c2437750] [c0073cf4] bpf_int_jit_compile+0xb30/0xdec [c2437880] [c0280394] bpf_prog_select_runtime+0x15c/0x478 [c24378d0] [c1263428] bpf_prepare_filter+0xbf8/0xc14 [c2437990] [c12677ec] bpf_prog_create_from_user+0x258/0x2b4 [c24379d0] [c027111c] do_seccomp+0x3dc/0x1890 [c2437ac0] [c001d8e0] system_call_exception+0x2dc/0x420 [c2437f30] [c00281ac] ret_from_syscall+0x0/0x2c --- interrupt: c00 at 0x5a1274 NIP:  005a1274 LR: 006a3b3c CTR: 005296c8 REGS: c2437f40 TRAP: 0c00   Tainted: G        W (6.13.0-rc6-PMacG4) MSR:  0200f932 <VEC,EE,PR,FP,ME,IR,DR,RI>  CR: 24004422  XER: 00000000  GPR00: 00000166 af8f3fa0 a7ee3540 00000001 00000000 013b6500 005a5858 0200f932 GPR08: 00000000 00001fe9 013d5fc8 005296c8 2822244c 00b2fcd8 00000000 af8f4b57 GPR16: 00000000 00000001 00000000 00000000 00000000 00000001 00000000 00000002 GPR24: 00afdbb0 00000000 00000000 00000000 006e0004 013ce060 006e7c1c 00000001 NIP [005a1274] 0x5a1274 LR [006a3b3c] 0x6a3b3c --- interrupt: c00  The buggy address belongs to the virtual mapping at [f1000000, f1002000) created by: text_area_cpu_up+0x20/0x190  The buggy address belongs to the physical page: page: refcount:1 mapcount:0 mapping:00000000 index:0x0 pfn:0x76e30 flags: 0x80000000(zone=2) raw: 80000000 00000000 00000122 00000000 00000000 00000000 ffffffff 00000001 raw: 00000000 page dumped because: kasan: bad access detected  Memory state around the buggy address: f0ffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 f0ffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 >f1000000: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 ^ f1000080: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f1000100: f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 f8 ==================================================================  f8 corresponds to KASAN_VMALLOC_INVALID which means the area is not initialised hence not supposed to be used yet.  Powerpc text patching infrastructure allocates a virtual memory area using get_vm_area() and flags it as VM_ALLOC. But that flag is meant to be used for vmalloc() and vmalloc() allocated memory is not supposed to be used before a call to __vmalloc_node_range() which is never called for that area.  That went undetected until commit e4137f08816b ("mm, kasan, kmsan: instrument copy_from/to_kernel_nofault")  The area allocated by text_area_cpu_up() is not vmalloc memory, it is mapped directly on demand when needed by map_kernel_page(). There is no VM flag corresponding to such usage, so just pass no flag. That way the area will be unpoisonned and usable immediately.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21864?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21864" src="https://img.shields.io/badge/CVE--2025--21864-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tcp: drop secpath at the same time as we currently drop dst  Xiumei reported hitting the WARN in xfrm6_tunnel_net_exit while running tests that boil down to: - create a pair of netns - run a basic TCP test over ipcomp6 - delete the pair of netns  The xfrm_state found on spi_byaddr was not deleted at the time we delete the netns, because we still have a reference on it. This lingering reference comes from a secpath (which holds a ref on the xfrm_state), which is still attached to an skb. This skb is not leaked, it ends up on sk_receive_queue and then gets defer-free'd by skb_attempt_defer_free.  The problem happens when we defer freeing an skb (push it on one CPU's defer_list), and don't flush that list before the netns is deleted. In that case, we still have a reference on the xfrm_state that we don't expect at this point.  We already drop the skb's dst in the TCP receive path when it's no longer needed, so let's also drop the secpath. At this point, tcp_filter has already called into the LSM hooks that may require the secpath, so it should not be needed anymore. However, in some of those places, the MPTCP extension has just been attached to the skb, so we cannot simply drop all extensions.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21862?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21862" src="https://img.shields.io/badge/CVE--2025--21862-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drop_monitor: fix incorrect initialization order  Syzkaller reports the following bug:  BUG: spinlock bad magic on CPU#1, syz-executor.0/7995 lock: 0xffff88805303f3e0, .magic: 00000000, .owner: <none>/-1, .owner_cpu: 0 CPU: 1 PID: 7995 Comm: syz-executor.0 Tainted: G            E     5.10.209+ #1 Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 11/12/2020 Call Trace: __dump_stack lib/dump_stack.c:77 [inline] dump_stack+0x119/0x179 lib/dump_stack.c:118 debug_spin_lock_before kernel/locking/spinlock_debug.c:83 [inline] do_raw_spin_lock+0x1f6/0x270 kernel/locking/spinlock_debug.c:112 __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:117 [inline] _raw_spin_lock_irqsave+0x50/0x70 kernel/locking/spinlock.c:159 reset_per_cpu_data+0xe6/0x240 [drop_monitor] net_dm_cmd_trace+0x43d/0x17a0 [drop_monitor] genl_family_rcv_msg_doit+0x22f/0x330 net/netlink/genetlink.c:739 genl_family_rcv_msg net/netlink/genetlink.c:783 [inline] genl_rcv_msg+0x341/0x5a0 net/netlink/genetlink.c:800 netlink_rcv_skb+0x14d/0x440 net/netlink/af_netlink.c:2497 genl_rcv+0x29/0x40 net/netlink/genetlink.c:811 netlink_unicast_kernel net/netlink/af_netlink.c:1322 [inline] netlink_unicast+0x54b/0x800 net/netlink/af_netlink.c:1348 netlink_sendmsg+0x914/0xe00 net/netlink/af_netlink.c:1916 sock_sendmsg_nosec net/socket.c:651 [inline] __sock_sendmsg+0x157/0x190 net/socket.c:663 ____sys_sendmsg+0x712/0x870 net/socket.c:2378 ___sys_sendmsg+0xf8/0x170 net/socket.c:2432 __sys_sendmsg+0xea/0x1b0 net/socket.c:2461 do_syscall_64+0x30/0x40 arch/x86/entry/common.c:46 entry_SYSCALL_64_after_hwframe+0x62/0xc7 RIP: 0033:0x7f3f9815aee9 Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007f3f972bf0c8 EFLAGS: 00000246 ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX: 00007f3f9826d050 RCX: 00007f3f9815aee9 RDX: 0000000020000000 RSI: 0000000020001300 RDI: 0000000000000007 RBP: 00007f3f981b63bd R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000 R13: 000000000000006e R14: 00007f3f9826d050 R15: 00007ffe01ee6768  If drop_monitor is built as a kernel module, syzkaller may have time to send a netlink NET_DM_CMD_START message during the module loading. This will call the net_dm_monitor_start() function that uses a spinlock that has not yet been initialized.  To fix this, let's place resource initialization above the registration of a generic netlink family.  Found by InfoTeCS on behalf of Linux Verification Center (linuxtesting.org) with Syzkaller.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21861?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21861" src="https://img.shields.io/badge/CVE--2025--21861-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm/migrate_device: don't add folio to be freed to LRU in migrate_device_finalize()  If migration succeeded, we called folio_migrate_flags()->mem_cgroup_migrate() to migrate the memcg from the old to the new folio.  This will set memcg_data of the old folio to 0.  Similarly, if migration failed, memcg_data of the dst folio is left unset.  If we call folio_putback_lru() on such folios (memcg_data == 0), we will add the folio to be freed to the LRU, making memcg code unhappy.  Running the hmm selftests:  # ./hmm-tests ... #  RUN           hmm.hmm_device_private.migrate ... [  102.078007][T14893] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x7ff27d200 pfn:0x13cc00 [  102.079974][T14893] anon flags: 0x17ff00000020018(uptodate|dirty|swapbacked|node=0|zone=2|lastcpupid=0x7ff) [  102.082037][T14893] raw: 017ff00000020018 dead000000000100 dead000000000122 ffff8881353896c9 [  102.083687][T14893] raw: 00000007ff27d200 0000000000000000 00000001ffffffff 0000000000000000 [  102.085331][T14893] page dumped because: VM_WARN_ON_ONCE_FOLIO(!memcg && !mem_cgroup_disabled()) [  102.087230][T14893] ------------[ cut here ]------------ [  102.088279][T14893] WARNING: CPU: 0 PID: 14893 at ./include/linux/memcontrol.h:726 folio_lruvec_lock_irqsave+0x10e/0x170 [  102.090478][T14893] Modules linked in: [  102.091244][T14893] CPU: 0 UID: 0 PID: 14893 Comm: hmm-tests Not tainted 6.13.0-09623-g6c216bc522fd #151 [  102.093089][T14893] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-2.fc40 04/01/2014 [  102.094848][T14893] RIP: 0010:folio_lruvec_lock_irqsave+0x10e/0x170 [  102.096104][T14893] Code: ... [  102.099908][T14893] RSP: 0018:ffffc900236c37b0 EFLAGS: 00010293 [  102.101152][T14893] RAX: 0000000000000000 RBX: ffffea0004f30000 RCX: ffffffff8183f426 [  102.102684][T14893] RDX: ffff8881063cb880 RSI: ffffffff81b8117f RDI: ffff8881063cb880 [  102.104227][T14893] RBP: 0000000000000000 R08: 0000000000000005 R09: 0000000000000000 [  102.105757][T14893] R10: 0000000000000001 R11: 0000000000000002 R12: ffffc900236c37d8 [  102.107296][T14893] R13: ffff888277a2bcb0 R14: 000000000000001f R15: 0000000000000000 [  102.108830][T14893] FS:  00007ff27dbdd740(0000) GS:ffff888277a00000(0000) knlGS:0000000000000000 [  102.110643][T14893] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  102.111924][T14893] CR2: 00007ff27d400000 CR3: 000000010866e000 CR4: 0000000000750ef0 [  102.113478][T14893] PKRU: 55555554 [  102.114172][T14893] Call Trace: [  102.114805][T14893]  <TASK> [  102.115397][T14893]  ? folio_lruvec_lock_irqsave+0x10e/0x170 [  102.116547][T14893]  ? __warn.cold+0x110/0x210 [  102.117461][T14893]  ? folio_lruvec_lock_irqsave+0x10e/0x170 [  102.118667][T14893]  ? report_bug+0x1b9/0x320 [  102.119571][T14893]  ? handle_bug+0x54/0x90 [  102.120494][T14893]  ? exc_invalid_op+0x17/0x50 [  102.121433][T14893]  ? asm_exc_invalid_op+0x1a/0x20 [  102.122435][T14893]  ? __wake_up_klogd.part.0+0x76/0xd0 [  102.123506][T14893]  ? dump_page+0x4f/0x60 [  102.124352][T14893]  ? folio_lruvec_lock_irqsave+0x10e/0x170 [  102.125500][T14893]  folio_batch_move_lru+0xd4/0x200 [  102.126577][T14893]  ? __pfx_lru_add+0x10/0x10 [  102.127505][T14893]  __folio_batch_add_and_move+0x391/0x720 [  102.128633][T14893]  ? __pfx_lru_add+0x10/0x10 [  102.129550][T14893]  folio_putback_lru+0x16/0x80 [  102.130564][T14893]  migrate_device_finalize+0x9b/0x530 [  102.131640][T14893]  dmirror_migrate_to_device.constprop.0+0x7c5/0xad0 [  102.133047][T14893]  dmirror_fops_unlocked_ioctl+0x89b/0xc80  Likely, nothing else goes wrong: putting the last folio reference will remove the folio from the LRU again.  So besides memcg complaining, adding the folio to be freed to the LRU is just an unnecessary step.  The new flow resembles what we have in migrate_folio_move(): add the dst to the lru, rem ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21859?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21859" src="https://img.shields.io/badge/CVE--2025--21859-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  USB: gadget: f_midi: f_midi_complete to call queue_work  When using USB MIDI, a lock is attempted to be acquired twice through a re-entrant call to f_midi_transmit, causing a deadlock.  Fix it by using queue_work() to schedule the inner f_midi_transmit() via a high priority work queue from the completion handler.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21857?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21857" src="https://img.shields.io/badge/CVE--2025--21857-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.015%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/sched: cls_api: fix error handling causing NULL dereference  tcf_exts_miss_cookie_base_alloc() calls xa_alloc_cyclic() which can return 1 if the allocation succeeded after wrapping. This was treated as an error, with value 1 returned to caller tcf_exts_init_ex() which sets exts->actions to NULL and returns 1 to caller fl_change().  fl_change() treats err == 1 as success, calling tcf_exts_validate_ex() which calls tcf_action_init() with exts->actions as argument, where it is dereferenced.  Example trace:  BUG: kernel NULL pointer dereference, address: 0000000000000000 CPU: 114 PID: 16151 Comm: handler114 Kdump: loaded Not tainted 5.14.0-503.16.1.el9_5.x86_64 #1 RIP: 0010:tcf_action_init+0x1f8/0x2c0 Call Trace: tcf_action_init+0x1f8/0x2c0 tcf_exts_validate_ex+0x175/0x190 fl_change+0x537/0x1120 [cls_flower]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21854?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21854" src="https://img.shields.io/badge/CVE--2025--21854-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.015%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sockmap, vsock: For connectible sockets allow only connected  sockmap expects all vsocks to have a transport assigned, which is expressed in vsock_proto::psock_update_sk_prot(). However, there is an edge case where an unconnected (connectible) socket may lose its previously assigned transport. This is handled with a NULL check in the vsock/BPF recv path.  Another design detail is that listening vsocks are not supposed to have any transport assigned at all. Which implies they are not supported by the sockmap. But this is complicated by the fact that a socket, before switching to TCP_LISTEN, may have had some transport assigned during a failed connect() attempt. Hence, we may end up with a listening vsock in a sockmap, which blows up quickly:  KASAN: null-ptr-deref in range [0x0000000000000120-0x0000000000000127] CPU: 7 UID: 0 PID: 56 Comm: kworker/7:0 Not tainted 6.14.0-rc1+ Workqueue: vsock-loopback vsock_loopback_work RIP: 0010:vsock_read_skb+0x4b/0x90 Call Trace: sk_psock_verdict_data_ready+0xa4/0x2e0 virtio_transport_recv_pkt+0x1ca8/0x2acc vsock_loopback_work+0x27d/0x3f0 process_one_work+0x846/0x1420 worker_thread+0x5b3/0xf80 kthread+0x35a/0x700 ret_from_fork+0x2d/0x70 ret_from_fork_asm+0x1a/0x30  For connectible sockets, instead of relying solely on the state of vsk->transport, tell sockmap to only allow those representing established connections. This aligns with the behaviour for AF_INET and AF_UNIX.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21853?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21853" src="https://img.shields.io/badge/CVE--2025--21853-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: avoid holding freeze_mutex during mmap operation  We use map->freeze_mutex to prevent races between map_freeze() and memory mapping BPF map contents with writable permissions. The way we naively do this means we'll hold freeze_mutex for entire duration of all the mm and VMA manipulations, which is completely unnecessary. This can potentially also lead to deadlocks, as reported by syzbot in [0].  So, instead, hold freeze_mutex only during writeability checks, bump (proactively) "write active" count for the map, unlock the mutex and proceed with mmap logic. And only if something went wrong during mmap logic, then undo that "write active" counter increment.  [0] https://lore.kernel.org/bpf/678dcbc9.050a0220.303755.0066.GAE@google.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21848?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21848" src="https://img.shields.io/badge/CVE--2025--21848-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfp: bpf: Add check for nfp_app_ctrl_msg_alloc()  Add check for the return value of nfp_app_ctrl_msg_alloc() in nfp_bpf_cmsg_alloc() to prevent null pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21847?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21847" src="https://img.shields.io/badge/CVE--2025--21847-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.015%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: SOF: stream-ipc: Check for cstream nullity in sof_ipc_msg_data()  The nullity of sps->cstream should be checked similarly as it is done in sof_set_stream_data_offset() function. Assuming that it is not NULL if sps->stream is NULL is incorrect and can lead to NULL pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21846?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21846" src="https://img.shields.io/badge/CVE--2025--21846-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  acct: perform last write from workqueue  In [1] it was reported that the acct(2) system call can be used to trigger NULL deref in cases where it is set to write to a file that triggers an internal lookup. This can e.g., happen when pointing acc(2) to /sys/power/resume. At the point the where the write to this file happens the calling task has already exited and called exit_fs(). A lookup will thus trigger a NULL-deref when accessing current->fs.  Reorganize the code so that the the final write happens from the workqueue but with the caller's credentials. This preserves the (strange) permission model and has almost no regression risk.  This api should stop to exist though.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21844?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21844" src="https://img.shields.io/badge/CVE--2025--21844-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: Add check for next_buffer in receive_encrypted_standard()  Add check for the return value of cifs_buf_get() and cifs_small_buf_get() in receive_encrypted_standard() to prevent null pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21833?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21833" src="https://img.shields.io/badge/CVE--2025--21833-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.015%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iommu/vt-d: Avoid use of NULL after WARN_ON_ONCE  There is a WARN_ON_ONCE to catch an unlikely situation when domain_remove_dev_pasid can't find the `pasid`. In case it nevertheless happens we must avoid using a NULL pointer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21820?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21820" src="https://img.shields.io/badge/CVE--2025--21820-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tty: xilinx_uartps: split sysrq handling  lockdep detects the following circular locking dependency:  CPU 0                      CPU 1 ========================== ============================ cdns_uart_isr()            printk() uart_port_lock(port)       console_lock() cdns_uart_console_write() if (!port->sysrq) uart_port_lock(port) uart_handle_break() port->sysrq = ... uart_handle_sysrq_char() printk() console_lock()  The fixed commit attempts to avoid this situation by only taking the port lock in cdns_uart_console_write if port->sysrq unset. However, if (as shown above) cdns_uart_console_write runs before port->sysrq is set, then it will try to take the port lock anyway. This may result in a deadlock.  Fix this by splitting sysrq handling into two parts. We use the prepare helper under the port lock and defer handling until we release the lock.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21814?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21814" src="https://img.shields.io/badge/CVE--2025--21814-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ptp: Ensure info->enable callback is always set  The ioctl and sysfs handlers unconditionally call the ->enable callback. Not all drivers implement that callback, leading to NULL dereferences. Example of affected drivers: ptp_s390.c, ptp_vclock.c and ptp_mock.c.  Instead use a dummy callback if no better was specified by the driver.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21809?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21809" src="https://img.shields.io/badge/CVE--2025--21809-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  rxrpc, afs: Fix peer hash locking vs RCU callback  In its address list, afs now retains pointers to and refs on one or more rxrpc_peer objects.  The address list is freed under RCU and at this time, it puts the refs on those peers.  Now, when an rxrpc_peer object runs out of refs, it gets removed from the peer hash table and, for that, rxrpc has to take a spinlock.  However, it is now being called from afs's RCU cleanup, which takes place in BH context - but it is just taking an ordinary spinlock.  The put may also be called from non-BH context, and so there exists the possibility of deadlock if the BH-based RCU cleanup happens whilst the hash spinlock is held.  This led to the attached lockdep complaint.  Fix this by changing spinlocks of rxnet->peer_hash_lock back to BH-disabling locks.  ================================ WARNING: inconsistent lock state 6.13.0-rc5-build2+ #1223 Tainted: G            E -------------------------------- inconsistent {SOFTIRQ-ON-W} -> {IN-SOFTIRQ-W} usage. swapper/1/0 [HC0[0]:SC1[1]:HE1:SE0] takes: ffff88810babe228 (&rxnet->peer_hash_lock){+.?.}-{3:3}, at: rxrpc_put_peer+0xcb/0x180 {SOFTIRQ-ON-W} state was registered at: mark_usage+0x164/0x180 __lock_acquire+0x544/0x990 lock_acquire.part.0+0x103/0x280 _raw_spin_lock+0x2f/0x40 rxrpc_peer_keepalive_worker+0x144/0x440 process_one_work+0x486/0x7c0 process_scheduled_works+0x73/0x90 worker_thread+0x1c8/0x2a0 kthread+0x19b/0x1b0 ret_from_fork+0x24/0x40 ret_from_fork_asm+0x1a/0x30 irq event stamp: 972402 hardirqs last  enabled at (972402): [<ffffffff8244360e>] _raw_spin_unlock_irqrestore+0x2e/0x50 hardirqs last disabled at (972401): [<ffffffff82443328>] _raw_spin_lock_irqsave+0x18/0x60 softirqs last  enabled at (972300): [<ffffffff810ffbbe>] handle_softirqs+0x3ee/0x430 softirqs last disabled at (972313): [<ffffffff810ffc54>] __irq_exit_rcu+0x44/0x110  other info that might help us debug this: Possible unsafe locking scenario: CPU0 ---- lock(&rxnet->peer_hash_lock); <Interrupt> lock(&rxnet->peer_hash_lock);  *** DEADLOCK *** 1 lock held by swapper/1/0: #0: ffffffff83576be0 (rcu_callback){....}-{0:0}, at: rcu_lock_acquire+0x7/0x30  stack backtrace: CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Tainted: G            E 6.13.0-rc5-build2+ #1223 Tainted: [E]=UNSIGNED_MODULE Hardware name: ASUS All Series/H97-PLUS, BIOS 2306 10/09/2014 Call Trace: <IRQ> dump_stack_lvl+0x57/0x80 print_usage_bug.part.0+0x227/0x240 valid_state+0x53/0x70 mark_lock_irq+0xa5/0x2f0 mark_lock+0xf7/0x170 mark_usage+0xe1/0x180 __lock_acquire+0x544/0x990 lock_acquire.part.0+0x103/0x280 _raw_spin_lock+0x2f/0x40 rxrpc_put_peer+0xcb/0x180 afs_free_addrlist+0x46/0x90 [kafs] rcu_do_batch+0x2d2/0x640 rcu_core+0x2f7/0x350 handle_softirqs+0x1ee/0x430 __irq_exit_rcu+0x44/0x110 irq_exit_rcu+0xa/0x30 sysvec_apic_timer_interrupt+0x7f/0xa0 </IRQ>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21798?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21798" src="https://img.shields.io/badge/CVE--2025--21798-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  firewire: test: Fix potential null dereference in firewire kunit test  kunit_kzalloc() may return a NULL pointer, dereferencing it without NULL check may lead to NULL dereference. Add a NULL check for test_state.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21793?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21793" src="https://img.shields.io/badge/CVE--2025--21793-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  spi: sn-f-ospi: Fix division by zero  When there is no dummy cycle in the spi-nor commands, both dummy bus cycle bytes and width are zero. Because of the cpu's warning when divided by zero, the warning should be avoided. Return just zero to avoid such calculations.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21792?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21792" src="https://img.shields.io/badge/CVE--2025--21792-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ax25: Fix refcount leak caused by setting SO_BINDTODEVICE sockopt  If an AX25 device is bound to a socket by setting the SO_BINDTODEVICE socket option, a refcount leak will occur in ax25_release().  Commit 9fd75b66b8f6 ("ax25: Fix refcount leaks caused by ax25_cb_del()") added decrement of device refcounts in ax25_release(). In order for that to work correctly the refcounts must already be incremented when the device is bound to the socket. An AX25 device can be bound to a socket by either calling ax25_bind() or setting SO_BINDTODEVICE socket option. In both cases the refcounts should be incremented, but in fact it is done only in ax25_bind().  This bug leads to the following issue reported by Syzkaller:  ================================================================ refcount_t: decrement hit 0; leaking memory. WARNING: CPU: 1 PID: 5932 at lib/refcount.c:31 refcount_warn_saturate+0x1ed/0x210 lib/refcount.c:31 Modules linked in: CPU: 1 UID: 0 PID: 5932 Comm: syz-executor424 Not tainted 6.13.0-rc4-syzkaller-00110-g4099a71718b0 #0 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 RIP: 0010:refcount_warn_saturate+0x1ed/0x210 lib/refcount.c:31 Call Trace: <TASK> __refcount_dec include/linux/refcount.h:336 [inline] refcount_dec include/linux/refcount.h:351 [inline] ref_tracker_free+0x710/0x820 lib/ref_tracker.c:236 netdev_tracker_free include/linux/netdevice.h:4156 [inline] netdev_put include/linux/netdevice.h:4173 [inline] netdev_put include/linux/netdevice.h:4169 [inline] ax25_release+0x33f/0xa10 net/ax25/af_ax25.c:1069 __sock_release+0xb0/0x270 net/socket.c:640 sock_close+0x1c/0x30 net/socket.c:1408 ... do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f ... </TASK> ================================================================  Fix the implementation of ax25_setsockopt() by adding increment of refcounts for the new device bound, and decrement of refcounts for the old unbound device.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21790?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21790" src="https://img.shields.io/badge/CVE--2025--21790-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vxlan: check vxlan_vnigroup_init() return value  vxlan_init() must check vxlan_vnigroup_init() success otherwise a crash happens later, spotted by syzbot.  Oops: general protection fault, probably for non-canonical address 0xdffffc000000002c: 0000 [#1] PREEMPT SMP KASAN NOPTI KASAN: null-ptr-deref in range [0x0000000000000160-0x0000000000000167] CPU: 0 UID: 0 PID: 7313 Comm: syz-executor147 Not tainted 6.14.0-rc1-syzkaller-00276-g69b54314c975 #0 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 RIP: 0010:vxlan_vnigroup_uninit+0x89/0x500 drivers/net/vxlan/vxlan_vnifilter.c:912 Code: 00 48 8b 44 24 08 4c 8b b0 98 41 00 00 49 8d 86 60 01 00 00 48 89 c2 48 89 44 24 10 48 b8 00 00 00 00 00 fc ff df 48 c1 ea 03 <80> 3c 02 00 0f 85 4d 04 00 00 49 8b 86 60 01 00 00 48 ba 00 00 00 RSP: 0018:ffffc9000cc1eea8 EFLAGS: 00010202 RAX: dffffc0000000000 RBX: 0000000000000001 RCX: ffffffff8672effb RDX: 000000000000002c RSI: ffffffff8672ecb9 RDI: ffff8880461b4f18 RBP: ffff8880461b4ef4 R08: 0000000000000001 R09: 0000000000000000 R10: 0000000000000001 R11: 0000000000000000 R12: 0000000000020000 R13: ffff8880461b0d80 R14: 0000000000000000 R15: dffffc0000000000 FS:  00007fecfa95d6c0(0000) GS:ffff88806a600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fecfa95cfb8 CR3: 000000004472c000 CR4: 0000000000352ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> vxlan_uninit+0x1ab/0x200 drivers/net/vxlan/vxlan_core.c:2942 unregister_netdevice_many_notify+0x12d6/0x1f30 net/core/dev.c:11824 unregister_netdevice_many net/core/dev.c:11866 [inline] unregister_netdevice_queue+0x307/0x3f0 net/core/dev.c:11736 register_netdevice+0x1829/0x1eb0 net/core/dev.c:10901 __vxlan_dev_create+0x7c6/0xa30 drivers/net/vxlan/vxlan_core.c:3981 vxlan_newlink+0xd1/0x130 drivers/net/vxlan/vxlan_core.c:4407 rtnl_newlink_create net/core/rtnetlink.c:3795 [inline] __rtnl_newlink net/core/rtnetlink.c:3906 [inline]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21787?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21787" src="https://img.shields.io/badge/CVE--2025--21787-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  team: better TEAM_OPTION_TYPE_STRING validation  syzbot reported following splat [1]  Make sure user-provided data contains one nul byte.  [1] BUG: KMSAN: uninit-value in string_nocheck lib/vsprintf.c:633 [inline] BUG: KMSAN: uninit-value in string+0x3ec/0x5f0 lib/vsprintf.c:714 string_nocheck lib/vsprintf.c:633 [inline] string+0x3ec/0x5f0 lib/vsprintf.c:714 vsnprintf+0xa5d/0x1960 lib/vsprintf.c:2843 __request_module+0x252/0x9f0 kernel/module/kmod.c:149 team_mode_get drivers/net/team/team_core.c:480 [inline] team_change_mode drivers/net/team/team_core.c:607 [inline] team_mode_option_set+0x437/0x970 drivers/net/team/team_core.c:1401 team_option_set drivers/net/team/team_core.c:375 [inline] team_nl_options_set_doit+0x1339/0x1f90 drivers/net/team/team_core.c:2662 genl_family_rcv_msg_doit net/netlink/genetlink.c:1115 [inline] genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline] genl_rcv_msg+0x1214/0x12c0 net/netlink/genetlink.c:1210 netlink_rcv_skb+0x375/0x650 net/netlink/af_netlink.c:2543 genl_rcv+0x40/0x60 net/netlink/genetlink.c:1219 netlink_unicast_kernel net/netlink/af_netlink.c:1322 [inline] netlink_unicast+0xf52/0x1260 net/netlink/af_netlink.c:1348 netlink_sendmsg+0x10da/0x11e0 net/netlink/af_netlink.c:1892 sock_sendmsg_nosec net/socket.c:718 [inline] __sock_sendmsg+0x30f/0x380 net/socket.c:733 ____sys_sendmsg+0x877/0xb60 net/socket.c:2573 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2627 __sys_sendmsg net/socket.c:2659 [inline] __do_sys_sendmsg net/socket.c:2664 [inline] __se_sys_sendmsg net/socket.c:2662 [inline] __x64_sys_sendmsg+0x212/0x3c0 net/socket.c:2662 x64_sys_call+0x2ed6/0x3c30 arch/x86/include/generated/asm/syscalls_64.h:47 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21783?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21783" src="https://img.shields.io/badge/CVE--2025--21783-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gpiolib: Fix crash on error in gpiochip_get_ngpios()  The gpiochip_get_ngpios() uses chip_*() macros to print messages. However these macros rely on gpiodev to be initialised and set, which is not the case when called via bgpio_init(). In such a case the printing messages will crash on NULL pointer dereference. Replace chip_*() macros by the respective dev_*() ones to avoid such crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21779?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21779" src="https://img.shields.io/badge/CVE--2025--21779-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  KVM: x86: Reject Hyper-V's SEND_IPI hypercalls if local APIC isn't in-kernel  Advertise support for Hyper-V's SEND_IPI and SEND_IPI_EX hypercalls if and only if the local API is emulated/virtualized by KVM, and explicitly reject said hypercalls if the local APIC is emulated in userspace, i.e. don't rely on userspace to opt-in to KVM_CAP_HYPERV_ENFORCE_CPUID.  Rejecting SEND_IPI and SEND_IPI_EX fixes a NULL-pointer dereference if Hyper-V enlightenments are exposed to the guest without an in-kernel local APIC:  dump_stack+0xbe/0xfd __kasan_report.cold+0x34/0x84 kasan_report+0x3a/0x50 __apic_accept_irq+0x3a/0x5c0 kvm_hv_send_ipi.isra.0+0x34e/0x820 kvm_hv_hypercall+0x8d9/0x9d0 kvm_emulate_hypercall+0x506/0x7e0 __vmx_handle_exit+0x283/0xb60 vmx_handle_exit+0x1d/0xd0 vcpu_enter_guest+0x16b0/0x24c0 vcpu_run+0xc0/0x550 kvm_arch_vcpu_ioctl_run+0x170/0x6d0 kvm_vcpu_ioctl+0x413/0xb20 __se_sys_ioctl+0x111/0x160 do_syscal1_64+0x30/0x40 entry_SYSCALL_64_after_hwframe+0x67/0xd1  Note, checking the sending vCPU is sufficient, as the per-VM irqchip_mode can't be modified after vCPUs are created, i.e. if one vCPU has an in-kernel local APIC, then all vCPUs have an in-kernel local APIC.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21776?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21776" src="https://img.shields.io/badge/CVE--2025--21776-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  USB: hub: Ignore non-compliant devices with too many configs or interfaces  Robert Morris created a test program which can cause usb_hub_to_struct_hub() to dereference a NULL or inappropriate pointer:  Oops: general protection fault, probably for non-canonical address 0xcccccccccccccccc: 0000 [#1] SMP DEBUG_PAGEALLOC PTI CPU: 7 UID: 0 PID: 117 Comm: kworker/7:1 Not tainted 6.13.0-rc3-00017-gf44d154d6e3d #14 Hardware name: FreeBSD BHYVE/BHYVE, BIOS 14.0 10/17/2021 Workqueue: usb_hub_wq hub_event RIP: 0010:usb_hub_adjust_deviceremovable+0x78/0x110 ... Call Trace: <TASK> ? die_addr+0x31/0x80 ? exc_general_protection+0x1b4/0x3c0 ? asm_exc_general_protection+0x26/0x30 ? usb_hub_adjust_deviceremovable+0x78/0x110 hub_probe+0x7c7/0xab0 usb_probe_interface+0x14b/0x350 really_probe+0xd0/0x2d0 ? __pfx___device_attach_driver+0x10/0x10 __driver_probe_device+0x6e/0x110 driver_probe_device+0x1a/0x90 __device_attach_driver+0x7e/0xc0 bus_for_each_drv+0x7f/0xd0 __device_attach+0xaa/0x1a0 bus_probe_device+0x8b/0xa0 device_add+0x62e/0x810 usb_set_configuration+0x65d/0x990 usb_generic_driver_probe+0x4b/0x70 usb_probe_device+0x36/0xd0  The cause of this error is that the device has two interfaces, and the hub driver binds to interface 1 instead of interface 0, which is where usb_hub_to_struct_hub() looks.  We can prevent the problem from occurring by refusing to accept hub devices that violate the USB spec by having more than one configuration or interface.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21775?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21775" src="https://img.shields.io/badge/CVE--2025--21775-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  can: ctucanfd: handle skb allocation failure  If skb allocation fails, the pointer to struct can_frame is NULL. This is actually handled everywhere inside ctucan_err_interrupt() except for the only place.  Add the missed NULL check.  Found by Linux Verification Center (linuxtesting.org) with SVACE static analysis tool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21773?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21773" src="https://img.shields.io/badge/CVE--2025--21773-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  can: etas_es58x: fix potential NULL pointer dereference on udev->serial  The driver assumed that es58x_dev->udev->serial could never be NULL. While this is true on commercially available devices, an attacker could spoof the device identity providing a NULL USB serial number. That would trigger a NULL pointer dereference.  Add a check on es58x_dev->udev->serial before accessing it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21749?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21749" src="https://img.shields.io/badge/CVE--2025--21749-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: rose: lock the socket in rose_bind()  syzbot reported a soft lockup in rose_loopback_timer(), with a repro calling bind() from multiple threads.  rose_bind() must lock the socket to avoid this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21748?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21748" src="https://img.shields.io/badge/CVE--2025--21748-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: fix integer overflows on 32 bit systems  On 32bit systems the addition operations in ipc_msg_alloc() can potentially overflow leading to memory corruption. Add bounds checking using KSMBD_IPC_MAX_PAYLOAD to avoid overflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21745?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21745" src="https://img.shields.io/badge/CVE--2025--21745-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  blk-cgroup: Fix class @block_class's subsystem refcount leakage  blkcg_fill_root_iostats() iterates over @block_class's devices by class_dev_iter_(init|next)(), but does not end iterating with class_dev_iter_exit(), so causes the class's subsystem refcount leakage.  Fix by ending the iterating with class_dev_iter_exit().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21744?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21744" src="https://img.shields.io/badge/CVE--2025--21744-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: brcmfmac: fix NULL pointer dereference in brcmf_txfinalize()  On removal of the device or unloading of the kernel module a potential NULL pointer dereference occurs.  The following sequence deletes the interface:  brcmf_detach() brcmf_remove_interface() brcmf_del_if()  Inside the brcmf_del_if() function the drvr->if2bss[ifidx] is updated to BRCMF_BSSIDX_INVALID (-1) if the bsscfgidx matches.  After brcmf_remove_interface() call the brcmf_proto_detach() function is called providing the following sequence:  brcmf_detach() brcmf_proto_detach() brcmf_proto_msgbuf_detach() brcmf_flowring_detach() brcmf_msgbuf_delete_flowring() brcmf_msgbuf_remove_flowring() brcmf_flowring_delete() brcmf_get_ifp() brcmf_txfinalize()  Since brcmf_get_ip() can and actually will return NULL in this case the call to brcmf_txfinalize() will result in a NULL pointer dereference inside brcmf_txfinalize() when trying to update ifp->ndev->stats.tx_errors.  This will only happen if a flowring still has an skb.  Although the NULL pointer dereference has only been seen when trying to update the tx statistic, all other uses of the ifp pointer have been guarded as well with an early return if ifp is NULL.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21736?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21736" src="https://img.shields.io/badge/CVE--2025--21736-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nilfs2: fix possible int overflows in nilfs_fiemap()  Since nilfs_bmap_lookup_contig() in nilfs_fiemap() calculates its result by being prepared to go through potentially maxblocks == INT_MAX blocks, the value in n may experience an overflow caused by left shift of blkbits.  While it is extremely unlikely to occur, play it safe and cast right hand expression to wider type to mitigate the issue.  Found by Linux Verification Center (linuxtesting.org) with static analysis tool SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21723?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21723" src="https://img.shields.io/badge/CVE--2025--21723-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: mpi3mr: Fix possible crash when setting up bsg fails  If bsg_setup_queue() fails, the bsg_queue is assigned a non-NULL value. Consequently, in mpi3mr_bsg_exit(), the condition "if(!mrioc->bsg_queue)" will not be satisfied, preventing execution from entering bsg_remove_queue(), which could lead to the following crash:  BUG: kernel NULL pointer dereference, address: 000000000000041c Call Trace: <TASK> mpi3mr_bsg_exit+0x1f/0x50 [mpi3mr] mpi3mr_remove+0x6f/0x340 [mpi3mr] pci_device_remove+0x3f/0xb0 device_release_driver_internal+0x19d/0x220 unbind_store+0xa4/0xb0 kernfs_fop_write_iter+0x11f/0x200 vfs_write+0x1fc/0x3e0 ksys_write+0x67/0xe0 do_syscall_64+0x38/0x80 entry_SYSCALL_64_after_hwframe+0x78/0xe2

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21716?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21716" src="https://img.shields.io/badge/CVE--2025--21716-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vxlan: Fix uninit-value in vxlan_vnifilter_dump()  KMSAN reported an uninit-value access in vxlan_vnifilter_dump() [1].  If the length of the netlink message payload is less than sizeof(struct tunnel_msg), vxlan_vnifilter_dump() accesses bytes beyond the message. This can lead to uninit-value access. Fix this by returning an error in such situations.  [1] BUG: KMSAN: uninit-value in vxlan_vnifilter_dump+0x328/0x920 drivers/net/vxlan/vxlan_vnifilter.c:422 vxlan_vnifilter_dump+0x328/0x920 drivers/net/vxlan/vxlan_vnifilter.c:422 rtnl_dumpit+0xd5/0x2f0 net/core/rtnetlink.c:6786 netlink_dump+0x93e/0x15f0 net/netlink/af_netlink.c:2317 __netlink_dump_start+0x716/0xd60 net/netlink/af_netlink.c:2432 netlink_dump_start include/linux/netlink.h:340 [inline] rtnetlink_dump_start net/core/rtnetlink.c:6815 [inline] rtnetlink_rcv_msg+0x1256/0x14a0 net/core/rtnetlink.c:6882 netlink_rcv_skb+0x467/0x660 net/netlink/af_netlink.c:2542 rtnetlink_rcv+0x35/0x40 net/core/rtnetlink.c:6944 netlink_unicast_kernel net/netlink/af_netlink.c:1321 [inline] netlink_unicast+0xed6/0x1290 net/netlink/af_netlink.c:1347 netlink_sendmsg+0x1092/0x1230 net/netlink/af_netlink.c:1891 sock_sendmsg_nosec net/socket.c:711 [inline] __sock_sendmsg+0x330/0x3d0 net/socket.c:726 ____sys_sendmsg+0x7f4/0xb50 net/socket.c:2583 ___sys_sendmsg+0x271/0x3b0 net/socket.c:2637 __sys_sendmsg net/socket.c:2669 [inline] __do_sys_sendmsg net/socket.c:2674 [inline] __se_sys_sendmsg net/socket.c:2672 [inline] __x64_sys_sendmsg+0x211/0x3e0 net/socket.c:2672 x64_sys_call+0x3878/0x3d90 arch/x86/include/generated/asm/syscalls_64.h:47 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xd9/0x1d0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  Uninit was created at: slab_post_alloc_hook mm/slub.c:4110 [inline] slab_alloc_node mm/slub.c:4153 [inline] kmem_cache_alloc_node_noprof+0x800/0xe80 mm/slub.c:4205 kmalloc_reserve+0x13b/0x4b0 net/core/skbuff.c:587 __alloc_skb+0x347/0x7d0 net/core/skbuff.c:678 alloc_skb include/linux/skbuff.h:1323 [inline] netlink_alloc_large_skb+0xa5/0x280 net/netlink/af_netlink.c:1196 netlink_sendmsg+0xac9/0x1230 net/netlink/af_netlink.c:1866 sock_sendmsg_nosec net/socket.c:711 [inline] __sock_sendmsg+0x330/0x3d0 net/socket.c:726 ____sys_sendmsg+0x7f4/0xb50 net/socket.c:2583 ___sys_sendmsg+0x271/0x3b0 net/socket.c:2637 __sys_sendmsg net/socket.c:2669 [inline] __do_sys_sendmsg net/socket.c:2674 [inline] __se_sys_sendmsg net/socket.c:2672 [inline] __x64_sys_sendmsg+0x211/0x3e0 net/socket.c:2672 x64_sys_call+0x3878/0x3d90 arch/x86/include/generated/asm/syscalls_64.h:47 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xd9/0x1d0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  CPU: 0 UID: 0 PID: 30991 Comm: syz.4.10630 Not tainted 6.12.0-10694-gc44daa7e3c73 #29 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-3.fc41 04/01/2014

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21711?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21711" src="https://img.shields.io/badge/CVE--2025--21711-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/rose: prevent integer overflows in rose_setsockopt()  In case of possible unpredictably large arguments passed to rose_setsockopt() and multiplied by extra values on top of that, integer overflows may occur.  Do the safest minimum and fix these issues by checking the contents of 'opt' and returning -EINVAL if they are too large. Also, switch to unsigned int and remove useless check for negative 'opt' in ROSE_IDLE case.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21707?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21707" src="https://img.shields.io/badge/CVE--2025--21707-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: consolidate suboption status  MPTCP maintains the received sub-options status is the bitmask carrying the received suboptions and in several bitfields carrying per suboption additional info.  Zeroing the bitmask before parsing is not enough to ensure a consistent status, and the MPTCP code has to additionally clear some bitfiled depending on the actually parsed suboption.  The above schema is fragile, and syzbot managed to trigger a path where a relevant bitfield is not cleared/initialized:  BUG: KMSAN: uninit-value in __mptcp_expand_seq net/mptcp/options.c:1030 [inline] BUG: KMSAN: uninit-value in mptcp_expand_seq net/mptcp/protocol.h:864 [inline] BUG: KMSAN: uninit-value in ack_update_msk net/mptcp/options.c:1060 [inline] BUG: KMSAN: uninit-value in mptcp_incoming_options+0x2036/0x3d30 net/mptcp/options.c:1209 __mptcp_expand_seq net/mptcp/options.c:1030 [inline] mptcp_expand_seq net/mptcp/protocol.h:864 [inline] ack_update_msk net/mptcp/options.c:1060 [inline] mptcp_incoming_options+0x2036/0x3d30 net/mptcp/options.c:1209 tcp_data_queue+0xb4/0x7be0 net/ipv4/tcp_input.c:5233 tcp_rcv_established+0x1061/0x2510 net/ipv4/tcp_input.c:6264 tcp_v4_do_rcv+0x7f3/0x11a0 net/ipv4/tcp_ipv4.c:1916 tcp_v4_rcv+0x51df/0x5750 net/ipv4/tcp_ipv4.c:2351 ip_protocol_deliver_rcu+0x2a3/0x13d0 net/ipv4/ip_input.c:205 ip_local_deliver_finish+0x336/0x500 net/ipv4/ip_input.c:233 NF_HOOK include/linux/netfilter.h:314 [inline] ip_local_deliver+0x21f/0x490 net/ipv4/ip_input.c:254 dst_input include/net/dst.h:460 [inline] ip_rcv_finish+0x4a2/0x520 net/ipv4/ip_input.c:447 NF_HOOK include/linux/netfilter.h:314 [inline] ip_rcv+0xcd/0x380 net/ipv4/ip_input.c:567 __netif_receive_skb_one_core net/core/dev.c:5704 [inline] __netif_receive_skb+0x319/0xa00 net/core/dev.c:5817 process_backlog+0x4ad/0xa50 net/core/dev.c:6149 __napi_poll+0xe7/0x980 net/core/dev.c:6902 napi_poll net/core/dev.c:6971 [inline] net_rx_action+0xa5a/0x19b0 net/core/dev.c:7093 handle_softirqs+0x1a0/0x7c0 kernel/softirq.c:561 __do_softirq+0x14/0x1a kernel/softirq.c:595 do_softirq+0x9a/0x100 kernel/softirq.c:462 __local_bh_enable_ip+0x9f/0xb0 kernel/softirq.c:389 local_bh_enable include/linux/bottom_half.h:33 [inline] rcu_read_unlock_bh include/linux/rcupdate.h:919 [inline] __dev_queue_xmit+0x2758/0x57d0 net/core/dev.c:4493 dev_queue_xmit include/linux/netdevice.h:3168 [inline] neigh_hh_output include/net/neighbour.h:523 [inline] neigh_output include/net/neighbour.h:537 [inline] ip_finish_output2+0x187c/0x1b70 net/ipv4/ip_output.c:236 __ip_finish_output+0x287/0x810 ip_finish_output+0x4b/0x600 net/ipv4/ip_output.c:324 NF_HOOK_COND include/linux/netfilter.h:303 [inline] ip_output+0x15f/0x3f0 net/ipv4/ip_output.c:434 dst_output include/net/dst.h:450 [inline] ip_local_out net/ipv4/ip_output.c:130 [inline] __ip_queue_xmit+0x1f2a/0x20d0 net/ipv4/ip_output.c:536 ip_queue_xmit+0x60/0x80 net/ipv4/ip_output.c:550 __tcp_transmit_skb+0x3cea/0x4900 net/ipv4/tcp_output.c:1468 tcp_transmit_skb net/ipv4/tcp_output.c:1486 [inline] tcp_write_xmit+0x3b90/0x9070 net/ipv4/tcp_output.c:2829 __tcp_push_pending_frames+0xc4/0x380 net/ipv4/tcp_output.c:3012 tcp_send_fin+0x9f6/0xf50 net/ipv4/tcp_output.c:3618 __tcp_close+0x140c/0x1550 net/ipv4/tcp.c:3130 __mptcp_close_ssk+0x74e/0x16f0 net/mptcp/protocol.c:2496 mptcp_close_ssk+0x26b/0x2c0 net/mptcp/protocol.c:2550 mptcp_pm_nl_rm_addr_or_subflow+0x635/0xd10 net/mptcp/pm_netlink.c:889 mptcp_pm_nl_rm_subflow_received net/mptcp/pm_netlink.c:924 [inline] mptcp_pm_flush_addrs_and_subflows net/mptcp/pm_netlink.c:1688 [inline] mptcp_nl_flush_addrs_list net/mptcp/pm_netlink.c:1709 [inline] mptcp_pm_nl_flush_addrs_doit+0xe10/0x1630 net/mptcp/pm_netlink.c:1750 genl_family_rcv_msg_doit net/netlink/genetlink.c:1115 [inline]  ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21699?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21699" src="https://img.shields.io/badge/CVE--2025--21699-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gfs2: Truncate address space when flipping GFS2_DIF_JDATA flag  Truncate an inode's address space when flipping the GFS2_DIF_JDATA flag: depending on that flag, the pages in the address space will either use buffer heads or iomap_folio_state structs, and we cannot mix the two.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21697?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21697" src="https://img.shields.io/badge/CVE--2025--21697-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/v3d: Ensure job pointer is set to NULL after job completion  After a job completes, the corresponding pointer in the device must be set to NULL. Failing to do so triggers a warning when unloading the driver, as it appears the job is still active. To prevent this, assign the job pointer to NULL after completing the job, indicating the job has finished.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21696?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21696" src="https://img.shields.io/badge/CVE--2025--21696-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm: clear uffd-wp PTE/PMD state on mremap()  When mremap()ing a memory region previously registered with userfaultfd as write-protected but without UFFD_FEATURE_EVENT_REMAP, an inconsistency in flag clearing leads to a mismatch between the vma flags (which have uffd-wp cleared) and the pte/pmd flags (which do not have uffd-wp cleared).  This mismatch causes a subsequent mprotect(PROT_WRITE) to trigger a warning in page_table_check_pte_flags() due to setting the pte to writable while uffd-wp is still set.  Fix this by always explicitly clearing the uffd-wp pte/pmd flags on any such mremap() so that the values are consistent with the existing clearing of VM_UFFD_WP.  Be careful to clear the logical flag regardless of its physical form; a PTE bit, a swap PTE bit, or a PTE marker.  Cover PTE, huge PMD and hugetlb paths.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21694?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21694" src="https://img.shields.io/badge/CVE--2025--21694-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs/proc: fix softlockup in __read_vmcore (part 2)  Since commit 5cbcb62dddf5 ("fs/proc: fix softlockup in __read_vmcore") the number of softlockups in __read_vmcore at kdump time have gone down, but they still happen sometimes.  In a memory constrained environment like the kdump image, a softlockup is not just a harmless message, but it can interfere with things like RCU freeing memory, causing the crashdump to get stuck.  The second loop in __read_vmcore has a lot more opportunities for natural sleep points, like scheduling out while waiting for a data write to happen, but apparently that is not always enough.  Add a cond_resched() to the second loop in __read_vmcore to (hopefully) get rid of the softlockups.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21690?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21690" src="https://img.shields.io/badge/CVE--2025--21690-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: storvsc: Ratelimit warning logs to prevent VM denial of service  If there's a persistent error in the hypervisor, the SCSI warning for failed I/O can flood the kernel log and max out CPU utilization, preventing troubleshooting from the VM side. Ratelimit the warning so it doesn't DoS the VM.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21689?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21689" src="https://img.shields.io/badge/CVE--2025--21689-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  USB: serial: quatech2: fix null-ptr-deref in qt2_process_read_urb()  This patch addresses a null-ptr-deref in qt2_process_read_urb() due to an incorrect bounds check in the following:  if (newport > serial->num_ports) { dev_err(&port->dev, "%s - port change to invalid port: %i\n", __func__, newport); break; }  The condition doesn't account for the valid range of the serial->port buffer, which is from 0 to serial->num_ports - 1. When newport is equal to serial->num_ports, the assignment of "port" in the following code is out-of-bounds and NULL:  serial_priv->current_port = newport; port = serial->port[serial_priv->current_port];  The fix checks if newport is greater than or equal to serial->num_ports indicating it is out-of-bounds.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21684?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21684" src="https://img.shields.io/badge/CVE--2025--21684-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gpio: xilinx: Convert gpio_lock to raw spinlock  irq_chip functions may be called in raw spinlock context. Therefore, we must also use a raw spinlock for our own internal locking.  This fixes the following lockdep splat:  [    5.349336] ============================= [    5.353349] [ BUG: Invalid wait context ] [    5.357361] 6.13.0-rc5+ #69 Tainted: G        W [    5.363031] ----------------------------- [    5.367045] kworker/u17:1/44 is trying to lock: [    5.371587] ffffff88018b02c0 (&chip->gpio_lock){....}-{3:3}, at: xgpio_irq_unmask (drivers/gpio/gpio-xilinx.c:433 (discriminator 8)) [    5.380079] other info that might help us debug this: [    5.385138] context-{5:5} [    5.387762] 5 locks held by kworker/u17:1/44: [    5.392123] #0: ffffff8800014958 ((wq_completion)events_unbound){+.+.}-{0:0}, at: process_one_work (kernel/workqueue.c:3204) [    5.402260] #1: ffffffc082fcbdd8 (deferred_probe_work){+.+.}-{0:0}, at: process_one_work (kernel/workqueue.c:3205) [    5.411528] #2: ffffff880172c900 (&dev->mutex){....}-{4:4}, at: __device_attach (drivers/base/dd.c:1006) [    5.419929] #3: ffffff88039c8268 (request_class#2){+.+.}-{4:4}, at: __setup_irq (kernel/irq/internals.h:156 kernel/irq/manage.c:1596) [    5.428331] #4: ffffff88039c80c8 (lock_class#2){....}-{2:2}, at: __setup_irq (kernel/irq/manage.c:1614) [    5.436472] stack backtrace: [    5.439359] CPU: 2 UID: 0 PID: 44 Comm: kworker/u17:1 Tainted: G W          6.13.0-rc5+ #69 [    5.448690] Tainted: [W]=WARN [    5.451656] Hardware name: xlnx,zynqmp (DT) [    5.455845] Workqueue: events_unbound deferred_probe_work_func [    5.461699] Call trace: [    5.464147] show_stack+0x18/0x24 C [    5.467821] dump_stack_lvl (lib/dump_stack.c:123) [    5.471501] dump_stack (lib/dump_stack.c:130) [    5.474824] __lock_acquire (kernel/locking/lockdep.c:4828 kernel/locking/lockdep.c:4898 kernel/locking/lockdep.c:5176) [    5.478758] lock_acquire (arch/arm64/include/asm/percpu.h:40 kernel/locking/lockdep.c:467 kernel/locking/lockdep.c:5851 kernel/locking/lockdep.c:5814) [    5.482429] _raw_spin_lock_irqsave (include/linux/spinlock_api_smp.h:111 kernel/locking/spinlock.c:162) [    5.486797] xgpio_irq_unmask (drivers/gpio/gpio-xilinx.c:433 (discriminator 8)) [    5.490737] irq_enable (kernel/irq/internals.h:236 kernel/irq/chip.c:170 kernel/irq/chip.c:439 kernel/irq/chip.c:432 kernel/irq/chip.c:345) [    5.494060] __irq_startup (kernel/irq/internals.h:241 kernel/irq/chip.c:180 kernel/irq/chip.c:250) [    5.497645] irq_startup (kernel/irq/chip.c:270) [    5.501143] __setup_irq (kernel/irq/manage.c:1807) [    5.504728] request_threaded_irq (kernel/irq/manage.c:2208)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21683?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21683" src="https://img.shields.io/badge/CVE--2025--21683-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Fix bpf_sk_select_reuseport() memory leak  As pointed out in the original comment, lookup in sockmap can return a TCP ESTABLISHED socket. Such TCP socket may have had SO_ATTACH_REUSEPORT_EBPF set before it was ESTABLISHED. In other words, a non-NULL sk_reuseport_cb does not imply a non-refcounted socket.  Drop sk's reference in both error paths.  unreferenced object 0xffff888101911800 (size 2048): comm "test_progs", pid 44109, jiffies 4297131437 hex dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ 80 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ backtrace (crc 9336483b): __kmalloc_noprof+0x3bf/0x560 __reuseport_alloc+0x1d/0x40 reuseport_alloc+0xca/0x150 reuseport_attach_prog+0x87/0x140 sk_reuseport_attach_bpf+0xc8/0x100 sk_setsockopt+0x1181/0x1990 do_sock_setsockopt+0x12b/0x160 __sys_setsockopt+0x7b/0xc0 __x64_sys_setsockopt+0x1b/0x30 do_syscall_64+0x93/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21682?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21682" src="https://img.shields.io/badge/CVE--2025--21682-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  eth: bnxt: always recalculate features after XDP clearing, fix null-deref  Recalculate features when XDP is detached.  Before: # ip li set dev eth0 xdp obj xdp_dummy.bpf.o sec xdp # ip li set dev eth0 xdp off # ethtool -k eth0 | grep gro rx-gro-hw: off [requested on]  After: # ip li set dev eth0 xdp obj xdp_dummy.bpf.o sec xdp # ip li set dev eth0 xdp off # ethtool -k eth0 | grep gro rx-gro-hw: on  The fact that HW-GRO doesn't get re-enabled automatically is just a minor annoyance. The real issue is that the features will randomly come back during another reconfiguration which just happens to invoke netdev_update_features(). The driver doesn't handle reconfiguring two things at a time very robustly.  Starting with commit 98ba1d931f61 ("bnxt_en: Fix RSS logic in __bnxt_reserve_rings()") we only reconfigure the RSS hash table if the "effective" number of Rx rings has changed. If HW-GRO is enabled "effective" number of rings is 2x what user sees. So if we are in the bad state, with HW-GRO re-enablement "pending" after XDP off, and we lower the rings by / 2 - the HW-GRO rings doing 2x and the ethtool -L doing / 2 may cancel each other out, and the:  if (old_rx_rings != bp->hw_resc.resv_rx_rings &&  condition in __bnxt_reserve_rings() will be false. The RSS map won't get updated, and we'll crash with:  BUG: kernel NULL pointer dereference, address: 0000000000000168 RIP: 0010:__bnxt_hwrm_vnic_set_rss+0x13a/0x1a0 bnxt_hwrm_vnic_rss_cfg_p5+0x47/0x180 __bnxt_setup_vnic_p5+0x58/0x110 bnxt_init_nic+0xb72/0xf50 __bnxt_open_nic+0x40d/0xab0 bnxt_open_nic+0x2b/0x60 ethtool_set_channels+0x18c/0x1d0  As we try to access a freed ring.  The issue is present since XDP support was added, really, but prior to commit 98ba1d931f61 ("bnxt_en: Fix RSS logic in __bnxt_reserve_rings()") it wasn't causing major issues.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21681?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21681" src="https://img.shields.io/badge/CVE--2025--21681-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  openvswitch: fix lockup on tx to unregistering netdev with carrier  Commit in a fixes tag attempted to fix the issue in the following sequence of calls:  do_output -> ovs_vport_send -> dev_queue_xmit -> __dev_queue_xmit -> netdev_core_pick_tx -> skb_tx_hash  When device is unregistering, the 'dev->real_num_tx_queues' goes to zero and the 'while (unlikely(hash >= qcount))' loop inside the 'skb_tx_hash' becomes infinite, locking up the core forever.  But unfortunately, checking just the carrier status is not enough to fix the issue, because some devices may still be in unregistering state while reporting carrier status OK.  One example of such device is a net/dummy.  It sets carrier ON on start, but it doesn't implement .ndo_stop to set the carrier off. And it makes sense, because dummy doesn't really have a carrier. Therefore, while this device is unregistering, it's still easy to hit the infinite loop in the skb_tx_hash() from the OVS datapath.  There might be other drivers that do the same, but dummy by itself is important for the OVS ecosystem, because it is frequently used as a packet sink for tcpdump while debugging OVS deployments.  And when the issue is hit, the only way to recover is to reboot.  Fix that by also checking if the device is running.  The running state is handled by the net core during unregistering, so it covers unregistering case better, and we don't really need to send packets to devices that are not running anyway.  While only checking the running state might be enough, the carrier check is preserved.  The running and the carrier states seem disjoined throughout the code and different drivers.  And other core functions like __dev_direct_xmit() check both before attempting to transmit a packet.  So, it seems safer to check both flags in OVS as well.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21676?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21676" src="https://img.shields.io/badge/CVE--2025--21676-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fec: handle page_pool_dev_alloc_pages error  The fec_enet_update_cbd function calls page_pool_dev_alloc_pages but did not handle the case when it returned NULL. There was a WARN_ON(!new_page) but it would still proceed to use the NULL pointer and then crash.  This case does seem somewhat rare but when the system is under memory pressure it can happen. One case where I can duplicate this with some frequency is when writing over a smbd share to a SATA HDD attached to an imx6q.  Setting /proc/sys/vm/min_free_kbytes to higher values also seems to solve the problem for my test case. But it still seems wrong that the fec driver ignores the memory allocation error and can crash.  This commit handles the allocation error by dropping the current packet.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21675?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21675" src="https://img.shields.io/badge/CVE--2025--21675-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: Clear port select structure when fail to create  Clear the port select structure on error so no stale values left after definers are destroyed. That's because the mlx5_lag_destroy_definers() always try to destroy all lag definers in the tt_map, so in the flow below lag definers get double-destroyed and cause kernel crash:  mlx5_lag_port_sel_create() mlx5_lag_create_definers() mlx5_lag_create_definer()     <- Failed on tt 1 mlx5_lag_destroy_definers() <- definers[tt=0] gets destroyed mlx5_lag_port_sel_create() mlx5_lag_create_definers() mlx5_lag_create_definer()     <- Failed on tt 0 mlx5_lag_destroy_definers() <- definers[tt=0] gets double-destroyed  Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008 Mem abort info: ESR = 0x0000000096000005 EC = 0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x05: level 1 translation fault Data abort info: ISV = 0, ISS = 0x00000005, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess = 0 GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 user pgtable: 64k pages, 48-bit VAs, pgdp=0000000112ce2e00 [0000000000000008] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000 Internal error: Oops: 0000000096000005 [#1] PREEMPT SMP Modules linked in: iptable_raw bonding ip_gre ip6_gre gre ip6_tunnel tunnel6 geneve ip6_udp_tunnel udp_tunnel ipip tunnel4 ip_tunnel rdma_ucm(OE) rdma_cm(OE) iw_cm(OE) ib_ipoib(OE) ib_cm(OE) ib_umad(OE) mlx5_ib(OE) ib_uverbs(OE) mlx5_fwctl(OE) fwctl(OE) mlx5_core(OE) mlxdevm(OE) ib_core(OE) mlxfw(OE) memtrack(OE) mlx_compat(OE) openvswitch nsh nf_conncount psample xt_conntrack xt_MASQUERADE nf_conntrack_netlink nfnetlink xfrm_user xfrm_algo xt_addrtype iptable_filter iptable_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 br_netfilter bridge stp llc netconsole overlay efi_pstore sch_fq_codel zram ip_tables crct10dif_ce qemu_fw_cfg fuse ipv6 crc_ccitt [last unloaded: mlx_compat(OE)] CPU: 3 UID: 0 PID: 217 Comm: kworker/u53:2 Tainted: G           OE 6.11.0+ #2 Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE Hardware name: QEMU KVM Virtual Machine, BIOS 0.0.0 02/06/2015 Workqueue: mlx5_lag mlx5_do_bond_work [mlx5_core] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : mlx5_del_flow_rules+0x24/0x2c0 [mlx5_core] lr : mlx5_lag_destroy_definer+0x54/0x100 [mlx5_core] sp : ffff800085fafb00 x29: ffff800085fafb00 x28: ffff0000da0c8000 x27: 0000000000000000 x26: ffff0000da0c8000 x25: ffff0000da0c8000 x24: ffff0000da0c8000 x23: ffff0000c31f81a0 x22: 0400000000000000 x21: ffff0000da0c8000 x20: 0000000000000000 x19: 0000000000000001 x18: 0000000000000000 x17: 0000000000000000 x16: 0000000000000000 x15: 0000ffff8b0c9350 x14: 0000000000000000 x13: ffff800081390d18 x12: ffff800081dc3cc0 x11: 0000000000000001 x10: 0000000000000b10 x9 : ffff80007ab7304c x8 : ffff0000d00711f0 x7 : 0000000000000004 x6 : 0000000000000190 x5 : ffff00027edb3010 x4 : 0000000000000000 x3 : 0000000000000000 x2 : ffff0000d39b8000 x1 : ffff0000d39b8000 x0 : 0400000000000000 Call trace: mlx5_del_flow_rules+0x24/0x2c0 [mlx5_core] mlx5_lag_destroy_definer+0x54/0x100 [mlx5_core] mlx5_lag_destroy_definers+0xa0/0x108 [mlx5_core] mlx5_lag_port_sel_create+0x2d4/0x6f8 [mlx5_core] mlx5_activate_lag+0x60c/0x6f8 [mlx5_core] mlx5_do_bond_work+0x284/0x5c8 [mlx5_core] process_one_work+0x170/0x3e0 worker_thread+0x2d8/0x3e0 kthread+0x11c/0x128 ret_from_fork+0x10/0x20 Code: a9025bf5 aa0003f6 a90363f7 f90023f9 (f9400400) ---[ end trace 0000000000000000 ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21674?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21674" src="https://img.shields.io/badge/CVE--2025--21674-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5e: Fix inversion dependency warning while enabling IPsec tunnel  Attempt to enable IPsec packet offload in tunnel mode in debug kernel generates the following kernel panic, which is happening due to two issues: 1. In SA add section, the should be _bh() variant when marking SA mode. 2. There is not needed flush_workqueue in SA delete routine. It is not needed as at this stage as it is removed from SADB and the running work will be canceled later in SA free.  ===================================================== WARNING: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected 6.12.0+ #4 Not tainted ----------------------------------------------------- charon/1337 [HC0[0]:SC0[4]:HE1:SE0] is trying to acquire: ffff88810f365020 (&xa->xa_lock#24){+.+.}-{3:3}, at: mlx5e_xfrm_del_state+0xca/0x1e0 [mlx5_core]  and this task is already holding: ffff88813e0f0d48 (&x->lock){+.-.}-{3:3}, at: xfrm_state_delete+0x16/0x30 which would create a new lock dependency: (&x->lock){+.-.}-{3:3} -> (&xa->xa_lock#24){+.+.}-{3:3}  but this new dependency connects a SOFTIRQ-irq-safe lock: (&x->lock){+.-.}-{3:3}  ... which became SOFTIRQ-irq-safe at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_timer_handler+0x91/0xd70 __hrtimer_run_queues+0x1dd/0xa60 hrtimer_run_softirq+0x146/0x2e0 handle_softirqs+0x266/0x860 irq_exit_rcu+0x115/0x1a0 sysvec_apic_timer_interrupt+0x6e/0x90 asm_sysvec_apic_timer_interrupt+0x16/0x20 default_idle+0x13/0x20 default_idle_call+0x67/0xa0 do_idle+0x2da/0x320 cpu_startup_entry+0x50/0x60 start_secondary+0x213/0x2a0 common_startup_64+0x129/0x138  to a SOFTIRQ-irq-unsafe lock: (&xa->xa_lock#24){+.+.}-{3:3}  ... which became SOFTIRQ-irq-unsafe at: ... lock_acquire+0x1be/0x520 _raw_spin_lock+0x2c/0x40 xa_set_mark+0x70/0x110 mlx5e_xfrm_add_state+0xe48/0x2290 [mlx5_core] xfrm_dev_state_add+0x3bb/0xd70 xfrm_add_sa+0x2451/0x4a90 xfrm_user_rcv_msg+0x493/0x880 netlink_rcv_skb+0x12e/0x380 xfrm_netlink_rcv+0x6d/0x90 netlink_unicast+0x42f/0x740 netlink_sendmsg+0x745/0xbe0 __sock_sendmsg+0xc5/0x190 __sys_sendto+0x1fe/0x2c0 __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x6d/0x140 entry_SYSCALL_64_after_hwframe+0x4b/0x53  other info that might help us debug this:  Possible interrupt unsafe locking scenario:  CPU0                    CPU1 ----                    ---- lock(&xa->xa_lock#24); local_irq_disable(); lock(&x->lock); lock(&xa->xa_lock#24); <Interrupt> lock(&x->lock);  *** DEADLOCK ***  2 locks held by charon/1337: #0: ffffffff87f8f858 (&net->xfrm.xfrm_cfg_mutex){+.+.}-{4:4}, at: xfrm_netlink_rcv+0x5e/0x90 #1: ffff88813e0f0d48 (&x->lock){+.-.}-{3:3}, at: xfrm_state_delete+0x16/0x30  the dependencies between SOFTIRQ-irq-safe lock and the holding lock: -> (&x->lock){+.-.}-{3:3} ops: 29 { HARDIRQ-ON-W at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_alloc_spi+0xc0/0xe60 xfrm_alloc_userspi+0x5f6/0xbc0 xfrm_user_rcv_msg+0x493/0x880 netlink_rcv_skb+0x12e/0x380 xfrm_netlink_rcv+0x6d/0x90 netlink_unicast+0x42f/0x740 netlink_sendmsg+0x745/0xbe0 __sock_sendmsg+0xc5/0x190 __sys_sendto+0x1fe/0x2c0 __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x6d/0x140 entry_SYSCALL_64_after_hwframe+0x4b/0x53 IN-SOFTIRQ-W at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_timer_handler+0x91/0xd70 __hrtimer_run_queues+0x1dd/0xa60  ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21673?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21673" src="https://img.shields.io/badge/CVE--2025--21673-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix double free of TCP_Server_Info::hostname  When shutting down the server in cifs_put_tcp_session(), cifsd thread might be reconnecting to multiple DFS targets before it realizes it should exit the loop, so @server->hostname can't be freed as long as cifsd thread isn't done.  Otherwise the following can happen:  RIP: 0010:__slab_free+0x223/0x3c0 Code: 5e 41 5f c3 cc cc cc cc 4c 89 de 4c 89 cf 44 89 44 24 08 4c 89 1c 24 e8 fb cf 8e 00 44 8b 44 24 08 4c 8b 1c 24 e9 5f fe ff ff <0f> 0b 41 f7 45 08 00 0d 21 00 0f 85 2d ff ff ff e9 1f ff ff ff 80 RSP: 0018:ffffb26180dbfd08 EFLAGS: 00010246 RAX: ffff8ea34728e510 RBX: ffff8ea34728e500 RCX: 0000000000800068 RDX: 0000000000800068 RSI: 0000000000000000 RDI: ffff8ea340042400 RBP: ffffe112041ca380 R08: 0000000000000001 R09: 0000000000000000 R10: 6170732e31303000 R11: 70726f632e786563 R12: ffff8ea34728e500 R13: ffff8ea340042400 R14: ffff8ea34728e500 R15: 0000000000800068 FS: 0000000000000000(0000) GS:ffff8ea66fd80000(0000) 000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffc25376080 CR3: 000000012a2ba001 CR4: PKRU: 55555554 Call Trace: <TASK> ? show_trace_log_lvl+0x1c4/0x2df ? show_trace_log_lvl+0x1c4/0x2df ? __reconnect_target_unlocked+0x3e/0x160 [cifs] ? __die_body.cold+0x8/0xd ? die+0x2b/0x50 ? do_trap+0xce/0x120 ? __slab_free+0x223/0x3c0 ? do_error_trap+0x65/0x80 ? __slab_free+0x223/0x3c0 ? exc_invalid_op+0x4e/0x70 ? __slab_free+0x223/0x3c0 ? asm_exc_invalid_op+0x16/0x20 ? __slab_free+0x223/0x3c0 ? extract_hostname+0x5c/0xa0 [cifs] ? extract_hostname+0x5c/0xa0 [cifs] ? __kmalloc+0x4b/0x140 __reconnect_target_unlocked+0x3e/0x160 [cifs] reconnect_dfs_server+0x145/0x430 [cifs] cifs_handle_standard+0x1ad/0x1d0 [cifs] cifs_demultiplex_thread+0x592/0x730 [cifs] ? __pfx_cifs_demultiplex_thread+0x10/0x10 [cifs] kthread+0xdd/0x100 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x29/0x50 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21672?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21672" src="https://img.shields.io/badge/CVE--2025--21672-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.015%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  afs: Fix merge preference rule failure condition  syzbot reported a lock held when returning to userspace[1].  This is because if argc is less than 0 and the function returns directly, the held inode lock is not released.  Fix this by store the error in ret and jump to done to clean up instead of returning directly.  [dh: Modified Lizhi Xu's original patch to make it honour the error code from afs_split_string()]  [1] WARNING: lock held when returning to user space! 6.13.0-rc3-syzkaller-00209-g499551201b5f #0 Not tainted ------------------------------------------------ syz-executor133/5823 is leaving the kernel with locks still held! 1 lock held by syz-executor133/5823: #0: ffff888071cffc00 (&sb->s_type->i_mutex_key#9){++++}-{4:4}, at: inode_lock include/linux/fs.h:818 [inline] #0: ffff888071cffc00 (&sb->s_type->i_mutex_key#9){++++}-{4:4}, at: afs_proc_addr_prefs_write+0x2bb/0x14e0 fs/afs/addr_prefs.c:388

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21670?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21670" src="https://img.shields.io/badge/CVE--2025--21670-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock/bpf: return early if transport is not assigned  Some of the core functions can only be called if the transport has been assigned.  As Michal reported, a socket might have the transport at NULL, for example after a failed connect(), causing the following trace:  BUG: kernel NULL pointer dereference, address: 00000000000000a0 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD 12faf8067 P4D 12faf8067 PUD 113670067 PMD 0 Oops: Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 15 UID: 0 PID: 1198 Comm: a.out Not tainted 6.13.0-rc2+ RIP: 0010:vsock_connectible_has_data+0x1f/0x40 Call Trace: vsock_bpf_recvmsg+0xca/0x5e0 sock_recvmsg+0xb9/0xc0 __sys_recvfrom+0xb3/0x130 __x64_sys_recvfrom+0x20/0x30 do_syscall_64+0x93/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e  So we need to check the `vsk->transport` in vsock_bpf_recvmsg(), especially for connected sockets (stream/seqpacket) as we already do in __vsock_connectible_recvmsg().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21669?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21669" src="https://img.shields.io/badge/CVE--2025--21669-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock/virtio: discard packets if the transport changes  If the socket has been de-assigned or assigned to another transport, we must discard any packets received because they are not expected and would cause issues when we access vsk->transport.  A possible scenario is described by Hyunwoo Kim in the attached link, where after a first connect() interrupted by a signal, and a second connect() failed, we can find `vsk->transport` at NULL, leading to a NULL pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21667?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21667" src="https://img.shields.io/badge/CVE--2025--21667-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iomap: avoid avoid truncating 64-bit offset to 32 bits  on 32-bit kernels, iomap_write_delalloc_scan() was inadvertently using a 32-bit position due to folio_next_index() returning an unsigned long. This could lead to an infinite loop when writing to an xfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21666?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21666" src="https://img.shields.io/badge/CVE--2025--21666-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock: prevent null-ptr-deref in vsock_*[has_data|has_space]  Recent reports have shown how we sometimes call vsock_*_has_data() when a vsock socket has been de-assigned from a transport (see attached links), but we shouldn't.  Previous commits should have solved the real problems, but we may have more in the future, so to avoid null-ptr-deref, we can return 0 (no space, no data available) but with a warning.  This way the code should continue to run in a nearly consistent state and have a warning that allows us to debug future problems.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21665?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21665" src="https://img.shields.io/badge/CVE--2025--21665-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  filemap: avoid truncating 64-bit offset to 32 bits  On 32-bit kernels, folio_seek_hole_data() was inadvertently truncating a 64-bit value to 32 bits, leading to a possible infinite loop when writing to an xfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21658?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21658" src="https://img.shields.io/badge/CVE--2025--21658-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: avoid NULL pointer dereference if no valid extent tree  [BUG] Syzbot reported a crash with the following call trace:  BTRFS info (device loop0): scrub: started on devid 1 BUG: kernel NULL pointer dereference, address: 0000000000000208 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD 106e70067 P4D 106e70067 PUD 107143067 PMD 0 Oops: Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 1 UID: 0 PID: 689 Comm: repro Kdump: loaded Tainted: G           O 6.13.0-rc4-custom+ #206 Tainted: [O]=OOT_MODULE Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS unknown 02/02/2022 RIP: 0010:find_first_extent_item+0x26/0x1f0 [btrfs] Call Trace: <TASK> scrub_find_fill_first_stripe+0x13d/0x3b0 [btrfs] scrub_simple_mirror+0x175/0x260 [btrfs] scrub_stripe+0x5d4/0x6c0 [btrfs] scrub_chunk+0xbb/0x170 [btrfs] scrub_enumerate_chunks+0x2f4/0x5f0 [btrfs] btrfs_scrub_dev+0x240/0x600 [btrfs] btrfs_ioctl+0x1dc8/0x2fa0 [btrfs] ? do_sys_openat2+0xa5/0xf0 __x64_sys_ioctl+0x97/0xc0 do_syscall_64+0x4f/0x120 entry_SYSCALL_64_after_hwframe+0x76/0x7e </TASK>  [CAUSE] The reproducer is using a corrupted image where extent tree root is corrupted, thus forcing to use "rescue=all,ro" mount option to mount the image.  Then it triggered a scrub, but since scrub relies on extent tree to find where the data/metadata extents are, scrub_find_fill_first_stripe() relies on an non-empty extent root.  But unfortunately scrub_find_fill_first_stripe() doesn't really expect an NULL pointer for extent root, it use extent_root to grab fs_info and triggered a NULL pointer dereference.  [FIX] Add an extra check for a valid extent root at the beginning of scrub_find_fill_first_stripe().  The new error path is introduced by 42437a6386ff ("btrfs: introduce mount option rescue=ignorebadroots"), but that's pretty old, and later commit b979547513ff ("btrfs: scrub: introduce helper to find and fill sector info for a scrub_stripe") changed how we do scrub.  So for kernels older than 6.6, the fix will need manual backport.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21649?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21649" src="https://img.shields.io/badge/CVE--2025--21649-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hns3: fix kernel crash when 1588 is sent on HIP08 devices  Currently, HIP08 devices does not register the ptp devices, so the hdev->ptp is NULL. But the tx process would still try to set hardware time stamp info with SKBTX_HW_TSTAMP flag and cause a kernel crash.  [  128.087798] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000018 ... [  128.280251] pc : hclge_ptp_set_tx_info+0x2c/0x140 [hclge] [  128.286600] lr : hclge_ptp_set_tx_info+0x20/0x140 [hclge] [  128.292938] sp : ffff800059b93140 [  128.297200] x29: ffff800059b93140 x28: 0000000000003280 [  128.303455] x27: ffff800020d48280 x26: ffff0cb9dc814080 [  128.309715] x25: ffff0cb9cde93fa0 x24: 0000000000000001 [  128.315969] x23: 0000000000000000 x22: 0000000000000194 [  128.322219] x21: ffff0cd94f986000 x20: 0000000000000000 [  128.328462] x19: ffff0cb9d2a166c0 x18: 0000000000000000 [  128.334698] x17: 0000000000000000 x16: ffffcf1fc523ed24 [  128.340934] x15: 0000ffffd530a518 x14: 0000000000000000 [  128.347162] x13: ffff0cd6bdb31310 x12: 0000000000000368 [  128.353388] x11: ffff0cb9cfbc7070 x10: ffff2cf55dd11e02 [  128.359606] x9 : ffffcf1f85a212b4 x8 : ffff0cd7cf27dab0 [  128.365831] x7 : 0000000000000a20 x6 : ffff0cd7cf27d000 [  128.372040] x5 : 0000000000000000 x4 : 000000000000ffff [  128.378243] x3 : 0000000000000400 x2 : ffffcf1f85a21294 [  128.384437] x1 : ffff0cb9db520080 x0 : ffff0cb9db500080 [  128.390626] Call trace: [  128.393964]  hclge_ptp_set_tx_info+0x2c/0x140 [hclge] [  128.399893]  hns3_nic_net_xmit+0x39c/0x4c4 [hns3] [  128.405468]  xmit_one.constprop.0+0xc4/0x200 [  128.410600]  dev_hard_start_xmit+0x54/0xf0 [  128.415556]  sch_direct_xmit+0xe8/0x634 [  128.420246]  __dev_queue_xmit+0x224/0xc70 [  128.425101]  dev_queue_xmit+0x1c/0x40 [  128.429608]  ovs_vport_send+0xac/0x1a0 [openvswitch] [  128.435409]  do_output+0x60/0x17c [openvswitch] [  128.440770]  do_execute_actions+0x898/0x8c4 [openvswitch] [  128.446993]  ovs_execute_actions+0x64/0xf0 [openvswitch] [  128.453129]  ovs_dp_process_packet+0xa0/0x224 [openvswitch] [  128.459530]  ovs_vport_receive+0x7c/0xfc [openvswitch] [  128.465497]  internal_dev_xmit+0x34/0xb0 [openvswitch] [  128.471460]  xmit_one.constprop.0+0xc4/0x200 [  128.476561]  dev_hard_start_xmit+0x54/0xf0 [  128.481489]  __dev_queue_xmit+0x968/0xc70 [  128.486330]  dev_queue_xmit+0x1c/0x40 [  128.490856]  ip_finish_output2+0x250/0x570 [  128.495810]  __ip_finish_output+0x170/0x1e0 [  128.500832]  ip_finish_output+0x3c/0xf0 [  128.505504]  ip_output+0xbc/0x160 [  128.509654]  ip_send_skb+0x58/0xd4 [  128.513892]  udp_send_skb+0x12c/0x354 [  128.518387]  udp_sendmsg+0x7a8/0x9c0 [  128.522793]  inet_sendmsg+0x4c/0x8c [  128.527116]  __sock_sendmsg+0x48/0x80 [  128.531609]  __sys_sendto+0x124/0x164 [  128.536099]  __arm64_sys_sendto+0x30/0x5c [  128.540935]  invoke_syscall+0x50/0x130 [  128.545508]  el0_svc_common.constprop.0+0x10c/0x124 [  128.551205]  do_el0_svc+0x34/0xdc [  128.555347]  el0_svc+0x20/0x30 [  128.559227]  el0_sync_handler+0xb8/0xc0 [  128.563883]  el0_sync+0x160/0x180

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21642?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21642" src="https://img.shields.io/badge/CVE--2025--21642-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: sysctl: sched: avoid using current->nsproxy  Using the 'net' structure via 'current' is not recommended for different reasons.  First, if the goal is to use it to read or write per-netns data, this is inconsistent with how the "generic" sysctl entries are doing: directly by only using pointers set to the table entry, e.g. table->data. Linked to that, the per-netns data should always be obtained from the table linked to the netns it had been created for, which may not coincide with the reader's or writer's netns.  Another reason is that access to current->nsproxy->netns can oops if attempted when current->nsproxy had been dropped when the current task is exiting. This is what syzbot found, when using acct(2):  Oops: general protection fault, probably for non-canonical address 0xdffffc0000000005: 0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range [0x0000000000000028-0x000000000000002f] CPU: 1 UID: 0 PID: 5924 Comm: syz-executor Not tainted 6.13.0-rc5-syzkaller-00004-gccb98ccef0e5 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:proc_scheduler+0xc6/0x3c0 net/mptcp/ctrl.c:125 Code: 03 42 80 3c 38 00 0f 85 fe 02 00 00 4d 8b a4 24 08 09 00 00 48 b8 00 00 00 00 00 fc ff df 49 8d 7c 24 28 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 cc 02 00 00 4d 8b 7c 24 28 48 8d 84 24 c8 00 00 RSP: 0018:ffffc900034774e8 EFLAGS: 00010206  RAX: dffffc0000000000 RBX: 1ffff9200068ee9e RCX: ffffc90003477620 RDX: 0000000000000005 RSI: ffffffff8b08f91e RDI: 0000000000000028 RBP: 0000000000000001 R08: ffffc90003477710 R09: 0000000000000040 R10: 0000000000000040 R11: 00000000726f7475 R12: 0000000000000000 R13: ffffc90003477620 R14: ffffc90003477710 R15: dffffc0000000000 FS:  0000000000000000(0000) GS:ffff8880b8700000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fee3cd452d8 CR3: 000000007d116000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> proc_sys_call_handler+0x403/0x5d0 fs/proc/proc_sysctl.c:601 __kernel_write_iter+0x318/0xa80 fs/read_write.c:612 __kernel_write+0xf6/0x140 fs/read_write.c:632 do_acct_process+0xcb0/0x14a0 kernel/acct.c:539 acct_pin_kill+0x2d/0x100 kernel/acct.c:192 pin_kill+0x194/0x7c0 fs/fs_pin.c:44 mnt_pin_kill+0x61/0x1e0 fs/fs_pin.c:81 cleanup_mnt+0x3ac/0x450 fs/namespace.c:1366 task_work_run+0x14e/0x250 kernel/task_work.c:239 exit_task_work include/linux/task_work.h:43 [inline] do_exit+0xad8/0x2d70 kernel/exit.c:938 do_group_exit+0xd3/0x2a0 kernel/exit.c:1087 get_signal+0x2576/0x2610 kernel/signal.c:3017 arch_do_signal_or_restart+0x90/0x7e0 arch/x86/kernel/signal.c:337 exit_to_user_mode_loop kernel/entry/common.c:111 [inline] exit_to_user_mode_prepare include/linux/entry-common.h:329 [inline] __syscall_exit_to_user_mode_work kernel/entry/common.c:207 [inline] syscall_exit_to_user_mode+0x150/0x2a0 kernel/entry/common.c:218 do_syscall_64+0xda/0x250 arch/x86/entry/common.c:89 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7fee3cb87a6a Code: Unable to access opcode bytes at 0x7fee3cb87a40. RSP: 002b:00007fffcccac688 EFLAGS: 00000202 ORIG_RAX: 0000000000000037 RAX: 0000000000000000 RBX: 00007fffcccac710 RCX: 00007fee3cb87a6a RDX: 0000000000000041 RSI: 0000000000000000 RDI: 0000000000000003 RBP: 0000000000000003 R08: 00007fffcccac6ac R09: 00007fffcccacac7 R10: 00007fffcccac710 R11: 0000000000000202 R12: 00007fee3cd49500 R13: 00007fffcccac6ac R14: 0000000000000000 R15: 00007fee3cd4b000 </TASK> Modules linked in: ---[ end trace 0000000000000000 ]--- RIP: 0010:proc_scheduler+0xc6/0x3c0 net/mptcp/ctrl.c:125 Code: 03 42 80 3c 38 00 0f 85 fe 02 00 00 4d 8b a4 24 08 09 00 00 48 b8 00 00 00 00 00 fc ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21640?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21640" src="https://img.shields.io/badge/CVE--2025--21640-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: cookie_hmac_alg: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, as this is the only member needed from the 'net' structure, but that would increase the size of this fix, to use '*data' everywhere 'net->sctp.sctp_hmac_alg' is used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21639?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21639" src="https://img.shields.io/badge/CVE--2025--21639-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: rto_min/max: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, as this is the only member needed from the 'net' structure, but that would increase the size of this fix, to use '*data' everywhere 'net->sctp.rto_min/max' is used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21638?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21638" src="https://img.shields.io/badge/CVE--2025--21638-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: auth_enable: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, but that would increase the size of this fix, while 'sctp.ctl_sock' still needs to be retrieved from 'net' structure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21637?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21637" src="https://img.shields.io/badge/CVE--2025--21637-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: udp_port: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, but that would increase the size of this fix, while 'sctp.ctl_sock' still needs to be retrieved from 'net' structure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21636?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21636" src="https://img.shields.io/badge/CVE--2025--21636-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: plpmtud_probe_interval: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, as this is the only member needed from the 'net' structure, but that would increase the size of this fix, to use '*data' everywhere 'net->sctp.probe_interval' is used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21635?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21635" src="https://img.shields.io/badge/CVE--2025--21635-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  rds: sysctl: rds_tcp_{rcv,snd}buf: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The per-netns structure can be obtained from the table->data using container_of(), then the 'net' one can be retrieved from the listen socket (if available).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21634?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2025--21634" src="https://img.shields.io/badge/CVE--2025--21634-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cgroup/cpuset: remove kernfs active break  A warning was found:  WARNING: CPU: 10 PID: 3486953 at fs/kernfs/file.c:828 CPU: 10 PID: 3486953 Comm: rmdir Kdump: loaded Tainted: G RIP: 0010:kernfs_should_drain_open_files+0x1a1/0x1b0 RSP: 0018:ffff8881107ef9e0 EFLAGS: 00010202 RAX: 0000000080000002 RBX: ffff888154738c00 RCX: dffffc0000000000 RDX: 0000000000000007 RSI: 0000000000000004 RDI: ffff888154738c04 RBP: ffff888154738c04 R08: ffffffffaf27fa15 R09: ffffed102a8e7180 R10: ffff888154738c07 R11: 0000000000000000 R12: ffff888154738c08 R13: ffff888750f8c000 R14: ffff888750f8c0e8 R15: ffff888154738ca0 FS:  00007f84cd0be740(0000) GS:ffff8887ddc00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000555f9fbe00c8 CR3: 0000000153eec001 CR4: 0000000000370ee0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: kernfs_drain+0x15e/0x2f0 __kernfs_remove+0x165/0x300 kernfs_remove_by_name_ns+0x7b/0xc0 cgroup_rm_file+0x154/0x1c0 cgroup_addrm_files+0x1c2/0x1f0 css_clear_dir+0x77/0x110 kill_css+0x4c/0x1b0 cgroup_destroy_locked+0x194/0x380 cgroup_rmdir+0x2a/0x140  It can be explained by: rmdir 				echo 1 > cpuset.cpus kernfs_fop_write_iter // active=0 cgroup_rm_file kernfs_remove_by_name_ns	kernfs_get_active // active=1 __kernfs_remove					  // active=0x80000002 kernfs_drain			cpuset_write_resmask wait_event //waiting (active == 0x80000001) kernfs_break_active_protection // active = 0x80000001 // continue kernfs_unbreak_active_protection // active = 0x80000002 ... kernfs_should_drain_open_files // warning occurs kernfs_put_active  This warning is caused by 'kernfs_break_active_protection' when it is writing to cpuset.cpus, and the cgroup is removed concurrently.  The commit 3a5a6d0c2b03 ("cpuset: don't nest cgroup_mutex inside get_online_cpus()") made cpuset_hotplug_workfn asynchronous, This change involves calling flush_work(), which can create a multiple processes circular locking dependency that involve cgroup_mutex, potentially leading to a deadlock. To avoid deadlock. the commit 76bb5ab8f6e3 ("cpuset: break kernfs active protection in cpuset_write_resmask()") added 'kernfs_break_active_protection' in the cpuset_write_resmask. This could lead to this warning.  After the commit 2125c0034c5d ("cgroup/cpuset: Make cpuset hotplug processing synchronous"), the cpuset_write_resmask no longer needs to wait the hotplug to finish, which means that concurrent hotplug and cpuset operations are no longer possible. Therefore, the deadlock doesn't exist anymore and it does not have to 'break active protection' now. To fix this warning, just remove kernfs_break_active_protection operation in the 'cpuset_write_resmask'.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58089?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58089" src="https://img.shields.io/badge/CVE--2024--58089-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: fix double accounting race when btrfs_run_delalloc_range() failed  [BUG] When running btrfs with block size (4K) smaller than page size (64K, aarch64), there is a very high chance to crash the kernel at generic/750, with the following messages: (before the call traces, there are 3 extra debug messages added)  BTRFS warning (device dm-3): read-write for sector size 4096 with page size 65536 is experimental BTRFS info (device dm-3): checking UUID tree hrtimer: interrupt took 5451385 ns BTRFS error (device dm-3): cow_file_range failed, root=4957 inode=257 start=1605632 len=69632: -28 BTRFS error (device dm-3): run_delalloc_nocow failed, root=4957 inode=257 start=1605632 len=69632: -28 BTRFS error (device dm-3): failed to run delalloc range, root=4957 ino=257 folio=1572864 submit_bitmap=8-15 start=1605632 len=69632: -28 ------------[ cut here ]------------ WARNING: CPU: 2 PID: 3020984 at ordered-data.c:360 can_finish_ordered_extent+0x370/0x3b8 [btrfs] CPU: 2 UID: 0 PID: 3020984 Comm: kworker/u24:1 Tainted: G           OE 6.13.0-rc1-custom+ #89 Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE Hardware name: QEMU KVM Virtual Machine, BIOS unknown 2/2/2022 Workqueue: events_unbound btrfs_async_reclaim_data_space [btrfs] pc : can_finish_ordered_extent+0x370/0x3b8 [btrfs] lr : can_finish_ordered_extent+0x1ec/0x3b8 [btrfs] Call trace: can_finish_ordered_extent+0x370/0x3b8 [btrfs] (P) can_finish_ordered_extent+0x1ec/0x3b8 [btrfs] (L) btrfs_mark_ordered_io_finished+0x130/0x2b8 [btrfs] extent_writepage+0x10c/0x3b8 [btrfs] extent_write_cache_pages+0x21c/0x4e8 [btrfs] btrfs_writepages+0x94/0x160 [btrfs] do_writepages+0x74/0x190 filemap_fdatawrite_wbc+0x74/0xa0 start_delalloc_inodes+0x17c/0x3b0 [btrfs] btrfs_start_delalloc_roots+0x17c/0x288 [btrfs] shrink_delalloc+0x11c/0x280 [btrfs] flush_space+0x288/0x328 [btrfs] btrfs_async_reclaim_data_space+0x180/0x228 [btrfs] process_one_work+0x228/0x680 worker_thread+0x1bc/0x360 kthread+0x100/0x118 ret_from_fork+0x10/0x20 ---[ end trace 0000000000000000 ]--- BTRFS critical (device dm-3): bad ordered extent accounting, root=4957 ino=257 OE offset=1605632 OE len=16384 to_dec=16384 left=0 BTRFS critical (device dm-3): bad ordered extent accounting, root=4957 ino=257 OE offset=1622016 OE len=12288 to_dec=12288 left=0 Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008 BTRFS critical (device dm-3): bad ordered extent accounting, root=4957 ino=257 OE offset=1634304 OE len=8192 to_dec=4096 left=0 CPU: 1 UID: 0 PID: 3286940 Comm: kworker/u24:3 Tainted: G        W  OE 6.13.0-rc1-custom+ #89 Hardware name: QEMU KVM Virtual Machine, BIOS unknown 2/2/2022 Workqueue:  btrfs_work_helper [btrfs] (btrfs-endio-write) pstate: 404000c5 (nZcv daIF +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : process_one_work+0x110/0x680 lr : worker_thread+0x1bc/0x360 Call trace: process_one_work+0x110/0x680 (P) worker_thread+0x1bc/0x360 (L) worker_thread+0x1bc/0x360 kthread+0x100/0x118 ret_from_fork+0x10/0x20 Code: f84086a1 f9000fe1 53041c21 b9003361 (f9400661) ---[ end trace 0000000000000000 ]--- Kernel panic - not syncing: Oops: Fatal exception SMP: stopping secondary CPUs SMP: failed to stop secondary CPUs 2-3 Dumping ftrace buffer: (ftrace buffer empty) Kernel Offset: 0x275bb9540000 from 0xffff800080000000 PHYS_OFFSET: 0xffff8fbba0000000 CPU features: 0x100,00000070,00801250,8201720b  [CAUSE] The above warning is triggered immediately after the delalloc range failure, this happens in the following sequence:  - Range [1568K, 1636K) is dirty  1536K  1568K     1600K    1636K  1664K |      |/////////|////////|      |  Where 1536K, 1600K and 1664K are page boundaries (64K page size)  - Enter extent_writepage() for page 1536K  - Enter run_delalloc_nocow() with locke ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58088?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58088" src="https://img.shields.io/badge/CVE--2024--58088-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Fix deadlock when freeing cgroup storage  The following commit bc235cdb423a ("bpf: Prevent deadlock from recursive bpf_task_storage_[get|delete]") first introduced deadlock prevention for fentry/fexit programs attaching on bpf_task_storage helpers. That commit also employed the logic in map free path in its v6 version.  Later bpf_cgrp_storage was first introduced in c4bcfb38a95e ("bpf: Implement cgroup storage available to non-cgroup-attached bpf progs") which faces the same issue as bpf_task_storage, instead of its busy counter, NULL was passed to bpf_local_storage_map_free() which opened a window to cause deadlock:  <TASK> (acquiring local_storage->lock) _raw_spin_lock_irqsave+0x3d/0x50 bpf_local_storage_update+0xd1/0x460 bpf_cgrp_storage_get+0x109/0x130 bpf_prog_a4d4a370ba857314_cgrp_ptr+0x139/0x170 ? __bpf_prog_enter_recur+0x16/0x80 bpf_trampoline_6442485186+0x43/0xa4 cgroup_storage_ptr+0x9/0x20 (holding local_storage->lock) bpf_selem_unlink_storage_nolock.constprop.0+0x135/0x160 bpf_selem_unlink_storage+0x6f/0x110 bpf_local_storage_map_free+0xa2/0x110 bpf_map_free_deferred+0x5b/0x90 process_one_work+0x17c/0x390 worker_thread+0x251/0x360 kthread+0xd2/0x100 ret_from_fork+0x34/0x50 ret_from_fork_asm+0x1a/0x30 </TASK>  Progs: - A: SEC("fentry/cgroup_storage_ptr") - cgid (BPF_MAP_TYPE_HASH) Record the id of the cgroup the current task belonging to in this hash map, using the address of the cgroup as the map key. - cgrpa (BPF_MAP_TYPE_CGRP_STORAGE) If current task is a kworker, lookup the above hash map using function parameter @owner as the key to get its corresponding cgroup id which is then used to get a trusted pointer to the cgroup through bpf_cgroup_from_id(). This trusted pointer can then be passed to bpf_cgrp_storage_get() to finally trigger the deadlock issue. - B: SEC("tp_btf/sys_enter") - cgrpb (BPF_MAP_TYPE_CGRP_STORAGE) The only purpose of this prog is to fill Prog A's hash map by calling bpf_cgrp_storage_get() for as many userspace tasks as possible.  Steps to reproduce: - Run A; - while (true) { Run B; Destroy B; }  Fix this issue by passing its busy counter to the free procedure so it can be properly incremented before storage/smap locking.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58081?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58081" src="https://img.shields.io/badge/CVE--2024--58081-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  clk: mmp2: call pm_genpd_init() only after genpd.name is set  Setting the genpd's struct device's name with dev_set_name() is happening within pm_genpd_init(). If it remains NULL, things can blow up later, such as when crafting the devfs hierarchy for the power domain:  Unable to handle kernel NULL pointer dereference at virtual address 00000000 when read ... Call trace: strlen from start_creating+0x90/0x138 start_creating from debugfs_create_dir+0x20/0x178 debugfs_create_dir from genpd_debug_add.part.0+0x4c/0x144 genpd_debug_add.part.0 from genpd_debug_init+0x74/0x90 genpd_debug_init from do_one_initcall+0x5c/0x244 do_one_initcall from kernel_init_freeable+0x19c/0x1f4 kernel_init_freeable from kernel_init+0x1c/0x12c kernel_init from ret_from_fork+0x14/0x28  Bisecting tracks this crash back to commit 899f44531fe6 ("pmdomain: core: Add GENPD_FLAG_DEV_NAME_FW flag"), which exchanges use of genpd->name with dev_name(&genpd->dev) in genpd_debug_add.part().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58080?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58080" src="https://img.shields.io/badge/CVE--2024--58080-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  clk: qcom: dispcc-sm6350: Add missing parent_map for a clock  If a clk_rcg2 has a parent, it should also have parent_map defined, otherwise we'll get a NULL pointer dereference when calling clk_set_rate like the following:  [    3.388105] Call trace: [    3.390664]  qcom_find_src_index+0x3c/0x70 (P) [    3.395301]  qcom_find_src_index+0x1c/0x70 (L) [    3.399934]  _freq_tbl_determine_rate+0x48/0x100 [    3.404753]  clk_rcg2_determine_rate+0x1c/0x28 [    3.409387]  clk_core_determine_round_nolock+0x58/0xe4 [    3.421414]  clk_core_round_rate_nolock+0x48/0xfc [    3.432974]  clk_core_round_rate_nolock+0xd0/0xfc [    3.444483]  clk_core_set_rate_nolock+0x8c/0x300 [    3.455886]  clk_set_rate+0x38/0x14c  Add the parent_map property for the clock where it's missing and also un-inline the parent_data as well to keep the matching parent_map and parent_data together.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58076?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58076" src="https://img.shields.io/badge/CVE--2024--58076-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  clk: qcom: gcc-sm6350: Add missing parent_map for two clocks  If a clk_rcg2 has a parent, it should also have parent_map defined, otherwise we'll get a NULL pointer dereference when calling clk_set_rate like the following:  [    3.388105] Call trace: [    3.390664]  qcom_find_src_index+0x3c/0x70 (P) [    3.395301]  qcom_find_src_index+0x1c/0x70 (L) [    3.399934]  _freq_tbl_determine_rate+0x48/0x100 [    3.404753]  clk_rcg2_determine_rate+0x1c/0x28 [    3.409387]  clk_core_determine_round_nolock+0x58/0xe4 [    3.421414]  clk_core_round_rate_nolock+0x48/0xfc [    3.432974]  clk_core_round_rate_nolock+0xd0/0xfc [    3.444483]  clk_core_set_rate_nolock+0x8c/0x300 [    3.455886]  clk_set_rate+0x38/0x14c  Add the parent_map property for two clocks where it's missing and also un-inline the parent_data as well to keep the matching parent_map and parent_data together.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58071?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58071" src="https://img.shields.io/badge/CVE--2024--58071-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  team: prevent adding a device which is already a team device lower  Prevent adding a device which is already a team device lower, e.g. adding veth0 if vlan1 was already added and veth0 is a lower of vlan1.  This is not useful in practice and can lead to recursive locking:  $ ip link add veth0 type veth peer name veth1 $ ip link set veth0 up $ ip link set veth1 up $ ip link add link veth0 name veth0.1 type vlan protocol 802.1Q id 1 $ ip link add team0 type team $ ip link set veth0.1 down $ ip link set veth0.1 master team0 team0: Port device veth0.1 added $ ip link set veth0 down $ ip link set veth0 master team0  ============================================ WARNING: possible recursive locking detected 6.13.0-rc2-virtme-00441-ga14a429069bb #46 Not tainted -------------------------------------------- ip/7684 is trying to acquire lock: ffff888016848e00 (team->team_lock_key){+.+.}-{4:4}, at: team_device_event (drivers/net/team/team_core.c:2928 drivers/net/team/team_core.c:2951 drivers/net/team/team_core.c:2973)  but task is already holding lock: ffff888016848e00 (team->team_lock_key){+.+.}-{4:4}, at: team_add_slave (drivers/net/team/team_core.c:1147 drivers/net/team/team_core.c:1977)  other info that might help us debug this: Possible unsafe locking scenario:  CPU0 ---- lock(team->team_lock_key); lock(team->team_lock_key);  *** DEADLOCK ***  May be due to missing lock nesting notation  2 locks held by ip/7684:  stack backtrace: CPU: 3 UID: 0 PID: 7684 Comm: ip Not tainted 6.13.0-rc2-virtme-00441-ga14a429069bb #46 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-debian-1.16.3-2 04/01/2014 Call Trace: <TASK> dump_stack_lvl (lib/dump_stack.c:122) print_deadlock_bug.cold (kernel/locking/lockdep.c:3040) __lock_acquire (kernel/locking/lockdep.c:3893 kernel/locking/lockdep.c:5226) ? netlink_broadcast_filtered (net/netlink/af_netlink.c:1548) lock_acquire.part.0 (kernel/locking/lockdep.c:467 kernel/locking/lockdep.c:5851) ? team_device_event (drivers/net/team/team_core.c:2928 drivers/net/team/team_core.c:2951 drivers/net/team/team_core.c:2973) ? trace_lock_acquire (./include/trace/events/lock.h:24 (discriminator 2)) ? team_device_event (drivers/net/team/team_core.c:2928 drivers/net/team/team_core.c:2951 drivers/net/team/team_core.c:2973) ? lock_acquire (kernel/locking/lockdep.c:5822) ? team_device_event (drivers/net/team/team_core.c:2928 drivers/net/team/team_core.c:2951 drivers/net/team/team_core.c:2973) __mutex_lock (kernel/locking/mutex.c:587 kernel/locking/mutex.c:735) ? team_device_event (drivers/net/team/team_core.c:2928 drivers/net/team/team_core.c:2951 drivers/net/team/team_core.c:2973) ? team_device_event (drivers/net/team/team_core.c:2928 drivers/net/team/team_core.c:2951 drivers/net/team/team_core.c:2973) ? fib_sync_up (net/ipv4/fib_semantics.c:2167) ? team_device_event (drivers/net/team/team_core.c:2928 drivers/net/team/team_core.c:2951 drivers/net/team/team_core.c:2973) team_device_event (drivers/net/team/team_core.c:2928 drivers/net/team/team_core.c:2951 drivers/net/team/team_core.c:2973) notifier_call_chain (kernel/notifier.c:85) call_netdevice_notifiers_info (net/core/dev.c:1996) __dev_notify_flags (net/core/dev.c:8993) ? __dev_change_flags (net/core/dev.c:8975) dev_change_flags (net/core/dev.c:9027) vlan_device_event (net/8021q/vlan.c:85 net/8021q/vlan.c:470) ? br_device_event (net/bridge/br.c:143) notifier_call_chain (kernel/notifier.c:85) call_netdevice_notifiers_info (net/core/dev.c:1996) dev_open (net/core/dev.c:1519 net/core/dev.c:1505) team_add_slave (drivers/net/team/team_core.c:1219 drivers/net/team/team_core.c:1977) ? __pfx_team_add_slave (drivers/net/team/team_core.c:1972) do_set_master (net/core/rtnetlink.c:2917) do_setlink.isra.0 (net/core/rtnetlink.c:3117)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58070?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58070" src="https://img.shields.io/badge/CVE--2024--58070-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: bpf_local_storage: Always use bpf_mem_alloc in PREEMPT_RT  In PREEMPT_RT, kmalloc(GFP_ATOMIC) is still not safe in non preemptible context. bpf_mem_alloc must be used in PREEMPT_RT. This patch is to enforce bpf_mem_alloc in the bpf_local_storage when CONFIG_PREEMPT_RT is enabled.  [   35.118559] BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48 [   35.118566] in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 1832, name: test_progs [   35.118569] preempt_count: 1, expected: 0 [   35.118571] RCU nest depth: 1, expected: 1 [   35.118577] INFO: lockdep is turned off. ... [   35.118647]  __might_resched+0x433/0x5b0 [   35.118677]  rt_spin_lock+0xc3/0x290 [   35.118700]  ___slab_alloc+0x72/0xc40 [   35.118723]  __kmalloc_noprof+0x13f/0x4e0 [   35.118732]  bpf_map_kzalloc+0xe5/0x220 [   35.118740]  bpf_selem_alloc+0x1d2/0x7b0 [   35.118755]  bpf_local_storage_update+0x2fa/0x8b0 [   35.118784]  bpf_sk_storage_get_tracing+0x15a/0x1d0 [   35.118791] bpf_prog_9a118d86fca78ebb_trace_inet_sock_set_state+0x44/0x66 [   35.118795]  bpf_trace_run3+0x222/0x400 [   35.118820]  __bpf_trace_inet_sock_set_state+0x11/0x20 [   35.118824]  trace_inet_sock_set_state+0x112/0x130 [   35.118830]  inet_sk_state_store+0x41/0x90 [   35.118836]  tcp_set_state+0x3b3/0x640  There is no need to adjust the gfp_flags passing to the bpf_mem_cache_alloc_flags() which only honors the GFP_KERNEL. The verifier has ensured GFP_KERNEL is passed only in sleepable context.  It has been an old issue since the first introduction of the bpf_local_storage ~5 years ago, so this patch targets the bpf-next.  bpf_mem_alloc is needed to solve it, so the Fixes tag is set to the commit when bpf_mem_alloc was first used in the bpf_local_storage.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58068?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58068" src="https://img.shields.io/badge/CVE--2024--58068-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  OPP: fix dev_pm_opp_find_bw_*() when bandwidth table not initialized  If a driver calls dev_pm_opp_find_bw_ceil/floor() the retrieve bandwidth from the OPP table but the bandwidth table was not created because the interconnect properties were missing in the OPP consumer node, the kernel will crash with:  Unable to handle kernel NULL pointer dereference at virtual address 0000000000000004 ... pc : _read_bw+0x8/0x10 lr : _opp_table_find_key+0x9c/0x174 ... Call trace: _read_bw+0x8/0x10 (P) _opp_table_find_key+0x9c/0x174 (L) _find_key+0x98/0x168 dev_pm_opp_find_bw_ceil+0x50/0x88 ...  In order to fix the crash, create an assert function to check if the bandwidth table was created before trying to get a bandwidth with _read_bw().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58063?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58063" src="https://img.shields.io/badge/CVE--2024--58063-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: rtlwifi: fix memory leaks and invalid access at probe error path  Deinitialize at reverse order when probe fails.  When init_sw_vars fails, rtl_deinit_core should not be called, specially now that it destroys the rtl_wq workqueue.  And call rtl_pci_deinit and deinit_sw_vars, otherwise, memory will be leaked.  Remove pci_set_drvdata call as it will already be cleaned up by the core driver code and could lead to memory leaks too. cf. commit 8d450935ae7f ("wireless: rtlwifi: remove unnecessary pci_set_drvdata()") and commit 3d86b93064c7 ("rtlwifi: Fix PCI probe error path orphaned memory").

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58058?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58058" src="https://img.shields.io/badge/CVE--2024--58058-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ubifs: skip dumping tnc tree when zroot is null  Clearing slab cache will free all znode in memory and make c->zroot.znode = NULL, then dumping tnc tree will access c->zroot.znode which cause null pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58052?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58052" src="https://img.shields.io/badge/CVE--2024--58052-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu: Fix potential NULL pointer dereference in atomctrl_get_smc_sclk_range_table  The function atomctrl_get_smc_sclk_range_table() does not check the return value of smu_atom_get_data_table(). If smu_atom_get_data_table() fails to retrieve SMU_Info table, it returns NULL which is later dereferenced.  Found by Linux Verification Center (linuxtesting.org) with SVACE.  In practice this should never happen as this code only gets called on polaris chips and the vbios data table will always be present on those chips.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58020?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58020" src="https://img.shields.io/badge/CVE--2024--58020-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  HID: multitouch: Add NULL check in mt_input_configured  devm_kasprintf() can return a NULL pointer on failure,but this returned value in mt_input_configured() is not checked. Add NULL check in mt_input_configured(), to handle kernel NULL pointer dereference error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58017?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58017" src="https://img.shields.io/badge/CVE--2024--58017-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  printk: Fix signed integer overflow when defining LOG_BUF_LEN_MAX  Shifting 1 << 31 on a 32-bit int causes signed integer overflow, which leads to undefined behavior. To prevent this, cast 1 to u32 before performing the shift, ensuring well-defined behavior.  This change explicitly avoids any potential overflow by ensuring that the shift occurs on an unsigned 32-bit integer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58012?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58012" src="https://img.shields.io/badge/CVE--2024--58012-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: SOF: Intel: hda-dai: Ensure DAI widget is valid during params  Each cpu DAI should associate with a widget. However, the topology might not create the right number of DAI widgets for aggregated amps. And it will cause NULL pointer deference. Check that the DAI widget associated with the CPU DAI is valid to prevent NULL pointer deference due to missing DAI widgets in topologies with aggregated amps.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58011?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58011" src="https://img.shields.io/badge/CVE--2024--58011-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  platform/x86: int3472: Check for adev == NULL  Not all devices have an ACPI companion fwnode, so adev might be NULL. This can e.g. (theoretically) happen when a user manually binds one of the int3472 drivers to another i2c/platform device through sysfs.  Add a check for adev not being set and return -ENODEV in that case to avoid a possible NULL pointer deref in skl_int3472_get_acpi_buffer().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58010?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58010" src="https://img.shields.io/badge/CVE--2024--58010-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  binfmt_flat: Fix integer overflow bug on 32 bit systems  Most of these sizes and counts are capped at 256MB so the math doesn't result in an integer overflow.  The "relocs" count needs to be checked as well.  Otherwise on 32bit systems the calculation of "full_data" could be wrong.  full_data = data_len + relocs * sizeof(unsigned long);

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58005?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--58005" src="https://img.shields.io/badge/CVE--2024--58005-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tpm: Change to kvalloc() in eventlog/acpi.c  The following failure was reported on HPE ProLiant D320:  [   10.693310][    T1] tpm_tis STM0925:00: 2.0 TPM (device-id 0x3, rev-id 0) [   10.848132][    T1] ------------[ cut here ]------------ [   10.853559][    T1] WARNING: CPU: 59 PID: 1 at mm/page_alloc.c:4727 __alloc_pages_noprof+0x2ca/0x330 [   10.862827][    T1] Modules linked in: [   10.866671][    T1] CPU: 59 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.12.0-lp155.2.g52785e2-default #1 openSUSE Tumbleweed (unreleased) 588cd98293a7c9eba9013378d807364c088c9375 [   10.882741][    T1] Hardware name: HPE ProLiant DL320 Gen12/ProLiant DL320 Gen12, BIOS 1.20 10/28/2024 [   10.892170][    T1] RIP: 0010:__alloc_pages_noprof+0x2ca/0x330 [   10.898103][    T1] Code: 24 08 e9 4a fe ff ff e8 34 36 fa ff e9 88 fe ff ff 83 fe 0a 0f 86 b3 fd ff ff 80 3d 01 e7 ce 01 00 75 09 c6 05 f8 e6 ce 01 01 <0f> 0b 45 31 ff e9 e5 fe ff ff f7 c2 00 00 08 00 75 42 89 d9 80 e1 [   10.917750][    T1] RSP: 0000:ffffb7cf40077980 EFLAGS: 00010246 [   10.923777][    T1] RAX: 0000000000000000 RBX: 0000000000040cc0 RCX: 0000000000000000 [   10.931727][    T1] RDX: 0000000000000000 RSI: 000000000000000c RDI: 0000000000040cc0  The above transcript shows that ACPI pointed a 16 MiB buffer for the log events because RSI maps to the 'order' parameter of __alloc_pages_noprof(). Address the bug by moving from devm_kmalloc() to devm_add_action() and kvmalloc() and devm_add_action().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57997?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57997" src="https://img.shields.io/badge/CVE--2024--57997-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: wcn36xx: fix channel survey memory allocation size  KASAN reported a memory allocation issue in wcn->chan_survey due to incorrect size calculation. This commit uses kcalloc to allocate memory for wcn->chan_survey, ensuring proper initialization and preventing the use of uninitialized values when there are no frames on the channel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57996?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57996" src="https://img.shields.io/badge/CVE--2024--57996-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: sch_sfq: don't allow 1 packet limit  The current implementation does not work correctly with a limit of 1. iproute2 actually checks for this and this patch adds the check in kernel as well.  This fixes the following syzkaller reported crash:  UBSAN: array-index-out-of-bounds in net/sched/sch_sfq.c:210:6 index 65535 is out of range for type 'struct sfq_head[128]' CPU: 0 PID: 2569 Comm: syz-executor101 Not tainted 5.10.0-smp-DEV #1 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Call Trace: __dump_stack lib/dump_stack.c:79 [inline] dump_stack+0x125/0x19f lib/dump_stack.c:120 ubsan_epilogue lib/ubsan.c:148 [inline] __ubsan_handle_out_of_bounds+0xed/0x120 lib/ubsan.c:347 sfq_link net/sched/sch_sfq.c:210 [inline] sfq_dec+0x528/0x600 net/sched/sch_sfq.c:238 sfq_dequeue+0x39b/0x9d0 net/sched/sch_sfq.c:500 sfq_reset+0x13/0x50 net/sched/sch_sfq.c:525 qdisc_reset+0xfe/0x510 net/sched/sch_generic.c:1026 tbf_reset+0x3d/0x100 net/sched/sch_tbf.c:319 qdisc_reset+0xfe/0x510 net/sched/sch_generic.c:1026 dev_reset_queue+0x8c/0x140 net/sched/sch_generic.c:1296 netdev_for_each_tx_queue include/linux/netdevice.h:2350 [inline] dev_deactivate_many+0x6dc/0xc20 net/sched/sch_generic.c:1362 __dev_close_many+0x214/0x350 net/core/dev.c:1468 dev_close_many+0x207/0x510 net/core/dev.c:1506 unregister_netdevice_many+0x40f/0x16b0 net/core/dev.c:10738 unregister_netdevice_queue+0x2be/0x310 net/core/dev.c:10695 unregister_netdevice include/linux/netdevice.h:2893 [inline] __tun_detach+0x6b6/0x1600 drivers/net/tun.c:689 tun_detach drivers/net/tun.c:705 [inline] tun_chr_close+0x104/0x1b0 drivers/net/tun.c:3640 __fput+0x203/0x840 fs/file_table.c:280 task_work_run+0x129/0x1b0 kernel/task_work.c:185 exit_task_work include/linux/task_work.h:33 [inline] do_exit+0x5ce/0x2200 kernel/exit.c:931 do_group_exit+0x144/0x310 kernel/exit.c:1046 __do_sys_exit_group kernel/exit.c:1057 [inline] __se_sys_exit_group kernel/exit.c:1055 [inline] __x64_sys_exit_group+0x3b/0x40 kernel/exit.c:1055 do_syscall_64+0x6c/0xd0 entry_SYSCALL_64_after_hwframe+0x61/0xcb RIP: 0033:0x7fe5e7b52479 Code: Unable to access opcode bytes at RIP 0x7fe5e7b5244f. RSP: 002b:00007ffd3c800398 EFLAGS: 00000246 ORIG_RAX: 00000000000000e7 RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007fe5e7b52479 RDX: 000000000000003c RSI: 00000000000000e7 RDI: 0000000000000000 RBP: 00007fe5e7bcd2d0 R08: ffffffffffffffb8 R09: 0000000000000014 R10: 0000000000000000 R11: 0000000000000246 R12: 00007fe5e7bcd2d0 R13: 0000000000000000 R14: 00007fe5e7bcdd20 R15: 00007fe5e7b24270  The crash can be also be reproduced with the following (with a tc recompiled to allow for sfq limits of 1):  tc qdisc add dev dummy0 handle 1: root tbf rate 1Kbit burst 100b lat 1s ../iproute2-6.9.0/tc/tc qdisc add dev dummy0 handle 2: parent 1:10 sfq limit 1 ifconfig dummy0 up ping -I dummy0 -f -c2 -W0.1 8.8.8.8 sleep 1  Scenario that triggers the crash:  * the first packet is sent and queued in TBF and SFQ; qdisc qlen is 1  * TBF dequeues: it peeks from SFQ which moves the packet to the gso_skb list and keeps qdisc qlen set to 1. TBF is out of tokens so it schedules itself for later.  * the second packet is sent and TBF tries to queues it to SFQ. qdisc qlen is now 2 and because the SFQ limit is 1 the packet is dropped by SFQ. At this point qlen is 1, and all of the SFQ slots are empty, however q->tail is not NULL.  At this point, assuming no more packets are queued, when sch_dequeue runs again it will decrement the qlen for the current empty slot causing an underflow and the subsequent out of bounds access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57981?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57981" src="https://img.shields.io/badge/CVE--2024--57981-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: xhci: Fix NULL pointer dereference on certain command aborts  If a command is queued to the final usable TRB of a ring segment, the enqueue pointer is advanced to the subsequent link TRB and no further. If the command is later aborted, when the abort completion is handled the dequeue pointer is advanced to the first TRB of the next segment.  If no further commands are queued, xhci_handle_stopped_cmd_ring() sees the ring pointers unequal and assumes that there is a pending command, so it calls xhci_mod_cmd_timer() which crashes if cur_cmd was NULL.  Don't attempt timer setup if cur_cmd is NULL. The subsequent doorbell ring likely is unnecessary too, but it's harmless. Leave it alone.  This is probably Bug 219532, but no confirmation has been received.  The issue has been independently reproduced and confirmed fixed using a USB MCU programmed to NAK the Status stage of SET_ADDRESS forever. Everything continued working normally after several prevented crashes.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57977?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57977" src="https://img.shields.io/badge/CVE--2024--57977-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  memcg: fix soft lockup in the OOM process  A soft lockup issue was found in the product with about 56,000 tasks were in the OOM cgroup, it was traversing them when the soft lockup was triggered.  watchdog: BUG: soft lockup - CPU#2 stuck for 23s! [VM Thread:1503066] CPU: 2 PID: 1503066 Comm: VM Thread Kdump: loaded Tainted: G Hardware name: Huawei Cloud OpenStack Nova, BIOS RIP: 0010:console_unlock+0x343/0x540 RSP: 0000:ffffb751447db9a0 EFLAGS: 00000247 ORIG_RAX: ffffffffffffff13 RAX: 0000000000000001 RBX: 0000000000000000 RCX: 00000000ffffffff RDX: 0000000000000000 RSI: 0000000000000004 RDI: 0000000000000247 RBP: ffffffffafc71f90 R08: 0000000000000000 R09: 0000000000000040 R10: 0000000000000080 R11: 0000000000000000 R12: ffffffffafc74bd0 R13: ffffffffaf60a220 R14: 0000000000000247 R15: 0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f2fe6ad91f0 CR3: 00000004b2076003 CR4: 0000000000360ee0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: vprintk_emit+0x193/0x280 printk+0x52/0x6e dump_task+0x114/0x130 mem_cgroup_scan_tasks+0x76/0x100 dump_header+0x1fe/0x210 oom_kill_process+0xd1/0x100 out_of_memory+0x125/0x570 mem_cgroup_out_of_memory+0xb5/0xd0 try_charge+0x720/0x770 mem_cgroup_try_charge+0x86/0x180 mem_cgroup_try_charge_delay+0x1c/0x40 do_anonymous_page+0xb5/0x390 handle_mm_fault+0xc4/0x1f0  This is because thousands of processes are in the OOM cgroup, it takes a long time to traverse all of them.  As a result, this lead to soft lockup in the OOM process.  To fix this issue, call 'cond_resched' in the 'mem_cgroup_scan_tasks' function per 1000 iterations.  For global OOM, call 'touch_softlockup_watchdog' per 1000 iterations to avoid this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57973?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57973" src="https://img.shields.io/badge/CVE--2024--57973-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  rdma/cxgb4: Prevent potential integer overflow on 32bit  The "gl->tot_len" variable is controlled by the user.  It comes from process_responses().  On 32bit systems, the "gl->tot_len + sizeof(struct cpl_pass_accept_req) + sizeof(struct rss_header)" addition could have an integer wrapping bug.  Use size_add() to prevent this.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57953?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57953" src="https://img.shields.io/badge/CVE--2024--57953-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  rtc: tps6594: Fix integer overflow on 32bit systems  The problem is this multiply in tps6594_rtc_set_offset()  tmp = offset * TICKS_PER_HOUR;  The "tmp" variable is an s64 but "offset" is a long in the (-277774)-277774 range.  On 32bit systems a long can hold numbers up to approximately two billion.  The number of TICKS_PER_HOUR is really large, (32768 * 3600) or roughly a hundred million.  When you start multiplying by a hundred million it doesn't take long to overflow the two billion mark.  Probably the safest way to fix this is to change the type of TICKS_PER_HOUR to long long because it's such a large number.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57952?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57952" src="https://img.shields.io/badge/CVE--2024--57952-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Revert "libfs: fix infinite directory reads for offset dir"  The current directory offset allocator (based on mtree_alloc_cyclic) stores the next offset value to return in octx->next_offset. This mechanism typically returns values that increase monotonically over time. Eventually, though, the newly allocated offset value wraps back to a low number (say, 2) which is smaller than other already- allocated offset values.  Yu Kuai <yukuai3@huawei.com> reports that, after commit 64a7ce76fb90 ("libfs: fix infinite directory reads for offset dir"), if a directory's offset allocator wraps, existing entries are no longer visible via readdir/getdents because offset_readdir() stops listing entries once an entry's offset is larger than octx->next_offset. These entries vanish persistently -- they can be looked up, but will never again appear in readdir(3) output.  The reason for this is that the commit treats directory offsets as monotonically increasing integer values rather than opaque cookies, and introduces this comparison:  if (dentry2offset(dentry) >= last_index) {  On 64-bit platforms, the directory offset value upper bound is 2^63 - 1. Directory offsets will monotonically increase for millions of years without wrapping.  On 32-bit platforms, however, LONG_MAX is 2^31 - 1. The allocator can wrap after only a few weeks (at worst).  Revert commit 64a7ce76fb90 ("libfs: fix infinite directory reads for offset dir") to prepare for a fix that can work properly on 32-bit systems and might apply to recent LTS kernels where shmem employs the simple_offset mechanism.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57950?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57950" src="https://img.shields.io/badge/CVE--2024--57950-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Initialize denominator defaults to 1  [WHAT & HOW] Variables, used as denominators and maybe not assigned to other values, should be initialized to non-zero to avoid DIVIDE_BY_ZERO, as reported by Coverity.  (cherry picked from commit e2c4c6c10542ccfe4a0830bb6c9fd5b177b7bbb7)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57949?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57949" src="https://img.shields.io/badge/CVE--2024--57949-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  irqchip/gic-v3-its: Don't enable interrupts in its_irq_set_vcpu_affinity()  The following call-chain leads to enabling interrupts in a nested interrupt disabled section:  irq_set_vcpu_affinity() irq_get_desc_lock() raw_spin_lock_irqsave()   <--- Disable interrupts its_irq_set_vcpu_affinity() guard(raw_spinlock_irq)   <--- Enables interrupts when leaving the guard() irq_put_desc_unlock()        <--- Warns because interrupts are enabled  This was broken in commit b97e8a2f7130, which replaced the original raw_spin_[un]lock() pair with guard(raw_spinlock_irq).  Fix the issue by using guard(raw_spinlock).  [ tglx: Massaged change log ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57940?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57940" src="https://img.shields.io/badge/CVE--2024--57940-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  exfat: fix the infinite loop in exfat_readdir()  If the file system is corrupted so that a cluster is linked to itself in the cluster chain, and there is an unused directory entry in the cluster, 'dentry' will not be incremented, causing condition 'dentry < max_dentries' unable to prevent an infinite loop.  This infinite loop causes s_lock not to be released, and other tasks will hang, such as exfat_sync_fs().  This commit stops traversing the cluster chain when there is unused directory entry in the cluster to avoid this infinite loop.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57939?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57939" src="https://img.shields.io/badge/CVE--2024--57939-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  riscv: Fix sleeping in invalid context in die()  die() can be called in exception handler, and therefore cannot sleep. However, die() takes spinlock_t which can sleep with PREEMPT_RT enabled. That causes the following warning:  BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48 in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 285, name: mutex preempt_count: 110001, expected: 0 RCU nest depth: 0, expected: 0 CPU: 0 UID: 0 PID: 285 Comm: mutex Not tainted 6.12.0-rc7-00022-ge19049cf7d56-dirty #234 Hardware name: riscv-virtio,qemu (DT) Call Trace: dump_backtrace+0x1c/0x24 show_stack+0x2c/0x38 dump_stack_lvl+0x5a/0x72 dump_stack+0x14/0x1c __might_resched+0x130/0x13a rt_spin_lock+0x2a/0x5c die+0x24/0x112 do_trap_insn_illegal+0xa0/0xea _new_vmalloc_restore_context_a0+0xcc/0xd8 Oops - illegal instruction [#1]  Switch to use raw_spinlock_t, which does not sleep even with PREEMPT_RT enabled.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57938?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57938" src="https://img.shields.io/badge/CVE--2024--57938-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/sctp: Prevent autoclose integer overflow in sctp_association_init()  While by default max_autoclose equals to INT_MAX / HZ, one may set net.sctp.max_autoclose to UINT_MAX. There is code in sctp_association_init() that can consequently trigger overflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57933?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57933" src="https://img.shields.io/badge/CVE--2024--57933-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gve: guard XSK operations on the existence of queues  This patch predicates the enabling and disabling of XSK pools on the existence of queues. As it stands, if the interface is down, disabling or enabling XSK pools would result in a crash, as the RX queue pointer would be NULL. XSK pool registration will occur as part of the next interface up.  Similarly, xsk_wakeup needs be guarded against queues disappearing while the function is executing, so a check against the GVE_PRIV_FLAGS_NAPI_ENABLED flag is added to synchronize with the disabling of the bit and the synchronize_net() in gve_turndown.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57922?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57922" src="https://img.shields.io/badge/CVE--2024--57922-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Add check for granularity in dml ceil/floor helpers  [Why] Wrapper functions for dcn_bw_ceil2() and dcn_bw_floor2() should check for granularity is non zero to avoid assert and divide-by-zero error in dcn_bw_ functions.  [How] Add check for granularity 0.  (cherry picked from commit f6e09701c3eb2ccb8cb0518e0b67f1c69742a4ec)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57916?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57916" src="https://img.shields.io/badge/CVE--2024--57916-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  misc: microchip: pci1xxxx: Resolve kernel panic during GPIO IRQ handling  Resolve kernel panic caused by improper handling of IRQs while accessing GPIO values. This is done by replacing generic_handle_irq with handle_nested_irq.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57915?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57915" src="https://img.shields.io/badge/CVE--2024--57915-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57902?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57902" src="https://img.shields.io/badge/CVE--2024--57902-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  af_packet: fix vlan_get_tci() vs MSG_PEEK  Blamed commit forgot MSG_PEEK case, allowing a crash [1] as found by syzbot.  Rework vlan_get_tci() to not touch skb at all, so that it can be used from many cpus on the same skb.  Add a const qualifier to skb argument.  [1] skbuff: skb_under_panic: text:ffffffff8a8da482 len:32 put:14 head:ffff88807a1d5800 data:ffff88807a1d5810 tail:0x14 end:0x140 dev:<NULL> ------------[ cut here ]------------ kernel BUG at net/core/skbuff.c:206 ! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 0 UID: 0 PID: 5880 Comm: syz-executor172 Not tainted 6.13.0-rc3-syzkaller-00762-g9268abe611b0 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:skb_panic net/core/skbuff.c:206 [inline] RIP: 0010:skb_under_panic+0x14b/0x150 net/core/skbuff.c:216 Code: 0b 8d 48 c7 c6 9e 6c 26 8e 48 8b 54 24 08 8b 0c 24 44 8b 44 24 04 4d 89 e9 50 41 54 41 57 41 56 e8 3a 5a 79 f7 48 83 c4 20 90 <0f> 0b 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 RSP: 0018:ffffc90003baf5b8 EFLAGS: 00010286 RAX: 0000000000000087 RBX: dffffc0000000000 RCX: 8565c1eec37aa000 RDX: 0000000000000000 RSI: 0000000080000000 RDI: 0000000000000000 RBP: ffff88802616fb50 R08: ffffffff817f0a4c R09: 1ffff92000775e50 R10: dffffc0000000000 R11: fffff52000775e51 R12: 0000000000000140 R13: ffff88807a1d5800 R14: ffff88807a1d5810 R15: 0000000000000014 FS:  00007fa03261f6c0(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffd65753000 CR3: 0000000031720000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> skb_push+0xe5/0x100 net/core/skbuff.c:2636 vlan_get_tci+0x272/0x550 net/packet/af_packet.c:565 packet_recvmsg+0x13c9/0x1ef0 net/packet/af_packet.c:3616 sock_recvmsg_nosec net/socket.c:1044 [inline] sock_recvmsg+0x22f/0x280 net/socket.c:1066 ____sys_recvmsg+0x1c6/0x480 net/socket.c:2814 ___sys_recvmsg net/socket.c:2856 [inline] do_recvmmsg+0x426/0xab0 net/socket.c:2951 __sys_recvmmsg net/socket.c:3025 [inline] __do_sys_recvmmsg net/socket.c:3048 [inline] __se_sys_recvmmsg net/socket.c:3041 [inline] __x64_sys_recvmmsg+0x199/0x250 net/socket.c:3041 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57901?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57901" src="https://img.shields.io/badge/CVE--2024--57901-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  af_packet: fix vlan_get_protocol_dgram() vs MSG_PEEK  Blamed commit forgot MSG_PEEK case, allowing a crash [1] as found by syzbot.  Rework vlan_get_protocol_dgram() to not touch skb at all, so that it can be used from many cpus on the same skb.  Add a const qualifier to skb argument.  [1] skbuff: skb_under_panic: text:ffffffff8a8ccd05 len:29 put:14 head:ffff88807fc8e400 data:ffff88807fc8e3f4 tail:0x11 end:0x140 dev:<NULL> ------------[ cut here ]------------ kernel BUG at net/core/skbuff.c:206 ! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 1 UID: 0 PID: 5892 Comm: syz-executor883 Not tainted 6.13.0-rc4-syzkaller-00054-gd6ef8b40d075 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:skb_panic net/core/skbuff.c:206 [inline] RIP: 0010:skb_under_panic+0x14b/0x150 net/core/skbuff.c:216 Code: 0b 8d 48 c7 c6 86 d5 25 8e 48 8b 54 24 08 8b 0c 24 44 8b 44 24 04 4d 89 e9 50 41 54 41 57 41 56 e8 5a 69 79 f7 48 83 c4 20 90 <0f> 0b 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 RSP: 0018:ffffc900038d7638 EFLAGS: 00010282 RAX: 0000000000000087 RBX: dffffc0000000000 RCX: 609ffd18ea660600 RDX: 0000000000000000 RSI: 0000000080000000 RDI: 0000000000000000 RBP: ffff88802483c8d0 R08: ffffffff817f0a8c R09: 1ffff9200071ae60 R10: dffffc0000000000 R11: fffff5200071ae61 R12: 0000000000000140 R13: ffff88807fc8e400 R14: ffff88807fc8e3f4 R15: 0000000000000011 FS:  00007fbac5e006c0(0000) GS:ffff8880b8700000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fbac5e00d58 CR3: 000000001238e000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> skb_push+0xe5/0x100 net/core/skbuff.c:2636 vlan_get_protocol_dgram+0x165/0x290 net/packet/af_packet.c:585 packet_recvmsg+0x948/0x1ef0 net/packet/af_packet.c:3552 sock_recvmsg_nosec net/socket.c:1033 [inline] sock_recvmsg+0x22f/0x280 net/socket.c:1055 ____sys_recvmsg+0x1c6/0x480 net/socket.c:2803 ___sys_recvmsg net/socket.c:2845 [inline] do_recvmmsg+0x426/0xab0 net/socket.c:2940 __sys_recvmmsg net/socket.c:3014 [inline] __do_sys_recvmmsg net/socket.c:3037 [inline] __se_sys_recvmmsg net/socket.c:3030 [inline] __x64_sys_recvmmsg+0x199/0x250 net/socket.c:3030 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57895?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57895" src="https://img.shields.io/badge/CVE--2024--57895-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: set ATTR_CTIME flags when setting mtime  David reported that the new warning from setattr_copy_mgtime is coming like the following.  [  113.215316] ------------[ cut here ]------------ [  113.215974] WARNING: CPU: 1 PID: 31 at fs/attr.c:300 setattr_copy+0x1ee/0x200 [  113.219192] CPU: 1 UID: 0 PID: 31 Comm: kworker/1:1 Not tainted 6.13.0-rc1+ #234 [  113.220127] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.2-3-gd478f380-rebuilt.opensuse.org 04/01/2014 [  113.221530] Workqueue: ksmbd-io handle_ksmbd_work [ksmbd] [  113.222220] RIP: 0010:setattr_copy+0x1ee/0x200 [  113.222833] Code: 24 28 49 8b 44 24 30 48 89 53 58 89 43 6c 5b 41 5c 41 5d 41 5e 41 5f 5d c3 cc cc cc cc 48 89 df e8 77 d6 ff ff e9 cd fe ff ff <0f> 0b e9 be fe ff ff 66 0 [  113.225110] RSP: 0018:ffffaf218010fb68 EFLAGS: 00010202 [  113.225765] RAX: 0000000000000120 RBX: ffffa446815f8568 RCX: 0000000000000003 [  113.226667] RDX: ffffaf218010fd38 RSI: ffffa446815f8568 RDI: ffffffff94eb03a0 [  113.227531] RBP: ffffaf218010fb90 R08: 0000001a251e217d R09: 00000000675259fa [  113.228426] R10: 0000000002ba8a6d R11: ffffa4468196c7a8 R12: ffffaf218010fd38 [  113.229304] R13: 0000000000000120 R14: ffffffff94eb03a0 R15: 0000000000000000 [  113.230210] FS:  0000000000000000(0000) GS:ffffa44739d00000(0000) knlGS:0000000000000000 [  113.231215] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  113.232055] CR2: 00007efe0053d27e CR3: 000000000331a000 CR4: 00000000000006b0 [  113.232926] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [  113.233812] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [  113.234797] Call Trace: [  113.235116]  <TASK> [  113.235393]  ? __warn+0x73/0xd0 [  113.235802]  ? setattr_copy+0x1ee/0x200 [  113.236299]  ? report_bug+0xf3/0x1e0 [  113.236757]  ? handle_bug+0x4d/0x90 [  113.237202]  ? exc_invalid_op+0x13/0x60 [  113.237689]  ? asm_exc_invalid_op+0x16/0x20 [  113.238185]  ? setattr_copy+0x1ee/0x200 [  113.238692]  btrfs_setattr+0x80/0x820 [btrfs] [  113.239285]  ? get_stack_info_noinstr+0x12/0xf0 [  113.239857]  ? __module_address+0x22/0xa0 [  113.240368]  ? handle_ksmbd_work+0x6e/0x460 [ksmbd] [  113.240993]  ? __module_text_address+0x9/0x50 [  113.241545]  ? __module_address+0x22/0xa0 [  113.242033]  ? unwind_next_frame+0x10e/0x920 [  113.242600]  ? __pfx_stack_trace_consume_entry+0x10/0x10 [  113.243268]  notify_change+0x2c2/0x4e0 [  113.243746]  ? stack_depot_save_flags+0x27/0x730 [  113.244339]  ? set_file_basic_info+0x130/0x2b0 [ksmbd] [  113.244993]  set_file_basic_info+0x130/0x2b0 [ksmbd] [  113.245613]  ? process_scheduled_works+0xbe/0x310 [  113.246181]  ? worker_thread+0x100/0x240 [  113.246696]  ? kthread+0xc8/0x100 [  113.247126]  ? ret_from_fork+0x2b/0x40 [  113.247606]  ? ret_from_fork_asm+0x1a/0x30 [  113.248132]  smb2_set_info+0x63f/0xa70 [ksmbd]  ksmbd is trying to set the atime and mtime via notify_change without also setting the ctime. so This patch add ATTR_CTIME flags when setting mtime to avoid a warning.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57890?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57890" src="https://img.shields.io/badge/CVE--2024--57890-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/uverbs: Prevent integer overflow issue  In the expression "cmd.wqe_size * cmd.wr_count", both variables are u32 values that come from the user so the multiplication can lead to integer wrapping.  Then we pass the result to uverbs_request_next_ptr() which also could potentially wrap.  The "cmd.sge_count * sizeof(struct ib_uverbs_sge)" multiplication can also overflow on 32bit systems although it's fine on 64bit systems.  This patch does two things.  First, I've re-arranged the condition in uverbs_request_next_ptr() so that the use controlled variable "len" is on one side of the comparison by itself without any math.  Then I've modified all the callers to use size_mul() for the multiplications.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57882?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57882" src="https://img.shields.io/badge/CVE--2024--57882-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: fix TCP options overflow.  Syzbot reported the following splat:  Oops: general protection fault, probably for non-canonical address 0xdffffc0000000001: 0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f] CPU: 1 UID: 0 PID: 5836 Comm: sshd Not tainted 6.13.0-rc3-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 11/25/2024 RIP: 0010:_compound_head include/linux/page-flags.h:242 [inline] RIP: 0010:put_page+0x23/0x260 include/linux/mm.h:1552 Code: 90 90 90 90 90 90 90 55 41 57 41 56 53 49 89 fe 48 bd 00 00 00 00 00 fc ff df e8 f8 5e 12 f8 49 8d 5e 08 48 89 d8 48 c1 e8 03 <80> 3c 28 00 74 08 48 89 df e8 8f c7 78 f8 48 8b 1b 48 89 de 48 83 RSP: 0000:ffffc90003916c90 EFLAGS: 00010202 RAX: 0000000000000001 RBX: 0000000000000008 RCX: ffff888030458000 RDX: 0000000000000100 RSI: 0000000000000000 RDI: 0000000000000000 RBP: dffffc0000000000 R08: ffffffff898ca81d R09: 1ffff110054414ac R10: dffffc0000000000 R11: ffffed10054414ad R12: 0000000000000007 R13: ffff88802a20a542 R14: 0000000000000000 R15: 0000000000000000 FS:  00007f34f496e800(0000) GS:ffff8880b8700000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f9d6ec9ec28 CR3: 000000004d260000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> skb_page_unref include/linux/skbuff_ref.h:43 [inline] __skb_frag_unref include/linux/skbuff_ref.h:56 [inline] skb_release_data+0x483/0x8a0 net/core/skbuff.c:1119 skb_release_all net/core/skbuff.c:1190 [inline] __kfree_skb+0x55/0x70 net/core/skbuff.c:1204 tcp_clean_rtx_queue net/ipv4/tcp_input.c:3436 [inline] tcp_ack+0x2442/0x6bc0 net/ipv4/tcp_input.c:4032 tcp_rcv_state_process+0x8eb/0x44e0 net/ipv4/tcp_input.c:6805 tcp_v4_do_rcv+0x77d/0xc70 net/ipv4/tcp_ipv4.c:1939 tcp_v4_rcv+0x2dc0/0x37f0 net/ipv4/tcp_ipv4.c:2351 ip_protocol_deliver_rcu+0x22e/0x440 net/ipv4/ip_input.c:205 ip_local_deliver_finish+0x341/0x5f0 net/ipv4/ip_input.c:233 NF_HOOK+0x3a4/0x450 include/linux/netfilter.h:314 NF_HOOK+0x3a4/0x450 include/linux/netfilter.h:314 __netif_receive_skb_one_core net/core/dev.c:5672 [inline] __netif_receive_skb+0x2bf/0x650 net/core/dev.c:5785 process_backlog+0x662/0x15b0 net/core/dev.c:6117 __napi_poll+0xcb/0x490 net/core/dev.c:6883 napi_poll net/core/dev.c:6952 [inline] net_rx_action+0x89b/0x1240 net/core/dev.c:7074 handle_softirqs+0x2d4/0x9b0 kernel/softirq.c:561 __do_softirq kernel/softirq.c:595 [inline] invoke_softirq kernel/softirq.c:435 [inline] __irq_exit_rcu+0xf7/0x220 kernel/softirq.c:662 irq_exit_rcu+0x9/0x30 kernel/softirq.c:678 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline] sysvec_apic_timer_interrupt+0x57/0xc0 arch/x86/kernel/apic/apic.c:1049 asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702 RIP: 0033:0x7f34f4519ad5 Code: 85 d2 74 0d 0f 10 02 48 8d 54 24 20 0f 11 44 24 20 64 8b 04 25 18 00 00 00 85 c0 75 27 41 b8 08 00 00 00 b8 0f 01 00 00 0f 05 <48> 3d 00 f0 ff ff 76 75 48 8b 15 24 73 0d 00 f7 d8 64 89 02 48 83 RSP: 002b:00007ffec5b32ce0 EFLAGS: 00000246 RAX: 0000000000000001 RBX: 00000000000668a0 RCX: 00007f34f4519ad5 RDX: 00007ffec5b32d00 RSI: 0000000000000004 RDI: 0000564f4bc6cae0 RBP: 0000564f4bc6b5a0 R08: 0000000000000008 R09: 0000000000000000 R10: 00007ffec5b32de8 R11: 0000000000000246 R12: 0000564f48ea8aa4 R13: 0000000000000001 R14: 0000564f48ea93e8 R15: 00007ffec5b32d68 </TASK>  Eric noted a probable shinfo->nr_frags corruption, which indeed occurs.  The root cause is a buggy MPTCP option len computation in some circumstances: the ADD_ADDR option should be mutually exclusive with DSS since the blamed commit.  Still, mptcp_established_options_add_addr() tries to set the relevant info in mptcp_out_options, if ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57841?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57841" src="https://img.shields.io/badge/CVE--2024--57841-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fix memory leak in tcp_conn_request()  If inet_csk_reqsk_queue_hash_add() return false, tcp_conn_request() will return without free the dst memory, which allocated in af_ops->route_req.  Here is the kmemleak stack:  unreferenced object 0xffff8881198631c0 (size 240): comm "softirq", pid 0, jiffies 4299266571 (age 1802.392s) hex dump (first 32 bytes): 00 10 9b 03 81 88 ff ff 80 98 da bc ff ff ff ff  ................ 81 55 18 bb ff ff ff ff 00 00 00 00 00 00 00 00  .U.............. backtrace: [<ffffffffb93e8d4c>] kmem_cache_alloc+0x60c/0xa80 [<ffffffffba11b4c5>] dst_alloc+0x55/0x250 [<ffffffffba227bf6>] rt_dst_alloc+0x46/0x1d0 [<ffffffffba23050a>] __mkroute_output+0x29a/0xa50 [<ffffffffba23456b>] ip_route_output_key_hash+0x10b/0x240 [<ffffffffba2346bd>] ip_route_output_flow+0x1d/0x90 [<ffffffffba254855>] inet_csk_route_req+0x2c5/0x500 [<ffffffffba26b331>] tcp_conn_request+0x691/0x12c0 [<ffffffffba27bd08>] tcp_rcv_state_process+0x3c8/0x11b0 [<ffffffffba2965c6>] tcp_v4_do_rcv+0x156/0x3b0 [<ffffffffba299c98>] tcp_v4_rcv+0x1cf8/0x1d80 [<ffffffffba239656>] ip_protocol_deliver_rcu+0xf6/0x360 [<ffffffffba2399a6>] ip_local_deliver_finish+0xe6/0x1e0 [<ffffffffba239b8e>] ip_local_deliver+0xee/0x360 [<ffffffffba239ead>] ip_rcv+0xad/0x2f0 [<ffffffffba110943>] __netif_receive_skb_one_core+0x123/0x140  Call dst_release() to free the dst memory when inet_csk_reqsk_queue_hash_add() return false in tcp_conn_request().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57834?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57834" src="https://img.shields.io/badge/CVE--2024--57834-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: vidtv: Fix a null-ptr-deref in vidtv_mux_stop_thread  syzbot report a null-ptr-deref in vidtv_mux_stop_thread. [1]  If dvb->mux is not initialized successfully by vidtv_mux_init() in the vidtv_start_streaming(), it will trigger null pointer dereference about mux in vidtv_mux_stop_thread().  Adjust the timing of streaming initialization and check it before stopping it.  [1] KASAN: null-ptr-deref in range [0x0000000000000128-0x000000000000012f] CPU: 0 UID: 0 PID: 5842 Comm: syz-executor248 Not tainted 6.13.0-rc4-syzkaller-00012-g9b2ffa6148b1 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:vidtv_mux_stop_thread+0x26/0x80 drivers/media/test-drivers/vidtv/vidtv_mux.c:471 Code: 90 90 90 90 66 0f 1f 00 55 53 48 89 fb e8 82 2e c8 f9 48 8d bb 28 01 00 00 48 b8 00 00 00 00 00 fc ff df 48 89 fa 48 c1 ea 03 <0f> b6 04 02 84 c0 74 02 7e 3b 0f b6 ab 28 01 00 00 31 ff 89 ee e8 RSP: 0018:ffffc90003f2faa8 EFLAGS: 00010202 RAX: dffffc0000000000 RBX: 0000000000000000 RCX: ffffffff87cfb125 RDX: 0000000000000025 RSI: ffffffff87d120ce RDI: 0000000000000128 RBP: ffff888029b8d220 R08: 0000000000000005 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000003 R12: ffff888029b8d188 R13: ffffffff8f590aa0 R14: ffffc9000581c5c8 R15: ffff888029a17710 FS:  00007f7eef5156c0(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f7eef5e635c CR3: 0000000076ca6000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> vidtv_stop_streaming drivers/media/test-drivers/vidtv/vidtv_bridge.c:209 [inline] vidtv_stop_feed+0x151/0x250 drivers/media/test-drivers/vidtv/vidtv_bridge.c:252 dmx_section_feed_stop_filtering+0x90/0x160 drivers/media/dvb-core/dvb_demux.c:1000 dvb_dmxdev_feed_stop.isra.0+0x1ee/0x270 drivers/media/dvb-core/dmxdev.c:486 dvb_dmxdev_filter_stop+0x22a/0x3a0 drivers/media/dvb-core/dmxdev.c:559 dvb_dmxdev_filter_free drivers/media/dvb-core/dmxdev.c:840 [inline] dvb_demux_release+0x92/0x550 drivers/media/dvb-core/dmxdev.c:1246 __fput+0x3f8/0xb60 fs/file_table.c:450 task_work_run+0x14e/0x250 kernel/task_work.c:239 get_signal+0x1d3/0x2610 kernel/signal.c:2790 arch_do_signal_or_restart+0x90/0x7e0 arch/x86/kernel/signal.c:337 exit_to_user_mode_loop kernel/entry/common.c:111 [inline] exit_to_user_mode_prepare include/linux/entry-common.h:329 [inline] __syscall_exit_to_user_mode_work kernel/entry/common.c:207 [inline] syscall_exit_to_user_mode+0x150/0x2a0 kernel/entry/common.c:218 do_syscall_64+0xda/0x250 arch/x86/entry/common.c:89 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57802?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--57802" src="https://img.shields.io/badge/CVE--2024--57802-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netrom: check buffer length before accessing it  Syzkaller reports an uninit value read from ax25cmp when sending raw message through ieee802154 implementation.  ===================================================== BUG: KMSAN: uninit-value in ax25cmp+0x3a5/0x460 net/ax25/ax25_addr.c:119 ax25cmp+0x3a5/0x460 net/ax25/ax25_addr.c:119 nr_dev_get+0x20e/0x450 net/netrom/nr_route.c:601 nr_route_frame+0x1a2/0xfc0 net/netrom/nr_route.c:774 nr_xmit+0x5a/0x1c0 net/netrom/nr_dev.c:144 __netdev_start_xmit include/linux/netdevice.h:4940 [inline] netdev_start_xmit include/linux/netdevice.h:4954 [inline] xmit_one net/core/dev.c:3548 [inline] dev_hard_start_xmit+0x247/0xa10 net/core/dev.c:3564 __dev_queue_xmit+0x33b8/0x5130 net/core/dev.c:4349 dev_queue_xmit include/linux/netdevice.h:3134 [inline] raw_sendmsg+0x654/0xc10 net/ieee802154/socket.c:299 ieee802154_sock_sendmsg+0x91/0xc0 net/ieee802154/socket.c:96 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745 [inline] ____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638 __sys_sendmsg net/socket.c:2667 [inline] __do_sys_sendmsg net/socket.c:2676 [inline] __se_sys_sendmsg net/socket.c:2674 [inline] __x64_sys_sendmsg+0x307/0x490 net/socket.c:2674 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0x44/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b  Uninit was created at: slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768 slab_alloc_node mm/slub.c:3478 [inline] kmem_cache_alloc_node+0x5e9/0xb10 mm/slub.c:3523 kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:560 __alloc_skb+0x318/0x740 net/core/skbuff.c:651 alloc_skb include/linux/skbuff.h:1286 [inline] alloc_skb_with_frags+0xc8/0xbd0 net/core/skbuff.c:6334 sock_alloc_send_pskb+0xa80/0xbf0 net/core/sock.c:2780 sock_alloc_send_skb include/net/sock.h:1884 [inline] raw_sendmsg+0x36d/0xc10 net/ieee802154/socket.c:282 ieee802154_sock_sendmsg+0x91/0xc0 net/ieee802154/socket.c:96 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745 [inline] ____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638 __sys_sendmsg net/socket.c:2667 [inline] __do_sys_sendmsg net/socket.c:2676 [inline] __se_sys_sendmsg net/socket.c:2674 [inline] __x64_sys_sendmsg+0x307/0x490 net/socket.c:2674 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0x44/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b  CPU: 0 PID: 5037 Comm: syz-executor166 Not tainted 6.7.0-rc7-syzkaller-00003-gfbafc3e621c3 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 11/17/2023 =====================================================  This issue occurs because the skb buffer is too small, and it's actual allocation is aligned. This hides an actual issue, which is that nr_route_frame does not validate the buffer size before using it.  Fix this issue by checking skb->len before accessing any fields in skb->data.  Found by Linux Verification Center (linuxtesting.org) with Syzkaller.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56761?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--56761" src="https://img.shields.io/badge/CVE--2024--56761-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  x86/fred: Clear WFE in missing-ENDBRANCH #CPs  An indirect branch instruction sets the CPU indirect branch tracker (IBT) into WAIT_FOR_ENDBRANCH (WFE) state and WFE stays asserted across the instruction boundary.  When the decoder finds an inappropriate instruction while WFE is set ENDBR, the CPU raises a #CP fault.  For the "kernel IBT no ENDBR" selftest where #CPs are deliberately triggered, the WFE state of the interrupted context needs to be cleared to let execution continue.  Otherwise when the CPU resumes from the instruction that just caused the previous #CP, another missing-ENDBRANCH #CP is raised and the CPU enters a dead loop.  This is not a problem with IDT because it doesn't preserve WFE and IRET doesn't set WFE.  But FRED provides space on the entry stack (in an expanded CS area) to save and restore the WFE state, thus the WFE state is no longer clobbered, so software must clear it.  Clear WFE to avoid dead looping in ibt_clear_fred_wfe() and the !ibt_fatal code path when execution is allowed to continue.  Clobbering WFE in any other circumstance is a security-relevant bug.  [ dhansen: changelog rewording ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56757?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--56757" src="https://img.shields.io/badge/CVE--2024--56757-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: btusb: mediatek: add intf release flow when usb disconnect  MediaTek claim an special usb intr interface for ISO data transmission. The interface need to be released before unregistering hci device when usb disconnect. Removing BT usb dongle without properly releasing the interface may cause Kernel panic while unregister hci device.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56712?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--56712" src="https://img.shields.io/badge/CVE--2024--56712-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  udmabuf: fix memory leak on last export_udmabuf() error path  In export_udmabuf(), if dma_buf_fd() fails because the FD table is full, a dma_buf owning the udmabuf has already been created; but the error handling in udmabuf_create() will tear down the udmabuf without doing anything about the containing dma_buf.  This leaves a dma_buf in memory that contains a dangling pointer; though that doesn't seem to lead to anything bad except a memory leak.  Fix it by moving the dma_buf_fd() call out of export_udmabuf() so that we can give it different error handling.  Note that the shape of this code changed a lot in commit 5e72b2b41a21 ("udmabuf: convert udmabuf driver to use folios"); but the memory leak seems to have existed since the introduction of udmabuf.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56702?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--56702" src="https://img.shields.io/badge/CVE--2024--56702-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Mark raw_tp arguments with PTR_MAYBE_NULL  Arguments to a raw tracepoint are tagged as trusted, which carries the semantics that the pointer will be non-NULL.  However, in certain cases, a raw tracepoint argument may end up being NULL. More context about this issue is available in [0].  Thus, there is a discrepancy between the reality, that raw_tp arguments can actually be NULL, and the verifier's knowledge, that they are never NULL, causing explicit NULL checks to be deleted, and accesses to such pointers potentially crashing the kernel.  To fix this, mark raw_tp arguments as PTR_MAYBE_NULL, and then special case the dereference and pointer arithmetic to permit it, and allow passing them into helpers/kfuncs; these exceptions are made for raw_tp programs only. Ensure that we don't do this when ref_obj_id > 0, as in that case this is an acquired object and doesn't need such adjustment.  The reason we do mask_raw_tp_trusted_reg logic is because other will recheck in places whether the register is a trusted_reg, and then consider our register as untrusted when detecting the presence of the PTR_MAYBE_NULL flag.  To allow safe dereference, we enable PROBE_MEM marking when we see loads into trusted pointers with PTR_MAYBE_NULL.  While trusted raw_tp arguments can also be passed into helpers or kfuncs where such broken assumption may cause issues, a future patch set will tackle their case separately, as PTR_TO_BTF_ID (without PTR_TRUSTED) can already be passed into helpers and causes similar problems. Thus, they are left alone for now.  It is possible that these checks also permit passing non-raw_tp args that are trusted PTR_TO_BTF_ID with null marking. In such a case, allowing dereference when pointer is NULL expands allowed behavior, so won't regress existing programs, and the case of passing these into helpers is the same as above and will be dealt with later.  Also update the failure case in tp_btf_nullable selftest to capture the new behavior, as the verifier will no longer cause an error when directly dereference a raw tracepoint argument marked as __nullable.  [0]: https://lore.kernel.org/bpf/ZrCZS6nisraEqehw@jlelli-thinkpadt14gen4.remote.csb

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56674?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--56674" src="https://img.shields.io/badge/CVE--2024--56674-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  virtio_net: correct netdev_tx_reset_queue() invocation point  When virtnet_close is followed by virtnet_open, some TX completions can possibly remain unconsumed, until they are finally processed during the first NAPI poll after the netdev_tx_reset_queue(), resulting in a crash [1]. Commit b96ed2c97c79 ("virtio_net: move netdev_tx_reset_queue() call before RX napi enable") was not sufficient to eliminate all BQL crash cases for virtio-net.  This issue can be reproduced with the latest net-next master by running: `while :; do ip l set DEV down; ip l set DEV up; done` under heavy network TX load from inside the machine.  netdev_tx_reset_queue() can actually be dropped from virtnet_open path; the device is not stopped in any case. For BQL core part, it's just like traffic nearly ceases to exist for some period. For stall detector added to BQL, even if virtnet_close could somehow lead to some TX completions delayed for long, followed by virtnet_open, we can just take it as stall as mentioned in commit 6025b9135f7a ("net: dqs: add NIC stall detector based on BQL"). Note also that users can still reset stall_max via sysfs.  So, drop netdev_tx_reset_queue() from virtnet_enable_queue_pair(). This eliminates the BQL crashes. As a result, netdev_tx_reset_queue() is now explicitly required in freeze/restore path. This patch adds it to immediately after free_unused_bufs(), following the rule of thumb: netdev_tx_reset_queue() should follow any SKB freeing not followed by netdev_tx_completed_queue(). This seems the most consistent and streamlined approach, and now netdev_tx_reset_queue() runs whenever free_unused_bufs() is done.  [1]: ------------[ cut here ]------------ kernel BUG at lib/dynamic_queue_limits.c:99! Oops: invalid opcode: 0000 [#1] PREEMPT SMP NOPTI CPU: 7 UID: 0 PID: 1598 Comm: ip Tainted: G    N 6.12.0net-next_main+ #2 Tainted: [N]=TEST Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), \ BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014 RIP: 0010:dql_completed+0x26b/0x290 Code: b7 c2 49 89 e9 44 89 da 89 c6 4c 89 d7 e8 ed 17 47 00 58 65 ff 0d 4d 27 90 7e 0f 85 fd fe ff ff e8 ea 53 8d ff e9 f3 fe ff ff <0f> 0b 01 d2 44 89 d1 29 d1 ba 00 00 00 00 0f 48 ca e9 28 ff ff ff RSP: 0018:ffffc900002b0d08 EFLAGS: 00010297 RAX: 0000000000000000 RBX: ffff888102398c80 RCX: 0000000080190009 RDX: 0000000000000000 RSI: 000000000000006a RDI: 0000000000000000 RBP: ffff888102398c00 R08: 0000000000000000 R09: 0000000000000000 R10: 00000000000000ca R11: 0000000000015681 R12: 0000000000000001 R13: ffffc900002b0d68 R14: ffff88811115e000 R15: ffff8881107aca40 FS:  00007f41ded69500(0000) GS:ffff888667dc0000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000556ccc2dc1a0 CR3: 0000000104fd8003 CR4: 0000000000772ef0 PKRU: 55555554 Call Trace: <IRQ> ? die+0x32/0x80 ? do_trap+0xd9/0x100 ? dql_completed+0x26b/0x290 ? dql_completed+0x26b/0x290 ? do_error_trap+0x6d/0xb0 ? dql_completed+0x26b/0x290 ? exc_invalid_op+0x4c/0x60 ? dql_completed+0x26b/0x290 ? asm_exc_invalid_op+0x16/0x20 ? dql_completed+0x26b/0x290 __free_old_xmit+0xff/0x170 [virtio_net] free_old_xmit+0x54/0xc0 [virtio_net] virtnet_poll+0xf4/0xe30 [virtio_net] ? __update_load_avg_cfs_rq+0x264/0x2d0 ? update_curr+0x35/0x260 ? reweight_entity+0x1be/0x260 __napi_poll.constprop.0+0x28/0x1c0 net_rx_action+0x329/0x420 ? enqueue_hrtimer+0x35/0x90 ? trace_hardirqs_on+0x1d/0x80 ? kvm_sched_clock_read+0xd/0x20 ? sched_clock+0xc/0x30 ? kvm_sched_clock_read+0xd/0x20 ? sched_clock+0xc/0x30 ? sched_clock_cpu+0xd/0x1a0 handle_softirqs+0x138/0x3e0 do_softirq.part.0+0x89/0xc0 </IRQ> <TASK> __local_bh_enable_ip+0xa7/0xb0 virtnet_open+0xc8/0x310 [virtio_net] __dev_open+0xfa/0x1b0 __dev_change_flags+0x1de/0x250 dev_change_flags+0x22/0x60 do_setlink.isra.0+0x2df/0x10b0 ? rtnetlink_rcv_msg+0x34f/0x3f0 ? netlink_rcv_skb+0x54/0x100 ? netlink_unicas ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56671?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--56671" src="https://img.shields.io/badge/CVE--2024--56671-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gpio: graniterapids: Fix vGPIO driver crash  Move setting irq_chip.name from probe() function to the initialization of "irq_chip" struct in order to fix vGPIO driver crash during bootup.  Crash was caused by unauthorized modification of irq_chip.name field where irq_chip struct was initialized as const.  This behavior is a consequence of suboptimal implementation of gpio_irq_chip_set_chip(), which should be changed to avoid casting away const qualifier.  Crash log: BUG: unable to handle page fault for address: ffffffffc0ba81c0 /#PF: supervisor write access in kernel mode /#PF: error_code(0x0003) - permissions violation CPU: 33 UID: 0 PID: 1075 Comm: systemd-udevd Not tainted 6.12.0-rc6-00077-g2e1b3cc9d7f7 #1 Hardware name: Intel Corporation Kaseyville RP/Kaseyville RP, BIOS KVLDCRB1.PGS.0026.D73.2410081258 10/08/2024 RIP: 0010:gnr_gpio_probe+0x171/0x220 [gpio_graniterapids]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56617?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--56617" src="https://img.shields.io/badge/CVE--2024--56617-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cacheinfo: Allocate memory during CPU hotplug if not done from the primary CPU  Commit  5944ce092b97 ("arch_topology: Build cacheinfo from primary CPU")  adds functionality that architectures can use to optionally allocate and build cacheinfo early during boot. Commit  6539cffa9495 ("cacheinfo: Add arch specific early level initializer")  lets secondary CPUs correct (and reallocate memory) cacheinfo data if needed.  If the early build functionality is not used and cacheinfo does not need correction, memory for cacheinfo is never allocated. x86 does not use the early build functionality. Consequently, during the cacheinfo CPU hotplug callback, last_level_cache_is_valid() attempts to dereference a NULL pointer:  BUG: kernel NULL pointer dereference, address: 0000000000000100 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not present page PGD 0 P4D 0 Oops: 0000 [#1] PREEPMT SMP NOPTI CPU: 0 PID 19 Comm: cpuhp/0 Not tainted 6.4.0-rc2 #1 RIP: 0010: last_level_cache_is_valid+0x95/0xe0a  Allocate memory for cacheinfo during the cacheinfo CPU hotplug callback if not done earlier.  Moreover, before determining the validity of the last-level cache info, ensure that it has been allocated. Simply checking for non-zero cache_leaves() is not sufficient, as some architectures (e.g., Intel processors) have non-zero cache_leaves() before allocation.  Dereferencing NULL cacheinfo can occur in update_per_cpu_data_slice_size(). This function iterates over all online CPUs. However, a CPU may have come online recently, but its cacheinfo may not have been allocated yet.  While here, remove an unnecessary indentation in allocate_cache_info().  [ bp: Massage. ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56544?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--56544" src="https://img.shields.io/badge/CVE--2024--56544-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  udmabuf: change folios array from kmalloc to kvmalloc  When PAGE_SIZE 4096, MAX_PAGE_ORDER 10, 64bit machine, page_alloc only support 4MB. If above this, trigger this warn and return NULL.  udmabuf can change size limit, if change it to 3072(3GB), and then alloc 3GB udmabuf, will fail create.  [ 4080.876581] ------------[ cut here ]------------ [ 4080.876843] WARNING: CPU: 3 PID: 2015 at mm/page_alloc.c:4556 __alloc_pages+0x2c8/0x350 [ 4080.878839] RIP: 0010:__alloc_pages+0x2c8/0x350 [ 4080.879470] Call Trace: [ 4080.879473]  <TASK> [ 4080.879473]  ? __alloc_pages+0x2c8/0x350 [ 4080.879475]  ? __warn.cold+0x8e/0xe8 [ 4080.880647]  ? __alloc_pages+0x2c8/0x350 [ 4080.880909]  ? report_bug+0xff/0x140 [ 4080.881175]  ? handle_bug+0x3c/0x80 [ 4080.881556]  ? exc_invalid_op+0x17/0x70 [ 4080.881559]  ? asm_exc_invalid_op+0x1a/0x20 [ 4080.882077]  ? udmabuf_create+0x131/0x400  Because MAX_PAGE_ORDER, kmalloc can max alloc 4096 * (1 << 10), 4MB memory, each array entry is pointer(8byte), so can save 524288 pages(2GB).  Further more, costly order(order 3) may not be guaranteed that it can be applied for, due to fragmentation.  This patch change udmabuf array use kvmalloc_array, this can fallback alloc into vmalloc, which can guarantee allocation for any size and does not affect the performance of kmalloc allocations.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53207?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--53207" src="https://img.shields.io/badge/CVE--2024--53207-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: MGMT: Fix possible deadlocks  This fixes possible deadlocks like the following caused by hci_cmd_sync_dequeue causing the destroy function to run:  INFO: task kworker/u19:0:143 blocked for more than 120 seconds. Tainted: G        W  O        6.8.0-2024-03-19-intel-next-iLS-24ww14 #1 "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message. task:kworker/u19:0   state:D stack:0     pid:143   tgid:143   ppid:2 flags:0x00004000 Workqueue: hci0 hci_cmd_sync_work [bluetooth] Call Trace: <TASK> __schedule+0x374/0xaf0 schedule+0x3c/0xf0 schedule_preempt_disabled+0x1c/0x30 __mutex_lock.constprop.0+0x3ef/0x7a0 __mutex_lock_slowpath+0x13/0x20 mutex_lock+0x3c/0x50 mgmt_set_connectable_complete+0xa4/0x150 [bluetooth] ? kfree+0x211/0x2a0 hci_cmd_sync_dequeue+0xae/0x130 [bluetooth] ? __pfx_cmd_complete_rsp+0x10/0x10 [bluetooth] cmd_complete_rsp+0x26/0x80 [bluetooth] mgmt_pending_foreach+0x4d/0x70 [bluetooth] __mgmt_power_off+0x8d/0x180 [bluetooth] ? _raw_spin_unlock_irq+0x23/0x40 hci_dev_close_sync+0x445/0x5b0 [bluetooth] hci_set_powered_sync+0x149/0x250 [bluetooth] set_powered_sync+0x24/0x60 [bluetooth] hci_cmd_sync_work+0x90/0x150 [bluetooth] process_one_work+0x13e/0x300 worker_thread+0x2f7/0x420 ? __pfx_worker_thread+0x10/0x10 kthread+0x107/0x140 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x3d/0x60 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53064?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--53064" src="https://img.shields.io/badge/CVE--2024--53064-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  idpf: fix idpf_vc_core_init error path  In an event where the platform running the device control plane is rebooted, reset is detected on the driver. It releases all the resources and waits for the reset to complete. Once the reset is done, it tries to build the resources back. At this time if the device control plane is not yet started, then the driver timeouts on the virtchnl message and retries to establish the mailbox again.  In the retry flow, mailbox is deinitialized but the mailbox workqueue is still alive and polling for the mailbox message. This results in accessing the released control queue leading to null-ptr-deref. Fix it by unrolling the work queue cancellation and mailbox deinitialization in the reverse order which they got initialized.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53056?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--53056" src="https://img.shields.io/badge/CVE--2024--53056-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/mediatek: Fix potential NULL dereference in mtk_crtc_destroy()  In mtk_crtc_create(), if the call to mbox_request_channel() fails then we set the "mtk_crtc->cmdq_client.chan" pointer to NULL.  In that situation, we do not call cmdq_pkt_create().  During the cleanup, we need to check if the "mtk_crtc->cmdq_client.chan" is NULL first before calling cmdq_pkt_destroy().  Calling cmdq_pkt_destroy() is unnecessary if we didn't call cmdq_pkt_create() and it will result in a NULL pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53054?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--53054" src="https://img.shields.io/badge/CVE--2024--53054-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-52559?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--52559" src="https://img.shields.io/badge/CVE--2024--52559-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/msm/gem: prevent integer overflow in msm_ioctl_gem_submit()  The "submit->cmd[i].size" and "submit->cmd[i].offset" variables are u32 values that come from the user via the submit_lookup_cmds() function. This addition could lead to an integer wrapping bug so use size_add() to prevent that.  Patchwork: https://patchwork.freedesktop.org/patch/624696/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50178?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--50178" src="https://img.shields.io/badge/CVE--2024--50178-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cpufreq: loongson3: Use raw_smp_processor_id() in do_service_request()  Use raw_smp_processor_id() instead of plain smp_processor_id() in do_service_request(), otherwise we may get some errors with the driver enabled:  BUG: using smp_processor_id() in preemptible [00000000] code: (udev-worker)/208 caller is loongson3_cpufreq_probe+0x5c/0x250 [loongson3_cpufreq]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50157?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--50157" src="https://img.shields.io/badge/CVE--2024--50157-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/bnxt_re: Avoid CPU lockups due fifo occupancy check loop  Driver waits indefinitely for the fifo occupancy to go below a threshold as soon as the pacing interrupt is received. This can cause soft lockup on one of the processors, if the rate of DB is very high.  Add a loop count for FPGA and exit the __wait_for_fifo_occupancy_below_th if the loop is taking more time. Pacing will be continuing until the occupancy is below the threshold. This is ensured by the checks in bnxt_re_pacing_timer_exp and further scheduling the work for pacing based on the fifo occupancy.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50102?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--50102" src="https://img.shields.io/badge/CVE--2024--50102-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  x86: fix user address masking non-canonical speculation issue  It turns out that AMD has a "Meltdown Lite(tm)" issue with non-canonical accesses in kernel space.  And so using just the high bit to decide whether an access is in user space or kernel space ends up with the good old "leak speculative data" if you have the right gadget using the result:  CVE-2020-12965 “Transient Execution of Non-Canonical Accesses“  Now, the kernel surrounds the access with a STAC/CLAC pair, and those instructions end up serializing execution on older Zen architectures, which closes the speculation window.  But that was true only up until Zen 5, which renames the AC bit [1]. That improves performance of STAC/CLAC a lot, but also means that the speculation window is now open.  Note that this affects not just the new address masking, but also the regular valid_user_address() check used by access_ok(), and the asm version of the sign bit check in the get_user() helpers.  It does not affect put_user() or clear_user() variants, since there's no speculative result to be used in a gadget for those operations.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50091?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--50091" src="https://img.shields.io/badge/CVE--2024--50091-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dm vdo: don't refer to dedupe_context after releasing it  Clear the dedupe_context pointer in a data_vio whenever ownership of the context is lost, so that vdo can't examine it accidentally.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50089?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--50089" src="https://img.shields.io/badge/CVE--2024--50089-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50034?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--50034" src="https://img.shields.io/badge/CVE--2024--50034-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/smc: fix lacks of icsk_syn_mss with IPPROTO_SMC  Eric report a panic on IPPROTO_SMC, and give the facts that when INET_PROTOSW_ICSK was set, icsk->icsk_sync_mss must be set too.  Bug: Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000 Mem abort info: ESR = 0x0000000086000005 EC = 0x21: IABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x05: level 1 translation fault user pgtable: 4k pages, 48-bit VAs, pgdp=00000001195d1000 [0000000000000000] pgd=0800000109c46003, p4d=0800000109c46003, pud=0000000000000000 Internal error: Oops: 0000000086000005 [#1] PREEMPT SMP Modules linked in: CPU: 1 UID: 0 PID: 8037 Comm: syz.3.265 Not tainted 6.11.0-rc7-syzkaller-g5f5673607153 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 08/06/2024 pstate: 80400005 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : 0x0 lr : cipso_v4_sock_setattr+0x2a8/0x3c0 net/ipv4/cipso_ipv4.c:1910 sp : ffff80009b887a90 x29: ffff80009b887aa0 x28: ffff80008db94050 x27: 0000000000000000 x26: 1fffe0001aa6f5b3 x25: dfff800000000000 x24: ffff0000db75da00 x23: 0000000000000000 x22: ffff0000d8b78518 x21: 0000000000000000 x20: ffff0000d537ad80 x19: ffff0000d8b78000 x18: 1fffe000366d79ee x17: ffff8000800614a8 x16: ffff800080569b84 x15: 0000000000000001 x14: 000000008b336894 x13: 00000000cd96feaa x12: 0000000000000003 x11: 0000000000040000 x10: 00000000000020a3 x9 : 1fffe0001b16f0f1 x8 : 0000000000000000 x7 : 0000000000000000 x6 : 000000000000003f x5 : 0000000000000040 x4 : 0000000000000001 x3 : 0000000000000000 x2 : 0000000000000002 x1 : 0000000000000000 x0 : ffff0000d8b78000 Call trace: 0x0 netlbl_sock_setattr+0x2e4/0x338 net/netlabel/netlabel_kapi.c:1000 smack_netlbl_add+0xa4/0x154 security/smack/smack_lsm.c:2593 smack_socket_post_create+0xa8/0x14c security/smack/smack_lsm.c:2973 security_socket_post_create+0x94/0xd4 security/security.c:4425 __sock_create+0x4c8/0x884 net/socket.c:1587 sock_create net/socket.c:1622 [inline] __sys_socket_create net/socket.c:1659 [inline] __sys_socket+0x134/0x340 net/socket.c:1706 __do_sys_socket net/socket.c:1720 [inline] __se_sys_socket net/socket.c:1718 [inline] __arm64_sys_socket+0x7c/0x94 net/socket.c:1718 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x98/0x2b8 arch/arm64/kernel/syscall.c:49 el0_svc_common+0x130/0x23c arch/arm64/kernel/syscall.c:132 do_el0_svc+0x48/0x58 arch/arm64/kernel/syscall.c:151 el0_svc+0x54/0x168 arch/arm64/kernel/entry-common.c:712 el0t_64_sync_handler+0x84/0xfc arch/arm64/kernel/entry-common.c:730 el0t_64_sync+0x190/0x194 arch/arm64/kernel/entry.S:598 Code: ???????? ???????? ???????? ???????? (????????) ---[ end trace 0000000000000000 ]---  This patch add a toy implementation that performs a simple return to prevent such panic. This is because MSS can be set in sock_create_kern or smc_setsockopt, similar to how it's done in AF_SMC. However, for AF_SMC, there is currently no way to synchronize MSS within __sys_connect_file. This toy implementation lays the groundwork for us to support such feature for IPPROTO_SMC in the future.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50004?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--50004" src="https://img.shields.io/badge/CVE--2024--50004-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: update DML2 policy EnhancedPrefetchScheduleAccelerationFinal DCN35  [WHY & HOW] Mismatch in DCN35 DML2 cause bw validation failed to acquire unexpected DPP pipe to cause grey screen and system hang. Remove EnhancedPrefetchScheduleAccelerationFinal value override to match HW spec.  (cherry picked from commit 9dad21f910fcea2bdcff4af46159101d7f9cd8ba)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50003?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--50003" src="https://img.shields.io/badge/CVE--2024--50003-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Fix system hang while resume with TBT monitor  [Why] Connected with a Thunderbolt monitor and do the suspend and the system may hang while resume.  The TBT monitor HPD will be triggered during the resume procedure and call the drm_client_modeset_probe() while struct drm_connector connector->dev->master is NULL.  It will mess up the pipe topology after resume.  [How] Skip the TBT monitor HPD during the resume procedure because we currently will probe the connectors after resume by default.  (cherry picked from commit 453f86a26945207a16b8f66aaed5962dc2b95b85)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49993?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49993" src="https://img.shields.io/badge/CVE--2024--49993-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49990?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49990" src="https://img.shields.io/badge/CVE--2024--49990-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/xe/hdcp: Check GSC structure validity  Sometimes xe_gsc is not initialized when checked at HDCP capability check. Add gsc structure check to avoid null pointer error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49971?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49971" src="https://img.shields.io/badge/CVE--2024--49971-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Increase array size of dummy_boolean  [WHY] dml2_core_shared_mode_support and dml_core_mode_support access the third element of dummy_boolean, i.e. hw_debug5 = &s->dummy_boolean[2], when dummy_boolean has size of 2. Any assignment to hw_debug5 causes an OVERRUN.  [HOW] Increase dummy_boolean's array size to 3.  This fixes 2 OVERRUN issues reported by Coverity.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49970?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49970" src="https://img.shields.io/badge/CVE--2024--49970-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Implement bounds check for stream encoder creation in DCN401  'stream_enc_regs' array is an array of dcn10_stream_enc_registers structures. The array is initialized with four elements, corresponding to the four calls to stream_enc_regs() in the array initializer. This means that valid indices for this array are 0, 1, 2, and 3.  The error message 'stream_enc_regs' 4 <= 5 below, is indicating that there is an attempt to access this array with an index of 5, which is out of bounds. This could lead to undefined behavior  Here, eng_id is used as an index to access the stream_enc_regs array. If eng_id is 5, this would result in an out-of-bounds access on the stream_enc_regs array.  Thus fixing Buffer overflow error in dcn401_stream_encoder_create  Found by smatch: drivers/gpu/drm/amd/amdgpu/../display/dc/resource/dcn401/dcn401_resource.c:1209 dcn401_stream_encoder_create() error: buffer overflow 'stream_enc_regs' 4 <= 5

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49940?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49940" src="https://img.shields.io/badge/CVE--2024--49940-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  l2tp: prevent possible tunnel refcount underflow  When a session is created, it sets a backpointer to its tunnel. When the session refcount drops to 0, l2tp_session_free drops the tunnel refcount if session->tunnel is non-NULL. However, session->tunnel is set in l2tp_session_create, before the tunnel refcount is incremented by l2tp_session_register, which leaves a small window where session->tunnel is non-NULL when the tunnel refcount hasn't been bumped.  Moving the assignment to l2tp_session_register is trivial but l2tp_session_create calls l2tp_session_set_header_len which uses session->tunnel to get the tunnel's encap. Add an encap arg to l2tp_session_set_header_len to avoid using session->tunnel.  If l2tpv3 sessions have colliding IDs, it is possible for l2tp_v3_session_get to race with l2tp_session_register and fetch a session which doesn't yet have session->tunnel set. Add a check for this case.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49932?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49932" src="https://img.shields.io/badge/CVE--2024--49932-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: don't readahead the relocation inode on RST  On relocation we're doing readahead on the relocation inode, but if the filesystem is backed by a RAID stripe tree we can get ENOENT (e.g. due to preallocated extents not being mapped in the RST) from the lookup.  But readahead doesn't handle the error and submits invalid reads to the device, causing an assertion in the scatter-gather list code:  BTRFS info (device nvme1n1): balance: start -d -m -s BTRFS info (device nvme1n1): relocating block group 6480920576 flags data|raid0 BTRFS error (device nvme1n1): cannot find raid-stripe for logical [6481928192, 6481969152] devid 2, profile raid0 ------------[ cut here ]------------ kernel BUG at include/linux/scatterlist.h:115! Oops: invalid opcode: 0000 [#1] PREEMPT SMP PTI CPU: 0 PID: 1012 Comm: btrfs Not tainted 6.10.0-rc7+ #567 RIP: 0010:__blk_rq_map_sg+0x339/0x4a0 RSP: 0018:ffffc90001a43820 EFLAGS: 00010202 RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffffea00045d4802 RDX: 0000000117520000 RSI: 0000000000000000 RDI: ffff8881027d1000 RBP: 0000000000003000 R08: ffffea00045d4902 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000001000 R12: ffff8881003d10b8 R13: ffffc90001a438f0 R14: 0000000000000000 R15: 0000000000003000 FS:  00007fcc048a6900(0000) GS:ffff88813bc00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000000002cd11000 CR3: 00000001109ea001 CR4: 0000000000370eb0 Call Trace: <TASK> ? __die_body.cold+0x14/0x25 ? die+0x2e/0x50 ? do_trap+0xca/0x110 ? do_error_trap+0x65/0x80 ? __blk_rq_map_sg+0x339/0x4a0 ? exc_invalid_op+0x50/0x70 ? __blk_rq_map_sg+0x339/0x4a0 ? asm_exc_invalid_op+0x1a/0x20 ? __blk_rq_map_sg+0x339/0x4a0 nvme_prep_rq.part.0+0x9d/0x770 nvme_queue_rq+0x7d/0x1e0 __blk_mq_issue_directly+0x2a/0x90 ? blk_mq_get_budget_and_tag+0x61/0x90 blk_mq_try_issue_list_directly+0x56/0xf0 blk_mq_flush_plug_list.part.0+0x52b/0x5d0 __blk_flush_plug+0xc6/0x110 blk_finish_plug+0x28/0x40 read_pages+0x160/0x1c0 page_cache_ra_unbounded+0x109/0x180 relocate_file_extent_cluster+0x611/0x6a0 ? btrfs_search_slot+0xba4/0xd20 ? balance_dirty_pages_ratelimited_flags+0x26/0xb00 relocate_data_extent.constprop.0+0x134/0x160 relocate_block_group+0x3f2/0x500 btrfs_relocate_block_group+0x250/0x430 btrfs_relocate_chunk+0x3f/0x130 btrfs_balance+0x71b/0xef0 ? kmalloc_trace_noprof+0x13b/0x280 btrfs_ioctl+0x2c2e/0x3030 ? kvfree_call_rcu+0x1e6/0x340 ? list_lru_add_obj+0x66/0x80 ? mntput_no_expire+0x3a/0x220 __x64_sys_ioctl+0x96/0xc0 do_syscall_64+0x54/0x110 entry_SYSCALL_64_after_hwframe+0x76/0x7e RIP: 0033:0x7fcc04514f9b Code: Unable to access opcode bytes at 0x7fcc04514f71. RSP: 002b:00007ffeba923370 EFLAGS: 00000246 ORIG_RAX: 0000000000000010 RAX: ffffffffffffffda RBX: 0000000000000003 RCX: 00007fcc04514f9b RDX: 00007ffeba923460 RSI: 00000000c4009420 RDI: 0000000000000003 RBP: 0000000000000000 R08: 0000000000000013 R09: 0000000000000001 R10: 00007fcc043fbba8 R11: 0000000000000246 R12: 00007ffeba924fc5 R13: 00007ffeba923460 R14: 0000000000000002 R15: 00000000004d4bb0 </TASK> Modules linked in: ---[ end trace 0000000000000000 ]--- RIP: 0010:__blk_rq_map_sg+0x339/0x4a0 RSP: 0018:ffffc90001a43820 EFLAGS: 00010202 RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffffea00045d4802 RDX: 0000000117520000 RSI: 0000000000000000 RDI: ffff8881027d1000 RBP: 0000000000003000 R08: ffffea00045d4902 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000001000 R12: ffff8881003d10b8 R13: ffffc90001a438f0 R14: 0000000000000000 R15: 0000000000003000 FS:  00007fcc048a6900(0000) GS:ffff88813bc00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fcc04514f71 CR3: 00000001109ea001 CR4: 0000000000370eb0 Kernel p ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49916?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49916" src="https://img.shields.io/badge/CVE--2024--49916-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Add NULL check for clk_mgr and clk_mgr->funcs in dcn401_init_hw  This commit addresses a potential null pointer dereference issue in the `dcn401_init_hw` function. The issue could occur when `dc->clk_mgr` or `dc->clk_mgr->funcs` is null.  The fix adds a check to ensure `dc->clk_mgr` and `dc->clk_mgr->funcs` is not null before accessing its functions. This prevents a potential null pointer dereference.  Reported by smatch: drivers/gpu/drm/amd/amdgpu/../display/dc/hwss/dcn401/dcn401_hwseq.c:416 dcn401_init_hw() error: we previously assumed 'dc->clk_mgr' could be null (see line 225)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49910?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49910" src="https://img.shields.io/badge/CVE--2024--49910-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Add NULL check for function pointer in dcn401_set_output_transfer_func  This commit adds a null check for the set_output_gamma function pointer in the dcn401_set_output_transfer_func function. Previously, set_output_gamma was being checked for null, but then it was being dereferenced without any null check. This could lead to a null pointer dereference if set_output_gamma is null.  To fix this, we now ensure that set_output_gamma is not null before dereferencing it. We do this by adding a null check for set_output_gamma before the call to set_output_gamma.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49908?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49908" src="https://img.shields.io/badge/CVE--2024--49908-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Add null check for 'afb' in amdgpu_dm_update_cursor (v2)  This commit adds a null check for the 'afb' variable in the amdgpu_dm_update_cursor function. Previously, 'afb' was assumed to be null at line 8388, but was used later in the code without a null check. This could potentially lead to a null pointer dereference.  Changes since v1: - Moved the null check for 'afb' to the line where 'afb' is used. (Alex)  Fixes the below: drivers/gpu/drm/amd/amdgpu/../display/amdgpu_dm/amdgpu_dm.c:8433 amdgpu_dm_update_cursor() error: we previously assumed 'afb' could be null (see line 8388)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49904?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49904" src="https://img.shields.io/badge/CVE--2024--49904-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu: add list empty check to avoid null pointer issue  Add list empty check to avoid null pointer issues in some corner cases. - list_for_each_entry_safe()

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49887?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--49887" src="https://img.shields.io/badge/CVE--2024--49887-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  f2fs: fix to don't panic system for no free segment fault injection  f2fs: fix to don't panic system for no free segment fault injection  syzbot reports a f2fs bug as below:  F2FS-fs (loop0): inject no free segment in get_new_segment of __allocate_new_segment+0x1ce/0x940 fs/f2fs/segment.c:3167 F2FS-fs (loop0): Stopped filesystem due to reason: 7 ------------[ cut here ]------------ kernel BUG at fs/f2fs/segment.c:2748! CPU: 0 UID: 0 PID: 5109 Comm: syz-executor304 Not tainted 6.11.0-rc6-syzkaller-00363-g89f5e14d05b4 #0 RIP: 0010:get_new_segment fs/f2fs/segment.c:2748 [inline] RIP: 0010:new_curseg+0x1f61/0x1f70 fs/f2fs/segment.c:2836 Call Trace: __allocate_new_segment+0x1ce/0x940 fs/f2fs/segment.c:3167 f2fs_allocate_new_section fs/f2fs/segment.c:3181 [inline] f2fs_allocate_pinning_section+0xfa/0x4e0 fs/f2fs/segment.c:3195 f2fs_expand_inode_data+0x5d6/0xbb0 fs/f2fs/file.c:1799 f2fs_fallocate+0x448/0x960 fs/f2fs/file.c:1903 vfs_fallocate+0x553/0x6c0 fs/open.c:334 do_vfs_ioctl+0x2592/0x2e50 fs/ioctl.c:886 __do_sys_ioctl fs/ioctl.c:905 [inline] __se_sys_ioctl+0x81/0x170 fs/ioctl.c:893 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0010:get_new_segment fs/f2fs/segment.c:2748 [inline] RIP: 0010:new_curseg+0x1f61/0x1f70 fs/f2fs/segment.c:2836  The root cause is when we inject no free segment fault into f2fs, we should not panic system, fix it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-47736?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--47736" src="https://img.shields.io/badge/CVE--2024--47736-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  erofs: handle overlapped pclusters out of crafted images properly  syzbot reported a task hang issue due to a deadlock case where it is waiting for the folio lock of a cached folio that will be used for cache I/Os.  After looking into the crafted fuzzed image, I found it's formed with several overlapped big pclusters as below:  Ext:   logical offset   |  length :     physical offset    |  length 0:        0..   16384 |   16384 :     151552..    167936 |   16384 1:    16384..   32768 |   16384 :     155648..    172032 |   16384 2:    32768..   49152 |   16384 :  537223168.. 537239552 |   16384 ...  Here, extent 0/1 are physically overlapped although it's entirely _impossible_ for normal filesystem images generated by mkfs.  First, managed folios containing compressed data will be marked as up-to-date and then unlocked immediately (unlike in-place folios) when compressed I/Os are complete.  If physical blocks are not submitted in the incremental order, there should be separate BIOs to avoid dependency issues.  However, the current code mis-arranges z_erofs_fill_bio_vec() and BIO submission which causes unexpected BIO waits.  Second, managed folios will be connected to their own pclusters for efficient inter-queries.  However, this is somewhat hard to implement easily if overlapped big pclusters exist.  Again, these only appear in fuzzed images so let's simply fall back to temporary short-lived pages for correctness.  Additionally, it justifies that referenced managed folios cannot be truncated for now and reverts part of commit 2080ca1ed3e4 ("erofs: tidy up `struct z_erofs_bvec`") for simplicity although it shouldn't be any difference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-47729?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--47729" src="https://img.shields.io/badge/CVE--2024--47729-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/xe: Use reserved copy engine for user binds on faulting devices  User binds map to engines with can fault, faults depend on user binds completion, thus we can deadlock. Avoid this by using reserved copy engine for user binds on faulting devices.  While we are here, normalize bind queue creation with a helper.  v2: - Pass in extensions to bind queue creation (CI) v3: - s/resevered/reserved (Lucas) - Fix NULL hwe check (Jonathan)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46742?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--46742" src="https://img.shields.io/badge/CVE--2024--46742-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb/server: fix potential null-ptr-deref of lease_ctx_info in smb2_open()  null-ptr-deref will occur when (req_op_level == SMB2_OPLOCK_LEVEL_LEASE) and parse_lease_state() return NULL.  Fix this by check if 'lease_ctx_info' is NULL.  Additionally, remove the redundant parentheses in parse_durable_handle_context().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-43903?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--43903" src="https://img.shields.io/badge/CVE--2024--43903-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-43872?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--43872" src="https://img.shields.io/badge/CVE--2024--43872-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/hns: Fix soft lockup under heavy CEQE load  CEQEs are handled in interrupt handler currently. This may cause the CPU core staying in interrupt context too long and lead to soft lockup under heavy load.  Handle CEQEs in BH workqueue and set an upper limit for the number of CEQE handled by a single call of work handler.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-43844?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--43844" src="https://img.shields.io/badge/CVE--2024--43844-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: rtw89: wow: fix GTK offload H2C skbuff issue  We mistakenly put skb too large and that may exceed skb->end. Therefore, we fix it.  skbuff: skb_over_panic: text:ffffffffc09e9a9d len:416 put:204 head:ffff8fba04eca780 data:ffff8fba04eca7e0 tail:0x200 end:0x140 dev:<NULL> ------------[ cut here ]------------ kernel BUG at net/core/skbuff.c:192! invalid opcode: 0000 [#1] PREEMPT SMP PTI CPU: 1 PID: 4747 Comm: kworker/u4:44 Tainted: G           O 6.6.30-02659-gc18865c4dfbd #1 86547039b47e46935493f615ee31d0b2d711d35e Hardware name: HP Meep/Meep, BIOS Google_Meep.11297.262.0 03/18/2021 Workqueue: events_unbound async_run_entry_fn RIP: 0010:skb_panic+0x5d/0x60 Code: c6 63 8b 8f bb 4c 0f 45 f6 48 c7 c7 4d 89 8b bb 48 89 ce 44 89 d1 41 56 53 41 53 ff b0 c8 00 00 00 e8 27 5f 23 00 48 83 c4 20 <0f> 0b 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 0f 1f 44 RSP: 0018:ffffaa700144bad0 EFLAGS: 00010282 RAX: 0000000000000089 RBX: 0000000000000140 RCX: 14432c5aad26c900 RDX: 0000000000000000 RSI: 00000000ffffdfff RDI: 0000000000000001 RBP: ffffaa700144bae0 R08: 0000000000000000 R09: ffffaa700144b920 R10: 00000000ffffdfff R11: ffffffffbc28fbc0 R12: ffff8fba4e57a010 R13: 0000000000000000 R14: ffffffffbb8f8b63 R15: 0000000000000000 FS:  0000000000000000(0000) GS:ffff8fba7bd00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007999c4ad1000 CR3: 000000015503a000 CR4: 0000000000350ee0 Call Trace: <TASK> ? __die_body+0x1f/0x70 ? die+0x3d/0x60 ? do_trap+0xa4/0x110 ? skb_panic+0x5d/0x60 ? do_error_trap+0x6d/0x90 ? skb_panic+0x5d/0x60 ? handle_invalid_op+0x30/0x40 ? skb_panic+0x5d/0x60 ? exc_invalid_op+0x3c/0x50 ? asm_exc_invalid_op+0x16/0x20 ? skb_panic+0x5d/0x60 skb_put+0x49/0x50 rtw89_fw_h2c_wow_gtk_ofld+0xbd/0x220 [rtw89_core 778b32de31cd1f14df2d6721ae99ba8a83636fa5] rtw89_wow_resume+0x31f/0x540 [rtw89_core 778b32de31cd1f14df2d6721ae99ba8a83636fa5] rtw89_ops_resume+0x2b/0xa0 [rtw89_core 778b32de31cd1f14df2d6721ae99ba8a83636fa5] ieee80211_reconfig+0x84/0x13e0 [mac80211 818a894e3b77da6298269c59ed7cdff065a4ed52] ? __pfx_wiphy_resume+0x10/0x10 [cfg80211 1a793119e2aeb157c4ca4091ff8e1d9ae233b59d] ? dev_printk_emit+0x51/0x70 ? _dev_info+0x6e/0x90 ? __pfx_wiphy_resume+0x10/0x10 [cfg80211 1a793119e2aeb157c4ca4091ff8e1d9ae233b59d] wiphy_resume+0x89/0x180 [cfg80211 1a793119e2aeb157c4ca4091ff8e1d9ae233b59d] ? __pfx_wiphy_resume+0x10/0x10 [cfg80211 1a793119e2aeb157c4ca4091ff8e1d9ae233b59d] dpm_run_callback+0x3c/0x140 device_resume+0x1f9/0x3c0 ? __pfx_dpm_watchdog_handler+0x10/0x10 async_resume+0x1d/0x30 async_run_entry_fn+0x29/0xd0 process_scheduled_works+0x1d8/0x3d0 worker_thread+0x1fc/0x2f0 kthread+0xed/0x110 ? __pfx_worker_thread+0x10/0x10 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x38/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK> Modules linked in: ccm 8021q r8153_ecm cdc_ether usbnet r8152 mii dm_integrity async_xor xor async_tx lz4 lz4_compress zstd zstd_compress zram zsmalloc uinput rfcomm cmac algif_hash rtw89_8922ae(O) algif_skcipher rtw89_8922a(O) af_alg rtw89_pci(O) rtw89_core(O) btusb(O) snd_soc_sst_bxt_da7219_max98357a btbcm(O) snd_soc_hdac_hdmi btintel(O) snd_soc_intel_hda_dsp_common snd_sof_probes btrtl(O) btmtk(O) snd_hda_codec_hdmi snd_soc_dmic uvcvideo videobuf2_vmalloc uvc videobuf2_memops videobuf2_v4l2 videobuf2_common snd_sof_pci_intel_apl snd_sof_intel_hda_common snd_soc_hdac_hda snd_sof_intel_hda soundwire_intel soundwire_generic_allocation snd_sof_intel_hda_mlink soundwire_cadence snd_sof_pci snd_sof_xtensa_dsp mac80211 snd_soc_acpi_intel_match snd_soc_acpi snd_sof snd_sof_utils soundwire_bus snd_soc_max98357a snd_soc_avs snd_soc_hda_codec snd_hda_ext_core snd_intel_dspcfg snd_intel_sdw_acpi snd_soc_da7219 snd_hda_codec snd_hwdep snd_hda_core veth ip6table_nat xt_MASQUERADE xt_cgroup fuse bluetooth ecdh_generic cfg80211 ecc gsmi: Log Shutdown ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-42139?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--42139" src="https://img.shields.io/badge/CVE--2024--42139-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ice: Fix improper extts handling  Extts events are disabled and enabled by the application ts2phc. However, in case where the driver is removed when the application is running, a specific extts event remains enabled and can cause a kernel crash. As a side effect, when the driver is reloaded and application is started again, remaining extts event for the channel from a previous run will keep firing and the message "extts on unexpected channel" might be printed to the user.  To avoid that, extts events shall be disabled when PTP is released.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38608?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--38608" src="https://img.shields.io/badge/CVE--2024--38608-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.061%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Fix netif state handling mlx5e_suspend cleans resources only if netif_device_present() returns true. However, mlx5e_resume changes the state of netif, via mlx5e_nic_enable, only if reg_state == NETREG_REGISTERED. In the below case, the above leads to NULL-ptr Oops[1] and memory leaks: mlx5e_probe _mlx5e_resume mlx5e_attach_netdev mlx5e_nic_enable <-- netdev not reg, not calling netif_device_attach() register_netdev <-- failed for some reason. ERROR_FLOW: _mlx5e_suspend <-- netif_device_present return false, resources aren't freed :( Hence, clean resources in this case as well. [1] BUG: kernel NULL pointer dereference, address: 0000000000000000 PGD 0 P4D 0 Oops: 0010 [#1] SMP CPU: 2 PID: 9345 Comm: test-ovs-ct-gen Not tainted 6.5.0_for_upstream_min_debug_2023_09_05_16_01 #1 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 RIP: 0010:0x0 Code: Unable to access opcode bytes at0xffffffffffffffd6. RSP: 0018:ffff888178aaf758 EFLAGS: 00010246 Call Trace: <TASK> ? __die+0x20/0x60 ? page_fault_oops+0x14c/0x3c0 ? exc_page_fault+0x75/0x140 ? asm_exc_page_fault+0x22/0x30 notifier_call_chain+0x35/0xb0 blocking_notifier_call_chain+0x3d/0x60 mlx5_blocking_notifier_call_chain+0x22/0x30 [mlx5_core] mlx5_core_uplink_netdev_event_replay+0x3e/0x60 [mlx5_core] mlx5_mdev_netdev_track+0x53/0x60 [mlx5_ib] mlx5_ib_roce_init+0xc3/0x340 [mlx5_ib] __mlx5_ib_add+0x34/0xd0 [mlx5_ib] mlx5r_probe+0xe1/0x210 [mlx5_ib] ? auxiliary_match_id+0x6a/0x90 auxiliary_bus_probe+0x38/0x80 ? driver_sysfs_add+0x51/0x80 really_probe+0xc9/0x3e0 ? driver_probe_device+0x90/0x90 __driver_probe_device+0x80/0x160 driver_probe_device+0x1e/0x90 __device_attach_driver+0x7d/0x100 bus_for_each_drv+0x80/0xd0 __device_attach+0xbc/0x1f0 bus_probe_device+0x86/0xa0 device_add+0x637/0x840 __auxiliary_device_add+0x3b/0xa0 add_adev+0xc9/0x140 [mlx5_core] mlx5_rescan_drivers_locked+0x22a/0x310 [mlx5_core] mlx5_register_device+0x53/0xa0 [mlx5_core] mlx5_init_one_devl_locked+0x5c4/0x9c0 [mlx5_core] mlx5_init_one+0x3b/0x60 [mlx5_core] probe_one+0x44c/0x730 [mlx5_core] local_pci_probe+0x3e/0x90 pci_device_probe+0xbf/0x210 ? kernfs_create_link+0x5d/0xa0 ? sysfs_do_create_link_sd+0x60/0xc0 really_probe+0xc9/0x3e0 ? driver_probe_device+0x90/0x90 __driver_probe_device+0x80/0x160 driver_probe_device+0x1e/0x90 __device_attach_driver+0x7d/0x100 bus_for_each_drv+0x80/0xd0 __device_attach+0xbc/0x1f0 pci_bus_add_device+0x54/0x80 pci_iov_add_virtfn+0x2e6/0x320 sriov_enable+0x208/0x420 mlx5_core_sriov_configure+0x9e/0x200 [mlx5_core] sriov_numvfs_store+0xae/0x1a0 kernfs_fop_write_iter+0x10c/0x1a0 vfs_write+0x291/0x3c0 ksys_write+0x5f/0xe0 do_syscall_64+0x3d/0x90 entry_SYSCALL_64_after_hwframe+0x46/0xb0 CR2: 0000000000000000 ---[ end trace 0000000000000000 ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36970?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--36970" src="https://img.shields.io/badge/CVE--2024--36970-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.050%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: wifi: iwlwifi: Use request_module_nowait This appears to work around a deadlock regression that came in with the LED merge in 6.9. The deadlock happens on my system with 24 iwlwifi radios, so maybe it something like all worker threads are busy and some work that needs to complete cannot complete. [also remove unnecessary "load_module" var and now-wrong comment]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36476?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--36476" src="https://img.shields.io/badge/CVE--2024--36476-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/rtrs: Ensure 'ib_sge list' is accessible  Move the declaration of the 'ib_sge list' variable outside the 'always_invalidate' block to ensure it remains accessible for use throughout the function.  Previously, 'ib_sge list' was declared within the 'always_invalidate' block, limiting its accessibility, then caused a 'BUG: kernel NULL pointer dereference'[1]. ? __die_body.cold+0x19/0x27 ? page_fault_oops+0x15a/0x2d0 ? search_module_extables+0x19/0x60 ? search_bpf_extables+0x5f/0x80 ? exc_page_fault+0x7e/0x180 ? asm_exc_page_fault+0x26/0x30 ? memcpy_orig+0xd5/0x140 rxe_mr_copy+0x1c3/0x200 [rdma_rxe] ? rxe_pool_get_index+0x4b/0x80 [rdma_rxe] copy_data+0xa5/0x230 [rdma_rxe] rxe_requester+0xd9b/0xf70 [rdma_rxe] ? finish_task_switch.isra.0+0x99/0x2e0 rxe_sender+0x13/0x40 [rdma_rxe] do_task+0x68/0x1e0 [rdma_rxe] process_one_work+0x177/0x330 worker_thread+0x252/0x390 ? __pfx_worker_thread+0x10/0x10  This change ensures the variable is available for subsequent operations that require it.  [1] https://lore.kernel.org/linux-rdma/6a1f3e8f-deb0-49f9-bc69-a9b03ecfcda7@fujitsu.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35895?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--35895" src="https://img.shields.io/badge/CVE--2024--35895-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.070%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: bpf, sockmap: Prevent lock inversion deadlock in map delete elem syzkaller started using corpuses where a BPF tracing program deletes elements from a sockmap/sockhash map. Because BPF tracing programs can be invoked from any interrupt context, locks taken during a map_delete_elem operation must be hardirq-safe. Otherwise a deadlock due to lock inversion is possible, as reported by lockdep: CPU0 CPU1 ---- ---- lock(&htab->buckets[i].lock); local_irq_disable(); lock(&host->lock); lock(&htab->buckets[i].lock); <Interrupt> lock(&host->lock); Locks in sockmap are hardirq-unsafe by design. We expects elements to be deleted from sockmap/sockhash only in task (normal) context with interrupts enabled, or in softirq context. Detect when map_delete_elem operation is invoked from a context which is _not_ hardirq-unsafe, that is interrupts are disabled, and bail out with an error. Note that map updates are not affected by this issue. BPF verifier does not allow updating sockmap/sockhash from a BPF tracing program today.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-27025?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2024--27025" src="https://img.shields.io/badge/CVE--2024--27025-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.086%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: nbd: null check for nla_nest_start nla_nest_start() may fail and return NULL. Insert a check and set errno based on other call sites within the same source code.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52879?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2023--52879" src="https://img.shields.io/badge/CVE--2023--52879-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.090%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: tracing: Have trace_event_file have ref counters The following can crash the kernel: # cd /sys/kernel/tracing # echo 'p:sched schedule' > kprobe_events # exec 5>>events/kprobes/sched/enable # > kprobe_events # exec 5>&- The above commands: 1. Change directory to the tracefs directory 2. Create a kprobe event (doesn't matter what one) 3. Open bash file descriptor 5 on the enable file of the kprobe event 4. Delete the kprobe event (removes the files too) 5. Close the bash file descriptor 5 The above causes a crash! BUG: kernel NULL pointer dereference, address: 0000000000000028 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: 0000 [#1] PREEMPT SMP PTI CPU: 6 PID: 877 Comm: bash Not tainted 6.5.0-rc4-test-00008-g2c6b6b1029d4-dirty #186 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.2-debian-1.16.2-1 04/01/2014 RIP: 0010:tracing_release_file_tr+0xc/0x50 What happens here is that the kprobe event creates a trace_event_file "file" descriptor that represents the file in tracefs to the event. It maintains state of the event (is it enabled for the given instance?). Opening the "enable" file gets a reference to the event "file" descriptor via the open file descriptor. When the kprobe event is deleted, the file is also deleted from the tracefs system which also frees the event "file" descriptor. But as the tracefs file is still opened by user space, it will not be totally removed until the final dput() is called on it. But this is not true with the event "file" descriptor that is already freed. If the user does a write to or simply closes the file descriptor it will reference the event "file" descriptor that was just freed, causing a use-after-free bug. To solve this, add a ref count to the event "file" descriptor as well as a new flag called "FREED". The "file" will not be freed until the last reference is released. But the FREE flag will be set when the event is removed to prevent any more modifications to that event from happening, even if there's still a reference to the event "file" descriptor.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-31082?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2023--31082" src="https://img.shields.io/badge/CVE--2023--31082-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.073%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

** DISPUTED ** An issue was discovered in drivers/tty/n_gsm.c in the Linux kernel 6.2. There is a sleeping function called from an invalid context in gsmld_write, which will block the kernel. Note: This has been disputed by 3rd parties as not a valid vulnerability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-0160?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2023--0160" src="https://img.shields.io/badge/CVE--2023--0160-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.010%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A deadlock flaw was found in the Linux kernel’s BPF subsystem. This flaw allows a local user to potentially crash the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48929?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--48929" src="https://img.shields.io/badge/CVE--2022--48929-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Fix crash due to out of bounds access into reg2btf_ids.  When commit e6ac2450d6de ("bpf: Support bpf program calling kernel function") added kfunc support, it defined reg2btf_ids as a cheap way to translate the verifier reg type to the appropriate btf_vmlinux BTF ID, however commit c25b2ae13603 ("bpf: Replace PTR_TO_XXX_OR_NULL with PTR_TO_XXX | PTR_MAYBE_NULL") moved the __BPF_REG_TYPE_MAX from the last member of bpf_reg_type enum to after the base register types, and defined other variants using type flag composition. However, now, the direct usage of reg->type to index into reg2btf_ids may no longer fall into __BPF_REG_TYPE_MAX range, and hence lead to out of bounds access and kernel crash on dereference of bad pointer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48846?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--48846" src="https://img.shields.io/badge/CVE--2022--48846-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  block: release rq qos structures for queue without disk  blkcg_init_queue() may add rq qos structures to request queue, previously blk_cleanup_queue() calls rq_qos_exit() to release them, but commit 8e141f9eb803 ("block: drain file system I/O on del_gendisk") moves rq_qos_exit() into del_gendisk(), so memory leak is caused because queues may not have disk, such as un-present scsi luns, nvme admin queue, ...  Fixes the issue by adding rq_qos_exit() to blk_cleanup_queue() back.  BTW, v5.18 won't need this patch any more since we move blkcg_init_queue()/blkcg_exit_queue() into disk allocation/release handler, and patches have been in for-5.18/block.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-4543?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--4543" src="https://img.shields.io/badge/CVE--2022--4543-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.123%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw named "EntryBleed" was found in the Linux Kernel Page Table Isolation (KPTI). This issue could allow a local attacker to leak KASLR base via prefetch side-channels based on TLB timing for Intel systems.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-0480?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2022--0480" src="https://img.shields.io/badge/CVE--2022--0480-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the filelock_init in fs/locks.c function in the Linux kernel. This issue can lead to host memory exhaustion due to memcg not limiting the number of Portable Operating System Interface (POSIX) file locks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-47615?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2021--47615" src="https://img.shields.io/badge/CVE--2021--47615-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: RDMA/mlx5: Fix releasing unallocated memory in dereg MR flow For the case of IB_MR_TYPE_DM the mr does doesn't have a umem, even though it is a user MR. This causes function mlx5_free_priv_descs() to think that it is a kernel MR, leading to wrongly accessing mr->descs that will get wrong values in the union which leads to attempt to release resources that were not allocated in the first place. For example: DMA-API: mlx5_core 0000:08:00.1: device driver tries to free DMA memory it has not allocated [device address=0x0000000000000000] [size=0 bytes] WARNING: CPU: 8 PID: 1021 at kernel/dma/debug.c:961 check_unmap+0x54f/0x8b0 RIP: 0010:check_unmap+0x54f/0x8b0 Call Trace: debug_dma_unmap_page+0x57/0x60 mlx5_free_priv_descs+0x57/0x70 [mlx5_ib] mlx5_ib_dereg_mr+0x1fb/0x3d0 [mlx5_ib] ib_dereg_mr_user+0x60/0x140 [ib_core] uverbs_destroy_uobject+0x59/0x210 [ib_uverbs] uobj_destroy+0x3f/0x80 [ib_uverbs] ib_uverbs_cmd_verbs+0x435/0xd10 [ib_uverbs] ? uverbs_finalize_object+0x50/0x50 [ib_uverbs] ? lock_acquire+0xc4/0x2e0 ? lock_acquired+0x12/0x380 ? lock_acquire+0xc4/0x2e0 ? lock_acquire+0xc4/0x2e0 ? ib_uverbs_ioctl+0x7c/0x140 [ib_uverbs] ? lock_release+0x28a/0x400 ib_uverbs_ioctl+0xc0/0x140 [ib_uverbs] ? ib_uverbs_ioctl+0x7c/0x140 [ib_uverbs] __x64_sys_ioctl+0x7f/0xb0 do_syscall_64+0x38/0x90 Fix it by reorganizing the dereg flow and mlx5_ib_mr structure: - Move the ib_umem field into the user MRs structure in the union as it's applicable only there. - Function mlx5_ib_dereg_mr() will now call mlx5_free_priv_descs() only in case there isn't udata, which indicates that this isn't a user MR.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2016-8660?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2016--8660" src="https://img.shields.io/badge/CVE--2016--8660-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.110%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The XFS subsystem in the Linux kernel through 4.8.2 allows local users to cause a denial of service (fdatasync failure and system hang) by using the vfs syscall group in the trinity program, related to a "page lock order bug in the XFS seek hole/data implementation."

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2015-7837?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 5.5: CVE--2015--7837" src="https://img.shields.io/badge/CVE--2015--7837-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.073%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Linux kernel, as used in Red Hat Enterprise Linux 7, kernel-rt, and Enterprise MRG 2 and when booted with UEFI Secure Boot enabled, allows local users to bypass intended securelevel/secureboot restrictions by leveraging improper handling of secure_boot flag across kexec reboot.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57913?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 4.7: CVE--2024--57913" src="https://img.shields.io/badge/CVE--2024--57913-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: f_fs: Remove WARN_ON in functionfs_bind  This commit addresses an issue related to below kernel panic where panic_on_warn is enabled. It is caused by the unnecessary use of WARN_ON in functionsfs_bind, which easily leads to the following scenarios.  1.adb_write in adbd               2. UDC write via configfs =================	             =====================  ->usb_ffs_open_thread()           ->UDC write ->open_functionfs()               ->configfs_write_iter() ->adb_open()                      ->gadget_dev_desc_UDC_store() ->adb_write()                     ->usb_gadget_register_driver_owner ->driver_register() ->StartMonitor()                       ->bus_add_driver() ->adb_read()                           ->gadget_bind_driver() <times-out without BIND event>           ->configfs_composite_bind() ->usb_add_function() ->open_functionfs()                        ->ffs_func_bind() ->adb_open()                               ->functionfs_bind() <ffs->state !=FFS_ACTIVE>  The adb_open, adb_read, and adb_write operations are invoked from the daemon, but trying to bind the function is a process that is invoked by UDC write through configfs, which opens up the possibility of a race condition between the two paths. In this race scenario, the kernel panic occurs due to the WARN_ON from functionfs_bind when panic_on_warn is enabled. This commit fixes the kernel panic by removing the unnecessary WARN_ON.  Kernel panic - not syncing: kernel: panic_on_warn set ... [   14.542395] Call trace: [   14.542464]  ffs_func_bind+0x1c8/0x14a8 [   14.542468]  usb_add_function+0xcc/0x1f0 [   14.542473]  configfs_composite_bind+0x468/0x588 [   14.542478]  gadget_bind_driver+0x108/0x27c [   14.542483]  really_probe+0x190/0x374 [   14.542488]  __driver_probe_device+0xa0/0x12c [   14.542492]  driver_probe_device+0x3c/0x220 [   14.542498]  __driver_attach+0x11c/0x1fc [   14.542502]  bus_for_each_dev+0x104/0x160 [   14.542506]  driver_attach+0x24/0x34 [   14.542510]  bus_add_driver+0x154/0x270 [   14.542514]  driver_register+0x68/0x104 [   14.542518]  usb_gadget_register_driver_owner+0x48/0xf4 [   14.542523]  gadget_dev_desc_UDC_store+0xf8/0x144 [   14.542526]  configfs_write_iter+0xf0/0x138

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53124?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 4.7: CVE--2024--53124" src="https://img.shields.io/badge/CVE--2024--53124-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fix data-races around sk->sk_forward_alloc  Syzkaller reported this warning: ------------[ cut here ]------------ WARNING: CPU: 0 PID: 16 at net/ipv4/af_inet.c:156 inet_sock_destruct+0x1c5/0x1e0 Modules linked in: CPU: 0 UID: 0 PID: 16 Comm: ksoftirqd/0 Not tainted 6.12.0-rc5 #26 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 RIP: 0010:inet_sock_destruct+0x1c5/0x1e0 Code: 24 12 4c 89 e2 5b 48 c7 c7 98 ec bb 82 41 5c e9 d1 18 17 ff 4c 89 e6 5b 48 c7 c7 d0 ec bb 82 41 5c e9 bf 18 17 ff 0f 0b eb 83 <0f> 0b eb 97 0f 0b eb 87 0f 0b e9 68 ff ff ff 66 66 2e 0f 1f 84 00 RSP: 0018:ffffc9000008bd90 EFLAGS: 00010206 RAX: 0000000000000300 RBX: ffff88810b172a90 RCX: 0000000000000007 RDX: 0000000000000002 RSI: 0000000000000300 RDI: ffff88810b172a00 RBP: ffff88810b172a00 R08: ffff888104273c00 R09: 0000000000100007 R10: 0000000000020000 R11: 0000000000000006 R12: ffff88810b172a00 R13: 0000000000000004 R14: 0000000000000000 R15: ffff888237c31f78 FS:  0000000000000000(0000) GS:ffff888237c00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffc63fecac8 CR3: 000000000342e000 CR4: 00000000000006f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> ? __warn+0x88/0x130 ? inet_sock_destruct+0x1c5/0x1e0 ? report_bug+0x18e/0x1a0 ? handle_bug+0x53/0x90 ? exc_invalid_op+0x18/0x70 ? asm_exc_invalid_op+0x1a/0x20 ? inet_sock_destruct+0x1c5/0x1e0 __sk_destruct+0x2a/0x200 rcu_do_batch+0x1aa/0x530 ? rcu_do_batch+0x13b/0x530 rcu_core+0x159/0x2f0 handle_softirqs+0xd3/0x2b0 ? __pfx_smpboot_thread_fn+0x10/0x10 run_ksoftirqd+0x25/0x30 smpboot_thread_fn+0xdd/0x1d0 kthread+0xd3/0x100 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x34/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1a/0x30 </TASK> ---[ end trace 0000000000000000 ]---  Its possible that two threads call tcp_v6_do_rcv()/sk_forward_alloc_add() concurrently when sk->sk_state == TCP_LISTEN with sk->sk_lock unlocked, which triggers a data-race around sk->sk_forward_alloc: tcp_v6_rcv tcp_v6_do_rcv skb_clone_and_charge_r sk_rmem_schedule __sk_mem_schedule sk_forward_alloc_add() skb_set_owner_r sk_mem_charge sk_forward_alloc_add() __kfree_skb skb_release_all skb_release_head_state sock_rfree sk_mem_uncharge sk_forward_alloc_add() sk_mem_reclaim // set local var reclaimable __sk_mem_reclaim sk_forward_alloc_add()  In this syzkaller testcase, two threads call tcp_v6_do_rcv() with skb->truesize=768, the sk_forward_alloc changes like this: (cpu 1)             | (cpu 2)             | sk_forward_alloc ...                 | ...                 | 0 __sk_mem_schedule() |                     | +4096 = 4096 | __sk_mem_schedule() | +4096 = 8192 sk_mem_charge()     |                     | -768  = 7424 | sk_mem_charge()     | -768  = 6656 ...                 |    ...              | sk_mem_uncharge()   |                     | +768  = 7424 reclaimable=7424    |                     | | sk_mem_uncharge()   | +768  = 8192 | reclaimable=8192    | __sk_mem_reclaim()  |                     | -4096 = 4096 | __sk_mem_reclaim()  | -8192 = -4096 != 0  The skb_clone_and_charge_r() should not be called in tcp_v6_do_rcv() when sk->sk_state is TCP_LISTEN, it happens later in tcp_v6_syn_recv_sock(). Fix the same issue in dccp_v6_do_rcv().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50277?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 4.7: CVE--2024--50277" src="https://img.shields.io/badge/CVE--2024--50277-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dm: fix a crash if blk_alloc_disk fails  If blk_alloc_disk fails, the variable md->disk is set to an error value. cleanup_mapped_device will see that md->disk is non-NULL and it will attempt to access it, causing a crash on this statement "md->disk->private_data = NULL;".

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-42107?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 4.7: CVE--2024--42107" src="https://img.shields.io/badge/CVE--2024--42107-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ice: Don't process extts if PTP is disabled  The ice_ptp_extts_event() function can race with ice_ptp_release() and result in a NULL pointer dereference which leads to a kernel panic.  Panic occurs because the ice_ptp_extts_event() function calls ptp_clock_event() with a NULL pointer. The ice driver has already released the PTP clock by the time the interrupt for the next external timestamp event occurs.  To fix this, modify the ice_ptp_extts_event() function to check the PTP state and bail early if PTP is not ready.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-17977?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 4.4: CVE--2018--17977" src="https://img.shields.io/badge/CVE--2018--17977-lightgrey?label=medium%204.4&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Linux kernel 4.14.67 mishandles certain interaction among XFRM Netlink messages, IPPROTO_AH packets, and IPPROTO_IP packets, which allows local users to cause a denial of service (memory consumption and system hang) by leveraging root access to execute crafted applications, as demonstrated on CentOS 7.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-2312?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--2312" src="https://img.shields.io/badge/CVE--2025--2312-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in cifs-utils. When trying to obtain Kerberos credentials, the cifs.upcall program from the cifs-utils package makes an upcall to the wrong namespace in containerized environments. This issue may lead to disclosing sensitive data from the host's Kerberos credentials cache.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21839?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21839" src="https://img.shields.io/badge/CVE--2025--21839-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  KVM: x86: Load DR6 with guest value only before entering .vcpu_run() loop  Move the conditional loading of hardware DR6 with the guest's DR6 value out of the core .vcpu_run() loop to fix a bug where KVM can load hardware with a stale vcpu->arch.dr6.  When the guest accesses a DR and host userspace isn't debugging the guest, KVM disables DR interception and loads the guest's values into hardware on VM-Enter and saves them on VM-Exit.  This allows the guest to access DRs at will, e.g. so that a sequence of DR accesses to configure a breakpoint only generates one VM-Exit.  For DR0-DR3, the logic/behavior is identical between VMX and SVM, and also identical between KVM_DEBUGREG_BP_ENABLED (userspace debugging the guest) and KVM_DEBUGREG_WONT_EXIT (guest using DRs), and so KVM handles loading DR0-DR3 in common code, _outside_ of the core kvm_x86_ops.vcpu_run() loop.  But for DR6, the guest's value doesn't need to be loaded into hardware for KVM_DEBUGREG_BP_ENABLED, and SVM provides a dedicated VMCB field whereas VMX requires software to manually load the guest value, and so loading the guest's value into DR6 is handled by {svm,vmx}_vcpu_run(), i.e. is done _inside_ the core run loop.  Unfortunately, saving the guest values on VM-Exit is initiated by common x86, again outside of the core run loop.  If the guest modifies DR6 (in hardware, when DR interception is disabled), and then the next VM-Exit is a fastpath VM-Exit, KVM will reload hardware DR6 with vcpu->arch.dr6 and clobber the guest's actual value.  The bug shows up primarily with nested VMX because KVM handles the VMX preemption timer in the fastpath, and the window between hardware DR6 being modified (in guest context) and DR6 being read by guest software is orders of magnitude larger in a nested setup.  E.g. in non-nested, the VMX preemption timer would need to fire precisely between #DB injection and the #DB handler's read of DR6, whereas with a KVM-on-KVM setup, the window where hardware DR6 is "dirty" extends all the way from L1 writing DR6 to VMRESUME (in L1).  L1's view: ========== <L1 disables DR interception> CPU 0/KVM-7289    [023] d....  2925.640961: kvm_entry: vcpu 0 A:  L1 Writes DR6 CPU 0/KVM-7289    [023] d....  2925.640963: <hack>: Set DRs, DR6 = 0xffff0ff1  B:        CPU 0/KVM-7289    [023] d....  2925.640967: kvm_exit: vcpu 0 reason EXTERNAL_INTERRUPT intr_info 0x800000ec  D: L1 reads DR6, arch.dr6 = 0 CPU 0/KVM-7289    [023] d....  2925.640969: <hack>: Sync DRs, DR6 = 0xffff0ff0  CPU 0/KVM-7289    [023] d....  2925.640976: kvm_entry: vcpu 0 L2 reads DR6, L1 disables DR interception CPU 0/KVM-7289    [023] d....  2925.640980: kvm_exit: vcpu 0 reason DR_ACCESS info1 0x0000000000000216 CPU 0/KVM-7289    [023] d....  2925.640983: kvm_entry: vcpu 0  CPU 0/KVM-7289    [023] d....  2925.640983: <hack>: Set DRs, DR6 = 0xffff0ff0  L2 detects failure CPU 0/KVM-7289    [023] d....  2925.640987: kvm_exit: vcpu 0 reason HLT L1 reads DR6 (confirms failure) CPU 0/KVM-7289    [023] d....  2925.640990: <hack>: Sync DRs, DR6 = 0xffff0ff0  L0's view: ========== L2 reads DR6, arch.dr6 = 0 CPU 23/KVM-5046    [001] d....  3410.005610: kvm_exit: vcpu 23 reason DR_ACCESS info1 0x0000000000000216 CPU 23/KVM-5046    [001] .....  3410.005610: kvm_nested_vmexit: vcpu 23 reason DR_ACCESS info1 0x0000000000000216  L2 => L1 nested VM-Exit CPU 23/KVM-5046    [001] .....  3410.005610: kvm_nested_vmexit_inject: reason: DR_ACCESS ext_inf1: 0x0000000000000216  CPU 23/KVM-5046    [001] d....  3410.005610: kvm_entry: vcpu 23 CPU 23/KVM-5046    [001] d....  3410.005611: kvm_exit: vcpu 23 reason VMREAD CPU 23/KVM-5046    [001] d....  3410.005611: kvm_entry: vcpu 23 CPU 23/KVM-5046    [001] d....  3410. ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21838?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21838" src="https://img.shields.io/badge/CVE--2025--21838-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: core: flush gadget workqueue after device removal  device_del() can lead to new work being scheduled in gadget->work workqueue. This is observed, for example, with the dwc3 driver with the following call stack: device_del() gadget_unbind_driver() usb_gadget_disconnect_locked() dwc3_gadget_pullup() dwc3_gadget_soft_disconnect() usb_gadget_set_state() schedule_work(&gadget->work)  Move flush_work() after device_del() to ensure the workqueue is cleaned up.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21836?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21836" src="https://img.shields.io/badge/CVE--2025--21836-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  io_uring/kbuf: reallocate buf lists on upgrade  IORING_REGISTER_PBUF_RING can reuse an old struct io_buffer_list if it was created for legacy selected buffer and has been emptied. It violates the requirement that most of the field should stay stable after publish. Always reallocate it instead.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21835?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21835" src="https://img.shields.io/badge/CVE--2025--21835-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: f_midi: fix MIDI Streaming descriptor lengths  While the MIDI jacks are configured correctly, and the MIDIStreaming endpoint descriptors are filled with the correct information, bNumEmbMIDIJack and bLength are set incorrectly in these descriptors.  This does not matter when the numbers of in and out ports are equal, but when they differ the host will receive broken descriptors with uninitialized stack memory leaking into the descriptor for whichever value is smaller.  The precise meaning of "in" and "out" in the port counts is not clearly defined and can be confusing.  But elsewhere the driver consistently uses this to match the USB meaning of IN and OUT viewed from the host, so that "in" ports send data to the host and "out" ports receive data from it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21832?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21832" src="https://img.shields.io/badge/CVE--2025--21832-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  block: don't revert iter for -EIOCBQUEUED  blkdev_read_iter() has a few odd checks, like gating the position and count adjustment on whether or not the result is bigger-than-or-equal to zero (where bigger than makes more sense), and not checking the return value of blkdev_direct_IO() before doing an iov_iter_revert(). The latter can lead to attempting to revert with a negative value, which when passed to iov_iter_revert() as an unsigned value will lead to throwing a WARN_ON() because unroll is bigger than MAX_RW_COUNT.  Be sane and don't revert for -EIOCBQUEUED, like what is done in other spots.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21830?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21830" src="https://img.shields.io/badge/CVE--2025--21830-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  landlock: Handle weird files  A corrupted filesystem (e.g. bcachefs) might return weird files. Instead of throwing a warning and allowing access to such file, treat them as regular files.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21829?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21829" src="https://img.shields.io/badge/CVE--2025--21829-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/rxe: Fix the warning "__rxe_cleanup+0x12c/0x170 [rdma_rxe]"  The Call Trace is as below: " <TASK> ? show_regs.cold+0x1a/0x1f ? __rxe_cleanup+0x12c/0x170 [rdma_rxe] ? __warn+0x84/0xd0 ? __rxe_cleanup+0x12c/0x170 [rdma_rxe] ? report_bug+0x105/0x180 ? handle_bug+0x46/0x80 ? exc_invalid_op+0x19/0x70 ? asm_exc_invalid_op+0x1b/0x20 ? __rxe_cleanup+0x12c/0x170 [rdma_rxe] ? __rxe_cleanup+0x124/0x170 [rdma_rxe] rxe_destroy_qp.cold+0x24/0x29 [rdma_rxe] ib_destroy_qp_user+0x118/0x190 [ib_core] rdma_destroy_qp.cold+0x43/0x5e [rdma_cm] rtrs_cq_qp_destroy.cold+0x1d/0x2b [rtrs_core] rtrs_srv_close_work.cold+0x1b/0x31 [rtrs_server] process_one_work+0x21d/0x3f0 worker_thread+0x4a/0x3c0 ? process_one_work+0x3f0/0x3f0 kthread+0xf0/0x120 ? kthread_complete_and_exit+0x20/0x20 ret_from_fork+0x22/0x30 </TASK> " When too many rdma resources are allocated, rxe needs more time to handle these rdma resources. Sometimes with the current timeout, rxe can not release the rdma resources correctly.  Compared with other rdma drivers, a bigger timeout is used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21828?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21828" src="https://img.shields.io/badge/CVE--2025--21828-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: mac80211: don't flush non-uploaded STAs  If STA state is pre-moved to AUTHORIZED (such as in IBSS scenarios) and insertion fails, the station is freed. In this case, the driver never knew about the station, so trying to flush it is unexpected and may crash.  Check if the sta was uploaded to the driver before and fix this.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21826?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21826" src="https://img.shields.io/badge/CVE--2025--21826-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_tables: reject mismatching sum of field_len with set key length  The field length description provides the length of each separated key field in the concatenation, each field gets rounded up to 32-bits to calculate the pipapo rule width from pipapo_init(). The set key length provides the total size of the key aligned to 32-bits.  Register-based arithmetics still allows for combining mismatching set key length and field length description, eg. set key length 10 and field description [ 5, 4 ] leading to pipapo width of 12.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21825?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21825" src="https://img.shields.io/badge/CVE--2025--21825-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Cancel the running bpf_timer through kworker for PREEMPT_RT  During the update procedure, when overwrite element in a pre-allocated htab, the freeing of old_element is protected by the bucket lock. The reason why the bucket lock is necessary is that the old_element has already been stashed in htab->extra_elems after alloc_htab_elem() returns. If freeing the old_element after the bucket lock is unlocked, the stashed element may be reused by concurrent update procedure and the freeing of old_element will run concurrently with the reuse of the old_element. However, the invocation of check_and_free_fields() may acquire a spin-lock which violates the lockdep rule because its caller has already held a raw-spin-lock (bucket lock). The following warning will be reported when such race happens:  BUG: scheduling while atomic: test_progs/676/0x00000003 3 locks held by test_progs/676: #0: ffffffff864b0240 (rcu_read_lock_trace){....}-{0:0}, at: bpf_prog_test_run_syscall+0x2c0/0x830 #1: ffff88810e961188 (&htab->lockdep_key){....}-{2:2}, at: htab_map_update_elem+0x306/0x1500 #2: ffff8881f4eac1b8 (&base->softirq_expiry_lock){....}-{2:2}, at: hrtimer_cancel_wait_running+0xe9/0x1b0 Modules linked in: bpf_testmod(O) Preemption disabled at: [<ffffffff817837a3>] htab_map_update_elem+0x293/0x1500 CPU: 0 UID: 0 PID: 676 Comm: test_progs Tainted: G ... 6.12.0+ #11 Tainted: [W]=WARN, [O]=OOT_MODULE Hardware name: QEMU Standard PC (i440FX + PIIX, 1996)... Call Trace: <TASK> dump_stack_lvl+0x57/0x70 dump_stack+0x10/0x20 __schedule_bug+0x120/0x170 __schedule+0x300c/0x4800 schedule_rtlock+0x37/0x60 rtlock_slowlock_locked+0x6d9/0x54c0 rt_spin_lock+0x168/0x230 hrtimer_cancel_wait_running+0xe9/0x1b0 hrtimer_cancel+0x24/0x30 bpf_timer_delete_work+0x1d/0x40 bpf_timer_cancel_and_free+0x5e/0x80 bpf_obj_free_fields+0x262/0x4a0 check_and_free_fields+0x1d0/0x280 htab_map_update_elem+0x7fc/0x1500 bpf_prog_9f90bc20768e0cb9_overwrite_cb+0x3f/0x43 bpf_prog_ea601c4649694dbd_overwrite_timer+0x5d/0x7e bpf_prog_test_run_syscall+0x322/0x830 __sys_bpf+0x135d/0x3ca0 __x64_sys_bpf+0x75/0xb0 x64_sys_call+0x1b5/0xa10 do_syscall_64+0x3b/0xc0 entry_SYSCALL_64_after_hwframe+0x4b/0x53 ... </TASK>  It seems feasible to break the reuse and refill of per-cpu extra_elems into two independent parts: reuse the per-cpu extra_elems with bucket lock being held and refill the old_element as per-cpu extra_elems after the bucket lock is unlocked. However, it will make the concurrent overwrite procedures on the same CPU return unexpected -E2BIG error when the map is full.  Therefore, the patch fixes the lock problem by breaking the cancelling of bpf_timer into two steps for PREEMPT_RT: 1) use hrtimer_try_to_cancel() and check its return value 2) if the timer is running, use hrtimer_cancel() through a kworker to cancel it again Considering that the current implementation of hrtimer_cancel() will try to acquire a being held softirq_expiry_lock when the current timer is running, these steps above are reasonable. However, it also has downside. When the timer is running, the cancelling of the timer is delayed when releasing the last map uref. The delay is also fixable (e.g., break the cancelling of bpf timer into two parts: one part in locked scope, another one in unlocked scope), it can be revised later if necessary.  It is a bit hard to decide the right fix tag. One reason is that the problem depends on PREEMPT_RT which is enabled in v6.12. Considering the softirq_expiry_lock lock exists since v5.4 and bpf_timer is introduced in v5.15, the bpf_timer commit is used in the fixes tag and an extra depends-on tag is added to state the dependency on PREEMPT_RT.  Depends-on: v6.12+ with PREEMPT_RT enabled

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21823?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21823" src="https://img.shields.io/badge/CVE--2025--21823-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  batman-adv: Drop unmanaged ELP metric worker  The ELP worker needs to calculate new metric values for all neighbors "reachable" over an interface. Some of the used metric sources require locks which might need to sleep. This sleep is incompatible with the RCU list iterator used for the recorded neighbors. The initial approach to work around of this problem was to queue another work item per neighbor and then run this in a new context.  Even when this solved the RCU vs might_sleep() conflict, it has a major problems: Nothing was stopping the work item in case it is not needed anymore - for example because one of the related interfaces was removed or the batman-adv module was unloaded - resulting in potential invalid memory accesses.  Directly canceling the metric worker also has various problems:  * cancel_work_sync for a to-be-deactivated interface is called with rtnl_lock held. But the code in the ELP metric worker also tries to use rtnl_lock() - which will never return in this case. This also means that cancel_work_sync would never return because it is waiting for the worker to finish. * iterating over the neighbor list for the to-be-deactivated interface is currently done using the RCU specific methods. Which means that it is possible to miss items when iterating over it without the associated spinlock - a behaviour which is acceptable for a periodic metric check but not for a cleanup routine (which must "stop" all still running workers)  The better approch is to get rid of the per interface neighbor metric worker and handle everything in the interface worker. The original problems are solved by:  * creating a list of neighbors which require new metric information inside the RCU protected context, gathering the metric according to the new list outside the RCU protected context * only use rcu_trylock inside metric gathering code to avoid a deadlock when the cancel_delayed_work_sync is called in the interface removal code (which is called with the rtnl_lock held)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21821?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21821" src="https://img.shields.io/badge/CVE--2025--21821-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fbdev: omap: use threaded IRQ for LCD DMA  When using touchscreen and framebuffer, Nokia 770 crashes easily with:  BUG: scheduling while atomic: irq/144-ads7846/82/0x00010000 Modules linked in: usb_f_ecm g_ether usb_f_rndis u_ether libcomposite configfs omap_udc ohci_omap ohci_hcd CPU: 0 UID: 0 PID: 82 Comm: irq/144-ads7846 Not tainted 6.12.7-770 #2 Hardware name: Nokia 770 Call trace: unwind_backtrace from show_stack+0x10/0x14 show_stack from dump_stack_lvl+0x54/0x5c dump_stack_lvl from __schedule_bug+0x50/0x70 __schedule_bug from __schedule+0x4d4/0x5bc __schedule from schedule+0x34/0xa0 schedule from schedule_preempt_disabled+0xc/0x10 schedule_preempt_disabled from __mutex_lock.constprop.0+0x218/0x3b4 __mutex_lock.constprop.0 from clk_prepare_lock+0x38/0xe4 clk_prepare_lock from clk_set_rate+0x18/0x154 clk_set_rate from sossi_read_data+0x4c/0x168 sossi_read_data from hwa742_read_reg+0x5c/0x8c hwa742_read_reg from send_frame_handler+0xfc/0x300 send_frame_handler from process_pending_requests+0x74/0xd0 process_pending_requests from lcd_dma_irq_handler+0x50/0x74 lcd_dma_irq_handler from __handle_irq_event_percpu+0x44/0x130 __handle_irq_event_percpu from handle_irq_event+0x28/0x68 handle_irq_event from handle_level_irq+0x9c/0x170 handle_level_irq from generic_handle_domain_irq+0x2c/0x3c generic_handle_domain_irq from omap1_handle_irq+0x40/0x8c omap1_handle_irq from generic_handle_arch_irq+0x28/0x3c generic_handle_arch_irq from call_with_stack+0x1c/0x24 call_with_stack from __irq_svc+0x94/0xa8 Exception stack(0xc5255da0 to 0xc5255de8) 5da0: 00000001 c22fc620 00000000 00000000 c08384a8 c106fc00 00000000 c240c248 5dc0: c113a600 c3f6ec30 00000001 00000000 c22fc620 c5255df0 c22fc620 c0279a94 5de0: 60000013 ffffffff __irq_svc from clk_prepare_lock+0x4c/0xe4 clk_prepare_lock from clk_get_rate+0x10/0x74 clk_get_rate from uwire_setup_transfer+0x40/0x180 uwire_setup_transfer from spi_bitbang_transfer_one+0x2c/0x9c spi_bitbang_transfer_one from spi_transfer_one_message+0x2d0/0x664 spi_transfer_one_message from __spi_pump_transfer_message+0x29c/0x498 __spi_pump_transfer_message from __spi_sync+0x1f8/0x2e8 __spi_sync from spi_sync+0x24/0x40 spi_sync from ads7846_halfd_read_state+0x5c/0x1c0 ads7846_halfd_read_state from ads7846_irq+0x58/0x348 ads7846_irq from irq_thread_fn+0x1c/0x78 irq_thread_fn from irq_thread+0x120/0x228 irq_thread from kthread+0xc8/0xe8 kthread from ret_from_fork+0x14/0x28  As a quick fix, switch to a threaded IRQ which provides a stable system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21819?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21819" src="https://img.shields.io/badge/CVE--2025--21819-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Revert "drm/amd/display: Use HW lock mgr for PSR1"  This reverts commit a2b5a9956269 ("drm/amd/display: Use HW lock mgr for PSR1")  Because it may cause system hang while connect with two edp panel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21817?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21817" src="https://img.shields.io/badge/CVE--2025--21817-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  block: mark GFP_NOIO around sysfs ->store()  sysfs ->store is called with queue freezed, meantime we have several ->store() callbacks(update_nr_requests, wbt, scheduler) to allocate memory with GFP_KERNEL which may run into direct reclaim code path, then potential deadlock can be caused.  Fix the issue by marking NOIO around sysfs ->store()

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21816?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21816" src="https://img.shields.io/badge/CVE--2025--21816-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  hrtimers: Force migrate away hrtimers queued after CPUHP_AP_HRTIMERS_DYING  hrtimers are migrated away from the dying CPU to any online target at the CPUHP_AP_HRTIMERS_DYING stage in order not to delay bandwidth timers handling tasks involved in the CPU hotplug forward progress.  However wakeups can still be performed by the outgoing CPU after CPUHP_AP_HRTIMERS_DYING. Those can result again in bandwidth timers being armed. Depending on several considerations (crystal ball power management based election, earliest timer already enqueued, timer migration enabled or not), the target may eventually be the current CPU even if offline. If that happens, the timer is eventually ignored.  The most notable example is RCU which had to deal with each and every of those wake-ups by deferring them to an online CPU, along with related workarounds:  _ e787644caf76 (rcu: Defer RCU kthreads wakeup when CPU is dying) _ 9139f93209d1 (rcu/nocb: Fix RT throttling hrtimer armed from offline CPU) _ f7345ccc62a4 (rcu/nocb: Fix rcuog wake-up from offline softirq)  The problem isn't confined to RCU though as the stop machine kthread (which runs CPUHP_AP_HRTIMERS_DYING) reports its completion at the end of its work through cpu_stop_signal_done() and performs a wake up that eventually arms the deadline server timer:  WARNING: CPU: 94 PID: 588 at kernel/time/hrtimer.c:1086 hrtimer_start_range_ns+0x289/0x2d0 CPU: 94 UID: 0 PID: 588 Comm: migration/94 Not tainted Stopper: multi_cpu_stop+0x0/0x120 <- stop_machine_cpuslocked+0x66/0xc0 RIP: 0010:hrtimer_start_range_ns+0x289/0x2d0 Call Trace: <TASK> start_dl_timer enqueue_dl_entity dl_server_start enqueue_task_fair enqueue_task ttwu_do_activate try_to_wake_up complete cpu_stopper_thread  Instead of providing yet another bandaid to work around the situation, fix it in the hrtimers infrastructure instead: always migrate away a timer to an online target whenever it is enqueued from an offline CPU.  This will also allow to revert all the above RCU disgraceful hacks.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21815?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21815" src="https://img.shields.io/badge/CVE--2025--21815-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm/compaction: fix UBSAN shift-out-of-bounds warning  syzkaller reported a UBSAN shift-out-of-bounds warning of (1UL << order) in isolate_freepages_block().  The bogus compound_order can be any value because it is union with flags.  Add back the MAX_PAGE_ORDER check to fix the warning.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21812?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21812" src="https://img.shields.io/badge/CVE--2025--21812-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ax25: rcu protect dev->ax25_ptr  syzbot found a lockdep issue [1].  We should remove ax25 RTNL dependency in ax25_setsockopt()  This should also fix a variety of possible UAF in ax25.  [1]  WARNING: possible circular locking dependency detected 6.13.0-rc3-syzkaller-00762-g9268abe611b0 #0 Not tainted ------------------------------------------------------ syz.5.1818/12806 is trying to acquire lock: ffffffff8fcb3988 (rtnl_mutex){+.+.}-{4:4}, at: ax25_setsockopt+0xa55/0xe90 net/ax25/af_ax25.c:680  but task is already holding lock: ffff8880617ac258 (sk_lock-AF_AX25){+.+.}-{0:0}, at: lock_sock include/net/sock.h:1618 [inline] ffff8880617ac258 (sk_lock-AF_AX25){+.+.}-{0:0}, at: ax25_setsockopt+0x209/0xe90 net/ax25/af_ax25.c:574  which lock already depends on the new lock.  the existing dependency chain (in reverse order) is:  -> #1 (sk_lock-AF_AX25){+.+.}-{0:0}: lock_acquire+0x1ed/0x550 kernel/locking/lockdep.c:5849 lock_sock_nested+0x48/0x100 net/core/sock.c:3642 lock_sock include/net/sock.h:1618 [inline] ax25_kill_by_device net/ax25/af_ax25.c:101 [inline] ax25_device_event+0x24d/0x580 net/ax25/af_ax25.c:146 notifier_call_chain+0x1a5/0x3f0 kernel/notifier.c:85 __dev_notify_flags+0x207/0x400 dev_change_flags+0xf0/0x1a0 net/core/dev.c:9026 dev_ifsioc+0x7c8/0xe70 net/core/dev_ioctl.c:563 dev_ioctl+0x719/0x1340 net/core/dev_ioctl.c:820 sock_do_ioctl+0x240/0x460 net/socket.c:1234 sock_ioctl+0x626/0x8e0 net/socket.c:1339 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:906 [inline] __se_sys_ioctl+0xf5/0x170 fs/ioctl.c:892 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  -> #0 (rtnl_mutex){+.+.}-{4:4}: check_prev_add kernel/locking/lockdep.c:3161 [inline] check_prevs_add kernel/locking/lockdep.c:3280 [inline] validate_chain+0x18ef/0x5920 kernel/locking/lockdep.c:3904 __lock_acquire+0x1397/0x2100 kernel/locking/lockdep.c:5226 lock_acquire+0x1ed/0x550 kernel/locking/lockdep.c:5849 __mutex_lock_common kernel/locking/mutex.c:585 [inline] __mutex_lock+0x1ac/0xee0 kernel/locking/mutex.c:735 ax25_setsockopt+0xa55/0xe90 net/ax25/af_ax25.c:680 do_sock_setsockopt+0x3af/0x720 net/socket.c:2324 __sys_setsockopt net/socket.c:2349 [inline] __do_sys_setsockopt net/socket.c:2355 [inline] __se_sys_setsockopt net/socket.c:2352 [inline] __x64_sys_setsockopt+0x1ee/0x280 net/socket.c:2352 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  other info that might help us debug this:  Possible unsafe locking scenario:  CPU0                    CPU1 ----                    ---- lock(sk_lock-AF_AX25); lock(rtnl_mutex); lock(sk_lock-AF_AX25); lock(rtnl_mutex);  *** DEADLOCK ***  1 lock held by syz.5.1818/12806: #0: ffff8880617ac258 (sk_lock-AF_AX25){+.+.}-{0:0}, at: lock_sock include/net/sock.h:1618 [inline] #0: ffff8880617ac258 (sk_lock-AF_AX25){+.+.}-{0:0}, at: ax25_setsockopt+0x209/0xe90 net/ax25/af_ax25.c:574  stack backtrace: CPU: 1 UID: 0 PID: 12806 Comm: syz.5.1818 Not tainted 6.13.0-rc3-syzkaller-00762-g9268abe611b0 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_circular_bug+0x13a/0x1b0 kernel/locking/lockdep.c:2074 check_noncircular+0x36a/0x4a0 kernel/locking/lockdep.c:2206 check_prev_add kernel/locking/lockdep.c:3161 [inline] check_prevs_add kernel/lockin ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21811?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21811" src="https://img.shields.io/badge/CVE--2025--21811-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nilfs2: protect access to buffers with no active references  nilfs_lookup_dirty_data_buffers(), which iterates through the buffers attached to dirty data folios/pages, accesses the attached buffers without locking the folios/pages.  For data cache, nilfs_clear_folio_dirty() may be called asynchronously when the file system degenerates to read only, so nilfs_lookup_dirty_data_buffers() still has the potential to cause use after free issues when buffers lose the protection of their dirty state midway due to this asynchronous clearing and are unintentionally freed by try_to_free_buffers().  Eliminate this race issue by adjusting the lock section in this function.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21810?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21810" src="https://img.shields.io/badge/CVE--2025--21810-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  driver core: class: Fix wild pointer dereferences in API class_dev_iter_next()  There are a potential wild pointer dereferences issue regarding APIs class_dev_iter_(init|next|exit)(), as explained by below typical usage:  // All members of @iter are wild pointers. struct class_dev_iter iter;  // class_dev_iter_init(@iter, @class, ...) checks parameter @class for // potential class_to_subsys() error, and it returns void type and does // not initialize its output parameter @iter, so caller can not detect // the error and continues to invoke class_dev_iter_next(@iter) even if // @iter still contains wild pointers. class_dev_iter_init(&iter, ...);  // Dereference these wild pointers in @iter here once suffer the error. while (dev = class_dev_iter_next(&iter)) { ... };  // Also dereference these wild pointers here. class_dev_iter_exit(&iter);  Actually, all callers of these APIs have such usage pattern in kernel tree. Fix by: - Initialize output parameter @iter by memset() in class_dev_iter_init() and give callers prompt by pr_crit() for the error. - Check if @iter is valid in class_dev_iter_next().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21808?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21808" src="https://img.shields.io/badge/CVE--2025--21808-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: xdp: Disallow attaching device-bound programs in generic mode  Device-bound programs are used to support RX metadata kfuncs. These kfuncs are driver-specific and rely on the driver context to read the metadata. This means they can't work in generic XDP mode. However, there is no check to disallow such programs from being attached in generic mode, in which case the metadata kfuncs will be called in an invalid context, leading to crashes.  Fix this by adding a check to disallow attaching device-bound programs in generic mode.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21806?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21806" src="https://img.shields.io/badge/CVE--2025--21806-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: let net.core.dev_weight always be non-zero  The following problem was encountered during stability test:  (NULL net_device): NAPI poll function process_backlog+0x0/0x530 \ returned 1, exceeding its budget of 0. ------------[ cut here ]------------ list_add double add: new=ffff88905f746f48, prev=ffff88905f746f48, \ next=ffff88905f746e40. WARNING: CPU: 18 PID: 5462 at lib/list_debug.c:35 \ __list_add_valid_or_report+0xf3/0x130 CPU: 18 UID: 0 PID: 5462 Comm: ping Kdump: loaded Not tainted 6.13.0-rc7+ RIP: 0010:__list_add_valid_or_report+0xf3/0x130 Call Trace: ? __warn+0xcd/0x250 ? __list_add_valid_or_report+0xf3/0x130 enqueue_to_backlog+0x923/0x1070 netif_rx_internal+0x92/0x2b0 __netif_rx+0x15/0x170 loopback_xmit+0x2ef/0x450 dev_hard_start_xmit+0x103/0x490 __dev_queue_xmit+0xeac/0x1950 ip_finish_output2+0x6cc/0x1620 ip_output+0x161/0x270 ip_push_pending_frames+0x155/0x1a0 raw_sendmsg+0xe13/0x1550 __sys_sendto+0x3bf/0x4e0 __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x5b/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  The reproduction command is as follows: sysctl -w net.core.dev_weight=0 ping 127.0.0.1  This is because when the napi's weight is set to 0, process_backlog() may return 0 and clear the NAPI_STATE_SCHED bit of napi->state, causing this napi to be re-polled in net_rx_action() until __do_softirq() times out. Since the NAPI_STATE_SCHED bit has been cleared, napi_schedule_rps() can be retriggered in enqueue_to_backlog(), causing this issue.  Making the napi's weight always non-zero solves this problem.  Triggering this issue requires system-wide admin (setting is not namespaced).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21804?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21804" src="https://img.shields.io/badge/CVE--2025--21804-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  PCI: rcar-ep: Fix incorrect variable used when calling devm_request_mem_region()  The rcar_pcie_parse_outbound_ranges() uses the devm_request_mem_region() macro to request a needed resource. A string variable that lives on the stack is then used to store a dynamically computed resource name, which is then passed on as one of the macro arguments. This can lead to undefined behavior.  Depending on the current contents of the memory, the manifestations of errors may vary. One possible output may be as follows:  $ cat /proc/iomem 30000000-37ffffff : 38000000-3fffffff :  Sometimes, garbage may appear after the colon.  In very rare cases, if no NULL-terminator is found in memory, the system might crash because the string iterator will overrun which can lead to access of unmapped memory above the stack.  Thus, fix this by replacing outbound_name with the name of the previously requested resource. With the changes applied, the output will be as follows:  $ cat /proc/iomem 30000000-37ffffff : memory2 38000000-3fffffff : memory3  [kwilczynski: commit log]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21803?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21803" src="https://img.shields.io/badge/CVE--2025--21803-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  LoongArch: Fix warnings during S3 suspend  The enable_gpe_wakeup() function calls acpi_enable_all_wakeup_gpes(), and the later one may call the preempt_schedule_common() function, resulting in a thread switch and causing the CPU to be in an interrupt enabled state after the enable_gpe_wakeup() function returns, leading to the warnings as follow.  [ C0] WARNING: ... at kernel/time/timekeeping.c:845 ktime_get+0xbc/0xc8 [ C0]          ... [ C0] Call Trace: [ C0] [<90000000002243b4>] show_stack+0x64/0x188 [ C0] [<900000000164673c>] dump_stack_lvl+0x60/0x88 [ C0] [<90000000002687e4>] __warn+0x8c/0x148 [ C0] [<90000000015e9978>] report_bug+0x1c0/0x2b0 [ C0] [<90000000016478e4>] do_bp+0x204/0x3b8 [ C0] [<90000000025b1924>] exception_handlers+0x1924/0x10000 [ C0] [<9000000000343bbc>] ktime_get+0xbc/0xc8 [ C0] [<9000000000354c08>] tick_sched_timer+0x30/0xb0 [ C0] [<90000000003408e0>] __hrtimer_run_queues+0x160/0x378 [ C0] [<9000000000341f14>] hrtimer_interrupt+0x144/0x388 [ C0] [<9000000000228348>] constant_timer_interrupt+0x38/0x48 [ C0] [<90000000002feba4>] __handle_irq_event_percpu+0x64/0x1e8 [ C0] [<90000000002fed48>] handle_irq_event_percpu+0x20/0x80 [ C0] [<9000000000306b9c>] handle_percpu_irq+0x5c/0x98 [ C0] [<90000000002fd4a0>] generic_handle_domain_irq+0x30/0x48 [ C0] [<9000000000d0c7b0>] handle_cpu_irq+0x70/0xa8 [ C0] [<9000000001646b30>] handle_loongarch_irq+0x30/0x48 [ C0] [<9000000001646bc8>] do_vint+0x80/0xe0 [ C0] [<90000000002aea1c>] finish_task_switch.isra.0+0x8c/0x2a8 [ C0] [<900000000164e34c>] __schedule+0x314/0xa48 [ C0] [<900000000164ead8>] schedule+0x58/0xf0 [ C0] [<9000000000294a2c>] worker_thread+0x224/0x498 [ C0] [<900000000029d2f0>] kthread+0xf8/0x108 [ C0] [<9000000000221f28>] ret_from_kernel_thread+0xc/0xa4 [ C0] [ C0] ---[ end trace 0000000000000000 ]---  The root cause is acpi_enable_all_wakeup_gpes() uses a mutex to protect acpi_hw_enable_all_wakeup_gpes(), and acpi_ut_acquire_mutex() may cause a thread switch. Since there is no longer concurrent execution during loongarch_acpi_suspend(), we can call acpi_hw_enable_all_wakeup_gpes() directly in enable_gpe_wakeup().  The solution is similar to commit 22db06337f590d01 ("ACPI: sleep: Avoid breaking S3 wakeup due to might_sleep()").

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21802?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21802" src="https://img.shields.io/badge/CVE--2025--21802-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hns3: fix oops when unload drivers paralleling  When unload hclge driver, it tries to disable sriov first for each ae_dev node from hnae3_ae_dev_list. If user unloads hns3 driver at the time, because it removes all the ae_dev nodes, and it may cause oops.  But we can't simply use hnae3_common_lock for this. Because in the process flow of pci_disable_sriov(), it will trigger the remove flow of VF, which will also take hnae3_common_lock.  To fixes it, introduce a new mutex to protect the unload process.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21801?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21801" src="https://img.shields.io/badge/CVE--2025--21801-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: ravb: Fix missing rtnl lock in suspend/resume path  Fix the suspend/resume path by ensuring the rtnl lock is held where required. Calls to ravb_open, ravb_close and wol operations must be performed under the rtnl lock to prevent conflicts with ongoing ndo operations.  Without this fix, the following warning is triggered: [   39.032969] ============================= [   39.032983] WARNING: suspicious RCU usage [   39.033019] ----------------------------- [   39.033033] drivers/net/phy/phy_device.c:2004 suspicious rcu_dereference_protected() usage! ... [   39.033597] stack backtrace: [   39.033613] CPU: 0 UID: 0 PID: 174 Comm: python3 Not tainted 6.13.0-rc7-next-20250116-arm64-renesas-00002-g35245dfdc62c #7 [   39.033623] Hardware name: Renesas SMARC EVK version 2 based on r9a08g045s33 (DT) [   39.033628] Call trace: [   39.033633]  show_stack+0x14/0x1c (C) [   39.033652]  dump_stack_lvl+0xb4/0xc4 [   39.033664]  dump_stack+0x14/0x1c [   39.033671]  lockdep_rcu_suspicious+0x16c/0x22c [   39.033682]  phy_detach+0x160/0x190 [   39.033694]  phy_disconnect+0x40/0x54 [   39.033703]  ravb_close+0x6c/0x1cc [   39.033714]  ravb_suspend+0x48/0x120 [   39.033721]  dpm_run_callback+0x4c/0x14c [   39.033731]  device_suspend+0x11c/0x4dc [   39.033740]  dpm_suspend+0xdc/0x214 [   39.033748]  dpm_suspend_start+0x48/0x60 [   39.033758]  suspend_devices_and_enter+0x124/0x574 [   39.033769]  pm_suspend+0x1ac/0x274 [   39.033778]  state_store+0x88/0x124 [   39.033788]  kobj_attr_store+0x14/0x24 [   39.033798]  sysfs_kf_write+0x48/0x6c [   39.033808]  kernfs_fop_write_iter+0x118/0x1a8 [   39.033817]  vfs_write+0x27c/0x378 [   39.033825]  ksys_write+0x64/0xf4 [   39.033833]  __arm64_sys_write+0x18/0x20 [   39.033841]  invoke_syscall+0x44/0x104 [   39.033852]  el0_svc_common.constprop.0+0xb4/0xd4 [   39.033862]  do_el0_svc+0x18/0x20 [   39.033870]  el0_svc+0x3c/0xf0 [   39.033880]  el0t_64_sync_handler+0xc0/0xc4 [   39.033888]  el0t_64_sync+0x154/0x158 [   39.041274] ravb 11c30000.ethernet eth0: Link is Down

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21799?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21799" src="https://img.shields.io/badge/CVE--2025--21799-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: ethernet: ti: am65-cpsw: fix freeing IRQ in am65_cpsw_nuss_remove_tx_chns()  When getting the IRQ we use k3_udma_glue_tx_get_irq() which returns negative error value on error. So not NULL check is not sufficient to deteremine if IRQ is valid. Check that IRQ is greater then zero to ensure it is valid.  There is no issue at probe time but at runtime user can invoke .set_channels which results in the following call chain. am65_cpsw_set_channels() am65_cpsw_nuss_update_tx_rx_chns() am65_cpsw_nuss_remove_tx_chns() am65_cpsw_nuss_init_tx_chns()  At this point if am65_cpsw_nuss_init_tx_chns() fails due to k3_udma_glue_tx_get_irq() then tx_chn->irq will be set to a negative value.  Then, at subsequent .set_channels with higher channel count we will attempt to free an invalid IRQ in am65_cpsw_nuss_remove_tx_chns() leading to a kernel warning.  The issue is present in the original commit that introduced this driver, although there, am65_cpsw_nuss_update_tx_rx_chns() existed as am65_cpsw_nuss_update_tx_chns().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21796?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21796" src="https://img.shields.io/badge/CVE--2025--21796-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfsd: clear acl_access/acl_default after releasing them  If getting acl_default fails, acl_access and acl_default will be released simultaneously. However, acl_access will still retain a pointer pointing to the released posix_acl, which will trigger a WARNING in nfs3svc_release_getacl like this:  ------------[ cut here ]------------ refcount_t: underflow; use-after-free. WARNING: CPU: 26 PID: 3199 at lib/refcount.c:28 refcount_warn_saturate+0xb5/0x170 Modules linked in: CPU: 26 UID: 0 PID: 3199 Comm: nfsd Not tainted 6.12.0-rc6-00079-g04ae226af01f-dirty #8 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.1-2.fc37 04/01/2014 RIP: 0010:refcount_warn_saturate+0xb5/0x170 Code: cc cc 0f b6 1d b3 20 a5 03 80 fb 01 0f 87 65 48 d8 00 83 e3 01 75 e4 48 c7 c7 c0 3b 9b 85 c6 05 97 20 a5 03 01 e8 fb 3e 30 ff <0f> 0b eb cd 0f b6 1d 8a3 RSP: 0018:ffffc90008637cd8 EFLAGS: 00010282 RAX: 0000000000000000 RBX: 0000000000000000 RCX: ffffffff83904fde RDX: dffffc0000000000 RSI: 0000000000000008 RDI: ffff88871ed36380 RBP: ffff888158beeb40 R08: 0000000000000001 R09: fffff520010c6f56 R10: ffffc90008637ab7 R11: 0000000000000001 R12: 0000000000000001 R13: ffff888140e77400 R14: ffff888140e77408 R15: ffffffff858b42c0 FS:  0000000000000000(0000) GS:ffff88871ed00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000562384d32158 CR3: 000000055cc6a000 CR4: 00000000000006f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> ? refcount_warn_saturate+0xb5/0x170 ? __warn+0xa5/0x140 ? refcount_warn_saturate+0xb5/0x170 ? report_bug+0x1b1/0x1e0 ? handle_bug+0x53/0xa0 ? exc_invalid_op+0x17/0x40 ? asm_exc_invalid_op+0x1a/0x20 ? tick_nohz_tick_stopped+0x1e/0x40 ? refcount_warn_saturate+0xb5/0x170 ? refcount_warn_saturate+0xb5/0x170 nfs3svc_release_getacl+0xc9/0xe0 svc_process_common+0x5db/0xb60 ? __pfx_svc_process_common+0x10/0x10 ? __rcu_read_unlock+0x69/0xa0 ? __pfx_nfsd_dispatch+0x10/0x10 ? svc_xprt_received+0xa1/0x120 ? xdr_init_decode+0x11d/0x190 svc_process+0x2a7/0x330 svc_handle_xprt+0x69d/0x940 svc_recv+0x180/0x2d0 nfsd+0x168/0x200 ? __pfx_nfsd+0x10/0x10 kthread+0x1a2/0x1e0 ? kthread+0xf4/0x1e0 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x34/0x60 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1a/0x30 </TASK> Kernel panic - not syncing: kernel: panic_on_warn set ...  Clear acl_access/acl_default after posix_acl_release is called to prevent UAF from being triggered.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21795?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21795" src="https://img.shields.io/badge/CVE--2025--21795-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  NFSD: fix hang in nfsd4_shutdown_callback  If nfs4_client is in courtesy state then there is no point to send the callback. This causes nfsd4_shutdown_callback to hang since cl_cb_inflight is not 0. This hang lasts about 15 minutes until TCP notifies NFSD that the connection was dropped.  This patch modifies nfsd4_run_cb_work to skip the RPC call if nfs4_client is in courtesy state.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21786?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21786" src="https://img.shields.io/badge/CVE--2025--21786-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  workqueue: Put the pwq after detaching the rescuer from the pool  The commit 68f83057b913("workqueue: Reap workers via kthread_stop() and remove detach_completion") adds code to reap the normal workers but mistakenly does not handle the rescuer and also removes the code waiting for the rescuer in put_unbound_pool(), which caused a use-after-free bug reported by Cheung Wall.  To avoid the use-after-free bug, the pool’s reference must be held until the detachment is complete. Therefore, move the code that puts the pwq after detaching the rescuer from the pool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21784?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21784" src="https://img.shields.io/badge/CVE--2025--21784-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu: bail out when failed to load fw in psp_init_cap_microcode()  In function psp_init_cap_microcode(), it should bail out when failed to load firmware, otherwise it may cause invalid memory access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21781?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21781" src="https://img.shields.io/badge/CVE--2025--21781-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  batman-adv: fix panic during interface removal  Reference counting is used to ensure that batadv_hardif_neigh_node and batadv_hard_iface are not freed before/during batadv_v_elp_throughput_metric_update work is finished.  But there isn't a guarantee that the hard if will remain associated with a soft interface up until the work is finished.  This fixes a crash triggered by reboot that looks like this:  Call trace: batadv_v_mesh_free+0xd0/0x4dc [batman_adv] batadv_v_elp_throughput_metric_update+0x1c/0xa4 process_one_work+0x178/0x398 worker_thread+0x2e8/0x4d0 kthread+0xd8/0xdc ret_from_fork+0x10/0x20  (the batadv_v_mesh_free call is misleading, and does not actually happen)  I was able to make the issue happen more reliably by changing hardif_neigh->bat_v.metric_work work to be delayed work. This allowed me to track down and confirm the fix.  [sven@narfation.org: prevent entering batadv_v_elp_get_throughput without soft_iface]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21772?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21772" src="https://img.shields.io/badge/CVE--2025--21772-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  partitions: mac: fix handling of bogus partition table  Fix several issues in partition probing:  - The bailout for a bad partoffset must use put_dev_sector(), since the preceding read_part_sector() succeeded. - If the partition table claims a silly sector size like 0xfff bytes (which results in partition table entries straddling sector boundaries), bail out instead of accessing out-of-bounds memory. - We must not assume that the partition table contains proper NUL termination - use strnlen() and strncmp() instead of strlen() and strcmp().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21768?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21768" src="https://img.shields.io/badge/CVE--2025--21768-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: ipv6: fix dst ref loops in rpl, seg6 and ioam6 lwtunnels  Some lwtunnels have a dst cache for post-transformation dst. If the packet destination did not change we may end up recording a reference to the lwtunnel in its own cache, and the lwtunnel state will never be freed.  Discovered by the ioam6.sh test, kmemleak was recently fixed to catch per-cpu memory leaks. I'm not sure if rpl and seg6 can actually hit this, but in principle I don't see why not.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21767?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21767" src="https://img.shields.io/badge/CVE--2025--21767-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  clocksource: Use migrate_disable() to avoid calling get_random_u32() in atomic context  The following bug report happened with a PREEMPT_RT kernel:  BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48 in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 2012, name: kwatchdog preempt_count: 1, expected: 0 RCU nest depth: 0, expected: 0 get_random_u32+0x4f/0x110 clocksource_verify_choose_cpus+0xab/0x1a0 clocksource_verify_percpu.part.0+0x6b/0x330 clocksource_watchdog_kthread+0x193/0x1a0  It is due to the fact that clocksource_verify_choose_cpus() is invoked with preemption disabled.  This function invokes get_random_u32() to obtain random numbers for choosing CPUs.  The batched_entropy_32 local lock and/or the base_crng.lock spinlock in driver/char/random.c will be acquired during the call. In PREEMPT_RT kernel, they are both sleeping locks and so cannot be acquired in atomic context.  Fix this problem by using migrate_disable() to allow smp_processor_id() to be reliably used without introducing atomic context. preempt_disable() is then called after clocksource_verify_choose_cpus() but before the clocksource measurement is being run to avoid introducing unexpected latency.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21766?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21766" src="https://img.shields.io/badge/CVE--2025--21766-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv4: use RCU protection in __ip_rt_update_pmtu()  __ip_rt_update_pmtu() must use RCU protection to make sure the net structure it reads does not disappear.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21765?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21765" src="https://img.shields.io/badge/CVE--2025--21765-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: use RCU protection in ip6_default_advmss()  ip6_default_advmss() needs rcu protection to make sure the net structure it reads does not disappear.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21764?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21764" src="https://img.shields.io/badge/CVE--2025--21764-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ndisc: use RCU protection in ndisc_alloc_skb()  ndisc_alloc_skb() can be called without RTNL or RCU being held.  Add RCU protection to avoid possible UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21763?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21763" src="https://img.shields.io/badge/CVE--2025--21763-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  neighbour: use RCU protection in __neigh_notify()  __neigh_notify() can be called without RTNL or RCU protection.  Use RCU protection to avoid potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21762?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21762" src="https://img.shields.io/badge/CVE--2025--21762-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  arp: use RCU protection in arp_xmit()  arp_xmit() can be called without RTNL or RCU protection.  Use RCU protection to avoid potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21761?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21761" src="https://img.shields.io/badge/CVE--2025--21761-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  openvswitch: use RCU protection in ovs_vport_cmd_fill_info()  ovs_vport_cmd_fill_info() can be called without RTNL or RCU.  Use RCU protection and dev_net_rcu() to avoid potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21760?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21760" src="https://img.shields.io/badge/CVE--2025--21760-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ndisc: extend RCU protection in ndisc_send_skb()  ndisc_send_skb() can be called without RTNL or RCU held.  Acquire rcu_read_lock() earlier, so that we can use dev_net_rcu() and avoid a potential UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21759?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21759" src="https://img.shields.io/badge/CVE--2025--21759-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: mcast: extend RCU protection in igmp6_send()  igmp6_send() can be called without RTNL or RCU being held.  Extend RCU protection so that we can safely fetch the net pointer and avoid a potential UAF.  Note that we no longer can use sock_alloc_send_skb() because ipv6.igmp_sk uses GFP_KERNEL allocations which can sleep.  Instead use alloc_skb() and charge the net->ipv6.igmp_sk socket under RCU protection.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21758?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21758" src="https://img.shields.io/badge/CVE--2025--21758-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: mcast: add RCU protection to mld_newpack()  mld_newpack() can be called without RTNL or RCU being held.  Note that we no longer can use sock_alloc_send_skb() because ipv6.igmp_sk uses GFP_KERNEL allocations which can sleep.  Instead use alloc_skb() and charge the net->ipv6.igmp_sk socket under RCU protection.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21754?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21754" src="https://img.shields.io/badge/CVE--2025--21754-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: fix assertion failure when splitting ordered extent after transaction abort  If while we are doing a direct IO write a transaction abort happens, we mark all existing ordered extents with the BTRFS_ORDERED_IOERR flag (done at btrfs_destroy_ordered_extents()), and then after that if we enter btrfs_split_ordered_extent() and the ordered extent has bytes left (meaning we have a bio that doesn't cover the whole ordered extent, see details at btrfs_extract_ordered_extent()), we will fail on the following assertion at btrfs_split_ordered_extent():  ASSERT(!(flags & ~BTRFS_ORDERED_TYPE_FLAGS));  because the BTRFS_ORDERED_IOERR flag is set and the definition of BTRFS_ORDERED_TYPE_FLAGS is just the union of all flags that identify the type of write (regular, nocow, prealloc, compressed, direct IO, encoded).  Fix this by returning an error from btrfs_extract_ordered_extent() if we find the BTRFS_ORDERED_IOERR flag in the ordered extent. The error will be the error that resulted in the transaction abort or -EIO if no transaction abort happened.  This was recently reported by syzbot with the following trace:  FAULT_INJECTION: forcing a failure. name failslab, interval 1, probability 0, space 0, times 1 CPU: 0 UID: 0 PID: 5321 Comm: syz.0.0 Not tainted 6.13.0-rc5-syzkaller #0 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 fail_dump lib/fault-inject.c:53 [inline] should_fail_ex+0x3b0/0x4e0 lib/fault-inject.c:154 should_failslab+0xac/0x100 mm/failslab.c:46 slab_pre_alloc_hook mm/slub.c:4072 [inline] slab_alloc_node mm/slub.c:4148 [inline] __do_kmalloc_node mm/slub.c:4297 [inline] __kmalloc_noprof+0xdd/0x4c0 mm/slub.c:4310 kmalloc_noprof include/linux/slab.h:905 [inline] kzalloc_noprof include/linux/slab.h:1037 [inline] btrfs_chunk_alloc_add_chunk_item+0x244/0x1100 fs/btrfs/volumes.c:5742 reserve_chunk_space+0x1ca/0x2c0 fs/btrfs/block-group.c:4292 check_system_chunk fs/btrfs/block-group.c:4319 [inline] do_chunk_alloc fs/btrfs/block-group.c:3891 [inline] btrfs_chunk_alloc+0x77b/0xf80 fs/btrfs/block-group.c:4187 find_free_extent_update_loop fs/btrfs/extent-tree.c:4166 [inline] find_free_extent+0x42d1/0x5810 fs/btrfs/extent-tree.c:4579 btrfs_reserve_extent+0x422/0x810 fs/btrfs/extent-tree.c:4672 btrfs_new_extent_direct fs/btrfs/direct-io.c:186 [inline] btrfs_get_blocks_direct_write+0x706/0xfa0 fs/btrfs/direct-io.c:321 btrfs_dio_iomap_begin+0xbb7/0x1180 fs/btrfs/direct-io.c:525 iomap_iter+0x697/0xf60 fs/iomap/iter.c:90 __iomap_dio_rw+0xeb9/0x25b0 fs/iomap/direct-io.c:702 btrfs_dio_write fs/btrfs/direct-io.c:775 [inline] btrfs_direct_write+0x610/0xa30 fs/btrfs/direct-io.c:880 btrfs_do_write_iter+0x2a0/0x760 fs/btrfs/file.c:1397 do_iter_readv_writev+0x600/0x880 vfs_writev+0x376/0xba0 fs/read_write.c:1050 do_pwritev fs/read_write.c:1146 [inline] __do_sys_pwritev2 fs/read_write.c:1204 [inline] __se_sys_pwritev2+0x196/0x2b0 fs/read_write.c:1195 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7f1281f85d29 RSP: 002b:00007f12819fe038 EFLAGS: 00000246 ORIG_RAX: 0000000000000148 RAX: ffffffffffffffda RBX: 00007f1282176080 RCX: 00007f1281f85d29 RDX: 0000000000000001 RSI: 0000000020000240 RDI: 0000000000000005 RBP: 00007f12819fe090 R08: 0000000000000000 R09: 0000000000000003 R10: 0000000000007000 R11: 0000000000000246 R12: 0000000000000002 R13: 0000000000000000 R14: 00007f1282176080 R15: 00007ffcb9e23328 </TASK> BTRFS error (device loop0 state A): Transaction aborted (error -12) BTRFS: error (device loop0 state A ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21753?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21753" src="https://img.shields.io/badge/CVE--2025--21753-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: fix use-after-free when attempting to join an aborted transaction  When we are trying to join the current transaction and if it's aborted, we read its 'aborted' field after unlocking fs_info->trans_lock and without holding any extra reference count on it. This means that a concurrent task that is aborting the transaction may free the transaction before we read its 'aborted' field, leading to a use-after-free.  Fix this by reading the 'aborted' field while holding fs_info->trans_lock since any freeing task must first acquire that lock and set fs_info->running_transaction to NULL before freeing the transaction.  This was reported by syzbot and Dmitry with the following stack traces from KASAN:  ================================================================== BUG: KASAN: slab-use-after-free in join_transaction+0xd9b/0xda0 fs/btrfs/transaction.c:278 Read of size 4 at addr ffff888011839024 by task kworker/u4:9/1128  CPU: 0 UID: 0 PID: 1128 Comm: kworker/u4:9 Not tainted 6.13.0-rc7-syzkaller-00019-gc45323b7560e #0 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 Workqueue: events_unbound btrfs_async_reclaim_data_space Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x169/0x550 mm/kasan/report.c:489 kasan_report+0x143/0x180 mm/kasan/report.c:602 join_transaction+0xd9b/0xda0 fs/btrfs/transaction.c:278 start_transaction+0xaf8/0x1670 fs/btrfs/transaction.c:697 flush_space+0x448/0xcf0 fs/btrfs/space-info.c:803 btrfs_async_reclaim_data_space+0x159/0x510 fs/btrfs/space-info.c:1321 process_one_work kernel/workqueue.c:3236 [inline] process_scheduled_works+0xa66/0x1840 kernel/workqueue.c:3317 worker_thread+0x870/0xd30 kernel/workqueue.c:3398 kthread+0x2f0/0x390 kernel/kthread.c:389 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK>  Allocated by task 5315: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68 poison_kmalloc_redzone mm/kasan/common.c:377 [inline] __kasan_kmalloc+0x98/0xb0 mm/kasan/common.c:394 kasan_kmalloc include/linux/kasan.h:260 [inline] __kmalloc_cache_noprof+0x243/0x390 mm/slub.c:4329 kmalloc_noprof include/linux/slab.h:901 [inline] join_transaction+0x144/0xda0 fs/btrfs/transaction.c:308 start_transaction+0xaf8/0x1670 fs/btrfs/transaction.c:697 btrfs_create_common+0x1b2/0x2e0 fs/btrfs/inode.c:6572 lookup_open fs/namei.c:3649 [inline] open_last_lookups fs/namei.c:3748 [inline] path_openat+0x1c03/0x3590 fs/namei.c:3984 do_filp_open+0x27f/0x4e0 fs/namei.c:4014 do_sys_openat2+0x13e/0x1d0 fs/open.c:1402 do_sys_open fs/open.c:1417 [inline] __do_sys_creat fs/open.c:1495 [inline] __se_sys_creat fs/open.c:1489 [inline] __x64_sys_creat+0x123/0x170 fs/open.c:1489 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  Freed by task 5336: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68 kasan_save_free_info+0x40/0x50 mm/kasan/generic.c:582 poison_slab_object mm/kasan/common.c:247 [inline] __kasan_slab_free+0x59/0x70 mm/kasan/common.c:264 kasan_slab_free include/linux/kasan.h:233 [inline] slab_free_hook mm/slub.c:2353 [inline] slab_free mm/slub.c:4613 [inline] kfree+0x196/0x430 mm/slub.c:4761 cleanup_transaction fs/btrfs/transaction.c:2063 [inline] btrfs_commit_transaction+0x2c97/0x3720 fs/btrfs/transaction.c:2598 insert_balance_item+0x1284/0x20b0 fs/btrfs/volumes.c:3757 btrfs_balance+0x992/ ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21752?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21752" src="https://img.shields.io/badge/CVE--2025--21752-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: don't use btrfs_set_item_key_safe on RAID stripe-extents  Don't use btrfs_set_item_key_safe() to modify the keys in the RAID stripe-tree, as this can lead to corruption of the tree, which is caught by the checks in btrfs_set_item_key_safe():  BTRFS info (device nvme1n1): leaf 49168384 gen 15 total ptrs 194 free space 8329 owner 12 BTRFS info (device nvme1n1): refs 2 lock_owner 1030 current 1030 [ snip ] item 105 key (354549760 230 20480) itemoff 14587 itemsize 16 stride 0 devid 5 physical 67502080 item 106 key (354631680 230 4096) itemoff 14571 itemsize 16 stride 0 devid 1 physical 88559616 item 107 key (354631680 230 32768) itemoff 14555 itemsize 16 stride 0 devid 1 physical 88555520 item 108 key (354717696 230 28672) itemoff 14539 itemsize 16 stride 0 devid 2 physical 67604480 [ snip ] BTRFS critical (device nvme1n1): slot 106 key (354631680 230 32768) new key (354635776 230 4096) ------------[ cut here ]------------ kernel BUG at fs/btrfs/ctree.c:2602! Oops: invalid opcode: 0000 [#1] PREEMPT SMP PTI CPU: 1 UID: 0 PID: 1055 Comm: fsstress Not tainted 6.13.0-rc1+ #1464 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.2-3-gd478f380-rebuilt.opensuse.org 04/01/2014 RIP: 0010:btrfs_set_item_key_safe+0xf7/0x270 Code: <snip> RSP: 0018:ffffc90001337ab0 EFLAGS: 00010287 RAX: 0000000000000000 RBX: ffff8881115fd000 RCX: 0000000000000000 RDX: 0000000000000001 RSI: 0000000000000001 RDI: 00000000ffffffff RBP: ffff888110ed6f50 R08: 00000000ffffefff R09: ffffffff8244c500 R10: 00000000ffffefff R11: 00000000ffffffff R12: ffff888100586000 R13: 00000000000000c9 R14: ffffc90001337b1f R15: ffff888110f23b58 FS:  00007f7d75c72740(0000) GS:ffff88813bd00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fa811652c60 CR3: 0000000111398001 CR4: 0000000000370eb0 Call Trace: <TASK> ? __die_body.cold+0x14/0x1a ? die+0x2e/0x50 ? do_trap+0xca/0x110 ? do_error_trap+0x65/0x80 ? btrfs_set_item_key_safe+0xf7/0x270 ? exc_invalid_op+0x50/0x70 ? btrfs_set_item_key_safe+0xf7/0x270 ? asm_exc_invalid_op+0x1a/0x20 ? btrfs_set_item_key_safe+0xf7/0x270 btrfs_partially_delete_raid_extent+0xc4/0xe0 btrfs_delete_raid_extent+0x227/0x240 __btrfs_free_extent.isra.0+0x57f/0x9c0 ? exc_coproc_segment_overrun+0x40/0x40 __btrfs_run_delayed_refs+0x2fa/0xe80 btrfs_run_delayed_refs+0x81/0xe0 btrfs_commit_transaction+0x2dd/0xbe0 ? preempt_count_add+0x52/0xb0 btrfs_sync_file+0x375/0x4c0 do_fsync+0x39/0x70 __x64_sys_fsync+0x13/0x20 do_syscall_64+0x54/0x110 entry_SYSCALL_64_after_hwframe+0x76/0x7e RIP: 0033:0x7f7d7550ef90 Code: <snip> RSP: 002b:00007ffd70237248 EFLAGS: 00000202 ORIG_RAX: 000000000000004a RAX: ffffffffffffffda RBX: 0000000000000004 RCX: 00007f7d7550ef90 RDX: 000000000000013a RSI: 000000000040eb28 RDI: 0000000000000004 RBP: 000000000000001b R08: 0000000000000078 R09: 00007ffd7023725c R10: 00007f7d75400390 R11: 0000000000000202 R12: 028f5c28f5c28f5c R13: 8f5c28f5c28f5c29 R14: 000000000040b520 R15: 00007f7d75c726c8 </TASK>  While the root cause of the tree order corruption isn't clear, using btrfs_duplicate_item() to copy the item and then adjusting both the key and the per-device physical addresses is a safe way to counter this problem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21751?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21751" src="https://img.shields.io/badge/CVE--2025--21751-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: HWS, change error flow on matcher disconnect  Currently, when firmware failure occurs during matcher disconnect flow, the error flow of the function reconnects the matcher back and returns an error, which continues running the calling function and eventually frees the matcher that is being disconnected. This leads to a case where we have a freed matcher on the matchers list, which in turn leads to use-after-free and eventual crash.  This patch fixes that by not trying to reconnect the matcher back when some FW command fails during disconnect.  Note that we're dealing here with FW error. We can't overcome this problem. This might lead to bad steering state (e.g. wrong connection between matchers), and will also lead to resource leakage, as it is the case with any other error handling during resource destruction.  However, the goal here is to allow the driver to continue and not crash the machine with use-after-free error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21750?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21750" src="https://img.shields.io/badge/CVE--2025--21750-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: brcmfmac: Check the return value of of_property_read_string_index()  Somewhen between 6.10 and 6.11 the driver started to crash on my MacBookPro14,3. The property doesn't exist and 'tmp' remains uninitialized, so we pass a random pointer to devm_kstrdup().  The crash I am getting looks like this:  BUG: unable to handle page fault for address: 00007f033c669379 PF: supervisor read access in kernel mode PF: error_code(0x0001) - permissions violation PGD 8000000101341067 P4D 8000000101341067 PUD 101340067 PMD 1013bb067 PTE 800000010aee9025 Oops: Oops: 0001 [#1] SMP PTI CPU: 4 UID: 0 PID: 827 Comm: (udev-worker) Not tainted 6.11.8-gentoo #1 Hardware name: Apple Inc. MacBookPro14,3/Mac-551B86E5744E2388, BIOS 529.140.2.0.0 06/23/2024 RIP: 0010:strlen+0x4/0x30 Code: f7 75 ec 31 c0 c3 cc cc cc cc 48 89 f8 c3 cc cc cc cc 0f 1f 40 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa <80> 3f 00 74 14 48 89 f8 48 83 c0 01 80 38 00 75 f7 48 29 f8 c3 cc RSP: 0018:ffffb4aac0683ad8 EFLAGS: 00010202 RAX: 00000000ffffffea RBX: 00007f033c669379 RCX: 0000000000000001 RDX: 0000000000000cc0 RSI: 00007f033c669379 RDI: 00007f033c669379 RBP: 00000000ffffffea R08: 0000000000000000 R09: 00000000c0ba916a R10: ffffffffffffffff R11: ffffffffb61ea260 R12: ffff91f7815b50c8 R13: 0000000000000cc0 R14: ffff91fafefffe30 R15: ffffb4aac0683b30 FS:  00007f033ccbe8c0(0000) GS:ffff91faeed00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f033c669379 CR3: 0000000107b1e004 CR4: 00000000003706f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> ? __die+0x23/0x70 ? page_fault_oops+0x149/0x4c0 ? raw_spin_rq_lock_nested+0xe/0x20 ? sched_balance_newidle+0x22b/0x3c0 ? update_load_avg+0x78/0x770 ? exc_page_fault+0x6f/0x150 ? asm_exc_page_fault+0x26/0x30 ? __pfx_pci_conf1_write+0x10/0x10 ? strlen+0x4/0x30 devm_kstrdup+0x25/0x70 brcmf_of_probe+0x273/0x350 [brcmfmac]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21746?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21746" src="https://img.shields.io/badge/CVE--2025--21746-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Input: synaptics - fix crash when enabling pass-through port  When enabling a pass-through port an interrupt might come before psmouse driver binds to the pass-through port. However synaptics sub-driver tries to access psmouse instance presumably associated with the pass-through port to figure out if only 1 byte of response or entire protocol packet needs to be forwarded to the pass-through port and may crash if psmouse instance has not been attached to the port yet.  Fix the crash by introducing open() and close() methods for the port and check if the port is open before trying to access psmouse instance. Because psmouse calls serio_open() only after attaching psmouse instance to serio port instance this prevents the potential crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21739?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21739" src="https://img.shields.io/badge/CVE--2025--21739-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: ufs: core: Fix use-after free in init error and remove paths  devm_blk_crypto_profile_init() registers a cleanup handler to run when the associated (platform-) device is being released. For UFS, the crypto private data and pointers are stored as part of the ufs_hba's data structure 'struct ufs_hba::crypto_profile'. This structure is allocated as part of the underlying ufshcd and therefore Scsi_host allocation.  During driver release or during error handling in ufshcd_pltfrm_init(), this structure is released as part of ufshcd_dealloc_host() before the (platform-) device associated with the crypto call above is released. Once this device is released, the crypto cleanup code will run, using the just-released 'struct ufs_hba::crypto_profile'. This causes a use-after-free situation:  Call trace: kfree+0x60/0x2d8 (P) kvfree+0x44/0x60 blk_crypto_profile_destroy_callback+0x28/0x70 devm_action_release+0x1c/0x30 release_nodes+0x6c/0x108 devres_release_all+0x98/0x100 device_unbind_cleanup+0x20/0x70 really_probe+0x218/0x2d0  In other words, the initialisation code flow is:  platform-device probe ufshcd_pltfrm_init() ufshcd_alloc_host() scsi_host_alloc() allocation of struct ufs_hba creation of scsi-host devices devm_blk_crypto_profile_init() devm registration of cleanup handler using platform-device  and during error handling of ufshcd_pltfrm_init() or during driver removal:  ufshcd_dealloc_host() scsi_host_put() put_device(scsi-host) release of struct ufs_hba put_device(platform-device) crypto cleanup handler  To fix this use-after free, change ufshcd_alloc_host() to register a devres action to automatically cleanup the underlying SCSI device on ufshcd destruction, without requiring explicit calls to ufshcd_dealloc_host(). This way:  * the crypto profile and all other ufs_hba-owned resources are destroyed before SCSI (as they've been registered after) * a memleak is plugged in tc-dwc-g210-pci.c remove() as a side-effect * EXPORT_SYMBOL_GPL(ufshcd_dealloc_host) can be removed fully as it's not needed anymore * no future drivers using ufshcd_alloc_host() could ever forget adding the cleanup

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21738?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21738" src="https://img.shields.io/badge/CVE--2025--21738-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ata: libata-sff: Ensure that we cannot write outside the allocated buffer  reveliofuzzing reported that a SCSI_IOCTL_SEND_COMMAND ioctl with out_len set to 0xd42, SCSI command set to ATA_16 PASS-THROUGH, ATA command set to ATA_NOP, and protocol set to ATA_PROT_PIO, can cause ata_pio_sector() to write outside the allocated buffer, overwriting random memory.  While a ATA device is supposed to abort a ATA_NOP command, there does seem to be a bug either in libata-sff or QEMU, where either this status is not set, or the status is cleared before read by ata_sff_hsm_move(). Anyway, that is most likely a separate bug.  Looking at __atapi_pio_bytes(), it already has a safety check to ensure that __atapi_pio_bytes() cannot write outside the allocated buffer.  Add a similar check to ata_pio_sector(), such that also ata_pio_sector() cannot write outside the allocated buffer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21734?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21734" src="https://img.shields.io/badge/CVE--2025--21734-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  misc: fastrpc: Fix copy buffer page size  For non-registered buffer, fastrpc driver copies the buffer and pass it to the remote subsystem. There is a problem with current implementation of page size calculation which is not considering the offset in the calculation. This might lead to passing of improper and out-of-bounds page size which could result in memory issue. Calculate page start and page end using the offset adjusted address instead of absolute address.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21733?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21733" src="https://img.shields.io/badge/CVE--2025--21733-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tracing/osnoise: Fix resetting of tracepoints  If a timerlat tracer is started with the osnoise option OSNOISE_WORKLOAD disabled, but then that option is enabled and timerlat is removed, the tracepoints that were enabled on timerlat registration do not get disabled. If the option is disabled again and timelat is started, then it triggers a warning in the tracepoint code due to registering the tracepoint again without ever disabling it.  Do not use the same user space defined options to know to disable the tracepoints when timerlat is removed. Instead, set a global flag when it is enabled and use that flag to know to disable the events.  ~# echo NO_OSNOISE_WORKLOAD > /sys/kernel/tracing/osnoise/options ~# echo timerlat > /sys/kernel/tracing/current_tracer ~# echo OSNOISE_WORKLOAD > /sys/kernel/tracing/osnoise/options ~# echo nop > /sys/kernel/tracing/current_tracer ~# echo NO_OSNOISE_WORKLOAD > /sys/kernel/tracing/osnoise/options ~# echo timerlat > /sys/kernel/tracing/current_tracer  Triggers:  ------------[ cut here ]------------ WARNING: CPU: 6 PID: 1337 at kernel/tracepoint.c:294 tracepoint_add_func+0x3b6/0x3f0 Modules linked in: CPU: 6 UID: 0 PID: 1337 Comm: rtla Not tainted 6.13.0-rc4-test-00018-ga867c441128e-dirty #73 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2 04/01/2014 RIP: 0010:tracepoint_add_func+0x3b6/0x3f0 Code: 48 8b 53 28 48 8b 73 20 4c 89 04 24 e8 23 59 11 00 4c 8b 04 24 e9 36 fe ff ff 0f 0b b8 ea ff ff ff 45 84 e4 0f 84 68 fe ff ff <0f> 0b e9 61 fe ff ff 48 8b 7b 18 48 85 ff 0f 84 4f ff ff ff 49 8b RSP: 0018:ffffb9b003a87ca0 EFLAGS: 00010202 RAX: 00000000ffffffef RBX: ffffffff92f30860 RCX: 0000000000000000 RDX: 0000000000000000 RSI: ffff9bf59e91ccd0 RDI: ffffffff913b6410 RBP: 000000000000000a R08: 00000000000005c7 R09: 0000000000000002 R10: ffffb9b003a87ce0 R11: 0000000000000002 R12: 0000000000000001 R13: ffffb9b003a87ce0 R14: ffffffffffffffef R15: 0000000000000008 FS:  00007fce81209240(0000) GS:ffff9bf6fdd00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000055e99b728000 CR3: 00000001277c0002 CR4: 0000000000172ef0 Call Trace: <TASK> ? __warn.cold+0xb7/0x14d ? tracepoint_add_func+0x3b6/0x3f0 ? report_bug+0xea/0x170 ? handle_bug+0x58/0x90 ? exc_invalid_op+0x17/0x70 ? asm_exc_invalid_op+0x1a/0x20 ? __pfx_trace_sched_migrate_callback+0x10/0x10 ? tracepoint_add_func+0x3b6/0x3f0 ? __pfx_trace_sched_migrate_callback+0x10/0x10 ? __pfx_trace_sched_migrate_callback+0x10/0x10 tracepoint_probe_register+0x78/0xb0 ? __pfx_trace_sched_migrate_callback+0x10/0x10 osnoise_workload_start+0x2b5/0x370 timerlat_tracer_init+0x76/0x1b0 tracing_set_tracer+0x244/0x400 tracing_set_trace_write+0xa0/0xe0 vfs_write+0xfc/0x570 ? do_sys_openat2+0x9c/0xe0 ksys_write+0x72/0xf0 do_syscall_64+0x79/0x1c0 entry_SYSCALL_64_after_hwframe+0x76/0x7e

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21732?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21732" src="https://img.shields.io/badge/CVE--2025--21732-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/mlx5: Fix a race for an ODP MR which leads to CQE with error  This patch addresses a race condition for an ODP MR that can result in a CQE with an error on the UMR QP.  During the __mlx5_ib_dereg_mr() flow, the following sequence of calls occurs:  mlx5_revoke_mr() mlx5r_umr_revoke_mr() mlx5r_umr_post_send_wait()  At this point, the lkey is freed from the hardware's perspective.  However, concurrently, mlx5_ib_invalidate_range() might be triggered by another task attempting to invalidate a range for the same freed lkey.  This task will: - Acquire the umem_odp->umem_mutex lock. - Call mlx5r_umr_update_xlt() on the UMR QP. - Since the lkey has already been freed, this can lead to a CQE error, causing the UMR QP to enter an error state [1].  To resolve this race condition, the umem_odp->umem_mutex lock is now also acquired as part of the mlx5_revoke_mr() scope.  Upon successful revoke, we set umem_odp->private which points to that MR to NULL, preventing any further invalidation attempts on its lkey.  [1] From dmesg:  infiniband rocep8s0f0: dump_cqe:277:(pid 0): WC error: 6, Message: memory bind operation error cqe_dump: 00000000: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 cqe_dump: 00000010: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 cqe_dump: 00000020: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 cqe_dump: 00000030: 00 00 00 00 08 00 78 06 25 00 11 b9 00 0e dd d2  WARNING: CPU: 15 PID: 1506 at drivers/infiniband/hw/mlx5/umr.c:394 mlx5r_umr_post_send_wait+0x15a/0x2b0 [mlx5_ib] Modules linked in: ip6table_mangle ip6table_natip6table_filter ip6_tables iptable_mangle xt_conntrack xt_MASQUERADE nf_conntrack_netlink nfnetlink xt_addrtype iptable_nat nf_nat br_netfilter rpcsec_gss_krb5 auth_rpcgss oid_registry overlay rpcrdma rdma_ucm ib_iser libiscsi scsi_transport_iscsi rdma_cm iw_cm ib_umad ib_ipoib ib_cm mlx5_ib ib_uverbs ib_core fuse mlx5_core CPU: 15 UID: 0 PID: 1506 Comm: ibv_rc_pingpong Not tainted 6.12.0-rc7+ #1626 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 RIP: 0010:mlx5r_umr_post_send_wait+0x15a/0x2b0 [mlx5_ib] [..] Call Trace: <TASK> mlx5r_umr_update_xlt+0x23c/0x3e0 [mlx5_ib] mlx5_ib_invalidate_range+0x2e1/0x330 [mlx5_ib] __mmu_notifier_invalidate_range_start+0x1e1/0x240 zap_page_range_single+0xf1/0x1a0 madvise_vma_behavior+0x677/0x6e0 do_madvise+0x1a2/0x4b0 __x64_sys_madvise+0x25/0x30 do_syscall_64+0x6b/0x140 entry_SYSCALL_64_after_hwframe+0x76/0x7e

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21731?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21731" src="https://img.shields.io/badge/CVE--2025--21731-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nbd: don't allow reconnect after disconnect  Following process can cause nbd_config UAF:  1) grab nbd_config temporarily;  2) nbd_genl_disconnect() flush all recv_work() and release the initial reference:  nbd_genl_disconnect nbd_disconnect_and_put nbd_disconnect flush_workqueue(nbd->recv_workq) if (test_and_clear_bit(NBD_RT_HAS_CONFIG_REF, ...)) nbd_config_put -> due to step 1), reference is still not zero  3) nbd_genl_reconfigure() queue recv_work() again;  nbd_genl_reconfigure config = nbd_get_config_unlocked(nbd) if (!config) -> succeed if (!test_bit(NBD_RT_BOUND, ...)) -> succeed nbd_reconnect_socket queue_work(nbd->recv_workq, &args->work)  4) step 1) release the reference;  5) Finially, recv_work() will trigger UAF:  recv_work nbd_config_put(nbd) -> nbd_config is freed atomic_dec(&config->recv_threads) -> UAF  Fix the problem by clearing NBD_RT_BOUND in nbd_genl_disconnect(), so that nbd_genl_reconfigure() will fail.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21730?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21730" src="https://img.shields.io/badge/CVE--2025--21730-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: rtw89: avoid to init mgnt_entry list twice when WoWLAN failed  If WoWLAN failed in resume flow, the rtw89_ops_add_interface() triggered without removing the interface first. Then the mgnt_entry list init again, causing the list_empty() check in rtw89_chanctx_ops_assign_vif() useless, and list_add_tail() again. Therefore, we have added a check to prevent double adding of the list.  rtw89_8852ce 0000:01:00.0: failed to check wow status disabled rtw89_8852ce 0000:01:00.0: wow: failed to check disable fw ready rtw89_8852ce 0000:01:00.0: wow: failed to swap to normal fw rtw89_8852ce 0000:01:00.0: failed to disable wow rtw89_8852ce 0000:01:00.0: failed to resume for wow -110 rtw89_8852ce 0000:01:00.0: MAC has already powered on i2c_hid_acpi i2c-ILTK0001:00: PM: acpi_subsys_resume+0x0/0x60 returned 0 after 284705 usecs list_add corruption. prev->next should be next (ffff9d9719d82228), but was ffff9d9719f96030. (prev=ffff9d9719f96030). ------------[ cut here ]------------ kernel BUG at lib/list_debug.c:34! invalid opcode: 0000 [#1] PREEMPT SMP NOPTI CPU: 2 PID: 6918 Comm: kworker/u8:19 Tainted: G     U     O Hardware name: Google Anraggar/Anraggar, BIOS Google_Anraggar.15217.514.0 03/25/2024 Workqueue: events_unbound async_run_entry_fn RIP: 0010:__list_add_valid_or_report+0x9f/0xb0 Code: e8 56 89 ff ff 0f 0b 48 c7 c7 3e fc e0 96 48 89 c6 e8 45 89 ff ... RSP: 0018:ffffa51b42bbbaf0 EFLAGS: 00010246 RAX: 0000000000000075 RBX: ffff9d9719d82ab0 RCX: 13acb86e047a4400 RDX: 3fffffffffffffff RSI: 0000000000000000 RDI: 00000000ffffdfff RBP: ffffa51b42bbbb28 R08: ffffffff9768e250 R09: 0000000000001fff R10: ffffffff9765e250 R11: 0000000000005ffd R12: ffff9d9719f95c40 R13: ffff9d9719f95be8 R14: ffff9d97081bfd78 R15: ffff9d9719d82060 FS:  0000000000000000(0000) GS:ffff9d9a6fb00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007e7d029a4060 CR3: 0000000345e38000 CR4: 0000000000750ee0 PKRU: 55555554 Call Trace: <TASK> ? __die_body+0x68/0xb0 ? die+0xaa/0xd0 ? do_trap+0x9f/0x170 ? __list_add_valid_or_report+0x9f/0xb0 ? __list_add_valid_or_report+0x9f/0xb0 ? handle_invalid_op+0x69/0x90 ? __list_add_valid_or_report+0x9f/0xb0 ? exc_invalid_op+0x3c/0x50 ? asm_exc_invalid_op+0x16/0x20 ? __list_add_valid_or_report+0x9f/0xb0 rtw89_chanctx_ops_assign_vif+0x1f9/0x210 [rtw89_core cbb375c44bf28564ce479002bff66617a25d9ac1] ? __mutex_unlock_slowpath+0xa0/0xf0 rtw89_ops_assign_vif_chanctx+0x4b/0x90 [rtw89_core cbb375c44bf28564ce479002bff66617a25d9ac1] drv_assign_vif_chanctx+0xa7/0x1f0 [mac80211 6efaad16237edaaea0868b132d4f93ecf918a8b6] ieee80211_reconfig+0x9cb/0x17b0 [mac80211 6efaad16237edaaea0868b132d4f93ecf918a8b6] ? __pfx_wiphy_resume+0x10/0x10 [cfg80211 572d03acaaa933fe38251be7fce3b3675284b8ed] ? dev_printk_emit+0x51/0x70 ? _dev_info+0x6e/0x90 wiphy_resume+0x89/0x180 [cfg80211 572d03acaaa933fe38251be7fce3b3675284b8ed] ? __pfx_wiphy_resume+0x10/0x10 [cfg80211 572d03acaaa933fe38251be7fce3b3675284b8ed] dpm_run_callback+0x37/0x1e0 device_resume+0x26d/0x4b0 ? __pfx_dpm_watchdog_handler+0x10/0x10 async_resume+0x1d/0x30 async_run_entry_fn+0x29/0xd0 worker_thread+0x397/0x970 kthread+0xed/0x110 ? __pfx_worker_thread+0x10/0x10 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x38/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21729?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21729" src="https://img.shields.io/badge/CVE--2025--21729-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: rtw89: fix race between cancel_hw_scan and hw_scan completion  The rtwdev->scanning flag isn't protected by mutex originally, so cancel_hw_scan can pass the condition, but suddenly hw_scan completion unset the flag and calls ieee80211_scan_completed() that will free local->hw_scan_req. Then, cancel_hw_scan raises null-ptr-deref and use-after-free. Fix it by moving the check condition to where protected by mutex.  KASAN: null-ptr-deref in range [0x0000000000000088-0x000000000000008f] CPU: 2 PID: 6922 Comm: kworker/2:2 Tainted: G           OE Hardware name: LENOVO 2356AD1/2356AD1, BIOS G7ETB6WW (2.76 ) 09/10/2019 Workqueue: events cfg80211_conn_work [cfg80211] RIP: 0010:rtw89_fw_h2c_scan_offload_be+0xc33/0x13c3 [rtw89_core] Code: 00 45 89 6c 24 1c 0f 85 23 01 00 00 48 8b 85 20 ff ff ff 48 8d RSP: 0018:ffff88811fd9f068 EFLAGS: 00010206 RAX: dffffc0000000000 RBX: ffff88811fd9f258 RCX: 0000000000000001 RDX: 0000000000000011 RSI: 0000000000000001 RDI: 0000000000000089 RBP: ffff88811fd9f170 R08: 0000000000000000 R09: 0000000000000000 R10: ffff88811fd9f108 R11: 0000000000000000 R12: ffff88810e47f960 R13: 0000000000000000 R14: 000000000000ffff R15: 0000000000000000 FS:  0000000000000000(0000) GS:ffff8881d6f00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007531dfca55b0 CR3: 00000001be296004 CR4: 00000000001706e0 Call Trace: <TASK> ? show_regs+0x61/0x73 ? __die_body+0x20/0x73 ? die_addr+0x4f/0x7b ? exc_general_protection+0x191/0x1db ? asm_exc_general_protection+0x27/0x30 ? rtw89_fw_h2c_scan_offload_be+0xc33/0x13c3 [rtw89_core] ? rtw89_fw_h2c_scan_offload_be+0x458/0x13c3 [rtw89_core] ? __pfx_rtw89_fw_h2c_scan_offload_be+0x10/0x10 [rtw89_core] ? do_raw_spin_lock+0x75/0xdb ? __pfx_do_raw_spin_lock+0x10/0x10 rtw89_hw_scan_offload+0xb5e/0xbf7 [rtw89_core] ? _raw_spin_unlock+0xe/0x24 ? __mutex_lock.constprop.0+0x40c/0x471 ? __pfx_rtw89_hw_scan_offload+0x10/0x10 [rtw89_core] ? __mutex_lock_slowpath+0x13/0x1f ? mutex_lock+0xa2/0xdc ? __pfx_mutex_lock+0x10/0x10 rtw89_hw_scan_abort+0x58/0xb7 [rtw89_core] rtw89_ops_cancel_hw_scan+0x120/0x13b [rtw89_core] ieee80211_scan_cancel+0x468/0x4d0 [mac80211] ieee80211_prep_connection+0x858/0x899 [mac80211] ieee80211_mgd_auth+0xbea/0xdde [mac80211] ? __pfx_ieee80211_mgd_auth+0x10/0x10 [mac80211] ? cfg80211_find_elem+0x15/0x29 [cfg80211] ? is_bss+0x1b7/0x1d7 [cfg80211] ieee80211_auth+0x18/0x27 [mac80211] cfg80211_mlme_auth+0x3bb/0x3e7 [cfg80211] cfg80211_conn_do_work+0x410/0xb81 [cfg80211] ? __pfx_cfg80211_conn_do_work+0x10/0x10 [cfg80211] ? __kasan_check_read+0x11/0x1f ? psi_group_change+0x8bc/0x944 ? __kasan_check_write+0x14/0x22 ? mutex_lock+0x8e/0xdc ? __pfx_mutex_lock+0x10/0x10 ? __pfx___radix_tree_lookup+0x10/0x10 cfg80211_conn_work+0x245/0x34d [cfg80211] ? __pfx_cfg80211_conn_work+0x10/0x10 [cfg80211] ? update_cfs_rq_load_avg+0x3bc/0x3d7 ? sched_clock_noinstr+0x9/0x1a ? sched_clock+0x10/0x24 ? sched_clock_cpu+0x7e/0x42e ? newidle_balance+0x796/0x937 ? __pfx_sched_clock_cpu+0x10/0x10 ? __pfx_newidle_balance+0x10/0x10 ? __kasan_check_read+0x11/0x1f ? psi_group_change+0x8bc/0x944 ? _raw_spin_unlock+0xe/0x24 ? raw_spin_rq_unlock+0x47/0x54 ? raw_spin_rq_unlock_irq+0x9/0x1f ? finish_task_switch.isra.0+0x347/0x586 ? __schedule+0x27bf/0x2892 ? mutex_unlock+0x80/0xd0 ? do_raw_spin_lock+0x75/0xdb ? __pfx___schedule+0x10/0x10 process_scheduled_works+0x58c/0x821 worker_thread+0x4c7/0x586 ? __kasan_check_read+0x11/0x1f kthread+0x285/0x294 ? __pfx_worker_thread+0x10/0x10 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x29/0x6f ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21728?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21728" src="https://img.shields.io/badge/CVE--2025--21728-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Send signals asynchronously if !preemptible  BPF programs can execute in all kinds of contexts and when a program running in a non-preemptible context uses the bpf_send_signal() kfunc, it will cause issues because this kfunc can sleep. Change `irqs_disabled()` to `!preemptible()`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21727?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21727" src="https://img.shields.io/badge/CVE--2025--21727-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  padata: fix UAF in padata_reorder  A bug was found when run ltp test:  BUG: KASAN: slab-use-after-free in padata_find_next+0x29/0x1a0 Read of size 4 at addr ffff88bbfe003524 by task kworker/u113:2/3039206  CPU: 0 PID: 3039206 Comm: kworker/u113:2 Kdump: loaded Not tainted 6.6.0+ Workqueue: pdecrypt_parallel padata_parallel_worker Call Trace: <TASK> dump_stack_lvl+0x32/0x50 print_address_description.constprop.0+0x6b/0x3d0 print_report+0xdd/0x2c0 kasan_report+0xa5/0xd0 padata_find_next+0x29/0x1a0 padata_reorder+0x131/0x220 padata_parallel_worker+0x3d/0xc0 process_one_work+0x2ec/0x5a0  If 'mdelay(10)' is added before calling 'padata_find_next' in the 'padata_reorder' function, this issue could be reproduced easily with ltp test (pcrypt_aead01).  This can be explained as bellow:  pcrypt_aead_encrypt ... padata_do_parallel refcount_inc(&pd->refcnt); // add refcnt ... padata_do_serial padata_reorder // pd while (1) { padata_find_next(pd, true); // using pd queue_work_on ... padata_serial_worker				crypto_del_alg padata_put_pd_cnt // sub refcnt padata_free_shell padata_put_pd(ps->pd); // pd is freed // loop again, but pd is freed // call padata_find_next, UAF }  In the padata_reorder function, when it loops in 'while', if the alg is deleted, the refcnt may be decreased to 0 before entering 'padata_find_next', which leads to UAF.  As mentioned in [1], do_serial is supposed to be called with BHs disabled and always happen under RCU protection, to address this issue, add synchronize_rcu() in 'padata_free_shell' wait for all _do_serial calls to finish.  [1] https://lore.kernel.org/all/20221028160401.cccypv4euxikusiq@parnassus.localdomain/ [2] https://lore.kernel.org/linux-kernel/jfjz5d7zwbytztackem7ibzalm5lnxldi2eofeiczqmqs2m7o6@fq426cwnjtkm/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21726?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21726" src="https://img.shields.io/badge/CVE--2025--21726-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  padata: avoid UAF for reorder_work  Although the previous patch can avoid ps and ps UAF for _do_serial, it can not avoid potential UAF issue for reorder_work. This issue can happen just as below:  crypto_request			crypto_request		crypto_del_alg padata_do_serial ... padata_reorder // processes all remaining // requests then breaks while (1) { if (!padata) break; ... }  padata_do_serial // new request added list_add // sees the new request queue_work(reorder_work) padata_reorder queue_work_on(squeue->work) ...  <kworker context> padata_serial_worker // completes new request, // no more outstanding // requests  crypto_del_alg // free pd  <kworker context> invoke_padata_reorder // UAF of pd  To avoid UAF for 'reorder_work', get 'pd' ref before put 'reorder_work' into the 'serial_wq' and put 'pd' ref until the 'serial_wq' finish.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21725?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21725" src="https://img.shields.io/badge/CVE--2025--21725-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix oops due to unset link speed  It isn't guaranteed that NETWORK_INTERFACE_INFO::LinkSpeed will always be set by the server, so the client must handle any values and then prevent oopses like below from happening:  Oops: divide error: 0000 [#1] PREEMPT SMP KASAN NOPTI CPU: 0 UID: 0 PID: 1323 Comm: cat Not tainted 6.13.0-rc7 #2 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-3.fc41 04/01/2014 RIP: 0010:cifs_debug_data_proc_show+0xa45/0x1460 [cifs] Code: 00 00 48 89 df e8 3b cd 1b c1 41 f6 44 24 2c 04 0f 84 50 01 00 00 48 89 ef e8 e7 d0 1b c1 49 8b 44 24 18 31 d2 49 8d 7c 24 28 <48> f7 74 24 18 48 89 c3 e8 6e cf 1b c1 41 8b 6c 24 28 49 8d 7c 24 RSP: 0018:ffffc90001817be0 EFLAGS: 00010246 RAX: 0000000000000000 RBX: ffff88811230022c RCX: ffffffffc041bd99 RDX: 0000000000000000 RSI: 0000000000000567 RDI: ffff888112300228 RBP: ffff888112300218 R08: fffff52000302f5f R09: ffffed1022fa58ac R10: ffff888117d2c566 R11: 00000000fffffffe R12: ffff888112300200 R13: 000000012a15343f R14: 0000000000000001 R15: ffff888113f2db58 FS: 00007fe27119e740(0000) GS:ffff888148600000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fe2633c5000 CR3: 0000000124da0000 CR4: 0000000000750ef0 PKRU: 55555554 Call Trace: <TASK> ? __die_body.cold+0x19/0x27 ? die+0x2e/0x50 ? do_trap+0x159/0x1b0 ? cifs_debug_data_proc_show+0xa45/0x1460 [cifs] ? do_error_trap+0x90/0x130 ? cifs_debug_data_proc_show+0xa45/0x1460 [cifs] ? exc_divide_error+0x39/0x50 ? cifs_debug_data_proc_show+0xa45/0x1460 [cifs] ? asm_exc_divide_error+0x1a/0x20 ? cifs_debug_data_proc_show+0xa39/0x1460 [cifs] ? cifs_debug_data_proc_show+0xa45/0x1460 [cifs] ? seq_read_iter+0x42e/0x790 seq_read_iter+0x19a/0x790 proc_reg_read_iter+0xbe/0x110 ? __pfx_proc_reg_read_iter+0x10/0x10 vfs_read+0x469/0x570 ? do_user_addr_fault+0x398/0x760 ? __pfx_vfs_read+0x10/0x10 ? find_held_lock+0x8a/0xa0 ? __pfx_lock_release+0x10/0x10 ksys_read+0xd3/0x170 ? __pfx_ksys_read+0x10/0x10 ? __rcu_read_unlock+0x50/0x270 ? mark_held_locks+0x1a/0x90 do_syscall_64+0xbb/0x1d0 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7fe271288911 Code: 00 48 8b 15 01 25 10 00 f7 d8 64 89 02 b8 ff ff ff ff eb bd e8 20 ad 01 00 f3 0f 1e fa 80 3d b5 a7 10 00 00 74 13 31 c0 0f 05 <48> 3d 00 f0 ff ff 77 4f c3 66 0f 1f 44 00 00 55 48 89 e5 48 83 ec RSP: 002b:00007ffe87c079d8 EFLAGS: 00000246 ORIG_RAX: 0000000000000000 RAX: ffffffffffffffda RBX: 0000000000040000 RCX: 00007fe271288911 RDX: 0000000000040000 RSI: 00007fe2633c6000 RDI: 0000000000000003 RBP: 00007ffe87c07a00 R08: 0000000000000000 R09: 00007fe2713e6380 R10: 0000000000000022 R11: 0000000000000246 R12: 0000000000040000 R13: 00007fe2633c6000 R14: 0000000000000003 R15: 0000000000000000 </TASK>  Fix this by setting cifs_server_iface::speed to a sane value (1Gbps) by default when link speed is unset.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21724?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21724" src="https://img.shields.io/badge/CVE--2025--21724-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iommufd/iova_bitmap: Fix shift-out-of-bounds in iova_bitmap_offset_to_index()  Resolve a UBSAN shift-out-of-bounds issue in iova_bitmap_offset_to_index() where shifting the constant "1" (of type int) by bitmap->mapped.pgshift (an unsigned long value) could result in undefined behavior.  The constant "1" defaults to a 32-bit "int", and when "pgshift" exceeds 31 (e.g., pgshift = 63) the shift operation overflows, as the result cannot be represented in a 32-bit type.  To resolve this, the constant is updated to "1UL", promoting it to an unsigned long type to match the operand's type.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21722?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21722" src="https://img.shields.io/badge/CVE--2025--21722-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nilfs2: do not force clear folio if buffer is referenced  Patch series "nilfs2: protect busy buffer heads from being force-cleared".  This series fixes the buffer head state inconsistency issues reported by syzbot that occurs when the filesystem is corrupted and falls back to read-only, and the associated buffer head use-after-free issue.   This patch (of 2):  Syzbot has reported that after nilfs2 detects filesystem corruption and falls back to read-only, inconsistencies in the buffer state may occur.  One of the inconsistencies is that when nilfs2 calls mark_buffer_dirty() to set a data or metadata buffer as dirty, but it detects that the buffer is not in the uptodate state:  WARNING: CPU: 0 PID: 6049 at fs/buffer.c:1177 mark_buffer_dirty+0x2e5/0x520 fs/buffer.c:1177 ... Call Trace: <TASK> nilfs_palloc_commit_alloc_entry+0x4b/0x160 fs/nilfs2/alloc.c:598 nilfs_ifile_create_inode+0x1dd/0x3a0 fs/nilfs2/ifile.c:73 nilfs_new_inode+0x254/0x830 fs/nilfs2/inode.c:344 nilfs_mkdir+0x10d/0x340 fs/nilfs2/namei.c:218 vfs_mkdir+0x2f9/0x4f0 fs/namei.c:4257 do_mkdirat+0x264/0x3a0 fs/namei.c:4280 __do_sys_mkdirat fs/namei.c:4295 [inline] __se_sys_mkdirat fs/namei.c:4293 [inline] __x64_sys_mkdirat+0x87/0xa0 fs/namei.c:4293 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  The other is when nilfs_btree_propagate(), which propagates the dirty state to the ancestor nodes of a b-tree that point to a dirty buffer, detects that the origin buffer is not dirty, even though it should be:  WARNING: CPU: 0 PID: 5245 at fs/nilfs2/btree.c:2089 nilfs_btree_propagate+0xc79/0xdf0 fs/nilfs2/btree.c:2089 ... Call Trace: <TASK> nilfs_bmap_propagate+0x75/0x120 fs/nilfs2/bmap.c:345 nilfs_collect_file_data+0x4d/0xd0 fs/nilfs2/segment.c:587 nilfs_segctor_apply_buffers+0x184/0x340 fs/nilfs2/segment.c:1006 nilfs_segctor_scan_file+0x28c/0xa50 fs/nilfs2/segment.c:1045 nilfs_segctor_collect_blocks fs/nilfs2/segment.c:1216 [inline] nilfs_segctor_collect fs/nilfs2/segment.c:1540 [inline] nilfs_segctor_do_construct+0x1c28/0x6b90 fs/nilfs2/segment.c:2115 nilfs_segctor_construct+0x181/0x6b0 fs/nilfs2/segment.c:2479 nilfs_segctor_thread_construct fs/nilfs2/segment.c:2587 [inline] nilfs_segctor_thread+0x69e/0xe80 fs/nilfs2/segment.c:2701 kthread+0x2f0/0x390 kernel/kthread.c:389 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK>  Both of these issues are caused by the callbacks that handle the page/folio write requests, forcibly clear various states, including the working state of the buffers they hold, at unexpected times when they detect read-only fallback.  Fix these issues by checking if the buffer is referenced before clearing the page/folio state, and skipping the clear if it is.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21721?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21721" src="https://img.shields.io/badge/CVE--2025--21721-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nilfs2: handle errors that nilfs_prepare_chunk() may return  Patch series "nilfs2: fix issues with rename operations".  This series fixes BUG_ON check failures reported by syzbot around rename operations, and a minor behavioral issue where the mtime of a child directory changes when it is renamed instead of moved.   This patch (of 2):  The directory manipulation routines nilfs_set_link() and nilfs_delete_entry() rewrite the directory entry in the folio/page previously read by nilfs_find_entry(), so error handling is omitted on the assumption that nilfs_prepare_chunk(), which prepares the buffer for rewriting, will always succeed for these.  And if an error is returned, it triggers the legacy BUG_ON() checks in each routine.  This assumption is wrong, as proven by syzbot: the buffer layer called by nilfs_prepare_chunk() may call nilfs_get_block() if necessary, which may fail due to metadata corruption or other reasons.  This has been there all along, but improved sanity checks and error handling may have made it more reproducible in fuzzing tests.  Fix this issue by adding missing error paths in nilfs_set_link(), nilfs_delete_entry(), and their caller nilfs_rename().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21720?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21720" src="https://img.shields.io/badge/CVE--2025--21720-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  xfrm: delete intermediate secpath entry in packet offload mode  Packets handled by hardware have added secpath as a way to inform XFRM core code that this path was already handled. That secpath is not needed at all after policy is checked and it is removed later in the stack.  However, in the case of IP forwarding is enabled (/proc/sys/net/ipv4/ip_forward), that secpath is not removed and packets which already were handled are reentered to the driver TX path with xfrm_offload set.  The following kernel panic is observed in mlx5 in such case:  mlx5_core 0000:04:00.0 enp4s0f0np0: Link up mlx5_core 0000:04:00.1 enp4s0f1np1: Link up Initializing XFRM netlink socket IPsec XFRM device driver BUG: kernel NULL pointer dereference, address: 0000000000000000 #PF: supervisor instruction fetch in kernel mode #PF: error_code(0x0010) - not-present page PGD 0 P4D 0 Oops: Oops: 0010 [#1] PREEMPT SMP CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.13.0-rc1-alex #3 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.13.0-1ubuntu1.1 04/01/2014 RIP: 0010:0x0 Code: Unable to access opcode bytes at 0xffffffffffffffd6. RSP: 0018:ffffb87380003800 EFLAGS: 00010206 RAX: ffff8df004e02600 RBX: ffffb873800038d8 RCX: 00000000ffff98cf RDX: ffff8df00733e108 RSI: ffff8df00521fb80 RDI: ffff8df001661f00 RBP: ffffb87380003850 R08: ffff8df013980000 R09: 0000000000000010 R10: 0000000000000002 R11: 0000000000000002 R12: ffff8df001661f00 R13: ffff8df00521fb80 R14: ffff8df00733e108 R15: ffff8df011faf04e FS:  0000000000000000(0000) GS:ffff8df46b800000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: ffffffffffffffd6 CR3: 0000000106384000 CR4: 0000000000350ef0 Call Trace: <IRQ> ? show_regs+0x63/0x70 ? __die_body+0x20/0x60 ? __die+0x2b/0x40 ? page_fault_oops+0x15c/0x550 ? do_user_addr_fault+0x3ed/0x870 ? exc_page_fault+0x7f/0x190 ? asm_exc_page_fault+0x27/0x30 mlx5e_ipsec_handle_tx_skb+0xe7/0x2f0 [mlx5_core] mlx5e_xmit+0x58e/0x1980 [mlx5_core] ? __fib_lookup+0x6a/0xb0 dev_hard_start_xmit+0x82/0x1d0 sch_direct_xmit+0xfe/0x390 __dev_queue_xmit+0x6d8/0xee0 ? __fib_lookup+0x6a/0xb0 ? internal_add_timer+0x48/0x70 ? mod_timer+0xe2/0x2b0 neigh_resolve_output+0x115/0x1b0 __neigh_update+0x26a/0xc50 neigh_update+0x14/0x20 arp_process+0x2cb/0x8e0 ? __napi_build_skb+0x5e/0x70 arp_rcv+0x11e/0x1c0 ? dev_gro_receive+0x574/0x820 __netif_receive_skb_list_core+0x1cf/0x1f0 netif_receive_skb_list_internal+0x183/0x2a0 napi_complete_done+0x76/0x1c0 mlx5e_napi_poll+0x234/0x7a0 [mlx5_core] __napi_poll+0x2d/0x1f0 net_rx_action+0x1a6/0x370 ? atomic_notifier_call_chain+0x3b/0x50 ? irq_int_handler+0x15/0x20 [mlx5_core] handle_softirqs+0xb9/0x2f0 ? handle_irq_event+0x44/0x60 irq_exit_rcu+0xdb/0x100 common_interrupt+0x98/0xc0 </IRQ> <TASK> asm_common_interrupt+0x27/0x40 RIP: 0010:pv_native_safe_halt+0xb/0x10 Code: 09 c3 66 66 2e 0f 1f 84 00 00 00 00 00 66 90 0f 22 0f 1f 84 00 00 00 00 00 90 eb 07 0f 00 2d 7f e9 36 00 fb 40 00 83 ff 07 77 21 89 ff ff 24 fd 88 3d a1 bd 0f 21 f8 RSP: 0018:ffffffffbe603de8 EFLAGS: 00000202 RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000f92f46680 RDX: 0000000000000037 RSI: 00000000ffffffff RDI: 00000000000518d4 RBP: ffffffffbe603df0 R08: 000000cd42e4dffb R09: ffffffffbe603d70 R10: 0000004d80d62680 R11: 0000000000000001 R12: ffffffffbe60bf40 R13: 0000000000000000 R14: 0000000000000000 R15: ffffffffbe60aff8 ? default_idle+0x9/0x20 arch_cpu_idle+0x9/0x10 default_idle_call+0x29/0xf0 do_idle+0x1f2/0x240 cpu_startup_entry+0x2c/0x30 rest_init+0xe7/0x100 start_kernel+0x76b/0xb90 x86_64_start_reservations+0x18/0x30 x86_64_start_kernel+0xc0/0x110 ? setup_ghcb+0xe/0x130 common_startup_64+0x13e/0x141 </TASK> Modules linked in: esp4_offload esp4 xfrm_interface xfrm6_tunnel tunnel4 tunnel6 xfrm_user xfrm_algo binf ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21719?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21719" src="https://img.shields.io/badge/CVE--2025--21719-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipmr: do not call mr_mfc_uses_dev() for unres entries  syzbot found that calling mr_mfc_uses_dev() for unres entries would crash [1], because c->mfc_un.res.minvif / c->mfc_un.res.maxvif alias to "struct sk_buff_head unresolved", which contain two pointers.  This code never worked, lets remove it.  [1] Unable to handle kernel paging request at virtual address ffff5fff2d536613 KASAN: maybe wild-memory-access in range [0xfffefff96a9b3098-0xfffefff96a9b309f] Modules linked in: CPU: 1 UID: 0 PID: 7321 Comm: syz.0.16 Not tainted 6.13.0-rc7-syzkaller-g1950a0af2d55 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 pstate: 80400005 (Nzcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : mr_mfc_uses_dev net/ipv4/ipmr_base.c:290 [inline] pc : mr_table_dump+0x5a4/0x8b0 net/ipv4/ipmr_base.c:334 lr : mr_mfc_uses_dev net/ipv4/ipmr_base.c:289 [inline] lr : mr_table_dump+0x694/0x8b0 net/ipv4/ipmr_base.c:334 Call trace: mr_mfc_uses_dev net/ipv4/ipmr_base.c:290 [inline] (P) mr_table_dump+0x5a4/0x8b0 net/ipv4/ipmr_base.c:334 (P) mr_rtm_dumproute+0x254/0x454 net/ipv4/ipmr_base.c:382 ipmr_rtm_dumproute+0x248/0x4b4 net/ipv4/ipmr.c:2648 rtnl_dump_all+0x2e4/0x4e8 net/core/rtnetlink.c:4327 rtnl_dumpit+0x98/0x1d0 net/core/rtnetlink.c:6791 netlink_dump+0x4f0/0xbc0 net/netlink/af_netlink.c:2317 netlink_recvmsg+0x56c/0xe64 net/netlink/af_netlink.c:1973 sock_recvmsg_nosec net/socket.c:1033 [inline] sock_recvmsg net/socket.c:1055 [inline] sock_read_iter+0x2d8/0x40c net/socket.c:1125 new_sync_read fs/read_write.c:484 [inline] vfs_read+0x740/0x970 fs/read_write.c:565 ksys_read+0x15c/0x26c fs/read_write.c:708

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21715?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21715" src="https://img.shields.io/badge/CVE--2025--21715-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: davicom: fix UAF in dm9000_drv_remove  dm is netdev private data and it cannot be used after free_netdev() call. Using dm after free_netdev() can cause UAF bug. Fix it by moving free_netdev() at the end of the function.  This is similar to the issue fixed in commit ad297cd2db89 ("net: qcom/emac: fix UAF in emac_remove").  This bug is detected by our static analysis tool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21714?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21714" src="https://img.shields.io/badge/CVE--2025--21714-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/mlx5: Fix implicit ODP use after free  Prevent double queueing of implicit ODP mr destroy work by using __xa_cmpxchg() to make sure this is the only time we are destroying this specific mr.  Without this change, we could try to invalidate this mr twice, which in turn could result in queuing a MR work destroy twice, and eventually the second work could execute after the MR was freed due to the first work, causing a user after free and trace below.  refcount_t: underflow; use-after-free. WARNING: CPU: 2 PID: 12178 at lib/refcount.c:28 refcount_warn_saturate+0x12b/0x130 Modules linked in: bonding ib_ipoib vfio_pci ip_gre geneve nf_tables ip6_gre gre ip6_tunnel tunnel6 ipip tunnel4 ib_umad rdma_ucm mlx5_vfio_pci vfio_pci_core vfio_iommu_type1 mlx5_ib vfio ib_uverbs mlx5_core iptable_raw openvswitch nsh rpcrdma ib_iser libiscsi scsi_transport_iscsi rdma_cm iw_cm ib_cm ib_core xt_conntrack xt_MASQUERADE nf_conntrack_netlink nfnetlink xt_addrtype iptable_nat nf_nat br_netfilter rpcsec_gss_krb5 auth_rpcgss oid_registry overlay zram zsmalloc fuse [last unloaded: ib_uverbs] CPU: 2 PID: 12178 Comm: kworker/u20:5 Not tainted 6.5.0-rc1_net_next_mlx5_58c644e #1 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 Workqueue: events_unbound free_implicit_child_mr_work [mlx5_ib] RIP: 0010:refcount_warn_saturate+0x12b/0x130 Code: 48 c7 c7 38 95 2a 82 c6 05 bc c6 fe 00 01 e8 0c 66 aa ff 0f 0b 5b c3 48 c7 c7 e0 94 2a 82 c6 05 a7 c6 fe 00 01 e8 f5 65 aa ff <0f> 0b 5b c3 90 8b 07 3d 00 00 00 c0 74 12 83 f8 01 74 13 8d 50 ff RSP: 0018:ffff8881008e3e40 EFLAGS: 00010286 RAX: 0000000000000000 RBX: 0000000000000000 RCX: 0000000000000027 RDX: ffff88852c91b5c8 RSI: 0000000000000001 RDI: ffff88852c91b5c0 RBP: ffff8881dacd4e00 R08: 00000000ffffffff R09: 0000000000000019 R10: 000000000000072e R11: 0000000063666572 R12: ffff88812bfd9e00 R13: ffff8881c792d200 R14: ffff88810011c005 R15: ffff8881002099c0 FS:  0000000000000000(0000) GS:ffff88852c900000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f5694b5e000 CR3: 00000001153f6003 CR4: 0000000000370ea0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> ? refcount_warn_saturate+0x12b/0x130 free_implicit_child_mr_work+0x180/0x1b0 [mlx5_ib] process_one_work+0x1cc/0x3c0 worker_thread+0x218/0x3c0 kthread+0xc6/0xf0 ret_from_fork+0x1f/0x30 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21712?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21712" src="https://img.shields.io/badge/CVE--2025--21712-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  md/md-bitmap: Synchronize bitmap_get_stats() with bitmap lifetime  After commit ec6bb299c7c3 ("md/md-bitmap: add 'sync_size' into struct md_bitmap_stats"), following panic is reported:  Oops: general protection fault, probably for non-canonical address RIP: 0010:bitmap_get_stats+0x2b/0xa0 Call Trace: <TASK> md_seq_show+0x2d2/0x5b0 seq_read_iter+0x2b9/0x470 seq_read+0x12f/0x180 proc_reg_read+0x57/0xb0 vfs_read+0xf6/0x380 ksys_read+0x6c/0xf0 do_syscall_64+0x82/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Root cause is that bitmap_get_stats() can be called at anytime if mddev is still there, even if bitmap is destroyed, or not fully initialized. Deferenceing bitmap in this case can crash the kernel. Meanwhile, the above commit start to deferencing bitmap->storage, make the problem easier to trigger.  Fix the problem by protecting bitmap_get_stats() with bitmap_info.mutex.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21710?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21710" src="https://img.shields.io/badge/CVE--2025--21710-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tcp: correct handling of extreme memory squeeze  Testing with iperf3 using the "pasta" protocol splicer has revealed a problem in the way tcp handles window advertising in extreme memory squeeze situations.  Under memory pressure, a socket endpoint may temporarily advertise a zero-sized window, but this is not stored as part of the socket data. The reasoning behind this is that it is considered a temporary setting which shouldn't influence any further calculations.  However, if we happen to stall at an unfortunate value of the current window size, the algorithm selecting a new value will consistently fail to advertise a non-zero window once we have freed up enough memory. This means that this side's notion of the current window size is different from the one last advertised to the peer, causing the latter to not send any data to resolve the sitution.  The problem occurs on the iperf3 server side, and the socket in question is a completely regular socket with the default settings for the fedora40 kernel. We do not use SO_PEEK or SO_RCVBUF on the socket.  The following excerpt of a logging session, with own comments added, shows more in detail what is happening:  //              tcp_v4_rcv(->) //                tcp_rcv_established(->) [5201<->39222]:     ==== Activating log @ net/ipv4/tcp_input.c/tcp_data_queue()/5257 ==== [5201<->39222]:     tcp_data_queue(->) [5201<->39222]:        DROPPING skb [265600160..265665640], reason: SKB_DROP_REASON_PROTO_MEM [rcv_nxt 265600160, rcv_wnd 262144, snt_ack 265469200, win_now 131184] [copied_seq 259909392->260034360 (124968), unread 5565800, qlen 85, ofoq 0] [OFO queue: gap: 65480, len: 0] [5201<->39222]:     tcp_data_queue(<-) [5201<->39222]:     __tcp_transmit_skb(->) [tp->rcv_wup: 265469200, tp->rcv_wnd: 262144, tp->rcv_nxt 265600160] [5201<->39222]:       tcp_select_window(->) [5201<->39222]:         (inet_csk(sk)->icsk_ack.pending & ICSK_ACK_NOMEM) ? --> TRUE [tp->rcv_wup: 265469200, tp->rcv_wnd: 262144, tp->rcv_nxt 265600160] returning 0 [5201<->39222]:       tcp_select_window(<-) [5201<->39222]:       ADVERTISING WIN 0, ACK_SEQ: 265600160 [5201<->39222]:     [__tcp_transmit_skb(<-) [5201<->39222]:   tcp_rcv_established(<-) [5201<->39222]: tcp_v4_rcv(<-)  // Receive queue is at 85 buffers and we are out of memory. // We drop the incoming buffer, although it is in sequence, and decide // to send an advertisement with a window of zero. // We don't update tp->rcv_wnd and tp->rcv_wup accordingly, which means // we unconditionally shrink the window.  [5201<->39222]: tcp_recvmsg_locked(->) [5201<->39222]:   __tcp_cleanup_rbuf(->) tp->rcv_wup: 265469200, tp->rcv_wnd: 262144, tp->rcv_nxt 265600160 [5201<->39222]:     [new_win = 0, win_now = 131184, 2 * win_now = 262368] [5201<->39222]:     [new_win >= (2 * win_now) ? --> time_to_ack = 0] [5201<->39222]:     NOT calling tcp_send_ack() [tp->rcv_wup: 265469200, tp->rcv_wnd: 262144, tp->rcv_nxt 265600160] [5201<->39222]:   __tcp_cleanup_rbuf(<-) [rcv_nxt 265600160, rcv_wnd 262144, snt_ack 265469200, win_now 131184] [copied_seq 260040464->260040464 (0), unread 5559696, qlen 85, ofoq 0] returning 6104 bytes [5201<->39222]: tcp_recvmsg_locked(<-)  // After each read, the algorithm for calculating the new receive // window in __tcp_cleanup_rbuf() finds it is too small to advertise // or to update tp->rcv_wnd. // Meanwhile, the peer thinks the window is zero, and will not send // any more data to trigger an update from the interrupt mode side.  [5201<->39222]: tcp_recvmsg_locked(->) [5201<->39222]:   __tcp_cleanup_rbuf(->) tp->rcv_wup: 265469200, tp->rcv_wnd: 262144, tp->rcv_nxt 265600160 [5201<->39222]:     [new_win = 262144, win_now = 131184, 2 * win_n ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21709?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21709" src="https://img.shields.io/badge/CVE--2025--21709-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  kernel: be more careful about dup_mmap() failures and uprobe registering  If a memory allocation fails during dup_mmap(), the maple tree can be left in an unsafe state for other iterators besides the exit path.  All the locks are dropped before the exit_mmap() call (in mm/mmap.c), but the incomplete mm_struct can be reached through (at least) the rmap finding the vmas which have a pointer back to the mm_struct.  Up to this point, there have been no issues with being able to find an mm_struct that was only partially initialised.  Syzbot was able to make the incomplete mm_struct fail with recent forking changes, so it has been proven unsafe to use the mm_struct that hasn't been initialised, as referenced in the link below.  Although 8ac662f5da19f ("fork: avoid inappropriate uprobe access to invalid mm") fixed the uprobe access, it does not completely remove the race.  This patch sets the MMF_OOM_SKIP to avoid the iteration of the vmas on the oom side (even though this is extremely unlikely to be selected as an oom victim in the race window), and sets MMF_UNSTABLE to avoid other potential users from using a partially initialised mm_struct.  When registering vmas for uprobe, skip the vmas in an mm that is marked unstable.  Modifying a vma in an unstable mm may cause issues if the mm isn't fully initialised.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21708?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21708" src="https://img.shields.io/badge/CVE--2025--21708-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.086%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: usb: rtl8150: enable basic endpoint checking  Syzkaller reports [1] encountering a common issue of utilizing a wrong usb endpoint type during URB submitting stage. This, in turn, triggers a warning shown below.  For now, enable simple endpoint checking (specifically, bulk and interrupt eps, testing control one is not essential) to mitigate the issue with a view to do other related cosmetic changes later, if they are necessary.  [1] Syzkaller report: usb 1-1: BOGUS urb xfer, pipe 3 != type 1 WARNING: CPU: 1 PID: 2586 at drivers/usb/core/urb.c:503 usb_submit_urb+0xe4b/0x1730 driv> Modules linked in: CPU: 1 UID: 0 PID: 2586 Comm: dhcpcd Not tainted 6.11.0-rc4-syzkaller-00069-gfc88bb11617> Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 08/06/2024 RIP: 0010:usb_submit_urb+0xe4b/0x1730 drivers/usb/core/urb.c:503 Code: 84 3c 02 00 00 e8 05 e4 fc fc 4c 89 ef e8 fd 25 d7 fe 45 89 e0 89 e9 4c 89 f2 48 8> RSP: 0018:ffffc9000441f740 EFLAGS: 00010282 RAX: 0000000000000000 RBX: ffff888112487a00 RCX: ffffffff811a99a9 RDX: ffff88810df6ba80 RSI: ffffffff811a99b6 RDI: 0000000000000001 RBP: 0000000000000003 R08: 0000000000000001 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000001 R12: 0000000000000001 R13: ffff8881023bf0a8 R14: ffff888112452a20 R15: ffff888112487a7c FS:  00007fc04eea5740(0000) GS:ffff8881f6300000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f0a1de9f870 CR3: 000000010dbd0000 CR4: 00000000003506f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> rtl8150_open+0x300/0xe30 drivers/net/usb/rtl8150.c:733 __dev_open+0x2d4/0x4e0 net/core/dev.c:1474 __dev_change_flags+0x561/0x720 net/core/dev.c:8838 dev_change_flags+0x8f/0x160 net/core/dev.c:8910 devinet_ioctl+0x127a/0x1f10 net/ipv4/devinet.c:1177 inet_ioctl+0x3aa/0x3f0 net/ipv4/af_inet.c:1003 sock_do_ioctl+0x116/0x280 net/socket.c:1222 sock_ioctl+0x22e/0x6c0 net/socket.c:1341 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:907 [inline] __se_sys_ioctl fs/ioctl.c:893 [inline] __x64_sys_ioctl+0x193/0x220 fs/ioctl.c:893 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7fc04ef73d49 ...  This change has not been tested on real hardware.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21706?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21706" src="https://img.shields.io/badge/CVE--2025--21706-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: pm: only set fullmesh for subflow endp  With the in-kernel path-manager, it is possible to change the 'fullmesh' flag. The code in mptcp_pm_nl_fullmesh() expects to change it only on 'subflow' endpoints, to recreate more or less subflows using the linked address.  Unfortunately, the set_flags() hook was a bit more permissive, and allowed 'implicit' endpoints to get the 'fullmesh' flag while it is not allowed before.  That's what syzbot found, triggering the following warning:  WARNING: CPU: 0 PID: 6499 at net/mptcp/pm_netlink.c:1496 __mark_subflow_endp_available net/mptcp/pm_netlink.c:1496 [inline] WARNING: CPU: 0 PID: 6499 at net/mptcp/pm_netlink.c:1496 mptcp_pm_nl_fullmesh net/mptcp/pm_netlink.c:1980 [inline] WARNING: CPU: 0 PID: 6499 at net/mptcp/pm_netlink.c:1496 mptcp_nl_set_flags net/mptcp/pm_netlink.c:2003 [inline] WARNING: CPU: 0 PID: 6499 at net/mptcp/pm_netlink.c:1496 mptcp_pm_nl_set_flags+0x974/0xdc0 net/mptcp/pm_netlink.c:2064 Modules linked in: CPU: 0 UID: 0 PID: 6499 Comm: syz.1.413 Not tainted 6.13.0-rc5-syzkaller-00172-gd1bf27c4e176 #0 Hardware name: Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:__mark_subflow_endp_available net/mptcp/pm_netlink.c:1496 [inline] RIP: 0010:mptcp_pm_nl_fullmesh net/mptcp/pm_netlink.c:1980 [inline] RIP: 0010:mptcp_nl_set_flags net/mptcp/pm_netlink.c:2003 [inline] RIP: 0010:mptcp_pm_nl_set_flags+0x974/0xdc0 net/mptcp/pm_netlink.c:2064 Code: 01 00 00 49 89 c5 e8 fb 45 e8 f5 e9 b8 fc ff ff e8 f1 45 e8 f5 4c 89 f7 be 03 00 00 00 e8 44 1d 0b f9 eb a0 e8 dd 45 e8 f5 90 <0f> 0b 90 e9 17 ff ff ff 89 d9 80 e1 07 38 c1 0f 8c c9 fc ff ff 48 RSP: 0018:ffffc9000d307240 EFLAGS: 00010293 RAX: ffffffff8bb72e03 RBX: 0000000000000000 RCX: ffff88807da88000 RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000 RBP: ffffc9000d307430 R08: ffffffff8bb72cf0 R09: 1ffff1100b842a5e R10: dffffc0000000000 R11: ffffed100b842a5f R12: ffff88801e2e5ac0 R13: ffff88805c214800 R14: ffff88805c2152e8 R15: 1ffff1100b842a5d FS:  00005555619f6500(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000020002840 CR3: 00000000247e6000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> genl_family_rcv_msg_doit net/netlink/genetlink.c:1115 [inline] genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline] genl_rcv_msg+0xb14/0xec0 net/netlink/genetlink.c:1210 netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2542 genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219 netlink_unicast_kernel net/netlink/af_netlink.c:1321 [inline] netlink_unicast+0x7f6/0x990 net/netlink/af_netlink.c:1347 netlink_sendmsg+0x8e4/0xcb0 net/netlink/af_netlink.c:1891 sock_sendmsg_nosec net/socket.c:711 [inline] __sock_sendmsg+0x221/0x270 net/socket.c:726 ____sys_sendmsg+0x52a/0x7e0 net/socket.c:2583 ___sys_sendmsg net/socket.c:2637 [inline] __sys_sendmsg+0x269/0x350 net/socket.c:2669 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7f5fe8785d29 Code: ff ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 a8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007fff571f5558 EFLAGS: 00000246 ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX: 00007f5fe8975fa0 RCX: 00007f5fe8785d29 RDX: 0000000000000000 RSI: 0000000020000480 RDI: 0000000000000007 RBP: 00007f5fe8801b08 R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000 R13: 00007f5fe8975fa0 R14: 00007f5fe8975fa0 R15: 000000 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21705?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21705" src="https://img.shields.io/badge/CVE--2025--21705-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: handle fastopen disconnect correctly  Syzbot was able to trigger a data stream corruption:  WARNING: CPU: 0 PID: 9846 at net/mptcp/protocol.c:1024 __mptcp_clean_una+0xddb/0xff0 net/mptcp/protocol.c:1024 Modules linked in: CPU: 0 UID: 0 PID: 9846 Comm: syz-executor351 Not tainted 6.13.0-rc2-syzkaller-00059-g00a5acdbf398 #0 Hardware name: Google Compute Engine/Google Compute Engine, BIOS Google 11/25/2024 RIP: 0010:__mptcp_clean_una+0xddb/0xff0 net/mptcp/protocol.c:1024 Code: fa ff ff 48 8b 4c 24 18 80 e1 07 fe c1 38 c1 0f 8c 8e fa ff ff 48 8b 7c 24 18 e8 e0 db 54 f6 e9 7f fa ff ff e8 e6 80 ee f5 90 <0f> 0b 90 4c 8b 6c 24 40 4d 89 f4 e9 04 f5 ff ff 44 89 f1 80 e1 07 RSP: 0018:ffffc9000c0cf400 EFLAGS: 00010293 RAX: ffffffff8bb0dd5a RBX: ffff888033f5d230 RCX: ffff888059ce8000 RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000 RBP: ffffc9000c0cf518 R08: ffffffff8bb0d1dd R09: 1ffff110170c8928 R10: dffffc0000000000 R11: ffffed10170c8929 R12: 0000000000000000 R13: ffff888033f5d220 R14: dffffc0000000000 R15: ffff8880592b8000 FS:  00007f6e866496c0(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f6e86f491a0 CR3: 00000000310e6000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> __mptcp_clean_una_wakeup+0x7f/0x2d0 net/mptcp/protocol.c:1074 mptcp_release_cb+0x7cb/0xb30 net/mptcp/protocol.c:3493 release_sock+0x1aa/0x1f0 net/core/sock.c:3640 inet_wait_for_connect net/ipv4/af_inet.c:609 [inline] __inet_stream_connect+0x8bd/0xf30 net/ipv4/af_inet.c:703 mptcp_sendmsg_fastopen+0x2a2/0x530 net/mptcp/protocol.c:1755 mptcp_sendmsg+0x1884/0x1b10 net/mptcp/protocol.c:1830 sock_sendmsg_nosec net/socket.c:711 [inline] __sock_sendmsg+0x1a6/0x270 net/socket.c:726 ____sys_sendmsg+0x52a/0x7e0 net/socket.c:2583 ___sys_sendmsg net/socket.c:2637 [inline] __sys_sendmsg+0x269/0x350 net/socket.c:2669 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7f6e86ebfe69 Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 b1 1f 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b0 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007f6e86649168 EFLAGS: 00000246 ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX: 00007f6e86f491b8 RCX: 00007f6e86ebfe69 RDX: 0000000030004001 RSI: 0000000020000080 RDI: 0000000000000003 RBP: 00007f6e86f491b0 R08: 00007f6e866496c0 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 00007f6e86f491bc R13: 000000000000006e R14: 00007ffe445d9420 R15: 00007ffe445d9508 </TASK>  The root cause is the bad handling of disconnect() generated internally by the MPTCP protocol in case of connect FASTOPEN errors.  Address the issue increasing the socket disconnect counter even on such a case, to allow other threads waiting on the same socket lock to properly error out.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21704?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21704" src="https://img.shields.io/badge/CVE--2025--21704-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.116%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: cdc-acm: Check control transfer buffer size before access  If the first fragment is shorter than struct usb_cdc_notification, we can't calculate an expected_size. Log an error and discard the notification instead of reading lengths from memory outside the received data, which can lead to memory corruption when the expected_size decreases between fragments, causing `expected_size - acm->nb_index` to wrap.  This issue has been present since the beginning of git history; however, it only leads to memory corruption since commit ea2583529cd1 ("cdc-acm: reassemble fragmented notifications").  A mitigating factor is that acm_ctrl_irq() can only execute after userspace has opened /dev/ttyACM*; but if ModemManager is running, ModemManager will do that automatically depending on the USB device's vendor/product IDs and its other interfaces.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21698?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21698" src="https://img.shields.io/badge/CVE--2025--21698-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21693?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21693" src="https://img.shields.io/badge/CVE--2025--21693-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm: zswap: properly synchronize freeing resources during CPU hotunplug  In zswap_compress() and zswap_decompress(), the per-CPU acomp_ctx of the current CPU at the beginning of the operation is retrieved and used throughout.  However, since neither preemption nor migration are disabled, it is possible that the operation continues on a different CPU.  If the original CPU is hotunplugged while the acomp_ctx is still in use, we run into a UAF bug as some of the resources attached to the acomp_ctx are freed during hotunplug in zswap_cpu_comp_dead() (i.e. acomp_ctx.buffer, acomp_ctx.req, or acomp_ctx.acomp).  The problem was introduced in commit 1ec3b5fe6eec ("mm/zswap: move to use crypto_acomp API for hardware acceleration") when the switch to the crypto_acomp API was made.  Prior to that, the per-CPU crypto_comp was retrieved using get_cpu_ptr() which disables preemption and makes sure the CPU cannot go away from under us.  Preemption cannot be disabled with the crypto_acomp API as a sleepable context is needed.  Use the acomp_ctx.mutex to synchronize CPU hotplug callbacks allocating and freeing resources with compression/decompression paths.  Make sure that acomp_ctx.req is NULL when the resources are freed.  In the compression/decompression paths, check if acomp_ctx.req is NULL after acquiring the mutex (meaning the CPU was offlined) and retry on the new CPU.  The initialization of acomp_ctx.mutex is moved from the CPU hotplug callback to the pool initialization where it belongs (where the mutex is allocated).  In addition to adding clarity, this makes sure that CPU hotplug cannot reinitialize a mutex that is already locked by compression/decompression.  Previously a fix was attempted by holding cpus_read_lock() [1].  This would have caused a potential deadlock as it is possible for code already holding the lock to fall into reclaim and enter zswap (causing a deadlock).  A fix was also attempted using SRCU for synchronization, but Johannes pointed out that synchronize_srcu() cannot be used in CPU hotplug notifiers [2].  Alternative fixes that were considered/attempted and could have worked: - Refcounting the per-CPU acomp_ctx. This involves complexity in handling the race between the refcount dropping to zero in zswap_[de]compress() and the refcount being re-initialized when the CPU is onlined. - Disabling migration before getting the per-CPU acomp_ctx [3], but that's discouraged and is a much bigger hammer than needed, and could result in subtle performance issues.  [1]https://lkml.kernel.org/20241219212437.2714151-1-yosryahmed@google.com/ [2]https://lkml.kernel.org/20250107074724.1756696-2-yosryahmed@google.com/ [3]https://lkml.kernel.org/20250107222236.2715883-2-yosryahmed@google.com/  [yosryahmed@google.com: remove comment] Link: https://lkml.kernel.org/r/CAJD7tkaxS1wjn+swugt8QCvQ-rVF5RZnjxwPGX17k8x9zSManA@mail.gmail.com

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21691?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21691" src="https://img.shields.io/badge/CVE--2025--21691-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cachestat: fix page cache statistics permission checking  When the 'cachestat()' system call was added in commit cf264e1329fb ("cachestat: implement cachestat syscall"), it was meant to be a much more convenient (and performant) version of mincore() that didn't need mapping things into the user virtual address space in order to work.  But it ended up missing the "check for writability or ownership" fix for mincore(), done in commit 134fca9063ad ("mm/mincore.c: make mincore() more conservative").  This just adds equivalent logic to 'cachestat()', modified for the file context (rather than vma).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21678?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21678" src="https://img.shields.io/badge/CVE--2025--21678-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.066%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gtp: Destroy device along with udp socket's netns dismantle.  gtp_newlink() links the device to a list in dev_net(dev) instead of src_net, where a udp tunnel socket is created.  Even when src_net is removed, the device stays alive on dev_net(dev). Then, removing src_net triggers the splat below. [0]  In this example, gtp0 is created in ns2, and the udp socket is created in ns1.  ip netns add ns1 ip netns add ns2 ip -n ns1 link add netns ns2 name gtp0 type gtp role sgsn ip netns del ns1  Let's link the device to the socket's netns instead.  Now, gtp_net_exit_batch_rtnl() needs another netdev iteration to remove all gtp devices in the netns.  [0]: ref_tracker: net notrefcnt@000000003d6e7d05 has 1/2 users at sk_alloc (./include/net/net_namespace.h:345 net/core/sock.c:2236) inet_create (net/ipv4/af_inet.c:326 net/ipv4/af_inet.c:252) __sock_create (net/socket.c:1558) udp_sock_create4 (net/ipv4/udp_tunnel_core.c:18) gtp_create_sock (./include/net/udp_tunnel.h:59 drivers/net/gtp.c:1423) gtp_create_sockets (drivers/net/gtp.c:1447) gtp_newlink (drivers/net/gtp.c:1507) rtnl_newlink (net/core/rtnetlink.c:3786 net/core/rtnetlink.c:3897 net/core/rtnetlink.c:4012) rtnetlink_rcv_msg (net/core/rtnetlink.c:6922) netlink_rcv_skb (net/netlink/af_netlink.c:2542) netlink_unicast (net/netlink/af_netlink.c:1321 net/netlink/af_netlink.c:1347) netlink_sendmsg (net/netlink/af_netlink.c:1891) ____sys_sendmsg (net/socket.c:711 net/socket.c:726 net/socket.c:2583) ___sys_sendmsg (net/socket.c:2639) __sys_sendmsg (net/socket.c:2669) do_syscall_64 (arch/x86/entry/common.c:52 arch/x86/entry/common.c:83)  WARNING: CPU: 1 PID: 60 at lib/ref_tracker.c:179 ref_tracker_dir_exit (lib/ref_tracker.c:179) Modules linked in: CPU: 1 UID: 0 PID: 60 Comm: kworker/u16:2 Not tainted 6.13.0-rc5-00147-g4c1224501e9d #5 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 Workqueue: netns cleanup_net RIP: 0010:ref_tracker_dir_exit (lib/ref_tracker.c:179) Code: 00 00 00 fc ff df 4d 8b 26 49 bd 00 01 00 00 00 00 ad de 4c 39 f5 0f 85 df 00 00 00 48 8b 74 24 08 48 89 df e8 a5 cc 12 02 90 <0f> 0b 90 48 8d 6b 44 be 04 00 00 00 48 89 ef e8 80 de 67 ff 48 89 RSP: 0018:ff11000009a07b60 EFLAGS: 00010286 RAX: 0000000000002bd3 RBX: ff1100000f4e1aa0 RCX: 1ffffffff0e40ac6 RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8423ee3c RBP: ff1100000f4e1af0 R08: 0000000000000001 R09: fffffbfff0e395ae R10: 0000000000000001 R11: 0000000000036001 R12: ff1100000f4e1af0 R13: dead000000000100 R14: ff1100000f4e1af0 R15: dffffc0000000000 FS:  0000000000000000(0000) GS:ff1100006ce80000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f9b2464bd98 CR3: 0000000005286005 CR4: 0000000000771ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe07f0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> ? __warn (kernel/panic.c:748) ? ref_tracker_dir_exit (lib/ref_tracker.c:179) ? report_bug (lib/bug.c:201 lib/bug.c:219) ? handle_bug (arch/x86/kernel/traps.c:285) ? exc_invalid_op (arch/x86/kernel/traps.c:309 (discriminator 1)) ? asm_exc_invalid_op (./arch/x86/include/asm/idtentry.h:621) ? _raw_spin_unlock_irqrestore (./arch/x86/include/asm/irqflags.h:42 ./arch/x86/include/asm/irqflags.h:97 ./arch/x86/include/asm/irqflags.h:155 ./include/linux/spinlock_api_smp.h:151 kernel/locking/spinlock.c:194) ? ref_tracker_dir_exit (lib/ref_tracker.c:179) ? __pfx_ref_tracker_dir_exit (lib/ref_tracker.c:158) ? kfree (mm/slub.c:4613 mm/slub.c:4761) net_free (net/core/net_namespace.c:476 net/core/net_namespace.c:467) cleanup_net (net/core/net_namespace.c:664 (discriminator 3)) process_one_work (kernel/workqueue.c:3229) worker_thread (kernel/workqueue.c:3304 kernel/workqueue.c:3391 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21668?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21668" src="https://img.shields.io/badge/CVE--2025--21668-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.038%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pmdomain: imx8mp-blk-ctrl: add missing loop break condition  Currently imx8mp_blk_ctrl_remove() will continue the for loop until an out-of-bounds exception occurs.  pstate: 60000005 (nZCv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : dev_pm_domain_detach+0x8/0x48 lr : imx8mp_blk_ctrl_shutdown+0x58/0x90 sp : ffffffc084f8bbf0 x29: ffffffc084f8bbf0 x28: ffffff80daf32ac0 x27: 0000000000000000 x26: ffffffc081658d78 x25: 0000000000000001 x24: ffffffc08201b028 x23: ffffff80d0db9490 x22: ffffffc082340a78 x21: 00000000000005b0 x20: ffffff80d19bc180 x19: 000000000000000a x18: ffffffffffffffff x17: ffffffc080a39e08 x16: ffffffc080a39c98 x15: 4f435f464f006c72 x14: 0000000000000004 x13: ffffff80d0172110 x12: 0000000000000000 x11: ffffff80d0537740 x10: ffffff80d05376c0 x9 : ffffffc0808ed2d8 x8 : ffffffc084f8bab0 x7 : 0000000000000000 x6 : 0000000000000000 x5 : ffffff80d19b9420 x4 : fffffffe03466e60 x3 : 0000000080800077 x2 : 0000000000000000 x1 : 0000000000000001 x0 : 0000000000000000 Call trace: dev_pm_domain_detach+0x8/0x48 platform_shutdown+0x2c/0x48 device_shutdown+0x158/0x268 kernel_restart_prepare+0x40/0x58 kernel_kexec+0x58/0xe8 __do_sys_reboot+0x198/0x258 __arm64_sys_reboot+0x2c/0x40 invoke_syscall+0x5c/0x138 el0_svc_common.constprop.0+0x48/0xf0 do_el0_svc+0x24/0x38 el0_svc+0x38/0xc8 el0t_64_sync_handler+0x120/0x130 el0t_64_sync+0x190/0x198 Code: 8128c2d0 ffffffc0 aa1e03e9 d503201f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21664?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21664" src="https://img.shields.io/badge/CVE--2025--21664-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.069%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dm thin: make get_first_thin use rcu-safe list first function  The documentation in rculist.h explains the absence of list_empty_rcu() and cautions programmers against relying on a list_empty() -> list_first() sequence in RCU safe code.  This is because each of these functions performs its own READ_ONCE() of the list head.  This can lead to a situation where the list_empty() sees a valid list entry, but the subsequent list_first() sees a different view of list head state after a modification.  In the case of dm-thin, this author had a production box crash from a GP fault in the process_deferred_bios path.  This function saw a valid list head in get_first_thin() but when it subsequently dereferenced that and turned it into a thin_c, it got the inside of the struct pool, since the list was now empty and referring to itself.  The kernel on which this occurred printed both a warning about a refcount_t being saturated, and a UBSAN error for an out-of-bounds cpuid access in the queued spinlock, prior to the fault itself.  When the resulting kdump was examined, it was possible to see another thread patiently waiting in thin_dtr's synchronize_rcu.  The thin_dtr call managed to pull the thin_c out of the active thins list (and have it be the last entry in the active_thins list) at just the wrong moment which lead to this crash.  Fortunately, the fix here is straight forward.  Switch get_first_thin() function to use list_first_or_null_rcu() which performs just a single READ_ONCE() and returns NULL if the list is already empty.  This was run against the devicemapper test suite's thin-provisioning suites for delete and suspend and no regressions were observed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21663?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21663" src="https://img.shields.io/badge/CVE--2025--21663-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: stmmac: dwmac-tegra: Read iommu stream id from device tree  Nvidia's Tegra MGBE controllers require the IOMMU "Stream ID" (SID) to be written to the MGBE_WRAP_AXI_ASID0_CTRL register.  The current driver is hard coded to use MGBE0's SID for all controllers. This causes softirq time outs and kernel panics when using controllers other than MGBE0.  Example dmesg errors when an ethernet cable is connected to MGBE1:  [  116.133290] tegra-mgbe 6910000.ethernet eth1: Link is Up - 1Gbps/Full - flow control rx/tx [  121.851283] tegra-mgbe 6910000.ethernet eth1: NETDEV WATCHDOG: CPU: 5: transmit queue 0 timed out 5690 ms [  121.851782] tegra-mgbe 6910000.ethernet eth1: Reset adapter. [  121.892464] tegra-mgbe 6910000.ethernet eth1: Register MEM_TYPE_PAGE_POOL RxQ-0 [  121.905920] tegra-mgbe 6910000.ethernet eth1: PHY [stmmac-1:00] driver [Aquantia AQR113] (irq=171) [  121.907356] tegra-mgbe 6910000.ethernet eth1: Enabling Safety Features [  121.907578] tegra-mgbe 6910000.ethernet eth1: IEEE 1588-2008 Advanced Timestamp supported [  121.908399] tegra-mgbe 6910000.ethernet eth1: registered PTP clock [  121.908582] tegra-mgbe 6910000.ethernet eth1: configuring for phy/10gbase-r link mode [  125.961292] tegra-mgbe 6910000.ethernet eth1: Link is Up - 1Gbps/Full - flow control rx/tx [  181.921198] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks: [  181.921404] rcu: 	7-....: (1 GPs behind) idle=540c/1/0x4000000000000002 softirq=1748/1749 fqs=2337 [  181.921684] rcu: 	(detected by 4, t=6002 jiffies, g=1357, q=1254 ncpus=8) [  181.921878] Sending NMI from CPU 4 to CPUs 7: [  181.921886] NMI backtrace for cpu 7 [  181.922131] CPU: 7 UID: 0 PID: 0 Comm: swapper/7 Kdump: loaded Not tainted 6.13.0-rc3+ #6 [  181.922390] Hardware name: NVIDIA CTI Forge + Orin AGX/Jetson, BIOS 202402.1-Unknown 10/28/2024 [  181.922658] pstate: 40400009 (nZcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) [  181.922847] pc : handle_softirqs+0x98/0x368 [  181.922978] lr : __do_softirq+0x18/0x20 [  181.923095] sp : ffff80008003bf50 [  181.923189] x29: ffff80008003bf50 x28: 0000000000000008 x27: 0000000000000000 [  181.923379] x26: ffffce78ea277000 x25: 0000000000000000 x24: 0000001c61befda0 [  181.924486] x23: 0000000060400009 x22: ffffce78e99918bc x21: ffff80008018bd70 [  181.925568] x20: ffffce78e8bb00d8 x19: ffff80008018bc20 x18: 0000000000000000 [  181.926655] x17: ffff318ebe7d3000 x16: ffff800080038000 x15: 0000000000000000 [  181.931455] x14: ffff000080816680 x13: ffff318ebe7d3000 x12: 000000003464d91d [  181.938628] x11: 0000000000000040 x10: ffff000080165a70 x9 : ffffce78e8bb0160 [  181.945804] x8 : ffff8000827b3160 x7 : f9157b241586f343 x6 : eeb6502a01c81c74 [  181.953068] x5 : a4acfcdd2e8096bb x4 : ffffce78ea277340 x3 : 00000000ffffd1e1 [  181.960329] x2 : 0000000000000101 x1 : ffffce78ea277340 x0 : ffff318ebe7d3000 [  181.967591] Call trace: [  181.970043]  handle_softirqs+0x98/0x368 (P) [  181.974240]  __do_softirq+0x18/0x20 [  181.977743]  ____do_softirq+0x14/0x28 [  181.981415]  call_on_irq_stack+0x24/0x30 [  181.985180]  do_softirq_own_stack+0x20/0x30 [  181.989379]  __irq_exit_rcu+0x114/0x140 [  181.993142]  irq_exit_rcu+0x14/0x28 [  181.996816]  el1_interrupt+0x44/0xb8 [  182.000316]  el1h_64_irq_handler+0x14/0x20 [  182.004343]  el1h_64_irq+0x80/0x88 [  182.007755]  cpuidle_enter_state+0xc4/0x4a8 (P) [  182.012305]  cpuidle_enter+0x3c/0x58 [  182.015980]  cpuidle_idle_call+0x128/0x1c0 [  182.020005]  do_idle+0xe0/0xf0 [  182.023155]  cpu_startup_entry+0x3c/0x48 [  182.026917]  secondary_start_kernel+0xdc/0x120 [  182.031379]  __secondary_switched+0x74/0x78 [  212.971162] rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks: { 7-.... } 6103 jiffies s: 417 root: 0x80/. [  212.985935] rcu: blocking rcu_node structures (internal RCU debug): [  212.992758] Sending NMI from CPU 0 to CPUs 7: [  212.998539] NMI backtrace for cpu 7 [  213.004304] CPU: 7 UID: 0 PI ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21662?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21662" src="https://img.shields.io/badge/CVE--2025--21662-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.037%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: Fix variable not being completed when function returns  When cmd_alloc_index(), fails cmd_work_handler() needs to complete ent->slotted before returning early. Otherwise the task which issued the command may hang:  mlx5_core 0000:01:00.0: cmd_work_handler:877:(pid 3880418): failed to allocate command entry INFO: task kworker/13:2:4055883 blocked for more than 120 seconds. Not tainted 4.19.90-25.44.v2101.ky10.aarch64 #1 "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message. kworker/13:2    D    0 4055883      2 0x00000228 Workqueue: events mlx5e_tx_dim_work [mlx5_core] Call trace: __switch_to+0xe8/0x150 __schedule+0x2a8/0x9b8 schedule+0x2c/0x88 schedule_timeout+0x204/0x478 wait_for_common+0x154/0x250 wait_for_completion+0x28/0x38 cmd_exec+0x7a0/0xa00 [mlx5_core] mlx5_cmd_exec+0x54/0x80 [mlx5_core] mlx5_core_modify_cq+0x6c/0x80 [mlx5_core] mlx5_core_modify_cq_moderation+0xa0/0xb8 [mlx5_core] mlx5e_tx_dim_work+0x54/0x68 [mlx5_core] process_one_work+0x1b0/0x448 worker_thread+0x54/0x468 kthread+0x134/0x138 ret_from_fork+0x10/0x18

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21660?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21660" src="https://img.shields.io/badge/CVE--2025--21660-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.037%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: fix unexpectedly changed path in ksmbd_vfs_kern_path_locked  When `ksmbd_vfs_kern_path_locked` met an error and it is not the last entry, it will exit without restoring changed path buffer. But later this buffer may be used as the filename for creation.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21659?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21659" src="https://img.shields.io/badge/CVE--2025--21659-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netdev: prevent accessing NAPI instances from another namespace  The NAPI IDs were not fully exposed to user space prior to the netlink API, so they were never namespaced. The netlink API must ensure that at the very least NAPI instance belongs to the same netns as the owner of the genl sock.  napi_by_id() can become static now, but it needs to move because of dev_get_by_napi_id().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21656?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21656" src="https://img.shields.io/badge/CVE--2025--21656-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  hwmon: (drivetemp) Fix driver producing garbage data when SCSI errors occur  scsi_execute_cmd() function can return both negative (linux codes) and positive (scsi_cmnd result field) error codes.  Currently the driver just passes error codes of scsi_execute_cmd() to hwmon core, which is incorrect because hwmon only checks for negative error codes. This leads to hwmon reporting uninitialized data to userspace in case of SCSI errors (for example if the disk drive was disconnected).  This patch checks scsi_execute_cmd() output and returns -EIO if it's error code is positive.  [groeck: Avoid inline variable declaration for portability]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21655?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21655" src="https://img.shields.io/badge/CVE--2025--21655-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  io_uring/eventfd: ensure io_eventfd_signal() defers another RCU period  io_eventfd_do_signal() is invoked from an RCU callback, but when dropping the reference to the io_ev_fd, it calls io_eventfd_free() directly if the refcount drops to zero. This isn't correct, as any potential freeing of the io_ev_fd should be deferred another RCU grace period.  Just call io_eventfd_put() rather than open-code the dec-and-test and free, which will correctly defer it another RCU grace period.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21654?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21654" src="https://img.shields.io/badge/CVE--2025--21654-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ovl: support encoding fid from inode with no alias  Dmitry Safonov reported that a WARN_ON() assertion can be trigered by userspace when calling inotify_show_fdinfo() for an overlayfs watched inode, whose dentry aliases were discarded with drop_caches.  The WARN_ON() assertion in inotify_show_fdinfo() was removed, because it is possible for encoding file handle to fail for other reason, but the impact of failing to encode an overlayfs file handle goes beyond this assertion.  As shown in the LTP test case mentioned in the link below, failure to encode an overlayfs file handle from a non-aliased inode also leads to failure to report an fid with FAN_DELETE_SELF fanotify events.  As Dmitry notes in his analyzis of the problem, ovl_encode_fh() fails if it cannot find an alias for the inode, but this failure can be fixed. ovl_encode_fh() seldom uses the alias and in the case of non-decodable file handles, as is often the case with fanotify fid info, ovl_encode_fh() never needs to use the alias to encode a file handle.  Defer finding an alias until it is actually needed so ovl_encode_fh() will not fail in the common case of FAN_DELETE_SELF fanotify events.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21653?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21653" src="https://img.shields.io/badge/CVE--2025--21653-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.069%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute  syzbot found that TCA_FLOW_RSHIFT attribute was not validated. Right shitfing a 32bit integer is undefined for large shift values.  UBSAN: shift-out-of-bounds in net/sched/cls_flow.c:329:23 shift exponent 9445 is too large for 32-bit type 'u32' (aka 'unsigned int') CPU: 1 UID: 0 PID: 54 Comm: kworker/u8:3 Not tainted 6.13.0-rc3-syzkaller-00180-g4f619d518db9 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Workqueue: ipv6_addrconf addrconf_dad_work Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 ubsan_epilogue lib/ubsan.c:231 [inline] __ubsan_handle_shift_out_of_bounds+0x3c8/0x420 lib/ubsan.c:468 flow_classify+0x24d5/0x25b0 net/sched/cls_flow.c:329 tc_classify include/net/tc_wrapper.h:197 [inline] __tcf_classify net/sched/cls_api.c:1771 [inline] tcf_classify+0x420/0x1160 net/sched/cls_api.c:1867 sfb_classify net/sched/sch_sfb.c:260 [inline] sfb_enqueue+0x3ad/0x18b0 net/sched/sch_sfb.c:318 dev_qdisc_enqueue+0x4b/0x290 net/core/dev.c:3793 __dev_xmit_skb net/core/dev.c:3889 [inline] __dev_queue_xmit+0xf0e/0x3f50 net/core/dev.c:4400 dev_queue_xmit include/linux/netdevice.h:3168 [inline] neigh_hh_output include/net/neighbour.h:523 [inline] neigh_output include/net/neighbour.h:537 [inline] ip_finish_output2+0xd41/0x1390 net/ipv4/ip_output.c:236 iptunnel_xmit+0x55d/0x9b0 net/ipv4/ip_tunnel_core.c:82 udp_tunnel_xmit_skb+0x262/0x3b0 net/ipv4/udp_tunnel_core.c:173 geneve_xmit_skb drivers/net/geneve.c:916 [inline] geneve_xmit+0x21dc/0x2d00 drivers/net/geneve.c:1039 __netdev_start_xmit include/linux/netdevice.h:5002 [inline] netdev_start_xmit include/linux/netdevice.h:5011 [inline] xmit_one net/core/dev.c:3590 [inline] dev_hard_start_xmit+0x27a/0x7d0 net/core/dev.c:3606 __dev_queue_xmit+0x1b73/0x3f50 net/core/dev.c:4434

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21651?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21651" src="https://img.shields.io/badge/CVE--2025--21651-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hns3: don't auto enable misc vector  Currently, there is a time window between misc irq enabled and service task inited. If an interrupte is reported at this time, it will cause warning like below:  [   16.324639] Call trace: [   16.324641]  __queue_delayed_work+0xb8/0xe0 [   16.324643]  mod_delayed_work_on+0x78/0xd0 [   16.324655]  hclge_errhand_task_schedule+0x58/0x90 [hclge] [   16.324662]  hclge_misc_irq_handle+0x168/0x240 [hclge] [   16.324666]  __handle_irq_event_percpu+0x64/0x1e0 [   16.324667]  handle_irq_event+0x80/0x170 [   16.324670]  handle_fasteoi_edge_irq+0x110/0x2bc [   16.324671]  __handle_domain_irq+0x84/0xfc [   16.324673]  gic_handle_irq+0x88/0x2c0 [   16.324674]  el1_irq+0xb8/0x140 [   16.324677]  arch_cpu_idle+0x18/0x40 [   16.324679]  default_idle_call+0x5c/0x1bc [   16.324682]  cpuidle_idle_call+0x18c/0x1c4 [   16.324684]  do_idle+0x174/0x17c [   16.324685]  cpu_startup_entry+0x30/0x6c [   16.324687]  secondary_start_kernel+0x1a4/0x280 [   16.324688] ---[ end trace 6aa0bff672a964aa ]---  So don't auto enable misc vector when request irq..

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21648?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21648" src="https://img.shields.io/badge/CVE--2025--21648-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.069%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: conntrack: clamp maximum hashtable size to INT_MAX  Use INT_MAX as maximum size for the conntrack hashtable. Otherwise, it is possible to hit WARN_ON_ONCE in __kvmalloc_node_noprof() when resizing hashtable because __GFP_NOWARN is unset. See:  0708a0afe291 ("mm: Consider __GFP_NOWARN flag for oversized kvmalloc() calls")  Note: hashtable resize is only possible from init_netns.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21647?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21647" src="https://img.shields.io/badge/CVE--2025--21647-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.069%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sched: sch_cake: add bounds checks to host bulk flow fairness counts  Even though we fixed a logic error in the commit cited below, syzbot still managed to trigger an underflow of the per-host bulk flow counters, leading to an out of bounds memory access.  To avoid any such logic errors causing out of bounds memory accesses, this commit factors out all accesses to the per-host bulk flow counters to a series of helpers that perform bounds-checking before any increments and decrements. This also has the benefit of improving readability by moving the conditional checks for the flow mode into these helpers, instead of having them spread out throughout the code (which was the cause of the original logic error).  As part of this change, the flow quantum calculation is consolidated into a helper function, which means that the dithering applied to the ost load scaling is now applied both in the DRR rotation and when a sparse flow's quantum is first initiated. The only user-visible effect of this is that the maximum packet size that can be sent while a flow stays sparse will now vary with +/- one byte in some cases. This should not make a noticeable difference in practice, and thus it's not worth complicating the code to preserve the old behaviour.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21646?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21646" src="https://img.shields.io/badge/CVE--2025--21646-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.069%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  afs: Fix the maximum cell name length  The kafs filesystem limits the maximum length of a cell to 256 bytes, but a problem occurs if someone actually does that: kafs tries to create a directory under /proc/net/afs/ with the name of the cell, but that fails with a warning:  WARNING: CPU: 0 PID: 9 at fs/proc/generic.c:405  because procfs limits the maximum filename length to 255.  However, the DNS limits the maximum lookup length and, by extension, the maximum cell name, to 255 less two (length count and trailing NUL).  Fix this by limiting the maximum acceptable cellname length to 253.  This also allows us to be sure we can create the "/afs/.<cell>/" mountpoint too.  Further, split the YFS VL record cell name maximum to be the 256 allowed by the protocol and ignore the record retrieved by YFSVL.GetCellName if it exceeds 253.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21645?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21645" src="https://img.shields.io/badge/CVE--2025--21645-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  platform/x86/amd/pmc: Only disable IRQ1 wakeup where i8042 actually enabled it  Wakeup for IRQ1 should be disabled only in cases where i8042 had actually enabled it, otherwise "wake_depth" for this IRQ will try to drop below zero and there will be an unpleasant WARN() logged:  kernel: atkbd serio0: Disabling IRQ1 wakeup source to avoid platform firmware bug kernel: ------------[ cut here ]------------ kernel: Unbalanced IRQ 1 wake disable kernel: WARNING: CPU: 10 PID: 6431 at kernel/irq/manage.c:920 irq_set_irq_wake+0x147/0x1a0  The PMC driver uses DEFINE_SIMPLE_DEV_PM_OPS() to define its dev_pm_ops which sets amd_pmc_suspend_handler() to the .suspend, .freeze, and .poweroff handlers. i8042_pm_suspend(), however, is only set as the .suspend handler.  Fix the issue by call PMC suspend handler only from the same set of dev_pm_ops handlers as i8042_pm_suspend(), which currently means just the .suspend handler.  To reproduce this issue try hibernating (S4) the machine after a fresh boot without putting it into s2idle first.  [ij: edited the commit message.]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21643?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21643" src="https://img.shields.io/badge/CVE--2025--21643-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfs: Fix kernel async DIO  Netfslib needs to be able to handle kernel-initiated asynchronous DIO that is supplied with a bio_vec[] array.  Currently, because of the async flag, this gets passed to netfs_extract_user_iter() which throws a warning and fails because it only handles IOVEC and UBUF iterators.  This can be triggered through a combination of cifs and a loopback blockdev with something like:  mount //my/cifs/share /foo dd if=/dev/zero of=/foo/m0 bs=4K count=1K losetup --sector-size 4096 --direct-io=on /dev/loop2046 /foo/m0 echo hello >/dev/loop2046  This causes the following to appear in syslog:  WARNING: CPU: 2 PID: 109 at fs/netfs/iterator.c:50 netfs_extract_user_iter+0x170/0x250 [netfs]  and the write to fail.  Fix this by removing the check in netfs_unbuffered_write_iter_locked() that causes async kernel DIO writes to be handled as userspace writes.  Note that this change relies on the kernel caller maintaining the existence of the bio_vec array (or kvec[] or folio_queue) until the op is complete.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21632?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2025--21632" src="https://img.shields.io/badge/CVE--2025--21632-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  x86/fpu: Ensure shadow stack is active before "getting" registers  The x86 shadow stack support has its own set of registers. Those registers are XSAVE-managed, but they are "supervisor state components" which means that userspace can not touch them with XSAVE/XRSTOR.  It also means that they are not accessible from the existing ptrace ABI for XSAVE state. Thus, there is a new ptrace get/set interface for it.  The regset code that ptrace uses provides an ->active() handler in addition to the get/set ones. For shadow stack this ->active() handler verifies that shadow stack is enabled via the ARCH_SHSTK_SHSTK bit in the thread struct. The ->active() handler is checked from some call sites of the regset get/set handlers, but not the ptrace ones. This was not understood when shadow stack support was put in place.  As a result, both the set/get handlers can be called with XFEATURE_CET_USER in its init state, which would cause get_xsave_addr() to return NULL and trigger a WARN_ON(). The ssp_set() handler luckily has an ssp_active() check to avoid surprising the kernel with shadow stack behavior when the kernel is not ready for it (ARCH_SHSTK_SHSTK==0). That check just happened to avoid the warning.  But the ->get() side wasn't so lucky. It can be called with shadow stacks disabled, triggering the warning in practice, as reported by Christina Schimpe:  WARNING: CPU: 5 PID: 1773 at arch/x86/kernel/fpu/regset.c:198 ssp_get+0x89/0xa0 [...] Call Trace: <TASK> ? show_regs+0x6e/0x80 ? ssp_get+0x89/0xa0 ? __warn+0x91/0x150 ? ssp_get+0x89/0xa0 ? report_bug+0x19d/0x1b0 ? handle_bug+0x46/0x80 ? exc_invalid_op+0x1d/0x80 ? asm_exc_invalid_op+0x1f/0x30 ? __pfx_ssp_get+0x10/0x10 ? ssp_get+0x89/0xa0 ? ssp_get+0x52/0xa0 __regset_get+0xad/0xf0 copy_regset_to_user+0x52/0xc0 ptrace_regset+0x119/0x140 ptrace_request+0x13c/0x850 ? wait_task_inactive+0x142/0x1d0 ? do_syscall_64+0x6d/0x90 arch_ptrace+0x102/0x300 [...]  Ensure that shadow stacks are active in a thread before looking them up in the XSAVE buffer. Since ARCH_SHSTK_SHSTK and user_ssp[SHSTK_EN] are set at the same time, the active check ensures that there will be something to find in the XSAVE buffer.  [ dhansen: changelog/subject tweaks ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58086?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58086" src="https://img.shields.io/badge/CVE--2024--58086-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/v3d: Stop active perfmon if it is being destroyed  If the active performance monitor (`v3d->active_perfmon`) is being destroyed, stop it first. Currently, the active perfmon is not stopped during destruction, leaving the `v3d->active_perfmon` pointer stale. This can lead to undefined behavior and instability.  This patch ensures that the active perfmon is stopped before being destroyed, aligning with the behavior introduced in commit 7d1fd3638ee3 ("drm/v3d: Stop the active perfmon before being destroyed").

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58085?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58085" src="https://img.shields.io/badge/CVE--2024--58085-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tomoyo: don't emit warning in tomoyo_write_control()  syzbot is reporting too large allocation warning at tomoyo_write_control(), for one can write a very very long line without new line character. To fix this warning, I use __GFP_NOWARN rather than checking for KMALLOC_MAX_SIZE, for practically a valid line should be always shorter than 32KB where the "too small to fail" memory-allocation rule applies.  One might try to write a valid line that is longer than 32KB, but such request will likely fail with -ENOMEM. Therefore, I feel that separately returning -EINVAL when a line is longer than KMALLOC_MAX_SIZE is redundant. There is no need to distinguish over-32KB and over-KMALLOC_MAX_SIZE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58083?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58083" src="https://img.shields.io/badge/CVE--2024--58083-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  KVM: Explicitly verify target vCPU is online in kvm_get_vcpu()  Explicitly verify the target vCPU is fully online _prior_ to clamping the index in kvm_get_vcpu().  If the index is "bad", the nospec clamping will generate '0', i.e. KVM will return vCPU0 instead of NULL.  In practice, the bug is unlikely to cause problems, as it will only come into play if userspace or the guest is buggy or misbehaving, e.g. KVM may send interrupts to vCPU0 instead of dropping them on the floor.  However, returning vCPU0 when it shouldn't exist per online_vcpus is problematic now that KVM uses an xarray for the vCPUs array, as KVM needs to insert into the xarray before publishing the vCPU to userspace (see commit c5b077549136 ("KVM: Convert the kvm->vcpus array to a xarray")), i.e. before vCPU creation is guaranteed to succeed.  As a result, incorrectly providing access to vCPU0 will trigger a use-after-free if vCPU0 is dereferenced and kvm_vm_ioctl_create_vcpu() bails out of vCPU creation due to an error and frees vCPU0.  Commit afb2acb2e3a3 ("KVM: Fix vcpu_array[0] races") papered over that issue, but in doing so introduced an unsolvable teardown conundrum.  Preventing accesses to vCPU0 before it's fully online will allow reverting commit afb2acb2e3a3, without re-introducing the vcpu_array[0] UAF race.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58082?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58082" src="https://img.shields.io/badge/CVE--2024--58082-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: nuvoton: Fix an error check in npcm_video_ece_init()  When function of_find_device_by_node() fails, it returns NULL instead of an error code. So the corresponding error check logic should be modified to check whether the return value is NULL and set the error code to be returned as -ENODEV.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58079?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58079" src="https://img.shields.io/badge/CVE--2024--58079-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: uvcvideo: Fix crash during unbind if gpio unit is in use  We used the wrong device for the device managed functions. We used the usb device, when we should be using the interface device.  If we unbind the driver from the usb interface, the cleanup functions are never called. In our case, the IRQ is never disabled.  If an IRQ is triggered, it will try to access memory sections that are already free, causing an OOPS.  We cannot use the function devm_request_threaded_irq here. The devm_* clean functions may be called after the main structure is released by uvc_delete.  Luckily this bug has small impact, as it is only affected by devices with gpio units and the user has to unbind the device, a disconnect will not trigger this error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58078?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58078" src="https://img.shields.io/badge/CVE--2024--58078-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  misc: misc_minor_alloc to use ida for all dynamic/misc dynamic minors  misc_minor_alloc was allocating id using ida for minor only in case of MISC_DYNAMIC_MINOR but misc_minor_free was always freeing ids using ida_free causing a mismatch and following warn: > > WARNING: CPU: 0 PID: 159 at lib/idr.c:525 ida_free+0x3e0/0x41f > > ida_free called for id=127 which is not allocated. > > <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<< ... > > [<60941eb4>] ida_free+0x3e0/0x41f > > [<605ac993>] misc_minor_free+0x3e/0xbc > > [<605acb82>] misc_deregister+0x171/0x1b3  misc_minor_alloc is changed to allocate id from ida for all minors falling in the range of dynamic/ misc dynamic minors

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58077?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58077" src="https://img.shields.io/badge/CVE--2024--58077-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: soc-pcm: don't use soc_pcm_ret() on .prepare callback  commit 1f5664351410 ("ASoC: lower "no backend DAIs enabled for ... Port" log severity") ignores -EINVAL error message on common soc_pcm_ret(). It is used from many functions, ignoring -EINVAL is over-kill.  The reason why -EINVAL was ignored was it really should only be used upon invalid parameters coming from userspace and in that case we don't want to log an error since we do not want to give userspace a way to do a denial-of-service attack on the syslog / diskspace.  So don't use soc_pcm_ret() on .prepare callback is better idea.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58072?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58072" src="https://img.shields.io/badge/CVE--2024--58072-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.079%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: rtlwifi: remove unused check_buddy_priv  Commit 2461c7d60f9f ("rtlwifi: Update header file") introduced a global list of private data structures.  Later on, commit 26634c4b1868 ("rtlwifi Modify existing bits to match vendor version 2013.02.07") started adding the private data to that list at probe time and added a hook, check_buddy_priv to find the private data from a similar device.  However, that function was never used.  Besides, though there is a lock for that list, it is never used. And when the probe fails, the private data is never removed from the list. This would cause a second probe to access freed memory.  Remove the unused hook, structures and members, which will prevent the potential race condition on the list and its corruption during a second probe when probe fails.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58061?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58061" src="https://img.shields.io/badge/CVE--2024--58061-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: mac80211: prohibit deactivating all links  In the internal API this calls this is a WARN_ON, but that should remain since internally we want to know about bugs that may cause this. Prevent deactivating all links in the debugfs write directly.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58057?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58057" src="https://img.shields.io/badge/CVE--2024--58057-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  idpf: convert workqueues to unbound  When a workqueue is created with `WQ_UNBOUND`, its work items are served by special worker-pools, whose host workers are not bound to any specific CPU. In the default configuration (i.e. when `queue_delayed_work` and friends do not specify which CPU to run the work item on), `WQ_UNBOUND` allows the work item to be executed on any CPU in the same node of the CPU it was enqueued on. While this solution potentially sacrifices locality, it avoids contention with other processes that might dominate the CPU time of the processor the work item was scheduled on.  This is not just a theoretical problem: in a particular scenario misconfigured process was hogging most of the time from CPU0, leaving less than 0.5% of its CPU time to the kworker. The IDPF workqueues that were using the kworker on CPU0 suffered large completion delays as a result, causing performance degradation, timeouts and eventual system crash.   * I have also run a manual test to gauge the performance improvement. The test consists of an antagonist process (`./stress --cpu 2`) consuming as much of CPU 0 as possible. This process is run under `taskset 01` to bind it to CPU0, and its priority is changed with `chrt -pQ 9900 10000 ${pid}` and `renice -n -20 ${pid}` after start.  Then, the IDPF driver is forced to prefer CPU0 by editing all calls to `queue_delayed_work`, `mod_delayed_work`, etc... to use CPU 0.  Finally, `ktraces` for the workqueue events are collected.  Without the current patch, the antagonist process can force arbitrary delays between `workqueue_queue_work` and `workqueue_execute_start`, that in my tests were as high as `30ms`. With the current patch applied, the workqueue can be migrated to another unloaded CPU in the same node, and, keeping everything else equal, the maximum delay I could see was `6us`.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58056?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58056" src="https://img.shields.io/badge/CVE--2024--58056-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  remoteproc: core: Fix ida_free call while not allocated  In the rproc_alloc() function, on error, put_device(&rproc->dev) is called, leading to the call of the rproc_type_release() function. An error can occurs before ida_alloc is called.  In such case in rproc_type_release(), the condition (rproc->index >= 0) is true as rproc->index has been  initialized to 0. ida_free() is called reporting a warning: [    4.181906] WARNING: CPU: 1 PID: 24 at lib/idr.c:525 ida_free+0x100/0x164 [    4.186378] stm32-display-dsi 5a000000.dsi: Fixed dependency cycle(s) with /soc/dsi@5a000000/panel@0 [    4.188854] ida_free called for id=0 which is not allocated. [    4.198256] mipi-dsi 5a000000.dsi.0: Fixed dependency cycle(s) with /soc/dsi@5a000000 [    4.203556] Modules linked in: panel_orisetech_otm8009a dw_mipi_dsi_stm(+) gpu_sched dw_mipi_dsi stm32_rproc stm32_crc32 stm32_ipcc(+) optee(+) [    4.224307] CPU: 1 UID: 0 PID: 24 Comm: kworker/u10:0 Not tainted 6.12.0 #442 [    4.231481] Hardware name: STM32 (Device Tree Support) [    4.236627] Workqueue: events_unbound deferred_probe_work_func [    4.242504] Call trace: [    4.242522]  unwind_backtrace from show_stack+0x10/0x14 [    4.250218]  show_stack from dump_stack_lvl+0x50/0x64 [    4.255274]  dump_stack_lvl from __warn+0x80/0x12c [    4.260134]  __warn from warn_slowpath_fmt+0x114/0x188 [    4.265199]  warn_slowpath_fmt from ida_free+0x100/0x164 [    4.270565]  ida_free from rproc_type_release+0x38/0x60 [    4.275832]  rproc_type_release from device_release+0x30/0xa0 [    4.281601]  device_release from kobject_put+0xc4/0x294 [    4.286762]  kobject_put from rproc_alloc.part.0+0x208/0x28c [    4.292430]  rproc_alloc.part.0 from devm_rproc_alloc+0x80/0xc4 [    4.298393]  devm_rproc_alloc from stm32_rproc_probe+0xd0/0x844 [stm32_rproc] [    4.305575]  stm32_rproc_probe [stm32_rproc] from platform_probe+0x5c/0xbc  Calling ida_alloc earlier in rproc_alloc ensures that the rproc->index is properly set.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58054?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58054" src="https://img.shields.io/badge/CVE--2024--58054-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  staging: media: max96712: fix kernel oops when removing module  The following kernel oops is thrown when trying to remove the max96712 module:  Unable to handle kernel paging request at virtual address 00007375746174db Mem abort info: ESR = 0x0000000096000004 EC = 0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x04: level 0 translation fault Data abort info: ISV = 0, ISS = 0x00000004, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess = 0 GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 user pgtable: 4k pages, 48-bit VAs, pgdp=000000010af89000 [00007375746174db] pgd=0000000000000000, p4d=0000000000000000 Internal error: Oops: 0000000096000004 [#1] PREEMPT SMP Modules linked in: crct10dif_ce polyval_ce mxc_jpeg_encdec flexcan snd_soc_fsl_sai snd_soc_fsl_asoc_card snd_soc_fsl_micfil dwc_mipi_csi2 imx_csi_formatter polyval_generic v4l2_jpeg imx_pcm_dma can_dev snd_soc_imx_audmux snd_soc_wm8962 snd_soc_imx_card snd_soc_fsl_utils max96712(C-) rpmsg_ctrl rpmsg_char pwm_fan fuse [last unloaded: imx8_isi] CPU: 0 UID: 0 PID: 754 Comm: rmmod Tainted: G         C    6.12.0-rc6-06364-g327fec852c31 #17 Tainted: [C]=CRAP Hardware name: NXP i.MX95 19X19 board (DT) pstate: 60400009 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : led_put+0x1c/0x40 lr : v4l2_subdev_put_privacy_led+0x48/0x58 sp : ffff80008699bbb0 x29: ffff80008699bbb0 x28: ffff00008ac233c0 x27: 0000000000000000 x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000 x23: ffff000080cf1170 x22: ffff00008b53bd00 x21: ffff8000822ad1c8 x20: ffff000080ff5c00 x19: ffff00008b53be40 x18: 0000000000000000 x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000 x14: 0000000000000004 x13: ffff0000800f8010 x12: 0000000000000000 x11: ffff000082acf5c0 x10: ffff000082acf478 x9 : ffff0000800f8010 x8 : 0101010101010101 x7 : 7f7f7f7f7f7f7f7f x6 : fefefeff6364626d x5 : 8080808000000000 x4 : 0000000000000020 x3 : 00000000553a3dc1 x2 : ffff00008ac233c0 x1 : ffff00008ac233c0 x0 : ff00737574617473 Call trace: led_put+0x1c/0x40 v4l2_subdev_put_privacy_led+0x48/0x58 v4l2_async_unregister_subdev+0x2c/0x1a4 max96712_remove+0x1c/0x38 [max96712] i2c_device_remove+0x2c/0x9c device_remove+0x4c/0x80 device_release_driver_internal+0x1cc/0x228 driver_detach+0x4c/0x98 bus_remove_driver+0x6c/0xbc driver_unregister+0x30/0x60 i2c_del_driver+0x54/0x64 max96712_i2c_driver_exit+0x18/0x1d0 [max96712] __arm64_sys_delete_module+0x1a4/0x290 invoke_syscall+0x48/0x10c el0_svc_common.constprop.0+0xc0/0xe0 do_el0_svc+0x1c/0x28 el0_svc+0x34/0xd8 el0t_64_sync_handler+0x120/0x12c el0t_64_sync+0x190/0x194 Code: f9000bf3 aa0003f3 f9402800 f9402000 (f9403400) ---[ end trace 0000000000000000 ]---  This happens because in v4l2_i2c_subdev_init(), the i2c_set_cliendata() is called again and the data is overwritten to point to sd, instead of priv. So, in remove(), the wrong pointer is passed to v4l2_async_unregister_subdev(), leading to a crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58053?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58053" src="https://img.shields.io/badge/CVE--2024--58053-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  rxrpc: Fix handling of received connection abort  Fix the handling of a connection abort that we've received.  Though the abort is at the connection level, it needs propagating to the calls on that connection.  Whilst the propagation bit is performed, the calls aren't then woken up to go and process their termination, and as no further input is forthcoming, they just hang.  Also add some tracing for the logging of connection aborts.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58051?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58051" src="https://img.shields.io/badge/CVE--2024--58051-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.106%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipmi: ipmb: Add check devm_kasprintf() returned value  devm_kasprintf() can return a NULL pointer on failure but this returned value is not checked.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58034?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58034" src="https://img.shields.io/badge/CVE--2024--58034-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  memory: tegra20-emc: fix an OF node reference bug in tegra_emc_find_node_by_ram_code()  As of_find_node_by_name() release the reference of the argument device node, tegra_emc_find_node_by_ram_code() releases some device nodes while still in use, resulting in possible UAFs. According to the bindings and the in-tree DTS files, the "emc-tables" node is always device's child node with the property "nvidia,use-ram-code", and the "lpddr2" node is a child of the "emc-tables" node. Thus utilize the for_each_child_of_node() macro and of_get_child_by_name() instead of of_find_node_by_name() to simplify the code.  This bug was found by an experimental verification tool that I am developing.  [krzysztof: applied v1, adjust the commit msg to incorporate v2 parts]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58019?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58019" src="https://img.shields.io/badge/CVE--2024--58019-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nvkm/gsp: correctly advance the read pointer of GSP message queue  A GSP event message consists three parts: message header, RPC header, message body. GSP calculates the number of pages to write from the total size of a GSP message. This behavior can be observed from the movement of the write pointer.  However, nvkm takes only the size of RPC header and message body as the message size when advancing the read pointer. When handling a two-page GSP message in the non rollback case, It wrongly takes the message body of the previous message as the message header of the next message. As the "message length" tends to be zero, in the calculation of size needs to be copied (0 - size of (message header)), the size needs to be copied will be "0xffffffxx". It also triggers a kernel panic due to a NULL pointer error.  [  547.614102] msg: 00000f90: ff ff ff ff ff ff ff ff 40 d7 18 fb 8b 00 00 00  ........@....... [  547.622533] msg: 00000fa0: 00 00 00 00 ff ff ff ff ff ff ff ff 00 00 00 00  ................ [  547.630965] msg: 00000fb0: ff ff ff ff ff ff ff ff 00 00 00 00 ff ff ff ff  ................ [  547.639397] msg: 00000fc0: ff ff ff ff 00 00 00 00 ff ff ff ff ff ff ff ff  ................ [  547.647832] nvkm 0000:c1:00.0: gsp: peek msg rpc fn:0 len:0x0/0xffffffffffffffe0 [  547.655225] nvkm 0000:c1:00.0: gsp: get msg rpc fn:0 len:0x0/0xffffffffffffffe0 [  547.662532] BUG: kernel NULL pointer dereference, address: 0000000000000020 [  547.669485] #PF: supervisor read access in kernel mode [  547.674624] #PF: error_code(0x0000) - not-present page [  547.679755] PGD 0 P4D 0 [  547.682294] Oops: 0000 [#1] PREEMPT SMP NOPTI [  547.686643] CPU: 22 PID: 322 Comm: kworker/22:1 Tainted: G            E 6.9.0-rc6+ #1 [  547.694893] Hardware name: ASRockRack 1U1G-MILAN/N/ROMED8-NL, BIOS L3.12E 09/06/2022 [  547.702626] Workqueue: events r535_gsp_msgq_work [nvkm] [  547.707921] RIP: 0010:r535_gsp_msg_recv+0x87/0x230 [nvkm] [  547.713375] Code: 00 8b 70 08 48 89 e1 31 d2 4c 89 f7 e8 12 f5 ff ff 48 89 c5 48 85 c0 0f 84 cf 00 00 00 48 81 fd 00 f0 ff ff 0f 87 c4 00 00 00 <8b> 55 10 41 8b 46 30 85 d2 0f 85 f6 00 00 00 83 f8 04 76 10 ba 05 [  547.732119] RSP: 0018:ffffabe440f87e10 EFLAGS: 00010203 [  547.737335] RAX: 0000000000000010 RBX: 0000000000000008 RCX: 000000000000003f [  547.744461] RDX: 0000000000000000 RSI: ffffabe4480a8030 RDI: 0000000000000010 [  547.751585] RBP: 0000000000000010 R08: 0000000000000000 R09: ffffabe440f87bb0 [  547.758707] R10: ffffabe440f87dc8 R11: 0000000000000010 R12: 0000000000000000 [  547.765834] R13: 0000000000000000 R14: ffff9351df1e5000 R15: 0000000000000000 [  547.772958] FS:  0000000000000000(0000) GS:ffff93708eb00000(0000) knlGS:0000000000000000 [  547.781035] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  547.786771] CR2: 0000000000000020 CR3: 00000003cc220002 CR4: 0000000000770ef0 [  547.793896] PKRU: 55555554 [  547.796600] Call Trace: [  547.799046]  <TASK> [  547.801152]  ? __die+0x20/0x70 [  547.804211]  ? page_fault_oops+0x75/0x170 [  547.808221]  ? print_hex_dump+0x100/0x160 [  547.812226]  ? exc_page_fault+0x64/0x150 [  547.816152]  ? asm_exc_page_fault+0x22/0x30 [  547.820341]  ? r535_gsp_msg_recv+0x87/0x230 [nvkm] [  547.825184]  r535_gsp_msgq_work+0x42/0x50 [nvkm] [  547.829845]  process_one_work+0x196/0x3d0 [  547.833861]  worker_thread+0x2fc/0x410 [  547.837613]  ? __pfx_worker_thread+0x10/0x10 [  547.841885]  kthread+0xdf/0x110 [  547.845031]  ? __pfx_kthread+0x10/0x10 [  547.848775]  ret_from_fork+0x30/0x50 [  547.852354]  ? __pfx_kthread+0x10/0x10 [  547.856097]  ret_from_fork_asm+0x1a/0x30 [  547.860019]  </TASK> [  547.862208] Modules linked in: nvkm(E) gsp_log(E) snd_seq_dummy(E) snd_hrtimer(E) snd_seq(E) snd_timer(E) snd_seq_device(E) snd(E) soundcore(E) rfkill(E) qrtr(E) vfat(E) fat(E) ipmi_ssif(E) amd_atl(E) intel_rapl_msr(E) intel_rapl_common(E) amd64_edac(E) mlx5_ib(E) edac_mce_amd(E) kvm_amd ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58018?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58018" src="https://img.shields.io/badge/CVE--2024--58018-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nvkm: correctly calculate the available space of the GSP cmdq buffer  r535_gsp_cmdq_push() waits for the available page in the GSP cmdq buffer when handling a large RPC request. When it sees at least one available page in the cmdq, it quits the waiting with the amount of free buffer pages in the queue.  Unfortunately, it always takes the [write pointer, buf_size) as available buffer pages before rolling back and wrongly calculates the size of the data should be copied. Thus, it can overwrite the RPC request that GSP is currently reading, which causes GSP hang due to corrupted RPC request:  [  549.209389] ------------[ cut here ]------------ [  549.214010] WARNING: CPU: 8 PID: 6314 at drivers/gpu/drm/nouveau/nvkm/subdev/gsp/r535.c:116 r535_gsp_msgq_wait+0xd0/0x190 [nvkm] [  549.225678] Modules linked in: nvkm(E+) gsp_log(E) snd_seq_dummy(E) snd_hrtimer(E) snd_seq(E) snd_timer(E) snd_seq_device(E) snd(E) soundcore(E) rfkill(E) qrtr(E) vfat(E) fat(E) ipmi_ssif(E) amd_atl(E) intel_rapl_msr(E) intel_rapl_common(E) mlx5_ib(E) amd64_edac(E) edac_mce_amd(E) kvm_amd(E) ib_uverbs(E) kvm(E) ib_core(E) acpi_ipmi(E) ipmi_si(E) mxm_wmi(E) ipmi_devintf(E) rapl(E) i2c_piix4(E) wmi_bmof(E) joydev(E) ptdma(E) acpi_cpufreq(E) k10temp(E) pcspkr(E) ipmi_msghandler(E) xfs(E) libcrc32c(E) ast(E) i2c_algo_bit(E) crct10dif_pclmul(E) drm_shmem_helper(E) nvme_tcp(E) crc32_pclmul(E) ahci(E) drm_kms_helper(E) libahci(E) nvme_fabrics(E) crc32c_intel(E) nvme(E) cdc_ether(E) mlx5_core(E) nvme_core(E) usbnet(E) drm(E) libata(E) ccp(E) ghash_clmulni_intel(E) mii(E) t10_pi(E) mlxfw(E) sp5100_tco(E) psample(E) pci_hyperv_intf(E) wmi(E) dm_multipath(E) sunrpc(E) dm_mirror(E) dm_region_hash(E) dm_log(E) dm_mod(E) be2iscsi(E) bnx2i(E) cnic(E) uio(E) cxgb4i(E) cxgb4(E) tls(E) libcxgbi(E) libcxgb(E) qla4xxx(E) [  549.225752]  iscsi_boot_sysfs(E) iscsi_tcp(E) libiscsi_tcp(E) libiscsi(E) scsi_transport_iscsi(E) fuse(E) [last unloaded: gsp_log(E)] [  549.326293] CPU: 8 PID: 6314 Comm: insmod Tainted: G            E 6.9.0-rc6+ #1 [  549.334039] Hardware name: ASRockRack 1U1G-MILAN/N/ROMED8-NL, BIOS L3.12E 09/06/2022 [  549.341781] RIP: 0010:r535_gsp_msgq_wait+0xd0/0x190 [nvkm] [  549.347343] Code: 08 00 00 89 da c1 e2 0c 48 8d ac 11 00 10 00 00 48 8b 0c 24 48 85 c9 74 1f c1 e0 0c 4c 8d 6d 30 83 e8 30 89 01 e9 68 ff ff ff <0f> 0b 49 c7 c5 92 ff ff ff e9 5a ff ff ff ba ff ff ff ff be c0 0c [  549.366090] RSP: 0018:ffffacbccaaeb7d0 EFLAGS: 00010246 [  549.371315] RAX: 0000000000000000 RBX: 0000000000000012 RCX: 0000000000923e28 [  549.378451] RDX: 0000000000000000 RSI: 0000000055555554 RDI: ffffacbccaaeb730 [  549.385590] RBP: 0000000000000001 R08: ffff8bd14d235f70 R09: ffff8bd14d235f70 [  549.392721] R10: 0000000000000002 R11: ffff8bd14d233864 R12: 0000000000000020 [  549.399854] R13: ffffacbccaaeb818 R14: 0000000000000020 R15: ffff8bb298c67000 [  549.406988] FS:  00007f5179244740(0000) GS:ffff8bd14d200000(0000) knlGS:0000000000000000 [  549.415076] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  549.420829] CR2: 00007fa844000010 CR3: 00000001567dc005 CR4: 0000000000770ef0 [  549.427963] PKRU: 55555554 [  549.430672] Call Trace: [  549.433126]  <TASK> [  549.435233]  ? __warn+0x7f/0x130 [  549.438473]  ? r535_gsp_msgq_wait+0xd0/0x190 [nvkm] [  549.443426]  ? report_bug+0x18a/0x1a0 [  549.447098]  ? handle_bug+0x3c/0x70 [  549.450589]  ? exc_invalid_op+0x14/0x70 [  549.454430]  ? asm_exc_invalid_op+0x16/0x20 [  549.458619]  ? r535_gsp_msgq_wait+0xd0/0x190 [nvkm] [  549.463565]  r535_gsp_msg_recv+0x46/0x230 [nvkm] [  549.468257]  r535_gsp_rpc_push+0x106/0x160 [nvkm] [  549.473033]  r535_gsp_rpc_rm_ctrl_push+0x40/0x130 [nvkm] [  549.478422]  nvidia_grid_init_vgpu_types+0xbc/0xe0 [nvkm] [  549.483899]  nvidia_grid_init+0xb1/0xd0 [nvkm] [  549.488420]  ? srso_alias_return_thunk+0x5/0xfbef5 [  549.493213]  nvkm_device_pci_probe+0x305/0x420 [nvkm] [  549.498338]  local_pci_probe+0x46/ ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58016?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58016" src="https://img.shields.io/badge/CVE--2024--58016-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.078%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  safesetid: check size of policy writes  syzbot attempts to write a buffer with a large size to a sysfs entry with writes handled by handle_policy_update(), triggering a warning in kmalloc.  Check the size specified for write buffers before allocating.  [PM: subject tweak]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58015?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58015" src="https://img.shields.io/badge/CVE--2024--58015-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: ath12k: Fix for out-of bound access error  Selfgen stats are placed in a buffer using print_array_to_buf_index() function. Array length parameter passed to the function is too big, resulting in possible out-of bound memory error. Decreasing buffer size by one fixes faulty upper bound of passed array.  Discovered in coverity scan, CID 1600742 and CID 1600758

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58014?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58014" src="https://img.shields.io/badge/CVE--2024--58014-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: brcmsmac: add gain range check to wlc_phy_iqcal_gainparams_nphy()  In 'wlc_phy_iqcal_gainparams_nphy()', add gain range check to WARN() instead of possible out-of-bounds 'tbl_iqcal_gainparams_nphy' access. Compile tested only.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58013?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58013" src="https://img.shields.io/badge/CVE--2024--58013-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: MGMT: Fix slab-use-after-free Read in mgmt_remove_adv_monitor_sync  This fixes the following crash:  ================================================================== BUG: KASAN: slab-use-after-free in mgmt_remove_adv_monitor_sync+0x3a/0xd0 net/bluetooth/mgmt.c:5543 Read of size 8 at addr ffff88814128f898 by task kworker/u9:4/5961  CPU: 1 UID: 0 PID: 5961 Comm: kworker/u9:4 Not tainted 6.12.0-syzkaller-10684-gf1cd565ce577 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Workqueue: hci0 hci_cmd_sync_work Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x169/0x550 mm/kasan/report.c:489 kasan_report+0x143/0x180 mm/kasan/report.c:602 mgmt_remove_adv_monitor_sync+0x3a/0xd0 net/bluetooth/mgmt.c:5543 hci_cmd_sync_work+0x22b/0x400 net/bluetooth/hci_sync.c:332 process_one_work kernel/workqueue.c:3229 [inline] process_scheduled_works+0xa63/0x1850 kernel/workqueue.c:3310 worker_thread+0x870/0xd30 kernel/workqueue.c:3391 kthread+0x2f0/0x390 kernel/kthread.c:389 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK>  Allocated by task 16026: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68 poison_kmalloc_redzone mm/kasan/common.c:377 [inline] __kasan_kmalloc+0x98/0xb0 mm/kasan/common.c:394 kasan_kmalloc include/linux/kasan.h:260 [inline] __kmalloc_cache_noprof+0x243/0x390 mm/slub.c:4314 kmalloc_noprof include/linux/slab.h:901 [inline] kzalloc_noprof include/linux/slab.h:1037 [inline] mgmt_pending_new+0x65/0x250 net/bluetooth/mgmt_util.c:269 mgmt_pending_add+0x36/0x120 net/bluetooth/mgmt_util.c:296 remove_adv_monitor+0x102/0x1b0 net/bluetooth/mgmt.c:5568 hci_mgmt_cmd+0xc47/0x11d0 net/bluetooth/hci_sock.c:1712 hci_sock_sendmsg+0x7b8/0x11c0 net/bluetooth/hci_sock.c:1832 sock_sendmsg_nosec net/socket.c:711 [inline] __sock_sendmsg+0x221/0x270 net/socket.c:726 sock_write_iter+0x2d7/0x3f0 net/socket.c:1147 new_sync_write fs/read_write.c:586 [inline] vfs_write+0xaeb/0xd30 fs/read_write.c:679 ksys_write+0x18f/0x2b0 fs/read_write.c:731 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  Freed by task 16022: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68 kasan_save_free_info+0x40/0x50 mm/kasan/generic.c:582 poison_slab_object mm/kasan/common.c:247 [inline] __kasan_slab_free+0x59/0x70 mm/kasan/common.c:264 kasan_slab_free include/linux/kasan.h:233 [inline] slab_free_hook mm/slub.c:2338 [inline] slab_free mm/slub.c:4598 [inline] kfree+0x196/0x420 mm/slub.c:4746 mgmt_pending_foreach+0xd1/0x130 net/bluetooth/mgmt_util.c:259 __mgmt_power_off+0x183/0x430 net/bluetooth/mgmt.c:9550 hci_dev_close_sync+0x6c4/0x11c0 net/bluetooth/hci_sync.c:5208 hci_dev_do_close net/bluetooth/hci_core.c:483 [inline] hci_dev_close+0x112/0x210 net/bluetooth/hci_core.c:508 sock_do_ioctl+0x158/0x460 net/socket.c:1209 sock_ioctl+0x626/0x8e0 net/socket.c:1328 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:906 [inline] __se_sys_ioctl+0xf5/0x170 fs/ioctl.c:892 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58006?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58006" src="https://img.shields.io/badge/CVE--2024--58006-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  PCI: dwc: ep: Prevent changing BAR size/flags in pci_epc_set_bar()  In commit 4284c88fff0e ("PCI: designware-ep: Allow pci_epc_set_bar() update inbound map address") set_bar() was modified to support dynamically changing the backing physical address of a BAR that was already configured.  This means that set_bar() can be called twice, without ever calling clear_bar() (as calling clear_bar() would clear the BAR's PCI address assigned by the host).  This can only be done if the new BAR size/flags does not differ from the existing BAR configuration. Add these missing checks.  If we allow set_bar() to set e.g. a new BAR size that differs from the existing BAR size, the new address translation range will be smaller than the BAR size already determined by the host, which would mean that a read past the new BAR size would pass the iATU untranslated, which could allow the host to read memory not belonging to the new struct pci_epf_bar.  While at it, add comments which clarifies the support for dynamically changing the physical address of a BAR. (Which was also missing.)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58003?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58003" src="https://img.shields.io/badge/CVE--2024--58003-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: i2c: ds90ub9x3: Fix extra fwnode_handle_put()  The ub913 and ub953 drivers call fwnode_handle_put(priv->sd.fwnode) as part of their remove process, and if the driver is removed multiple times, eventually leads to put "overflow", possibly causing memory corruption or crash.  The fwnode_handle_put() is a leftover from commit 905f88ccebb1 ("media: i2c: ds90ub9x3: Fix sub-device matching"), which changed the code related to the sd.fwnode, but missed removing these fwnode_handle_put() calls.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58001?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--58001" src="https://img.shields.io/badge/CVE--2024--58001-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.086%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ocfs2: handle a symlink read error correctly  Patch series "Convert ocfs2 to use folios".  Mark did a conversion of ocfs2 to use folios and sent it to me as a giant patch for review ;-)  So I've redone it as individual patches, and credited Mark for the patches where his code is substantially the same.  It's not a bad way to do it; his patch had some bugs and my patches had some bugs.  Hopefully all our bugs were different from each other.  And hopefully Mark likes all the changes I made to his code!   This patch (of 23):  If we can't read the buffer, be sure to unlock the page before returning.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57999?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57999" src="https://img.shields.io/badge/CVE--2024--57999-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  powerpc/pseries/iommu: IOMMU incorrectly marks MMIO range in DDW  Power Hypervisor can possibily allocate MMIO window intersecting with Dynamic DMA Window (DDW) range, which is over 32-bit addressing.  These MMIO pages needs to be marked as reserved so that IOMMU doesn't map DMA buffers in this range.  The current code is not marking these pages correctly which is resulting in LPAR to OOPS while booting. The stack is at below  BUG: Unable to handle kernel data access on read at 0xc00800005cd40000 Faulting instruction address: 0xc00000000005cdac Oops: Kernel access of bad area, sig: 11 [#1] LE PAGE_SIZE=64K MMU=Hash SMP NR_CPUS=2048 NUMA pSeries Modules linked in: af_packet rfkill ibmveth(X) lpfc(+) nvmet_fc nvmet nvme_keyring crct10dif_vpmsum nvme_fc nvme_fabrics nvme_core be2net(+) nvme_auth rtc_generic nfsd auth_rpcgss nfs_acl lockd grace sunrpc fuse configfs ip_tables x_tables xfs libcrc32c dm_service_time ibmvfc(X) scsi_transport_fc vmx_crypto gf128mul crc32c_vpmsum dm_mirror dm_region_hash dm_log dm_multipath dm_mod sd_mod scsi_dh_emc scsi_dh_rdac scsi_dh_alua t10_pi crc64_rocksoft_generic crc64_rocksoft sg crc64 scsi_mod Supported: Yes, External CPU: 8 PID: 241 Comm: kworker/8:1 Kdump: loaded Not tainted 6.4.0-150600.23.14-default #1 SLE15-SP6 b44ee71c81261b9e4bab5e0cde1f2ed891d5359b Hardware name: IBM,9080-M9S POWER9 (raw) 0x4e2103 0xf000005 of:IBM,FW950.B0 (VH950_149) hv:phyp pSeries Workqueue: events work_for_cpu_fn NIP:  c00000000005cdac LR: c00000000005e830 CTR: 0000000000000000 REGS: c00001400c9ff770 TRAP: 0300   Not tainted (6.4.0-150600.23.14-default) MSR:  800000000280b033 <SF,VEC,VSX,EE,FP,ME,IR,DR,RI,LE>  CR: 24228448 XER: 00000001 CFAR: c00000000005cdd4 DAR: c00800005cd40000 DSISR: 40000000 IRQMASK: 0 GPR00: c00000000005e830 c00001400c9ffa10 c000000001987d00 c00001400c4fe800 GPR04: 0000080000000000 0000000000000001 0000000004000000 0000000000800000 GPR08: 0000000004000000 0000000000000001 c00800005cd40000 ffffffffffffffff GPR12: 0000000084228882 c00000000a4c4f00 0000000000000010 0000080000000000 GPR16: c00001400c4fe800 0000000004000000 0800000000000000 c00000006088b800 GPR20: c00001401a7be980 c00001400eff3800 c000000002a2da68 000000000000002b GPR24: c0000000026793a8 c000000002679368 000000000000002a c0000000026793c8 GPR28: 000008007effffff 0000080000000000 0000000000800000 c00001400c4fe800 NIP [c00000000005cdac] iommu_table_reserve_pages+0xac/0x100 LR [c00000000005e830] iommu_init_table+0x80/0x1e0 Call Trace: [c00001400c9ffa10] [c00000000005e810] iommu_init_table+0x60/0x1e0 (unreliable) [c00001400c9ffa90] [c00000000010356c] iommu_bypass_supported_pSeriesLP+0x9cc/0xe40 [c00001400c9ffc30] [c00000000005c300] dma_iommu_dma_supported+0xf0/0x230 [c00001400c9ffcb0] [c00000000024b0c4] dma_supported+0x44/0x90 [c00001400c9ffcd0] [c00000000024b14c] dma_set_mask+0x3c/0x80 [c00001400c9ffd00] [c0080000555b715c] be_probe+0xc4/0xb90 [be2net] [c00001400c9ffdc0] [c000000000986f3c] local_pci_probe+0x6c/0x110 [c00001400c9ffe40] [c000000000188f28] work_for_cpu_fn+0x38/0x60 [c00001400c9ffe70] [c00000000018e454] process_one_work+0x314/0x620 [c00001400c9fff10] [c00000000018f280] worker_thread+0x2b0/0x620 [c00001400c9fff90] [c00000000019bb18] kthread+0x148/0x150 [c00001400c9fffe0] [c00000000000ded8] start_kernel_thread+0x14/0x18  There are 2 issues in the code  1. The index is "int" while the address is "unsigned long". This results in negative value when setting the bitmap.  2. The DMA offset is page shifted but the MMIO range is used as-is (64-bit address). MMIO address needs to be page shifted as well.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57998?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57998" src="https://img.shields.io/badge/CVE--2024--57998-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.050%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  OPP: add index check to assert to avoid buffer overflow in _read_freq()  Pass the freq index to the assert function to make sure we do not read a freq out of the opp->rates[] table when called from the indexed variants: dev_pm_opp_find_freq_exact_indexed() or dev_pm_opp_find_freq_ceil/floor_indexed().  Add a secondary parameter to the assert function, unused for assert_single_clk() then add assert_clk_index() which will check for the clock index when called from the _indexed() find functions.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57994?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57994" src="https://img.shields.io/badge/CVE--2024--57994-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ptr_ring: do not block hard interrupts in ptr_ring_resize_multiple()  Jakub added a lockdep_assert_no_hardirq() check in __page_pool_put_page() to increase test coverage.  syzbot found a splat caused by hard irq blocking in ptr_ring_resize_multiple() [1]  As current users of ptr_ring_resize_multiple() do not require hard irqs being masked, replace it to only block BH.  Rename helpers to better reflect they are safe against BH only.  - ptr_ring_resize_multiple() to ptr_ring_resize_multiple_bh() - skb_array_resize_multiple() to skb_array_resize_multiple_bh()  [1]  WARNING: CPU: 1 PID: 9150 at net/core/page_pool.c:709 __page_pool_put_page net/core/page_pool.c:709 [inline] WARNING: CPU: 1 PID: 9150 at net/core/page_pool.c:709 page_pool_put_unrefed_netmem+0x157/0xa40 net/core/page_pool.c:780 Modules linked in: CPU: 1 UID: 0 PID: 9150 Comm: syz.1.1052 Not tainted 6.11.0-rc3-syzkaller-00202-gf8669d7b5f5d #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 08/06/2024 RIP: 0010:__page_pool_put_page net/core/page_pool.c:709 [inline] RIP: 0010:page_pool_put_unrefed_netmem+0x157/0xa40 net/core/page_pool.c:780 Code: 74 0e e8 7c aa fb f7 eb 43 e8 75 aa fb f7 eb 3c 65 8b 1d 38 a8 6a 76 31 ff 89 de e8 a3 ae fb f7 85 db 74 0b e8 5a aa fb f7 90 <0f> 0b 90 eb 1d 65 8b 1d 15 a8 6a 76 31 ff 89 de e8 84 ae fb f7 85 RSP: 0018:ffffc9000bda6b58 EFLAGS: 00010083 RAX: ffffffff8997e523 RBX: 0000000000000000 RCX: 0000000000040000 RDX: ffffc9000fbd0000 RSI: 0000000000001842 RDI: 0000000000001843 RBP: 0000000000000000 R08: ffffffff8997df2c R09: 1ffffd40003a000d R10: dffffc0000000000 R11: fffff940003a000e R12: ffffea0001d00040 R13: ffff88802e8a4000 R14: dffffc0000000000 R15: 00000000ffffffff FS:  00007fb7aaf716c0(0000) GS:ffff8880b9300000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fa15a0d4b72 CR3: 00000000561b0000 CR4: 00000000003506f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> tun_ptr_free drivers/net/tun.c:617 [inline] __ptr_ring_swap_queue include/linux/ptr_ring.h:571 [inline] ptr_ring_resize_multiple_noprof include/linux/ptr_ring.h:643 [inline] tun_queue_resize drivers/net/tun.c:3694 [inline] tun_device_event+0xaaf/0x1080 drivers/net/tun.c:3714 notifier_call_chain+0x19f/0x3e0 kernel/notifier.c:93 call_netdevice_notifiers_extack net/core/dev.c:2032 [inline] call_netdevice_notifiers net/core/dev.c:2046 [inline] dev_change_tx_queue_len+0x158/0x2a0 net/core/dev.c:9024 do_setlink+0xff6/0x41f0 net/core/rtnetlink.c:2923 rtnl_setlink+0x40d/0x5a0 net/core/rtnetlink.c:3201 rtnetlink_rcv_msg+0x73f/0xcf0 net/core/rtnetlink.c:6647 netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2550

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57993?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57993" src="https://img.shields.io/badge/CVE--2024--57993-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.050%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  HID: hid-thrustmaster: Fix warning in thrustmaster_probe by adding endpoint check  syzbot has found a type mismatch between a USB pipe and the transfer endpoint, which is triggered by the hid-thrustmaster driver[1]. There is a number of similar, already fixed issues [2]. In this case as in others, implementing check for endpoint type fixes the issue.  [1] https://syzkaller.appspot.com/bug?extid=040e8b3db6a96908d470 [2] https://syzkaller.appspot.com/bug?extid=348331f63b034f89b622

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57986?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57986" src="https://img.shields.io/badge/CVE--2024--57986-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.086%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  HID: core: Fix assumption that Resolution Multipliers must be in Logical Collections  A report in 2019 by the syzbot fuzzer was found to be connected to two errors in the HID core associated with Resolution Multipliers.  One of the errors was fixed by commit ea427a222d8b ("HID: core: Fix deadloop in hid_apply_multiplier."), but the other has not been fixed.  This error arises because hid_apply_multipler() assumes that every Resolution Multiplier control is contained in a Logical Collection, i.e., there's no way the routine can ever set multiplier_collection to NULL.  This is in spite of the fact that the function starts with a big comment saying:  * "The Resolution Multiplier control must be contained in the same * Logical Collection as the control(s) to which it is to be applied. ... *  If no Logical Collection is * defined, the Resolution Multiplier is associated with all * controls in the report." * HID Usage Table, v1.12, Section 4.3.1, p30 * * Thus, search from the current collection upwards until we find a * logical collection...  The comment and the code overlook the possibility that none of the collections found may be a Logical Collection.  The fix is to set the multiplier_collection pointer to NULL if the collection found isn't a Logical Collection.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57984?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57984" src="https://img.shields.io/badge/CVE--2024--57984-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  i3c: dw: Fix use-after-free in dw_i3c_master driver due to race condition  In dw_i3c_common_probe, &master->hj_work is bound with dw_i3c_hj_work. And dw_i3c_master_irq_handler can call dw_i3c_master_irq_handle_ibis function to start the work.  If we remove the module which will call dw_i3c_common_remove to make cleanup, it will free master->base through i3c_master_unregister while the work mentioned above will be used. The sequence of operations that may lead to a UAF bug is as follows:  CPU0                                      CPU1  | dw_i3c_hj_work dw_i3c_common_remove                 | i3c_master_unregister(&master->base) | device_unregister(&master->dev)      | device_release                       | //free master->base                  | | i3c_master_do_daa(&master->base) | //use master->base  Fix it by ensuring that the work is canceled before proceeding with the cleanup in dw_i3c_common_remove.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57979?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57979" src="https://img.shields.io/badge/CVE--2024--57979-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pps: Fix a use-after-free  On a board running ntpd and gpsd, I'm seeing a consistent use-after-free in sys_exit() from gpsd when rebooting:  pps pps1: removed ------------[ cut here ]------------ kobject: '(null)' (00000000db4bec24): is not initialized, yet kobject_put() is being called. WARNING: CPU: 2 PID: 440 at lib/kobject.c:734 kobject_put+0x120/0x150 CPU: 2 UID: 299 PID: 440 Comm: gpsd Not tainted 6.11.0-rc6-00308-gb31c44928842 #1 Hardware name: Raspberry Pi 4 Model B Rev 1.1 (DT) pstate: 60000005 (nZCv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : kobject_put+0x120/0x150 lr : kobject_put+0x120/0x150 sp : ffffffc0803d3ae0 x29: ffffffc0803d3ae0 x28: ffffff8042dc9738 x27: 0000000000000001 x26: 0000000000000000 x25: ffffff8042dc9040 x24: ffffff8042dc9440 x23: ffffff80402a4620 x22: ffffff8042ef4bd0 x21: ffffff80405cb600 x20: 000000000008001b x19: ffffff8040b3b6e0 x18: 0000000000000000 x17: 0000000000000000 x16: 0000000000000000 x15: 696e6920746f6e20 x14: 7369203a29343263 x13: 205d303434542020 x12: 0000000000000000 x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000 x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000 x5 : 0000000000000000 x4 : 0000000000000000 x3 : 0000000000000000 x2 : 0000000000000000 x1 : 0000000000000000 x0 : 0000000000000000 Call trace: kobject_put+0x120/0x150 cdev_put+0x20/0x3c __fput+0x2c4/0x2d8 ____fput+0x1c/0x38 task_work_run+0x70/0xfc do_exit+0x2a0/0x924 do_group_exit+0x34/0x90 get_signal+0x7fc/0x8c0 do_signal+0x128/0x13b4 do_notify_resume+0xdc/0x160 el0_svc+0xd4/0xf8 el0t_64_sync_handler+0x140/0x14c el0t_64_sync+0x190/0x194 ---[ end trace 0000000000000000 ]---  ...followed by more symptoms of corruption, with similar stacks:  refcount_t: underflow; use-after-free. kernel BUG at lib/list_debug.c:62! Kernel panic - not syncing: Oops - BUG: Fatal exception  This happens because pps_device_destruct() frees the pps_device with the embedded cdev immediately after calling cdev_del(), but, as the comment above cdev_del() notes, fops for previously opened cdevs are still callable even after cdev_del() returns. I think this bug has always been there: I can't explain why it suddenly started happening every time I reboot this particular board.  In commit d953e0e837e6 ("pps: Fix a use-after free bug when unregistering a source."), George Spelvin suggested removing the embedded cdev. That seems like the simplest way to fix this, so I've implemented his suggestion, using __register_chrdev() with pps_idr becoming the source of truth for which minor corresponds to which device.  But now that pps_idr defines userspace visibility instead of cdev_add(), we need to be sure the pps->dev refcount can't reach zero while userspace can still find it again. So, the idr_remove() call moves to pps_unregister_cdev(), and pps_idr now holds a reference to pps->dev.  pps_core: source serial1 got cdev (251:1) <...> pps pps1: removed pps_core: unregistering pps1 pps_core: deallocating pps1

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57976?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57976" src="https://img.shields.io/badge/CVE--2024--57976-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: do proper folio cleanup when cow_file_range() failed  [BUG] When testing with COW fixup marked as BUG_ON() (this is involved with the new pin_user_pages*() change, which should not result new out-of-band dirty pages), I hit a crash triggered by the BUG_ON() from hitting COW fixup path.  This BUG_ON() happens just after a failed btrfs_run_delalloc_range():  BTRFS error (device dm-2): failed to run delalloc range, root 348 ino 405 folio 65536 submit_bitmap 6-15 start 90112 len 106496: -28 ------------[ cut here ]------------ kernel BUG at fs/btrfs/extent_io.c:1444! Internal error: Oops - BUG: 00000000f2000800 [#1] SMP CPU: 0 UID: 0 PID: 434621 Comm: kworker/u24:8 Tainted: G           OE 6.12.0-rc7-custom+ #86 Hardware name: QEMU KVM Virtual Machine, BIOS unknown 2/2/2022 Workqueue: events_unbound btrfs_async_reclaim_data_space [btrfs] pc : extent_writepage_io+0x2d4/0x308 [btrfs] lr : extent_writepage_io+0x2d4/0x308 [btrfs] Call trace: extent_writepage_io+0x2d4/0x308 [btrfs] extent_writepage+0x218/0x330 [btrfs] extent_write_cache_pages+0x1d4/0x4b0 [btrfs] btrfs_writepages+0x94/0x150 [btrfs] do_writepages+0x74/0x190 filemap_fdatawrite_wbc+0x88/0xc8 start_delalloc_inodes+0x180/0x3b0 [btrfs] btrfs_start_delalloc_roots+0x174/0x280 [btrfs] shrink_delalloc+0x114/0x280 [btrfs] flush_space+0x250/0x2f8 [btrfs] btrfs_async_reclaim_data_space+0x180/0x228 [btrfs] process_one_work+0x164/0x408 worker_thread+0x25c/0x388 kthread+0x100/0x118 ret_from_fork+0x10/0x20 Code: aa1403e1 9402f3ef aa1403e0 9402f36f (d4210000) ---[ end trace 0000000000000000 ]---  [CAUSE] That failure is mostly from cow_file_range(), where we can hit -ENOSPC.  Although the -ENOSPC is already a bug related to our space reservation code, let's just focus on the error handling.  For example, we have the following dirty range [0, 64K) of an inode, with 4K sector size and 4K page size:  0        16K        32K       48K       64K |///////////////////////////////////////| |#######################################|  Where |///| means page are still dirty, and |###| means the extent io tree has EXTENT_DELALLOC flag.  - Enter extent_writepage() for page 0  - Enter btrfs_run_delalloc_range() for range [0, 64K)  - Enter cow_file_range() for range [0, 64K)  - Function btrfs_reserve_extent() only reserved one 16K extent So we created extent map and ordered extent for range [0, 16K)  0        16K        32K       48K       64K |////////|//////////////////////////////| |<- OE ->|##############################|  And range [0, 16K) has its delalloc flag cleared. But since we haven't yet submit any bio, involved 4 pages are still dirty.  - Function btrfs_reserve_extent() returns with -ENOSPC Now we have to run error cleanup, which will clear all EXTENT_DELALLOC* flags and clear the dirty flags for the remaining ranges:  0        16K        32K       48K       64K |////////|                              | |        |                              |  Note that range [0, 16K) still has its pages dirty.  - Some time later, writeback is triggered again for the range [0, 16K) since the page range still has dirty flags.  - btrfs_run_delalloc_range() will do nothing because there is no EXTENT_DELALLOC flag.  - extent_writepage_io() finds page 0 has no ordered flag Which falls into the COW fixup path, triggering the BUG_ON().  Unfortunately this error handling bug dates back to the introduction of btrfs.  Thankfully with the abuse of COW fixup, at least it won't crash the kernel.  [FIX] Instead of immediately unlocking the extent and folios, we keep the extent and folios locked until either erroring out or the whole delalloc range finished.  When the whole delalloc range finished without error, we just unlock the whole range with PAGE_SET_ORDERED (and PAGE_UNLOCK for !keep_locked cases) ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57975?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57975" src="https://img.shields.io/badge/CVE--2024--57975-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: do proper folio cleanup when run_delalloc_nocow() failed  [BUG] With CONFIG_DEBUG_VM set, test case generic/476 has some chance to crash with the following VM_BUG_ON_FOLIO():  BTRFS error (device dm-3): cow_file_range failed, start 1146880 end 1253375 len 106496 ret -28 BTRFS error (device dm-3): run_delalloc_nocow failed, start 1146880 end 1253375 len 106496 ret -28 page: refcount:4 mapcount:0 mapping:00000000592787cc index:0x12 pfn:0x10664 aops:btrfs_aops [btrfs] ino:101 dentry name(?):"f1774" flags: 0x2fffff80004028(uptodate|lru|private|node=0|zone=2|lastcpupid=0xfffff) page dumped because: VM_BUG_ON_FOLIO(!folio_test_locked(folio)) ------------[ cut here ]------------ kernel BUG at mm/page-writeback.c:2992! Internal error: Oops - BUG: 00000000f2000800 [#1] SMP CPU: 2 UID: 0 PID: 3943513 Comm: kworker/u24:15 Tainted: G           OE 6.12.0-rc7-custom+ #87 Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE Hardware name: QEMU KVM Virtual Machine, BIOS unknown 2/2/2022 Workqueue: events_unbound btrfs_async_reclaim_data_space [btrfs] pc : folio_clear_dirty_for_io+0x128/0x258 lr : folio_clear_dirty_for_io+0x128/0x258 Call trace: folio_clear_dirty_for_io+0x128/0x258 btrfs_folio_clamp_clear_dirty+0x80/0xd0 [btrfs] __process_folios_contig+0x154/0x268 [btrfs] extent_clear_unlock_delalloc+0x5c/0x80 [btrfs] run_delalloc_nocow+0x5f8/0x760 [btrfs] btrfs_run_delalloc_range+0xa8/0x220 [btrfs] writepage_delalloc+0x230/0x4c8 [btrfs] extent_writepage+0xb8/0x358 [btrfs] extent_write_cache_pages+0x21c/0x4e8 [btrfs] btrfs_writepages+0x94/0x150 [btrfs] do_writepages+0x74/0x190 filemap_fdatawrite_wbc+0x88/0xc8 start_delalloc_inodes+0x178/0x3a8 [btrfs] btrfs_start_delalloc_roots+0x174/0x280 [btrfs] shrink_delalloc+0x114/0x280 [btrfs] flush_space+0x250/0x2f8 [btrfs] btrfs_async_reclaim_data_space+0x180/0x228 [btrfs] process_one_work+0x164/0x408 worker_thread+0x25c/0x388 kthread+0x100/0x118 ret_from_fork+0x10/0x20 Code: 910a8021 a90363f7 a9046bf9 94012379 (d4210000) ---[ end trace 0000000000000000 ]---  [CAUSE] The first two lines of extra debug messages show the problem is caused by the error handling of run_delalloc_nocow().  E.g. we have the following dirtied range (4K blocksize 4K page size):  0                 16K                  32K |//////////////////////////////////////| |  Pre-allocated  |  And the range [0, 16K) has a preallocated extent.  - Enter run_delalloc_nocow() for range [0, 16K) Which found range [0, 16K) is preallocated, can do the proper NOCOW write.  - Enter fallback_to_fow() for range [16K, 32K) Since the range [16K, 32K) is not backed by preallocated extent, we have to go COW.  - cow_file_range() failed for range [16K, 32K) So cow_file_range() will do the clean up by clearing folio dirty, unlock the folios.  Now the folios in range [16K, 32K) is unlocked.  - Enter extent_clear_unlock_delalloc() from run_delalloc_nocow() Which is called with PAGE_START_WRITEBACK to start page writeback. But folios can only be marked writeback when it's properly locked, thus this triggered the VM_BUG_ON_FOLIO().  Furthermore there is another hidden but common bug that run_delalloc_nocow() is not clearing the folio dirty flags in its error handling path. This is the common bug shared between run_delalloc_nocow() and cow_file_range().  [FIX] - Clear folio dirty for range [@start, @cur_offset) Introduce a helper, cleanup_dirty_folios(), which will find and lock the folio in the range, clear the dirty flag and start/end the writeback, with the extra handling for the @locked_folio.  - Introduce a helper to clear folio dirty, start and end writeback  - Introduce a helper to record the last failed COW range end This is to trace which range we should skip, to avoid double unlocking.  - Skip the failed COW range for the e ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57974?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57974" src="https://img.shields.io/badge/CVE--2024--57974-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  udp: Deal with race between UDP socket address change and rehash  If a UDP socket changes its local address while it's receiving datagrams, as a result of connect(), there is a period during which a lookup operation might fail to find it, after the address is changed but before the secondary hash (port and address) and the four-tuple hash (local and remote ports and addresses) are updated.  Secondary hash chains were introduced by commit 30fff9231fad ("udp: bind() optimisation") and, as a result, a rehash operation became needed to make a bound socket reachable again after a connect().  This operation was introduced by commit 719f835853a9 ("udp: add rehash on connect()") which isn't however a complete fix: the socket will be found once the rehashing completes, but not while it's pending.  This is noticeable with a socat(1) server in UDP4-LISTEN mode, and a client sending datagrams to it. After the server receives the first datagram (cf. _xioopen_ipdgram_listen()), it issues a connect() to the address of the sender, in order to set up a directed flow.  Now, if the client, running on a different CPU thread, happens to send a (subsequent) datagram while the server's socket changes its address, but is not rehashed yet, this will result in a failed lookup and a port unreachable error delivered to the client, as apparent from the following reproducer:  LEN=$(($(cat /proc/sys/net/core/wmem_default) / 4)) dd if=/dev/urandom bs=1 count=${LEN} of=tmp.in  while :; do taskset -c 1 socat UDP4-LISTEN:1337,null-eof OPEN:tmp.out,create,trunc & sleep 0.1 || sleep 1 taskset -c 2 socat OPEN:tmp.in UDP4:localhost:1337,shut-null wait done  where the client will eventually get ECONNREFUSED on a write() (typically the second or third one of a given iteration):  2024/11/13 21:28:23 socat[46901] E write(6, 0x556db2e3c000, 8192): Connection refused  This issue was first observed as a seldom failure in Podman's tests checking UDP functionality while using pasta(1) to connect the container's network namespace, which leads us to a reproducer with the lookup error resulting in an ICMP packet on a tap device:  LOCAL_ADDR="$(ip -j -4 addr show|jq -rM '.[] | .addr_info[0] | select(.scope == "global").local')"  while :; do ./pasta --config-net -p pasta.pcap -u 1337 socat UDP4-LISTEN:1337,null-eof OPEN:tmp.out,create,trunc & sleep 0.2 || sleep 1 socat OPEN:tmp.in UDP4:${LOCAL_ADDR}:1337,shut-null wait cmp tmp.in tmp.out done  Once this fails:  tmp.in tmp.out differ: char 8193, line 29  we can finally have a look at what's going on:  $ tshark -r pasta.pcap 1   0.000000           :: ? ff02::16     ICMPv6 110 Multicast Listener Report Message v2 2   0.168690 88.198.0.161 ? 88.198.0.164 UDP 8234 60260 ? 1337 Len=8192 3   0.168767 88.198.0.161 ? 88.198.0.164 UDP 8234 60260 ? 1337 Len=8192 4   0.168806 88.198.0.161 ? 88.198.0.164 UDP 8234 60260 ? 1337 Len=8192 5   0.168827 c6:47:05:8d:dc:04 ? Broadcast    ARP 42 Who has 88.198.0.161? Tell 88.198.0.164 6   0.168851 9a:55:9a:55:9a:55 ? c6:47:05:8d:dc:04 ARP 42 88.198.0.161 is at 9a:55:9a:55:9a:55 7   0.168875 88.198.0.161 ? 88.198.0.164 UDP 8234 60260 ? 1337 Len=8192 8   0.168896 88.198.0.164 ? 88.198.0.161 ICMP 590 Destination unreachable (Port unreachable) 9   0.168926 88.198.0.161 ? 88.198.0.164 UDP 8234 60260 ? 1337 Len=8192 10   0.168959 88.198.0.161 ? 88.198.0.164 UDP 8234 60260 ? 1337 Len=8192 11   0.168989 88.198.0.161 ? 88.198.0.164 UDP 4138 60260 ? 1337 Len=4096 12   0.169010 88.198.0.161 ? 88.198.0.164 UDP 42 60260 ? 1337 Len=0  On the third datagram received, the network namespace of the container initiates an ARP lookup to deliver the ICMP message.  In another variant of this reproducer, starting the client with:  strace -f pasta --config-net -u 1337 socat UDP4-LISTEN:1337,null-eof OPEN:tmp.out,create,tru ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57948?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57948" src="https://img.shields.io/badge/CVE--2024--57948-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.066%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mac802154: check local interfaces before deleting sdata list  syzkaller reported a corrupted list in ieee802154_if_remove. [1]  Remove an IEEE 802.15.4 network interface after unregister an IEEE 802.15.4 hardware device from the system.  CPU0					CPU1 ====					==== genl_family_rcv_msg_doit		ieee802154_unregister_hw ieee802154_del_iface			ieee802154_remove_interfaces rdev_del_virtual_intf_deprecated	list_del(&sdata->list) ieee802154_if_remove list_del_rcu  The net device has been unregistered, since the rcu grace period, unregistration must be run before ieee802154_if_remove.  To avoid this issue, add a check for local->interfaces before deleting sdata list.  [1] kernel BUG at lib/list_debug.c:58! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 0 UID: 0 PID: 6277 Comm: syz-executor157 Not tainted 6.12.0-rc6-syzkaller-00005-g557329bcecc2 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:__list_del_entry_valid_or_report+0xf4/0x140 lib/list_debug.c:56 Code: e8 a1 7e 00 07 90 0f 0b 48 c7 c7 e0 37 60 8c 4c 89 fe e8 8f 7e 00 07 90 0f 0b 48 c7 c7 40 38 60 8c 4c 89 fe e8 7d 7e 00 07 90 <0f> 0b 48 c7 c7 a0 38 60 8c 4c 89 fe e8 6b 7e 00 07 90 0f 0b 48 c7 RSP: 0018:ffffc9000490f3d0 EFLAGS: 00010246 RAX: 000000000000004e RBX: dead000000000122 RCX: d211eee56bb28d00 RDX: 0000000000000000 RSI: 0000000080000000 RDI: 0000000000000000 RBP: ffff88805b278dd8 R08: ffffffff8174a12c R09: 1ffffffff2852f0d R10: dffffc0000000000 R11: fffffbfff2852f0e R12: dffffc0000000000 R13: dffffc0000000000 R14: dead000000000100 R15: ffff88805b278cc0 FS:  0000555572f94380(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000056262e4a3000 CR3: 0000000078496000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> __list_del_entry_valid include/linux/list.h:124 [inline] __list_del_entry include/linux/list.h:215 [inline] list_del_rcu include/linux/rculist.h:157 [inline] ieee802154_if_remove+0x86/0x1e0 net/mac802154/iface.c:687 rdev_del_virtual_intf_deprecated net/ieee802154/rdev-ops.h:24 [inline] ieee802154_del_iface+0x2c0/0x5c0 net/ieee802154/nl-phy.c:323 genl_family_rcv_msg_doit net/netlink/genetlink.c:1115 [inline] genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline] genl_rcv_msg+0xb14/0xec0 net/netlink/genetlink.c:1210 netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2551 genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219 netlink_unicast_kernel net/netlink/af_netlink.c:1331 [inline] netlink_unicast+0x7f6/0x990 net/netlink/af_netlink.c:1357 netlink_sendmsg+0x8e4/0xcb0 net/netlink/af_netlink.c:1901 sock_sendmsg_nosec net/socket.c:729 [inline] __sock_sendmsg+0x221/0x270 net/socket.c:744 ____sys_sendmsg+0x52a/0x7e0 net/socket.c:2607 ___sys_sendmsg net/socket.c:2661 [inline] __sys_sendmsg+0x292/0x380 net/socket.c:2690 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57945?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57945" src="https://img.shields.io/badge/CVE--2024--57945-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  riscv: mm: Fix the out of bound issue of vmemmap address  In sparse vmemmap model, the virtual address of vmemmap is calculated as: ((struct page *)VMEMMAP_START - (phys_ram_base >> PAGE_SHIFT)). And the struct page's va can be calculated with an offset: (vmemmap + (pfn)).  However, when initializing struct pages, kernel actually starts from the first page from the same section that phys_ram_base belongs to. If the first page's physical address is not (phys_ram_base >> PAGE_SHIFT), then we get an va below VMEMMAP_START when calculating va for it's struct page.  For example, if phys_ram_base starts from 0x82000000 with pfn 0x82000, the first page in the same section is actually pfn 0x80000. During init_unavailable_range(), we will initialize struct page for pfn 0x80000 with virtual address ((struct page *)VMEMMAP_START - 0x2000), which is below VMEMMAP_START as well as PCI_IO_END.  This commit fixes this bug by introducing a new variable 'vmemmap_start_pfn' which is aligned with memory section size and using it to calculate vmemmap address instead of phys_ram_base.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57932?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57932" src="https://img.shields.io/badge/CVE--2024--57932-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gve: guard XDP xmit NDO on existence of xdp queues  In GVE, dedicated XDP queues only exist when an XDP program is installed and the interface is up. As such, the NDO XDP XMIT callback should return early if either of these conditions are false.  In the case of no loaded XDP program, priv->num_xdp_queues=0 which can cause a divide-by-zero error, and in the case of interface down, num_xdp_queues remains untouched to persist XDP queue count for the next interface up, but the TX pointer itself would be NULL.  The XDP xmit callback also needs to synchronize with a device transitioning from open to close. This synchronization will happen via the GVE_PRIV_FLAGS_NAPI_ENABLED bit along with a synchronize_net() call, which waits for any RCU critical sections at call-time to complete.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57931?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57931" src="https://img.shields.io/badge/CVE--2024--57931-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  selinux: ignore unknown extended permissions  When evaluating extended permissions, ignore unknown permissions instead of calling BUG(). This commit ensures that future permissions can be added without interfering with older kernels.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57929?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57929" src="https://img.shields.io/badge/CVE--2024--57929-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.069%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dm array: fix releasing a faulty array block twice in dm_array_cursor_end  When dm_bm_read_lock() fails due to locking or checksum errors, it releases the faulty block implicitly while leaving an invalid output pointer behind. The caller of dm_bm_read_lock() should not operate on this invalid dm_block pointer, or it will lead to undefined result. For example, the dm_array_cursor incorrectly caches the invalid pointer on reading a faulty array block, causing a double release in dm_array_cursor_end(), then hitting the BUG_ON in dm-bufio cache_put().  Reproduce steps:  1. initialize a cache device  dmsetup create cmeta --table "0 8192 linear /dev/sdc 0" dmsetup create cdata --table "0 65536 linear /dev/sdc 8192" dmsetup create corig --table "0 524288 linear /dev/sdc $262144" dd if=/dev/zero of=/dev/mapper/cmeta bs=4k count=1 dmsetup create cache --table "0 524288 cache /dev/mapper/cmeta \ /dev/mapper/cdata /dev/mapper/corig 128 2 metadata2 writethrough smq 0"  2. wipe the second array block offline  dmsteup remove cache cmeta cdata corig mapping_root=$(dd if=/dev/sdc bs=1c count=8 skip=192 \ 2>/dev/null | hexdump -e '1/8 "%u\n"') ablock=$(dd if=/dev/sdc bs=1c count=8 skip=$((4096*mapping_root+2056)) \ 2>/dev/null | hexdump -e '1/8 "%u\n"') dd if=/dev/zero of=/dev/sdc bs=4k count=1 seek=$ablock  3. try reopen the cache device  dmsetup create cmeta --table "0 8192 linear /dev/sdc 0" dmsetup create cdata --table "0 65536 linear /dev/sdc 8192" dmsetup create corig --table "0 524288 linear /dev/sdc $262144" dmsetup create cache --table "0 524288 cache /dev/mapper/cmeta \ /dev/mapper/cdata /dev/mapper/corig 128 2 metadata2 writethrough smq 0"  Kernel logs:  (snip) device-mapper: array: array_block_check failed: blocknr 0 != wanted 10 device-mapper: block manager: array validator check failed for block 10 device-mapper: array: get_ablock failed device-mapper: cache metadata: dm_array_cursor_next for mapping failed ------------[ cut here ]------------ kernel BUG at drivers/md/dm-bufio.c:638!  Fix by setting the cached block pointer to NULL on errors.  In addition to the reproducer described above, this fix can be verified using the "array_cursor/damaged" test in dm-unit: dm-unit run /pdata/array_cursor/damaged --kernel-dir <KERNEL_DIR>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57924?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57924" src="https://img.shields.io/badge/CVE--2024--57924-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs: relax assertions on failure to encode file handles  Encoding file handles is usually performed by a filesystem >encode_fh() method that may fail for various reasons.  The legacy users of exportfs_encode_fh(), namely, nfsd and name_to_handle_at(2) syscall are ready to cope with the possibility of failure to encode a file handle.  There are a few other users of exportfs_encode_{fh,fid}() that currently have a WARN_ON() assertion when ->encode_fh() fails. Relax those assertions because they are wrong.  The second linked bug report states commit 16aac5ad1fa9 ("ovl: support encoding non-decodable file handles") in v6.6 as the regressing commit, but this is not accurate.  The aforementioned commit only increases the chances of the assertion and allows triggering the assertion with the reproducer using overlayfs, inotify and drop_caches.  Triggering this assertion was always possible with other filesystems and other reasons of ->encode_fh() failures and more particularly, it was also possible with the exact same reproducer using overlayfs that is mounted with options index=on,nfs_export=on also on kernels < v6.6. Therefore, I am not listing the aforementioned commit as a Fixes commit.  Backport hint: this patch will have a trivial conflict applying to v6.6.y, and other trivial conflicts applying to stable kernels < v6.6.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57917?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57917" src="https://img.shields.io/badge/CVE--2024--57917-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  topology: Keep the cpumask unchanged when printing cpumap  During fuzz testing, the following warning was discovered:  different return values (15 and 11) from vsnprintf("%*pbl ", ...)  test:keyward is WARNING in kvasprintf WARNING: CPU: 55 PID: 1168477 at lib/kasprintf.c:30 kvasprintf+0x121/0x130 Call Trace: kvasprintf+0x121/0x130 kasprintf+0xa6/0xe0 bitmap_print_to_buf+0x89/0x100 core_siblings_list_read+0x7e/0xb0 kernfs_file_read_iter+0x15b/0x270 new_sync_read+0x153/0x260 vfs_read+0x215/0x290 ksys_read+0xb9/0x160 do_syscall_64+0x56/0x100 entry_SYSCALL_64_after_hwframe+0x78/0xe2  The call trace shows that kvasprintf() reported this warning during the printing of core_siblings_list. kvasprintf() has several steps:  (1) First, calculate the length of the resulting formatted string.  (2) Allocate a buffer based on the returned length.  (3) Then, perform the actual string formatting.  (4) Check whether the lengths of the formatted strings returned in steps (1) and (2) are consistent.  If the core_cpumask is modified between steps (1) and (3), the lengths obtained in these two steps may not match. Indeed our test includes cpu hotplugging, which should modify core_cpumask while printing.  To fix this issue, cache the cpumask into a temporary variable before calling cpumap_print_{list, cpumask}_to_buf(), to keep it unchanged during the printing process.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57904?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57904" src="https://img.shields.io/badge/CVE--2024--57904-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.069%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: adc: at91: call input_free_device() on allocated iio_dev  Current implementation of at91_ts_register() calls input_free_deivce() on st->ts_input, however, the err label can be reached before the allocated iio_dev is stored to st->ts_input. Thus call input_free_device() on input instead of st->ts_input.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57903?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57903" src="https://img.shields.io/badge/CVE--2024--57903-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: restrict SO_REUSEPORT to inet sockets  After blamed commit, crypto sockets could accidentally be destroyed from RCU call back, as spotted by zyzbot [1].  Trying to acquire a mutex in RCU callback is not allowed.  Restrict SO_REUSEPORT socket option to inet sockets.  v1 of this patch supported TCP, UDP and SCTP sockets, but fcnal-test.sh test needed RAW and ICMP support.  [1] BUG: sleeping function called from invalid context at kernel/locking/mutex.c:562 in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 24, name: ksoftirqd/1 preempt_count: 100, expected: 0 RCU nest depth: 0, expected: 0 1 lock held by ksoftirqd/1/24: #0: ffffffff8e937ba0 (rcu_callback){....}-{0:0}, at: rcu_lock_acquire include/linux/rcupdate.h:337 [inline] #0: ffffffff8e937ba0 (rcu_callback){....}-{0:0}, at: rcu_do_batch kernel/rcu/tree.c:2561 [inline] #0: ffffffff8e937ba0 (rcu_callback){....}-{0:0}, at: rcu_core+0xa37/0x17a0 kernel/rcu/tree.c:2823 Preemption disabled at: [<ffffffff8161c8c8>] softirq_handle_begin kernel/softirq.c:402 [inline] [<ffffffff8161c8c8>] handle_softirqs+0x128/0x9b0 kernel/softirq.c:537 CPU: 1 UID: 0 PID: 24 Comm: ksoftirqd/1 Not tainted 6.13.0-rc3-syzkaller-00174-ga024e377efed #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 __might_resched+0x5d4/0x780 kernel/sched/core.c:8758 __mutex_lock_common kernel/locking/mutex.c:562 [inline] __mutex_lock+0x131/0xee0 kernel/locking/mutex.c:735 crypto_put_default_null_skcipher+0x18/0x70 crypto/crypto_null.c:179 aead_release+0x3d/0x50 crypto/algif_aead.c:489 alg_do_release crypto/af_alg.c:118 [inline] alg_sock_destruct+0x86/0xc0 crypto/af_alg.c:502 __sk_destruct+0x58/0x5f0 net/core/sock.c:2260 rcu_do_batch kernel/rcu/tree.c:2567 [inline] rcu_core+0xaaa/0x17a0 kernel/rcu/tree.c:2823 handle_softirqs+0x2d4/0x9b0 kernel/softirq.c:561 run_ksoftirqd+0xca/0x130 kernel/softirq.c:950 smpboot_thread_fn+0x544/0xa30 kernel/smpboot.c:164 kthread+0x2f0/0x390 kernel/kthread.c:389 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57899?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57899" src="https://img.shields.io/badge/CVE--2024--57899-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.037%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: mac80211: fix mbss changed flags corruption on 32 bit systems  On 32-bit systems, the size of an unsigned long is 4 bytes, while a u64 is 8 bytes. Therefore, when using or_each_set_bit(bit, &bits, sizeof(changed) * BITS_PER_BYTE), the code is incorrectly searching for a bit in a 32-bit variable that is expected to be 64 bits in size, leading to incorrect bit finding.  Solution: Ensure that the size of the bits variable is correctly adjusted for each architecture.  Call Trace: ? show_regs+0x54/0x58 ? __warn+0x6b/0xd4 ? ieee80211_link_info_change_notify+0xcc/0xd4 [mac80211] ? report_bug+0x113/0x150 ? exc_overflow+0x30/0x30 ? handle_bug+0x27/0x44 ? exc_invalid_op+0x18/0x50 ? handle_exception+0xf6/0xf6 ? exc_overflow+0x30/0x30 ? ieee80211_link_info_change_notify+0xcc/0xd4 [mac80211] ? exc_overflow+0x30/0x30 ? ieee80211_link_info_change_notify+0xcc/0xd4 [mac80211] ? ieee80211_mesh_work+0xff/0x260 [mac80211] ? cfg80211_wiphy_work+0x72/0x98 [cfg80211] ? process_one_work+0xf1/0x1fc ? worker_thread+0x2c0/0x3b4 ? kthread+0xc7/0xf0 ? mod_delayed_work_on+0x4c/0x4c ? kthread_complete_and_exit+0x14/0x14 ? ret_from_fork+0x24/0x38 ? kthread_complete_and_exit+0x14/0x14 ? ret_from_fork_asm+0xf/0x14 ? entry_INT80_32+0xf0/0xf0  [restore no-op path for no changes]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57898?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57898" src="https://img.shields.io/badge/CVE--2024--57898-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.033%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: cfg80211: clear link ID from bitmap during link delete after clean up  Currently, during link deletion, the link ID is first removed from the valid_links bitmap before performing any clean-up operations. However, some functions require the link ID to remain in the valid_links bitmap. One such example is cfg80211_cac_event(). The flow is -  nl80211_remove_link() cfg80211_remove_link() ieee80211_del_intf_link() ieee80211_vif_set_links() ieee80211_vif_update_links() ieee80211_link_stop() cfg80211_cac_event()  cfg80211_cac_event() requires link ID to be present but it is cleared already in cfg80211_remove_link(). Ultimately, WARN_ON() is hit.  Therefore, clear the link ID from the bitmap only after completing the link clean-up.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57897?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57897" src="https://img.shields.io/badge/CVE--2024--57897-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdkfd: Correct the migration DMA map direction  The SVM DMA device map direction should be set the same as the DMA unmap setting, otherwise the DMA core will report the following warning.  Before finialize this solution, there're some discussion on the DMA mapping type(stream-based or coherent) in this KFD migration case, followed by https://lore.kernel.org/all/04d4ab32 -45a1-4b88-86ee-fb0f35a0ca40@amd.com/T/.  As there's no dma_sync_single_for_*() in the DMA buffer accessed that because this migration operation should be sync properly and automatically. Give that there's might not be a performance problem in various cache sync policy of DMA sync. Therefore, in order to simplify the DMA direction setting alignment, let's set the DMA map direction as BIDIRECTIONAL.  [  150.834218] WARNING: CPU: 8 PID: 1812 at kernel/dma/debug.c:1028 check_unmap+0x1cc/0x930 [  150.834225] Modules linked in: amdgpu(OE) amdxcp drm_exec(OE) gpu_sched drm_buddy(OE) drm_ttm_helper(OE) ttm(OE) drm_suballoc_helper(OE) drm_display_helper(OE) drm_kms_helper(OE) i2c_algo_bit rpcsec_gss_krb5 auth_rpcgss nfsv4 nfs lockd grace netfs xt_conntrack xt_MASQUERADE nf_conntrack_netlink xfrm_user xfrm_algo iptable_nat xt_addrtype iptable_filter br_netfilter nvme_fabrics overlay nfnetlink_cttimeout nfnetlink openvswitch nsh nf_conncount nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 libcrc32c bridge stp llc sch_fq_codel intel_rapl_msr amd_atl intel_rapl_common snd_hda_codec_realtek snd_hda_codec_generic snd_hda_scodec_component snd_hda_codec_hdmi snd_hda_intel snd_intel_dspcfg edac_mce_amd snd_pci_acp6x snd_hda_codec snd_acp_config snd_hda_core snd_hwdep snd_soc_acpi kvm_amd sunrpc snd_pcm kvm binfmt_misc snd_seq_midi crct10dif_pclmul snd_seq_midi_event ghash_clmulni_intel sha512_ssse3 snd_rawmidi nls_iso8859_1 sha256_ssse3 sha1_ssse3 snd_seq aesni_intel snd_seq_device crypto_simd snd_timer cryptd input_leds [  150.834310]  wmi_bmof serio_raw k10temp rapl snd sp5100_tco ipmi_devintf soundcore ccp ipmi_msghandler cm32181 industrialio mac_hid msr parport_pc ppdev lp parport efi_pstore drm(OE) ip_tables x_tables pci_stub crc32_pclmul nvme ahci libahci i2c_piix4 r8169 nvme_core i2c_designware_pci realtek i2c_ccgx_ucsi video wmi hid_generic cdc_ether usbnet usbhid hid r8152 mii [  150.834354] CPU: 8 PID: 1812 Comm: rocrtst64 Tainted: G           OE 6.10.0-custom #492 [  150.834358] Hardware name: AMD Majolica-RN/Majolica-RN, BIOS RMJ1009A 06/13/2021 [  150.834360] RIP: 0010:check_unmap+0x1cc/0x930 [  150.834363] Code: c0 4c 89 4d c8 e8 34 bf 86 00 4c 8b 4d c8 4c 8b 45 c0 48 8b 4d b8 48 89 c6 41 57 4c 89 ea 48 c7 c7 80 49 b4 84 e8 b4 81 f3 ff <0f> 0b 48 c7 c7 04 83 ac 84 e8 76 ba fc ff 41 8b 76 4c 49 8d 7e 50 [  150.834365] RSP: 0018:ffffaac5023739e0 EFLAGS: 00010086 [  150.834368] RAX: 0000000000000000 RBX: ffffffff8566a2e0 RCX: 0000000000000027 [  150.834370] RDX: ffff8f6a8f621688 RSI: 0000000000000001 RDI: ffff8f6a8f621680 [  150.834372] RBP: ffffaac502373a30 R08: 00000000000000c9 R09: ffffaac502373850 [  150.834373] R10: ffffaac502373848 R11: ffffffff84f46328 R12: ffffaac502373a40 [  150.834375] R13: ffff8f6741045330 R14: ffff8f6741a77700 R15: ffffffff84ac831b [  150.834377] FS:  00007faf0fc94c00(0000) GS:ffff8f6a8f600000(0000) knlGS:0000000000000000 [  150.834379] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  150.834381] CR2: 00007faf0b600020 CR3: 000000010a52e000 CR4: 0000000000350ef0 [  150.834383] Call Trace: [  150.834385]  <TASK> [  150.834387]  ? show_regs+0x6d/0x80 [  150.834393]  ? __warn+0x8c/0x140 [  150.834397]  ? check_unmap+0x1cc/0x930 [  150.834400]  ? report_bug+0x193/0x1a0 [  150.834406]  ? handle_bug+0x46/0x80 [  150.834410]  ? exc_invalid_op+0x1d/0x80 [  150.834413]  ? asm_exc_invalid_op+0x1f/0x30 [  150.834420]  ? check_unmap+0x1cc/0x930 [  150.834425]  debug_dma_unmap_page+0x86/0x90 [  150.834431]  ? srso_return_thunk+0x5/0x5f [  150.834435] ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57894?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57894" src="https://img.shields.io/badge/CVE--2024--57894-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57893?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57893" src="https://img.shields.io/badge/CVE--2024--57893-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ALSA: seq: oss: Fix races at processing SysEx messages  OSS sequencer handles the SysEx messages split in 6 bytes packets, and ALSA sequencer OSS layer tries to combine those.  It stores the data in the internal buffer and this access is racy as of now, which may lead to the out-of-bounds access.  As a temporary band-aid fix, introduce a mutex for serializing the process of the SysEx message packets.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57889?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57889" src="https://img.shields.io/badge/CVE--2024--57889-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pinctrl: mcp23s08: Fix sleeping in atomic context due to regmap locking  If a device uses MCP23xxx IO expander to receive IRQs, the following bug can happen:  BUG: sleeping function called from invalid context at kernel/locking/mutex.c:283 in_atomic(): 1, irqs_disabled(): 1, non_block: 0, ... preempt_count: 1, expected: 0 ... Call Trace: ... __might_resched+0x104/0x10e __might_sleep+0x3e/0x62 mutex_lock+0x20/0x4c regmap_lock_mutex+0x10/0x18 regmap_update_bits_base+0x2c/0x66 mcp23s08_irq_set_type+0x1ae/0x1d6 __irq_set_trigger+0x56/0x172 __setup_irq+0x1e6/0x646 request_threaded_irq+0xb6/0x160 ...  We observed the problem while experimenting with a touchscreen driver which used MCP23017 IO expander (I2C).  The regmap in the pinctrl-mcp23s08 driver uses a mutex for protection from concurrent accesses, which is the default for regmaps without .fast_io, .disable_locking, etc.  mcp23s08_irq_set_type() calls regmap_update_bits_base(), and the latter locks the mutex.  However, __setup_irq() locks desc->lock spinlock before calling these functions. As a result, the system tries to lock the mutex whole holding the spinlock.  It seems, the internal regmap locks are not needed in this driver at all. mcp->lock seems to protect the regmap from concurrent accesses already, except, probably, in mcp_pinconf_get/set.  mcp23s08_irq_set_type() and mcp23s08_irq_mask/unmask() are called under chip_bus_lock(), which calls mcp23s08_irq_bus_lock(). The latter takes mcp->lock and enables regmap caching, so that the potentially slow I2C accesses are deferred until chip_bus_unlock().  The accesses to the regmap from mcp23s08_probe_one() do not need additional locking.  In all remaining places where the regmap is accessed, except mcp_pinconf_get/set(), the driver already takes mcp->lock.  This patch adds locking in mcp_pinconf_get/set() and disables internal locking in the regmap config. Among other things, it fixes the sleeping in atomic context described above.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57888?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57888" src="https://img.shields.io/badge/CVE--2024--57888-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker  After commit 746ae46c1113 ("drm/sched: Mark scheduler work queues with WQ_MEM_RECLAIM") amdgpu started seeing the following warning:  [ ] workqueue: WQ_MEM_RECLAIM sdma0:drm_sched_run_job_work [gpu_sched] is flushing !WQ_MEM_RECLAIM events:amdgpu_device_delay_enable_gfx_off [amdgpu] ... [ ] Workqueue: sdma0 drm_sched_run_job_work [gpu_sched] ... [ ] Call Trace: [ ]  <TASK> ... [ ]  ? check_flush_dependency+0xf5/0x110 ... [ ]  cancel_delayed_work_sync+0x6e/0x80 [ ]  amdgpu_gfx_off_ctrl+0xab/0x140 [amdgpu] [ ]  amdgpu_ring_alloc+0x40/0x50 [amdgpu] [ ]  amdgpu_ib_schedule+0xf4/0x810 [amdgpu] [ ]  ? drm_sched_run_job_work+0x22c/0x430 [gpu_sched] [ ]  amdgpu_job_run+0xaa/0x1f0 [amdgpu] [ ]  drm_sched_run_job_work+0x257/0x430 [gpu_sched] [ ]  process_one_work+0x217/0x720 ... [ ]  </TASK>  The intent of the verifcation done in check_flush_depedency is to ensure forward progress during memory reclaim, by flagging cases when either a memory reclaim process, or a memory reclaim work item is flushed from a context not marked as memory reclaim safe.  This is correct when flushing, but when called from the cancel(_delayed)_work_sync() paths it is a false positive because work is either already running, or will not be running at all. Therefore cancelling it is safe and we can relax the warning criteria by letting the helper know of the calling context.  References: 746ae46c1113 ("drm/sched: Mark scheduler work queues with WQ_MEM_RECLAIM")

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57885?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57885" src="https://img.shields.io/badge/CVE--2024--57885-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm/kmemleak: fix sleeping function called from invalid context at print message  Address a bug in the kernel that triggers a "sleeping function called from invalid context" warning when /sys/kernel/debug/kmemleak is printed under specific conditions: - CONFIG_PREEMPT_RT=y - Set SELinux as the LSM for the system - Set kptr_restrict to 1 - kmemleak buffer contains at least one item  BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48 in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 136, name: cat preempt_count: 1, expected: 0 RCU nest depth: 2, expected: 2 6 locks held by cat/136: #0: ffff32e64bcbf950 (&p->lock){+.+.}-{3:3}, at: seq_read_iter+0xb8/0xe30 #1: ffffafe6aaa9dea0 (scan_mutex){+.+.}-{3:3}, at: kmemleak_seq_start+0x34/0x128 #3: ffff32e6546b1cd0 (&object->lock){....}-{2:2}, at: kmemleak_seq_show+0x3c/0x1e0 #4: ffffafe6aa8d8560 (rcu_read_lock){....}-{1:2}, at: has_ns_capability_noaudit+0x8/0x1b0 #5: ffffafe6aabbc0f8 (notif_lock){+.+.}-{2:2}, at: avc_compute_av+0xc4/0x3d0 irq event stamp: 136660 hardirqs last  enabled at (136659): [<ffffafe6a80fd7a0>] _raw_spin_unlock_irqrestore+0xa8/0xd8 hardirqs last disabled at (136660): [<ffffafe6a80fd85c>] _raw_spin_lock_irqsave+0x8c/0xb0 softirqs last  enabled at (0): [<ffffafe6a5d50b28>] copy_process+0x11d8/0x3df8 softirqs last disabled at (0): [<0000000000000000>] 0x0 Preemption disabled at: [<ffffafe6a6598a4c>] kmemleak_seq_show+0x3c/0x1e0 CPU: 1 UID: 0 PID: 136 Comm: cat Tainted: G            E      6.11.0-rt7+ #34 Tainted: [E]=UNSIGNED_MODULE Hardware name: linux,dummy-virt (DT) Call trace: dump_backtrace+0xa0/0x128 show_stack+0x1c/0x30 dump_stack_lvl+0xe8/0x198 dump_stack+0x18/0x20 rt_spin_lock+0x8c/0x1a8 avc_perm_nonode+0xa0/0x150 cred_has_capability.isra.0+0x118/0x218 selinux_capable+0x50/0x80 security_capable+0x7c/0xd0 has_ns_capability_noaudit+0x94/0x1b0 has_capability_noaudit+0x20/0x30 restricted_pointer+0x21c/0x4b0 pointer+0x298/0x760 vsnprintf+0x330/0xf70 seq_printf+0x178/0x218 print_unreferenced+0x1a4/0x2d0 kmemleak_seq_show+0xd0/0x1e0 seq_read_iter+0x354/0xe30 seq_read+0x250/0x378 full_proxy_read+0xd8/0x148 vfs_read+0x190/0x918 ksys_read+0xf0/0x1e0 __arm64_sys_read+0x70/0xa8 invoke_syscall.constprop.0+0xd4/0x1d8 el0_svc+0x50/0x158 el0t_64_sync+0x17c/0x180  %pS and %pK, in the same back trace line, are redundant, and %pS can void %pK service in certain contexts.  %pS alone already provides the necessary information, and if it cannot resolve the symbol, it falls back to printing the raw address voiding the original intent behind the %pK.  Additionally, %pK requires a privilege check CAP_SYSLOG enforced through the LSM, which can trigger a "sleeping function called from invalid context" warning under RT_PREEMPT kernels when the check occurs in an atomic context. This issue may also affect other LSMs.  This change avoids the unnecessary privilege check and resolves the sleeping function warning without any loss of information.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57884?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57884" src="https://img.shields.io/badge/CVE--2024--57884-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim()  The task sometimes continues looping in throttle_direct_reclaim() because allow_direct_reclaim(pgdat) keeps returning false.  #0 [ffff80002cb6f8d0] __switch_to at ffff8000080095ac #1 [ffff80002cb6f900] __schedule at ffff800008abbd1c #2 [ffff80002cb6f990] schedule at ffff800008abc50c #3 [ffff80002cb6f9b0] throttle_direct_reclaim at ffff800008273550 #4 [ffff80002cb6fa20] try_to_free_pages at ffff800008277b68 #5 [ffff80002cb6fae0] __alloc_pages_nodemask at ffff8000082c4660 #6 [ffff80002cb6fc50] alloc_pages_vma at ffff8000082e4a98 #7 [ffff80002cb6fca0] do_anonymous_page at ffff80000829f5a8 #8 [ffff80002cb6fce0] __handle_mm_fault at ffff8000082a5974 #9 [ffff80002cb6fd90] handle_mm_fault at ffff8000082a5bd4  At this point, the pgdat contains the following two zones:  NODE: 4  ZONE: 0  ADDR: ffff00817fffe540  NAME: "DMA32" SIZE: 20480  MIN/LOW/HIGH: 11/28/45 VM_STAT: NR_FREE_PAGES: 359 NR_ZONE_INACTIVE_ANON: 18813 NR_ZONE_ACTIVE_ANON: 0 NR_ZONE_INACTIVE_FILE: 50 NR_ZONE_ACTIVE_FILE: 0 NR_ZONE_UNEVICTABLE: 0 NR_ZONE_WRITE_PENDING: 0 NR_MLOCK: 0 NR_BOUNCE: 0 NR_ZSPAGES: 0 NR_FREE_CMA_PAGES: 0  NODE: 4  ZONE: 1  ADDR: ffff00817fffec00  NAME: "Normal" SIZE: 8454144  PRESENT: 98304  MIN/LOW/HIGH: 68/166/264 VM_STAT: NR_FREE_PAGES: 146 NR_ZONE_INACTIVE_ANON: 94668 NR_ZONE_ACTIVE_ANON: 3 NR_ZONE_INACTIVE_FILE: 735 NR_ZONE_ACTIVE_FILE: 78 NR_ZONE_UNEVICTABLE: 0 NR_ZONE_WRITE_PENDING: 0 NR_MLOCK: 0 NR_BOUNCE: 0 NR_ZSPAGES: 0 NR_FREE_CMA_PAGES: 0  In allow_direct_reclaim(), while processing ZONE_DMA32, the sum of inactive/active file-backed pages calculated in zone_reclaimable_pages() based on the result of zone_page_state_snapshot() is zero.  Additionally, since this system lacks swap, the calculation of inactive/ active anonymous pages is skipped.  crash> p nr_swap_pages nr_swap_pages = $1937 = { counter = 0 }  As a result, ZONE_DMA32 is deemed unreclaimable and skipped, moving on to the processing of the next zone, ZONE_NORMAL, despite ZONE_DMA32 having free pages significantly exceeding the high watermark.  The problem is that the pgdat->kswapd_failures hasn't been incremented.  crash> px ((struct pglist_data *) 0xffff00817fffe540)->kswapd_failures $1935 = 0x0  This is because the node deemed balanced.  The node balancing logic in balance_pgdat() evaluates all zones collectively.  If one or more zones (e.g., ZONE_DMA32) have enough free pages to meet their watermarks, the entire node is deemed balanced.  This causes balance_pgdat() to exit early before incrementing the kswapd_failures, as it considers the overall memory state acceptable, even though some zones (like ZONE_NORMAL) remain under significant pressure.   The patch ensures that zone_reclaimable_pages() includes free pages (NR_FREE_PAGES) in its calculation when no other reclaimable pages are available (e.g., file-backed or anonymous pages).  This change prevents zones like ZONE_DMA32, which have sufficient free pages, from being mistakenly deemed unreclaimable.  By doing so, the patch ensures proper node balancing, avoids masking pressure on other zones like ZONE_NORMAL, and prevents infinite loops in throttle_direct_reclaim() caused by allow_direct_reclaim(pgdat) repeatedly returning false.   The kernel hangs due to a task stuck in throttle_direct_reclaim(), caused by a node being incorrectly deemed balanced despite pressure in certain zones, such as ZONE_NORMAL.  This issue arises from zone_reclaimable_pages ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57883?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57883" src="https://img.shields.io/badge/CVE--2024--57883-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm: hugetlb: independent PMD page table shared count  The folio refcount may be increased unexpectly through try_get_folio() by caller such as split_huge_pages.  In huge_pmd_unshare(), we use refcount to check whether a pmd page table is shared.  The check is incorrect if the refcount is increased by the above caller, and this can cause the page table leaked:  BUG: Bad page state in process sh  pfn:109324 page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x66 pfn:0x109324 flags: 0x17ffff800000000(node=0|zone=2|lastcpupid=0xfffff) page_type: f2(table) raw: 017ffff800000000 0000000000000000 0000000000000000 0000000000000000 raw: 0000000000000066 0000000000000000 00000000f2000000 0000000000000000 page dumped because: nonzero mapcount ... CPU: 31 UID: 0 PID: 7515 Comm: sh Kdump: loaded Tainted: G    B 6.13.0-rc2master+ #7 Tainted: [B]=BAD_PAGE Hardware name: QEMU KVM Virtual Machine, BIOS 0.0.0 02/06/2015 Call trace: show_stack+0x20/0x38 (C) dump_stack_lvl+0x80/0xf8 dump_stack+0x18/0x28 bad_page+0x8c/0x130 free_page_is_bad_report+0xa4/0xb0 free_unref_page+0x3cc/0x620 __folio_put+0xf4/0x158 split_huge_pages_all+0x1e0/0x3e8 split_huge_pages_write+0x25c/0x2d8 full_proxy_write+0x64/0xd8 vfs_write+0xcc/0x280 ksys_write+0x70/0x110 __arm64_sys_write+0x24/0x38 invoke_syscall+0x50/0x120 el0_svc_common.constprop.0+0xc8/0xf0 do_el0_svc+0x24/0x38 el0_svc+0x34/0x128 el0t_64_sync_handler+0xc8/0xd0 el0t_64_sync+0x190/0x198  The issue may be triggered by damon, offline_page, page_idle, etc, which will increase the refcount of page table.  1. The page table itself will be discarded after reporting the "nonzero mapcount".  2. The HugeTLB page mapped by the page table miss freeing since we treat the page table as shared and a shared page table will not be unmapped.  Fix it by introducing independent PMD page table shared count.  As described by comment, pt_index/pt_mm/pt_frag_refcount are used for s390 gmap, x86 pgds and powerpc, pt_share_count is used for x86/arm64/riscv pmds, so we can reuse the field as pt_share_count.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57875?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57875" src="https://img.shields.io/badge/CVE--2024--57875-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  block: RCU protect disk->conv_zones_bitmap  Ensure that a disk revalidation changing the conventional zones bitmap of a disk does not cause invalid memory references when using the disk_zone_is_conv() helper by RCU protecting the disk->conv_zones_bitmap pointer.  disk_zone_is_conv() is modified to operate under the RCU read lock and the function disk_set_conv_zones_bitmap() is added to update a disk conv_zones_bitmap pointer using rcu_replace_pointer() with the disk zone_wplugs_lock spinlock held.  disk_free_zone_resources() is modified to call disk_update_zone_resources() with a NULL bitmap pointer to free the disk conv_zones_bitmap. disk_set_conv_zones_bitmap() is also used in disk_update_zone_resources() to set the new (revalidated) bitmap and free the old one.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57857?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57857" src="https://img.shields.io/badge/CVE--2024--57857-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/siw: Remove direct link to net_device  Do not manage a per device direct link to net_device. Rely on associated ib_devices net_device management, not doubling the effort locally. A badly managed local link to net_device was causing a 'KASAN: slab-use-after-free' exception during siw_query_port() call.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57852?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57852" src="https://img.shields.io/badge/CVE--2024--57852-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  firmware: qcom: scm: smc: Handle missing SCM device  Commit ca61d6836e6f ("firmware: qcom: scm: fix a NULL-pointer dereference") makes it explicit that qcom_scm_get_tzmem_pool() can return NULL, therefore its users should handle this.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57809?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57809" src="https://img.shields.io/badge/CVE--2024--57809-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  PCI: imx6: Fix suspend/resume support on i.MX6QDL  The suspend/resume functionality is currently broken on the i.MX6QDL platform, as documented in the NXP errata (ERR005723):  https://www.nxp.com/docs/en/errata/IMX6DQCE.pdf  This patch addresses the issue by sharing most of the suspend/resume sequences used by other i.MX devices, while avoiding modifications to critical registers that disrupt the PCIe functionality. It targets the same problem as the following downstream commit:   https://github.com/nxp-imx/linux-imx/commit/4e92355e1f79d225ea842511fcfd42b343b32995  Unlike the downstream commit, this patch also resets the connected PCIe device if possible. Without this reset, certain drivers, such as ath10k or iwlwifi, will crash on resume. The device reset is also done by the driver on other i.MX platforms, making this patch consistent with existing practices.  Upon resuming, the kernel will hang and display an error. Here's an example of the error encountered with the ath10k driver:  ath10k_pci 0000:01:00.0: Unable to change power state from D3hot to D0, device inaccessible Unhandled fault: imprecise external abort (0x1406) at 0x0106f944  Without this patch, suspend/resume will fail on i.MX6QDL devices if a PCIe device is connected.  [kwilczynski: commit log, added tag for stable releases]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57795?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--57795" src="https://img.shields.io/badge/CVE--2024--57795-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/rxe: Remove the direct link to net_device  The similar patch in siw is in the link: https://git.kernel.org/rdma/rdma/c/16b87037b48889  This problem also occurred in RXE. The following analyze this problem. In the following Call Traces: " BUG: KASAN: slab-use-after-free in dev_get_flags+0x188/0x1d0 net/core/dev.c:8782 Read of size 4 at addr ffff8880554640b0 by task kworker/1:4/5295  CPU: 1 UID: 0 PID: 5295 Comm: kworker/1:4 Not tainted 6.12.0-rc3-syzkaller-00399-g9197b73fd7bb #0 Hardware name: Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Workqueue: infiniband ib_cache_event_task Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:377 [inline] print_report+0x169/0x550 mm/kasan/report.c:488 kasan_report+0x143/0x180 mm/kasan/report.c:601 dev_get_flags+0x188/0x1d0 net/core/dev.c:8782 rxe_query_port+0x12d/0x260 drivers/infiniband/sw/rxe/rxe_verbs.c:60 __ib_query_port drivers/infiniband/core/device.c:2111 [inline] ib_query_port+0x168/0x7d0 drivers/infiniband/core/device.c:2143 ib_cache_update+0x1a9/0xb80 drivers/infiniband/core/cache.c:1494 ib_cache_event_task+0xf3/0x1e0 drivers/infiniband/core/cache.c:1568 process_one_work kernel/workqueue.c:3229 [inline] process_scheduled_works+0xa65/0x1850 kernel/workqueue.c:3310 worker_thread+0x870/0xd30 kernel/workqueue.c:3391 kthread+0x2f2/0x390 kernel/kthread.c:389 ret_from_fork+0x4d/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK> "  1). In the link [1],  " infiniband syz2: set down "  This means that on 839.350575, the event ib_cache_event_task was sent andi queued in ib_wq.  2). In the link [1],  " team0 (unregistering): Port device team_slave_0 removed "  It indicates that before 843.251853, the net device should be freed.  3). In the link [1],  " BUG: KASAN: slab-use-after-free in dev_get_flags+0x188/0x1d0 "  This means that on 850.559070, this slab-use-after-free problem occurred.  In all, on 839.350575, the event ib_cache_event_task was sent and queued in ib_wq,  before 843.251853, the net device veth was freed.  on 850.559070, this event was executed, and the mentioned freed net device was called. Thus, the above call trace occurred.  [1] https://syzkaller.appspot.com/x/log.txt?x=12e7025f980000

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56788?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--56788" src="https://img.shields.io/badge/CVE--2024--56788-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: ethernet: oa_tc6: fix tx skb race condition between reference pointers  There are two skb pointers to manage tx skb's enqueued from n/w stack. waiting_tx_skb pointer points to the tx skb which needs to be processed and ongoing_tx_skb pointer points to the tx skb which is being processed.  SPI thread prepares the tx data chunks from the tx skb pointed by the ongoing_tx_skb pointer. When the tx skb pointed by the ongoing_tx_skb is processed, the tx skb pointed by the waiting_tx_skb is assigned to ongoing_tx_skb and the waiting_tx_skb pointer is assigned with NULL. Whenever there is a new tx skb from n/w stack, it will be assigned to waiting_tx_skb pointer if it is NULL. Enqueuing and processing of a tx skb handled in two different threads.  Consider a scenario where the SPI thread processed an ongoing_tx_skb and it moves next tx skb from waiting_tx_skb pointer to ongoing_tx_skb pointer without doing any NULL check. At this time, if the waiting_tx_skb pointer is NULL then ongoing_tx_skb pointer is also assigned with NULL. After that, if a new tx skb is assigned to waiting_tx_skb pointer by the n/w stack and there is a chance to overwrite the tx skb pointer with NULL in the SPI thread. Finally one of the tx skb will be left as unhandled, resulting packet missing and memory leak.  - Consider the below scenario where the TXC reported from the previous transfer is 10 and ongoing_tx_skb holds an tx ethernet frame which can be transported in 20 TXCs and waiting_tx_skb is still NULL. tx_credits = 10; /* 21 are filled in the previous transfer */ ongoing_tx_skb = 20; waiting_tx_skb = NULL; /* Still NULL */ - So, (tc6->ongoing_tx_skb || tc6->waiting_tx_skb) becomes true. - After oa_tc6_prepare_spi_tx_buf_for_tx_skbs() ongoing_tx_skb = 10; waiting_tx_skb = NULL; /* Still NULL */ - Perform SPI transfer. - Process SPI rx buffer to get the TXC from footers. - Now let's assume previously filled 21 TXCs are freed so we are good to transport the next remaining 10 tx chunks from ongoing_tx_skb. tx_credits = 21; ongoing_tx_skb = 10; waiting_tx_skb = NULL; - So, (tc6->ongoing_tx_skb || tc6->waiting_tx_skb) becomes true again. - In the oa_tc6_prepare_spi_tx_buf_for_tx_skbs() ongoing_tx_skb = NULL; waiting_tx_skb = NULL;  - Now the below bad case might happen,  Thread1 (oa_tc6_start_xmit)	Thread2 (oa_tc6_spi_thread_handler) ---------------------------	----------------------------------- - if waiting_tx_skb is NULL - if ongoing_tx_skb is NULL - ongoing_tx_skb = waiting_tx_skb - waiting_tx_skb = skb - waiting_tx_skb = NULL ... - ongoing_tx_skb = NULL - if waiting_tx_skb is NULL - waiting_tx_skb = skb  To overcome the above issue, protect the moving of tx skb reference from waiting_tx_skb pointer to ongoing_tx_skb pointer and assigning new tx skb to waiting_tx_skb pointer, so that the other thread can't access the waiting_tx_skb pointer until the current thread completes moving the tx skb reference safely.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56686?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--56686" src="https://img.shields.io/badge/CVE--2024--56686-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56639?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--56639" src="https://img.shields.io/badge/CVE--2024--56639-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hsr: must allocate more bytes for RedBox support  Blamed commit forgot to change hsr_init_skb() to allocate larger skb for RedBox case.  Indeed, send_hsr_supervision_frame() will add two additional components (struct hsr_sup_tlv and struct hsr_sup_payload)  syzbot reported the following crash: skbuff: skb_over_panic: text:ffffffff8afd4b0a len:34 put:6 head:ffff88802ad29e00 data:ffff88802ad29f22 tail:0x144 end:0x140 dev:gretap0 ------------[ cut here ]------------ kernel BUG at net/core/skbuff.c:206 ! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN NOPTI CPU: 2 UID: 0 PID: 7611 Comm: syz-executor Not tainted 6.12.0-syzkaller #0 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 RIP: 0010:skb_panic+0x157/0x1d0 net/core/skbuff.c:206 Code: b6 04 01 84 c0 74 04 3c 03 7e 21 8b 4b 70 41 56 45 89 e8 48 c7 c7 a0 7d 9b 8c 41 57 56 48 89 ee 52 4c 89 e2 e8 9a 76 79 f8 90 <0f> 0b 4c 89 4c 24 10 48 89 54 24 08 48 89 34 24 e8 94 76 fb f8 4c RSP: 0018:ffffc90000858ab8 EFLAGS: 00010282 RAX: 0000000000000087 RBX: ffff8880598c08c0 RCX: ffffffff816d3e69 RDX: 0000000000000000 RSI: ffffffff816de786 RDI: 0000000000000005 RBP: ffffffff8c9b91c0 R08: 0000000000000005 R09: 0000000000000000 R10: 0000000000000302 R11: ffffffff961cc1d0 R12: ffffffff8afd4b0a R13: 0000000000000006 R14: ffff88804b938130 R15: 0000000000000140 FS:  000055558a3d6500(0000) GS:ffff88806a800000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f1295974ff8 CR3: 000000002ab6e000 CR4: 0000000000352ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <IRQ> skb_over_panic net/core/skbuff.c:211 [inline] skb_put+0x174/0x1b0 net/core/skbuff.c:2617 send_hsr_supervision_frame+0x6fa/0x9e0 net/hsr/hsr_device.c:342 hsr_proxy_announce+0x1a3/0x4a0 net/hsr/hsr_device.c:436 call_timer_fn+0x1a0/0x610 kernel/time/timer.c:1794 expire_timers kernel/time/timer.c:1845 [inline] __run_timers+0x6e8/0x930 kernel/time/timer.c:2419 __run_timer_base kernel/time/timer.c:2430 [inline] __run_timer_base kernel/time/timer.c:2423 [inline] run_timer_base+0x111/0x190 kernel/time/timer.c:2439 run_timer_softirq+0x1a/0x40 kernel/time/timer.c:2449 handle_softirqs+0x213/0x8f0 kernel/softirq.c:554 __do_softirq kernel/softirq.c:588 [inline] invoke_softirq kernel/softirq.c:428 [inline] __irq_exit_rcu kernel/softirq.c:637 [inline] irq_exit_rcu+0xbb/0x120 kernel/softirq.c:649 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline] sysvec_apic_timer_interrupt+0xa4/0xc0 arch/x86/kernel/apic/apic.c:1049 </IRQ>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56591?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--56591" src="https://img.shields.io/badge/CVE--2024--56591-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: hci_conn: Use disable_delayed_work_sync  This makes use of disable_delayed_work_sync instead cancel_delayed_work_sync as it not only cancel the ongoing work but also disables new submit which is disarable since the object holding the work is about to be freed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56571?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--56571" src="https://img.shields.io/badge/CVE--2024--56571-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56552?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--56552" src="https://img.shields.io/badge/CVE--2024--56552-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/xe/guc_submit: fix race around suspend_pending  Currently in some testcases we can trigger:  xe 0000:03:00.0: [drm] Assertion `exec_queue_destroyed(q)` failed! .... WARNING: CPU: 18 PID: 2640 at drivers/gpu/drm/xe/xe_guc_submit.c:1826 xe_guc_sched_done_handler+0xa54/0xef0 [xe] xe 0000:03:00.0: [drm] *ERROR* GT1: DEREGISTER_DONE: Unexpected engine state 0x00a1, guc_id=57  Looking at a snippet of corresponding ftrace for this GuC id we can see:  162.673311: xe_sched_msg_add:     dev=0000:03:00.0, gt=1 guc_id=57, opcode=3 162.673317: xe_sched_msg_recv:    dev=0000:03:00.0, gt=1 guc_id=57, opcode=3 162.673319: xe_exec_queue_scheduling_disable: dev=0000:03:00.0, 1:0x2, gt=1, width=1, guc_id=57, guc_state=0x29, flags=0x0 162.674089: xe_exec_queue_kill:   dev=0000:03:00.0, 1:0x2, gt=1, width=1, guc_id=57, guc_state=0x29, flags=0x0 162.674108: xe_exec_queue_close:  dev=0000:03:00.0, 1:0x2, gt=1, width=1, guc_id=57, guc_state=0xa9, flags=0x0 162.674488: xe_exec_queue_scheduling_done: dev=0000:03:00.0, 1:0x2, gt=1, width=1, guc_id=57, guc_state=0xa9, flags=0x0 162.678452: xe_exec_queue_deregister: dev=0000:03:00.0, 1:0x2, gt=1, width=1, guc_id=57, guc_state=0xa1, flags=0x0  It looks like we try to suspend the queue (opcode=3), setting suspend_pending and triggering a disable_scheduling. The user then closes the queue. However the close will also forcefully signal the suspend fence after killing the queue, later when the G2H response for disable_scheduling comes back we have now cleared suspend_pending when signalling the suspend fence, so the disable_scheduling now incorrectly tries to also deregister the queue. This leads to warnings since the queue has yet to even be marked for destruction. We also seem to trigger errors later with trying to double unregister the same queue.  To fix this tweak the ordering when handling the response to ensure we don't race with a disable_scheduling that didn't actually intend to perform an unregister.  The destruction path should now also correctly wait for any pending_disable before marking as destroyed.  (cherry picked from commit f161809b362f027b6d72bd998e47f8f0bad60a2e)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56368?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--56368" src="https://img.shields.io/badge/CVE--2024--56368-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ring-buffer: Fix overflow in __rb_map_vma  An overflow occurred when performing the following calculation:  nr_pages = ((nr_subbufs + 1) << subbuf_order) - pgoff;  Add a check before the calculation to avoid this problem.  syzbot reported this as a slab-out-of-bounds in __rb_map_vma:  BUG: KASAN: slab-out-of-bounds in __rb_map_vma+0x9ab/0xae0 kernel/trace/ring_buffer.c:7058 Read of size 8 at addr ffff8880767dd2b8 by task syz-executor187/5836  CPU: 0 UID: 0 PID: 5836 Comm: syz-executor187 Not tainted 6.13.0-rc2-syzkaller-00159-gf932fb9b4074 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 11/25/2024 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0xc3/0x620 mm/kasan/report.c:489 kasan_report+0xd9/0x110 mm/kasan/report.c:602 __rb_map_vma+0x9ab/0xae0 kernel/trace/ring_buffer.c:7058 ring_buffer_map+0x56e/0x9b0 kernel/trace/ring_buffer.c:7138 tracing_buffers_mmap+0xa6/0x120 kernel/trace/trace.c:8482 call_mmap include/linux/fs.h:2183 [inline] mmap_file mm/internal.h:124 [inline] __mmap_new_file_vma mm/vma.c:2291 [inline] __mmap_new_vma mm/vma.c:2355 [inline] __mmap_region+0x1786/0x2670 mm/vma.c:2456 mmap_region+0x127/0x320 mm/mmap.c:1348 do_mmap+0xc00/0xfc0 mm/mmap.c:496 vm_mmap_pgoff+0x1ba/0x360 mm/util.c:580 ksys_mmap_pgoff+0x32c/0x5c0 mm/mmap.c:542 __do_sys_mmap arch/x86/kernel/sys_x86_64.c:89 [inline] __se_sys_mmap arch/x86/kernel/sys_x86_64.c:82 [inline] __x64_sys_mmap+0x125/0x190 arch/x86/kernel/sys_x86_64.c:82 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x250 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  The reproducer for this bug is:  ------------------------8<------------------------- #include <fcntl.h> #include <stdlib.h> #include <unistd.h> #include <asm/types.h> #include <sys/mman.h>  int main(int argc, char **argv) { int page_size = getpagesize(); int fd; void *meta;  system("echo 1 > /sys/kernel/tracing/buffer_size_kb"); fd = open("/sys/kernel/tracing/per_cpu/cpu0/trace_pipe_raw", O_RDONLY);  meta = mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, page_size * 5); } ------------------------>8-------------------------

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54458?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--54458" src="https://img.shields.io/badge/CVE--2024--54458-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: ufs: bsg: Set bsg_queue to NULL after removal  Currently, this does not cause any issues, but I believe it is necessary to set bsg_queue to NULL after removing it to prevent potential use-after-free (UAF) access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54456?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--54456" src="https://img.shields.io/badge/CVE--2024--54456-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  NFS: Fix potential buffer overflowin nfs_sysfs_link_rpc_client()  name is char[64] where the size of clnt->cl_program->name remains unknown. Invoking strcat() directly will also lead to potential buffer overflow. Change them to strscpy() and strncat() to fix potential issues.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53216?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--53216" src="https://img.shields.io/badge/CVE--2024--53216-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfsd: release svc_expkey/svc_export with rcu_work  The last reference for `cache_head` can be reduced to zero in `c_show` and `e_show`(using `rcu_read_lock` and `rcu_read_unlock`). Consequently, `svc_export_put` and `expkey_put` will be invoked, leading to two issues:  1. The `svc_export_put` will directly free ex_uuid. However, `e_show`/`c_show` will access `ex_uuid` after `cache_put`, which can trigger a use-after-free issue, shown below.  ================================================================== BUG: KASAN: slab-use-after-free in svc_export_show+0x362/0x430 [nfsd] Read of size 1 at addr ff11000010fdc120 by task cat/870  CPU: 1 UID: 0 PID: 870 Comm: cat Not tainted 6.12.0-rc3+ #1 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.1-2.fc37 04/01/2014 Call Trace: <TASK> dump_stack_lvl+0x53/0x70 print_address_description.constprop.0+0x2c/0x3a0 print_report+0xb9/0x280 kasan_report+0xae/0xe0 svc_export_show+0x362/0x430 [nfsd] c_show+0x161/0x390 [sunrpc] seq_read_iter+0x589/0x770 seq_read+0x1e5/0x270 proc_reg_read+0xe1/0x140 vfs_read+0x125/0x530 ksys_read+0xc1/0x160 do_syscall_64+0x5f/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Allocated by task 830: kasan_save_stack+0x20/0x40 kasan_save_track+0x14/0x30 __kasan_kmalloc+0x8f/0xa0 __kmalloc_node_track_caller_noprof+0x1bc/0x400 kmemdup_noprof+0x22/0x50 svc_export_parse+0x8a9/0xb80 [nfsd] cache_do_downcall+0x71/0xa0 [sunrpc] cache_write_procfs+0x8e/0xd0 [sunrpc] proc_reg_write+0xe1/0x140 vfs_write+0x1a5/0x6d0 ksys_write+0xc1/0x160 do_syscall_64+0x5f/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Freed by task 868: kasan_save_stack+0x20/0x40 kasan_save_track+0x14/0x30 kasan_save_free_info+0x3b/0x60 __kasan_slab_free+0x37/0x50 kfree+0xf3/0x3e0 svc_export_put+0x87/0xb0 [nfsd] cache_purge+0x17f/0x1f0 [sunrpc] nfsd_destroy_serv+0x226/0x2d0 [nfsd] nfsd_svc+0x125/0x1e0 [nfsd] write_threads+0x16a/0x2a0 [nfsd] nfsctl_transaction_write+0x74/0xa0 [nfsd] vfs_write+0x1a5/0x6d0 ksys_write+0xc1/0x160 do_syscall_64+0x5f/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  2. We cannot sleep while using `rcu_read_lock`/`rcu_read_unlock`. However, `svc_export_put`/`expkey_put` will call path_put, which subsequently triggers a sleeping operation due to the following `dput`.  ============================= WARNING: suspicious RCU usage 5.10.0-dirty #141 Not tainted ----------------------------- ... Call Trace: dump_stack+0x9a/0xd0 ___might_sleep+0x231/0x240 dput+0x39/0x600 path_put+0x1b/0x30 svc_export_put+0x17/0x80 e_show+0x1c9/0x200 seq_read_iter+0x63f/0x7c0 seq_read+0x226/0x2d0 vfs_read+0x113/0x2c0 ksys_read+0xc9/0x170 do_syscall_64+0x33/0x40 entry_SYSCALL_64_after_hwframe+0x67/0xd1  Fix these issues by using `rcu_work` to help release `svc_expkey`/`svc_export`. This approach allows for an asynchronous context to invoke `path_put` and also facilitates the freeing of `uuid/exp/key` after an RCU grace period.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53159?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--53159" src="https://img.shields.io/badge/CVE--2024--53159-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53102?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--53102" src="https://img.shields.io/badge/CVE--2024--53102-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-52560?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--52560" src="https://img.shields.io/badge/CVE--2024--52560-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs/ntfs3: Mark inode as bad as soon as error detected in mi_enum_attr()  Extended the `mi_enum_attr()` function interface with an additional parameter, `struct ntfs_inode *ni`, to allow marking the inode as bad as soon as an error is detected.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50219?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--50219" src="https://img.shields.io/badge/CVE--2024--50219-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-47755?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--47755" src="https://img.shields.io/badge/CVE--2024--47755-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-47725?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--47725" src="https://img.shields.io/badge/CVE--2024--47725-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46748?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--46748" src="https://img.shields.io/badge/CVE--2024--46748-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cachefiles: Set the max subreq size for cache writes to MAX_RW_COUNT  Set the maximum size of a subrequest that writes to cachefiles to be MAX_RW_COUNT so that we don't overrun the maximum write we can make to the backing filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-42125?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--42125" src="https://img.shields.io/badge/CVE--2024--42125-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.114%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: rtw89: fw: scan offload prohibit all 6 GHz channel if no 6 GHz sband  We have some policy via BIOS to block uses of 6 GHz. In this case, 6 GHz sband will be NULL even if it is WiFi 7 chip. So, add NULL handling here to avoid crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-42116?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--42116" src="https://img.shields.io/badge/CVE--2024--42116-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-41024?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--41024" src="https://img.shields.io/badge/CVE--2024--41024-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-41008?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--41008" src="https://img.shields.io/badge/CVE--2024--41008-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.120%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu: change vm->task_info handling  This patch changes the handling and lifecycle of vm->task_info object. The major changes are: - vm->task_info is a dynamically allocated ptr now, and its uasge is reference counted. - introducing two new helper funcs for task_info lifecycle management - amdgpu_vm_get_task_info: reference counts up task_info before returning this info - amdgpu_vm_put_task_info: reference counts down task_info - last put to task_info() frees task_info from the vm.  This patch also does logistical changes required for existing usage of vm->task_info.  V2: Do not block all the prints when task_info not found (Felix)  V3: Fixed review comments from Felix - Fix wrong indentation - No debug message for -ENOMEM - Add NULL check for task_info - Do not duplicate the debug messages (ti vs no ti) - Get first reference of task_info in vm_init(), put last in vm_fini()  V4: Fixed review comments from Felix - fix double reference increment in create_task_info - change amdgpu_vm_get_task_info_pasid - additional changes in amdgpu_gem.c while porting

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-39293?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--39293" src="https://img.shields.io/badge/CVE--2024--39293-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.134%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Revert "xsk: Support redirect to any socket bound to the same umem"  This reverts commit 2863d665ea41282379f108e4da6c8a2366ba66db.  This patch introduced a potential kernel crash when multiple napi instances redirect to the same AF_XDP socket. By removing the queue_index check, it is possible for multiple napi instances to access the Rx ring at the same time, which will result in a corrupted ring state which can lead to a crash when flushing the rings in __xsk_flush(). This can happen when the linked list of sockets to flush gets corrupted by concurrent accesses. A quick and small fix is not possible, so let us revert this for now.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-39282?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--39282" src="https://img.shields.io/badge/CVE--2024--39282-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: wwan: t7xx: Fix FSM command timeout issue  When driver processes the internal state change command, it use an asynchronous thread to process the command operation. If the main thread detects that the task has timed out, the asynchronous thread will panic when executing the completion notification because the main thread completion object has been released.  BUG: unable to handle page fault for address: fffffffffffffff8 PGD 1f283a067 P4D 1f283a067 PUD 1f283c067 PMD 0 Oops: 0000 [#1] PREEMPT SMP NOPTI RIP: 0010:complete_all+0x3e/0xa0 [...] Call Trace: <TASK> ? __die_body+0x68/0xb0 ? page_fault_oops+0x379/0x3e0 ? exc_page_fault+0x69/0xa0 ? asm_exc_page_fault+0x22/0x30 ? complete_all+0x3e/0xa0 fsm_main_thread+0xa3/0x9c0 [mtk_t7xx (HASH:1400 5)] ? __pfx_autoremove_wake_function+0x10/0x10 kthread+0xd8/0x110 ? __pfx_fsm_main_thread+0x10/0x10 [mtk_t7xx (HASH:1400 5)] ? __pfx_kthread+0x10/0x10 ret_from_fork+0x38/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK> [...] CR2: fffffffffffffff8 ---[ end trace 0000000000000000 ]---  Use the reference counter to ensure safe release as Sergey suggests: https://lore.kernel.org/all/da90f64c-260a-4329-87bf-1f9ff20a5951@gmail.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36885?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--36885" src="https://img.shields.io/badge/CVE--2024--36885-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: drm/nouveau/firmware: Fix SG_DEBUG error with nvkm_firmware_ctor() Currently, enabling SG_DEBUG in the kernel will cause nouveau to hit a BUG() on startup: kernel BUG at include/linux/scatterlist.h:187! invalid opcode: 0000 [#1] PREEMPT SMP NOPTI CPU: 7 PID: 930 Comm: (udev-worker) Not tainted 6.9.0-rc3Lyude-Test+ #30 Hardware name: MSI MS-7A39/A320M GAMING PRO (MS-7A39), BIOS 1.I0 01/22/2019 RIP: 0010:sg_init_one+0x85/0xa0 Code: 69 88 32 01 83 e1 03 f6 c3 03 75 20 a8 01 75 1e 48 09 cb 41 89 54 24 08 49 89 1c 24 41 89 6c 24 0c 5b 5d 41 5c e9 7b b9 88 00 <0f> 0b 0f 0b 0f 0b 48 8b 05 5e 46 9a 01 eb b2 66 66 2e 0f 1f 84 00 RSP: 0018:ffffa776017bf6a0 EFLAGS: 00010246 RAX: 0000000000000000 RBX: ffffa77600d87000 RCX: 000000000000002b RDX: 0000000000000001 RSI: 0000000000000000 RDI: ffffa77680d87000 RBP: 000000000000e000 R08: 0000000000000000 R09: 0000000000000000 R10: ffff98f4c46aa508 R11: 0000000000000000 R12: ffff98f4c46aa508 R13: ffff98f4c46aa008 R14: ffffa77600d4a000 R15: ffffa77600d4a018 FS: 00007feeb5aae980(0000) GS:ffff98f5c4dc0000(0000) knlGS:0000000000000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f22cb9a4520 CR3: 00000001043ba000 CR4: 00000000003506f0 Call Trace: <TASK> ? die+0x36/0x90 ? do_trap+0xdd/0x100 ? sg_init_one+0x85/0xa0 ? do_error_trap+0x65/0x80 ? sg_init_one+0x85/0xa0 ? exc_invalid_op+0x50/0x70 ? sg_init_one+0x85/0xa0 ? asm_exc_invalid_op+0x1a/0x20 ? sg_init_one+0x85/0xa0 nvkm_firmware_ctor+0x14a/0x250 [nouveau] nvkm_falcon_fw_ctor+0x42/0x70 [nouveau] ga102_gsp_booter_ctor+0xb4/0x1a0 [nouveau] r535_gsp_oneinit+0xb3/0x15f0 [nouveau] ? srso_return_thunk+0x5/0x5f ? srso_return_thunk+0x5/0x5f ? nvkm_udevice_new+0x95/0x140 [nouveau] ? srso_return_thunk+0x5/0x5f ? srso_return_thunk+0x5/0x5f ? ktime_get+0x47/0xb0 ? srso_return_thunk+0x5/0x5f nvkm_subdev_oneinit_+0x4f/0x120 [nouveau] nvkm_subdev_init_+0x39/0x140 [nouveau] ? srso_return_thunk+0x5/0x5f nvkm_subdev_init+0x44/0x90 [nouveau] nvkm_device_init+0x166/0x2e0 [nouveau] nvkm_udevice_init+0x47/0x70 [nouveau] nvkm_object_init+0x41/0x1c0 [nouveau] nvkm_ioctl_new+0x16a/0x290 [nouveau] ? __pfx_nvkm_client_child_new+0x10/0x10 [nouveau] ? __pfx_nvkm_udevice_new+0x10/0x10 [nouveau] nvkm_ioctl+0x126/0x290 [nouveau] nvif_object_ctor+0x112/0x190 [nouveau] nvif_device_ctor+0x23/0x60 [nouveau] nouveau_cli_init+0x164/0x640 [nouveau] nouveau_drm_device_init+0x97/0x9e0 [nouveau] ? srso_return_thunk+0x5/0x5f ? pci_update_current_state+0x72/0xb0 ? srso_return_thunk+0x5/0x5f nouveau_drm_probe+0x12c/0x280 [nouveau] ? srso_return_thunk+0x5/0x5f local_pci_probe+0x45/0xa0 pci_device_probe+0xc7/0x270 really_probe+0xe6/0x3a0 __driver_probe_device+0x87/0x160 driver_probe_device+0x1f/0xc0 __driver_attach+0xec/0x1f0 ? __pfx___driver_attach+0x10/0x10 bus_for_each_dev+0x88/0xd0 bus_add_driver+0x116/0x220 driver_register+0x59/0x100 ? __pfx_nouveau_drm_init+0x10/0x10 [nouveau] do_one_initcall+0x5b/0x320 do_init_module+0x60/0x250 init_module_from_file+0x86/0xc0 idempotent_init_module+0x120/0x2b0 __x64_sys_finit_module+0x5e/0xb0 do_syscall_64+0x83/0x160 ? srso_return_thunk+0x5/0x5f entry_SYSCALL_64_after_hwframe+0x71/0x79 RIP: 0033:0x7feeb5cc20cd Code: ff c3 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 1b cd 0c 00 f7 d8 64 89 01 48 RSP: 002b:00007ffcf220b2c8 EFLAGS: 00000246 ORIG_RAX: 0000000000000139 RAX: ffffffffffffffda RBX: 000055fdd2916aa0 RCX: 00007feeb5cc20cd RDX: 0000000000000000 RSI: 000055fdd29161e0 RDI: 0000000000000035 RBP: 00007ffcf220b380 R08: 00007feeb5d8fb20 R09: 00007ffcf220b310 R10: 000055fdd2909dc0 R11: 0000000000000246 R12: 000055 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36347?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--36347" src="https://img.shields.io/badge/CVE--2024--36347-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

[AMD CPU Microcode Signature Verification Vulnerability]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35995?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--35995" src="https://img.shields.io/badge/CVE--2024--35995-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.272%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>48th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: ACPI: CPPC: Use access_width over bit_width for system memory accesses To align with ACPI 6.3+, since bit_width can be any 8-bit value, it cannot be depended on to be always on a clean 8b boundary. This was uncovered on the Cobalt 100 platform. SError Interrupt on CPU26, code 0xbe000011 -- SError CPU: 26 PID: 1510 Comm: systemd-udevd Not tainted 5.15.2.1-13 #1 Hardware name: MICROSOFT CORPORATION, BIOS MICROSOFT CORPORATION pstate: 62400009 (nZCv daif +PAN -UAO +TCO -DIT -SSBS BTYPE=--) pc : cppc_get_perf_caps+0xec/0x410 lr : cppc_get_perf_caps+0xe8/0x410 sp : ffff8000155ab730 x29: ffff8000155ab730 x28: ffff0080139d0038 x27: ffff0080139d0078 x26: 0000000000000000 x25: ffff0080139d0058 x24: 00000000ffffffff x23: ffff0080139d0298 x22: ffff0080139d0278 x21: 0000000000000000 x20: ffff00802b251910 x19: ffff0080139d0000 x18: ffffffffffffffff x17: 0000000000000000 x16: ffffdc7e111bad04 x15: ffff00802b251008 x14: ffffffffffffffff x13: ffff013f1fd63300 x12: 0000000000000006 x11: ffffdc7e128f4420 x10: 0000000000000000 x9 : ffffdc7e111badec x8 : ffff00802b251980 x7 : 0000000000000000 x6 : ffff0080139d0028 x5 : 0000000000000000 x4 : ffff0080139d0018 x3 : 00000000ffffffff x2 : 0000000000000008 x1 : ffff8000155ab7a0 x0 : 0000000000000000 Kernel panic - not syncing: Asynchronous SError Interrupt CPU: 26 PID: 1510 Comm: systemd-udevd Not tainted 5.15.2.1-13 #1 Hardware name: MICROSOFT CORPORATION, BIOS MICROSOFT CORPORATION Call trace: dump_backtrace+0x0/0x1e0 show_stack+0x24/0x30 dump_stack_lvl+0x8c/0xb8 dump_stack+0x18/0x34 panic+0x16c/0x384 add_taint+0x0/0xc0 arm64_serror_panic+0x7c/0x90 arm64_is_fatal_ras_serror+0x34/0xa4 do_serror+0x50/0x6c el1h_64_error_handler+0x40/0x74 el1h_64_error+0x7c/0x80 cppc_get_perf_caps+0xec/0x410 cppc_cpufreq_cpu_init+0x74/0x400 [cppc_cpufreq] cpufreq_online+0x2dc/0xa30 cpufreq_add_dev+0xc0/0xd4 subsys_interface_register+0x134/0x14c cpufreq_register_driver+0x1b0/0x354 cppc_cpufreq_init+0x1a8/0x1000 [cppc_cpufreq] do_one_initcall+0x50/0x250 do_init_module+0x60/0x27c load_module+0x2300/0x2570 __do_sys_finit_module+0xa8/0x114 __arm64_sys_finit_module+0x2c/0x3c invoke_syscall+0x78/0x100 el0_svc_common.constprop.0+0x180/0x1a0 do_el0_svc+0x84/0xa0 el0_svc+0x2c/0xc0 el0t_64_sync_handler+0xa4/0x12c el0t_64_sync+0x1a4/0x1a8 Instead, use access_width to determine the size and use the offset and width to shift and mask the bits to read/write out. Make sure to add a check for system memory since pcc redefines the access_width to subspace id. If access_width is not set, then fall back to using bit_width. [ rjw: Subject and changelog edits, comment adjustments ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35948?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--35948" src="https://img.shields.io/badge/CVE--2024--35948-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.070%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: bcachefs: Check for journal entries overruning end of sb clean section Fix a missing bounds check in superblock validation. Note that we don't yet have repair code for this case - repair code for individual items is generally low priority, since the whole superblock is checksummed, validated prior to write, and we have backups.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35928?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--35928" src="https://img.shields.io/badge/CVE--2024--35928-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: drm/amd/amdgpu: Fix potential ioremap() memory leaks in amdgpu_device_init() This ensures that the memory mapped by ioremap for adev->rmmio, is properly handled in amdgpu_device_init(). If the function exits early due to an error, the memory is unmapped. If the function completes successfully, the memory remains mapped. Reported by smatch: drivers/gpu/drm/amd/amdgpu/amdgpu_device.c:4337 amdgpu_device_init() warn: 'adev->rmmio' from ioremap() not released on lines: 4035,4045,4051,4058,4068,4337

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26720?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--26720" src="https://img.shields.io/badge/CVE--2024--26720-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: mm/writeback: fix possible divide-by-zero in wb_dirty_limits(), again (struct dirty_throttle_control *)->thresh is an unsigned long, but is passed as the u32 divisor argument to div_u64(). On architectures where unsigned long is 64 bytes, the argument will be implicitly truncated. Use div64_u64() instead of div_u64() so that the value used in the "is this a safe division" check is the same as the divisor. Also, remove redundant cast of the numerator to u64, as that should happen implicitly. This would be difficult to exploit in memcg domain, given the ratio-based arithmetic domain_drity_limits() uses, but is much easier in global writeback domain with a BDI_CAP_STRICTLIMIT-backing device, using e.g. vm.dirty_bytes=(1<<32)*PAGE_SIZE so that dtc->thresh == (1<<32)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26713?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2024--26713" src="https://img.shields.io/badge/CVE--2024--26713-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: powerpc/pseries/iommu: Fix iommu initialisation during DLPAR add When a PCI device is dynamically added, the kernel oopses with a NULL pointer dereference: BUG: Kernel NULL pointer dereference on read at 0x00000030 Faulting instruction address: 0xc0000000006bbe5c Oops: Kernel access of bad area, sig: 11 [#1] LE PAGE_SIZE=64K MMU=Radix SMP NR_CPUS=2048 NUMA pSeries Modules linked in: rpadlpar_io rpaphp rpcsec_gss_krb5 auth_rpcgss nfsv4 dns_resolver nfs lockd grace fscache netfs xsk_diag bonding nft_compat nf_tables nfnetlink rfkill binfmt_misc dm_multipath rpcrdma sunrpc rdma_ucm ib_srpt ib_isert iscsi_target_mod target_core_mod ib_umad ib_iser libiscsi scsi_transport_iscsi ib_ipoib rdma_cm iw_cm ib_cm mlx5_ib ib_uverbs ib_core pseries_rng drm drm_panel_orientation_quirks xfs libcrc32c mlx5_core mlxfw sd_mod t10_pi sg tls ibmvscsi ibmveth scsi_transport_srp vmx_crypto pseries_wdt psample dm_mirror dm_region_hash dm_log dm_mod fuse CPU: 17 PID: 2685 Comm: drmgr Not tainted 6.7.0-203405+ #66 Hardware name: IBM,9080-HEX POWER10 (raw) 0x800200 0xf000006 of:IBM,FW1060.00 (NH1060_008) hv:phyp pSeries NIP: c0000000006bbe5c LR: c000000000a13e68 CTR: c0000000000579f8 REGS: c00000009924f240 TRAP: 0300 Not tainted (6.7.0-203405+) MSR: 8000000000009033 <SF,EE,ME,IR,DR,RI,LE> CR: 24002220 XER: 20040006 CFAR: c000000000a13e64 DAR: 0000000000000030 DSISR: 40000000 IRQMASK: 0 ... NIP sysfs_add_link_to_group+0x34/0x94 LR iommu_device_link+0x5c/0x118 Call Trace: iommu_init_device+0x26c/0x318 (unreliable) iommu_device_link+0x5c/0x118 iommu_init_device+0xa8/0x318 iommu_probe_device+0xc0/0x134 iommu_bus_notifier+0x44/0x104 notifier_call_chain+0xb8/0x19c blocking_notifier_call_chain+0x64/0x98 bus_notify+0x50/0x7c device_add+0x640/0x918 pci_device_add+0x23c/0x298 of_create_pci_dev+0x400/0x884 of_scan_pci_dev+0x124/0x1b0 __of_scan_bus+0x78/0x18c pcibios_scan_phb+0x2a4/0x3b0 init_phb_dynamic+0xb8/0x110 dlpar_add_slot+0x170/0x3b8 [rpadlpar_io] add_slot_store.part.0+0xb4/0x130 [rpadlpar_io] kobj_attr_store+0x2c/0x48 sysfs_kf_write+0x64/0x78 kernfs_fop_write_iter+0x1b0/0x290 vfs_write+0x350/0x4a0 ksys_write+0x84/0x140 system_call_exception+0x124/0x330 system_call_vectored_common+0x15c/0x2ec Commit a940904443e4 ("powerpc/iommu: Add iommu_ops to report capabilities and allow blocking domains") broke DLPAR add of PCI devices. The above added iommu_device structure to pci_controller. During system boot, PCI devices are discovered and this newly added iommu_device structure is initialized by a call to iommu_device_register(). During DLPAR add of a PCI device, a new pci_controller structure is allocated but there are no calls made to iommu_device_register() interface. Fix is to register the iommu device during DLPAR add as well. [mpe: Trim oops and tweak some change log wording]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48993?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2022--48993" src="https://img.shields.io/badge/CVE--2022--48993-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48900?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2022--48900" src="https://img.shields.io/badge/CVE--2022--48900-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-47472?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2021--47472" src="https://img.shields.io/badge/CVE--2021--47472-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

** REJECT ** This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2013-7445?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium : CVE--2013--7445" src="https://img.shields.io/badge/CVE--2013--7445-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.833%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>73rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The Direct Rendering Manager (DRM) subsystem in the Linux kernel through 4.x mishandles requests for Graphics Execution Manager (GEM) objects, which allows context-dependent attackers to cause a denial of service (memory consumption) via an application that processes graphics data, as demonstrated by JavaScript code that creates many CANVAS elements for rendering by Chrome or Firefox.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-33053?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2023--33053" src="https://img.shields.io/badge/CVE--2023--33053-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Memory corruption in Kernel while parsing metadata.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-26934?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2021--26934" src="https://img.shields.io/badge/CVE--2021--26934-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.081%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel 4.18 through 5.10.16, as used by Xen. The backend allocation (aka be-alloc) mode of the drm_xen_front drivers was not meant to be a supported configuration, but this wasn't stated accordingly in its support status entry.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-19814?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2019--19814" src="https://img.shields.io/badge/CVE--2019--19814-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.980%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>75th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel 5.0.21, mounting a crafted f2fs filesystem image can cause __remove_dirty_segment slab-out-of-bounds write access because an array is bounded by the number of dirty types (8) but the array index can exceed this.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-19378?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2019--19378" src="https://img.shields.io/badge/CVE--2019--19378-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.507%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>64th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel 5.0.21, mounting a crafted btrfs filesystem image can lead to slab-out-of-bounds write access in index_rbio_pages in fs/btrfs/raid56.c.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-12931?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2018--12931" src="https://img.shields.io/badge/CVE--2018--12931-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.114%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ntfs_attr_find in the ntfs.ko filesystem driver in the Linux kernel 4.15.0 allows attackers to trigger a stack-based out-of-bounds write and cause a denial of service (kernel oops or panic) or possibly have unspecified other impact via a crafted ntfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-12930?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2018--12930" src="https://img.shields.io/badge/CVE--2018--12930-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.114%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ntfs_end_buffer_async_read in the ntfs.ko filesystem driver in the Linux kernel 4.15.0 allows attackers to trigger a stack-based out-of-bounds write and cause a denial of service (kernel oops or panic) or possibly have unspecified other impact via a crafted ntfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-13165?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.8: CVE--2017--13165" src="https://img.shields.io/badge/CVE--2017--13165-lightgrey?label=low%207.8&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An elevation of privilege vulnerability in the kernel file system. Product: Android. Versions: Android kernel. Android ID A-31269937.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-14899?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.4: CVE--2019--14899" src="https://img.shields.io/badge/CVE--2019--14899-lightgrey?label=low%207.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.192%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was discovered in Linux, FreeBSD, OpenBSD, MacOS, iOS, and Android that allows a malicious access point, or an adjacent user, to determine if a connected user is using a VPN, make positive inferences about the websites they are visiting, and determine the correct sequence and acknowledgement numbers in use, allowing the bad actor to inject data into the TCP stream. This provides everything that is needed for an attacker to hijack active connections inside the VPN tunnel.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-45885?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.0: CVE--2022--45885" src="https://img.shields.io/badge/CVE--2022--45885-lightgrey?label=low%207.0&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvb_frontend.c has a race condition that can cause a use-after-free when a device is disconnected.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-45884?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.0: CVE--2022--45884" src="https://img.shields.io/badge/CVE--2022--45884-lightgrey?label=low%207.0&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.0.9. drivers/media/dvb-core/dvbdev.c has a use-after-free, related to dvb_register_device dynamically allocating fops.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6238?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 6.7: CVE--2023--6238" src="https://img.shields.io/badge/CVE--2023--6238-lightgrey?label=low%206.7&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A buffer overflow vulnerability was found in the NVM Express (NVMe) driver in the Linux kernel. Only privileged user could specify a small meta buffer and let the device perform larger Direct Memory Access (DMA) into the same buffer, overwriting unrelated kernel memory, causing random kernel crashes and memory corruption.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-0564?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2024--0564" src="https://img.shields.io/badge/CVE--2024--0564-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.091%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernel's memory deduplication mechanism. The max page sharing of Kernel Samepage Merging (KSM), added in Linux kernel version 4.4.0-96.119, can create a side channel. When the attacker and the victim share the same host and the default setting of KSM is "max page sharing=256", it is possible for the attacker to time the unmap to merge with the victim's page. The unmapping time depends on whether it merges with the victim's page and additional physical pages are created beyond the KSM's "max page share". Through these operations, the attacker can leak the victim's page.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-44034?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 6.4: CVE--2022--44034" src="https://img.shields.io/badge/CVE--2022--44034-lightgrey?label=low%206.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel through 6.0.6. drivers/char/pcmcia/scr24x_cs.c has a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling open(), aka a race condition between scr24x_open() and scr24x_remove().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-1121?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 5.9: CVE--2018--1121" src="https://img.shields.io/badge/CVE--2018--1121-lightgrey?label=low%205.9&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.9</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>2.080%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>82nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

procps-ng, procps is vulnerable to a process hiding through race condition. Since the kernel's proc_pid_readdir() returns PID entries in ascending numeric order, a process occupying a high PID can use inotify events to determine when the process list is being scanned, and fork/exec to obtain a lower PID, thus avoiding enumeration. An unprivileged attacker can hide a process from procps-ng's utilities by exploiting a race condition in reading /proc/PID entries. This vulnerability affects procps and procps-ng up to version 3.3.15, newer versions might be affected also.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-12929?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2018--12929" src="https://img.shields.io/badge/CVE--2018--12929-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.121%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

ntfs_read_locked_inode in the ntfs.ko filesystem driver in the Linux kernel 4.15.0 allows attackers to trigger a use-after-free read and possibly cause a denial of service (kernel oops or panic) via a crafted ntfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2018-12928?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2018--12928" src="https://img.shields.io/badge/CVE--2018--12928-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.065%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel 4.15.0, a NULL pointer dereference was discovered in hfs_ext_read_extent in hfs.ko. This can occur during a mount of a crafted hfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-13693?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2017--13693" src="https://img.shields.io/badge/CVE--2017--13693-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.062%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The acpi_ds_create_operands() function in drivers/acpi/acpica/dsutils.c in the Linux kernel through 4.12.9 does not flush the operand cache and causes a kernel stack dump, which allows local users to obtain sensitive information from kernel memory and bypass the KASLR protection mechanism (in the kernel through 4.9) via a crafted ACPI table.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2017-0537?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 4.7: CVE--2017--0537" src="https://img.shields.io/badge/CVE--2017--0537-lightgrey?label=low%204.7&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.198%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An information disclosure vulnerability in the kernel USB gadget driver could enable a local malicious application to access data outside of its permission levels. This issue is rated as Moderate because it first requires compromising a privileged process. Product: Android. Versions: Kernel-3.18. Android ID: A-31614969.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-4010?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 4.6: CVE--2023--4010" src="https://img.shields.io/badge/CVE--2023--4010-lightgrey?label=low%204.6&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.110%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the USB Host Controller Driver framework in the Linux kernel. The usb_giveback_urb function has a logic loophole in its implementation. Due to the inappropriate judgment condition of the goto statement, the function cannot return under the input of a specific malformed descriptor file, so it falls into an endless loop, resulting in a denial of service.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2019-15213?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 4.6: CVE--2019--15213" src="https://img.shields.io/badge/CVE--2019--15213-lightgrey?label=low%204.6&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.073%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel before 5.2.3. There is a use-after-free caused by a malicious USB device in the drivers/media/usb/dvb-usb/dvb-usb-init.c driver.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-14304?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 4.4: CVE--2020--14304" src="https://img.shields.io/badge/CVE--2020--14304-lightgrey?label=low%204.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.098%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A memory disclosure flaw was found in the Linux kernel's ethernet drivers, in the way it read data from the EEPROM of the device. This flaw allows a local user to read uninitialized values from the kernel memory. The highest threat from this vulnerability is to confidentiality.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-41848?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 4.2: CVE--2022--41848" src="https://img.shields.io/badge/CVE--2022--41848-lightgrey?label=low%204.2&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.2</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:P/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

drivers/char/pcmcia/synclink_cs.c in the Linux kernel through 5.19.12 has a race condition and resultant use-after-free if a physically proximate attacker removes a PCMCIA device while calling ioctl, aka a race condition between mgslpc_ioctl and mgslpc_detach.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-35501?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 3.4: CVE--2020--35501" src="https://img.shields.io/badge/CVE--2020--35501-lightgrey?label=low%203.4&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>3.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.012%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the Linux kernels implementation of audit rules, where a syscall can unexpectedly not be correctly not be logged by the audit subsystem

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pam</strong> <code>1.5.3-5ubuntu5.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pam@1.5.3-5ubuntu5.1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-10963?s=ubuntu&n=pam&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 7.4: CVE--2024--10963" src="https://img.shields.io/badge/CVE--2024--10963-lightgrey?label=medium%207.4&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.099%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname, gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who can access certain services or terminals.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-10041?s=ubuntu&n=pam&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 4.7: CVE--2024--10041" src="https://img.shields.io/badge/CVE--2024--10041-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs, the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result in leaked passwords, such as those found in /etc/shadow while performing authentications.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libcap2</strong> <code>1:2.66-5ubuntu2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libcap2@1%3A2.66-5ubuntu2?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-1390?s=ubuntu&n=libcap2&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C1%3A2.66-5ubuntu2.2"><img alt="medium : CVE--2025--1390" src="https://img.shields.io/badge/CVE--2025--1390-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1:2.66-5ubuntu2.2</code></td></tr>
<tr><td>Fixed version</td><td><code>1:2.66-5ubuntu2.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The PAM module pam_cap.so of libcap configuration supports group names starting with “@”, during actual parsing, configurations not starting with “@” are incorrectly recognized as group names. This may result in nonintended users being granted an inherited capability set, potentially leading to security risks. Attackers can exploit this vulnerability to achieve local privilege escalation on systems where /etc/security/capability.conf is used to configure user inherited privileges by constructing specific usernames.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.8.3-1.1ubuntu3.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnutls28@3.8.3-1.1ubuntu3.2?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12243?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C3.8.3-1.1ubuntu3.3"><img alt="medium 5.3: CVE--2024--12243" src="https://img.shields.io/badge/CVE--2024--12243-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.8.3-1.1ubuntu3.3</code></td></tr>
<tr><td>Fixed version</td><td><code>3.8.3-1.1ubuntu3.3</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.171%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GnuTLS, which relies on libtasn1 for ASN.1 data processing. Due to an inefficient algorithm in libtasn1, decoding certain DER-encoded certificate data can take excessive time, leading to increased resource consumption. This flaw allows a remote attacker to send a specially crafted certificate, causing GnuTLS to become unresponsive or slow, resulting in a denial-of-service condition.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>wget</strong> <code>1.21.4-1ubuntu4.1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/wget@1.21.4-1ubuntu4.1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2021-31879?s=ubuntu&n=wget&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="medium 6.1: CVE--2021--31879" src="https://img.shields.io/badge/CVE--2021--31879-lightgrey?label=medium%206.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.095%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GNU Wget through 1.21.1 does not omit the Authorization header upon a redirect to a different origin, a related issue to CVE-2018-1000007.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libtasn1-6</strong> <code>4.19.0-3build1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libtasn1-6@4.19.0-3build1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-12133?s=ubuntu&n=libtasn1-6&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C4.19.0-3ubuntu0.24.04.1"><img alt="medium 5.3: CVE--2024--12133" src="https://img.shields.io/badge/CVE--2024--12133-lightgrey?label=medium%205.3&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><4.19.0-3ubuntu0.24.04.1</code></td></tr>
<tr><td>Fixed version</td><td><code>4.19.0-3ubuntu0.24.04.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw in libtasn1 causes inefficient handling of specific certificate data. When processing a large number of elements in a certificate, libtasn1 takes much longer than expected, which can slow down or even crash the system. This flaw allows an attacker to send a specially crafted certificate, causing a denial of service attack.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>patch</strong> <code>2.7.6-7build3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/patch@2.7.6-7build3?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2018-6952?s=ubuntu&n=patch&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2018--6952" src="https://img.shields.io/badge/CVE--2018--6952-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>11.377%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A double free exists in the another_hunk function in pch.c in GNU patch through 2.7.6.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2021-45261?s=ubuntu&n=patch&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2021--45261" src="https://img.shields.io/badge/CVE--2021--45261-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.087%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An Invalid Pointer vulnerability exists in GNU patch 2.7 via the another_hunk function, which causes a Denial of Service.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>shadow</strong> <code>1:4.13+dfsg1-4ubuntu3.2</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/shadow@1%3A4.13%2Bdfsg1-4ubuntu3.2?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-56433?s=ubuntu&n=shadow&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low : CVE--2024--56433" src="https://img.shields.io/badge/CVE--2024--56433-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>3.171%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>86th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

shadow-utils (aka shadow) 4.4 through 4.17.0 establishes a default /etc/subuid behavior (e.g., uid 100000 through 165535 for the first user account) that can realistically conflict with the uids of users defined on locally administered networks, potentially leading to account takeover, e.g., by leveraging newuidmap for access to an NFS home directory (or same-host resources in the case of remote logins by these local network users). NOTE: it may also be argued that system administrators should not have assigned uids, within local networks, that are within the range that can occur in /etc/subuid.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>openssl</strong> <code>3.0.13-0ubuntu3.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openssl@3.0.13-0ubuntu3.5?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-41996?s=ubuntu&n=openssl&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low : CVE--2024--41996" src="https://img.shields.io/badge/CVE--2024--41996-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.438%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>60th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Validating the order of the public keys in the Diffie-Hellman Key Agreement Protocol, when an approved safe prime is used, allows remote attackers (from the client side) to trigger unnecessarily expensive server-side DHE modular-exponentiation calculations. The client may cause asymmetric resource consumption. The basic attack scenario is that the client must claim that it can only communicate with DHE, and the server must be configured to allow DHE and validate the order of the public key.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>libgcrypt20</strong> <code>1.10.3-2build1</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libgcrypt20@1.10.3-2build1?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-2236?s=ubuntu&n=libgcrypt20&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low : CVE--2024--2236" src="https://img.shields.io/badge/CVE--2024--2236-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.123%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>29th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A timing-based side-channel flaw was found in libgcrypt's RSA implementation. This issue may allow a remote attacker to initiate a Bleichenbacher-style attack, which can lead to the decryption of RSA ciphertexts.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>coreutils</strong> <code>9.4-3ubuntu6</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/coreutils@9.4-3ubuntu6?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2016-2781?s=ubuntu&n=coreutils&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 6.5: CVE--2016--2781" src="https://img.shields.io/badge/CVE--2016--2781-lightgrey?label=low%206.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>6.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.072%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

chroot in GNU coreutils, when used with --userspec, allows local users to escape to the parent session via a crafted TIOCSTI ioctl call, which pushes characters to the terminal's input buffer.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>binutils</strong> <code>2.42-4ubuntu2.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/binutils@2.42-4ubuntu2.4?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2017-13716?s=ubuntu&n=binutils&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 5.5: CVE--2017--13716" src="https://img.shields.io/badge/CVE--2017--13716-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.255%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>46th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

The C++ symbol demangler routine in cplus-dem.c in libiberty, as distributed in GNU Binutils 2.29, allows remote attackers to cause a denial of service (excessive memory allocation and application crash) via a crafted file, as demonstrated by a call from the Binary File Descriptor (BFD) library (aka libbfd).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>glibc</strong> <code>2.39-0ubuntu8.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/glibc@2.39-0ubuntu8.4?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2016-20013?s=ubuntu&n=glibc&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 7.5: CVE--2016--20013" src="https://img.shields.io/badge/CVE--2016--20013-lightgrey?label=low%207.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.201%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

sha256crypt and sha512crypt through 0.6 allow attackers to cause a denial of service (CPU consumption) because the algorithm's runtime is proportional to the square of the length of the password.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>curl</strong> <code>8.5.0-2ubuntu10.6</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.6?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-0167?s=ubuntu&n=curl&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low : CVE--2025--0167" src="https://img.shields.io/badge/CVE--2025--0167-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>EPSS Score</td><td><code>0.054%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

When asked to use a `.netrc` file for credentials **and** to follow HTTP redirects, curl could leak the password used for the first host to the followed-to host under certain circumstances.  This flaw only manifests itself if the netrc file has a `default` entry that omits both login and password. A rare circumstance.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>gnupg2</strong> <code>2.4.4-2ubuntu17</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnupg2@2.4.4-2ubuntu17?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-3219?s=ubuntu&n=gnupg2&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3E%3D0"><img alt="low 3.3: CVE--2022--3219" src="https://img.shields.io/badge/CVE--2022--3219-lightgrey?label=low%203.3&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code>>=0</code></td></tr>
<tr><td>Fixed version</td><td><strong>Not Fixed</strong></td></tr>
<tr><td>CVSS Score</td><td><code>3.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.012%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

GnuPG can be made to spin on a relatively small input by (for example) crafting a public key with thousands of signatures attached, compressed down to just a few KB.

</blockquote>
</details>
</details></td></tr>
</table>

