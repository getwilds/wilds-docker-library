# Vulnerability Report for getwilds/python-dl:1.0

Report generated on 2025-09-10 01:44:16 PST

<h2>:mag: Vulnerabilities of <code>getwilds/python-dl:1.0</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/python-dl:1.0</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:91a4f34604d5a3bc7568c97b52b5ed72cc454565ce1dd472dce16d13afaa8911</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 78" src="https://img.shields.io/badge/high-78-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/medium-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/low-0-lightgrey"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>9.3 GB</td></tr>
<tr><td>packages</td><td>413</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 72" src="https://img.shields.io/badge/H-72-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>linux</strong> <code>5.15.0-88.98</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@5.15.0-88.98?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-47685?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-127.137"><img alt="high 9.1: CVE--2024--47685" src="https://img.shields.io/badge/CVE--2024--47685-lightgrey?label=high%209.1&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-127.137</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-127.137</code></td></tr>
<tr><td>CVSS Score</td><td><code>9.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.790%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>73rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_reject_ipv6: fix nf_reject_ip6_tcphdr_put()  syzbot reported that nf_reject_ip6_tcphdr_put() was possibly sending garbage on the four reserved tcp bits (th->res1)  Use skb_put_zero() to clear the whole TCP header, as done in nf_reject_ip_tcphdr_put()  BUG: KMSAN: uninit-value in nf_reject_ip6_tcphdr_put+0x688/0x6c0 net/ipv6/netfilter/nf_reject_ipv6.c:255 nf_reject_ip6_tcphdr_put+0x688/0x6c0 net/ipv6/netfilter/nf_reject_ipv6.c:255 nf_send_reset6+0xd84/0x15b0 net/ipv6/netfilter/nf_reject_ipv6.c:344 nft_reject_inet_eval+0x3c1/0x880 net/netfilter/nft_reject_inet.c:48 expr_call_ops_eval net/netfilter/nf_tables_core.c:240 [inline] nft_do_chain+0x438/0x22a0 net/netfilter/nf_tables_core.c:288 nft_do_chain_inet+0x41a/0x4f0 net/netfilter/nft_chain_filter.c:161 nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline] nf_hook_slow+0xf4/0x400 net/netfilter/core.c:626 nf_hook include/linux/netfilter.h:269 [inline] NF_HOOK include/linux/netfilter.h:312 [inline] ipv6_rcv+0x29b/0x390 net/ipv6/ip6_input.c:310 __netif_receive_skb_one_core net/core/dev.c:5661 [inline] __netif_receive_skb+0x1da/0xa00 net/core/dev.c:5775 process_backlog+0x4ad/0xa50 net/core/dev.c:6108 __napi_poll+0xe7/0x980 net/core/dev.c:6772 napi_poll net/core/dev.c:6841 [inline] net_rx_action+0xa5a/0x19b0 net/core/dev.c:6963 handle_softirqs+0x1ce/0x800 kernel/softirq.c:554 __do_softirq+0x14/0x1a kernel/softirq.c:588 do_softirq+0x9a/0x100 kernel/softirq.c:455 __local_bh_enable_ip+0x9f/0xb0 kernel/softirq.c:382 local_bh_enable include/linux/bottom_half.h:33 [inline] rcu_read_unlock_bh include/linux/rcupdate.h:908 [inline] __dev_queue_xmit+0x2692/0x5610 net/core/dev.c:4450 dev_queue_xmit include/linux/netdevice.h:3105 [inline] neigh_resolve_output+0x9ca/0xae0 net/core/neighbour.c:1565 neigh_output include/net/neighbour.h:542 [inline] ip6_finish_output2+0x2347/0x2ba0 net/ipv6/ip6_output.c:141 __ip6_finish_output net/ipv6/ip6_output.c:215 [inline] ip6_finish_output+0xbb8/0x14b0 net/ipv6/ip6_output.c:226 NF_HOOK_COND include/linux/netfilter.h:303 [inline] ip6_output+0x356/0x620 net/ipv6/ip6_output.c:247 dst_output include/net/dst.h:450 [inline] NF_HOOK include/linux/netfilter.h:314 [inline] ip6_xmit+0x1ba6/0x25d0 net/ipv6/ip6_output.c:366 inet6_csk_xmit+0x442/0x530 net/ipv6/inet6_connection_sock.c:135 __tcp_transmit_skb+0x3b07/0x4880 net/ipv4/tcp_output.c:1466 tcp_transmit_skb net/ipv4/tcp_output.c:1484 [inline] tcp_connect+0x35b6/0x7130 net/ipv4/tcp_output.c:4143 tcp_v6_connect+0x1bcc/0x1e40 net/ipv6/tcp_ipv6.c:333 __inet_stream_connect+0x2ef/0x1730 net/ipv4/af_inet.c:679 inet_stream_connect+0x6a/0xd0 net/ipv4/af_inet.c:750 __sys_connect_file net/socket.c:2061 [inline] __sys_connect+0x606/0x690 net/socket.c:2078 __do_sys_connect net/socket.c:2088 [inline] __se_sys_connect net/socket.c:2085 [inline] __x64_sys_connect+0x91/0xe0 net/socket.c:2085 x64_sys_call+0x27a5/0x3ba0 arch/x86/include/generated/asm/syscalls_64.h:43 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  Uninit was stored to memory at: nf_reject_ip6_tcphdr_put+0x60c/0x6c0 net/ipv6/netfilter/nf_reject_ipv6.c:249 nf_send_reset6+0xd84/0x15b0 net/ipv6/netfilter/nf_reject_ipv6.c:344 nft_reject_inet_eval+0x3c1/0x880 net/netfilter/nft_reject_inet.c:48 expr_call_ops_eval net/netfilter/nf_tables_core.c:240 [inline] nft_do_chain+0x438/0x22a0 net/netfilter/nf_tables_core.c:288 nft_do_chain_inet+0x41a/0x4f0 net/netfilter/nft_chain_filter.c:161 nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline] nf_hook_slow+0xf4/0x400 net/netfilter/core.c:626 nf_hook include/linux/netfilter.h:269 [inline] NF_HOOK include/linux/netfilter.h:312 [inline] ipv6_rcv+0x29b/0x390 net/ipv6/ip6_input.c:310 __netif_receive_skb_one_core ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2020-12351?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-130.140"><img alt="high 8.8: CVE--2020--12351" src="https://img.shields.io/badge/CVE--2020--12351-lightgrey?label=high%208.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-130.140</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-130.140</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>3.242%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>87th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Improper input validation in BlueZ may allow an unauthenticated user to potentially enable escalation of privilege via adjacent access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57850?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high 7.8: CVE--2024--57850" src="https://img.shields.io/badge/CVE--2024--57850-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jffs2: Prevent rtime decompress memory corruption  The rtime decompression routine does not fully check bounds during the entirety of the decompression pass and can corrupt memory outside the decompression buffer if the compressed data is corrupted. This adds the required check to prevent this failure mode.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57798?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-136.147"><img alt="high 7.8: CVE--2024--57798" src="https://img.shields.io/badge/CVE--2024--57798-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-136.147</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-136.147</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/dp_mst: Ensure mst_primary pointer is valid in drm_dp_mst_handle_up_req()  While receiving an MST up request message from one thread in drm_dp_mst_handle_up_req(), the MST topology could be removed from another thread via drm_dp_mst_topology_mgr_set_mst(false), freeing mst_primary and setting drm_dp_mst_topology_mgr::mst_primary to NULL. This could lead to a NULL deref/use-after-free of mst_primary in drm_dp_mst_handle_up_req().  Avoid the above by holding a reference for mst_primary in drm_dp_mst_handle_up_req() while it's used.  v2: Fix kfreeing the request if getting an mst_primary reference fails.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56658?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-136.147"><img alt="high 7.8: CVE--2024--56658" src="https://img.shields.io/badge/CVE--2024--56658-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-136.147</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-136.147</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: defer final 'struct net' free in netns dismantle  Ilya reported a slab-use-after-free in dst_destroy [1]  Issue is in xfrm6_net_init() and xfrm4_net_init() :  They copy xfrm[46]_dst_ops_template into net->xfrm.xfrm[46]_dst_ops.  But net structure might be freed before all the dst callbacks are called. So when dst_destroy() calls later :  if (dst->ops->destroy) dst->ops->destroy(dst);  dst->ops points to the old net->xfrm.xfrm[46]_dst_ops, which has been freed.  See a relevant issue fixed in :  ac888d58869b ("net: do not delay dst_entries_add() in dst_release()")  A fix is to queue the 'struct net' to be freed after one another cleanup_net() round (and existing rcu_barrier())  [1]  BUG: KASAN: slab-use-after-free in dst_destroy (net/core/dst.c:112) Read of size 8 at addr ffff8882137ccab0 by task swapper/37/0 Dec 03 05:46:18 kernel: CPU: 37 UID: 0 PID: 0 Comm: swapper/37 Kdump: loaded Not tainted 6.12.0 #67 Hardware name: Red Hat KVM/RHEL, BIOS 1.16.1-1.el9 04/01/2014 Call Trace: <IRQ> dump_stack_lvl (lib/dump_stack.c:124) print_address_description.constprop.0 (mm/kasan/report.c:378) ? dst_destroy (net/core/dst.c:112) print_report (mm/kasan/report.c:489) ? dst_destroy (net/core/dst.c:112) ? kasan_addr_to_slab (mm/kasan/common.c:37) kasan_report (mm/kasan/report.c:603) ? dst_destroy (net/core/dst.c:112) ? rcu_do_batch (kernel/rcu/tree.c:2567) dst_destroy (net/core/dst.c:112) rcu_do_batch (kernel/rcu/tree.c:2567) ? __pfx_rcu_do_batch (kernel/rcu/tree.c:2491) ? lockdep_hardirqs_on_prepare (kernel/locking/lockdep.c:4339 kernel/locking/lockdep.c:4406) rcu_core (kernel/rcu/tree.c:2825) handle_softirqs (kernel/softirq.c:554) __irq_exit_rcu (kernel/softirq.c:589 kernel/softirq.c:428 kernel/softirq.c:637) irq_exit_rcu (kernel/softirq.c:651) sysvec_apic_timer_interrupt (arch/x86/kernel/apic/apic.c:1049 arch/x86/kernel/apic/apic.c:1049) </IRQ> <TASK> asm_sysvec_apic_timer_interrupt (./arch/x86/include/asm/idtentry.h:702) RIP: 0010:default_idle (./arch/x86/include/asm/irqflags.h:37 ./arch/x86/include/asm/irqflags.h:92 arch/x86/kernel/process.c:743) Code: 00 4d 29 c8 4c 01 c7 4c 29 c2 e9 6e ff ff ff 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 66 90 0f 00 2d c7 c9 27 00 fb f4 <fa> c3 cc cc cc cc 66 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 40 00 90 RSP: 0018:ffff888100d2fe00 EFLAGS: 00000246 RAX: 00000000001870ed RBX: 1ffff110201a5fc2 RCX: ffffffffb61a3e46 RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffffb3d4d123 RBP: 0000000000000000 R08: 0000000000000001 R09: ffffed11c7e1835d R10: ffff888e3f0c1aeb R11: 0000000000000000 R12: 0000000000000000 R13: ffff888100d20000 R14: dffffc0000000000 R15: 0000000000000000 ? ct_kernel_exit.constprop.0 (kernel/context_tracking.c:148) ? cpuidle_idle_call (kernel/sched/idle.c:186) default_idle_call (./include/linux/cpuidle.h:143 kernel/sched/idle.c:118) cpuidle_idle_call (kernel/sched/idle.c:186) ? __pfx_cpuidle_idle_call (kernel/sched/idle.c:168) ? lock_release (kernel/locking/lockdep.c:467 kernel/locking/lockdep.c:5848) ? lockdep_hardirqs_on_prepare (kernel/locking/lockdep.c:4347 kernel/locking/lockdep.c:4406) ? tsc_verify_tsc_adjust (arch/x86/kernel/tsc_sync.c:59) do_idle (kernel/sched/idle.c:326) cpu_startup_entry (kernel/sched/idle.c:423 (discriminator 1)) start_secondary (arch/x86/kernel/smpboot.c:202 arch/x86/kernel/smpboot.c:282) ? __pfx_start_secondary (arch/x86/kernel/smpboot.c:232) ? soft_restart_cpu (arch/x86/kernel/head_64.S:452) common_startup_64 (arch/x86/kernel/head_64.S:414) </TASK> Dec 03 05:46:18 kernel: Allocated by task 12184: kasan_save_stack (mm/kasan/common.c:48) kasan_save_track (./arch/x86/include/asm/current.h:49 mm/kasan/common.c:60 mm/kasan/common.c:69) __kasan_slab_alloc (mm/kasan/common.c:319 mm/kasan/common.c:345) kmem_cache_alloc_noprof (mm/slub.c:4085 mm/slub.c:4134 mm/slub.c:4141) copy_net_ns (net/core/net_namespace.c:421 net/core/net_namespace.c:480) create_new_namespaces ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56608?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-141.151"><img alt="high 7.8: CVE--2024--56608" src="https://img.shields.io/badge/CVE--2024--56608-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-141.151</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-141.151</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Fix out-of-bounds access in 'dcn21_link_encoder_create'  An issue was identified in the dcn21_link_encoder_create function where an out-of-bounds access could occur when the hpd_source index was used to reference the link_enc_hpd_regs array. This array has a fixed size and the index was not being checked against the array's bounds before accessing it.  This fix adds a conditional check to ensure that the hpd_source index is within the valid range of the link_enc_hpd_regs array. If the index is out of bounds, the function now returns NULL to prevent undefined behavior.  References:  [   65.920507] ------------[ cut here ]------------ [   65.920510] UBSAN: array-index-out-of-bounds in drivers/gpu/drm/amd/amdgpu/../display/dc/resource/dcn21/dcn21_resource.c:1312:29 [   65.920519] index 7 is out of range for type 'dcn10_link_enc_hpd_registers [5]' [   65.920523] CPU: 3 PID: 1178 Comm: modprobe Tainted: G           OE 6.8.0-cleanershaderfeatureresetasdntipmi200nv2132 #13 [   65.920525] Hardware name: AMD Majolica-RN/Majolica-RN, BIOS WMJ0429N_Weekly_20_04_2 04/29/2020 [   65.920527] Call Trace: [   65.920529]  <TASK> [   65.920532]  dump_stack_lvl+0x48/0x70 [   65.920541]  dump_stack+0x10/0x20 [   65.920543]  __ubsan_handle_out_of_bounds+0xa2/0xe0 [   65.920549]  dcn21_link_encoder_create+0xd9/0x140 [amdgpu] [   65.921009]  link_create+0x6d3/0xed0 [amdgpu] [   65.921355]  create_links+0x18a/0x4e0 [amdgpu] [   65.921679]  dc_create+0x360/0x720 [amdgpu] [   65.921999]  ? dmi_matches+0xa0/0x220 [   65.922004]  amdgpu_dm_init+0x2b6/0x2c90 [amdgpu] [   65.922342]  ? console_unlock+0x77/0x120 [   65.922348]  ? dev_printk_emit+0x86/0xb0 [   65.922354]  dm_hw_init+0x15/0x40 [amdgpu] [   65.922686]  amdgpu_device_init+0x26a8/0x33a0 [amdgpu] [   65.922921]  amdgpu_driver_load_kms+0x1b/0xa0 [amdgpu] [   65.923087]  amdgpu_pci_probe+0x1b7/0x630 [amdgpu] [   65.923087]  local_pci_probe+0x4b/0xb0 [   65.923087]  pci_device_probe+0xc8/0x280 [   65.923087]  really_probe+0x187/0x300 [   65.923087]  __driver_probe_device+0x85/0x130 [   65.923087]  driver_probe_device+0x24/0x110 [   65.923087]  __driver_attach+0xac/0x1d0 [   65.923087]  ? __pfx___driver_attach+0x10/0x10 [   65.923087]  bus_for_each_dev+0x7d/0xd0 [   65.923087]  driver_attach+0x1e/0x30 [   65.923087]  bus_add_driver+0xf2/0x200 [   65.923087]  driver_register+0x64/0x130 [   65.923087]  ? __pfx_amdgpu_init+0x10/0x10 [amdgpu] [   65.923087]  __pci_register_driver+0x61/0x70 [   65.923087]  amdgpu_init+0x7d/0xff0 [amdgpu] [   65.923087]  do_one_initcall+0x49/0x310 [   65.923087]  ? kmalloc_trace+0x136/0x360 [   65.923087]  do_init_module+0x6a/0x270 [   65.923087]  load_module+0x1fce/0x23a0 [   65.923087]  init_module_from_file+0x9c/0xe0 [   65.923087]  ? init_module_from_file+0x9c/0xe0 [   65.923087]  idempotent_init_module+0x179/0x230 [   65.923087]  __x64_sys_finit_module+0x5d/0xa0 [   65.923087]  do_syscall_64+0x76/0x120 [   65.923087]  entry_SYSCALL_64_after_hwframe+0x6e/0x76 [   65.923087] RIP: 0033:0x7f2d80f1e88d [   65.923087] Code: 5b 41 5c c3 66 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d 73 b5 0f 00 f7 d8 64 89 01 48 [   65.923087] RSP: 002b:00007ffc7bc1aa78 EFLAGS: 00000246 ORIG_RAX: 0000000000000139 [   65.923087] RAX: ffffffffffffffda RBX: 0000564c9c1db130 RCX: 00007f2d80f1e88d [   65.923087] RDX: 0000000000000000 RSI: 0000564c9c1e5480 RDI: 000000000000000f [   65.923087] RBP: 0000000000040000 R08: 0000000000000000 R09: 0000000000000002 [   65.923087] R10: 000000000000000f R11: 0000000000000246 R12: 0000564c9c1e5480 [   65.923087] R13: 0000564c9c1db260 R14: 0000000000000000 R15: 0000564c9c1e54b0 [   65.923087]  </TASK> [   65.923927] ---[ end trace ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56598?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high 7.8: CVE--2024--56598" src="https://img.shields.io/badge/CVE--2024--56598-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jfs: array-index-out-of-bounds fix in dtReadFirst  The value of stbl can be sometimes out of bounds due to a bad filesystem. Added a check with appopriate return of error code in that case.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56596?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high 7.8: CVE--2024--56596" src="https://img.shields.io/badge/CVE--2024--56596-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jfs: fix array-index-out-of-bounds in jfs_readdir  The stbl might contain some invalid values. Added a check to return error code in that case.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56595?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high 7.8: CVE--2024--56595" src="https://img.shields.io/badge/CVE--2024--56595-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jfs: add a check to prevent array-index-out-of-bounds in dbAdjTree  When the value of lp is 0 at the beginning of the for loop, it will become negative in the next assignment and we should bail out.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56551?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-141.151"><img alt="high 7.8: CVE--2024--56551" src="https://img.shields.io/badge/CVE--2024--56551-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-141.151</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-141.151</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdgpu: fix usage slab after free  [  +0.000021] BUG: KASAN: slab-use-after-free in drm_sched_entity_flush+0x6cb/0x7a0 [gpu_sched] [  +0.000027] Read of size 8 at addr ffff8881b8605f88 by task amd_pci_unplug/2147  [  +0.000023] CPU: 6 PID: 2147 Comm: amd_pci_unplug Not tainted 6.10.0+ #1 [  +0.000016] Hardware name: ASUS System Product Name/ROG STRIX B550-F GAMING (WI-FI), BIOS 1401 12/03/2020 [  +0.000016] Call Trace: [  +0.000008]  <TASK> [  +0.000009]  dump_stack_lvl+0x76/0xa0 [  +0.000017]  print_report+0xce/0x5f0 [  +0.000017]  ? drm_sched_entity_flush+0x6cb/0x7a0 [gpu_sched] [  +0.000019]  ? srso_return_thunk+0x5/0x5f [  +0.000015]  ? kasan_complete_mode_report_info+0x72/0x200 [  +0.000016]  ? drm_sched_entity_flush+0x6cb/0x7a0 [gpu_sched] [  +0.000019]  kasan_report+0xbe/0x110 [  +0.000015]  ? drm_sched_entity_flush+0x6cb/0x7a0 [gpu_sched] [  +0.000023]  __asan_report_load8_noabort+0x14/0x30 [  +0.000014]  drm_sched_entity_flush+0x6cb/0x7a0 [gpu_sched] [  +0.000020]  ? srso_return_thunk+0x5/0x5f [  +0.000013]  ? __kasan_check_write+0x14/0x30 [  +0.000016]  ? __pfx_drm_sched_entity_flush+0x10/0x10 [gpu_sched] [  +0.000020]  ? srso_return_thunk+0x5/0x5f [  +0.000013]  ? __kasan_check_write+0x14/0x30 [  +0.000013]  ? srso_return_thunk+0x5/0x5f [  +0.000013]  ? enable_work+0x124/0x220 [  +0.000015]  ? __pfx_enable_work+0x10/0x10 [  +0.000013]  ? srso_return_thunk+0x5/0x5f [  +0.000014]  ? free_large_kmalloc+0x85/0xf0 [  +0.000016]  drm_sched_entity_destroy+0x18/0x30 [gpu_sched] [  +0.000020]  amdgpu_vce_sw_fini+0x55/0x170 [amdgpu] [  +0.000735]  ? __kasan_check_read+0x11/0x20 [  +0.000016]  vce_v4_0_sw_fini+0x80/0x110 [amdgpu] [  +0.000726]  amdgpu_device_fini_sw+0x331/0xfc0 [amdgpu] [  +0.000679]  ? mutex_unlock+0x80/0xe0 [  +0.000017]  ? __pfx_amdgpu_device_fini_sw+0x10/0x10 [amdgpu] [  +0.000662]  ? srso_return_thunk+0x5/0x5f [  +0.000014]  ? __kasan_check_write+0x14/0x30 [  +0.000013]  ? srso_return_thunk+0x5/0x5f [  +0.000013]  ? mutex_unlock+0x80/0xe0 [  +0.000016]  amdgpu_driver_release_kms+0x16/0x80 [amdgpu] [  +0.000663]  drm_minor_release+0xc9/0x140 [drm] [  +0.000081]  drm_release+0x1fd/0x390 [drm] [  +0.000082]  __fput+0x36c/0xad0 [  +0.000018]  __fput_sync+0x3c/0x50 [  +0.000014]  __x64_sys_close+0x7d/0xe0 [  +0.000014]  x64_sys_call+0x1bc6/0x2680 [  +0.000014]  do_syscall_64+0x70/0x130 [  +0.000014]  ? srso_return_thunk+0x5/0x5f [  +0.000014]  ? irqentry_exit_to_user_mode+0x60/0x190 [  +0.000015]  ? srso_return_thunk+0x5/0x5f [  +0.000014]  ? irqentry_exit+0x43/0x50 [  +0.000012]  ? srso_return_thunk+0x5/0x5f [  +0.000013]  ? exc_page_fault+0x7c/0x110 [  +0.000015]  entry_SYSCALL_64_after_hwframe+0x76/0x7e [  +0.000014] RIP: 0033:0x7ffff7b14f67 [  +0.000013] Code: ff e8 0d 16 02 00 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 f3 0f 1e fa 64 8b 04 25 18 00 00 00 85 c0 75 10 b8 03 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 41 c3 48 83 ec 18 89 7c 24 0c e8 73 ba f7 ff [  +0.000026] RSP: 002b:00007fffffffe378 EFLAGS: 00000246 ORIG_RAX: 0000000000000003 [  +0.000019] RAX: ffffffffffffffda RBX: 0000000000000000 RCX: 00007ffff7b14f67 [  +0.000014] RDX: 0000000000000000 RSI: 00007ffff7f6f47a RDI: 0000000000000003 [  +0.000014] RBP: 00007fffffffe3a0 R08: 0000555555569890 R09: 0000000000000000 [  +0.000014] R10: 0000000000000000 R11: 0000000000000246 R12: 00007fffffffe5c8 [  +0.000013] R13: 00005555555552a9 R14: 0000555555557d48 R15: 00007ffff7ffd040 [  +0.000020]  </TASK>  [  +0.000016] Allocated by task 383 on cpu 7 at 26.880319s: [  +0.000014]  kasan_save_stack+0x28/0x60 [  +0.000008]  kasan_save_track+0x18/0x70 [  +0.000007]  kasan_save_alloc_info+0x38/0x60 [  +0.000007]  __kasan_kmalloc+0xc1/0xd0 [  +0.000007]  kmalloc_trace_noprof+0x180/0x380 [  +0.000007]  drm_sched_init+0x411/0xec0 [gpu_sched] [  +0.000012]  amdgpu_device_init+0x695f/0xa610 [amdgpu] [  +0.000658]  amdgpu_driver_load_kms+0x1a/0x120 [amdgpu] [  +0.000662]  amdgpu_pci_p ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53171?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high 7.8: CVE--2024--53171" src="https://img.shields.io/badge/CVE--2024--53171-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ubifs: authentication: Fix use-after-free in ubifs_tnc_end_commit  After an insertion in TNC, the tree might split and cause a node to change its `znode->parent`. A further deletion of other nodes in the tree (which also could free the nodes), the aforementioned node's `znode->cparent` could still point to a freed node. This `znode->cparent` may not be updated when getting nodes to commit in `ubifs_tnc_start_commit()`. This could then trigger a use-after-free when accessing the `znode->cparent` in `write_index()` in `ubifs_tnc_end_commit()`.  This can be triggered by running  rm -f /etc/test-file.bin dd if=/dev/urandom of=/etc/test-file.bin bs=1M count=60 conv=fsync  in a loop, and with `CONFIG_UBIFS_FS_AUTHENTICATION`. KASAN then reports:  BUG: KASAN: use-after-free in ubifs_tnc_end_commit+0xa5c/0x1950 Write of size 32 at addr ffffff800a3af86c by task ubifs_bgt0_20/153  Call trace: dump_backtrace+0x0/0x340 show_stack+0x18/0x24 dump_stack_lvl+0x9c/0xbc print_address_description.constprop.0+0x74/0x2b0 kasan_report+0x1d8/0x1f0 kasan_check_range+0xf8/0x1a0 memcpy+0x84/0xf4 ubifs_tnc_end_commit+0xa5c/0x1950 do_commit+0x4e0/0x1340 ubifs_bg_thread+0x234/0x2e0 kthread+0x36c/0x410 ret_from_fork+0x10/0x20  Allocated by task 401: kasan_save_stack+0x38/0x70 __kasan_kmalloc+0x8c/0xd0 __kmalloc+0x34c/0x5bc tnc_insert+0x140/0x16a4 ubifs_tnc_add+0x370/0x52c ubifs_jnl_write_data+0x5d8/0x870 do_writepage+0x36c/0x510 ubifs_writepage+0x190/0x4dc __writepage+0x58/0x154 write_cache_pages+0x394/0x830 do_writepages+0x1f0/0x5b0 filemap_fdatawrite_wbc+0x170/0x25c file_write_and_wait_range+0x140/0x190 ubifs_fsync+0xe8/0x290 vfs_fsync_range+0xc0/0x1e4 do_fsync+0x40/0x90 __arm64_sys_fsync+0x34/0x50 invoke_syscall.constprop.0+0xa8/0x260 do_el0_svc+0xc8/0x1f0 el0_svc+0x34/0x70 el0t_64_sync_handler+0x108/0x114 el0t_64_sync+0x1a4/0x1a8  Freed by task 403: kasan_save_stack+0x38/0x70 kasan_set_track+0x28/0x40 kasan_set_free_info+0x28/0x4c __kasan_slab_free+0xd4/0x13c kfree+0xc4/0x3a0 tnc_delete+0x3f4/0xe40 ubifs_tnc_remove_range+0x368/0x73c ubifs_tnc_remove_ino+0x29c/0x2e0 ubifs_jnl_delete_inode+0x150/0x260 ubifs_evict_inode+0x1d4/0x2e4 evict+0x1c8/0x450 iput+0x2a0/0x3c4 do_unlinkat+0x2cc/0x490 __arm64_sys_unlinkat+0x90/0x100 invoke_syscall.constprop.0+0xa8/0x260 do_el0_svc+0xc8/0x1f0 el0_svc+0x34/0x70 el0t_64_sync_handler+0x108/0x114 el0t_64_sync+0x1a4/0x1a8  The offending `memcpy()` in `ubifs_copy_hash()` has a use-after-free when a node becomes root in TNC but still has a `cparent` to an already freed node. More specifically, consider the following TNC:  zroot / / zp1 / / zn  Inserting a new node `zn_new` with a key smaller then `zn` will trigger a split in `tnc_insert()` if `zp1` is full:  zroot /   \ /     \ zp1     zp2 /         \ /           \ zn_new          zn  `zn->parent` has now been moved to `zp2`, *but* `zn->cparent` still points to `zp1`.  Now, consider a removal of all the nodes _except_ `zn`. Just when `tnc_delete()` is about to delete `zroot` and `zp2`:  zroot \ \ zp2 \ \ zn  `zroot` and `zp2` get freed and the tree collapses:  zn  `zn` now becomes the new `zroot`.  `get_znodes_to_commit()` will now only find `zn`, the new `zroot`, and `write_index()` will check its `znode->cparent` that wrongly points to the already freed `zp1`. `ubifs_copy_hash()` thus gets wrongly called with `znode->cparent->zbranch[znode->iip].hash` that triggers the use-after-free!  Fix this by explicitly setting `znode->cparent` to `NULL` in `get_znodes_to_commit()` for the root node. The search for the dirty nodes ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53168?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-141.151"><img alt="high 7.8: CVE--2024--53168" src="https://img.shields.io/badge/CVE--2024--53168-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-141.151</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-141.151</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sunrpc: fix one UAF issue caused by sunrpc kernel tcp socket  BUG: KASAN: slab-use-after-free in tcp_write_timer_handler+0x156/0x3e0 Read of size 1 at addr ffff888111f322cd by task swapper/0/0  CPU: 0 UID: 0 PID: 0 Comm: swapper/0 Not tainted 6.12.0-rc4-dirty #7 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 Call Trace: <IRQ> dump_stack_lvl+0x68/0xa0 print_address_description.constprop.0+0x2c/0x3d0 print_report+0xb4/0x270 kasan_report+0xbd/0xf0 tcp_write_timer_handler+0x156/0x3e0 tcp_write_timer+0x66/0x170 call_timer_fn+0xfb/0x1d0 __run_timers+0x3f8/0x480 run_timer_softirq+0x9b/0x100 handle_softirqs+0x153/0x390 __irq_exit_rcu+0x103/0x120 irq_exit_rcu+0xe/0x20 sysvec_apic_timer_interrupt+0x76/0x90 </IRQ> <TASK> asm_sysvec_apic_timer_interrupt+0x1a/0x20 RIP: 0010:default_idle+0xf/0x20 Code: 4c 01 c7 4c 29 c2 e9 72 ff ff ff 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa 66 90 0f 00 2d 33 f8 25 00 fb f4 <fa> c3 cc cc cc cc 66 66 2e 0f 1f 84 00 00 00 00 00 90 90 90 90 90 RSP: 0018:ffffffffa2007e28 EFLAGS: 00000242 RAX: 00000000000f3b31 RBX: 1ffffffff4400fc7 RCX: ffffffffa09c3196 RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff9f00590f RBP: 0000000000000000 R08: 0000000000000001 R09: ffffed102360835d R10: ffff88811b041aeb R11: 0000000000000001 R12: 0000000000000000 R13: ffffffffa202d7c0 R14: 0000000000000000 R15: 00000000000147d0 default_idle_call+0x6b/0xa0 cpuidle_idle_call+0x1af/0x1f0 do_idle+0xbc/0x130 cpu_startup_entry+0x33/0x40 rest_init+0x11f/0x210 start_kernel+0x39a/0x420 x86_64_start_reservations+0x18/0x30 x86_64_start_kernel+0x97/0xa0 common_startup_64+0x13e/0x141 </TASK>  Allocated by task 595: kasan_save_stack+0x24/0x50 kasan_save_track+0x14/0x30 __kasan_slab_alloc+0x87/0x90 kmem_cache_alloc_noprof+0x12b/0x3f0 copy_net_ns+0x94/0x380 create_new_namespaces+0x24c/0x500 unshare_nsproxy_namespaces+0x75/0xf0 ksys_unshare+0x24e/0x4f0 __x64_sys_unshare+0x1f/0x30 do_syscall_64+0x70/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Freed by task 100: kasan_save_stack+0x24/0x50 kasan_save_track+0x14/0x30 kasan_save_free_info+0x3b/0x60 __kasan_slab_free+0x54/0x70 kmem_cache_free+0x156/0x5d0 cleanup_net+0x5d3/0x670 process_one_work+0x776/0xa90 worker_thread+0x2e2/0x560 kthread+0x1a8/0x1f0 ret_from_fork+0x34/0x60 ret_from_fork_asm+0x1a/0x30  Reproduction script:  mkdir -p /mnt/nfsshare mkdir -p /mnt/nfs/netns_1 mkfs.ext4 /dev/sdb mount /dev/sdb /mnt/nfsshare systemctl restart nfs-server chmod 777 /mnt/nfsshare exportfs -i -o rw,no_root_squash *:/mnt/nfsshare  ip netns add netns_1 ip link add name veth_1_peer type veth peer veth_1 ifconfig veth_1_peer 11.11.0.254 up ip link set veth_1 netns netns_1 ip netns exec netns_1 ifconfig veth_1 11.11.0.1  ip netns exec netns_1 /root/iptables -A OUTPUT -d 11.11.0.254 -p tcp \ --tcp-flags FIN FIN  -j DROP  (note: In my environment, a DESTROY_CLIENTID operation is always sent immediately, breaking the nfs tcp connection.) ip netns exec netns_1 timeout -s 9 300 mount -t nfs -o proto=tcp,vers=4.1 \ 11.11.0.254:/mnt/nfsshare /mnt/nfs/netns_1  ip netns del netns_1  The reason here is that the tcp socket in netns_1 (nfs side) has been shutdown and closed (done in xs_destroy), but the FIN message (with ack) is discarded, and the nfsd side keeps sending retransmission messages. As a result, when the tcp sock in netns_1 processes the received message, it sends the message (FIN message) in the sending queue, and the tcp timer is re-established. When the network namespace is deleted, the net structure accessed by tcp's timer handler function causes problems.  To fix this problem, let's hold netns refcnt for the tcp kernel socket as done in other modules. This is an ugly hack which can easily be backported to earlier kernels. A proper fix which cleans up the interfaces will follow, but may not be so easy to backport.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53104?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-133.144"><img alt="high 7.8: CVE--2024--53104" src="https://img.shields.io/badge/CVE--2024--53104-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-133.144</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-133.144</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>1.671%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>81st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: uvcvideo: Skip parsing frames of type UVC_VS_UNDEFINED in uvc_parse_format  This can lead to out of bounds writes since frames of this type were not taken into account when calculating the size of the frames buffer in uvc_parse_streaming.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53103?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-131.141"><img alt="high 7.8: CVE--2024--53103" src="https://img.shields.io/badge/CVE--2024--53103-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-131.141</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-131.141</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  hv_sock: Initializing vsk->trans to NULL to prevent a dangling pointer  When hvs is released, there is a possibility that vsk->trans may not be initialized to NULL, which could lead to a dangling pointer. This issue is resolved by initializing vsk->trans to NULL.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50264?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-130.140"><img alt="high 7.8: CVE--2024--50264" src="https://img.shields.io/badge/CVE--2024--50264-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-130.140</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-130.140</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock/virtio: Initialization of the dangling pointer occurring in vsk->trans  During loopback communication, a dangling pointer can be created in vsk->trans, potentially leading to a Use-After-Free condition.  This issue is resolved by initializing vsk->trans to NULL.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50047?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="high 7.8: CVE--2024--50047" src="https://img.shields.io/badge/CVE--2024--50047-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix UAF in async decryption  Doing an async decryption (large read) crashes with a slab-use-after-free way down in the crypto API.  Reproducer: # mount.cifs -o ...,seal,esize=1 //srv/share /mnt # dd if=/mnt/largefile of=/dev/null ... [  194.196391] ================================================================== [  194.196844] BUG: KASAN: slab-use-after-free in gf128mul_4k_lle+0xc1/0x110 [  194.197269] Read of size 8 at addr ffff888112bd0448 by task kworker/u77:2/899 [  194.197707] [  194.197818] CPU: 12 UID: 0 PID: 899 Comm: kworker/u77:2 Not tainted 6.11.0-lku-00028-gfca3ca14a17a-dirty #43 [  194.198400] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.16.2-3-gd478f380-prebuilt.qemu.org 04/01/2014 [  194.199046] Workqueue: smb3decryptd smb2_decrypt_offload [cifs] [  194.200032] Call Trace: [  194.200191]  <TASK> [  194.200327]  dump_stack_lvl+0x4e/0x70 [  194.200558]  ? gf128mul_4k_lle+0xc1/0x110 [  194.200809]  print_report+0x174/0x505 [  194.201040]  ? __pfx__raw_spin_lock_irqsave+0x10/0x10 [  194.201352]  ? srso_return_thunk+0x5/0x5f [  194.201604]  ? __virt_addr_valid+0xdf/0x1c0 [  194.201868]  ? gf128mul_4k_lle+0xc1/0x110 [  194.202128]  kasan_report+0xc8/0x150 [  194.202361]  ? gf128mul_4k_lle+0xc1/0x110 [  194.202616]  gf128mul_4k_lle+0xc1/0x110 [  194.202863]  ghash_update+0x184/0x210 [  194.203103]  shash_ahash_update+0x184/0x2a0 [  194.203377]  ? __pfx_shash_ahash_update+0x10/0x10 [  194.203651]  ? srso_return_thunk+0x5/0x5f [  194.203877]  ? crypto_gcm_init_common+0x1ba/0x340 [  194.204142]  gcm_hash_assoc_remain_continue+0x10a/0x140 [  194.204434]  crypt_message+0xec1/0x10a0 [cifs] [  194.206489]  ? __pfx_crypt_message+0x10/0x10 [cifs] [  194.208507]  ? srso_return_thunk+0x5/0x5f [  194.209205]  ? srso_return_thunk+0x5/0x5f [  194.209925]  ? srso_return_thunk+0x5/0x5f [  194.210443]  ? srso_return_thunk+0x5/0x5f [  194.211037]  decrypt_raw_data+0x15f/0x250 [cifs] [  194.212906]  ? __pfx_decrypt_raw_data+0x10/0x10 [cifs] [  194.214670]  ? srso_return_thunk+0x5/0x5f [  194.215193]  smb2_decrypt_offload+0x12a/0x6c0 [cifs]  This is because TFM is being used in parallel.  Fix this by allocating a new AEAD TFM for async decryption, but keep the existing one for synchronous READ cases (similar to what is done in smb3_calc_signature()).  Also remove the calls to aead_request_set_callback() and crypto_wait_req() since it's always going to be a synchronous operation.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49883?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-127.137"><img alt="high 7.8: CVE--2024--49883" src="https://img.shields.io/badge/CVE--2024--49883-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-127.137</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-127.137</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ext4: aovid use-after-free in ext4_ext_insert_extent()  As Ojaswin mentioned in Link, in ext4_ext_insert_extent(), if the path is reallocated in ext4_ext_create_new_leaf(), we'll use the stale path and cause UAF. Below is a sample trace with dummy values:  ext4_ext_insert_extent path = *ppath = 2000 ext4_ext_create_new_leaf(ppath) ext4_find_extent(ppath) path = *ppath = 2000 if (depth > path[0].p_maxdepth) kfree(path = 2000); *ppath = path = NULL; path = kcalloc() = 3000 *ppath = 3000; return path; /* here path is still 2000, UAF! */ eh = path[depth].p_hdr  ================================================================== BUG: KASAN: slab-use-after-free in ext4_ext_insert_extent+0x26d4/0x3330 Read of size 8 at addr ffff8881027bf7d0 by task kworker/u36:1/179 CPU: 3 UID: 0 PID: 179 Comm: kworker/u6:1 Not tainted 6.11.0-rc2-dirty #866 Call Trace: <TASK> ext4_ext_insert_extent+0x26d4/0x3330 ext4_ext_map_blocks+0xe22/0x2d40 ext4_map_blocks+0x71e/0x1700 ext4_do_writepages+0x1290/0x2800 [...]  Allocated by task 179: ext4_find_extent+0x81c/0x1f70 ext4_ext_map_blocks+0x146/0x2d40 ext4_map_blocks+0x71e/0x1700 ext4_do_writepages+0x1290/0x2800 ext4_writepages+0x26d/0x4e0 do_writepages+0x175/0x700 [...]  Freed by task 179: kfree+0xcb/0x240 ext4_find_extent+0x7c0/0x1f70 ext4_ext_insert_extent+0xa26/0x3330 ext4_ext_map_blocks+0xe22/0x2d40 ext4_map_blocks+0x71e/0x1700 ext4_do_writepages+0x1290/0x2800 ext4_writepages+0x26d/0x4e0 do_writepages+0x175/0x700 [...] ==================================================================  So use *ppath to update the path to avoid the above problem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38630?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-124.134"><img alt="high 7.8: CVE--2024--38630" src="https://img.shields.io/badge/CVE--2024--38630-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-124.134</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-124.134</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  watchdog: cpu5wdt.c: Fix use-after-free bug caused by cpu5wdt_trigger  When the cpu5wdt module is removing, the origin code uses del_timer() to de-activate the timer. If the timer handler is running, del_timer() could not stop it and will return directly. If the port region is released by release_region() and then the timer handler cpu5wdt_trigger() calls outb() to write into the region that is released, the use-after-free bug will happen.  Change del_timer() to timer_shutdown_sync() in order that the timer handler could be finished before the port region is released.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36971?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-121.131"><img alt="high 7.8: CVE--2024--36971" src="https://img.shields.io/badge/CVE--2024--36971-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-121.131</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-121.131</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fix __dst_negative_advice() race  __dst_negative_advice() does not enforce proper RCU rules when sk->dst_cache must be cleared, leading to possible UAF.  RCU rules are that we must first clear sk->sk_dst_cache, then call dst_release(old_dst).  Note that sk_dst_reset(sk) is implementing this protocol correctly, while __dst_negative_advice() uses the wrong order.  Given that ip6_negative_advice() has special logic against RTF_CACHE, this means each of the three ->negative_advice() existing methods must perform the sk_dst_reset() themselves.  Note the check against NULL dst is centralized in __dst_negative_advice(), there is no need to duplicate it in various callbacks.  Many thanks to Clement Lecigne for tracking this issue.  This old bug became visible after the blamed commit, using UDP sockets.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35864?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-136.147"><img alt="high 7.8: CVE--2024--35864" src="https://img.shields.io/badge/CVE--2024--35864-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-136.147</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-136.147</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix potential UAF in smb2_is_valid_lease_break()  Skip sessions that are being teared down (status == SES_EXITING) to avoid UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26928?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-136.147"><img alt="high 7.8: CVE--2024--26928" src="https://img.shields.io/badge/CVE--2024--26928-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-136.147</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-136.147</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix potential UAF in cifs_debug_files_proc_show()  Skip sessions that are being teared down (status == SES_EXITING) to avoid UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26800?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-125.135"><img alt="high 7.8: CVE--2024--26800" src="https://img.shields.io/badge/CVE--2024--26800-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-125.135</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-125.135</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tls: fix use-after-free on failed backlog decryption  When the decrypt request goes to the backlog and crypto_aead_decrypt returns -EBUSY, tls_do_decryption will wait until all async decryptions have completed. If one of them fails, tls_do_decryption will return -EBADMSG and tls_decrypt_sg jumps to the error path, releasing all the pages. But the pages have been passed to the async callback, and have already been released by tls_decrypt_done.  The only true async case is when crypto_aead_decrypt returns -EINPROGRESS. With -EBUSY, we already waited so we can tell tls_sw_recvmsg that the data is available for immediate copy, but we need to notify tls_decrypt_sg (via the new ->async_done flag) that the memory has already been released.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26689?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-106.116"><img alt="high 7.8: CVE--2024--26689" src="https://img.shields.io/badge/CVE--2024--26689-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-106.116</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-106.116</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ceph: prevent use-after-free in encode_cap_msg()  In fs/ceph/caps.c, in encode_cap_msg(), "use after free" error was caught by KASAN at this line - 'ceph_buffer_get(arg->xattr_buf);'. This implies before the refcount could be increment here, it was freed.  In same file, in "handle_cap_grant()" refcount is decremented by this line - 'ceph_buffer_put(ci->i_xattrs.blob);'. It appears that a race occurred and resource was freed by the latter line before the former line could increment it.  encode_cap_msg() is called by __send_cap() and __send_cap() is called by ceph_check_caps() after calling __prep_cap(). __prep_cap() is where arg->xattr_buf is assigned to ci->i_xattrs.blob. This is the spot where the refcount must be increased to prevent "use after free" error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26581?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-105.115"><img alt="high 7.8: CVE--2024--26581" src="https://img.shields.io/badge/CVE--2024--26581-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-105.115</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-105.115</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.182%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>40th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nft_set_rbtree: skip end interval element from gc  rbtree lazy gc on insert might collect an end interval element that has been just added in this transactions, skip end interval elements that are not yet active.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-1086?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-101.111"><img alt="high 7.8: CVE--2024--1086" src="https://img.shields.io/badge/CVE--2024--1086-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-101.111</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-101.111</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>84.406%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>99th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.  The nft_verdict_init() function allows positive values as drop error within the hook verdict, and hence the nf_hook_slow() function can cause a double free vulnerability when NF_DROP is issued with a drop error which resembles NF_ACCEPT.  We recommend upgrading past commit f342de4e2f33e0e39165d8639387aa6c19dff660.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-1085?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-101.111"><img alt="high 7.8: CVE--2024--1085" src="https://img.shields.io/badge/CVE--2024--1085-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-101.111</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-101.111</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.  The nft_setelem_catchall_deactivate() function checks whether the catch-all set element is active in the current generation instead of the next generation before freeing it, but only flags it inactive in the next generation, making it possible to free the element multiple times, leading to a double free vulnerability.  We recommend upgrading past commit b1db244ffd041a49ecc9618e8feb6b5c1afcdaa7.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-0646?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-97.107"><img alt="high 7.8: CVE--2024--0646" src="https://img.shields.io/badge/CVE--2024--0646-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-97.107</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-97.107</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds memory write flaw was found in the Linux kernel’s Transport Layer Security functionality in how a user calls a function splice with a ktls socket as the destination. This flaw allows a local user to crash or potentially escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6817?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="high 7.8: CVE--2023--6817" src="https://img.shields.io/badge/CVE--2023--6817-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to achieve local privilege escalation.  The function nft_pipapo_walk did not skip inactive elements during set walk which could lead double deactivations of PIPAPO (Pile Packet Policies) elements, leading to use-after-free.  We recommend upgrading past commit 317eb9685095678f2c9f5a8189de698c5354316a.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52664?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-139.149"><img alt="high 7.8: CVE--2023--52664" src="https://img.shields.io/badge/CVE--2023--52664-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-139.149</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-139.149</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: atlantic: eliminate double free in error handling logic  Driver has a logic leak in ring data allocation/free, where aq_ring_free could be called multiple times on same ring, if system is under stress and got memory allocation error.  Ring pointer was used as an indicator of failure, but this is not correct since only ring data is allocated/deallocated. Ring itself is an array member.  Changing ring allocation functions to return error code directly. This simplifies error handling and eliminates aq_ring_free on higher layer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-0995?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-138.148"><img alt="high 7.8: CVE--2022--0995" src="https://img.shields.io/badge/CVE--2022--0995-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-138.148</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-138.148</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>28.801%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>96th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An out-of-bounds (OOB) memory write flaw was found in the Linux kernel’s watch_queue event notification subsystem. This flaw can overwrite parts of the kernel state, potentially allowing a local user to gain privileged access or cause a denial of service on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53150?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high 7.1: CVE--2024--53150" src="https://img.shields.io/badge/CVE--2024--53150-lightgrey?label=high%207.1&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.143%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ALSA: usb-audio: Fix out of bounds reads when finding clock sources  The current USB-audio driver code doesn't check bLength of each descriptor at traversing for clock descriptors.  That is, when a device provides a bogus descriptor with a shorter bLength, the driver might hit out-of-bounds reads.  For addressing it, this patch adds sanity checks to the validator functions for the clock descriptor traversal.  When the descriptor length is shorter than expected, it's skipped in the loop.  For the clock source and clock multiplier descriptors, we can just check bLength against the sizeof() of each descriptor type. OTOH, the clock selector descriptor of UAC2 and UAC3 has an array of bNrInPins elements and two more fields at its tail, hence those have to be checked in addition to the sizeof() check.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26597?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-102.112"><img alt="high 7.1: CVE--2024--26597" src="https://img.shields.io/badge/CVE--2024--26597-lightgrey?label=high%207.1&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-102.112</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-102.112</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: qualcomm: rmnet: fix global oob in rmnet_policy  The variable rmnet_link_ops assign a *bigger* maxtype which leads to a global out-of-bounds read when parsing the netlink attributes. See bug trace below:  ================================================================== BUG: KASAN: global-out-of-bounds in validate_nla lib/nlattr.c:386 [inline] BUG: KASAN: global-out-of-bounds in __nla_validate_parse+0x24af/0x2750 lib/nlattr.c:600 Read of size 1 at addr ffffffff92c438d0 by task syz-executor.6/84207  CPU: 0 PID: 84207 Comm: syz-executor.6 Tainted: G                 N 6.1.0 #3 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.13.0-1ubuntu1.1 04/01/2014 Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x8b/0xb3 lib/dump_stack.c:106 print_address_description mm/kasan/report.c:284 [inline] print_report+0x172/0x475 mm/kasan/report.c:395 kasan_report+0xbb/0x1c0 mm/kasan/report.c:495 validate_nla lib/nlattr.c:386 [inline] __nla_validate_parse+0x24af/0x2750 lib/nlattr.c:600 __nla_parse+0x3e/0x50 lib/nlattr.c:697 nla_parse_nested_deprecated include/net/netlink.h:1248 [inline] __rtnl_newlink+0x50a/0x1880 net/core/rtnetlink.c:3485 rtnl_newlink+0x64/0xa0 net/core/rtnetlink.c:3594 rtnetlink_rcv_msg+0x43c/0xd70 net/core/rtnetlink.c:6091 netlink_rcv_skb+0x14f/0x410 net/netlink/af_netlink.c:2540 netlink_unicast_kernel net/netlink/af_netlink.c:1319 [inline] netlink_unicast+0x54e/0x800 net/netlink/af_netlink.c:1345 netlink_sendmsg+0x930/0xe50 net/netlink/af_netlink.c:1921 sock_sendmsg_nosec net/socket.c:714 [inline] sock_sendmsg+0x154/0x190 net/socket.c:734 ____sys_sendmsg+0x6df/0x840 net/socket.c:2482 ___sys_sendmsg+0x110/0x1b0 net/socket.c:2536 __sys_sendmsg+0xf3/0x1c0 net/socket.c:2565 do_syscall_x64 arch/x86/entry/common.c:50 [inline] do_syscall_64+0x3b/0x90 arch/x86/entry/common.c:80 entry_SYSCALL_64_after_hwframe+0x63/0xcd RIP: 0033:0x7fdcf2072359 Code: 28 00 00 00 75 05 48 83 c4 28 c3 e8 f1 19 00 00 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 b8 ff ff ff f7 d8 64 89 01 48 RSP: 002b:00007fdcf13e3168 EFLAGS: 00000246 ORIG_RAX: 000000000000002e RAX: ffffffffffffffda RBX: 00007fdcf219ff80 RCX: 00007fdcf2072359 RDX: 0000000000000000 RSI: 0000000020000200 RDI: 0000000000000003 RBP: 00007fdcf20bd493 R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000000 R13: 00007fffbb8d7bdf R14: 00007fdcf13e3300 R15: 0000000000022000 </TASK>  The buggy address belongs to the variable: rmnet_policy+0x30/0xe0  The buggy address belongs to the physical page: page:0000000065bdeb3c refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x155243 flags: 0x200000000001000(reserved|node=0|zone=2) raw: 0200000000001000 ffffea00055490c8 ffffea00055490c8 0000000000000000 raw: 0000000000000000 0000000000000000 00000001ffffffff 0000000000000000 page dumped because: kasan: bad access detected  Memory state around the buggy address: ffffffff92c43780: f9 f9 f9 f9 00 00 00 02 f9 f9 f9 f9 00 00 00 07 ffffffff92c43800: f9 f9 f9 f9 00 00 00 05 f9 f9 f9 f9 06 f9 f9 f9 >ffffffff92c43880: f9 f9 f9 f9 00 00 00 00 00 00 f9 f9 f9 f9 f9 f9 ^ ffffffff92c43900: 00 00 00 00 00 00 00 00 07 f9 f9 f9 f9 f9 f9 f9 ffffffff92c43980: 00 00 00 07 f9 f9 f9 f9 00 00 00 05 f9 f9 f9 f9  According to the comment of `nla_parse_nested_deprecated`, the maxtype should be len(destination array) - 1. Hence use `IFLA_RMNET_MAX` here.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56672?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-134.145"><img alt="high 7.0: CVE--2024--56672" src="https://img.shields.io/badge/CVE--2024--56672-lightgrey?label=high%207.0&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-134.145</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-134.145</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  blk-cgroup: Fix UAF in blkcg_unpin_online()  blkcg_unpin_online() walks up the blkcg hierarchy putting the online pin. To walk up, it uses blkcg_parent(blkcg) but it was calling that after blkcg_destroy_blkgs(blkcg) which could free the blkcg, leading to the following UAF:  ================================================================== BUG: KASAN: slab-use-after-free in blkcg_unpin_online+0x15a/0x270 Read of size 8 at addr ffff8881057678c0 by task kworker/9:1/117  CPU: 9 UID: 0 PID: 117 Comm: kworker/9:1 Not tainted 6.13.0-rc1-work-00182-gb8f52214c61a-dirty #48 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS unknown 02/02/2022 Workqueue: cgwb_release cgwb_release_workfn Call Trace: <TASK> dump_stack_lvl+0x27/0x80 print_report+0x151/0x710 kasan_report+0xc0/0x100 blkcg_unpin_online+0x15a/0x270 cgwb_release_workfn+0x194/0x480 process_scheduled_works+0x71b/0xe20 worker_thread+0x82a/0xbd0 kthread+0x242/0x2c0 ret_from_fork+0x33/0x70 ret_from_fork_asm+0x1a/0x30 </TASK> ... Freed by task 1944: kasan_save_track+0x2b/0x70 kasan_save_free_info+0x3c/0x50 __kasan_slab_free+0x33/0x50 kfree+0x10c/0x330 css_free_rwork_fn+0xe6/0xb30 process_scheduled_works+0x71b/0xe20 worker_thread+0x82a/0xbd0 kthread+0x242/0x2c0 ret_from_fork+0x33/0x70 ret_from_fork_asm+0x1a/0x30  Note that the UAF is not easy to trigger as the free path is indirected behind a couple RCU grace periods and a work item execution. I could only trigger it with artifical msleep() injected in blkcg_unpin_online().  Fix it by reading the parent pointer before destroying the blkcg's blkg's.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-43882?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-125.135"><img alt="high 7.0: CVE--2024--43882" src="https://img.shields.io/badge/CVE--2024--43882-lightgrey?label=high%207.0&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-125.135</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-125.135</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.064%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  exec: Fix ToCToU between perm check and set-uid/gid usage  When opening a file for exec via do_filp_open(), permission checking is done against the file's metadata at that moment, and on success, a file pointer is passed back. Much later in the execve() code path, the file metadata (specifically mode, uid, and gid) is used to determine if/how to set the uid and gid. However, those values may have changed since the permissions check, meaning the execution may gain unintended privileges.  For example, if a file could change permissions from executable and not set-id:  ---------x 1 root root 16048 Aug  7 13:16 target  to set-id and non-executable:  ---S------ 1 root root 16048 Aug  7 13:16 target  it is possible to gain root privileges when execution should have been disallowed.  While this race condition is rare in real-world scenarios, it has been observed (and proven exploitable) when package managers are updating the setuid bits of installed programs. Such files start with being world-executable but then are adjusted to be group-exec with a set-uid bit. For example, "chmod o-x,u+s target" makes "target" executable only by uid "root" and gid "cdrom", while also becoming setuid-root:  -rwxr-xr-x 1 root cdrom 16048 Aug  7 13:16 target  becomes:  -rwsr-xr-- 1 root cdrom 16048 Aug  7 13:16 target  But racing the chmod means users without group "cdrom" membership can get the permission to execute "target" just before the chmod, and when the chmod finishes, the exec reaches brpm_fill_uid(), and performs the setuid to root, violating the expressed authorization of "only cdrom group members can setuid to root".  Re-check that we still have execute permissions in case the metadata has changed. It would be better to keep a copy from the perm-check time, but until we can do that refactoring, the least-bad option is to do a full inode_permission() call (under inode lock). It is understood that this is safe against dead-locks, but hardly optimal.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6932?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="high 7.0: CVE--2023--6932" src="https://img.shields.io/badge/CVE--2023--6932-lightgrey?label=high%207.0&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free vulnerability in the Linux kernel's ipv4: igmp component can be exploited to achieve local privilege escalation.  A race condition can be exploited to cause a timer be mistakenly registered on a RCU read locked object which is freed by another thread.  We recommend upgrading past commit e2b706c691905fe78468c361aaabc719d0a496f1.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6931?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="high 7.0: CVE--2023--6931" src="https://img.shields.io/badge/CVE--2023--6931-lightgrey?label=high%207.0&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.179%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>40th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component can be exploited to achieve local privilege escalation.  A perf_event's read_size can overflow, leading to an heap out-of-bounds increment or write in perf_read_group().  We recommend upgrading past commit 382c27f4ed28f803b1f1473ac2d8db0afc795a1b.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6270?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-112.122"><img alt="high 7.0: CVE--2023--6270" src="https://img.shields.io/badge/CVE--2023--6270-lightgrey?label=high%207.0&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-112.122</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-112.122</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the ATA over Ethernet (AoE) driver in the Linux kernel. The aoecmd_cfg_pkts() function improperly updates the refcnt on `struct net_device`, and a use-after-free can be triggered by racing between the free on the struct and the access through the `skbtxq` global queue. This could lead to a denial of service condition or potential code execution.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-51781?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-97.107"><img alt="high 7.0: CVE--2023--51781" src="https://img.shields.io/badge/CVE--2023--51781-lightgrey?label=high%207.0&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-97.107</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-97.107</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An issue was discovered in the Linux kernel before 6.6.8. atalk_ioctl in net/appletalk/ddp.c has a use-after-free because of an atalk_recvmsg race condition.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-0193?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-92.102"><img alt="high 6.7: CVE--2024--0193" src="https://img.shields.io/badge/CVE--2024--0193-lightgrey?label=high%206.7&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-92.102</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-92.102</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A use-after-free flaw was found in the netfilter subsystem of the Linux kernel. If the catchall element is garbage-collected when the pipapo set is removed, the element can be deactivated twice. This can cause a use-after-free issue on an NFT_CHAIN object or NFT_OBJECT object, allowing a local unprivileged user with CAP_NET_ADMIN capability to escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52447?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-112.122"><img alt="high 6.7: CVE--2023--52447" src="https://img.shields.io/badge/CVE--2023--52447-lightgrey?label=high%206.7&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-112.122</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-112.122</code></td></tr>
<tr><td>CVSS Score</td><td><code>6.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Defer the free of inner map when necessary  When updating or deleting an inner map in map array or map htab, the map may still be accessed by non-sleepable program or sleepable program. However bpf_map_fd_put_ptr() decreases the ref-counter of the inner map directly through bpf_map_put(), if the ref-counter is the last one (which is true for most cases), the inner map will be freed by ops->map_free() in a kworker. But for now, most .map_free() callbacks don't use synchronize_rcu() or its variants to wait for the elapse of a RCU grace period, so after the invocation of ops->map_free completes, the bpf program which is accessing the inner map may incur use-after-free problem.  Fix the free of inner map by invoking bpf_map_free_deferred() after both one RCU grace period and one tasks trace RCU grace period if the inner map has been removed from the outer map before. The deferment is accomplished by using call_rcu() or call_rcu_tasks_trace() when releasing the last ref-counter of bpf map. The newly-added rcu_head field in bpf_map shares the same storage space with work field to reduce the size of bpf_map.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56593?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high 5.5: CVE--2024--56593" src="https://img.shields.io/badge/CVE--2024--56593-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.038%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: brcmfmac: Fix oops due to NULL pointer dereference in brcmf_sdiod_sglist_rw()  This patch fixes a NULL pointer dereference bug in brcmfmac that occurs when a high 'sd_sgentry_align' value applies (e.g. 512) and a lot of queued SKBs are sent from the pkt queue.  The problem is the number of entries in the pre-allocated sgtable, it is nents = max(rxglom_size, txglom_size) + max(rxglom_size, txglom_size) >> 4 + 1. Given the default [rt]xglom_size=32 it's actually 35 which is too small. Worst case, the pkt queue can end up with 64 SKBs. This occurs when a new SKB is added for each original SKB if tailroom isn't enough to hold tail_pad. At least one sg entry is needed for each SKB. So, eventually the "skb_queue_walk loop" in brcmf_sdiod_sglist_rw may run out of sg entries. This makes sg_next return NULL and this causes the oops.  The patch sets nents to max(rxglom_size, txglom_size) * 2 to be able handle the worst-case. Btw. this requires only 64-35=29 * 16 (or 20 if CONFIG_NEED_SG_DMA_LENGTH) = 464 additional bytes of memory.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53140?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high 5.5: CVE--2024--53140" src="https://img.shields.io/badge/CVE--2024--53140-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netlink: terminate outstanding dump on socket close  Netlink supports iterative dumping of data. It provides the families the following ops: - start - (optional) kicks off the dumping process - dump  - actual dump helper, keeps getting called until it returns 0 - done  - (optional) pairs with .start, can be used for cleanup The whole process is asynchronous and the repeated calls to .dump don't actually happen in a tight loop, but rather are triggered in response to recvmsg() on the socket.  This gives the user full control over the dump, but also means that the user can close the socket without getting to the end of the dump. To make sure .start is always paired with .done we check if there is an ongoing dump before freeing the socket, and if so call .done.  The complication is that sockets can get freed from BH and .done is allowed to sleep. So we use a workqueue to defer the call, when needed.  Unfortunately this does not work correctly. What we defer is not the cleanup but rather releasing a reference on the socket. We have no guarantee that we own the last reference, if someone else holds the socket they may release it in BH and we're back to square one.  The whole dance, however, appears to be unnecessary. Only the user can interact with dumps, so we can clean up when socket is closed. And close always happens in process context. Some async code may still access the socket after close, queue notification skbs to it etc. but no dumps can start, end or otherwise make progress.  Delete the workqueue and flush the dump state directly from the release handler. Note that further cleanup is possible in -next, for instance we now always call .done before releasing the main module reference, so dump doesn't have to take a reference of its own.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53063?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-133.144"><img alt="high 5.5: CVE--2024--53063" src="https://img.shields.io/badge/CVE--2024--53063-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-133.144</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-133.144</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.111%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>30th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: dvbdev: prevent the risk of out of memory access  The dvbdev contains a static variable used to store dvb minors.  The behavior of it depends if CONFIG_DVB_DYNAMIC_MINORS is set or not. When not set, dvb_register_device() won't check for boundaries, as it will rely that a previous call to dvb_register_adapter() would already be enforcing it.  On a similar way, dvb_device_open() uses the assumption that the register functions already did the needed checks.  This can be fragile if some device ends using different calls. This also generate warnings on static check analysers like Coverity.  So, add explicit guards to prevent potential risk of OOM issues.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50302?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-133.144"><img alt="high 5.5: CVE--2024--50302" src="https://img.shields.io/badge/CVE--2024--50302-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-133.144</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-133.144</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.298%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>53rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  HID: core: zero-initialize the report buffer  Since the report buffer is used by all kinds of drivers in various ways, let's zero-initialize it during allocation to make sure that it can't be ever used to leak kernel memory via specially-crafted report.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49958?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-127.137"><img alt="high 5.5: CVE--2024--49958" src="https://img.shields.io/badge/CVE--2024--49958-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-127.137</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-127.137</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ocfs2: reserve space for inline xattr before attaching reflink tree  One of our customers reported a crash and a corrupted ocfs2 filesystem. The crash was due to the detection of corruption.  Upon troubleshooting, the fsck -fn output showed the below corruption  [EXTENT_LIST_FREE] Extent list in owner 33080590 claims 230 as the next free chain record, but fsck believes the largest valid value is 227.  Clamp the next record value? n  The stat output from the debugfs.ocfs2 showed the following corruption where the "Next Free Rec:" had overshot the "Count:" in the root metadata block.  Inode: 33080590   Mode: 0640   Generation: 2619713622 (0x9c25a856) FS Generation: 904309833 (0x35e6ac49) CRC32: 00000000   ECC: 0000 Type: Regular   Attr: 0x0   Flags: Valid Dynamic Features: (0x16) HasXattr InlineXattr Refcounted Extended Attributes Block: 0  Extended Attributes Inline Size: 256 User: 0 (root)   Group: 0 (root)   Size: 281320357888 Links: 1   Clusters: 141738 ctime: 0x66911b56 0x316edcb8 -- Fri Jul 12 06:02:30.829349048 2024 atime: 0x66911d6b 0x7f7a28d -- Fri Jul 12 06:11:23.133669517 2024 mtime: 0x66911b56 0x12ed75d7 -- Fri Jul 12 06:02:30.317552087 2024 dtime: 0x0 -- Wed Dec 31 17:00:00 1969 Refcount Block: 2777346 Last Extblk: 2886943   Orphan Slot: 0 Sub Alloc Slot: 0   Sub Alloc Bit: 14 Tree Depth: 1   Count: 227   Next Free Rec: 230 ## Offset        Clusters       Block# 0  0             2310           2776351 1  2310          2139           2777375 2  4449          1221           2778399 3  5670          731            2779423 4  6401          566            2780447 .......          ....           ....... .......          ....           .......  The issue was in the reflink workfow while reserving space for inline xattr.  The problematic function is ocfs2_reflink_xattr_inline().  By the time this function is called the reflink tree is already recreated at the destination inode from the source inode.  At this point, this function reserves space for inline xattrs at the destination inode without even checking if there is space at the root metadata block.  It simply reduces the l_count from 243 to 227 thereby making space of 256 bytes for inline xattr whereas the inode already has extents beyond this index (in this case up to 230), thereby causing corruption.  The fix for this is to reserve space for inline metadata at the destination inode before the reflink tree gets recreated. The customer has verified the fix.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26809?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-112.122"><img alt="high 5.5: CVE--2024--26809" src="https://img.shields.io/badge/CVE--2024--26809-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-112.122</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-112.122</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nft_set_pipapo: release elements in clone only from destroy path  Clone already always provides a current view of the lookup table, use it to destroy the set, otherwise it is possible to destroy elements twice.  This fix requires:  212ed75dc5fb ("netfilter: nf_tables: integrate pipapo into commit protocol")  which came after:  9827a0e6e23b ("netfilter: nft_set_pipapo: release elements in clone from abort path").

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26643?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-113.123"><img alt="high 5.5: CVE--2024--26643" src="https://img.shields.io/badge/CVE--2024--26643-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-113.123</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-113.123</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.010%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_tables: mark set as dead when unbinding anonymous set with timeout  While the rhashtable set gc runs asynchronously, a race allows it to collect elements from anonymous sets with timeouts while it is being released from the commit path.  Mingi Cho originally reported this issue in a different path in 6.1.x with a pipapo set with low timeouts which is not possible upstream since 7395dfacfff6 ("netfilter: nf_tables: use timestamp to check for set element timeout").  Fix this by setting on the dead flag for anonymous sets to skip async gc in this case.  According to 08e4c8c5919f ("netfilter: nf_tables: mark newset as dead on transaction abort"), Florian plans to accelerate abort path by releasing objects via workqueue, therefore, this sets on the dead flag for abort path too.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26642?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-116.126"><img alt="high 5.5: CVE--2024--26642" src="https://img.shields.io/badge/CVE--2024--26642-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-116.126</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-116.126</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.010%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_tables: disallow anonymous set with timeout flag  Anonymous sets are never used with timeout from userspace, reject this. Exception to this rule is NFT_SET_EVAL to ensure legacy meters still work.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26584?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-112.122"><img alt="high 5.5: CVE--2024--26584" src="https://img.shields.io/badge/CVE--2024--26584-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-112.122</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-112.122</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: tls: handle backlogging of crypto requests  Since we're setting the CRYPTO_TFM_REQ_MAY_BACKLOG flag on our requests to the crypto API, crypto_aead_{encrypt,decrypt} can return -EBUSY instead of -EINPROGRESS in valid situations. For example, when the cryptd queue for AESNI is full (easy to trigger with an artificially low cryptd.cryptd_max_cpu_qlen), requests will be enqueued to the backlog but still processed. In that case, the async callback will also be called twice: first with err == -EINPROGRESS, which it seems we can just ignore, then with err == 0.  Compared to Sabrina's original patch this version uses the new tls_*crypt_async_wait() helpers and converts the EBUSY to EINPROGRESS to avoid having to modify all the error handling paths. The handling is identical.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52927?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-139.149"><img alt="high 5.5: CVE--2023--52927" src="https://img.shields.io/badge/CVE--2023--52927-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-139.149</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-139.149</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: allow exp not to be removed in nf_ct_find_expectation  Currently nf_conntrack_in() calling nf_ct_find_expectation() will remove the exp from the hash table. However, in some scenario, we expect the exp not to be removed when the created ct will not be confirmed, like in OVS and TC conntrack in the following patches.  This patch allows exp not to be removed by setting IPS_CONFIRMED in the status of the tmpl.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-36402?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-91.101"><img alt="high 5.5: CVE--2022--36402" src="https://img.shields.io/badge/CVE--2022--36402-lightgrey?label=high%205.5&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-91.101</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-91.101</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

An integer overflow vulnerability was found in vmwgfx driver in drivers/gpu/vmxgfx/vmxgfx_execbuf.c in GPU component of Linux kernel with device file '/dev/dri/renderD128 (or Dxxx)'. This flaw allows a local attacker with a user account on the system to gain privilege, causing a denial of service(DoS).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26585?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-112.122"><img alt="high 4.7: CVE--2024--26585" src="https://img.shields.io/badge/CVE--2024--26585-lightgrey?label=high%204.7&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-112.122</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-112.122</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tls: fix race between tx work scheduling and socket close  Similarly to previous commit, the submitting thread (recvmsg/sendmsg) may exit as soon as the async crypto handler calls complete(). Reorder scheduling the work before calling complete(). This seems more logical in the first place, as it's the inverse order of what the submitting thread will do.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26583?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-112.122"><img alt="high 4.7: CVE--2024--26583" src="https://img.shields.io/badge/CVE--2024--26583-lightgrey?label=high%204.7&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-112.122</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-112.122</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tls: fix race between async notify and socket close  The submitting thread (one which called recvmsg/sendmsg) may exit as soon as the async crypto handler calls complete() so any code past that point risks touching already freed data.  Try to avoid the locking and extra flags altogether. Have the main thread hold an extra reference, this way we can depend solely on the atomic ref counter for synchronization.  Don't futz with reiniting the completion, either, we are now tightly controlling when completion fires.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-6176?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-94.104"><img alt="high 4.7: CVE--2023--6176" src="https://img.shields.io/badge/CVE--2023--6176-lightgrey?label=high%204.7&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-94.104</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-94.104</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.010%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A null pointer dereference flaw was found in the Linux kernel API for the cryptographic algorithm scatterwalk functionality. This issue occurs when a user constructs a malicious packet with specific socket configuration, which could allow a local user to crash the system or escalate their privileges on the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-20569?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-112.122"><img alt="high 4.7: CVE--2023--20569" src="https://img.shields.io/badge/CVE--2023--20569-lightgrey?label=high%204.7&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-112.122</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-112.122</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.633%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>69th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A side channel vulnerability on some of the AMD CPUs may allow an attacker to influence the return address prediction. This may result in speculative execution at an attacker-controlled address, potentially leading to information disclosure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21887?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-140.150"><img alt="high : CVE--2025--21887" src="https://img.shields.io/badge/CVE--2025--21887-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-140.150</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-140.150</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ovl: fix UAF in ovl_dentry_update_reval by moving dput() in ovl_link_up  The issue was caused by dput(upper) being called before ovl_dentry_update_reval(), while upper->d_flags was still accessed in ovl_dentry_remote().  Move dput(upper) after its last use to prevent use-after-free.  BUG: KASAN: slab-use-after-free in ovl_dentry_remote fs/overlayfs/util.c:162 [inline] BUG: KASAN: slab-use-after-free in ovl_dentry_update_reval+0xd2/0xf0 fs/overlayfs/util.c:167  Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:114 print_address_description mm/kasan/report.c:377 [inline] print_report+0xc3/0x620 mm/kasan/report.c:488 kasan_report+0xd9/0x110 mm/kasan/report.c:601 ovl_dentry_remote fs/overlayfs/util.c:162 [inline] ovl_dentry_update_reval+0xd2/0xf0 fs/overlayfs/util.c:167 ovl_link_up fs/overlayfs/copy_up.c:610 [inline] ovl_copy_up_one+0x2105/0x3490 fs/overlayfs/copy_up.c:1170 ovl_copy_up_flags+0x18d/0x200 fs/overlayfs/copy_up.c:1223 ovl_rename+0x39e/0x18c0 fs/overlayfs/dir.c:1136 vfs_rename+0xf84/0x20a0 fs/namei.c:4893 ... </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53197?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-135.146"><img alt="high : CVE--2024--53197" src="https://img.shields.io/badge/CVE--2024--53197-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-135.146</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-135.146</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.300%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>53rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ALSA: usb-audio: Fix potential out-of-bound accesses for Extigy and Mbox devices  A bogus device can provide a bNumConfigurations value that exceeds the initial value used in usb_get_configuration for allocating dev->config.  This can lead to out-of-bounds accesses later, e.g. in usb_destroy_configuration.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38558?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-121.131"><img alt="high : CVE--2024--38558" src="https://img.shields.io/badge/CVE--2024--38558-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-121.131</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-121.131</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.080%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: openvswitch: fix overwriting ct original tuple for ICMPv6  OVS_PACKET_CMD_EXECUTE has 3 main attributes: - OVS_PACKET_ATTR_KEY - Packet metadata in a netlink format. - OVS_PACKET_ATTR_PACKET - Binary packet content. - OVS_PACKET_ATTR_ACTIONS - Actions to execute on the packet.  OVS_PACKET_ATTR_KEY is parsed first to populate sw_flow_key structure with the metadata like conntrack state, input port, recirculation id, etc.  Then the packet itself gets parsed to populate the rest of the keys from the packet headers.  Whenever the packet parsing code starts parsing the ICMPv6 header, it first zeroes out fields in the key corresponding to Neighbor Discovery information even if it is not an ND packet.  It is an 'ipv6.nd' field.  However, the 'ipv6' is a union that shares the space between 'nd' and 'ct_orig' that holds the original tuple conntrack metadata parsed from the OVS_PACKET_ATTR_KEY.  ND packets should not normally have conntrack state, so it's fine to share the space, but normal ICMPv6 Echo packets or maybe other types of ICMPv6 can have the state attached and it should not be overwritten.  The issue results in all but the last 4 bytes of the destination address being wiped from the original conntrack tuple leading to incorrect packet matching and potentially executing wrong actions in case this packet recirculates within the datapath or goes back to userspace.  ND fields should not be accessed in non-ND packets, so not clearing them should be fine.  Executing memset() only for actual ND packets to avoid the issue.  Initializing the whole thing before parsing is needed because ND packet may not contain all the options.  The issue only affects the OVS_PACKET_CMD_EXECUTE path and doesn't affect packets entering OVS datapath from network interfaces, because in this case CT metadata is populated from skb after the packet is already parsed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36972?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-121.131"><img alt="high : CVE--2024--36972" src="https://img.shields.io/badge/CVE--2024--36972-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-121.131</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-121.131</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.099%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  af_unix: Update unix_sk(sk)->oob_skb under sk_receive_queue lock.  Billy Jheng Bing-Jhong reported a race between __unix_gc() and queue_oob().  __unix_gc() tries to garbage-collect close()d inflight sockets, and then if the socket has MSG_OOB in unix_sk(sk)->oob_skb, GC will drop the reference and set NULL to it locklessly.  However, the peer socket still can send MSG_OOB message and queue_oob() can update unix_sk(sk)->oob_skb concurrently, leading NULL pointer dereference. [0]  To fix the issue, let's update unix_sk(sk)->oob_skb under the sk_receive_queue's lock and take it everywhere we touch oob_skb.  Note that we defer kfree_skb() in manage_oob() to silence lockdep false-positive (See [1]).  [0]: BUG: kernel NULL pointer dereference, address: 0000000000000008 PF: supervisor write access in kernel mode PF: error_code(0x0002) - not-present page PGD 8000000009f5e067 P4D 8000000009f5e067 PUD 9f5d067 PMD 0 Oops: 0002 [#1] PREEMPT SMP PTI CPU: 3 PID: 50 Comm: kworker/3:1 Not tainted 6.9.0-rc5-00191-gd091e579b864 #110 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 Workqueue: events delayed_fput RIP: 0010:skb_dequeue (./include/linux/skbuff.h:2386 ./include/linux/skbuff.h:2402 net/core/skbuff.c:3847) Code: 39 e3 74 3e 8b 43 10 48 89 ef 83 e8 01 89 43 10 49 8b 44 24 08 49 c7 44 24 08 00 00 00 00 49 8b 14 24 49 c7 04 24 00 00 00 00 <48> 89 42 08 48 89 10 e8 e7 c5 42 00 4c 89 e0 5b 5d 41 5c c3 cc cc RSP: 0018:ffffc900001bfd48 EFLAGS: 00000002 RAX: 0000000000000000 RBX: ffff8880088f5ae8 RCX: 00000000361289f9 RDX: 0000000000000000 RSI: 0000000000000206 RDI: ffff8880088f5b00 RBP: ffff8880088f5b00 R08: 0000000000080000 R09: 0000000000000001 R10: 0000000000000003 R11: 0000000000000001 R12: ffff8880056b6a00 R13: ffff8880088f5280 R14: 0000000000000001 R15: ffff8880088f5a80 FS:  0000000000000000(0000) GS:ffff88807dd80000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000000000008 CR3: 0000000006314000 CR4: 00000000007506f0 PKRU: 55555554 Call Trace: <TASK> unix_release_sock (net/unix/af_unix.c:654) unix_release (net/unix/af_unix.c:1050) __sock_release (net/socket.c:660) sock_close (net/socket.c:1423) __fput (fs/file_table.c:423) delayed_fput (fs/file_table.c:444 (discriminator 3)) process_one_work (kernel/workqueue.c:3259) worker_thread (kernel/workqueue.c:3329 kernel/workqueue.c:3416) kthread (kernel/kthread.c:388) ret_from_fork (arch/x86/kernel/process.c:153) ret_from_fork_asm (arch/x86/entry/entry_64.S:257) </TASK> Modules linked in: CR2: 0000000000000008

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36016?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-117.127"><img alt="high : CVE--2024--36016" src="https://img.shields.io/badge/CVE--2024--36016-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-117.127</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-117.127</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tty: n_gsm: fix possible out-of-bounds in gsm0_receive()  Assuming the following: - side A configures the n_gsm in basic option mode - side B sends the header of a basic option mode frame with data length 1 - side A switches to advanced option mode - side B sends 2 data bytes which exceeds gsm->len Reason: gsm->len is not used in advanced option mode. - side A switches to basic option mode - side B keeps sending until gsm0_receive() writes past gsm->buf Reason: Neither gsm->state nor gsm->len have been reset after reconfiguration.  Fix this by changing gsm->count to gsm->len comparison from equal to less than. Also add upper limit checks against the constant MAX_MRU in gsm0_receive() and gsm1_receive() to harden against memory corruption of gsm->len and gsm->mru.  All other checks remain as we still need to limit the data according to the user configuration and actual payload size.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-27407?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-153.163"><img alt="high : CVE--2024--27407" src="https://img.shields.io/badge/CVE--2024--27407-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-153.163</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-153.163</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs/ntfs3: Fixed overflow check in mi_enum_attr()

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-27398?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-118.128"><img alt="high : CVE--2024--27398" src="https://img.shields.io/badge/CVE--2024--27398-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-118.128</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-118.128</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.874%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>74th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: Fix use-after-free bugs caused by sco_sock_timeout  When the sco connection is established and then, the sco socket is releasing, timeout_work will be scheduled to judge whether the sco disconnection is timeout. The sock will be deallocated later, but it is dereferenced again in sco_sock_timeout. As a result, the use-after-free bugs will happen. The root cause is shown below:  Cleanup Thread               |      Worker Thread sco_sock_release                 | sco_sock_close                 | __sco_sock_close             | sco_sock_set_timer         | schedule_delayed_work    | sco_sock_kill                  |    (wait a time) sock_put(sk) //FREE          |  sco_sock_timeout |    sock_hold(sk) //USE  The KASAN report triggered by POC is shown below:  [   95.890016] ================================================================== [   95.890496] BUG: KASAN: slab-use-after-free in sco_sock_timeout+0x5e/0x1c0 [   95.890755] Write of size 4 at addr ffff88800c388080 by task kworker/0:0/7 ... [   95.890755] Workqueue: events sco_sock_timeout [   95.890755] Call Trace: [   95.890755]  <TASK> [   95.890755]  dump_stack_lvl+0x45/0x110 [   95.890755]  print_address_description+0x78/0x390 [   95.890755]  print_report+0x11b/0x250 [   95.890755]  ? __virt_addr_valid+0xbe/0xf0 [   95.890755]  ? sco_sock_timeout+0x5e/0x1c0 [   95.890755]  kasan_report+0x139/0x170 [   95.890755]  ? update_load_avg+0xe5/0x9f0 [   95.890755]  ? sco_sock_timeout+0x5e/0x1c0 [   95.890755]  kasan_check_range+0x2c3/0x2e0 [   95.890755]  sco_sock_timeout+0x5e/0x1c0 [   95.890755]  process_one_work+0x561/0xc50 [   95.890755]  worker_thread+0xab2/0x13c0 [   95.890755]  ? pr_cont_work+0x490/0x490 [   95.890755]  kthread+0x279/0x300 [   95.890755]  ? pr_cont_work+0x490/0x490 [   95.890755]  ? kthread_blkcg+0xa0/0xa0 [   95.890755]  ret_from_fork+0x34/0x60 [   95.890755]  ? kthread_blkcg+0xa0/0xa0 [   95.890755]  ret_from_fork_asm+0x11/0x20 [   95.890755]  </TASK> [   95.890755] [   95.890755] Allocated by task 506: [   95.890755]  kasan_save_track+0x3f/0x70 [   95.890755]  __kasan_kmalloc+0x86/0x90 [   95.890755]  __kmalloc+0x17f/0x360 [   95.890755]  sk_prot_alloc+0xe1/0x1a0 [   95.890755]  sk_alloc+0x31/0x4e0 [   95.890755]  bt_sock_alloc+0x2b/0x2a0 [   95.890755]  sco_sock_create+0xad/0x320 [   95.890755]  bt_sock_create+0x145/0x320 [   95.890755]  __sock_create+0x2e1/0x650 [   95.890755]  __sys_socket+0xd0/0x280 [   95.890755]  __x64_sys_socket+0x75/0x80 [   95.890755]  do_syscall_64+0xc4/0x1b0 [   95.890755]  entry_SYSCALL_64_after_hwframe+0x67/0x6f [   95.890755] [   95.890755] Freed by task 506: [   95.890755]  kasan_save_track+0x3f/0x70 [   95.890755]  kasan_save_free_info+0x40/0x50 [   95.890755]  poison_slab_object+0x118/0x180 [   95.890755]  __kasan_slab_free+0x12/0x30 [   95.890755]  kfree+0xb2/0x240 [   95.890755]  __sk_destruct+0x317/0x410 [   95.890755]  sco_sock_release+0x232/0x280 [   95.890755]  sock_close+0xb2/0x210 [   95.890755]  __fput+0x37f/0x770 [   95.890755]  task_work_run+0x1ae/0x210 [   95.890755]  get_signal+0xe17/0xf70 [   95.890755]  arch_do_signal_or_restart+0x3f/0x520 [   95.890755]  syscall_exit_to_user_mode+0x55/0x120 [   95.890755]  do_syscall_64+0xd1/0x1b0 [   95.890755]  entry_SYSCALL_64_after_hwframe+0x67/0x6f [   95.890755] [   95.890755] The buggy address belongs to the object at ffff88800c388000 [   95.890755]  which belongs to the cache kmalloc-1k of size 1024 [   95.890755] The buggy address is located 128 bytes inside of [   95.890755]  freed 1024-byte region [ffff88800c388000, ffff88800c388400) [   95.890755] [   95.890755] The buggy address belongs to the physical page: [   95.890755] page: refcount:1 mapcount:0 mapping:0000000000000000 index:0xffff88800c38a800 pfn:0xc388 [   95.890755] head: order:3 entire_mapcount:0 nr_pages_mapped:0 pincount:0 [   95.890755] ano ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-27397?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-124.134"><img alt="high : CVE--2024--27397" src="https://img.shields.io/badge/CVE--2024--27397-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-124.134</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-124.134</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.260%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>49th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_tables: use timestamp to check for set element timeout  Add a timestamp field at the beginning of the transaction, store it in the nftables per-netns area.  Update set backend .insert, .deactivate and sync gc path to use the timestamp, this avoids that an element expires while control plane transaction is still unfinished.  .lookup and .update, which are used from packet path, still use the current time to check if the element has expired. And .get path and dump also since this runs lockless under rcu read size lock. Then, there is async gc which also needs to check the current time since it runs asynchronously from a workqueue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26960?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-116.126"><img alt="high : CVE--2024--26960" src="https://img.shields.io/badge/CVE--2024--26960-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-116.126</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-116.126</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.005%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm: swap: fix race between free_swap_and_cache() and swapoff()  There was previously a theoretical window where swapoff() could run and teardown a swap_info_struct while a call to free_swap_and_cache() was running in another thread.  This could cause, amongst other bad possibilities, swap_page_trans_huge_swapped() (called by free_swap_and_cache()) to access the freed memory for swap_map.  This is a theoretical problem and I haven't been able to provoke it from a test case.  But there has been agreement based on code review that this is possible (see link below).  Fix it by using get_swap_device()/put_swap_device(), which will stall swapoff().  There was an extra check in _swap_info_get() to confirm that the swap entry was not free.  This isn't present in get_swap_device() because it doesn't make sense in general due to the race between getting the reference and swapoff.  So I've added an equivalent check directly in free_swap_and_cache().  Details of how to provoke one possible issue (thanks to David Hildenbrand for deriving this):  --8<-----  __swap_entry_free() might be the last user and result in "count == SWAP_HAS_CACHE".  swapoff->try_to_unuse() will stop as soon as soon as si->inuse_pages==0.  So the question is: could someone reclaim the folio and turn si->inuse_pages==0, before we completed swap_page_trans_huge_swapped().  Imagine the following: 2 MiB folio in the swapcache. Only 2 subpages are still references by swap entries.  Process 1 still references subpage 0 via swap entry. Process 2 still references subpage 1 via swap entry.  Process 1 quits. Calls free_swap_and_cache(). -> count == SWAP_HAS_CACHE [then, preempted in the hypervisor etc.]  Process 2 quits. Calls free_swap_and_cache(). -> count == SWAP_HAS_CACHE  Process 2 goes ahead, passes swap_page_trans_huge_swapped(), and calls __try_to_reclaim_swap().  __try_to_reclaim_swap()->folio_free_swap()->delete_from_swap_cache()-> put_swap_folio()->free_swap_slot()->swapcache_free_entries()-> swap_entry_free()->swap_range_free()-> ... WRITE_ONCE(si->inuse_pages, si->inuse_pages - nr_entries);  What stops swapoff to succeed after process 2 reclaimed the swap cache but before process1 finished its call to swap_page_trans_huge_swapped()?  --8<-----

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26925?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-116.126"><img alt="high : CVE--2024--26925" src="https://img.shields.io/badge/CVE--2024--26925-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-116.126</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-116.126</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.054%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_tables: release mutex after nft_gc_seq_end from abort path  The commit mutex should not be released during the critical section between nft_gc_seq_begin() and nft_gc_seq_end(), otherwise, async GC worker could collect expired objects and get the released commit lock within the same GC sequence.  nf_tables_module_autoload() temporarily releases the mutex to load module dependencies, then it goes back to replay the transaction again. Move it at the end of the abort phase after nft_gc_seq_end() is called.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26924?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-113.123"><img alt="high : CVE--2024--26924" src="https://img.shields.io/badge/CVE--2024--26924-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-113.123</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-113.123</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.088%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nft_set_pipapo: do not free live element  Pablo reports a crash with large batches of elements with a back-to-back add/remove pattern.  Quoting Pablo:  add_elem("00000000") timeout 100 ms ... add_elem("0000000X") timeout 100 ms del_elem("0000000X") <---------------- delete one that was just added ... add_elem("00005000") timeout 100 ms  1) nft_pipapo_remove() removes element 0000000X Then, KASAN shows a splat.  Looking at the remove function there is a chance that we will drop a rule that maps to a non-deactivated element.  Removal happens in two steps, first we do a lookup for key k and return the to-be-removed element and mark it as inactive in the next generation. Then, in a second step, the element gets removed from the set/map.  The _remove function does not work correctly if we have more than one element that share the same key.  This can happen if we insert an element into a set when the set already holds an element with same key, but the element mapping to the existing key has timed out or is not active in the next generation.  In such case its possible that removal will unmap the wrong element. If this happens, we will leak the non-deactivated element, it becomes unreachable.  The element that got deactivated (and will be freed later) will remain reachable in the set data structure, this can result in a crash when such an element is retrieved during lookup (stale pointer).  Add a check that the fully matching key does in fact map to the element that we have marked as inactive in the deactivation step. If not, we need to continue searching.  Add a bug/warn trap at the end of the function as well, the remove function must not ever be called with an invisible/unreachable/non-existent element.  v2: avoid uneeded temporary variable (Stefano)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26923?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-116.126"><img alt="high : CVE--2024--26923" src="https://img.shields.io/badge/CVE--2024--26923-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-116.126</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-116.126</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.073%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  af_unix: Fix garbage collector racing against connect()  Garbage collector does not take into account the risk of embryo getting enqueued during the garbage collection. If such embryo has a peer that carries SCM_RIGHTS, two consecutive passes of scan_children() may see a different set of children. Leading to an incorrectly elevated inflight count, and then a dangling pointer within the gc_inflight_list.  sockets are AF_UNIX/SOCK_STREAM S is an unconnected socket L is a listening in-flight socket bound to addr, not in fdtable V's fd will be passed via sendmsg(), gets inflight count bumped  connect(S, addr)	sendmsg(S, [V]); close(V)	__unix_gc() ----------------	-------------------------	-----------  NS = unix_create1() skb1 = sock_wmalloc(NS) L = unix_find_other(addr) unix_state_lock(L) unix_peer(S) = NS // V count=1 inflight=0  NS = unix_peer(S) skb2 = sock_alloc() skb_queue_tail(NS, skb2[V])  // V became in-flight // V count=2 inflight=1  close(V)  // V count=1 inflight=1 // GC candidate condition met  for u in gc_inflight_list: if (total_refs == inflight_refs) add u to gc_candidates  // gc_candidates={L, V}  for u in gc_candidates: scan_children(u, dec_inflight)  // embryo (skb1) was not // reachable from L yet, so V's // inflight remains unchanged __skb_queue_tail(L, skb1) unix_state_unlock(L) for u in gc_candidates: if (u.inflight) scan_children(u, inc_inflight_move_tail)  // V count=1 inflight=2 (!)  If there is a GC-candidate listening socket, lock/unlock its state. This makes GC wait until the end of any ongoing connect() to that socket. After flipping the lock, a possibly SCM-laden embryo is already enqueued. And if there is another embryo coming, it can not possibly carry SCM_RIGHTS. At this point, unix_inflight() can not happen because unix_gc_lock is already taken. Inflight graph remains unaffected.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26921?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-119.129"><img alt="high : CVE--2024--26921" src="https://img.shields.io/badge/CVE--2024--26921-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-119.129</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-119.129</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.193%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>41st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  inet: inet_defrag: prevent sk release while still in use  ip_local_out() and other functions can pass skb->sk as function argument.  If the skb is a fragment and reassembly happens before such function call returns, the sk must not be released.  This affects skb fragments reassembled via netfilter or similar modules, e.g. openvswitch or ct_act.c, when run as part of tx pipeline.  Eric Dumazet made an initial analysis of this bug.  Quoting Eric: Calling ip_defrag() in output path is also implying skb_orphan(), which is buggy because output path relies on sk not disappearing.  A relevant old patch about the issue was : 8282f27449bf ("inet: frag: Always orphan skbs inside ip_defrag()")  [..]  net/ipv4/ip_output.c depends on skb->sk being set, and probably to an inet socket, not an arbitrary one.  If we orphan the packet in ipvlan, then downstream things like FQ packet scheduler will not work properly.  We need to change ip_defrag() to only use skb_orphan() when really needed, ie whenever frag_list is going to be used.  Eric suggested to stash sk in fragment queue and made an initial patch. However there is a problem with this:  If skb is refragmented again right after, ip_do_fragment() will copy head->sk to the new fragments, and sets up destructor to sock_wfree. IOW, we have no choice but to fix up sk_wmem accouting to reflect the fully reassembled skb, else wmem will underflow.  This change moves the orphan down into the core, to last possible moment. As ip_defrag_offset is aliased with sk_buff->sk member, we must move the offset into the FRAG_CB, else skb->sk gets clobbered.  This allows to delay the orphaning long enough to learn if the skb has to be queued or if the skb is completing the reasm queue.  In the former case, things work as before, skb is orphaned.  This is safe because skb gets queued/stolen and won't continue past reasm engine.  In the latter case, we will steal the skb->sk reference, reattach it to the head skb, and fix up wmem accouting when inet_frag inflates truesize.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26828?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-116.126"><img alt="high : CVE--2024--26828" src="https://img.shields.io/badge/CVE--2024--26828-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-116.126</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-116.126</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cifs: fix underflow in parse_server_interfaces()  In this loop, we step through the buffer and after each item we check if the size_left is greater than the minimum size we need.  However, the problem is that "bytes_left" is type ssize_t while sizeof() is type size_t.  That means that because of type promotion, the comparison is done as an unsigned and if we have negative bytes left the loop continues instead of ending.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26808?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-106.116"><img alt="high : CVE--2024--26808" src="https://img.shields.io/badge/CVE--2024--26808-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-106.116</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-106.116</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nft_chain_filter: handle NETDEV_UNREGISTER for inet/ingress basechain  Remove netdevice from inet/ingress basechain in case NETDEV_UNREGISTER event is reported, otherwise a stale reference to netdevice remains in the hook list.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52880?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-116.126"><img alt="high : CVE--2023--52880" src="https://img.shields.io/badge/CVE--2023--52880-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-116.126</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-116.126</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.050%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tty: n_gsm: require CAP_NET_ADMIN to attach N_GSM0710 ldisc  Any unprivileged user can attach N_GSM0710 ldisc, but it requires CAP_NET_ADMIN to create a GSM network anyway.  Require initial namespace CAP_NET_ADMIN to do that.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52620?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-112.122"><img alt="high : CVE--2023--52620" src="https://img.shields.io/badge/CVE--2023--52620-lightgrey?label=high%20&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-112.122</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-112.122</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_tables: disallow timeout for anonymous sets  Never used from userspace, disallow these parameters.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 3" src="https://img.shields.io/badge/H-3-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>setuptools</strong> <code>59.6.0</code> (pypi)</summary>

<small><code>pkg:pypi/setuptools@59.6.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-40897?s=github&n=setuptools&t=pypi&vr=%3C65.5.1"><img alt="high 8.7: CVE--2022--40897" src="https://img.shields.io/badge/CVE--2022--40897-lightgrey?label=high%208.7&labelColor=e25d68"/></a> <i>Inefficient Regular Expression Complexity</i>

<table>
<tr><td>Affected range</td><td><code><65.5.1</code></td></tr>
<tr><td>Fixed version</td><td><code>65.5.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:L/SI:L/SA:N</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.318%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>54th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Python Packaging Authority (PyPA)'s setuptools is a library designed to facilitate packaging Python projects. Setuptools version 65.5.0 and earlier could allow remote attackers to cause a denial of service by fetching malicious HTML from a PyPI package or custom PackageIndex page due to a vulnerable Regular Expression in `package_index`. This has been patched in version 65.5.1.

</blockquote>
</details>

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
<tr><td>EPSS Score</td><td><code>10.079%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>93rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the `package_index` module of pypa/setuptools versions up to 69.1.1 allows for remote code execution via its download functions. These functions, which are used to download packages from URLs provided by users or retrieved from package index servers, are susceptible to code injection. If these functions are exposed to user-controlled inputs, such as package URLs, they can execute arbitrary commands on the system. The issue is fixed in version 70.0.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 2" src="https://img.shields.io/badge/H-2-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>keras</strong> <code>3.6.0</code> (pypi)</summary>

<small><code>pkg:pypi/keras@3.6.0</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-8747?s=github&n=keras&t=pypi&vr=%3E%3D3.0.0%2C%3C3.11.0"><img alt="high 8.8: CVE--2025--8747" src="https://img.shields.io/badge/CVE--2025--8747-lightgrey?label=high%208.8&labelColor=e25d68"/></a> <i>Deserialization of Untrusted Data</i>

<table>
<tr><td>Affected range</td><td><code>>=3.0.0<br/><3.11.0</code></td></tr>
<tr><td>Fixed version</td><td><code>3.11.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.006%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Summary
It is possible to bypass the mitigation introduced in response to [CVE-2025-1550](https://github.com/keras-team/keras/security/advisories/GHSA-48g7-3x6r-xfhp), when an untrusted Keras v3 model is loaded, even when “safe_mode” is enabled, by crafting malicious arguments to built-in Keras modules.

The vulnerability is exploitable on the default configuration and does not depend on user input (just requires an untrusted model to be loaded).

### Impact

| Type   | Vector   |Impact|
| -------- | ------- | ------- |
|Unsafe deserialization |Client-Side (when loading untrusted model)|Arbitrary file overwrite. Can lead to Arbitrary code execution in many cases.|


### Details

Keras’ [safe_mode](https://www.tensorflow.org/api_docs/python/tf/keras/models/load_model) flag is designed to disallow unsafe lambda deserialization - specifically by rejecting any arbitrary embedded Python code, marked by the “__lambda__” class name.
https://github.com/keras-team/keras/blob/v3.8.0/keras/src/saving/serialization_lib.py#L641 -

```
if config["class_name"] == "__lambda__":
        if safe_mode:
            raise ValueError(
                "Requested the deserialization of a `lambda` object. "
                "This carries a potential risk of arbitrary code execution "
                "and thus it is disallowed by default. If you trust the "
                "source of the saved model, you can pass `safe_mode=False` to "
                "the loading function in order to allow `lambda` loading, "
                "or call `keras.config.enable_unsafe_deserialization()`."
            )
```

A fix to the vulnerability, allowing deserialization of the object only from internal Keras modules, was introduced in the commit [bb340d6780fdd6e115f2f4f78d8dbe374971c930](https://github.com/keras-team/keras/commit/bb340d6780fdd6e115f2f4f78d8dbe374971c930). 

```
package = module.split(".", maxsplit=1)[0]
if package in {"keras", "keras_hub", "keras_cv", "keras_nlp"}:
```

However, it is still possible to exploit model loading, for example by reusing the internal Keras function `keras.utils.get_file`, and download remote files to an attacker-controlled location.
This allows for arbitrary file overwrite which in many cases could also lead to remote code execution. For example, an attacker would be able to download a malicious `authorized_keys` file into the user’s SSH folder, giving the attacker full SSH access to the victim’s machine.
Since the model does not contain arbitrary Python code, this scenario will not be blocked by “safe_mode”. It will bypass the latest fix since it uses a function from one of the approved modules (`keras`).

#### Example 
The following truncated `config.json` will cause a remote file download from https://raw.githubusercontent.com/andr3colonel/when_you_watch_computer/refs/heads/master/index.js to the local `/tmp` folder, by sending arbitrary arguments to Keras’ builtin function `keras.utils.get_file()` -

```
           {
                "class_name": "Lambda",
                "config": {
                    "arguments": {
                        "origin": "https://raw.githubusercontent.com/andr3colonel/when_you_watch_computer/refs/heads/master/index.js",
                        "cache_dir":"/tmp",
                        "cache_subdir":"",
                        "force_download": true},
                    "function": {
                        "class_name": "function",
                        "config": "get_file",
                        "module": "keras.utils"
                    }
                },
 ```


### PoC

1. Download [malicious_model_download.keras](https://drive.google.com/file/d/1gS2I6VTTRUwUq8gBoMmvTGaN0SX1Vr8F/view?usp=drive_link) to a local directory

2. Load the model -

```
from keras.models import load_model
model = load_model("malicious_model_download.keras", safe_mode=True)
```

3. Observe that a new file `index.js` was created in the `/tmp` directory 

### Fix suggestions
1. Add an additional flag `block_all_lambda` that allows users to completely disallow loading models with a Lambda layer.
1. Audit the `keras`, `keras_hub`, `keras_cv`, `keras_nlp` modules and remove/block all “gadget functions” which could be used by malicious ML models.
1. Add an additional flag `lambda_whitelist_functions` that allows users to specify a list of functions that are allowed to be invoked by a Lambda layer

### Credit 
The vulnerability was discovered by Andrey Polkovnichenko of the JFrog Vulnerability Research

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-1550?s=github&n=keras&t=pypi&vr=%3E%3D3.0.0%2C%3C3.9.0"><img alt="high 7.3: CVE--2025--1550" src="https://img.shields.io/badge/CVE--2025--1550-lightgrey?label=high%207.3&labelColor=e25d68"/></a> <i>Improper Control of Generation of Code ('Code Injection')</i>

<table>
<tr><td>Affected range</td><td><code>>=3.0.0<br/><3.9.0</code></td></tr>
<tr><td>Fixed version</td><td><code>3.9.0</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.3</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.260%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>49th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

### Impact

The Keras `Model.load_model` function permits arbitrary code execution, even with `safe_mode=True`, through a manually constructed, malicious `.keras` archive. By altering the `config.json` file within the archive, an attacker can specify arbitrary Python modules and functions, along with their arguments, to be loaded and executed during model loading.

### Patches

This problem is fixed starting with version `3.9`.

### Workarounds

Only load models from trusted sources and model archives created with Keras.

### References

- https://www.cve.org/cverecord?id=CVE-2025-1550
- https://github.com/keras-team/keras/pull/20751

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 0" src="https://img.shields.io/badge/M-0-lightgrey"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>wheel</strong> <code>0.37.1</code> (pypi)</summary>

<small><code>pkg:pypi/wheel@0.37.1</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2022-40898?s=github&n=wheel&t=pypi&vr=%3C0.38.1"><img alt="high 7.5: CVE--2022--40898" src="https://img.shields.io/badge/CVE--2022--40898-lightgrey?label=high%207.5&labelColor=e25d68"/></a> <i>Inefficient Regular Expression Complexity</i>

<table>
<tr><td>Affected range</td><td><code><0.38.1</code></td></tr>
<tr><td>Fixed version</td><td><code>0.38.1</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.196%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>42nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Python Packaging Authority (PyPA) Wheel is a reference implementation of the Python wheel packaging standard. Wheel 0.37.1 and earlier are vulnerable to a Regular Expression denial of service via attacker controlled input to the wheel cli. The vulnerable regex is used to verify the validity of Wheel file names. This has been patched in version 0.38.1.

</blockquote>
</details>
</details></td></tr>
</table>