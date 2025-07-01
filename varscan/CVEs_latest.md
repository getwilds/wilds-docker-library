# Vulnerability Report for getwilds/varscan:latest

Report generated on 2025-07-01 08:56:10 PST

<h2>:mag: Vulnerabilities of <code>getwilds/varscan:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/varscan:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:d81e80829d154f8dea5da0ba3d8677db4d691c8e1c3efea3bba40cadda9f6392</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 68" src="https://img.shields.io/badge/medium-68-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/low-1-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>446 MB</td></tr>
<tr><td>packages</td><td>467</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 66" src="https://img.shields.io/badge/M-66-fbb552"/> <img alt="low: 1" src="https://img.shields.io/badge/L-1-fce1a9"/> <!-- unspecified: 0 --><strong>linux</strong> <code>5.15.0-141.151</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@5.15.0-141.151?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-8805?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 8.8: CVE--2024--8805" src="https://img.shields.io/badge/CVE--2024--8805-lightgrey?label=medium%208.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.349%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>57th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

BlueZ HID over GATT Profile Improper Access Control Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of BlueZ. Authentication is not required to exploit this vulnerability.  The specific flaw exists within the implementation of the HID over GATT Profile. The issue results from the lack of authorization prior to allowing access to functionality. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-25177.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22056?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.8: CVE--2025--22056" src="https://img.shields.io/badge/CVE--2025--22056-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nft_tunnel: fix geneve_opt type confusion addition  When handling multiple NFTA_TUNNEL_KEY_OPTS_GENEVE attributes, the parsing logic should place every geneve_opt structure one by one compactly. Hence, when deciding the next geneve_opt position, the pointer addition should be in units of char *.  However, the current implementation erroneously does type conversion before the addition, which will lead to heap out-of-bounds write.  [    6.989857] ================================================================== [    6.990293] BUG: KASAN: slab-out-of-bounds in nft_tunnel_obj_init+0x977/0xa70 [    6.990725] Write of size 124 at addr ffff888005f18974 by task poc/178 [    6.991162] [    6.991259] CPU: 0 PID: 178 Comm: poc-oob-write Not tainted 6.1.132 #1 [    6.991655] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 [    6.992281] Call Trace: [    6.992423]  <TASK> [    6.992586]  dump_stack_lvl+0x44/0x5c [    6.992801]  print_report+0x184/0x4be [    6.993790]  kasan_report+0xc5/0x100 [    6.994252]  kasan_check_range+0xf3/0x1a0 [    6.994486]  memcpy+0x38/0x60 [    6.994692]  nft_tunnel_obj_init+0x977/0xa70 [    6.995677]  nft_obj_init+0x10c/0x1b0 [    6.995891]  nf_tables_newobj+0x585/0x950 [    6.996922]  nfnetlink_rcv_batch+0xdf9/0x1020 [    6.998997]  nfnetlink_rcv+0x1df/0x220 [    6.999537]  netlink_unicast+0x395/0x530 [    7.000771]  netlink_sendmsg+0x3d0/0x6d0 [    7.001462]  __sock_sendmsg+0x99/0xa0 [    7.001707]  ____sys_sendmsg+0x409/0x450 [    7.002391]  ___sys_sendmsg+0xfd/0x170 [    7.003145]  __sys_sendmsg+0xea/0x170 [    7.004359]  do_syscall_64+0x5e/0x90 [    7.005817]  entry_SYSCALL_64_after_hwframe+0x6e/0xd8 [    7.006127] RIP: 0033:0x7ec756d4e407 [    7.006339] Code: 48 89 fa 4c 89 df e8 38 aa 00 00 8b 93 08 03 00 00 59 5e 48 83 f8 fc 74 1a 5b c3 0f 1f 84 00 00 00 00 00 48 8b 44 24 10 0f 05 <5b> c3 0f 1f 80 00 00 00 00 83 e2 39 83 faf [    7.007364] RSP: 002b:00007ffed5d46760 EFLAGS: 00000202 ORIG_RAX: 000000000000002e [    7.007827] RAX: ffffffffffffffda RBX: 00007ec756cc4740 RCX: 00007ec756d4e407 [    7.008223] RDX: 0000000000000000 RSI: 00007ffed5d467f0 RDI: 0000000000000003 [    7.008620] RBP: 00007ffed5d468a0 R08: 0000000000000000 R09: 0000000000000000 [    7.009039] R10: 0000000000000000 R11: 0000000000000202 R12: 0000000000000000 [    7.009429] R13: 00007ffed5d478b0 R14: 00007ec756ee5000 R15: 00005cbd4e655cb8  Fix this bug with correct pointer addition and conversion in parse and dump code.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22020?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.8: CVE--2025--22020" src="https://img.shields.io/badge/CVE--2025--22020-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  memstick: rtsx_usb_ms: Fix slab-use-after-free in rtsx_usb_ms_drv_remove  This fixes the following crash:  ================================================================== BUG: KASAN: slab-use-after-free in rtsx_usb_ms_poll_card+0x159/0x200 [rtsx_usb_ms] Read of size 8 at addr ffff888136335380 by task kworker/6:0/140241  CPU: 6 UID: 0 PID: 140241 Comm: kworker/6:0 Kdump: loaded Tainted: G E      6.14.0-rc6+ #1 Tainted: [E]=UNSIGNED_MODULE Hardware name: LENOVO 30FNA1V7CW/1057, BIOS S0EKT54A 07/01/2024 Workqueue: events rtsx_usb_ms_poll_card [rtsx_usb_ms] Call Trace: <TASK> dump_stack_lvl+0x51/0x70 print_address_description.constprop.0+0x27/0x320 ? rtsx_usb_ms_poll_card+0x159/0x200 [rtsx_usb_ms] print_report+0x3e/0x70 kasan_report+0xab/0xe0 ? rtsx_usb_ms_poll_card+0x159/0x200 [rtsx_usb_ms] rtsx_usb_ms_poll_card+0x159/0x200 [rtsx_usb_ms] ? __pfx_rtsx_usb_ms_poll_card+0x10/0x10 [rtsx_usb_ms] ? __pfx___schedule+0x10/0x10 ? kick_pool+0x3b/0x270 process_one_work+0x357/0x660 worker_thread+0x390/0x4c0 ? __pfx_worker_thread+0x10/0x10 kthread+0x190/0x1d0 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x2d/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1a/0x30 </TASK>  Allocated by task 161446: kasan_save_stack+0x20/0x40 kasan_save_track+0x10/0x30 __kasan_kmalloc+0x7b/0x90 __kmalloc_noprof+0x1a7/0x470 memstick_alloc_host+0x1f/0xe0 [memstick] rtsx_usb_ms_drv_probe+0x47/0x320 [rtsx_usb_ms] platform_probe+0x60/0xe0 call_driver_probe+0x35/0x120 really_probe+0x123/0x410 __driver_probe_device+0xc7/0x1e0 driver_probe_device+0x49/0xf0 __device_attach_driver+0xc6/0x160 bus_for_each_drv+0xe4/0x160 __device_attach+0x13a/0x2b0 bus_probe_device+0xbd/0xd0 device_add+0x4a5/0x760 platform_device_add+0x189/0x370 mfd_add_device+0x587/0x5e0 mfd_add_devices+0xb1/0x130 rtsx_usb_probe+0x28e/0x2e0 [rtsx_usb] usb_probe_interface+0x15c/0x460 call_driver_probe+0x35/0x120 really_probe+0x123/0x410 __driver_probe_device+0xc7/0x1e0 driver_probe_device+0x49/0xf0 __device_attach_driver+0xc6/0x160 bus_for_each_drv+0xe4/0x160 __device_attach+0x13a/0x2b0 rebind_marked_interfaces.isra.0+0xcc/0x110 usb_reset_device+0x352/0x410 usbdev_do_ioctl+0xe5c/0x1860 usbdev_ioctl+0xa/0x20 __x64_sys_ioctl+0xc5/0xf0 do_syscall_64+0x59/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Freed by task 161506: kasan_save_stack+0x20/0x40 kasan_save_track+0x10/0x30 kasan_save_free_info+0x36/0x60 __kasan_slab_free+0x34/0x50 kfree+0x1fd/0x3b0 device_release+0x56/0xf0 kobject_cleanup+0x73/0x1c0 rtsx_usb_ms_drv_remove+0x13d/0x220 [rtsx_usb_ms] platform_remove+0x2f/0x50 device_release_driver_internal+0x24b/0x2e0 bus_remove_device+0x124/0x1d0 device_del+0x239/0x530 platform_device_del.part.0+0x19/0xe0 platform_device_unregister+0x1c/0x40 mfd_remove_devices_fn+0x167/0x170 device_for_each_child_reverse+0xc9/0x130 mfd_remove_devices+0x6e/0xa0 rtsx_usb_disconnect+0x2e/0xd0 [rtsx_usb] usb_unbind_interface+0xf3/0x3f0 device_release_driver_internal+0x24b/0x2e0 proc_disconnect_claim+0x13d/0x220 usbdev_do_ioctl+0xb5e/0x1860 usbdev_ioctl+0xa/0x20 __x64_sys_ioctl+0xc5/0xf0 do_syscall_64+0x59/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Last potentially related work creation: kasan_save_stack+0x20/0x40 kasan_record_aux_stack+0x85/0x90 insert_work+0x29/0x100 __queue_work+0x34a/0x540 call_timer_fn+0x2a/0x160 expire_timers+0x5f/0x1f0 __run_timer_base.part.0+0x1b6/0x1e0 run_timer_softirq+0x8b/0xe0 handle_softirqs+0xf9/0x360 __irq_exit_rcu+0x114/0x130 sysvec_apic_timer_interrupt+0x72/0x90 asm_sysvec_apic_timer_interrupt+0x16/0x20  Second to last potentially related work creation: kasan_save_stack+0x20/0x40 kasan_record_aux_stack+0x85/0x90 insert_work+0x29/0x100 __queue_work+0x34a/0x540 call_timer_fn+0x2a/0x160 expire_timers+0x5f/0x1f0 __run_timer_base.part.0+0x1b6/0x1e0 run_timer_softirq+0x8b/0xe0 handle_softirqs+0xf9/0x ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21991?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.8: CVE--2025--21991" src="https://img.shields.io/badge/CVE--2025--21991-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  x86/microcode/AMD: Fix out-of-bounds on systems with CPU-less NUMA nodes  Currently, load_microcode_amd() iterates over all NUMA nodes, retrieves their CPU masks and unconditionally accesses per-CPU data for the first CPU of each mask.  According to Documentation/admin-guide/mm/numaperf.rst:  "Some memory may share the same node as a CPU, and others are provided as memory only nodes."  Therefore, some node CPU masks may be empty and wouldn't have a "first CPU".  On a machine with far memory (and therefore CPU-less NUMA nodes): - cpumask_of_node(nid) is 0 - cpumask_first(0) is CONFIG_NR_CPUS - cpu_data(CONFIG_NR_CPUS) accesses the cpu_info per-CPU array at an index that is 1 out of bounds  This does not have any security implications since flashing microcode is a privileged operation but I believe this has reliability implications by potentially corrupting memory while flashing a microcode update.  When booting with CONFIG_UBSAN_BOUNDS=y on an AMD machine that flashes a microcode update. I get the following splat:  UBSAN: array-index-out-of-bounds in arch/x86/kernel/cpu/microcode/amd.c:X:Y index 512 is out of range for type 'unsigned long[512]' [...] Call Trace: dump_stack __ubsan_handle_out_of_bounds load_microcode_amd request_microcode_amd reload_store kernfs_fop_write_iter vfs_write ksys_write do_syscall_64 entry_SYSCALL_64_after_hwframe  Change the loop to go over only NUMA nodes which have CPUs before determining whether the first CPU on the respective node needs microcode update.  [ bp: Massage commit message, fix typo. ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21968?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.8: CVE--2025--21968" src="https://img.shields.io/badge/CVE--2025--21968-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Fix slab-use-after-free on hdcp_work  [Why] A slab-use-after-free is reported when HDCP is destroyed but the property_validate_dwork queue is still running.  [How] Cancel the delayed work when destroying workqueue.  (cherry picked from commit 725a04ba5a95e89c89633d4322430cfbca7ce128)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46821?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.8: CVE--2024--46821" src="https://img.shields.io/badge/CVE--2024--46821-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/pm: Fix negative array index read  Avoid using the negative values for clk_idex as an index into an array pptable->DpmDescriptor.  V2: fix clk_index return check (Tim Huang)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46812?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.8: CVE--2024--46812" src="https://img.shields.io/badge/CVE--2024--46812-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Skip inactive planes within ModeSupportAndSystemConfiguration  [Why] Coverity reports Memory - illegal accesses.  [How] Skip inactive planes.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-39735?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.1: CVE--2025--39735" src="https://img.shields.io/badge/CVE--2025--39735-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jfs: fix slab-out-of-bounds read in ea_get()  During the "size_check" label in ea_get(), the code checks if the extended attribute list (xattr) size matches ea_size. If not, it logs "ea_get: invalid extended attribute" and calls print_hex_dump().  Here, EALIST_SIZE(ea_buf->xattr) returns 4110417968, which exceeds INT_MAX (2,147,483,647). Then ea_size is clamped:  int size = clamp_t(int, ea_size, 0, EALIST_SIZE(ea_buf->xattr));  Although clamp_t aims to bound ea_size between 0 and 4110417968, the upper limit is treated as an int, causing an overflow above 2^31 - 1. This leads "size" to wrap around and become negative (-184549328).  The "size" is then passed to print_hex_dump() (called "len" in print_hex_dump()), it is passed as type size_t (an unsigned type), this is then stored inside a variable called "int remaining", which is then assigned to "int linelen" which is then passed to hex_dump_to_buffer(). In print_hex_dump() the for loop, iterates through 0 to len-1, where len is 18446744073525002176, calling hex_dump_to_buffer() on each iteration:  for (i = 0; i < len; i += rowsize) { linelen = min(remaining, rowsize); remaining -= rowsize;  hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize, linebuf, sizeof(linebuf), ascii);  ... }  The expected stopping condition (i < len) is effectively broken since len is corrupted and very large. This eventually leads to the "ptr+i" being passed to hex_dump_to_buffer() to get closer to the end of the actual bounds of "ptr", eventually an out of bounds access is done in hex_dump_to_buffer() in the following for loop:  for (j = 0; j < len; j++) { if (linebuflen < lx + 2) goto overflow2; ch = ptr[j]; ... }  To fix this we should validate "EALIST_SIZE(ea_buf->xattr)" before it is utilised.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37785?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.1: CVE--2025--37785" src="https://img.shields.io/badge/CVE--2025--37785-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ext4: fix OOB read when checking dotdot dir  Mounting a corrupted filesystem with directory which contains '.' dir entry with rec_len == block size results in out-of-bounds read (later on, when the corrupted directory is removed).  ext4_empty_dir() assumes every ext4 directory contains at least '.' and '..' as directory entries in the first data block. It first loads the '.' dir entry, performs sanity checks by calling ext4_check_dir_entry() and then uses its rec_len member to compute the location of '..' dir entry (in ext4_next_entry). It assumes the '..' dir entry fits into the same data block.  If the rec_len of '.' is precisely one block (4KB), it slips through the sanity checks (it is considered the last directory entry in the data block) and leaves "struct ext4_dir_entry_2 *de" point exactly past the memory slot allocated to the data block. The following call to ext4_check_dir_entry() on new value of de then dereferences this pointer which results in out-of-bounds mem access.  Fix this by extending __ext4_check_dir_entry() to check for '.' dir entries that reach the end of data block. Make sure to ignore the phony dir entries for checksum (by checking name_len for non-zero).  Note: This is reported by KASAN as use-after-free in case another structure was recently freed from the slot past the bound, but it is really an OOB read.  This issue was found by syzkaller tool.  Call Trace: [   38.594108] BUG: KASAN: slab-use-after-free in __ext4_check_dir_entry+0x67e/0x710 [   38.594649] Read of size 2 at addr ffff88802b41a004 by task syz-executor/5375 [   38.595158] [   38.595288] CPU: 0 UID: 0 PID: 5375 Comm: syz-executor Not tainted 6.14.0-rc7 #1 [   38.595298] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014 [   38.595304] Call Trace: [   38.595308]  <TASK> [   38.595311]  dump_stack_lvl+0xa7/0xd0 [   38.595325]  print_address_description.constprop.0+0x2c/0x3f0 [   38.595339]  ? __ext4_check_dir_entry+0x67e/0x710 [   38.595349]  print_report+0xaa/0x250 [   38.595359]  ? __ext4_check_dir_entry+0x67e/0x710 [   38.595368]  ? kasan_addr_to_slab+0x9/0x90 [   38.595378]  kasan_report+0xab/0xe0 [   38.595389]  ? __ext4_check_dir_entry+0x67e/0x710 [   38.595400]  __ext4_check_dir_entry+0x67e/0x710 [   38.595410]  ext4_empty_dir+0x465/0x990 [   38.595421]  ? __pfx_ext4_empty_dir+0x10/0x10 [   38.595432]  ext4_rmdir.part.0+0x29a/0xd10 [   38.595441]  ? __dquot_initialize+0x2a7/0xbf0 [   38.595455]  ? __pfx_ext4_rmdir.part.0+0x10/0x10 [   38.595464]  ? __pfx___dquot_initialize+0x10/0x10 [   38.595478]  ? down_write+0xdb/0x140 [   38.595487]  ? __pfx_down_write+0x10/0x10 [   38.595497]  ext4_rmdir+0xee/0x140 [   38.595506]  vfs_rmdir+0x209/0x670 [   38.595517]  ? lookup_one_qstr_excl+0x3b/0x190 [   38.595529]  do_rmdir+0x363/0x3c0 [   38.595537]  ? __pfx_do_rmdir+0x10/0x10 [   38.595544]  ? strncpy_from_user+0x1ff/0x2e0 [   38.595561]  __x64_sys_unlinkat+0xf0/0x130 [   38.595570]  do_syscall_64+0x5b/0x180 [   38.595583]  entry_SYSCALL_64_after_hwframe+0x76/0x7e

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56664?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.0: CVE--2024--56664" src="https://img.shields.io/badge/CVE--2024--56664-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf, sockmap: Fix race between element replace and close()  Element replace (with a socket different from the one stored) may race with socket's close() link popping & unlinking. __sock_map_delete() unconditionally unrefs the (wrong) element:  // set map[0] = s0 map_update_elem(map, 0, s0)  // drop fd of s0 close(s0) sock_map_close() lock_sock(sk)               (s0!) sock_map_remove_links(sk) link = sk_psock_link_pop() sock_map_unlink(sk, link) sock_map_delete_from_link // replace map[0] with s1 map_update_elem(map, 0, s1) sock_map_update_elem (s1!)       lock_sock(sk) sock_map_update_common psock = sk_psock(sk) spin_lock(&stab->lock) osk = stab->sks[idx] sock_map_add_link(..., &stab->sks[idx]) sock_map_unref(osk, &stab->sks[idx]) psock = sk_psock(osk) sk_psock_put(sk, psock) if (refcount_dec_and_test(&psock)) sk_psock_drop(sk, psock) spin_unlock(&stab->lock) unlock_sock(sk) __sock_map_delete spin_lock(&stab->lock) sk = *psk                        // s1 replaced s0; sk == s1 if (!sk_test || sk_test == sk)   // sk_test (s0) != sk (s1); no branch sk = xchg(psk, NULL) if (sk) sock_map_unref(sk, psk)        // unref s1; sks[idx] will dangle psock = sk_psock(sk) sk_psock_put(sk, psock) if (refcount_dec_and_test()) sk_psock_drop(sk, psock) spin_unlock(&stab->lock) release_sock(sk)  Then close(map) enqueues bpf_map_free_deferred, which finally calls sock_map_free(). This results in some refcount_t warnings along with a KASAN splat [1].  Fix __sock_map_delete(), do not allow sock_map_unref() on elements that may have been replaced.  [1]: BUG: KASAN: slab-use-after-free in sock_map_free+0x10e/0x330 Write of size 4 at addr ffff88811f5b9100 by task kworker/u64:12/1063  CPU: 14 UID: 0 PID: 1063 Comm: kworker/u64:12 Not tainted 6.12.0+ #125 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Arch Linux 1.16.3-1-1 04/01/2014 Workqueue: events_unbound bpf_map_free_deferred Call Trace: <TASK> dump_stack_lvl+0x68/0x90 print_report+0x174/0x4f6 kasan_report+0xb9/0x190 kasan_check_range+0x10f/0x1e0 sock_map_free+0x10e/0x330 bpf_map_free_deferred+0x173/0x320 process_one_work+0x846/0x1420 worker_thread+0x5b3/0xf80 kthread+0x29e/0x360 ret_from_fork+0x2d/0x70 ret_from_fork_asm+0x1a/0x30 </TASK>  Allocated by task 1202: kasan_save_stack+0x1e/0x40 kasan_save_track+0x10/0x30 __kasan_slab_alloc+0x85/0x90 kmem_cache_alloc_noprof+0x131/0x450 sk_prot_alloc+0x5b/0x220 sk_alloc+0x2c/0x870 unix_create1+0x88/0x8a0 unix_create+0xc5/0x180 __sock_create+0x241/0x650 __sys_socketpair+0x1ce/0x420 __x64_sys_socketpair+0x92/0x100 do_syscall_64+0x93/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Freed by task 46: kasan_save_stack+0x1e/0x40 kasan_save_track+0x10/0x30 kasan_save_free_info+0x37/0x60 __kasan_slab_free+0x4b/0x70 kmem_cache_free+0x1a1/0x590 __sk_destruct+0x388/0x5a0 sk_psock_destroy+0x73e/0xa50 process_one_work+0x846/0x1420 worker_thread+0x5b3/0xf80 kthread+0x29e/0x360 ret_from_fork+0x2d/0x70 ret_from_fork_asm+0x1a/0x30  The bu ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-39728?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--39728" src="https://img.shields.io/badge/CVE--2025--39728-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  clk: samsung: Fix UBSAN panic in samsung_clk_init()  With UBSAN_ARRAY_BOUNDS=y, I'm hitting the below panic due to dereferencing `ctx->clk_data.hws` before setting `ctx->clk_data.num = nr_clks`. Move that up to fix the crash.  UBSAN: array index out of bounds: 00000000f2005512 [#1] PREEMPT SMP <snip> Call trace: samsung_clk_init+0x110/0x124 (P) samsung_clk_init+0x48/0x124 (L) samsung_cmu_register_one+0x3c/0xa0 exynos_arm64_register_cmu+0x54/0x64 __gs101_cmu_top_of_clk_init_declare+0x28/0x60 ...

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38152?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--38152" src="https://img.shields.io/badge/CVE--2025--38152-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  remoteproc: core: Clear table_sz when rproc_shutdown  There is case as below could trigger kernel dump: Use U-Boot to start remote processor(rproc) with resource table published to a fixed address by rproc. After Kernel boots up, stop the rproc, load a new firmware which doesn't have resource table ,and start rproc.  When starting rproc with a firmware not have resource table, `memcpy(loaded_table, rproc->cached_table, rproc->table_sz)` will trigger dump, because rproc->cache_table is set to NULL during the last stop operation, but rproc->table_sz is still valid.  This issue is found on i.MX8MP and i.MX9.  Dump as below: Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000 Mem abort info: ESR = 0x0000000096000004 EC = 0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x04: level 0 translation fault Data abort info: ISV = 0, ISS = 0x00000004, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess = 0 GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 user pgtable: 4k pages, 48-bit VAs, pgdp=000000010af63000 [0000000000000000] pgd=0000000000000000, p4d=0000000000000000 Internal error: Oops: 0000000096000004 [#1] PREEMPT SMP Modules linked in: CPU: 2 UID: 0 PID: 1060 Comm: sh Not tainted 6.14.0-rc7-next-20250317-dirty #38 Hardware name: NXP i.MX8MPlus EVK board (DT) pstate: a0000005 (NzCv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : __pi_memcpy_generic+0x110/0x22c lr : rproc_start+0x88/0x1e0 Call trace: __pi_memcpy_generic+0x110/0x22c (P) rproc_boot+0x198/0x57c state_store+0x40/0x104 dev_attr_store+0x18/0x2c sysfs_kf_write+0x7c/0x94 kernfs_fop_write_iter+0x120/0x1cc vfs_write+0x240/0x378 ksys_write+0x70/0x108 __arm64_sys_write+0x1c/0x28 invoke_syscall+0x48/0x10c el0_svc_common.constprop.0+0xc0/0xe0 do_el0_svc+0x1c/0x28 el0_svc+0x30/0xcc el0t_64_sync_handler+0x10c/0x138 el0t_64_sync+0x198/0x19c  Clear rproc->table_sz to address the issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23136?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--23136" src="https://img.shields.io/badge/CVE--2025--23136-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  thermal: int340x: Add NULL check for adev  Not all devices have an ACPI companion fwnode, so adev might be NULL. This is similar to the commit cd2fd6eab480 ("platform/x86: int3472: Check for adev == NULL").  Add a check for adev not being set and return -ENODEV in that case to avoid a possible NULL pointer deref in int3402_thermal_probe().  Note, under the same directory, int3400_thermal_probe() has such a check.  [ rjw: Subject edit, added Fixes: ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22081?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22081" src="https://img.shields.io/badge/CVE--2025--22081-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs/ntfs3: Fix a couple integer overflows on 32bit systems  On 32bit systems the "off + sizeof(struct NTFS_DE)" addition can have an integer wrapping issue.  Fix it by using size_add().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22066?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22066" src="https://img.shields.io/badge/CVE--2025--22066-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: imx-card: Add NULL check in imx_card_probe()  devm_kasprintf() returns NULL when memory allocation fails. Currently, imx_card_probe() does not check for this case, which results in a NULL pointer dereference.  Add NULL check after devm_kasprintf() to prevent this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22063?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22063" src="https://img.shields.io/badge/CVE--2025--22063-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netlabel: Fix NULL pointer exception caused by CALIPSO on IPv4 sockets  When calling netlbl_conn_setattr(), addr->sa_family is used to determine the function behavior. If sk is an IPv4 socket, but the connect function is called with an IPv6 address, the function calipso_sock_setattr() is triggered. Inside this function, the following code is executed:  sk_fullsock(__sk) ? inet_sk(__sk)->pinet6 : NULL;  Since sk is an IPv4 socket, pinet6 is NULL, leading to a null pointer dereference.  This patch fixes the issue by checking if inet6_sk(sk) returns a NULL pointer before accessing pinet6.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22054?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22054" src="https://img.shields.io/badge/CVE--2025--22054-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  arcnet: Add NULL check in com20020pci_probe()  devm_kasprintf() returns NULL when memory allocation fails. Currently, com20020pci_probe() does not check for this case, which results in a NULL pointer dereference.  Add NULL check after devm_kasprintf() to prevent this issue and ensure no resources are left allocated.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22018?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22018" src="https://img.shields.io/badge/CVE--2025--22018-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  atm: Fix NULL pointer dereference  When MPOA_cache_impos_rcvd() receives the msg, it can trigger Null Pointer Dereference Vulnerability if both entry and holding_time are NULL. Because there is only for the situation where entry is NULL and holding_time exists, it can be passed when both entry and holding_time are NULL. If these are NULL, the entry will be passd to eg_cache_put() as parameter and it is referenced by entry->use code in it.  kasan log:  [    3.316691] Oops: general protection fault, probably for non-canonical address 0xdffffc0000000006:I [    3.317568] KASAN: null-ptr-deref in range [0x0000000000000030-0x0000000000000037] [    3.318188] CPU: 3 UID: 0 PID: 79 Comm: ex Not tainted 6.14.0-rc2 #102 [    3.318601] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 [    3.319298] RIP: 0010:eg_cache_remove_entry+0xa5/0x470 [    3.319677] Code: c1 f7 6e fd 48 c7 c7 00 7e 38 b2 e8 95 64 54 fd 48 c7 c7 40 7e 38 b2 48 89 ee e80 [    3.321220] RSP: 0018:ffff88800583f8a8 EFLAGS: 00010006 [    3.321596] RAX: 0000000000000006 RBX: ffff888005989000 RCX: ffffffffaecc2d8e [    3.322112] RDX: 0000000000000000 RSI: 0000000000000004 RDI: 0000000000000030 [    3.322643] RBP: 0000000000000000 R08: 0000000000000000 R09: fffffbfff6558b88 [    3.323181] R10: 0000000000000003 R11: 203a207972746e65 R12: 1ffff11000b07f15 [    3.323707] R13: dffffc0000000000 R14: ffff888005989000 R15: ffff888005989068 [    3.324185] FS:  000000001b6313c0(0000) GS:ffff88806d380000(0000) knlGS:0000000000000000 [    3.325042] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [    3.325545] CR2: 00000000004b4b40 CR3: 000000000248e000 CR4: 00000000000006f0 [    3.326430] Call Trace: [    3.326725]  <TASK> [    3.326927]  ? die_addr+0x3c/0xa0 [    3.327330]  ? exc_general_protection+0x161/0x2a0 [    3.327662]  ? asm_exc_general_protection+0x26/0x30 [    3.328214]  ? vprintk_emit+0x15e/0x420 [    3.328543]  ? eg_cache_remove_entry+0xa5/0x470 [    3.328910]  ? eg_cache_remove_entry+0x9a/0x470 [    3.329294]  ? __pfx_eg_cache_remove_entry+0x10/0x10 [    3.329664]  ? console_unlock+0x107/0x1d0 [    3.329946]  ? __pfx_console_unlock+0x10/0x10 [    3.330283]  ? do_syscall_64+0xa6/0x1a0 [    3.330584]  ? entry_SYSCALL_64_after_hwframe+0x47/0x7f [    3.331090]  ? __pfx_prb_read_valid+0x10/0x10 [    3.331395]  ? down_trylock+0x52/0x80 [    3.331703]  ? vprintk_emit+0x15e/0x420 [    3.331986]  ? __pfx_vprintk_emit+0x10/0x10 [    3.332279]  ? down_trylock+0x52/0x80 [    3.332527]  ? _printk+0xbf/0x100 [    3.332762]  ? __pfx__printk+0x10/0x10 [    3.333007]  ? _raw_write_lock_irq+0x81/0xe0 [    3.333284]  ? __pfx__raw_write_lock_irq+0x10/0x10 [    3.333614]  msg_from_mpoad+0x1185/0x2750 [    3.333893]  ? __build_skb_around+0x27b/0x3a0 [    3.334183]  ? __pfx_msg_from_mpoad+0x10/0x10 [    3.334501]  ? __alloc_skb+0x1c0/0x310 [    3.334809]  ? __pfx___alloc_skb+0x10/0x10 [    3.335283]  ? _raw_spin_lock+0xe0/0xe0 [    3.335632]  ? finish_wait+0x8d/0x1e0 [    3.335975]  vcc_sendmsg+0x684/0xba0 [    3.336250]  ? __pfx_vcc_sendmsg+0x10/0x10 [    3.336587]  ? __pfx_autoremove_wake_function+0x10/0x10 [    3.337056]  ? fdget+0x176/0x3e0 [    3.337348]  __sys_sendto+0x4a2/0x510 [    3.337663]  ? __pfx___sys_sendto+0x10/0x10 [    3.337969]  ? ioctl_has_perm.constprop.0.isra.0+0x284/0x400 [    3.338364]  ? sock_ioctl+0x1bb/0x5a0 [    3.338653]  ? __rseq_handle_notify_resume+0x825/0xd20 [    3.339017]  ? __pfx_sock_ioctl+0x10/0x10 [    3.339316]  ? __pfx___rseq_handle_notify_resume+0x10/0x10 [    3.339727]  ? selinux_file_ioctl+0xa4/0x260 [    3.340166]  __x64_sys_sendto+0xe0/0x1c0 [    3.340526]  ? syscall_exit_to_user_mode+0x123/0x140 [    3.340898]  do_syscall_64+0xa6/0x1a0 [    3.341170]  entry_SYSCALL_64_after_hwframe+0x77/0x7f [    3.341533] RIP: 0033:0x44a380 [    3.341757] Code: 0f 1f 84 00 00 00 00 00 66 90 f3 0f 1e fa 41 89 ca 64 8b 04 25 18 00 00 00 85 c00 [ ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22014?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22014" src="https://img.shields.io/badge/CVE--2025--22014-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  soc: qcom: pdr: Fix the potential deadlock  When some client process A call pdr_add_lookup() to add the look up for the service and does schedule locator work, later a process B got a new server packet indicating locator is up and call pdr_locator_new_server() which eventually sets pdr->locator_init_complete to true which process A sees and takes list lock and queries domain list but it will timeout due to deadlock as the response will queued to the same qmi->wq and it is ordered workqueue and process B is not able to complete new server request work due to deadlock on list lock.  Fix it by removing the unnecessary list iteration as the list iteration is already being done inside locator work, so avoid it here and just call schedule_work() here.  Process A                        Process B  process_scheduled_works() pdr_add_lookup()                      qmi_data_ready_work() process_scheduled_works()             pdr_locator_new_server() pdr->locator_init_complete=true; pdr_locator_work() mutex_lock(&pdr->list_lock);  pdr_locate_service()                  mutex_lock(&pdr->list_lock);  pdr_get_domain_list() pr_err("PDR: %s get domain list txn wait failed: %d\n", req->service_name, ret);  Timeout error log due to deadlock:  " PDR: tms/servreg get domain list txn wait failed: -110 PDR: service lookup for msm/adsp/sensor_pd:tms/servreg failed: -110 "  Thanks to Bjorn and Johan for letting me know that this commit also fixes an audio regression when using the in-kernel pd-mapper as that makes it easier to hit this race. [1]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22010?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22010" src="https://img.shields.io/badge/CVE--2025--22010-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/hns: Fix soft lockup during bt pages loop  Driver runs a for-loop when allocating bt pages and mapping them with buffer pages. When a large buffer (e.g. MR over 100GB) is being allocated, it may require a considerable loop count. This will lead to soft lockup:  watchdog: BUG: soft lockup - CPU#27 stuck for 22s! ... Call trace: hem_list_alloc_mid_bt+0x124/0x394 [hns_roce_hw_v2] hns_roce_hem_list_request+0xf8/0x160 [hns_roce_hw_v2] hns_roce_mtr_create+0x2e4/0x360 [hns_roce_hw_v2] alloc_mr_pbl+0xd4/0x17c [hns_roce_hw_v2] hns_roce_reg_user_mr+0xf8/0x190 [hns_roce_hw_v2] ib_uverbs_reg_mr+0x118/0x290  watchdog: BUG: soft lockup - CPU#35 stuck for 23s! ... Call trace: hns_roce_hem_list_find_mtt+0x7c/0xb0 [hns_roce_hw_v2] mtr_map_bufs+0xc4/0x204 [hns_roce_hw_v2] hns_roce_mtr_create+0x31c/0x3c4 [hns_roce_hw_v2] alloc_mr_pbl+0xb0/0x160 [hns_roce_hw_v2] hns_roce_reg_user_mr+0x108/0x1c0 [hns_roce_hw_v2] ib_uverbs_reg_mr+0x120/0x2bc  Add a cond_resched() to fix soft lockup during these loops. In order not to affect the allocation performance of normal-size buffer, set the loop count of a 100GB MR as the threshold to call cond_resched().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22007?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22007" src="https://img.shields.io/badge/CVE--2025--22007-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: Fix error code in chan_alloc_skb_cb()  The chan_alloc_skb_cb() function is supposed to return error pointers on error.  Returning NULL will lead to a NULL dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22005?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--22005" src="https://img.shields.io/badge/CVE--2025--22005-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: Fix memleak of nhc_pcpu_rth_output in fib_check_nh_v6_gw().  fib_check_nh_v6_gw() expects that fib6_nh_init() cleans up everything when it fails.  Commit 7dd73168e273 ("ipv6: Always allocate pcpu memory in a fib6_nh") moved fib_nh_common_init() before alloc_percpu_gfp() within fib6_nh_init() but forgot to add cleanup for fib6_nh->nh_common.nhc_pcpu_rth_output in case it fails to allocate fib6_nh->rt6i_pcpu, resulting in memleak.  Let's call fib_nh_common_release() and clear nhc_pcpu_rth_output in the error path.  Note that we can remove the fib6_nh_release() call in nh_create_ipv6() later in net-next.git.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21996?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--21996" src="https://img.shields.io/badge/CVE--2025--21996-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/radeon: fix uninitialized size issue in radeon_vce_cs_parse()  On the off chance that command stream passed from userspace via ioctl() call to radeon_vce_cs_parse() is weirdly crafted and first command to execute is to encode (case 0x03000001), the function in question will attempt to call radeon_vce_cs_reloc() with size argument that has not been properly initialized. Specifically, 'size' will point to 'tmp' variable before the latter had a chance to be assigned any value.  Play it safe and init 'tmp' with 0, thus ensuring that radeon_vce_cs_reloc() will catch an early error in cases like these.  Found by Linux Verification Center (linuxtesting.org) with static analysis tool SVACE.  (cherry picked from commit 2d52de55f9ee7aaee0e09ac443f77855989c6b68)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21981?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--21981" src="https://img.shields.io/badge/CVE--2025--21981-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ice: fix memory leak in aRFS after reset  Fix aRFS (accelerated Receive Flow Steering) structures memory leak by adding a checker to verify if aRFS memory is already allocated while configuring VSI. aRFS objects are allocated in two cases: - as part of VSI initialization (at probe), and - as part of reset handling  However, VSI reconfiguration executed during reset involves memory allocation one more time, without prior releasing already allocated resources. This led to the memory leak with the following signature:  [root@os-delivery ~]# cat /sys/kernel/debug/kmemleak unreferenced object 0xff3c1ca7252e6000 (size 8192): comm "kworker/0:0", pid 8, jiffies 4296833052 hex dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ backtrace (crc 0): [<ffffffff991ec485>] __kmalloc_cache_noprof+0x275/0x340 [<ffffffffc0a6e06a>] ice_init_arfs+0x3a/0xe0 [ice] [<ffffffffc09f1027>] ice_vsi_cfg_def+0x607/0x850 [ice] [<ffffffffc09f244b>] ice_vsi_setup+0x5b/0x130 [ice] [<ffffffffc09c2131>] ice_init+0x1c1/0x460 [ice] [<ffffffffc09c64af>] ice_probe+0x2af/0x520 [ice] [<ffffffff994fbcd3>] local_pci_probe+0x43/0xa0 [<ffffffff98f07103>] work_for_cpu_fn+0x13/0x20 [<ffffffff98f0b6d9>] process_one_work+0x179/0x390 [<ffffffff98f0c1e9>] worker_thread+0x239/0x340 [<ffffffff98f14abc>] kthread+0xcc/0x100 [<ffffffff98e45a6d>] ret_from_fork+0x2d/0x50 [<ffffffff98e083ba>] ret_from_fork_asm+0x1a/0x30 ...

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21964?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--21964" src="https://img.shields.io/badge/CVE--2025--21964-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cifs: Fix integer overflow while processing acregmax mount option  User-provided mount parameter acregmax of type u32 is intended to have an upper limit, but before it is validated, the value is converted from seconds to jiffies which can lead to an integer overflow.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21963?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--21963" src="https://img.shields.io/badge/CVE--2025--21963-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cifs: Fix integer overflow while processing acdirmax mount option  User-provided mount parameter acdirmax of type u32 is intended to have an upper limit, but before it is validated, the value is converted from seconds to jiffies which can lead to an integer overflow.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21962?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--21962" src="https://img.shields.io/badge/CVE--2025--21962-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cifs: Fix integer overflow while processing closetimeo mount option  User-provided mount parameter closetimeo of type u32 is intended to have an upper limit, but before it is validated, the value is converted from seconds to jiffies which can lead to an integer overflow.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21959?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--21959" src="https://img.shields.io/badge/CVE--2025--21959-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: nf_conncount: Fully initialize struct nf_conncount_tuple in insert_tree()  Since commit b36e4523d4d5 ("netfilter: nf_conncount: fix garbage collection confirm race"), `cpu` and `jiffies32` were introduced to the struct nf_conncount_tuple.  The commit made nf_conncount_add() initialize `conn->cpu` and `conn->jiffies32` when allocating the struct. In contrast, count_tree() was not changed to initialize them.  By commit 34848d5c896e ("netfilter: nf_conncount: Split insert and traversal"), count_tree() was split and the relevant allocation code now resides in insert_tree(). Initialize `conn->cpu` and `conn->jiffies32` in insert_tree().  BUG: KMSAN: uninit-value in find_or_evict net/netfilter/nf_conncount.c:117 [inline] BUG: KMSAN: uninit-value in __nf_conncount_add+0xd9c/0x2850 net/netfilter/nf_conncount.c:143 find_or_evict net/netfilter/nf_conncount.c:117 [inline] __nf_conncount_add+0xd9c/0x2850 net/netfilter/nf_conncount.c:143 count_tree net/netfilter/nf_conncount.c:438 [inline] nf_conncount_count+0x82f/0x1e80 net/netfilter/nf_conncount.c:521 connlimit_mt+0x7f6/0xbd0 net/netfilter/xt_connlimit.c:72 __nft_match_eval net/netfilter/nft_compat.c:403 [inline] nft_match_eval+0x1a5/0x300 net/netfilter/nft_compat.c:433 expr_call_ops_eval net/netfilter/nf_tables_core.c:240 [inline] nft_do_chain+0x426/0x2290 net/netfilter/nf_tables_core.c:288 nft_do_chain_ipv4+0x1a5/0x230 net/netfilter/nft_chain_filter.c:23 nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline] nf_hook_slow+0xf4/0x400 net/netfilter/core.c:626 nf_hook_slow_list+0x24d/0x860 net/netfilter/core.c:663 NF_HOOK_LIST include/linux/netfilter.h:350 [inline] ip_sublist_rcv+0x17b7/0x17f0 net/ipv4/ip_input.c:633 ip_list_rcv+0x9ef/0xa40 net/ipv4/ip_input.c:669 __netif_receive_skb_list_ptype net/core/dev.c:5936 [inline] __netif_receive_skb_list_core+0x15c5/0x1670 net/core/dev.c:5983 __netif_receive_skb_list net/core/dev.c:6035 [inline] netif_receive_skb_list_internal+0x1085/0x1700 net/core/dev.c:6126 netif_receive_skb_list+0x5a/0x460 net/core/dev.c:6178 xdp_recv_frames net/bpf/test_run.c:280 [inline] xdp_test_run_batch net/bpf/test_run.c:361 [inline] bpf_test_run_xdp_live+0x2e86/0x3480 net/bpf/test_run.c:390 bpf_prog_test_run_xdp+0xf1d/0x1ae0 net/bpf/test_run.c:1316 bpf_prog_test_run+0x5e5/0xa30 kernel/bpf/syscall.c:4407 __sys_bpf+0x6aa/0xd90 kernel/bpf/syscall.c:5813 __do_sys_bpf kernel/bpf/syscall.c:5902 [inline] __se_sys_bpf kernel/bpf/syscall.c:5900 [inline] __ia32_sys_bpf+0xa0/0xe0 kernel/bpf/syscall.c:5900 ia32_sys_call+0x394d/0x4180 arch/x86/include/generated/asm/syscalls_32.h:358 do_syscall_32_irqs_on arch/x86/entry/common.c:165 [inline] __do_fast_syscall_32+0xb0/0x110 arch/x86/entry/common.c:387 do_fast_syscall_32+0x38/0x80 arch/x86/entry/common.c:412 do_SYSENTER_32+0x1f/0x30 arch/x86/entry/common.c:450 entry_SYSENTER_compat_after_hwframe+0x84/0x8e  Uninit was created at: slab_post_alloc_hook mm/slub.c:4121 [inline] slab_alloc_node mm/slub.c:4164 [inline] kmem_cache_alloc_noprof+0x915/0xe10 mm/slub.c:4171 insert_tree net/netfilter/nf_conncount.c:372 [inline] count_tree net/netfilter/nf_conncount.c:450 [inline] nf_conncount_count+0x1415/0x1e80 net/netfilter/nf_conncount.c:521 connlimit_mt+0x7f6/0xbd0 net/netfilter/xt_connlimit.c:72 __nft_match_eval net/netfilter/nft_compat.c:403 [inline] nft_match_eval+0x1a5/0x300 net/netfilter/nft_compat.c:433 expr_call_ops_eval net/netfilter/nf_tables_core.c:240 [inline] nft_do_chain+0x426/0x2290 net/netfilter/nf_tables_core.c:288 nft_do_chain_ipv4+0x1a5/0x230 net/netfilter/nft_chain_filter.c:23 nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline] nf_hook_slow+0xf4/0x400 net/netfilter/core.c:626 nf_hook_slow_list+0x24d/0x860 net/netfilter/core.c:663 NF_HOOK_LIST include/linux/netfilter.h:350 [inline] ip_sublist_rcv+0x17b7/0x17f0 net/ipv4/ip_input.c:633 ip_list_rcv+0x9ef/0xa40 net/ip ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21957?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--21957" src="https://img.shields.io/badge/CVE--2025--21957-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: qla1280: Fix kernel oops when debug level > 2  A null dereference or oops exception will eventually occur when qla1280.c driver is compiled with DEBUG_QLA1280 enabled and ql_debug_level > 2.  I think its clear from the code that the intention here is sg_dma_len(s) not length of sg_next(s) when printing the debug info.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21941?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2025--21941" src="https://img.shields.io/badge/CVE--2025--21941-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Fix null check for pipe_ctx->plane_state in resource_build_scaling_params  Null pointer dereference issue could occur when pipe_ctx->plane_state is null. The fix adds a check to ensure 'pipe_ctx->plane_state' is not null before accessing. This prevents a null pointer dereference.  Found by code review.  (cherry picked from commit 63e6a77ccf239337baa9b1e7787cde9fa0462092)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-49728?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2022--49728" src="https://img.shields.io/badge/CVE--2022--49728-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: Fix signed integer overflow in __ip6_append_data  Resurrect ubsan overflow checks and ubsan report this warning, fix it by change the variable [length] type to size_t.  UBSAN: signed-integer-overflow in net/ipv6/ip6_output.c:1489:19 2147479552 + 8567 cannot be represented in type 'int' CPU: 0 PID: 253 Comm: err Not tainted 5.16.0+ #1 Hardware name: linux,dummy-virt (DT) Call trace: dump_backtrace+0x214/0x230 show_stack+0x30/0x78 dump_stack_lvl+0xf8/0x118 dump_stack+0x18/0x30 ubsan_epilogue+0x18/0x60 handle_overflow+0xd0/0xf0 __ubsan_handle_add_overflow+0x34/0x44 __ip6_append_data.isra.48+0x1598/0x1688 ip6_append_data+0x128/0x260 udpv6_sendmsg+0x680/0xdd0 inet6_sendmsg+0x54/0x90 sock_sendmsg+0x70/0x88 ____sys_sendmsg+0xe8/0x368 ___sys_sendmsg+0x98/0xe0 __sys_sendmmsg+0xf4/0x3b8 __arm64_sys_sendmmsg+0x34/0x48 invoke_syscall+0x64/0x160 el0_svc_common.constprop.4+0x124/0x300 do_el0_svc+0x44/0xc8 el0_svc+0x3c/0x1e8 el0t_64_sync_handler+0x88/0xb0 el0t_64_sync+0x16c/0x170  Changes since v1: -Change the variable [length] type to unsigned, as Eric Dumazet suggested. Changes since v2: -Don't change exthdrlen type in ip6_make_skb, as Paolo Abeni suggested. Changes since v3: -Don't change ulen type in udpv6_sendmsg and l2tp_ip6_sendmsg, as Jakub Kicinski suggested.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-49636?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2022--49636" src="https://img.shields.io/badge/CVE--2022--49636-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vlan: fix memory leak in vlan_newlink()  Blamed commit added back a bug I fixed in commit 9bbd917e0bec ("vlan: fix memory leak in vlan_dev_set_egress_priority")  If a memory allocation fails in vlan_changelink() after other allocations succeeded, we need to call vlan_dev_free_egress_priority() to free all allocated memory because after a failed ->newlink() we do not call any methods like ndo_uninit() or dev->priv_destructor().  In following example, if the allocation for last element 2000:2001 fails, we need to free eight prior allocations:  ip link add link dummy0 dummy0.100 type vlan id 100 \ egress-qos-map 1:2 2:3 3:4 4:5 5:6 6:7 7:8 8:9 2000:2001  syzbot report was:  BUG: memory leak unreferenced object 0xffff888117bd1060 (size 32): comm "syz-executor408", pid 3759, jiffies 4294956555 (age 34.090s) hex dump (first 32 bytes): 09 00 00 00 00 a0 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ backtrace: [<ffffffff83fc60ad>] kmalloc include/linux/slab.h:600 [inline] [<ffffffff83fc60ad>] vlan_dev_set_egress_priority+0xed/0x170 net/8021q/vlan_dev.c:193 [<ffffffff83fc6628>] vlan_changelink+0x178/0x1d0 net/8021q/vlan_netlink.c:128 [<ffffffff83fc67c8>] vlan_newlink+0x148/0x260 net/8021q/vlan_netlink.c:185 [<ffffffff838b1278>] rtnl_newlink_create net/core/rtnetlink.c:3363 [inline] [<ffffffff838b1278>] __rtnl_newlink+0xa58/0xdc0 net/core/rtnetlink.c:3580 [<ffffffff838b1629>] rtnl_newlink+0x49/0x70 net/core/rtnetlink.c:3593 [<ffffffff838ac66c>] rtnetlink_rcv_msg+0x21c/0x5c0 net/core/rtnetlink.c:6089 [<ffffffff839f9c37>] netlink_rcv_skb+0x87/0x1d0 net/netlink/af_netlink.c:2501 [<ffffffff839f8da7>] netlink_unicast_kernel net/netlink/af_netlink.c:1319 [inline] [<ffffffff839f8da7>] netlink_unicast+0x397/0x4c0 net/netlink/af_netlink.c:1345 [<ffffffff839f9266>] netlink_sendmsg+0x396/0x710 net/netlink/af_netlink.c:1921 [<ffffffff8384dbf6>] sock_sendmsg_nosec net/socket.c:714 [inline] [<ffffffff8384dbf6>] sock_sendmsg+0x56/0x80 net/socket.c:734 [<ffffffff8384e15c>] ____sys_sendmsg+0x36c/0x390 net/socket.c:2488 [<ffffffff838523cb>] ___sys_sendmsg+0x8b/0xd0 net/socket.c:2542 [<ffffffff838525b8>] __sys_sendmsg net/socket.c:2571 [inline] [<ffffffff838525b8>] __do_sys_sendmsg net/socket.c:2580 [inline] [<ffffffff838525b8>] __se_sys_sendmsg net/socket.c:2578 [inline] [<ffffffff838525b8>] __x64_sys_sendmsg+0x78/0xf0 net/socket.c:2578 [<ffffffff845ad8d5>] do_syscall_x64 arch/x86/entry/common.c:50 [inline] [<ffffffff845ad8d5>] do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80 [<ffffffff8460006a>] entry_SYSCALL_64_after_hwframe+0x46/0xb0

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-42230?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 4.4: CVE--2024--42230" src="https://img.shields.io/badge/CVE--2024--42230-lightgrey?label=medium%204.4&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.4</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  powerpc/pseries: Fix scv instruction crash with kexec  kexec on pseries disables AIL (reloc_on_exc), required for scv instruction support, before other CPUs have been shut down. This means they can execute scv instructions after AIL is disabled, which causes an interrupt at an unexpected entry location that crashes the kernel.  Change the kexec sequence to disable AIL after other CPUs have been brought down.  As a refresher, the real-mode scv interrupt vector is 0x17000, and the fixed-location head code probably couldn't easily deal with implementing such high addresses so it was just decided not to support that interrupt at all.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38637?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--38637" src="https://img.shields.io/badge/CVE--2025--38637-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: skbprio: Remove overly strict queue assertions  In the current implementation, skbprio enqueue/dequeue contains an assertion that fails under certain conditions when SKBPRIO is used as a child qdisc under TBF with specific parameters. The failure occurs because TBF sometimes peeks at packets in the child qdisc without actually dequeuing them when tokens are unavailable.  This peek operation creates a discrepancy between the parent and child qdisc queue length counters. When TBF later receives a high-priority packet, SKBPRIO's queue length may show a different value than what's reflected in its internal priority queue tracking, triggering the assertion.  The fix removes this overly strict assertions in SKBPRIO, they are not necessary at all.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38575?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--38575" src="https://img.shields.io/badge/CVE--2025--38575-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: use aead_request_free to match aead_request_alloc  Use aead_request_free() instead of kfree() to properly free memory allocated by aead_request_alloc(). This ensures sensitive crypto data is zeroed before being freed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37937?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--37937" src="https://img.shields.io/badge/CVE--2025--37937-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  objtool, media: dib8000: Prevent divide-by-zero in dib8000_set_dds()  If dib8000_set_dds()'s call to dib8000_read32() returns zero, the result is a divide-by-zero.  Prevent that from happening.  Fixes the following warning with an UBSAN kernel:  drivers/media/dvb-frontends/dib8000.o: warning: objtool: dib8000_tune() falls through to next function dib8096p_cfg_DibRx()

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37889?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--37889" src="https://img.shields.io/badge/CVE--2025--37889-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: ops: Consistently treat platform_max as control value  This reverts commit 9bdd10d57a88 ("ASoC: ops: Shift tested values in snd_soc_put_volsw() by +min"), and makes some additional related updates.  There are two ways the platform_max could be interpreted; the maximum register value, or the maximum value the control can be set to. The patch moved from treating the value as a control value to a register one. When the patch was applied it was technically correct as snd_soc_limit_volume() also used the register interpretation. However, even then most of the other usages treated platform_max as a control value, and snd_soc_limit_volume() has since been updated to also do so in commit fb9ad24485087 ("ASoC: ops: add correct range check for limiting volume"). That patch however, missed updating snd_soc_put_volsw() back to the control interpretation, and fixing snd_soc_info_volsw_range(). The control interpretation makes more sense as limiting is typically done from the machine driver, so it is appropriate to use the customer facing representation rather than the internal codec representation. Update all the code to consistently use this interpretation of platform_max.  Finally, also add some comments to the soc_mixer_control struct to hopefully avoid further patches switching between the two approaches.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23138?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--23138" src="https://img.shields.io/badge/CVE--2025--23138-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  watch_queue: fix pipe accounting mismatch  Currently, watch_queue_set_size() modifies the pipe buffers charged to user->pipe_bufs without updating the pipe->nr_accounted on the pipe itself, due to the if (!pipe_has_watch_queue()) test in pipe_resize_ring(). This means that when the pipe is ultimately freed, we decrement user->pipe_bufs by something other than what than we had charged to it, potentially leading to an underflow. This in turn can cause subsequent too_many_pipe_buffers_soft() tests to fail with -EPERM.  To remedy this, explicitly account for the pipe usage in watch_queue_set_size() to match the number set via account_pipe_buffers()  (It's unclear why watch_queue_set_size() does not update nr_accounted; it may be due to intentional overprovisioning in watch_queue_set_size()?)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-2312?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--2312" src="https://img.shields.io/badge/CVE--2025--2312-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in cifs-utils. When trying to obtain Kerberos credentials, the cifs.upcall program from the cifs-utils package makes an upcall to the wrong namespace in containerized environments. This issue may lead to disclosing sensitive data from the host's Kerberos credentials cache.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22097?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22097" src="https://img.shields.io/badge/CVE--2025--22097-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/vkms: Fix use after free and double free on init error  If the driver initialization fails, the vkms_exit() function might access an uninitialized or freed default_config pointer and it might double free it.  Fix both possible errors by initializing default_config only when the driver initialization succeeded.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22089?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22089" src="https://img.shields.io/badge/CVE--2025--22089-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/core: Don't expose hw_counters outside of init net namespace  Commit 467f432a521a ("RDMA/core: Split port and device counter sysfs attributes") accidentally almost exposed hw counters to non-init net namespaces. It didn't expose them fully, as an attempt to read any of those counters leads to a crash like this one:  [42021.807566] BUG: kernel NULL pointer dereference, address: 0000000000000028 [42021.814463] #PF: supervisor read access in kernel mode [42021.819549] #PF: error_code(0x0000) - not-present page [42021.824636] PGD 0 P4D 0 [42021.827145] Oops: 0000 [#1] SMP PTI [42021.830598] CPU: 82 PID: 2843922 Comm: switchto-defaul Kdump: loaded Tainted: G S      W I        XXX [42021.841697] Hardware name: XXX [42021.849619] RIP: 0010:hw_stat_device_show+0x1e/0x40 [ib_core] [42021.855362] Code: 90 90 90 90 90 90 90 90 90 90 90 90 f3 0f 1e fa 0f 1f 44 00 00 49 89 d0 4c 8b 5e 20 48 8b 8f b8 04 00 00 48 81 c7 f0 fa ff ff <48> 8b 41 28 48 29 ce 48 83 c6 d0 48 c1 ee 04 69 d6 ab aa aa aa 48 [42021.873931] RSP: 0018:ffff97fe90f03da0 EFLAGS: 00010287 [42021.879108] RAX: ffff9406988a8c60 RBX: ffff940e1072d438 RCX: 0000000000000000 [42021.886169] RDX: ffff94085f1aa000 RSI: ffff93c6cbbdbcb0 RDI: ffff940c7517aef0 [42021.893230] RBP: ffff97fe90f03e70 R08: ffff94085f1aa000 R09: 0000000000000000 [42021.900294] R10: ffff94085f1aa000 R11: ffffffffc0775680 R12: ffffffff87ca2530 [42021.907355] R13: ffff940651602840 R14: ffff93c6cbbdbcb0 R15: ffff94085f1aa000 [42021.914418] FS:  00007fda1a3b9700(0000) GS:ffff94453fb80000(0000) knlGS:0000000000000000 [42021.922423] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [42021.928130] CR2: 0000000000000028 CR3: 00000042dcfb8003 CR4: 00000000003726f0 [42021.935194] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [42021.942257] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [42021.949324] Call Trace: [42021.951756]  <TASK> [42021.953842]  [<ffffffff86c58674>] ? show_regs+0x64/0x70 [42021.959030]  [<ffffffff86c58468>] ? __die+0x78/0xc0 [42021.963874]  [<ffffffff86c9ef75>] ? page_fault_oops+0x2b5/0x3b0 [42021.969749]  [<ffffffff87674b92>] ? exc_page_fault+0x1a2/0x3c0 [42021.975549]  [<ffffffff87801326>] ? asm_exc_page_fault+0x26/0x30 [42021.981517]  [<ffffffffc0775680>] ? __pfx_show_hw_stats+0x10/0x10 [ib_core] [42021.988482]  [<ffffffffc077564e>] ? hw_stat_device_show+0x1e/0x40 [ib_core] [42021.995438]  [<ffffffff86ac7f8e>] dev_attr_show+0x1e/0x50 [42022.000803]  [<ffffffff86a3eeb1>] sysfs_kf_seq_show+0x81/0xe0 [42022.006508]  [<ffffffff86a11134>] seq_read_iter+0xf4/0x410 [42022.011954]  [<ffffffff869f4b2e>] vfs_read+0x16e/0x2f0 [42022.017058]  [<ffffffff869f50ee>] ksys_read+0x6e/0xe0 [42022.022073]  [<ffffffff8766f1ca>] do_syscall_64+0x6a/0xa0 [42022.027441]  [<ffffffff8780013b>] entry_SYSCALL_64_after_hwframe+0x78/0xe2  The problem can be reproduced using the following steps: ip netns add foo ip netns exec foo bash cat /sys/class/infiniband/mlx4_0/hw_counters/*  The panic occurs because of casting the device pointer into an ib_device pointer using container_of() in hw_stat_device_show() is wrong and leads to a memory corruption.  However the real problem is that hw counters should never been exposed outside of the non-init net namespace.  Fix this by saving the index of the corresponding attribute group (it might be 1 or 2 depending on the presence of driver-specific attributes) and zeroing the pointer to hw_counters group for compat devices during the initialization.  With this fix applied hw_counters are not available in a non-init net namespace: find /sys/class/infiniband/mlx4_0/ -name hw_counters /sys/class/infiniband/mlx4_0/ports/1/hw_counters /sys/class/infiniband/mlx4_0/ports/2/hw_counters /sys/class/infiniband/mlx4_0/hw_counters  ip netns add foo ip netns exec foo bash find /sys/class/infiniband/mlx4_0/ -name hw_counters

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22086?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22086" src="https://img.shields.io/badge/CVE--2025--22086-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/mlx5: Fix mlx5_poll_one() cur_qp update flow  When cur_qp isn't NULL, in order to avoid fetching the QP from the radix tree again we check if the next cqe QP is identical to the one we already have.  The bug however is that we are checking if the QP is identical by checking the QP number inside the CQE against the QP number inside the mlx5_ib_qp, but that's wrong since the QP number from the CQE is from FW so it should be matched against mlx5_core_qp which is our FW QP number.  Otherwise we could use the wrong QP when handling a CQE which could cause the kernel trace below.  This issue is mainly noticeable over QPs 0 & 1, since for now they are the only QPs in our driver whereas the QP number inside mlx5_ib_qp doesn't match the QP number inside mlx5_core_qp.  BUG: kernel NULL pointer dereference, address: 0000000000000012 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD 0 P4D 0 Oops: Oops: 0000 [#1] SMP CPU: 0 UID: 0 PID: 7927 Comm: kworker/u62:1 Not tainted 6.14.0-rc3+ #189 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014 Workqueue: ib-comp-unb-wq ib_cq_poll_work [ib_core] RIP: 0010:mlx5_ib_poll_cq+0x4c7/0xd90 [mlx5_ib] Code: 03 00 00 8d 58 ff 21 cb 66 39 d3 74 39 48 c7 c7 3c 89 6e a0 0f b7 db e8 b7 d2 b3 e0 49 8b 86 60 03 00 00 48 c7 c7 4a 89 6e a0 <0f> b7 5c 98 02 e8 9f d2 b3 e0 41 0f b7 86 78 03 00 00 83 e8 01 21 RSP: 0018:ffff88810511bd60 EFLAGS: 00010046 RAX: 0000000000000010 RBX: 0000000000000000 RCX: 0000000000000000 RDX: 0000000000000000 RSI: ffff88885fa1b3c0 RDI: ffffffffa06e894a RBP: 00000000000000b0 R08: 0000000000000000 R09: ffff88810511bc10 R10: 0000000000000001 R11: 0000000000000001 R12: ffff88810d593000 R13: ffff88810e579108 R14: ffff888105146000 R15: 00000000000000b0 FS:  0000000000000000(0000) GS:ffff88885fa00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000000000012 CR3: 00000001077e6001 CR4: 0000000000370eb0 Call Trace: <TASK> ? __die+0x20/0x60 ? page_fault_oops+0x150/0x3e0 ? exc_page_fault+0x74/0x130 ? asm_exc_page_fault+0x22/0x30 ? mlx5_ib_poll_cq+0x4c7/0xd90 [mlx5_ib] __ib_process_cq+0x5a/0x150 [ib_core] ib_cq_poll_work+0x31/0x90 [ib_core] process_one_work+0x169/0x320 worker_thread+0x288/0x3a0 ? work_busy+0xb0/0xb0 kthread+0xd7/0x1f0 ? kthreads_online_cpu+0x130/0x130 ? kthreads_online_cpu+0x130/0x130 ret_from_fork+0x2d/0x50 ? kthreads_online_cpu+0x130/0x130 ret_from_fork_asm+0x11/0x20 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22079?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22079" src="https://img.shields.io/badge/CVE--2025--22079-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ocfs2: validate l_tree_depth to avoid out-of-bounds access  The l_tree_depth field is 16-bit (__le16), but the actual maximum depth is limited to OCFS2_MAX_PATH_DEPTH.  Add a check to prevent out-of-bounds access if l_tree_depth has an invalid value, which may occur when reading from a corrupted mounted disk [1].

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22075?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22075" src="https://img.shields.io/badge/CVE--2025--22075-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  rtnetlink: Allocate vfinfo size for VF GUIDs when supported  Commit 30aad41721e0 ("net/core: Add support for getting VF GUIDs") added support for getting VF port and node GUIDs in netlink ifinfo messages, but their size was not taken into consideration in the function that allocates the netlink message, causing the following warning when a netlink message is filled with many VF port and node GUIDs: # echo 64 > /sys/bus/pci/devices/0000\:08\:00.0/sriov_numvfs # ip link show dev ib0 RTNETLINK answers: Message too long Cannot send link get request: Message too long  Kernel warning:  ------------[ cut here ]------------ WARNING: CPU: 2 PID: 1930 at net/core/rtnetlink.c:4151 rtnl_getlink+0x586/0x5a0 Modules linked in: xt_conntrack xt_MASQUERADE nfnetlink xt_addrtype iptable_nat nf_nat br_netfilter overlay mlx5_ib macsec mlx5_core tls rpcrdma rdma_ucm ib_uverbs ib_iser libiscsi scsi_transport_iscsi ib_umad rdma_cm iw_cm ib_ipoib fuse ib_cm ib_core CPU: 2 UID: 0 PID: 1930 Comm: ip Not tainted 6.14.0-rc2+ #1 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 RIP: 0010:rtnl_getlink+0x586/0x5a0 Code: cb 82 e8 3d af 0a 00 4d 85 ff 0f 84 08 ff ff ff 4c 89 ff 41 be ea ff ff ff e8 66 63 5b ff 49 c7 07 80 4f cb 82 e9 36 fc ff ff <0f> 0b e9 16 fe ff ff e8 de a0 56 00 66 66 2e 0f 1f 84 00 00 00 00 RSP: 0018:ffff888113557348 EFLAGS: 00010246 RAX: 00000000ffffffa6 RBX: ffff88817e87aa34 RCX: dffffc0000000000 RDX: 0000000000000003 RSI: 0000000000000000 RDI: ffff88817e87afb8 RBP: 0000000000000009 R08: ffffffff821f44aa R09: 0000000000000000 R10: ffff8881260f79a8 R11: ffff88817e87af00 R12: ffff88817e87aa00 R13: ffffffff8563d300 R14: 00000000ffffffa6 R15: 00000000ffffffff FS:  00007f63a5dbf280(0000) GS:ffff88881ee00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f63a5ba4493 CR3: 00000001700fe002 CR4: 0000000000772eb0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> ? __warn+0xa5/0x230 ? rtnl_getlink+0x586/0x5a0 ? report_bug+0x22d/0x240 ? handle_bug+0x53/0xa0 ? exc_invalid_op+0x14/0x50 ? asm_exc_invalid_op+0x16/0x20 ? skb_trim+0x6a/0x80 ? rtnl_getlink+0x586/0x5a0 ? __pfx_rtnl_getlink+0x10/0x10 ? rtnetlink_rcv_msg+0x1e5/0x860 ? __pfx___mutex_lock+0x10/0x10 ? rcu_is_watching+0x34/0x60 ? __pfx_lock_acquire+0x10/0x10 ? stack_trace_save+0x90/0xd0 ? filter_irq_stacks+0x1d/0x70 ? kasan_save_stack+0x30/0x40 ? kasan_save_stack+0x20/0x40 ? kasan_save_track+0x10/0x30 rtnetlink_rcv_msg+0x21c/0x860 ? entry_SYSCALL_64_after_hwframe+0x76/0x7e ? __pfx_rtnetlink_rcv_msg+0x10/0x10 ? arch_stack_walk+0x9e/0xf0 ? rcu_is_watching+0x34/0x60 ? lock_acquire+0xd5/0x410 ? rcu_is_watching+0x34/0x60 netlink_rcv_skb+0xe0/0x210 ? __pfx_rtnetlink_rcv_msg+0x10/0x10 ? __pfx_netlink_rcv_skb+0x10/0x10 ? rcu_is_watching+0x34/0x60 ? __pfx___netlink_lookup+0x10/0x10 ? lock_release+0x62/0x200 ? netlink_deliver_tap+0xfd/0x290 ? rcu_is_watching+0x34/0x60 ? lock_release+0x62/0x200 ? netlink_deliver_tap+0x95/0x290 netlink_unicast+0x31f/0x480 ? __pfx_netlink_unicast+0x10/0x10 ? rcu_is_watching+0x34/0x60 ? lock_acquire+0xd5/0x410 netlink_sendmsg+0x369/0x660 ? lock_release+0x62/0x200 ? __pfx_netlink_sendmsg+0x10/0x10 ? import_ubuf+0xb9/0xf0 ? __import_iovec+0x254/0x2b0 ? lock_release+0x62/0x200 ? __pfx_netlink_sendmsg+0x10/0x10 ____sys_sendmsg+0x559/0x5a0 ? __pfx_____sys_sendmsg+0x10/0x10 ? __pfx_copy_msghdr_from_user+0x10/0x10 ? rcu_is_watching+0x34/0x60 ? do_read_fault+0x213/0x4a0 ? rcu_is_watching+0x34/0x60 ___sys_sendmsg+0xe4/0x150 ? __pfx____sys_sendmsg+0x10/0x10 ? do_fault+0x2cc/0x6f0 ? handle_pte_fault+0x2e3/0x3d0 ? __pfx_handle_pte_fault+0x10/0x10 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22073?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22073" src="https://img.shields.io/badge/CVE--2025--22073-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  spufs: fix a leak on spufs_new_file() failure  It's called from spufs_fill_dir(), and caller of that will do spufs_rmdir() in case of failure.  That does remove everything we'd managed to create, but... the problem dentry is still negative.  IOW, it needs to be explicitly dropped.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22071?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22071" src="https://img.shields.io/badge/CVE--2025--22071-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  spufs: fix a leak in spufs_create_context()  Leak fixes back in 2008 missed one case - if we are trying to set affinity and spufs_mkdir() fails, we need to drop the reference to neighbor.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22060?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22060" src="https://img.shields.io/badge/CVE--2025--22060-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: mvpp2: Prevent parser TCAM memory corruption  Protect the parser TCAM/SRAM memory, and the cached (shadow) SRAM information, from concurrent modifications.  Both the TCAM and SRAM tables are indirectly accessed by configuring an index register that selects the row to read or write to. This means that operations must be atomic in order to, e.g., avoid spreading writes across multiple rows. Since the shadow SRAM array is used to find free rows in the hardware table, it must also be protected in order to avoid TOCTOU errors where multiple cores allocate the same row.  This issue was detected in a situation where `mvpp2_set_rx_mode()` ran concurrently on two CPUs. In this particular case the MVPP2_PE_MAC_UC_PROMISCUOUS entry was corrupted, causing the classifier unit to drop all incoming unicast - indicated by the `rx_classifier_drops` counter.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22055?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22055" src="https://img.shields.io/badge/CVE--2025--22055-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fix geneve_opt length integer overflow  struct geneve_opt uses 5 bit length for each single option, which means every vary size option should be smaller than 128 bytes.  However, all current related Netlink policies cannot promise this length condition and the attacker can exploit a exact 128-byte size option to *fake* a zero length option and confuse the parsing logic, further achieve heap out-of-bounds read.  One example crash log is like below:  [    3.905425] ================================================================== [    3.905925] BUG: KASAN: slab-out-of-bounds in nla_put+0xa9/0xe0 [    3.906255] Read of size 124 at addr ffff888005f291cc by task poc/177 [    3.906646] [    3.906775] CPU: 0 PID: 177 Comm: poc-oob-read Not tainted 6.1.132 #1 [    3.907131] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 [    3.907784] Call Trace: [    3.907925]  <TASK> [    3.908048]  dump_stack_lvl+0x44/0x5c [    3.908258]  print_report+0x184/0x4be [    3.909151]  kasan_report+0xc5/0x100 [    3.909539]  kasan_check_range+0xf3/0x1a0 [    3.909794]  memcpy+0x1f/0x60 [    3.909968]  nla_put+0xa9/0xe0 [    3.910147]  tunnel_key_dump+0x945/0xba0 [    3.911536]  tcf_action_dump_1+0x1c1/0x340 [    3.912436]  tcf_action_dump+0x101/0x180 [    3.912689]  tcf_exts_dump+0x164/0x1e0 [    3.912905]  fw_dump+0x18b/0x2d0 [    3.913483]  tcf_fill_node+0x2ee/0x460 [    3.914778]  tfilter_notify+0xf4/0x180 [    3.915208]  tc_new_tfilter+0xd51/0x10d0 [    3.918615]  rtnetlink_rcv_msg+0x4a2/0x560 [    3.919118]  netlink_rcv_skb+0xcd/0x200 [    3.919787]  netlink_unicast+0x395/0x530 [    3.921032]  netlink_sendmsg+0x3d0/0x6d0 [    3.921987]  __sock_sendmsg+0x99/0xa0 [    3.922220]  __sys_sendto+0x1b7/0x240 [    3.922682]  __x64_sys_sendto+0x72/0x90 [    3.922906]  do_syscall_64+0x5e/0x90 [    3.923814]  entry_SYSCALL_64_after_hwframe+0x6e/0xd8 [    3.924122] RIP: 0033:0x7e83eab84407 [    3.924331] Code: 48 89 fa 4c 89 df e8 38 aa 00 00 8b 93 08 03 00 00 59 5e 48 83 f8 fc 74 1a 5b c3 0f 1f 84 00 00 00 00 00 48 8b 44 24 10 0f 05 <5b> c3 0f 1f 80 00 00 00 00 83 e2 39 83 faf [    3.925330] RSP: 002b:00007ffff505e370 EFLAGS: 00000202 ORIG_RAX: 000000000000002c [    3.925752] RAX: ffffffffffffffda RBX: 00007e83eaafa740 RCX: 00007e83eab84407 [    3.926173] RDX: 00000000000001a8 RSI: 00007ffff505e3c0 RDI: 0000000000000003 [    3.926587] RBP: 00007ffff505f460 R08: 00007e83eace1000 R09: 000000000000000c [    3.926977] R10: 0000000000000000 R11: 0000000000000202 R12: 00007ffff505f3c0 [    3.927367] R13: 00007ffff505f5c8 R14: 00007e83ead1b000 R15: 00005d4fbbe6dcb8  Fix these issues by enforing correct length condition in related policies.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22050?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22050" src="https://img.shields.io/badge/CVE--2025--22050-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usbnet:fix NPE during rx_complete  Missing usbnet_going_away Check in Critical Path. The usb_submit_urb function lacks a usbnet_going_away validation, whereas __usbnet_queue_skb includes this check.  This inconsistency creates a race condition where: A URB request may succeed, but the corresponding SKB data fails to be queued.  Subsequent processes: (e.g., rx_complete → defer_bh → __skb_unlink(skb, list)) attempt to access skb->next, triggering a NULL pointer dereference (Kernel Panic).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22045?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22045" src="https://img.shields.io/badge/CVE--2025--22045-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  x86/mm: Fix flush_tlb_range() when used for zapping normal PMDs  On the following path, flush_tlb_range() can be used for zapping normal PMD entries (PMD entries that point to page tables) together with the PTE entries in the pointed-to page table:  collapse_pte_mapped_thp pmdp_collapse_flush flush_tlb_range  The arm64 version of flush_tlb_range() has a comment describing that it can be used for page table removal, and does not use any last-level invalidation optimizations. Fix the X86 version by making it behave the same way.  Currently, X86 only uses this information for the following two purposes, which I think means the issue doesn't have much impact:  - In native_flush_tlb_multi() for checking if lazy TLB CPUs need to be IPI'd to avoid issues with speculative page table walks. - In Hyper-V TLB paravirtualization, again for lazy TLB stuff.  The patch "x86/mm: only invalidate final translations with INVLPGB" which is currently under review (see <https://lore.kernel.org/all/20241230175550.4046587-13-riel@surriel.com/>) would probably be making the impact of this a lot worse.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22044?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22044" src="https://img.shields.io/badge/CVE--2025--22044-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  acpi: nfit: fix narrowing conversion in acpi_nfit_ctl  Syzkaller has reported a warning in to_nfit_bus_uuid(): "only secondary bus families can be translated". This warning is emited if the argument is equal to NVDIMM_BUS_FAMILY_NFIT == 0. Function acpi_nfit_ctl() first verifies that a user-provided value call_pkg->nd_family of type u64 is not equal to 0. Then the value is converted to int, and only after that is compared to NVDIMM_BUS_FAMILY_MAX. This can lead to passing an invalid argument to acpi_nfit_ctl(), if call_pkg->nd_family is non-zero, while the lower 32 bits are zero.  Furthermore, it is best to return EINVAL immediately upon seeing the invalid user input.  The WARNING is insufficient to prevent further undefined behavior based on other invalid user input.  All checks of the input value should be applied to the original variable call_pkg->nd_family.  [iweiny: update commit message]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22035?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22035" src="https://img.shields.io/badge/CVE--2025--22035-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tracing: Fix use-after-free in print_graph_function_flags during tracer switching  Kairui reported a UAF issue in print_graph_function_flags() during ftrace stress testing [1]. This issue can be reproduced if puting a 'mdelay(10)' after 'mutex_unlock(&trace_types_lock)' in s_start(), and executing the following script:  $ echo function_graph > current_tracer $ cat trace > /dev/null & $ sleep 5  # Ensure the 'cat' reaches the 'mdelay(10)' point $ echo timerlat > current_tracer  The root cause lies in the two calls to print_graph_function_flags within print_trace_line during each s_show():  * One through 'iter->trace->print_line()'; * Another through 'event->funcs->trace()', which is hidden in print_trace_fmt() before print_trace_line returns.  Tracer switching only updates the former, while the latter continues to use the print_line function of the old tracer, which in the script above is print_graph_function_flags.  Moreover, when switching from the 'function_graph' tracer to the 'timerlat' tracer, s_start only calls graph_trace_close of the 'function_graph' tracer to free 'iter->private', but does not set it to NULL. This provides an opportunity for 'event->funcs->trace()' to use an invalid 'iter->private'.  To fix this issue, set 'iter->private' to NULL immediately after freeing it in graph_trace_close(), ensuring that an invalid pointer is not passed to other tracers. Additionally, clean up the unnecessary 'iter->private = NULL' during each 'cat trace' when using wakeup and irqsoff tracers.  [1] https://lore.kernel.org/all/20231112150030.84609-1-ryncsn@gmail.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22025?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22025" src="https://img.shields.io/badge/CVE--2025--22025-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfsd: put dl_stid if fail to queue dl_recall  Before calling nfsd4_run_cb to queue dl_recall to the callback_wq, we increment the reference count of dl_stid. We expect that after the corresponding work_struct is processed, the reference count of dl_stid will be decremented through the callback function nfsd4_cb_recall_release. However, if the call to nfsd4_run_cb fails, the incremented reference count of dl_stid will not be decremented correspondingly, leading to the following nfs4_stid leak: unreferenced object 0xffff88812067b578 (size 344): comm "nfsd", pid 2761, jiffies 4295044002 (age 5541.241s) hex dump (first 32 bytes): 01 00 00 00 6b 6b 6b 6b b8 02 c0 e2 81 88 ff ff  ....kkkk........ 00 6b 6b 6b 6b 6b 6b 6b 00 00 00 00 ad 4e ad de  .kkkkkkk.....N.. backtrace: kmem_cache_alloc+0x4b9/0x700 nfsd4_process_open1+0x34/0x300 nfsd4_open+0x2d1/0x9d0 nfsd4_proc_compound+0x7a2/0xe30 nfsd_dispatch+0x241/0x3e0 svc_process_common+0x5d3/0xcc0 svc_process+0x2a3/0x320 nfsd+0x180/0x2e0 kthread+0x199/0x1d0 ret_from_fork+0x30/0x50 ret_from_fork_asm+0x1b/0x30 unreferenced object 0xffff8881499f4d28 (size 368): comm "nfsd", pid 2761, jiffies 4295044005 (age 5541.239s) hex dump (first 32 bytes): 01 00 00 00 00 00 00 00 30 4d 9f 49 81 88 ff ff  ........0M.I.... 30 4d 9f 49 81 88 ff ff 20 00 00 00 01 00 00 00  0M.I.... ....... backtrace: kmem_cache_alloc+0x4b9/0x700 nfs4_alloc_stid+0x29/0x210 alloc_init_deleg+0x92/0x2e0 nfs4_set_delegation+0x284/0xc00 nfs4_open_delegation+0x216/0x3f0 nfsd4_process_open2+0x2b3/0xee0 nfsd4_open+0x770/0x9d0 nfsd4_proc_compound+0x7a2/0xe30 nfsd_dispatch+0x241/0x3e0 svc_process_common+0x5d3/0xcc0 svc_process+0x2a3/0x320 nfsd+0x180/0x2e0 kthread+0x199/0x1d0 ret_from_fork+0x30/0x50 ret_from_fork_asm+0x1b/0x30 Fix it by checking the result of nfsd4_run_cb and call nfs4_put_stid if fail to queue dl_recall.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22021?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22021" src="https://img.shields.io/badge/CVE--2025--22021-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: socket: Lookup orig tuple for IPv6 SNAT  nf_sk_lookup_slow_v4 does the conntrack lookup for IPv4 packets to restore the original 5-tuple in case of SNAT, to be able to find the right socket (if any). Then socket_match() can correctly check whether the socket was transparent.  However, the IPv6 counterpart (nf_sk_lookup_slow_v6) lacks this conntrack lookup, making xt_socket fail to match on the socket when the packet was SNATed. Add the same logic to nf_sk_lookup_slow_v6.  IPv6 SNAT is used in Kubernetes clusters for pod-to-world packets, as pods' addresses are in the fd00::/8 ULA subnet and need to be replaced with the node's external address. Cilium leverages Envoy to enforce L7 policies, and Envoy uses transparent sockets. Cilium inserts an iptables prerouting rule that matches on `-m socket --transparent` and redirects the packets to localhost, but it fails to match SNATed IPv6 packets due to that missing conntrack lookup.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22008?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22008" src="https://img.shields.io/badge/CVE--2025--22008-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  regulator: check that dummy regulator has been probed before using it  Due to asynchronous driver probing there is a chance that the dummy regulator hasn't already been probed when first accessing it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22004?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--22004" src="https://img.shields.io/badge/CVE--2025--22004-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: atm: fix use after free in lec_send()  The ->send() operation frees skb so save the length before calling ->send() to avoid a use after free.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21999?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--21999" src="https://img.shields.io/badge/CVE--2025--21999-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  proc: fix UAF in proc_get_inode()  Fix race between rmmod and /proc/XXX's inode instantiation.  The bug is that pde->proc_ops don't belong to /proc, it belongs to a module, therefore dereferencing it after /proc entry has been registered is a bug unless use_pde/unuse_pde() pair has been used.  use_pde/unuse_pde can be avoided (2 atomic ops!) because pde->proc_ops never changes so information necessary for inode instantiation can be saved _before_ proc_register() in PDE itself and used later, avoiding pde->proc_ops->...  dereference.  rmmod                         lookup sys_delete_module proc_lookup_de pde_get(de); proc_get_inode(dir->i_sb, de); mod->exit() proc_remove remove_proc_subtree proc_entry_rundown(de); free_module(mod);  if (S_ISREG(inode->i_mode)) if (de->proc_ops->proc_read_iter) --> As module is already freed, will trigger UAF  BUG: unable to handle page fault for address: fffffbfff80a702b PGD 817fc4067 P4D 817fc4067 PUD 817fc0067 PMD 102ef4067 PTE 0 Oops: Oops: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 26 UID: 0 PID: 2667 Comm: ls Tainted: G Hardware name: QEMU Standard PC (i440FX + PIIX, 1996) RIP: 0010:proc_get_inode+0x302/0x6e0 RSP: 0018:ffff88811c837998 EFLAGS: 00010a06 RAX: dffffc0000000000 RBX: ffffffffc0538140 RCX: 0000000000000007 RDX: 1ffffffff80a702b RSI: 0000000000000001 RDI: ffffffffc0538158 RBP: ffff8881299a6000 R08: 0000000067bbe1e5 R09: 1ffff11023906f20 R10: ffffffffb560ca07 R11: ffffffffb2b43a58 R12: ffff888105bb78f0 R13: ffff888100518048 R14: ffff8881299a6004 R15: 0000000000000001 FS:  00007f95b9686840(0000) GS:ffff8883af100000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: fffffbfff80a702b CR3: 0000000117dd2000 CR4: 00000000000006f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> proc_lookup_de+0x11f/0x2e0 __lookup_slow+0x188/0x350 walk_component+0x2ab/0x4f0 path_lookupat+0x120/0x660 filename_lookup+0x1ce/0x560 vfs_statx+0xac/0x150 __do_sys_newstat+0x96/0x110 do_syscall_64+0x5f/0x170 entry_SYSCALL_64_after_hwframe+0x76/0x7e  [adobriyan@gmail.com: don't do 2 atomic ops on the common path]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21994?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--21994" src="https://img.shields.io/badge/CVE--2025--21994-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: fix incorrect validation for num_aces field of smb_acl  parse_dcal() validate num_aces to allocate posix_ace_state_array.  if (num_aces > ULONG_MAX / sizeof(struct smb_ace *))  It is an incorrect validation that we can create an array of size ULONG_MAX. smb_acl has ->size field to calculate actual number of aces in request buffer size. Use this to check invalid num_aces.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21992?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--21992" src="https://img.shields.io/badge/CVE--2025--21992-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.065%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  HID: ignore non-functional sensor in HP 5MP Camera  The HP 5MP Camera (USB ID 0408:5473) reports a HID sensor interface that is not actually implemented. Attempting to access this non-functional sensor via iio_info causes system hangs as runtime PM tries to wake up an unresponsive sensor.  [453] hid-sensor-hub 0003:0408:5473.0003: Report latency attributes: ffffffff:ffffffff [453] hid-sensor-hub 0003:0408:5473.0003: common attributes: 5:1, 2:1, 3:1 ffffffff:ffffffff  Add this device to the HID ignore list since the sensor interface is non-functional by design and should not be exposed to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21975?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--21975" src="https://img.shields.io/badge/CVE--2025--21975-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: handle errors in mlx5_chains_create_table()  In mlx5_chains_create_table(), the return value of mlx5_get_fdb_sub_ns() and mlx5_get_flow_namespace() must be checked to prevent NULL pointer dereferences. If either function fails, the function should log error message with mlx5_core_warn() and return error pointer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21970?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--21970" src="https://img.shields.io/badge/CVE--2025--21970-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: Bridge, fix the crash caused by LAG state check  When removing LAG device from bridge, NETDEV_CHANGEUPPER event is triggered. Driver finds the lower devices (PFs) to flush all the offloaded entries. And mlx5_lag_is_shared_fdb is checked, it returns false if one of PF is unloaded. In such case, mlx5_esw_bridge_lag_rep_get() and its caller return NULL, instead of the alive PF, and the flush is skipped.  Besides, the bridge fdb entry's lastuse is updated in mlx5 bridge event handler. But this SWITCHDEV_FDB_ADD_TO_BRIDGE event can be ignored in this case because the upper interface for bond is deleted, and the entry will never be aged because lastuse is never updated.  To make things worse, as the entry is alive, mlx5 bridge workqueue keeps sending that event, which is then handled by kernel bridge notifier. It causes the following crash when accessing the passed bond netdev which is already destroyed.  To fix this issue, remove such checks. LAG state is already checked in commit 15f8f168952f ("net/mlx5: Bridge, verify LAG state when adding bond to bridge"), driver still need to skip offload if LAG becomes invalid state after initialization.  Oops: stack segment: 0000 [#1] SMP CPU: 3 UID: 0 PID: 23695 Comm: kworker/u40:3 Tainted: G           OE 6.11.0_mlnx #1 Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 Workqueue: mlx5_bridge_wq mlx5_esw_bridge_update_work [mlx5_core] RIP: 0010:br_switchdev_event+0x2c/0x110 [bridge] Code: 44 00 00 48 8b 02 48 f7 00 00 02 00 00 74 69 41 54 55 53 48 83 ec 08 48 8b a8 08 01 00 00 48 85 ed 74 4a 48 83 fe 02 48 89 d3 <4c> 8b 65 00 74 23 76 49 48 83 fe 05 74 7e 48 83 fe 06 75 2f 0f b7 RSP: 0018:ffffc900092cfda0 EFLAGS: 00010297 RAX: ffff888123bfe000 RBX: ffffc900092cfe08 RCX: 00000000ffffffff RDX: ffffc900092cfe08 RSI: 0000000000000001 RDI: ffffffffa0c585f0 RBP: 6669746f6e690a30 R08: 0000000000000000 R09: ffff888123ae92c8 R10: 0000000000000000 R11: fefefefefefefeff R12: ffff888123ae9c60 R13: 0000000000000001 R14: ffffc900092cfe08 R15: 0000000000000000 FS:  0000000000000000(0000) GS:ffff88852c980000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f15914c8734 CR3: 0000000002830005 CR4: 0000000000770ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> ? __die_body+0x1a/0x60 ? die+0x38/0x60 ? do_trap+0x10b/0x120 ? do_error_trap+0x64/0xa0 ? exc_stack_segment+0x33/0x50 ? asm_exc_stack_segment+0x22/0x30 ? br_switchdev_event+0x2c/0x110 [bridge] ? sched_balance_newidle.isra.149+0x248/0x390 notifier_call_chain+0x4b/0xa0 atomic_notifier_call_chain+0x16/0x20 mlx5_esw_bridge_update+0xec/0x170 [mlx5_core] mlx5_esw_bridge_update_work+0x19/0x40 [mlx5_core] process_scheduled_works+0x81/0x390 worker_thread+0x106/0x250 ? bh_worker+0x110/0x110 kthread+0xb7/0xe0 ? kthread_park+0x80/0x80 ret_from_fork+0x2d/0x50 ? kthread_park+0x80/0x80 ret_from_fork_asm+0x11/0x20 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21956?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--21956" src="https://img.shields.io/badge/CVE--2025--21956-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Assign normalized_pix_clk when color depth = 14  [WHY & HOW] A warning message "WARNING: CPU: 4 PID: 459 at ... /dc_resource.c:3397 calculate_phy_pix_clks+0xef/0x100 [amdgpu]" occurs because the display_color_depth == COLOR_DEPTH_141414 is not handled. This is observed in Radeon RX 6600 XT.  It is fixed by assigning pix_clk * (14 * 3) / 24 - same as the rests.  Also fixes the indentation in get_norm_pix_clk.  (cherry picked from commit 274a87eb389f58eddcbc5659ab0b180b37e92775)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53144?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2024--53144" src="https://img.shields.io/badge/CVE--2024--53144-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: hci_event: Align BR/EDR JUST_WORKS paring with LE  This aligned BR/EDR JUST_WORKS method with LE which since 92516cd97fd4 ("Bluetooth: Always request for user confirmation for Just Works") always request user confirmation with confirm_hint set since the likes of bluetoothd have dedicated policy around JUST_WORKS method (e.g. main.conf:JustWorksRepairing).  CVE: CVE-2024-8805

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46753?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2024--46753" src="https://img.shields.io/badge/CVE--2024--46753-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.165%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>38th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: handle errors from btrfs_dec_ref() properly  In walk_up_proc() we BUG_ON(ret) from btrfs_dec_ref().  This is incorrect, we have proper error handling here, return the error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36945?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2024--36945" src="https://img.shields.io/badge/CVE--2024--36945-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.140%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>35th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: net/smc: fix neighbour and rtable leak in smc_ib_find_route() In smc_ib_find_route(), the neighbour found by neigh_lookup() and rtable resolved by ip_route_output_flow() are not released or put before return. It may cause the refcount leak, so fix it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-53034?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2023--53034" src="https://img.shields.io/badge/CVE--2023--53034-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ntb_hw_switchtec: Fix shift-out-of-bounds in switchtec_ntb_mw_set_trans  There is a kernel API ntb_mw_clear_trans() would pass 0 to both addr and size. This would make xlate_pos negative.  [   23.734156] switchtec switchtec0: MW 0: part 0 addr 0x0000000000000000 size 0x0000000000000000 [   23.734158] ================================================================================ [   23.734172] UBSAN: shift-out-of-bounds in drivers/ntb/hw/mscc/ntb_hw_switchtec.c:293:7 [   23.734418] shift exponent -1 is negative  Ensuring xlate_pos is a positive or zero before BIT.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58093?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="low : CVE--2024--58093" src="https://img.shields.io/badge/CVE--2024--58093-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  PCI/ASPM: Fix link state exit during switch upstream function removal  Before 456d8aa37d0f ("PCI/ASPM: Disable ASPM on MFD function removal to avoid use-after-free"), we would free the ASPM link only after the last function on the bus pertaining to the given link was removed.  That was too late. If function 0 is removed before sibling function, link->downstream would point to free'd memory after.  After above change, we freed the ASPM parent link state upon any function removal on the bus pertaining to a given link.  That is too early. If the link is to a PCIe switch with MFD on the upstream port, then removing functions other than 0 first would free a link which still remains parent_link to the remaining downstream ports.  The resulting GPFs are especially frequent during hot-unplug, because pciehp removes devices on the link bus in reverse order.  On that switch, function 0 is the virtual P2P bridge to the internal bus. Free exactly when function 0 is removed -- before the parent link is obsolete, but after all subordinate links are gone.  [kwilczynski: commit log]

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
</table>