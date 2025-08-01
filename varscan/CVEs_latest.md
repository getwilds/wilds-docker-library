# Vulnerability Report for getwilds/varscan:latest

Report generated on 2025-08-01 09:34:42 PST

<h2>:mag: Vulnerabilities of <code>getwilds/varscan:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/varscan:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:d81e80829d154f8dea5da0ba3d8677db4d691c8e1c3efea3bba40cadda9f6392</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/high-1-e25d68"/> <img alt="medium: 233" src="https://img.shields.io/badge/medium-233-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/low-2-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>446 MB</td></tr>
<tr><td>packages</td><td>467</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 1" src="https://img.shields.io/badge/H-1-e25d68"/> <img alt="medium: 215" src="https://img.shields.io/badge/M-215-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>linux</strong> <code>5.15.0-141.151</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@5.15.0-141.151?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-50047?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="high 7.8: CVE--2024--50047" src="https://img.shields.io/badge/CVE--2024--50047-lightgrey?label=high%207.8&labelColor=e25d68"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix UAF in async decryption  Doing an async decryption (large read) crashes with a slab-use-after-free way down in the crypto API.  Reproducer: # mount.cifs -o ...,seal,esize=1 //srv/share /mnt # dd if=/mnt/largefile of=/dev/null ... [  194.196391] ================================================================== [  194.196844] BUG: KASAN: slab-use-after-free in gf128mul_4k_lle+0xc1/0x110 [  194.197269] Read of size 8 at addr ffff888112bd0448 by task kworker/u77:2/899 [  194.197707] [  194.197818] CPU: 12 UID: 0 PID: 899 Comm: kworker/u77:2 Not tainted 6.11.0-lku-00028-gfca3ca14a17a-dirty #43 [  194.198400] Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.16.2-3-gd478f380-prebuilt.qemu.org 04/01/2014 [  194.199046] Workqueue: smb3decryptd smb2_decrypt_offload [cifs] [  194.200032] Call Trace: [  194.200191]  <TASK> [  194.200327]  dump_stack_lvl+0x4e/0x70 [  194.200558]  ? gf128mul_4k_lle+0xc1/0x110 [  194.200809]  print_report+0x174/0x505 [  194.201040]  ? __pfx__raw_spin_lock_irqsave+0x10/0x10 [  194.201352]  ? srso_return_thunk+0x5/0x5f [  194.201604]  ? __virt_addr_valid+0xdf/0x1c0 [  194.201868]  ? gf128mul_4k_lle+0xc1/0x110 [  194.202128]  kasan_report+0xc8/0x150 [  194.202361]  ? gf128mul_4k_lle+0xc1/0x110 [  194.202616]  gf128mul_4k_lle+0xc1/0x110 [  194.202863]  ghash_update+0x184/0x210 [  194.203103]  shash_ahash_update+0x184/0x2a0 [  194.203377]  ? __pfx_shash_ahash_update+0x10/0x10 [  194.203651]  ? srso_return_thunk+0x5/0x5f [  194.203877]  ? crypto_gcm_init_common+0x1ba/0x340 [  194.204142]  gcm_hash_assoc_remain_continue+0x10a/0x140 [  194.204434]  crypt_message+0xec1/0x10a0 [cifs] [  194.206489]  ? __pfx_crypt_message+0x10/0x10 [cifs] [  194.208507]  ? srso_return_thunk+0x5/0x5f [  194.209205]  ? srso_return_thunk+0x5/0x5f [  194.209925]  ? srso_return_thunk+0x5/0x5f [  194.210443]  ? srso_return_thunk+0x5/0x5f [  194.211037]  decrypt_raw_data+0x15f/0x250 [cifs] [  194.212906]  ? __pfx_decrypt_raw_data+0x10/0x10 [cifs] [  194.214670]  ? srso_return_thunk+0x5/0x5f [  194.215193]  smb2_decrypt_offload+0x12a/0x6c0 [cifs]  This is because TFM is being used in parallel.  Fix this by allocating a new AEAD TFM for async decryption, but keep the existing one for synchronous READ cases (similar to what is done in smb3_calc_signature()).  Also remove the calls to aead_request_set_callback() and crypto_wait_req() since it's always going to be a synchronous operation.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-8805?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 8.8: CVE--2024--8805" src="https://img.shields.io/badge/CVE--2024--8805-lightgrey?label=medium%208.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.414%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>61st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

BlueZ HID over GATT Profile Improper Access Control Remote Code Execution Vulnerability. This vulnerability allows network-adjacent attackers to execute arbitrary code on affected installations of BlueZ. Authentication is not required to exploit this vulnerability.  The specific flaw exists within the implementation of the HID over GATT Profile. The issue results from the lack of authorization prior to allowing access to functionality. An attacker can leverage this vulnerability to execute code in the context of the current user. Was ZDI-CAN-25177.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37803?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2025--37803" src="https://img.shields.io/badge/CVE--2025--37803-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  udmabuf: fix a buf size overflow issue during udmabuf creation  by casting size_limit_mb to u64  when calculate pglimit.

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

<a href="https://scout.docker.com/v/CVE-2024-53203?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2024--53203" src="https://img.shields.io/badge/CVE--2024--53203-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.037%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: typec: fix potential array underflow in ucsi_ccg_sync_control()  The "command" variable can be controlled by the user via debugfs.  The worry is that if con_index is zero then "&uc->ucsi->connector[con_index - 1]" would be an array underflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50125?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2024--50125" src="https://img.shields.io/badge/CVE--2024--50125-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: SCO: Fix UAF on sco_sock_timeout  conn->sk maybe have been unlinked/freed while waiting for sco_conn_lock so this checks if the conn->sk is still valid by checking if it part of sco_sk_list.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50073?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-151.161"><img alt="medium 7.8: CVE--2024--50073" src="https://img.shields.io/badge/CVE--2024--50073-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-151.161</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-151.161</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tty: n_gsm: Fix use-after-free in gsm_cleanup_mux  BUG: KASAN: slab-use-after-free in gsm_cleanup_mux+0x77b/0x7b0 drivers/tty/n_gsm.c:3160 [n_gsm] Read of size 8 at addr ffff88815fe99c00 by task poc/3379 CPU: 0 UID: 0 PID: 3379 Comm: poc Not tainted 6.11.0+ #56 Hardware name: VMware, Inc. VMware Virtual Platform/440BX Desktop Reference Platform, BIOS 6.00 11/12/2020 Call Trace: <TASK> gsm_cleanup_mux+0x77b/0x7b0 drivers/tty/n_gsm.c:3160 [n_gsm] __pfx_gsm_cleanup_mux+0x10/0x10 drivers/tty/n_gsm.c:3124 [n_gsm] __pfx_sched_clock_cpu+0x10/0x10 kernel/sched/clock.c:389 update_load_avg+0x1c1/0x27b0 kernel/sched/fair.c:4500 __pfx_min_vruntime_cb_rotate+0x10/0x10 kernel/sched/fair.c:846 __rb_insert_augmented+0x492/0xbf0 lib/rbtree.c:161 gsmld_ioctl+0x395/0x1450 drivers/tty/n_gsm.c:3408 [n_gsm] _raw_spin_lock_irqsave+0x92/0xf0 arch/x86/include/asm/atomic.h:107 __pfx_gsmld_ioctl+0x10/0x10 drivers/tty/n_gsm.c:3822 [n_gsm] ktime_get+0x5e/0x140 kernel/time/timekeeping.c:195 ldsem_down_read+0x94/0x4e0 arch/x86/include/asm/atomic64_64.h:79 __pfx_ldsem_down_read+0x10/0x10 drivers/tty/tty_ldsem.c:338 __pfx_do_vfs_ioctl+0x10/0x10 fs/ioctl.c:805 tty_ioctl+0x643/0x1100 drivers/tty/tty_io.c:2818  Allocated by task 65: gsm_data_alloc.constprop.0+0x27/0x190 drivers/tty/n_gsm.c:926 [n_gsm] gsm_send+0x2c/0x580 drivers/tty/n_gsm.c:819 [n_gsm] gsm1_receive+0x547/0xad0 drivers/tty/n_gsm.c:3038 [n_gsm] gsmld_receive_buf+0x176/0x280 drivers/tty/n_gsm.c:3609 [n_gsm] tty_ldisc_receive_buf+0x101/0x1e0 drivers/tty/tty_buffer.c:391 tty_port_default_receive_buf+0x61/0xa0 drivers/tty/tty_port.c:39 flush_to_ldisc+0x1b0/0x750 drivers/tty/tty_buffer.c:445 process_scheduled_works+0x2b0/0x10d0 kernel/workqueue.c:3229 worker_thread+0x3dc/0x950 kernel/workqueue.c:3391 kthread+0x2a3/0x370 kernel/kthread.c:389 ret_from_fork+0x2d/0x70 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:257  Freed by task 3367: kfree+0x126/0x420 mm/slub.c:4580 gsm_cleanup_mux+0x36c/0x7b0 drivers/tty/n_gsm.c:3160 [n_gsm] gsmld_ioctl+0x395/0x1450 drivers/tty/n_gsm.c:3408 [n_gsm] tty_ioctl+0x643/0x1100 drivers/tty/tty_io.c:2818  [Analysis] gsm_msg on the tx_ctrl_list or tx_data_list of gsm_mux can be freed by multi threads through ioctl,which leads to the occurrence of uaf. Protect it by gsm tx lock.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49989?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2024--49989" src="https://img.shields.io/badge/CVE--2024--49989-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: fix double free issue during amdgpu module unload  Flexible endpoints use DIGs from available inflexible endpoints, so only the encoders of inflexible links need to be freed. Otherwise, a double free issue may occur when unloading the amdgpu module.  [  279.190523] RIP: 0010:__slab_free+0x152/0x2f0 [  279.190577] Call Trace: [  279.190580]  <TASK> [  279.190582]  ? show_regs+0x69/0x80 [  279.190590]  ? die+0x3b/0x90 [  279.190595]  ? do_trap+0xc8/0xe0 [  279.190601]  ? do_error_trap+0x73/0xa0 [  279.190605]  ? __slab_free+0x152/0x2f0 [  279.190609]  ? exc_invalid_op+0x56/0x70 [  279.190616]  ? __slab_free+0x152/0x2f0 [  279.190642]  ? asm_exc_invalid_op+0x1f/0x30 [  279.190648]  ? dcn10_link_encoder_destroy+0x19/0x30 [amdgpu] [  279.191096]  ? __slab_free+0x152/0x2f0 [  279.191102]  ? dcn10_link_encoder_destroy+0x19/0x30 [amdgpu] [  279.191469]  kfree+0x260/0x2b0 [  279.191474]  dcn10_link_encoder_destroy+0x19/0x30 [amdgpu] [  279.191821]  link_destroy+0xd7/0x130 [amdgpu] [  279.192248]  dc_destruct+0x90/0x270 [amdgpu] [  279.192666]  dc_destroy+0x19/0x40 [amdgpu] [  279.193020]  amdgpu_dm_fini+0x16e/0x200 [amdgpu] [  279.193432]  dm_hw_fini+0x26/0x40 [amdgpu] [  279.193795]  amdgpu_device_fini_hw+0x24c/0x400 [amdgpu] [  279.194108]  amdgpu_driver_unload_kms+0x4f/0x70 [amdgpu] [  279.194436]  amdgpu_pci_remove+0x40/0x80 [amdgpu] [  279.194632]  pci_device_remove+0x3a/0xa0 [  279.194638]  device_remove+0x40/0x70 [  279.194642]  device_release_driver_internal+0x1ad/0x210 [  279.194647]  driver_detach+0x4e/0xa0 [  279.194650]  bus_remove_driver+0x6f/0xf0 [  279.194653]  driver_unregister+0x33/0x60 [  279.194657]  pci_unregister_driver+0x44/0x90 [  279.194662]  amdgpu_exit+0x19/0x1f0 [amdgpu] [  279.194939]  __do_sys_delete_module.isra.0+0x198/0x2f0 [  279.194946]  __x64_sys_delete_module+0x16/0x20 [  279.194950]  do_syscall_64+0x58/0x120 [  279.194954]  entry_SYSCALL_64_after_hwframe+0x6e/0x76 [  279.194980]  </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49960?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2024--49960" src="https://img.shields.io/badge/CVE--2024--49960-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ext4: fix timer use-after-free on failed mount  Syzbot has found an ODEBUG bug in ext4_fill_super  The del_timer_sync function cancels the s_err_report timer, which reminds about filesystem errors daily. We should guarantee the timer is no longer active before kfree(sbi).  When filesystem mounting fails, the flow goes to failed_mount3, where an error occurs when ext4_stop_mmpd is called, causing a read I/O failure. This triggers the ext4_handle_error function that ultimately re-arms the timer, leaving the s_err_report timer active before kfree(sbi) is called.  Fix the issue by canceling the s_err_report timer after calling ext4_stop_mmpd.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46821?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.8: CVE--2024--46821" src="https://img.shields.io/badge/CVE--2024--46821-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.055%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Skip inactive planes within ModeSupportAndSystemConfiguration  [Why] Coverity reports Memory - illegal accesses.  [How] Skip inactive planes.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35867?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2024--35867" src="https://img.shields.io/badge/CVE--2024--35867-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.009%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: smb: client: fix potential UAF in cifs_stats_proc_show() Skip sessions that are being teared down (status == SES_EXITING) to avoid UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35866?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2024--35866" src="https://img.shields.io/badge/CVE--2024--35866-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: smb: client: fix potential UAF in cifs_dump_full_key() Skip sessions that are being teared down (status == SES_EXITING) to avoid UAF.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26739?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2024--26739" src="https://img.shields.io/badge/CVE--2024--26739-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.010%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mirred: don't override retval if we already lost the skb If we're redirecting the skb, and haven't called tcf_mirred_forward(), yet, we need to tell the core to drop the skb by setting the retcode to SHOT. If we have called tcf_mirred_forward(), however, the skb is out of our hands and returning SHOT will lead to UaF. Move the retval override to the error path which actually need it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52757?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2023--52757" src="https://img.shields.io/badge/CVE--2023--52757-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.008%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: smb: client: fix potential deadlock when releasing mids All release_mid() callers seem to hold a reference of @mid so there is no need to call kref_put(&mid->refcount, __release_mid) under @server->mid_lock spinlock. If they don't, then an use-after-free bug would have occurred anyways. By getting rid of such spinlock also fixes a potential deadlock as shown below CPU 0 CPU 1 ------------------------------------------------------------------ cifs_demultiplex_thread() cifs_debug_data_proc_show() release_mid() spin_lock(&server->mid_lock); spin_lock(&cifs_tcp_ses_lock) spin_lock(&server->mid_lock) __release_mid() smb2_find_smb_tcon() spin_lock(&cifs_tcp_ses_lock) *deadlock*

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2023-52572?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.8: CVE--2023--52572" src="https://img.shields.io/badge/CVE--2023--52572-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: cifs: Fix UAF in cifs_demultiplex_thread() There is a UAF when xfstests on cifs: BUG: KASAN: use-after-free in smb2_is_network_name_deleted+0x27/0x160 Read of size 4 at addr ffff88810103fc08 by task cifsd/923 CPU: 1 PID: 923 Comm: cifsd Not tainted 6.1.0-rc4+ #45 ... Call Trace: <TASK> dump_stack_lvl+0x34/0x44 print_report+0x171/0x472 kasan_report+0xad/0x130 kasan_check_range+0x145/0x1a0 smb2_is_network_name_deleted+0x27/0x160 cifs_demultiplex_thread.cold+0x172/0x5a4 kthread+0x165/0x1a0 ret_from_fork+0x1f/0x30 </TASK> Allocated by task 923: kasan_save_stack+0x1e/0x40 kasan_set_track+0x21/0x30 __kasan_slab_alloc+0x54/0x60 kmem_cache_alloc+0x147/0x320 mempool_alloc+0xe1/0x260 cifs_small_buf_get+0x24/0x60 allocate_buffers+0xa1/0x1c0 cifs_demultiplex_thread+0x199/0x10d0 kthread+0x165/0x1a0 ret_from_fork+0x1f/0x30 Freed by task 921: kasan_save_stack+0x1e/0x40 kasan_set_track+0x21/0x30 kasan_save_free_info+0x2a/0x40 ____kasan_slab_free+0x143/0x1b0 kmem_cache_free+0xe3/0x4d0 cifs_small_buf_release+0x29/0x90 SMB2_negotiate+0x8b7/0x1c60 smb2_negotiate+0x51/0x70 cifs_negotiate_protocol+0xf0/0x160 cifs_get_smb_ses+0x5fa/0x13c0 mount_get_conns+0x7a/0x750 cifs_mount+0x103/0xd00 cifs_smb3_do_mount+0x1dd/0xcb0 smb3_get_tree+0x1d5/0x300 vfs_get_tree+0x41/0xf0 path_mount+0x9b3/0xdd0 __x64_sys_mount+0x190/0x1d0 do_syscall_64+0x35/0x80 entry_SYSCALL_64_after_hwframe+0x46/0xb0 The UAF is because: mount(pid: 921) | cifsd(pid: 923) -------------------------------|------------------------------- | cifs_demultiplex_thread SMB2_negotiate | cifs_send_recv | compound_send_recv | smb_send_rqst | wait_for_response | wait_event_state [1] | | standard_receive3 | cifs_handle_standard | handle_mid | mid->resp_buf = buf; [2] | dequeue_mid [3] KILL the process [4] | resp_iov[i].iov_base = buf | free_rsp_buf [5] | | is_network_name_deleted [6] | callback 1. After send request to server, wait the response until mid->mid_state != SUBMITTED; 2. Receive response from server, and set it to mid; 3. Set the mid state to RECEIVED; 4. Kill the process, the mid state already RECEIVED, get 0; 5. Handle and release the negotiate response; 6. UAF. It can be easily reproduce with add some delay in [3] - [6]. Only sync call has the problem since async call's callback is executed in cifsd process. Add an extra state to mark the mid state to READY before wakeup the waitter, then it can get the resp safely.

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

<a href="https://scout.docker.com/v/CVE-2024-46774?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 7.1: CVE--2024--46774" src="https://img.shields.io/badge/CVE--2024--46774-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.137%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>34th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  powerpc/rtas: Prevent Spectre v1 gadget construction in sys_rtas()  Smatch warns:  arch/powerpc/kernel/rtas.c:1932 __do_sys_rtas() warn: potential spectre issue 'args.args' [r] (local cap)  The 'nargs' and 'nret' locals come directly from a user-supplied buffer and are used as indexes into a small stack-based array and as inputs to copy_to_user() after they are subject to bounds checks.  Use array_index_nospec() after the bounds checks to clamp these values for speculative execution.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56664?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 7.0: CVE--2024--56664" src="https://img.shields.io/badge/CVE--2024--56664-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
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

<a href="https://scout.docker.com/v/CVE-2025-37805?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2025--37805" src="https://img.shields.io/badge/CVE--2025--37805-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sound/virtio: Fix cancel_sync warnings on uninitialized work_structs  Betty reported hitting the following warning:  [    8.709131][  T221] WARNING: CPU: 2 PID: 221 at kernel/workqueue.c:4182 ... [    8.713282][  T221] Call trace: [    8.713365][  T221]  __flush_work+0x8d0/0x914 [    8.713468][  T221]  __cancel_work_sync+0xac/0xfc [    8.713570][  T221]  cancel_work_sync+0x24/0x34 [    8.713667][  T221]  virtsnd_remove+0xa8/0xf8 [virtio_snd ab15f34d0dd772f6d11327e08a81d46dc9c36276] [    8.713868][  T221]  virtsnd_probe+0x48c/0x664 [virtio_snd ab15f34d0dd772f6d11327e08a81d46dc9c36276] [    8.714035][  T221]  virtio_dev_probe+0x28c/0x390 [    8.714139][  T221]  really_probe+0x1bc/0x4c8 ...  It seems we're hitting the error path in virtsnd_probe(), which triggers a virtsnd_remove() which iterates over the substreams calling cancel_work_sync() on the elapsed_period work_struct.  Looking at the code, from earlier in: virtsnd_probe()->virtsnd_build_devs()->virtsnd_pcm_parse_cfg()  We set snd->nsubstreams, allocate the snd->substreams, and if we then hit an error on the info allocation or something in virtsnd_ctl_query_info() fails, we will exit without having initialized the elapsed_period work_struct.  When that error path unwinds we then call virtsnd_remove() which as long as the substreams array is allocated, will iterate through calling cancel_work_sync() on the uninitialized work struct hitting this warning.  Takashi Iwai suggested this fix, which initializes the substreams structure right after allocation, so that if we hit the error paths we avoid trying to cleanup uninitialized data.  Note: I have not yet managed to reproduce the issue myself, so this patch has had limited testing.  Feedback or thoughts would be appreciated!

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

<a href="https://scout.docker.com/v/CVE-2025-22062?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2025--22062" src="https://img.shields.io/badge/CVE--2025--22062-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: add mutual exclusion in proc_sctp_do_udp_port()  We must serialize calls to sctp_udp_sock_stop() and sctp_udp_sock_start() or risk a crash as syzbot reported:  Oops: general protection fault, probably for non-canonical address 0xdffffc000000000d: 0000 [#1] SMP KASAN PTI KASAN: null-ptr-deref in range [0x0000000000000068-0x000000000000006f] CPU: 1 UID: 0 PID: 6551 Comm: syz.1.44 Not tainted 6.14.0-syzkaller-g7f2ff7b62617 #0 PREEMPT(full) Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/12/2025 RIP: 0010:kernel_sock_shutdown+0x47/0x70 net/socket.c:3653 Call Trace: <TASK> udp_tunnel_sock_release+0x68/0x80 net/ipv4/udp_tunnel_core.c:181 sctp_udp_sock_stop+0x71/0x160 net/sctp/protocol.c:930 proc_sctp_do_udp_port+0x264/0x450 net/sctp/sysctl.c:553 proc_sys_call_handler+0x3d0/0x5b0 fs/proc/proc_sysctl.c:601 iter_file_splice_write+0x91c/0x1150 fs/splice.c:738 do_splice_from fs/splice.c:935 [inline] direct_splice_actor+0x18f/0x6c0 fs/splice.c:1158 splice_direct_to_actor+0x342/0xa30 fs/splice.c:1102 do_splice_direct_actor fs/splice.c:1201 [inline] do_splice_direct+0x174/0x240 fs/splice.c:1227 do_sendfile+0xafd/0xe50 fs/read_write.c:1368 __do_sys_sendfile64 fs/read_write.c:1429 [inline] __se_sys_sendfile64 fs/read_write.c:1415 [inline] __x64_sys_sendfile64+0x1d8/0x220 fs/read_write.c:1415 do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]

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

<a href="https://scout.docker.com/v/CVE-2025-21853?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2025--21853" src="https://img.shields.io/badge/CVE--2025--21853-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: avoid holding freeze_mutex during mmap operation  We use map->freeze_mutex to prevent races between map_freeze() and memory mapping BPF map contents with writable permissions. The way we naively do this means we'll hold freeze_mutex for entire duration of all the mm and VMA manipulations, which is completely unnecessary. This can potentially also lead to deadlocks, as reported by syzbot in [0].  So, instead, hold freeze_mutex only during writeability checks, bump (proactively) "write active" count for the map, unlock the mutex and proceed with mmap logic. And only if something went wrong during mmap logic, then undo that "write active" counter increment.  [0] https://lore.kernel.org/bpf/678dcbc9.050a0220.303755.0066.GAE@google.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56751?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2024--56751" src="https://img.shields.io/badge/CVE--2024--56751-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipv6: release nexthop on device removal  The CI is hitting some aperiodic hangup at device removal time in the pmtu.sh self-test:  unregister_netdevice: waiting for veth_A-R1 to become free. Usage count = 6 ref_tracker: veth_A-R1@ffff888013df15d8 has 1/5 users at dst_init+0x84/0x4a0 dst_alloc+0x97/0x150 ip6_dst_alloc+0x23/0x90 ip6_rt_pcpu_alloc+0x1e6/0x520 ip6_pol_route+0x56f/0x840 fib6_rule_lookup+0x334/0x630 ip6_route_output_flags+0x259/0x480 ip6_dst_lookup_tail.constprop.0+0x5c2/0x940 ip6_dst_lookup_flow+0x88/0x190 udp_tunnel6_dst_lookup+0x2a7/0x4c0 vxlan_xmit_one+0xbde/0x4a50 [vxlan] vxlan_xmit+0x9ad/0xf20 [vxlan] dev_hard_start_xmit+0x10e/0x360 __dev_queue_xmit+0xf95/0x18c0 arp_solicit+0x4a2/0xe00 neigh_probe+0xaa/0xf0  While the first suspect is the dst_cache, explicitly tracking the dst owing the last device reference via probes proved such dst is held by the nexthop in the originating fib6_info.  Similar to commit f5b51fe804ec ("ipv6: route: purge exception on removal"), we need to explicitly release the originating fib info when disconnecting a to-be-removed device from a live ipv6 dst: move the fib6_info cleanup into ip6_dst_ifdown().  Tested running:  ./pmtu.sh cleanup_ipv6_exception  in a tight loop for more than 400 iterations with no spat, running an unpatched kernel  I observed a splat every ~10 iterations.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53051?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium 5.5: CVE--2024--53051" src="https://img.shields.io/badge/CVE--2024--53051-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/i915/hdcp: Add encoder check in intel_hdcp_get_capability  Sometimes during hotplug scenario or suspend/resume scenario encoder is not always initialized when intel_hdcp_get_capability add a check to avoid kernel null pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50272?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2024--50272" src="https://img.shields.io/badge/CVE--2024--50272-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  filemap: Fix bounds checking in filemap_read()  If the caller supplies an iocb->ki_pos value that is close to the filesystem upper limit, and an iterator with a count that causes us to overflow that limit, then filemap_read() enters an infinite loop.  This behaviour was discovered when testing xfstests generic/525 with the "localio" optimisation for loopback NFS mounts.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50258?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2024--50258" src="https://img.shields.io/badge/CVE--2024--50258-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fix crash when config small gso_max_size/gso_ipv4_max_size  Config a small gso_max_size/gso_ipv4_max_size will lead to an underflow in sk_dst_gso_max_size(), which may trigger a BUG_ON crash, because sk->sk_gso_max_size would be much bigger than device limits. Call Trace: tcp_write_xmit tso_segs = tcp_init_tso_segs(skb, mss_now); tcp_set_skb_tso_segs tcp_skb_pcount_set // skb->len = 524288, mss_now = 8 // u16 tso_segs = 524288/8 = 65535 -> 0 tso_segs = DIV_ROUND_UP(skb->len, mss_now) BUG_ON(!tso_segs) Add check for the minimum value of gso_max_size and gso_ipv4_max_size.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46816?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2024--46816" src="https://img.shields.io/badge/CVE--2024--46816-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.093%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/display: Stop amdgpu_dm initialize when link nums greater than max_links  [Why] Coverity report OVERRUN warning. There are only max_links elements within dc->links. link count could up to AMDGPU_DM_MAX_DISPLAY_INDEX 31.  [How] Make sure link count less than max_links.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46751?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2024--46751" src="https://img.shields.io/badge/CVE--2024--46751-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.093%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: don't BUG_ON() when 0 reference count at btrfs_lookup_extent_info()  Instead of doing a BUG_ON() handle the error by returning -EUCLEAN, aborting the transaction and logging an error message.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46742?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2024--46742" src="https://img.shields.io/badge/CVE--2024--46742-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.068%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb/server: fix potential null-ptr-deref of lease_ctx_info in smb2_open()  null-ptr-deref will occur when (req_op_level == SMB2_OPLOCK_LEVEL_LEASE) and parse_lease_state() return NULL.  Fix this by check if 'lease_ctx_info' is NULL.  Additionally, remove the redundant parentheses in parse_durable_handle_context().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35790?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2024--35790" src="https://img.shields.io/badge/CVE--2024--35790-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: usb: typec: altmodes/displayport: create sysfs nodes as driver's default device attribute group The DisplayPort driver's sysfs nodes may be present to the userspace before typec_altmode_set_drvdata() completes in dp_altmode_probe. This means that a sysfs read can trigger a NULL pointer error by deferencing dp->hpd in hpd_show or dp->lock in pin_assignment_show, as dev_get_drvdata() returns NULL in those cases. Remove manual sysfs node creation in favor of adding attribute group as default for devices bound to the driver. The ATTRIBUTE_GROUPS() macro is not used here otherwise the path to the sysfs nodes is no longer compliant with the ABI.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-26686?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2024--26686" src="https://img.shields.io/badge/CVE--2024--26686-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.010%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: fs/proc: do_task_stat: use sig->stats_lock to gather the threads/children stats lock_task_sighand() can trigger a hard lockup. If NR_CPUS threads call do_task_stat() at the same time and the process has NR_THREADS, it will spin with irqs disabled O(NR_CPUS * NR_THREADS) time. Change do_task_stat() to use sig->stats_lock to gather the statistics outside of ->siglock protected section, in the likely case this code will run lockless.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-49728?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium 5.5: CVE--2022--49728" src="https://img.shields.io/badge/CVE--2022--49728-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
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
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vlan: fix memory leak in vlan_newlink()  Blamed commit added back a bug I fixed in commit 9bbd917e0bec ("vlan: fix memory leak in vlan_dev_set_egress_priority")  If a memory allocation fails in vlan_changelink() after other allocations succeeded, we need to call vlan_dev_free_egress_priority() to free all allocated memory because after a failed ->newlink() we do not call any methods like ndo_uninit() or dev->priv_destructor().  In following example, if the allocation for last element 2000:2001 fails, we need to free eight prior allocations:  ip link add link dummy0 dummy0.100 type vlan id 100 \ egress-qos-map 1:2 2:3 3:4 4:5 5:6 6:7 7:8 8:9 2000:2001  syzbot report was:  BUG: memory leak unreferenced object 0xffff888117bd1060 (size 32): comm "syz-executor408", pid 3759, jiffies 4294956555 (age 34.090s) hex dump (first 32 bytes): 09 00 00 00 00 a0 00 00 00 00 00 00 00 00 00 00 ................ 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ................ backtrace: [<ffffffff83fc60ad>] kmalloc include/linux/slab.h:600 [inline] [<ffffffff83fc60ad>] vlan_dev_set_egress_priority+0xed/0x170 net/8021q/vlan_dev.c:193 [<ffffffff83fc6628>] vlan_changelink+0x178/0x1d0 net/8021q/vlan_netlink.c:128 [<ffffffff83fc67c8>] vlan_newlink+0x148/0x260 net/8021q/vlan_netlink.c:185 [<ffffffff838b1278>] rtnl_newlink_create net/core/rtnetlink.c:3363 [inline] [<ffffffff838b1278>] __rtnl_newlink+0xa58/0xdc0 net/core/rtnetlink.c:3580 [<ffffffff838b1629>] rtnl_newlink+0x49/0x70 net/core/rtnetlink.c:3593 [<ffffffff838ac66c>] rtnetlink_rcv_msg+0x21c/0x5c0 net/core/rtnetlink.c:6089 [<ffffffff839f9c37>] netlink_rcv_skb+0x87/0x1d0 net/netlink/af_netlink.c:2501 [<ffffffff839f8da7>] netlink_unicast_kernel net/netlink/af_netlink.c:1319 [inline] [<ffffffff839f8da7>] netlink_unicast+0x397/0x4c0 net/netlink/af_netlink.c:1345 [<ffffffff839f9266>] netlink_sendmsg+0x396/0x710 net/netlink/af_netlink.c:1921 [<ffffffff8384dbf6>] sock_sendmsg_nosec net/socket.c:714 [inline] [<ffffffff8384dbf6>] sock_sendmsg+0x56/0x80 net/socket.c:734 [<ffffffff8384e15c>] ____sys_sendmsg+0x36c/0x390 net/socket.c:2488 [<ffffffff838523cb>] ___sys_sendmsg+0x8b/0xd0 net/socket.c:2542 [<ffffffff838525b8>] __sys_sendmsg net/socket.c:2571 [inline] [<ffffffff838525b8>] __do_sys_sendmsg net/socket.c:2580 [inline] [<ffffffff838525b8>] __se_sys_sendmsg net/socket.c:2578 [inline] [<ffffffff838525b8>] __x64_sys_sendmsg+0x78/0xf0 net/socket.c:2578 [<ffffffff845ad8d5>] do_syscall_x64 arch/x86/entry/common.c:50 [inline] [<ffffffff845ad8d5>] do_syscall_64+0x35/0xb0 arch/x86/entry/common.c:80 [<ffffffff8460006a>] entry_SYSCALL_64_after_hwframe+0x46/0xb0

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-48893?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 5.5: CVE--2022--48893" src="https://img.shields.io/badge/CVE--2022--48893-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.066%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/i915/gt: Cleanup partial engine discovery failures  If we abort driver initialisation in the middle of gt/engine discovery, some engines will be fully setup and some not. Those incompletely setup engines only have 'engine->release == NULL' and so will leak any of the common objects allocated.  v2: - Drop the destroy_pinned_context() helper for now.  It's not really worth it with just a single callsite at the moment.  (Janusz)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-22027?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium 4.7: CVE--2025--22027" src="https://img.shields.io/badge/CVE--2025--22027-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: streamzap: fix race between device disconnection and urb callback  Syzkaller has reported a general protection fault at function ir_raw_event_store_with_filter(). This crash is caused by a NULL pointer dereference of dev->raw pointer, even though it is checked for NULL in the same function, which means there is a race condition. It occurs due to the incorrect order of actions in the streamzap_disconnect() function: rc_unregister_device() is called before usb_kill_urb(). The dev->raw pointer is freed and set to NULL in rc_unregister_device(), and only after that usb_kill_urb() waits for in-progress requests to finish.  If rc_unregister_device() is called while streamzap_callback() handler is not finished, this can lead to accessing freed resources. Thus rc_unregister_device() should be called after usb_kill_urb().  Found by Linux Verification Center (linuxtesting.org) with Syzkaller.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46787?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium 4.7: CVE--2024--46787" src="https://img.shields.io/badge/CVE--2024--46787-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  userfaultfd: fix checks for huge PMDs  Patch series "userfaultfd: fix races around pmd_trans_huge() check", v2.  The pmd_trans_huge() code in mfill_atomic() is wrong in three different ways depending on kernel version:  1. The pmd_trans_huge() check is racy and can lead to a BUG_ON() (if you hit the right two race windows) - I've tested this in a kernel build with some extra mdelay() calls. See the commit message for a description of the race scenario. On older kernels (before 6.5), I think the same bug can even theoretically lead to accessing transhuge page contents as a page table if you hit the right 5 narrow race windows (I haven't tested this case). 2. As pointed out by Qi Zheng, pmd_trans_huge() is not sufficient for detecting PMDs that don't point to page tables. On older kernels (before 6.5), you'd just have to win a single fairly wide race to hit this. I've tested this on 6.1 stable by racing migration (with a mdelay() patched into try_to_migrate()) against UFFDIO_ZEROPAGE - on my x86 VM, that causes a kernel oops in ptlock_ptr(). 3. On newer kernels (>=6.5), for shmem mappings, khugepaged is allowed to yank page tables out from under us (though I haven't tested that), so I think the BUG_ON() checks in mfill_atomic() are just wrong.  I decided to write two separate fixes for these (one fix for bugs 1+2, one fix for bug 3), so that the first fix can be backported to kernels affected by bugs 1+2.   This patch (of 2):  This fixes two issues.  I discovered that the following race can occur:  mfill_atomic                other thread ============                ============ <zap PMD> pmdp_get_lockless() [reads none pmd] <bail if trans_huge> <if none:> <pagefault creates transhuge zeropage> __pte_alloc [no-op] <zap PMD> <bail if pmd_trans_huge(*dst_pmd)> BUG_ON(pmd_none(*dst_pmd))  I have experimentally verified this in a kernel with extra mdelay() calls; the BUG_ON(pmd_none(*dst_pmd)) triggers.  On kernels newer than commit 0d940a9b270b ("mm/pgtable: allow pte_offset_map[_lock]() to fail"), this can't lead to anything worse than a BUG_ON(), since the page table access helpers are actually designed to deal with page tables concurrently disappearing; but on older kernels (<=6.4), I think we could probably theoretically race past the two BUG_ON() checks and end up treating a hugepage as a page table.  The second issue is that, as Qi Zheng pointed out, there are other types of huge PMDs that pmd_trans_huge() can't catch: devmap PMDs and swap PMDs (in particular, migration PMDs).  On <=6.4, this is worse than the first issue: If mfill_atomic() runs on a PMD that contains a migration entry (which just requires winning a single, fairly wide race), it will pass the PMD to pte_offset_map_lock(), which assumes that the PMD points to a page table.  Breakage follows: First, the kernel tries to take the PTE lock (which will crash or maybe worse if there is no "struct page" for the address bits in the migration entry PMD - I think at least on X86 there usually is no corresponding "struct page" thanks to the PTE inversion mitigation, amd64 looks different).  If that didn't crash, the kernel would next try to write a PTE into what it wrongly thinks is a page table.  As part of fixing these issues, get rid of the check for pmd_trans_huge() before __pte_alloc() - that's redundant, we're going to have to check for that after the __pte_alloc() anyway.  Backport note: pmdp_get_lockless() is pmd_read_atomic() in older kernels.

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

<a href="https://scout.docker.com/v/CVE-2025-38177?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium : CVE--2025--38177" src="https://img.shields.io/badge/CVE--2025--38177-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sch_hfsc: make hfsc_qlen_notify() idempotent  hfsc_qlen_notify() is not idempotent either and not friendly to its callers, like fq_codel_dequeue(). Let's make it idempotent to ease qdisc_tree_reduce_backlog() callers' life:  1. update_vf() decreases cl->cl_nactive, so we can check whether it is non-zero before calling it.  2. eltree_remove() always removes RB node cl->el_node, but we can use RB_EMPTY_NODE() + RB_CLEAR_NODE() to make it safe.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38094?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--38094" src="https://img.shields.io/badge/CVE--2025--38094-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: cadence: macb: Fix a possible deadlock in macb_halt_tx.  There is a situation where after THALT is set high, TGO stays high as well. Because jiffies are never updated, as we are in a context with interrupts disabled, we never exit that loop and have a deadlock.  That deadlock was noticed on a sama5d4 device that stayed locked for days.  Use retries instead of jiffies so that the timeout really works and we do not have a deadlock anymore.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38083?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-151.161"><img alt="medium : CVE--2025--38083" src="https://img.shields.io/badge/CVE--2025--38083-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-151.161</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-151.161</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: prio: fix a race in prio_tune()  Gerrard Tai reported a race condition in PRIO, whenever SFQ perturb timer fires at the wrong time.  The race is as follows:  CPU 0                                 CPU 1 [1]: lock root [2]: qdisc_tree_flush_backlog() [3]: unlock root | |                                    [5]: lock root |                                    [6]: rehash |                                    [7]: qdisc_tree_reduce_backlog() | [4]: qdisc_put()  This can be abused to underflow a parent's qlen.  Calling qdisc_purge_queue() instead of qdisc_tree_flush_backlog() should fix the race, because all packets will be purged from the qdisc before releasing the lock.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38024?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--38024" src="https://img.shields.io/badge/CVE--2025--38024-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/rxe: Fix slab-use-after-free Read in rxe_queue_cleanup bug  Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x7d/0xa0 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0xcf/0x610 mm/kasan/report.c:489 kasan_report+0xb5/0xe0 mm/kasan/report.c:602 rxe_queue_cleanup+0xd0/0xe0 drivers/infiniband/sw/rxe/rxe_queue.c:195 rxe_cq_cleanup+0x3f/0x50 drivers/infiniband/sw/rxe/rxe_cq.c:132 __rxe_cleanup+0x168/0x300 drivers/infiniband/sw/rxe/rxe_pool.c:232 rxe_create_cq+0x22e/0x3a0 drivers/infiniband/sw/rxe/rxe_verbs.c:1109 create_cq+0x658/0xb90 drivers/infiniband/core/uverbs_cmd.c:1052 ib_uverbs_create_cq+0xc7/0x120 drivers/infiniband/core/uverbs_cmd.c:1095 ib_uverbs_write+0x969/0xc90 drivers/infiniband/core/uverbs_main.c:679 vfs_write fs/read_write.c:677 [inline] vfs_write+0x26a/0xcc0 fs/read_write.c:659 ksys_write+0x1b8/0x200 fs/read_write.c:731 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xaa/0x1b0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f  In the function rxe_create_cq, when rxe_cq_from_init fails, the function rxe_cleanup will be called to handle the allocated resources. In fact, some memory resources have already been freed in the function rxe_cq_from_init. Thus, this problem will occur.  The solution is to let rxe_cleanup do all the work.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38023?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--38023" src="https://img.shields.io/badge/CVE--2025--38023-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfs: handle failure of nfs_get_lock_context in unlock path  When memory is insufficient, the allocation of nfs_lock_context in nfs_get_lock_context() fails and returns -ENOMEM. If we mistakenly treat an nfs4_unlockdata structure (whose l_ctx member has been set to -ENOMEM) as valid and proceed to execute rpc_run_task(), this will trigger a NULL pointer dereference in nfs4_locku_prepare. For example:  BUG: kernel NULL pointer dereference, address: 000000000000000c PGD 0 P4D 0 Oops: Oops: 0000 [#1] SMP PTI CPU: 15 UID: 0 PID: 12 Comm: kworker/u64:0 Not tainted 6.15.0-rc2-dirty #60 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.3-2.fc40 Workqueue: rpciod rpc_async_schedule RIP: 0010:nfs4_locku_prepare+0x35/0xc2 Code: 89 f2 48 89 fd 48 c7 c7 68 69 ef b5 53 48 8b 8e 90 00 00 00 48 89 f3 RSP: 0018:ffffbbafc006bdb8 EFLAGS: 00010246 RAX: 000000000000004b RBX: ffff9b964fc1fa00 RCX: 0000000000000000 RDX: 0000000000000000 RSI: fffffffffffffff4 RDI: ffff9ba53fddbf40 RBP: ffff9ba539934000 R08: 0000000000000000 R09: ffffbbafc006bc38 R10: ffffffffb6b689c8 R11: 0000000000000003 R12: ffff9ba539934030 R13: 0000000000000001 R14: 0000000004248060 R15: ffffffffb56d1c30 FS: 0000000000000000(0000) GS:ffff9ba5881f0000(0000) knlGS:00000000 CS: 0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000000000000000c CR3: 000000093f244000 CR4: 00000000000006f0 Call Trace: <TASK> __rpc_execute+0xbc/0x480 rpc_async_schedule+0x2f/0x40 process_one_work+0x232/0x5d0 worker_thread+0x1da/0x3d0 ? __pfx_worker_thread+0x10/0x10 kthread+0x10d/0x240 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x34/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1a/0x30 </TASK> Modules linked in: CR2: 000000000000000c ---[ end trace 0000000000000000 ]---  Free the allocated nfs4_unlockdata when nfs_get_lock_context() fails and return NULL to terminate subsequent rpc_run_task, preventing NULL pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38009?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--38009" src="https://img.shields.io/badge/CVE--2025--38009-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: mt76: disable napi on driver removal  A warning on driver removal started occurring after commit 9dd05df8403b ("net: warn if NAPI instance wasn't shut down"). Disable tx napi before deleting it in mt76_dma_cleanup().  WARNING: CPU: 4 PID: 18828 at net/core/dev.c:7288 __netif_napi_del_locked+0xf0/0x100 CPU: 4 UID: 0 PID: 18828 Comm: modprobe Not tainted 6.15.0-rc4 #4 PREEMPT(lazy) Hardware name: ASUS System Product Name/PRIME X670E-PRO WIFI, BIOS 3035 09/05/2024 RIP: 0010:__netif_napi_del_locked+0xf0/0x100 Call Trace: <TASK> mt76_dma_cleanup+0x54/0x2f0 [mt76] mt7921_pci_remove+0xd5/0x190 [mt7921e] pci_device_remove+0x47/0xc0 device_release_driver_internal+0x19e/0x200 driver_detach+0x48/0x90 bus_remove_driver+0x6d/0xf0 pci_unregister_driver+0x2e/0xb0 __do_sys_delete_module.isra.0+0x197/0x2e0 do_syscall_64+0x7b/0x160 entry_SYSCALL_64_after_hwframe+0x76/0x7e  Tested with mt7921e but the same pattern can be actually applied to other mt76 drivers calling mt76_dma_cleanup() during removal. Tx napi is enabled in their *_dma_init() functions and only toggled off and on again inside their suspend/resume/reset paths. So it should be okay to disable tx napi in such a generic way.  Found by Linux Verification Center (linuxtesting.org).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38005?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--38005" src="https://img.shields.io/badge/CVE--2025--38005-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dmaengine: ti: k3-udma: Add missing locking  Recent kernels complain about a missing lock in k3-udma.c when the lock validator is enabled:  [    4.128073] WARNING: CPU: 0 PID: 746 at drivers/dma/ti/../virt-dma.h:169 udma_start.isra.0+0x34/0x238 [    4.137352] CPU: 0 UID: 0 PID: 746 Comm: kworker/0:3 Not tainted 6.12.9-arm64 #28 [    4.144867] Hardware name: pp-v12 (DT) [    4.148648] Workqueue: events udma_check_tx_completion [    4.153841] pstate: 60000005 (nZCv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) [    4.160834] pc : udma_start.isra.0+0x34/0x238 [    4.165227] lr : udma_start.isra.0+0x30/0x238 [    4.169618] sp : ffffffc083cabcf0 [    4.172963] x29: ffffffc083cabcf0 x28: 0000000000000000 x27: ffffff800001b005 [    4.180167] x26: ffffffc0812f0000 x25: 0000000000000000 x24: 0000000000000000 [    4.187370] x23: 0000000000000001 x22: 00000000e21eabe9 x21: ffffff8000fa0670 [    4.194571] x20: ffffff8001b6bf00 x19: ffffff8000fa0430 x18: ffffffc083b95030 [    4.201773] x17: 0000000000000000 x16: 00000000f0000000 x15: 0000000000000048 [    4.208976] x14: 0000000000000048 x13: 0000000000000000 x12: 0000000000000001 [    4.216179] x11: ffffffc08151a240 x10: 0000000000003ea1 x9 : ffffffc08046ab68 [    4.223381] x8 : ffffffc083cabac0 x7 : ffffffc081df3718 x6 : 0000000000029fc8 [    4.230583] x5 : ffffffc0817ee6d8 x4 : 0000000000000bc0 x3 : 0000000000000000 [    4.237784] x2 : 0000000000000000 x1 : 00000000001fffff x0 : 0000000000000000 [    4.244986] Call trace: [    4.247463]  udma_start.isra.0+0x34/0x238 [    4.251509]  udma_check_tx_completion+0xd0/0xdc [    4.256076]  process_one_work+0x244/0x3fc [    4.260129]  process_scheduled_works+0x6c/0x74 [    4.264610]  worker_thread+0x150/0x1dc [    4.268398]  kthread+0xd8/0xe8 [    4.271492]  ret_from_fork+0x10/0x20 [    4.275107] irq event stamp: 220 [    4.278363] hardirqs last  enabled at (219): [<ffffffc080a27c7c>] _raw_spin_unlock_irq+0x38/0x50 [    4.287183] hardirqs last disabled at (220): [<ffffffc080a1c154>] el1_dbg+0x24/0x50 [    4.294879] softirqs last  enabled at (182): [<ffffffc080037e68>] handle_softirqs+0x1c0/0x3cc [    4.303437] softirqs last disabled at (177): [<ffffffc080010170>] __do_softirq+0x1c/0x28 [    4.311559] ---[ end trace 0000000000000000 ]---  This commit adds the missing locking.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38001?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium : CVE--2025--38001" src="https://img.shields.io/badge/CVE--2025--38001-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: hfsc: Address reentrant enqueue adding class to eltree twice  Savino says: "We are writing to report that this recent patch (141d34391abbb315d68556b7c67ad97885407547) [1] can be bypassed, and a UAF can still occur when HFSC is utilized with NETEM.  The patch only checks the cl->cl_nactive field to determine whether it is the first insertion or not [2], but this field is only incremented by init_vf [3].  By using HFSC_RSC (which uses init_ed) [4], it is possible to bypass the check and insert the class twice in the eltree. Under normal conditions, this would lead to an infinite loop in hfsc_dequeue for the reasons we already explained in this report [5].  However, if TBF is added as root qdisc and it is configured with a very low rate, it can be utilized to prevent packets from being dequeued. This behavior can be exploited to perform subsequent insertions in the HFSC eltree and cause a UAF."  To fix both the UAF and the infinite loop, with netem as an hfsc child, check explicitly in hfsc_enqueue whether the class is already in the eltree whenever the HFSC_RSC flag is set.  [1] https://web.git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=141d34391abbb315d68556b7c67ad97885407547 [2] https://elixir.bootlin.com/linux/v6.15-rc5/source/net/sched/sch_hfsc.c#L1572 [3] https://elixir.bootlin.com/linux/v6.15-rc5/source/net/sched/sch_hfsc.c#L677 [4] https://elixir.bootlin.com/linux/v6.15-rc5/source/net/sched/sch_hfsc.c#L1574 [5] https://lore.kernel.org/netdev/8DuRWwfqjoRDLDmBMlIfbrsZg9Gx50DHJc1ilxsEBNe2D6NMoigR_eIRIG0LOjMc3r10nUUZtArXx4oZBIdUfZQrwjcQhdinnMis_0G7VEk=@willsroot.io/T/#u

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-38000?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium : CVE--2025--38000" src="https://img.shields.io/badge/CVE--2025--38000-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sch_hfsc: Fix qlen accounting bug when using peek in hfsc_enqueue()  When enqueuing the first packet to an HFSC class, hfsc_enqueue() calls the child qdisc's peek() operation before incrementing sch->q.qlen and sch->qstats.backlog. If the child qdisc uses qdisc_peek_dequeued(), this may trigger an immediate dequeue and potential packet drop. In such cases, qdisc_tree_reduce_backlog() is called, but the HFSC qdisc's qlen and backlog have not yet been updated, leading to inconsistent queue accounting. This can leave an empty HFSC class in the active list, causing further consequences like use-after-free.  This patch fixes the bug by moving the increment of sch->q.qlen and sch->qstats.backlog before the call to the child qdisc's peek() operation. This ensures that queue length and backlog are always accurate when packet drops or dequeues are triggered during the peek.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37998?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37998" src="https://img.shields.io/badge/CVE--2025--37998-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  openvswitch: Fix unsafe attribute parsing in output_userspace()  This patch replaces the manual Netlink attribute iteration in output_userspace() with nla_for_each_nested(), which ensures that only well-formed attributes are processed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37997?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium : CVE--2025--37997" src="https://img.shields.io/badge/CVE--2025--37997-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: ipset: fix region locking in hash types  Region locking introduced in v5.6-rc4 contained three macros to handle the region locks: ahash_bucket_start(), ahash_bucket_end() which gave back the start and end hash bucket values belonging to a given region lock and ahash_region() which should give back the region lock belonging to a given hash bucket. The latter was incorrect which can lead to a race condition between the garbage collector and adding new elements when a hash type of set is defined with timeouts.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37995?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37995" src="https://img.shields.io/badge/CVE--2025--37995-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  module: ensure that kobject_put() is safe for module type kobjects  In 'lookup_or_create_module_kobject()', an internal kobject is created using 'module_ktype'. So call to 'kobject_put()' on error handling path causes an attempt to use an uninitialized completion pointer in 'module_kobject_release()'. In this scenario, we just want to release kobject without an extra synchronization required for a regular module unloading process, so adding an extra check whether 'complete()' is actually required makes 'kobject_put()' safe.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37994?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37994" src="https://img.shields.io/badge/CVE--2025--37994-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: typec: ucsi: displayport: Fix NULL pointer access  This patch ensures that the UCSI driver waits for all pending tasks in the ucsi_displayport_work workqueue to finish executing before proceeding with the partner removal.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37992?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37992" src="https://img.shields.io/badge/CVE--2025--37992-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: Flush gso_skb list too during ->change()  Previously, when reducing a qdisc's limit via the ->change() operation, only the main skb queue was trimmed, potentially leaving packets in the gso_skb list. This could result in NULL pointer dereference when we only check sch->limit against sch->q.qlen.  This patch introduces a new helper, qdisc_dequeue_internal(), which ensures both the gso_skb list and the main queue are properly flushed when trimming excess packets. All relevant qdiscs (codel, fq, fq_codel, fq_pie, hhf, pie) are updated to use this helper in their ->change() routines.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37991?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37991" src="https://img.shields.io/badge/CVE--2025--37991-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  parisc: Fix double SIGFPE crash  Camm noticed that on parisc a SIGFPE exception will crash an application with a second SIGFPE in the signal handler.  Dave analyzed it, and it happens because glibc uses a double-word floating-point store to atomically update function descriptors. As a result of lazy binding, we hit a floating-point store in fpe_func almost immediately.  When the T bit is set, an assist exception trap occurs when when the co-processor encounters *any* floating-point instruction except for a double store of register %fr0.  The latter cancels all pending traps.  Let's fix this by clearing the Trap (T) bit in the FP status register before returning to the signal handler in userspace.  The issue can be reproduced with this test program:  root@parisc:~# cat fpe.c  static void fpe_func(int sig, siginfo_t *i, void *v) { sigset_t set; sigemptyset(&set); sigaddset(&set, SIGFPE); sigprocmask(SIG_UNBLOCK, &set, NULL); printf("GOT signal %d with si_code %ld\n", sig, i->si_code); }  int main() { struct sigaction action = { .sa_sigaction = fpe_func, .sa_flags = SA_RESTART|SA_SIGINFO }; sigaction(SIGFPE, &action, 0); feenableexcept(FE_OVERFLOW); return printf("%lf\n",1.7976931348623158E308*1.7976931348623158E308); }  root@parisc:~# gcc fpe.c -lm root@parisc:~# ./a.out Floating point exception  root@parisc:~# strace -f ./a.out execve("./a.out", ["./a.out"], 0xf9ac7034 /* 20 vars */) = 0 getrlimit(RLIMIT_STACK, {rlim_cur=8192*1024, rlim_max=RLIM_INFINITY}) = 0 ... rt_sigaction(SIGFPE, {sa_handler=0x1110a, sa_mask=[], sa_flags=SA_RESTART|SA_SIGINFO}, NULL, 8) = 0 --- SIGFPE {si_signo=SIGFPE, si_code=FPE_FLTOVF, si_addr=0x1078f} --- --- SIGFPE {si_signo=SIGFPE, si_code=FPE_FLTOVF, si_addr=0xf8f21237} --- +++ killed by SIGFPE +++ Floating point exception

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37990?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37990" src="https://img.shields.io/badge/CVE--2025--37990-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: brcm80211: fmac: Add error handling for brcmf_usb_dl_writeimage()  The function brcmf_usb_dl_writeimage() calls the function brcmf_usb_dl_cmd() but dose not check its return value. The 'state.state' and the 'state.bytes' are uninitialized if the function brcmf_usb_dl_cmd() fails. It is dangerous to use uninitialized variables in the conditions.  Add error handling for brcmf_usb_dl_cmd() to jump to error handling path if the brcmf_usb_dl_cmd() fails and the 'state.state' and the 'state.bytes' are uninitialized.  Improve the error message to report more detailed error information.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37989?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37989" src="https://img.shields.io/badge/CVE--2025--37989-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: phy: leds: fix memory leak  A network restart test on a router led to an out-of-memory condition, which was traced to a memory leak in the PHY LED trigger code.  The root cause is misuse of the devm API. The registration function (phy_led_triggers_register) is called from phy_attach_direct, not phy_probe, and the unregister function (phy_led_triggers_unregister) is called from phy_detach, not phy_remove. This means the register and unregister functions can be called multiple times for the same PHY device, but devm-allocated memory is not freed until the driver is unbound.  This also prevents kmemleak from detecting the leak, as the devm API internally stores the allocated pointer.  Fix this by replacing devm_kzalloc/devm_kcalloc with standard kzalloc/kcalloc, and add the corresponding kfree calls in the unregister path.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37985?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37985" src="https://img.shields.io/badge/CVE--2025--37985-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  USB: wdm: close race between wdm_open and wdm_wwan_port_stop  Clearing WDM_WWAN_IN_USE must be the last action or we can open a chardev whose URBs are still poisoned

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37983?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37983" src="https://img.shields.io/badge/CVE--2025--37983-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  qibfs: fix _another_ leak  failure to allocate inode => leaked dentry...  this one had been there since the initial merge; to be fair, if we are that far OOM, the odds of failing at that particular allocation are low...

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37982?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37982" src="https://img.shields.io/badge/CVE--2025--37982-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: wl1251: fix memory leak in wl1251_tx_work  The skb dequeued from tx_queue is lost when wl1251_ps_elp_wakeup fails with a -ETIMEDOUT error. Fix that by queueing the skb back to tx_queue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37970?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37970" src="https://img.shields.io/badge/CVE--2025--37970-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: imu: st_lsm6dsx: fix possible lockup in st_lsm6dsx_read_fifo  Prevent st_lsm6dsx_read_fifo from falling in an infinite loop in case pattern_len is equal to zero and the device FIFO is not empty.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37969?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37969" src="https://img.shields.io/badge/CVE--2025--37969-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: imu: st_lsm6dsx: fix possible lockup in st_lsm6dsx_read_tagged_fifo  Prevent st_lsm6dsx_read_tagged_fifo from falling in an infinite loop in case pattern_len is equal to zero and the device FIFO is not empty.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37967?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37967" src="https://img.shields.io/badge/CVE--2025--37967-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: typec: ucsi: displayport: Fix deadlock  This patch introduces the ucsi_con_mutex_lock / ucsi_con_mutex_unlock functions to the UCSI driver. ucsi_con_mutex_lock ensures the connector mutex is only locked if a connection is established and the partner pointer is valid. This resolves a deadlock scenario where ucsi_displayport_remove_partner holds con->mutex waiting for dp_altmode_work to complete while dp_altmode_work attempts to acquire it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37964?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37964" src="https://img.shields.io/badge/CVE--2025--37964-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  x86/mm: Eliminate window where TLB flushes may be inadvertently skipped  tl;dr: There is a window in the mm switching code where the new CR3 is set and the CPU should be getting TLB flushes for the new mm.  But should_flush_tlb() has a bug and suppresses the flush.  Fix it by widening the window where should_flush_tlb() sends an IPI.  Long Version:  === History ===  There were a few things leading up to this.  First, updating mm_cpumask() was observed to be too expensive, so it was made lazier.  But being lazy caused too many unnecessary IPIs to CPUs due to the now-lazy mm_cpumask().  So code was added to cull mm_cpumask() periodically[2].  But that culling was a bit too aggressive and skipped sending TLB flushes to CPUs that need them.  So here we are again.  === Problem ===  The too-aggressive code in should_flush_tlb() strikes in this window:  // Turn on IPIs for this CPU/mm combination, but only // if should_flush_tlb() agrees: cpumask_set_cpu(cpu, mm_cpumask(next));  next_tlb_gen = atomic64_read(&next->context.tlb_gen); choose_new_asid(next, next_tlb_gen, &new_asid, &need_flush); load_new_mm_cr3(need_flush); // ^ After 'need_flush' is set to false, IPIs *MUST* // be sent to this CPU and not be ignored.  this_cpu_write(cpu_tlbstate.loaded_mm, next); // ^ Not until this point does should_flush_tlb() // become true!  should_flush_tlb() will suppress TLB flushes between load_new_mm_cr3() and writing to 'loaded_mm', which is a window where they should not be suppressed.  Whoops.  === Solution ===  Thankfully, the fuzzy "just about to write CR3" window is already marked with loaded_mm==LOADED_MM_SWITCHING.  Simply checking for that state in should_flush_tlb() is sufficient to ensure that the CPU is targeted with an IPI.  This will cause more TLB flush IPIs.  But the window is relatively small and I do not expect this to cause any kind of measurable performance impact.  Update the comment where LOADED_MM_SWITCHING is written since it grew yet another user.  Peter Z also raised a concern that should_flush_tlb() might not observe 'loaded_mm' and 'is_lazy' in the same order that switch_mm_irqs_off() writes them.  Add a barrier to ensure that they are observed in the order they are written.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37949?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37949" src="https://img.shields.io/badge/CVE--2025--37949-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  xenbus: Use kref to track req lifetime  Marek reported seeing a NULL pointer fault in the xenbus_thread callstack: BUG: kernel NULL pointer dereference, address: 0000000000000000 RIP: e030:__wake_up_common+0x4c/0x180 Call Trace: <TASK> __wake_up_common_lock+0x82/0xd0 process_msg+0x18e/0x2f0 xenbus_thread+0x165/0x1c0  process_msg+0x18e is req->cb(req).  req->cb is set to xs_wake_up(), a thin wrapper around wake_up(), or xenbus_dev_queue_reply().  It seems like it was xs_wake_up() in this case.  It seems like req may have woken up the xs_wait_for_reply(), which kfree()ed the req.  When xenbus_thread resumes, it faults on the zero-ed data.  Linux Device Drivers 2nd edition states: "Normally, a wake_up call can cause an immediate reschedule to happen, meaning that other processes might run before wake_up returns." ... which would match the behaviour observed.  Change to keeping two krefs on each request.  One for the caller, and one for xenbus_thread.  Each will kref_put() when finished, and the last will free it.  This use of kref matches the description in Documentation/core-api/kref.rst

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37940?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37940" src="https://img.shields.io/badge/CVE--2025--37940-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ftrace: Add cond_resched() to ftrace_graph_set_hash()  When the kernel contains a large number of functions that can be traced, the loop in ftrace_graph_set_hash() may take a lot of time to execute. This may trigger the softlockup watchdog.  Add cond_resched() within the loop to allow the kernel to remain responsive even when processing a large number of functions.  This matches the cond_resched() that is used in other locations of the code that iterates over all functions that can be traced.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37937?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--37937" src="https://img.shields.io/badge/CVE--2025--37937-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  objtool, media: dib8000: Prevent divide-by-zero in dib8000_set_dds()  If dib8000_set_dds()'s call to dib8000_read32() returns zero, the result is a divide-by-zero.  Prevent that from happening.  Fixes the following warning with an UBSAN kernel:  drivers/media/dvb-frontends/dib8000.o: warning: objtool: dib8000_tune() falls through to next function dib8096p_cfg_DibRx()

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37932?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium : CVE--2025--37932" src="https://img.shields.io/badge/CVE--2025--37932-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sch_htb: make htb_qlen_notify() idempotent  htb_qlen_notify() always deactivates the HTB class and in fact could trigger a warning if it is already deactivated. Therefore, it is not idempotent and not friendly to its callers, like fq_codel_dequeue().  Let's make it idempotent to ease qdisc_tree_reduce_backlog() callers' life.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37930?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37930" src="https://img.shields.io/badge/CVE--2025--37930-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.065%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/nouveau: Fix WARN_ON in nouveau_fence_context_kill()  Nouveau is mostly designed in a way that it's expected that fences only ever get signaled through nouveau_fence_signal(). However, in at least one other place, nouveau_fence_done(), can signal fences, too. If that happens (race) a signaled fence remains in the pending list for a while, until it gets removed by nouveau_fence_update().  Should nouveau_fence_context_kill() run in the meantime, this would be a bug because the function would attempt to set an error code on an already signaled fence.  Have nouveau_fence_context_kill() check for a fence being signaled.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37927?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37927" src="https://img.shields.io/badge/CVE--2025--37927-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.075%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iommu/amd: Fix potential buffer overflow in parse_ivrs_acpihid  There is a string parsing logic error which can lead to an overflow of hid or uid buffers. Comparing ACPIID_LEN against a total string length doesn't take into account the lengths of individual hid and uid buffers so the check is insufficient in some cases. For example if the length of hid string is 4 and the length of the uid string is 260, the length of str will be equal to ACPIID_LEN + 1 but uid string will overflow uid buffer which size is 256.  The same applies to the hid string with length 13 and uid string with length 250.  Check the length of hid and uid strings separately to prevent buffer overflow.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37923?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37923" src="https://img.shields.io/badge/CVE--2025--37923-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tracing: Fix oob write in trace_seq_to_buffer()  syzbot reported this bug: ================================================================== BUG: KASAN: slab-out-of-bounds in trace_seq_to_buffer kernel/trace/trace.c:1830 [inline] BUG: KASAN: slab-out-of-bounds in tracing_splice_read_pipe+0x6be/0xdd0 kernel/trace/trace.c:6822 Write of size 4507 at addr ffff888032b6b000 by task syz.2.320/7260  CPU: 1 UID: 0 PID: 7260 Comm: syz.2.320 Not tainted 6.15.0-rc1-syzkaller-00301-g3bde70a2c827 #0 PREEMPT(full) Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/12/2025 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:408 [inline] print_report+0xc3/0x670 mm/kasan/report.c:521 kasan_report+0xe0/0x110 mm/kasan/report.c:634 check_region_inline mm/kasan/generic.c:183 [inline] kasan_check_range+0xef/0x1a0 mm/kasan/generic.c:189 __asan_memcpy+0x3c/0x60 mm/kasan/shadow.c:106 trace_seq_to_buffer kernel/trace/trace.c:1830 [inline] tracing_splice_read_pipe+0x6be/0xdd0 kernel/trace/trace.c:6822 .... ==================================================================  It has been reported that trace_seq_to_buffer() tries to copy more data than PAGE_SIZE to buf. Therefore, to prevent this, we should use the smaller of trace_seq_used(&iter->seq) and PAGE_SIZE as an argument.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37915?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37915" src="https://img.shields.io/badge/CVE--2025--37915-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: drr: Fix double list add in class with netem as child qdisc  As described in Gerrard's report [1], there are use cases where a netem child qdisc will make the parent qdisc's enqueue callback reentrant. In the case of drr, there won't be a UAF, but the code will add the same classifier to the list twice, which will cause memory corruption.  In addition to checking for qlen being zero, this patch checks whether the class was already added to the active_list (cl_is_active) before adding to the list to cover for the reentrant case.  [1] https://lore.kernel.org/netdev/CAHcdcOm+03OD2j6R0=YHKqmy=VgJ8xEOKuP6c7mSgnp-TEJJbw@mail.gmail.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37914?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37914" src="https://img.shields.io/badge/CVE--2025--37914-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: ets: Fix double list add in class with netem as child qdisc  As described in Gerrard's report [1], there are use cases where a netem child qdisc will make the parent qdisc's enqueue callback reentrant. In the case of ets, there won't be a UAF, but the code will add the same classifier to the list twice, which will cause memory corruption.  In addition to checking for qlen being zero, this patch checks whether the class was already added to the active_list (cl_is_active) before doing the addition to cater for the reentrant case.  [1] https://lore.kernel.org/netdev/CAHcdcOm+03OD2j6R0=YHKqmy=VgJ8xEOKuP6c7mSgnp-TEJJbw@mail.gmail.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37913?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37913" src="https://img.shields.io/badge/CVE--2025--37913-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: qfq: Fix double list add in class with netem as child qdisc  As described in Gerrard's report [1], there are use cases where a netem child qdisc will make the parent qdisc's enqueue callback reentrant. In the case of qfq, there won't be a UAF, but the code will add the same classifier to the list twice, which will cause memory corruption.  This patch checks whether the class was already added to the agg->active list (cl_is_active) before doing the addition to cater for the reentrant case.  [1] https://lore.kernel.org/netdev/CAHcdcOm+03OD2j6R0=YHKqmy=VgJ8xEOKuP6c7mSgnp-TEJJbw@mail.gmail.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37912?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37912" src="https://img.shields.io/badge/CVE--2025--37912-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ice: Check VF VSI Pointer Value in ice_vc_add_fdir_fltr()  As mentioned in the commit baeb705fd6a7 ("ice: always check VF VSI pointer values"), we need to perform a null pointer check on the return value of ice_get_vf_vsi() before using it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37911?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37911" src="https://img.shields.io/badge/CVE--2025--37911-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bnxt_en: Fix out-of-bound memcpy() during ethtool -w  When retrieving the FW coredump using ethtool, it can sometimes cause memory corruption:  BUG: KFENCE: memory corruption in __bnxt_get_coredump+0x3ef/0x670 [bnxt_en] Corrupted memory at 0x000000008f0f30e8 [ ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ! ] (in kfence-#45): __bnxt_get_coredump+0x3ef/0x670 [bnxt_en] ethtool_get_dump_data+0xdc/0x1a0 __dev_ethtool+0xa1e/0x1af0 dev_ethtool+0xa8/0x170 dev_ioctl+0x1b5/0x580 sock_do_ioctl+0xab/0xf0 sock_ioctl+0x1ce/0x2e0 __x64_sys_ioctl+0x87/0xc0 do_syscall_64+0x5c/0xf0 entry_SYSCALL_64_after_hwframe+0x78/0x80  ...  This happens when copying the coredump segment list in bnxt_hwrm_dbg_dma_data() with the HWRM_DBG_COREDUMP_LIST FW command. The info->dest_buf buffer is allocated based on the number of coredump segments returned by the FW.  The segment list is then DMA'ed by the FW and the length of the DMA is returned by FW.  The driver then copies this DMA'ed segment list to info->dest_buf.  In some cases, this DMA length may exceed the info->dest_buf length and cause the above BUG condition.  Fix it by capping the copy length to not exceed the length of info->dest_buf.  The extra DMA data contains no useful information.  This code path is shared for the HWRM_DBG_COREDUMP_LIST and the HWRM_DBG_COREDUMP_RETRIEVE FW commands.  The buffering is different for these 2 FW commands.  To simplify the logic, we need to move the line to adjust the buffer length for HWRM_DBG_COREDUMP_RETRIEVE up, so that the new check to cap the copy length will work for both commands.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37909?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37909" src="https://img.shields.io/badge/CVE--2025--37909-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: lan743x: Fix memleak issue when GSO enabled  Always map the `skb` to the LS descriptor. Previously skb was mapped to EXT descriptor when the number of fragments is zero with GSO enabled. Mapping the skb to EXT descriptor prevents it from being freed, leading to a memory leak

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37905?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37905" src="https://img.shields.io/badge/CVE--2025--37905-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  firmware: arm_scmi: Balance device refcount when destroying devices  Using device_find_child() to lookup the proper SCMI device to destroy causes an unbalance in device refcount, since device_find_child() calls an implicit get_device(): this, in turns, inhibits the call of the provided release methods upon devices destruction.  As a consequence, one of the structures that is not freed properly upon destruction is the internal struct device_private dev->p populated by the drivers subsystem core.  KMemleak detects this situation since loading/unloding some SCMI driver causes related devices to be created/destroyed without calling any device_release method.  unreferenced object 0xffff00000f583800 (size 512): comm "insmod", pid 227, jiffies 4294912190 hex dump (first 32 bytes): 00 00 00 00 ad 4e ad de ff ff ff ff 00 00 00 00  .....N.......... ff ff ff ff ff ff ff ff 60 36 1d 8a 00 80 ff ff  ........`6...... backtrace (crc 114e2eed): kmemleak_alloc+0xbc/0xd8 __kmalloc_cache_noprof+0x2dc/0x398 device_add+0x954/0x12d0 device_register+0x28/0x40 __scmi_device_create.part.0+0x1bc/0x380 scmi_device_create+0x2d0/0x390 scmi_create_protocol_devices+0x74/0xf8 scmi_device_request_notifier+0x1f8/0x2a8 notifier_call_chain+0x110/0x3b0 blocking_notifier_call_chain+0x70/0xb0 scmi_driver_register+0x350/0x7f0 0xffff80000a3b3038 do_one_initcall+0x12c/0x730 do_init_module+0x1dc/0x640 load_module+0x4b20/0x5b70 init_module_from_file+0xec/0x158  $ ./scripts/faddr2line ./vmlinux device_add+0x954/0x12d0 device_add+0x954/0x12d0: kmalloc_noprof at include/linux/slab.h:901 (inlined by) kzalloc_noprof at include/linux/slab.h:1037 (inlined by) device_private_init at drivers/base/core.c:3510 (inlined by) device_add at drivers/base/core.c:3561  Balance device refcount by issuing a put_device() on devices found via device_find_child().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37892?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37892" src="https://img.shields.io/badge/CVE--2025--37892-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mtd: inftlcore: Add error check for inftl_read_oob()  In INFTL_findwriteunit(), the return value of inftl_read_oob() need to be checked. A proper implementation can be found in INFTL_deleteblock(). The status will be set as SECTOR_IGNORE to break from the while-loop correctly if the inftl_read_oob() fails.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37890?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium : CVE--2025--37890" src="https://img.shields.io/badge/CVE--2025--37890-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: hfsc: Fix a UAF vulnerability in class with netem as child qdisc  As described in Gerrard's report [1], we have a UAF case when an hfsc class has a netem child qdisc. The crux of the issue is that hfsc is assuming that checking for cl->qdisc->q.qlen == 0 guarantees that it hasn't inserted the class in the vttree or eltree (which is not true for the netem duplicate case).  This patch checks the n_active class variable to make sure that the code won't insert the class in the vttree or eltree twice, catering for the reentrant case.  [1] https://lore.kernel.org/netdev/CAHcdcOm+03OD2j6R0=YHKqmy=VgJ8xEOKuP6c7mSgnp-TEJJbw@mail.gmail.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37889?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2025--37889" src="https://img.shields.io/badge/CVE--2025--37889-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: ops: Consistently treat platform_max as control value  This reverts commit 9bdd10d57a88 ("ASoC: ops: Shift tested values in snd_soc_put_volsw() by +min"), and makes some additional related updates.  There are two ways the platform_max could be interpreted; the maximum register value, or the maximum value the control can be set to. The patch moved from treating the value as a control value to a register one. When the patch was applied it was technically correct as snd_soc_limit_volume() also used the register interpretation. However, even then most of the other usages treated platform_max as a control value, and snd_soc_limit_volume() has since been updated to also do so in commit fb9ad24485087 ("ASoC: ops: add correct range check for limiting volume"). That patch however, missed updating snd_soc_put_volsw() back to the control interpretation, and fixing snd_soc_info_volsw_range(). The control interpretation makes more sense as limiting is typically done from the machine driver, so it is appropriate to use the customer facing representation rather than the internal codec representation. Update all the code to consistently use this interpretation of platform_max.  Finally, also add some comments to the soc_mixer_control struct to hopefully avoid further patches switching between the two approaches.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37885?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37885" src="https://img.shields.io/badge/CVE--2025--37885-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  KVM: x86: Reset IRTE to host control if *new* route isn't postable  Restore an IRTE back to host control (remapped or posted MSI mode) if the *new* GSI route prevents posting the IRQ directly to a vCPU, regardless of the GSI routing type.  Updating the IRTE if and only if the new GSI is an MSI results in KVM leaving an IRTE posting to a vCPU.  The dangling IRTE can result in interrupts being incorrectly delivered to the guest, and in the worst case scenario can result in use-after-free, e.g. if the VM is torn down, but the underlying host IRQ isn't freed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37883?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37883" src="https://img.shields.io/badge/CVE--2025--37883-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  s390/sclp: Add check for get_zeroed_page()  Add check for the return value of get_zeroed_page() in sclp_console_init() to prevent null pointer dereference. Furthermore, to solve the memory leak caused by the loop allocation, add a free helper to do the free job.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37881?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37881" src="https://img.shields.io/badge/CVE--2025--37881-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: aspeed: Add NULL pointer check in ast_vhub_init_dev()  The variable d->name, returned by devm_kasprintf(), could be NULL. A pointer check is added to prevent potential NULL pointer dereference. This is similar to the fix in commit 3027e7b15b02 ("ice: Fix some null pointer dereference issues in ice_ptp.c").  This issue is found by our static analysis tool

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37875?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37875" src="https://img.shields.io/badge/CVE--2025--37875-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  igc: fix PTM cycle trigger logic  Writing to clear the PTM status 'valid' bit while the PTM cycle is triggered results in unreliable PTM operation. To fix this, clear the PTM 'trigger' and status after each PTM transaction.  The issue can be reproduced with the following:  $ sudo phc2sys -R 1000 -O 0 -i tsn0 -m  Note: 1000 Hz (-R 1000) is unrealistically large, but provides a way to quickly reproduce the issue.  PHC2SYS exits with:  "ioctl PTP_OFFSET_PRECISE: Connection timed out" when the PTM transaction fails  This patch also fixes a hang in igc_probe() when loading the igc driver in the kdump kernel on systems supporting PTM.  The igc driver running in the base kernel enables PTM trigger in igc_probe().  Therefore the driver is always in PTM trigger mode, except in brief periods when manually triggering a PTM cycle.  When a crash occurs, the NIC is reset while PTM trigger is enabled. Due to a hardware problem, the NIC is subsequently in a bad busmaster state and doesn't handle register reads/writes.  When running igc_probe() in the kdump kernel, the first register access to a NIC register hangs driver probing and ultimately breaks kdump.  With this patch, igc has PTM trigger disabled most of the time, and the trigger is only enabled for very brief (10 - 100 us) periods when manually triggering a PTM cycle.  Chances that a crash occurs during a PTM trigger are not 0, but extremely reduced.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37871?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37871" src="https://img.shields.io/badge/CVE--2025--37871-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nfsd: decrease sc_count directly if fail to queue dl_recall  A deadlock warning occurred when invoking nfs4_put_stid following a failed dl_recall queue operation: T1                            T2 nfs4_laundromat nfs4_get_client_reaplist nfs4_anylock_blockers __break_lease spin_lock // ctx->flc_lock spin_lock // clp->cl_lock nfs4_lockowner_has_blockers locks_owner_has_blockers spin_lock // flctx->flc_lock nfsd_break_deleg_cb nfsd_break_one_deleg nfs4_put_stid refcount_dec_and_lock spin_lock // clp->cl_lock  When a file is opened, an nfs4_delegation is allocated with sc_count initialized to 1, and the file_lease holds a reference to the delegation. The file_lease is then associated with the file through kernel_setlease.  The disassociation is performed in nfsd4_delegreturn via the following call chain: nfsd4_delegreturn --> destroy_delegation --> destroy_unhashed_deleg --> nfs4_unlock_deleg_lease --> kernel_setlease --> generic_delete_lease The corresponding sc_count reference will be released after this disassociation.  Since nfsd_break_one_deleg executes while holding the flc_lock, the disassociation process becomes blocked when attempting to acquire flc_lock in generic_delete_lease. This means: 1) sc_count in nfsd_break_one_deleg will not be decremented to 0; 2) The nfs4_put_stid called by nfsd_break_one_deleg will not attempt to acquire cl_lock; 3) Consequently, no deadlock condition is created.  Given that sc_count in nfsd_break_one_deleg remains non-zero, we can safely perform refcount_dec on sc_count directly. This approach effectively avoids triggering deadlock warnings.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37867?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37867" src="https://img.shields.io/badge/CVE--2025--37867-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/core: Silence oversized kvmalloc() warning  syzkaller triggered an oversized kvmalloc() warning. Silence it by adding __GFP_NOWARN.  syzkaller log: WARNING: CPU: 7 PID: 518 at mm/util.c:665 __kvmalloc_node_noprof+0x175/0x180 CPU: 7 UID: 0 PID: 518 Comm: c_repro Not tainted 6.11.0-rc6+ #6 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 RIP: 0010:__kvmalloc_node_noprof+0x175/0x180 RSP: 0018:ffffc90001e67c10 EFLAGS: 00010246 RAX: 0000000000000100 RBX: 0000000000000400 RCX: ffffffff8149d46b RDX: 0000000000000000 RSI: ffff8881030fae80 RDI: 0000000000000002 RBP: 000000712c800000 R08: 0000000000000100 R09: 0000000000000000 R10: ffffc90001e67c10 R11: 0030ae0601000000 R12: 0000000000000000 R13: 0000000000000000 R14: 00000000ffffffff R15: 0000000000000000 FS:  00007fde79159740(0000) GS:ffff88813bdc0000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000020000180 CR3: 0000000105eb4005 CR4: 00000000003706b0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> ib_umem_odp_get+0x1f6/0x390 mlx5_ib_reg_user_mr+0x1e8/0x450 ib_uverbs_reg_mr+0x28b/0x440 ib_uverbs_write+0x7d3/0xa30 vfs_write+0x1ac/0x6c0 ksys_write+0x134/0x170 ? __sanitizer_cov_trace_pc+0x1c/0x50 do_syscall_64+0x50/0x110 entry_SYSCALL_64_after_hwframe+0x76/0x7e

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37862?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37862" src="https://img.shields.io/badge/CVE--2025--37862-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  HID: pidff: Fix null pointer dereference in pidff_find_fields  This function triggered a null pointer dereference if used to search for a report that isn't implemented on the device. This happened both for optional and required reports alike.  The same logic was applied to pidff_find_special_field and although pidff_init_fields should return an error earlier if one of the required reports is missing, future modifications could change this logic and resurface this possible null pointer dereference again.  LKML bug report: https://lore.kernel.org/all/CAL-gK7f5=R0nrrQdPtaZZr1fd-cdAMbDMuZ_NLA8vM0SX+nGSw@mail.gmail.com

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37859?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37859" src="https://img.shields.io/badge/CVE--2025--37859-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  page_pool: avoid infinite loop to schedule delayed worker  We noticed the kworker in page_pool_release_retry() was waken up repeatedly and infinitely in production because of the buggy driver causing the inflight less than 0 and warning us in page_pool_inflight()[1].  Since the inflight value goes negative, it means we should not expect the whole page_pool to get back to work normally.  This patch mitigates the adverse effect by not rescheduling the kworker when detecting the inflight negative in page_pool_release_retry().  [1] [Mon Feb 10 20:36:11 2025] ------------[ cut here ]------------ [Mon Feb 10 20:36:11 2025] Negative(-51446) inflight packet-pages ... [Mon Feb 10 20:36:11 2025] Call Trace: [Mon Feb 10 20:36:11 2025]  page_pool_release_retry+0x23/0x70 [Mon Feb 10 20:36:11 2025]  process_one_work+0x1b1/0x370 [Mon Feb 10 20:36:11 2025]  worker_thread+0x37/0x3a0 [Mon Feb 10 20:36:11 2025]  kthread+0x11a/0x140 [Mon Feb 10 20:36:11 2025]  ? process_one_work+0x370/0x370 [Mon Feb 10 20:36:11 2025]  ? __kthread_cancel_work+0x40/0x40 [Mon Feb 10 20:36:11 2025]  ret_from_fork+0x35/0x40 [Mon Feb 10 20:36:11 2025] ---[ end trace ebffe800f33e7e34 ]--- Note: before this patch, the above calltrace would flood the dmesg due to repeated reschedule of release_dw kworker.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37858?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37858" src="https://img.shields.io/badge/CVE--2025--37858-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs/jfs: Prevent integer overflow in AG size calculation  The JFS filesystem calculates allocation group (AG) size using 1 << l2agsize in dbExtendFS(). When l2agsize exceeds 31 (possible with >2TB aggregates on 32-bit systems), this 32-bit shift operation causes undefined behavior and improper AG sizing.  On 32-bit architectures: - Left-shifting 1 by 32+ bits results in 0 due to integer overflow - This creates invalid AG sizes (0 or garbage values) in sbi->bmap->db_agsize - Subsequent block allocations would reference invalid AG structures - Could lead to: - Filesystem corruption during extend operations - Kernel crashes due to invalid memory accesses - Security vulnerabilities via malformed on-disk structures  Fix by casting to s64 before shifting: bmp->db_agsize = (s64)1 << l2agsize;  This ensures 64-bit arithmetic even on 32-bit architectures. The cast matches the data type of db_agsize (s64) and follows similar patterns in JFS block calculation code.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37857?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37857" src="https://img.shields.io/badge/CVE--2025--37857-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: st: Fix array overflow in st_setup()  Change the array size to follow parms size instead of a fixed value.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37851?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37851" src="https://img.shields.io/badge/CVE--2025--37851-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fbdev: omapfb: Add 'plane' value check  Function dispc_ovl_setup is not intended to work with the value OMAP_DSS_WB of the enum parameter plane.  The value of this parameter is initialized in dss_init_overlays and in the current state of the code it cannot take this value so it's not a real problem.  For the purposes of defensive coding it wouldn't be superfluous to check the parameter value, because some functions down the call stack process this value correctly and some not.  For example, in dispc_ovl_setup_global_alpha it may lead to buffer overflow.  Add check for this value.  Found by Linux Verification Center (linuxtesting.org) with SVACE static analysis tool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37850?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37850" src="https://img.shields.io/badge/CVE--2025--37850-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pwm: mediatek: Prevent divide-by-zero in pwm_mediatek_config()  With CONFIG_COMPILE_TEST && !CONFIG_HAVE_CLK, pwm_mediatek_config() has a divide-by-zero in the following line:  do_div(resolution, clk_get_rate(pc->clk_pwms[pwm->hwpwm]));  due to the fact that the !CONFIG_HAVE_CLK version of clk_get_rate() returns zero.  This is presumably just a theoretical problem: COMPILE_TEST overrides the dependency on RALINK which would select COMMON_CLK.  Regardless it's a good idea to check for the error explicitly to avoid divide-by-zero.  Fixes the following warning:  drivers/pwm/pwm-mediatek.o: warning: objtool: .text: unexpected end of section  [ukleinek: s/CONFIG_CLK/CONFIG_HAVE_CLK/]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37844?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37844" src="https://img.shields.io/badge/CVE--2025--37844-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cifs: avoid NULL pointer dereference in dbg call  cifs_server_dbg() implies server to be non-NULL so move call under condition to avoid NULL pointer dereference.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37841?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37841" src="https://img.shields.io/badge/CVE--2025--37841-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pm: cpupower: bench: Prevent NULL dereference on malloc failure  If malloc returns NULL due to low memory, 'config' pointer can be NULL. Add a check to prevent NULL dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37840?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37840" src="https://img.shields.io/badge/CVE--2025--37840-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mtd: rawnand: brcmnand: fix PM resume warning  Fixed warning on PM resume as shown below caused due to uninitialized struct nand_operation that checks chip select field : WARN_ON(op->cs >= nanddev_ntargets(&chip->base)  [   14.588522] ------------[ cut here ]------------ [   14.588529] WARNING: CPU: 0 PID: 1392 at drivers/mtd/nand/raw/internals.h:139 nand_reset_op+0x1e0/0x1f8 [   14.588553] Modules linked in: bdc udc_core [   14.588579] CPU: 0 UID: 0 PID: 1392 Comm: rtcwake Tainted: G        W 6.14.0-rc4-g5394eea10651 #16 [   14.588590] Tainted: [W]=WARN [   14.588593] Hardware name: Broadcom STB (Flattened Device Tree) [   14.588598] Call trace: [   14.588604]  dump_backtrace from show_stack+0x18/0x1c [   14.588622]  r7:00000009 r6:0000008b r5:60000153 r4:c0fa558c [   14.588625]  show_stack from dump_stack_lvl+0x70/0x7c [   14.588639]  dump_stack_lvl from dump_stack+0x18/0x1c [   14.588653]  r5:c08d40b0 r4:c1003cb0 [   14.588656]  dump_stack from __warn+0x84/0xe4 [   14.588668]  __warn from warn_slowpath_fmt+0x18c/0x194 [   14.588678]  r7:c08d40b0 r6:c1003cb0 r5:00000000 r4:00000000 [   14.588681]  warn_slowpath_fmt from nand_reset_op+0x1e0/0x1f8 [   14.588695]  r8:70c40dff r7:89705f41 r6:36b4a597 r5:c26c9444 r4:c26b0048 [   14.588697]  nand_reset_op from brcmnand_resume+0x13c/0x150 [   14.588714]  r9:00000000 r8:00000000 r7:c24f8010 r6:c228a3f8 r5:c26c94bc r4:c26b0040 [   14.588717]  brcmnand_resume from platform_pm_resume+0x34/0x54 [   14.588735]  r5:00000010 r4:c0840a50 [   14.588738]  platform_pm_resume from dpm_run_callback+0x5c/0x14c [   14.588757]  dpm_run_callback from device_resume+0xc0/0x324 [   14.588776]  r9:c24f8054 r8:c24f80a0 r7:00000000 r6:00000000 r5:00000010 r4:c24f8010 [   14.588779]  device_resume from dpm_resume+0x130/0x160 [   14.588799]  r9:c22539e4 r8:00000010 r7:c22bebb0 r6:c24f8010 r5:c22539dc r4:c22539b0 [   14.588802]  dpm_resume from dpm_resume_end+0x14/0x20 [   14.588822]  r10:c2204e40 r9:00000000 r8:c228a3fc r7:00000000 r6:00000003 r5:c228a414 [   14.588826]  r4:00000010 [   14.588828]  dpm_resume_end from suspend_devices_and_enter+0x274/0x6f8 [   14.588848]  r5:c228a414 r4:00000000 [   14.588851]  suspend_devices_and_enter from pm_suspend+0x228/0x2bc [   14.588868]  r10:c3502910 r9:c3501f40 r8:00000004 r7:c228a438 r6:c0f95e18 r5:00000000 [   14.588871]  r4:00000003 [   14.588874]  pm_suspend from state_store+0x74/0xd0 [   14.588889]  r7:c228a438 r6:c0f934c8 r5:00000003 r4:00000003 [   14.588892]  state_store from kobj_attr_store+0x1c/0x28 [   14.588913]  r9:00000000 r8:00000000 r7:f09f9f08 r6:00000004 r5:c3502900 r4:c0283250 [   14.588916]  kobj_attr_store from sysfs_kf_write+0x40/0x4c [   14.588936]  r5:c3502900 r4:c0d92a48 [   14.588939]  sysfs_kf_write from kernfs_fop_write_iter+0x104/0x1f0 [   14.588956]  r5:c3502900 r4:c3501f40 [   14.588960]  kernfs_fop_write_iter from vfs_write+0x250/0x420 [   14.588980]  r10:c0e14b48 r9:00000000 r8:c25f5780 r7:00443398 r6:f09f9f68 r5:c34f7f00 [   14.588983]  r4:c042a88c [   14.588987]  vfs_write from ksys_write+0x74/0xe4 [   14.589005]  r10:00000004 r9:c25f5780 r8:c02002fA0 r7:00000000 r6:00000000 r5:c34f7f00 [   14.589008]  r4:c34f7f00 [   14.589011]  ksys_write from sys_write+0x10/0x14 [   14.589029]  r7:00000004 r6:004421c0 r5:00443398 r4:00000004 [   14.589032]  sys_write from ret_fast_syscall+0x0/0x5c [   14.589044] Exception stack(0xf09f9fa8 to 0xf09f9ff0) [   14.589050] 9fa0:                   00000004 00443398 00000004 00443398 00000004 00000001 [   14.589056] 9fc0: 00000004 00443398 004421c0 00000004 b6ecbd58 00000008 bebfbc38 0043eb78 [   14.589062] 9fe0: 00440eb0 bebfbaf8 b6de18a0 b6e579e8 [   14.589065] ---[ end trace 0000000000000000 ]---  The fix uses the higher level nand_reset(chip, chipnr); where chipnr = 0, when doing PM resume operation in compliance with the controller support for single die nand chip. Switching from nand_reset_op() to nan ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37839?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37839" src="https://img.shields.io/badge/CVE--2025--37839-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jbd2: remove wrong sb->s_sequence check  Journal emptiness is not determined by sb->s_sequence == 0 but rather by sb->s_start == 0 (which is set a few lines above). Furthermore 0 is a valid transaction ID so the check can spuriously trigger. Remove the invalid WARN_ON.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37838?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37838" src="https://img.shields.io/badge/CVE--2025--37838-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  HSI: ssi_protocol: Fix use after free vulnerability in ssi_protocol Driver Due to Race Condition  In the ssi_protocol_probe() function, &ssi->work is bound with ssip_xmit_work(), In ssip_pn_setup(), the ssip_pn_xmit() function within the ssip_pn_ops structure is capable of starting the work.  If we remove the module which will call ssi_protocol_remove() to make a cleanup, it will free ssi through kfree(ssi), while the work mentioned above will be used. The sequence of operations that may lead to a UAF bug is as follows:  CPU0                                    CPU1  | ssip_xmit_work ssi_protocol_remove     | kfree(ssi);             | | struct hsi_client *cl = ssi->cl; | // use ssi  Fix it by ensuring that the work is canceled before proceeding with the cleanup in ssi_protocol_remove().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37836?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37836" src="https://img.shields.io/badge/CVE--2025--37836-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  PCI: Fix reference leak in pci_register_host_bridge()  If device_register() fails, call put_device() to give up the reference to avoid a memory leak, per the comment at device_register().  Found by code review.  [bhelgaas: squash Dan Carpenter's double free fix from https://lore.kernel.org/r/db806a6c-a91b-4e5a-a84b-6b7e01bdac85@stanley.mountain]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37830?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37830" src="https://img.shields.io/badge/CVE--2025--37830-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cpufreq: scmi: Fix null-ptr-deref in scmi_cpufreq_get_rate()  cpufreq_cpu_get_raw() can return NULL when the target CPU is not present in the policy->cpus mask. scmi_cpufreq_get_rate() does not check for this case, which results in a NULL pointer dereference.  Add NULL check after cpufreq_cpu_get_raw() to prevent this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37829?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37829" src="https://img.shields.io/badge/CVE--2025--37829-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cpufreq: scpi: Fix null-ptr-deref in scpi_cpufreq_get_rate()  cpufreq_cpu_get_raw() can return NULL when the target CPU is not present in the policy->cpus mask. scpi_cpufreq_get_rate() does not check for this case, which results in a NULL pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37824?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37824" src="https://img.shields.io/badge/CVE--2025--37824-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tipc: fix NULL pointer dereference in tipc_mon_reinit_self()  syzbot reported:  tipc: Node number set to 1055423674 Oops: general protection fault, probably for non-canonical address 0xdffffc0000000000: 0000 [#1] SMP KASAN NOPTI KASAN: null-ptr-deref in range [0x0000000000000000-0x0000000000000007] CPU: 3 UID: 0 PID: 6017 Comm: kworker/3:5 Not tainted 6.15.0-rc1-syzkaller-00246-g900241a5cc15 #0 PREEMPT(full) Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 Workqueue: events tipc_net_finalize_work RIP: 0010:tipc_mon_reinit_self+0x11c/0x210 net/tipc/monitor.c:719 ... RSP: 0018:ffffc9000356fb68 EFLAGS: 00010246 RAX: 0000000000000000 RBX: 0000000000000000 RCX: 000000003ee87cba RDX: 0000000000000000 RSI: ffffffff8dbc56a7 RDI: ffff88804c2cc010 RBP: dffffc0000000000 R08: 0000000000000001 R09: 0000000000000000 R10: 0000000000000001 R11: 0000000000000000 R12: 0000000000000007 R13: fffffbfff2111097 R14: ffff88804ead8000 R15: ffff88804ead9010 FS:  0000000000000000(0000) GS:ffff888097ab9000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00000000f720eb00 CR3: 000000000e182000 CR4: 0000000000352ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> tipc_net_finalize+0x10b/0x180 net/tipc/net.c:140 process_one_work+0x9cc/0x1b70 kernel/workqueue.c:3238 process_scheduled_works kernel/workqueue.c:3319 [inline] worker_thread+0x6c8/0xf10 kernel/workqueue.c:3400 kthread+0x3c2/0x780 kernel/kthread.c:464 ret_from_fork+0x45/0x80 arch/x86/kernel/process.c:153 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:245 </TASK> ... RIP: 0010:tipc_mon_reinit_self+0x11c/0x210 net/tipc/monitor.c:719 ... RSP: 0018:ffffc9000356fb68 EFLAGS: 00010246 RAX: 0000000000000000 RBX: 0000000000000000 RCX: 000000003ee87cba RDX: 0000000000000000 RSI: ffffffff8dbc56a7 RDI: ffff88804c2cc010 RBP: dffffc0000000000 R08: 0000000000000001 R09: 0000000000000000 R10: 0000000000000001 R11: 0000000000000000 R12: 0000000000000007 R13: fffffbfff2111097 R14: ffff88804ead8000 R15: ffff88804ead9010 FS:  0000000000000000(0000) GS:ffff888097ab9000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00000000f720eb00 CR3: 000000000e182000 CR4: 0000000000352ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400  There is a racing condition between workqueue created when enabling bearer and another thread created when disabling bearer right after that as follow:  enabling_bearer                          | disabling_bearer ---------------                          | ---------------- tipc_disc_timeout()                      | {                                        | bearer_disable() ...                                     | { schedule_work(&tn->work);               |  tipc_mon_delete() ...                                     |  { }                                        |   ... |   write_lock_bh(&mon->lock); |   mon->self = NULL; |   write_unlock_bh(&mon->lock); |   ... |  } tipc_net_finalize_work()                 | } {                                        | ...                                     | tipc_net_finalize()                     | {                                       | ...                                    | tipc_mon_reinit_self()                 | {                                      | ...                                   | write_lock_bh(&mon->lock);            | mon->self->addr = tipc_own_addr(net); | write_unlock_bh(&mon->lock);          | ... ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37823?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37823" src="https://img.shields.io/badge/CVE--2025--37823-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: hfsc: Fix a potential UAF in hfsc_dequeue() too  Similarly to the previous patch, we need to safe guard hfsc_dequeue() too. But for this one, we don't have a reliable reproducer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37819?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37819" src="https://img.shields.io/badge/CVE--2025--37819-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  irqchip/gic-v2m: Prevent use after free of gicv2m_get_fwnode()  With ACPI in place, gicv2m_get_fwnode() is registered with the pci subsystem as pci_msi_get_fwnode_cb(), which may get invoked at runtime during a PCI host bridge probe. But, the call back is wrongly marked as __init, causing it to be freed, while being registered with the PCI subsystem and could trigger:  Unable to handle kernel paging request at virtual address ffff8000816c0400 gicv2m_get_fwnode+0x0/0x58 (P) pci_set_bus_msi_domain+0x74/0x88 pci_register_host_bridge+0x194/0x548  This is easily reproducible on a Juno board with ACPI boot.  Retain the function for later use.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37817?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37817" src="https://img.shields.io/badge/CVE--2025--37817-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mcb: fix a double free bug in chameleon_parse_gdd()  In chameleon_parse_gdd(), if mcb_device_register() fails, 'mdev' would be released in mcb_device_register() via put_device(). Thus, goto 'err' label and free 'mdev' again causes a double free. Just return if mcb_device_register() fails.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37812?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37812" src="https://img.shields.io/badge/CVE--2025--37812-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: cdns3: Fix deadlock when using NCM gadget  The cdns3 driver has the same NCM deadlock as fixed in cdnsp by commit 58f2fcb3a845 ("usb: cdnsp: Fix deadlock issue during using NCM gadget").  Under PREEMPT_RT the deadlock can be readily triggered by heavy network traffic, for example using "iperf --bidir" over NCM ethernet link.  The deadlock occurs because the threaded interrupt handler gets preempted by a softirq, but both are protected by the same spinlock. Prevent deadlock by disabling softirq during threaded irq handler.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37811?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37811" src="https://img.shields.io/badge/CVE--2025--37811-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: chipidea: ci_hdrc_imx: fix usbmisc handling  usbmisc is an optional device property so it is totally valid for the corresponding data->usbmisc_data to have a NULL value.  Check that before dereferencing the pointer.  Found by Linux Verification Center (linuxtesting.org) with Svace static analysis tool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37810?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37810" src="https://img.shields.io/badge/CVE--2025--37810-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: dwc3: gadget: check that event count does not exceed event buffer length  The event count is read from register DWC3_GEVNTCOUNT. There is a check for the count being zero, but not for exceeding the event buffer length. Check that event count does not exceed event buffer length, avoiding an out-of-bounds access when memcpy'ing the event. Crash log: Unable to handle kernel paging request at virtual address ffffffc0129be000 pc : __memcpy+0x114/0x180 lr : dwc3_check_event_buf+0xec/0x348 x3 : 0000000000000030 x2 : 000000000000dfc4 x1 : ffffffc0129be000 x0 : ffffff87aad60080 Call trace: __memcpy+0x114/0x180 dwc3_interrupt+0x24/0x34

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37808?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37808" src="https://img.shields.io/badge/CVE--2025--37808-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  crypto: null - Use spin lock instead of mutex  As the null algorithm may be freed in softirq context through af_alg, use spin locks instead of mutexes to protect the default null algorithm.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37798?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-143.153"><img alt="medium : CVE--2025--37798" src="https://img.shields.io/badge/CVE--2025--37798-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-143.153</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-143.153</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  codel: remove sch->q.qlen check before qdisc_tree_reduce_backlog()  After making all ->qlen_notify() callbacks idempotent, now it is safe to remove the check of qlen!=0 from both fq_codel_dequeue() and codel_qdisc_dequeue().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37797?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37797" src="https://img.shields.io/badge/CVE--2025--37797-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: hfsc: Fix a UAF vulnerability in class handling  This patch fixes a Use-After-Free vulnerability in the HFSC qdisc class handling. The issue occurs due to a time-of-check/time-of-use condition in hfsc_change_class() when working with certain child qdiscs like netem or codel.  The vulnerability works as follows: 1. hfsc_change_class() checks if a class has packets (q.qlen != 0) 2. It then calls qdisc_peek_len(), which for certain qdiscs (e.g., codel, netem) might drop packets and empty the queue 3. The code continues assuming the queue is still non-empty, adding the class to vttree 4. This breaks HFSC scheduler assumptions that only non-empty classes are in vttree 5. Later, when the class is destroyed, this can lead to a Use-After-Free  The fix adds a second queue length check after qdisc_peek_len() to verify the queue wasn't emptied.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37796?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37796" src="https://img.shields.io/badge/CVE--2025--37796-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: at76c50x: fix use after free access in at76_disconnect  The memory pointed to by priv is freed at the end of at76_delete_device function (using ieee80211_free_hw). But the code then accesses the udev field of the freed object to put the USB device. This may also lead to a memory leak of the usb device. Fix this by using udev from interface.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37794?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37794" src="https://img.shields.io/badge/CVE--2025--37794-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: mac80211: Purge vif txq in ieee80211_do_stop()  After ieee80211_do_stop() SKB from vif's txq could still be processed. Indeed another concurrent vif schedule_and_wake_txq call could cause those packets to be dequeued (see ieee80211_handle_wake_tx_queue()) without checking the sdata current state.  Because vif.drv_priv is now cleared in this function, this could lead to driver crash.  For example in ath12k, ahvif is store in vif.drv_priv. Thus if ath12k_mac_op_tx() is called after ieee80211_do_stop(), ahvif->ah can be NULL, leading the ath12k_warn(ahvif->ah,...) call in this function to trigger the NULL deref below.  Unable to handle kernel paging request at virtual address dfffffc000000001 KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f] batman_adv: bat0: Interface deactivated: brbh1337 Mem abort info: ESR = 0x0000000096000004 EC = 0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x04: level 0 translation fault Data abort info: ISV = 0, ISS = 0x00000004, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess = 0 GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 [dfffffc000000001] address between user and kernel address ranges Internal error: Oops: 0000000096000004 [#1] SMP CPU: 1 UID: 0 PID: 978 Comm: lbd Not tainted 6.13.0-g633f875b8f1e #114 Hardware name: HW (DT) pstate: 10000005 (nzcV daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : ath12k_mac_op_tx+0x6cc/0x29b8 [ath12k] lr : ath12k_mac_op_tx+0x174/0x29b8 [ath12k] sp : ffffffc086ace450 x29: ffffffc086ace450 x28: 0000000000000000 x27: 1ffffff810d59ca4 x26: ffffff801d05f7c0 x25: 0000000000000000 x24: 000000004000001e x23: ffffff8009ce4926 x22: ffffff801f9c0800 x21: ffffff801d05f7f0 x20: ffffff8034a19f40 x19: 0000000000000000 x18: ffffff801f9c0958 x17: ffffff800bc0a504 x16: dfffffc000000000 x15: ffffffc086ace4f8 x14: ffffff801d05f83c x13: 0000000000000000 x12: ffffffb003a0bf03 x11: 0000000000000000 x10: ffffffb003a0bf02 x9 : ffffff8034a19f40 x8 : ffffff801d05f818 x7 : 1ffffff0069433dc x6 : ffffff8034a19ee0 x5 : ffffff801d05f7f0 x4 : 0000000000000000 x3 : 0000000000000001 x2 : 0000000000000000 x1 : dfffffc000000000 x0 : 0000000000000008 Call trace: ath12k_mac_op_tx+0x6cc/0x29b8 [ath12k] (P) ieee80211_handle_wake_tx_queue+0x16c/0x260 ieee80211_queue_skb+0xeec/0x1d20 ieee80211_tx+0x200/0x2c8 ieee80211_xmit+0x22c/0x338 __ieee80211_subif_start_xmit+0x7e8/0xc60 ieee80211_subif_start_xmit+0xc4/0xee0 __ieee80211_subif_start_xmit_8023.isra.0+0x854/0x17a0 ieee80211_subif_start_xmit_8023+0x124/0x488 dev_hard_start_xmit+0x160/0x5a8 __dev_queue_xmit+0x6f8/0x3120 br_dev_queue_push_xmit+0x120/0x4a8 __br_forward+0xe4/0x2b0 deliver_clone+0x5c/0xd0 br_flood+0x398/0x580 br_dev_xmit+0x454/0x9f8 dev_hard_start_xmit+0x160/0x5a8 __dev_queue_xmit+0x6f8/0x3120 ip6_finish_output2+0xc28/0x1b60 __ip6_finish_output+0x38c/0x638 ip6_output+0x1b4/0x338 ip6_local_out+0x7c/0xa8 ip6_send_skb+0x7c/0x1b0 ip6_push_pending_frames+0x94/0xd0 rawv6_sendmsg+0x1a98/0x2898 inet_sendmsg+0x94/0xe0 __sys_sendto+0x1e4/0x308 __arm64_sys_sendto+0xc4/0x140 do_el0_svc+0x110/0x280 el0_svc+0x20/0x60 el0t_64_sync_handler+0x104/0x138 el0t_64_sync+0x154/0x158  To avoid that, empty vif's txq at ieee80211_do_stop() so no packet could be dequeued after ieee80211_do_stop() (new packets cannot be queued because SDATA_STATE_RUNNING is cleared at this point).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37792?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37792" src="https://img.shields.io/badge/CVE--2025--37792-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: btrtl: Prevent potential NULL dereference  The btrtl_initialize() function checks that rtl_load_file() either had an error or it loaded a zero length file.  However, if it loaded a zero length file then the error code is not set correctly.  It results in an error pointer vs NULL bug, followed by a NULL pointer dereference.  This was detected by Smatch:  drivers/bluetooth/btrtl.c:592 btrtl_initialize() warn: passing zero to 'ERR_PTR'

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37790?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37790" src="https://img.shields.io/badge/CVE--2025--37790-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: mctp: Set SOCK_RCU_FREE  Bind lookup runs under RCU, so ensure that a socket doesn't go away in the middle of a lookup.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37789?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37789" src="https://img.shields.io/badge/CVE--2025--37789-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: openvswitch: fix nested key length validation in the set() action  It's not safe to access nla_len(ovs_key) if the data is smaller than the netlink header.  Check that the attribute is OK first.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37788?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37788" src="https://img.shields.io/badge/CVE--2025--37788-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cxgb4: fix memory leak in cxgb4_init_ethtool_filters() error path  In the for loop used to allocate the loc_array and bmap for each port, a memory leak is possible when the allocation for loc_array succeeds, but the allocation for bmap fails. This is because when the control flow goes to the label free_eth_finfo, only the allocations starting from (i-1)th iteration are freed.  Fix that by freeing the loc_array in the bmap allocation error path.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37787?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37787" src="https://img.shields.io/badge/CVE--2025--37787-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: dsa: mv88e6xxx: avoid unregistering devlink regions which were never registered  Russell King reports that a system with mv88e6xxx dereferences a NULL pointer when unbinding this driver: https://lore.kernel.org/netdev/Z_lRkMlTJ1KQ0kVX@shell.armlinux.org.uk/  The crash seems to be in devlink_region_destroy(), which is not NULL tolerant but is given a NULL devlink global region pointer.  At least on some chips, some devlink regions are conditionally registered since the blamed commit, see mv88e6xxx_setup_devlink_regions_global():  if (cond && !cond(chip)) continue;  These are MV88E6XXX_REGION_STU and MV88E6XXX_REGION_PVT. If the chip does not have an STU or PVT, it should crash like this.  To fix the issue, avoid unregistering those regions which are NULL, i.e. were skipped at mv88e6xxx_setup_devlink_regions_global() time.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37781?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37781" src="https://img.shields.io/badge/CVE--2025--37781-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  i2c: cros-ec-tunnel: defer probe if parent EC is not present  When i2c-cros-ec-tunnel and the EC driver are built-in, the EC parent device will not be found, leading to NULL pointer dereference.  That can also be reproduced by unbinding the controller driver and then loading i2c-cros-ec-tunnel module (or binding the device).  [  271.991245] BUG: kernel NULL pointer dereference, address: 0000000000000058 [  271.998215] #PF: supervisor read access in kernel mode [  272.003351] #PF: error_code(0x0000) - not-present page [  272.008485] PGD 0 P4D 0 [  272.011022] Oops: Oops: 0000 [#1] SMP NOPTI [  272.015207] CPU: 0 UID: 0 PID: 3859 Comm: insmod Tainted: G S 6.15.0-rc1-00004-g44722359ed83 #30 PREEMPT(full) 3c7fb39a552e7d949de2ad921a7d6588d3a4fdc5 [  272.030312] Tainted: [S]=CPU_OUT_OF_SPEC [  272.034233] Hardware name: HP Berknip/Berknip, BIOS Google_Berknip.13434.356.0 05/17/2021 [  272.042400] RIP: 0010:ec_i2c_probe+0x2b/0x1c0 [i2c_cros_ec_tunnel] [  272.048577] Code: 1f 44 00 00 41 57 41 56 41 55 41 54 53 48 83 ec 10 65 48 8b 05 06 a0 6c e7 48 89 44 24 08 4c 8d 7f 10 48 8b 47 50 4c 8b 60 78 <49> 83 7c 24 58 00 0f 84 2f 01 00 00 48 89 fb be 30 06 00 00 4c 9 [  272.067317] RSP: 0018:ffffa32082a03940 EFLAGS: 00010282 [  272.072541] RAX: ffff969580b6a810 RBX: ffff969580b68c10 RCX: 0000000000000000 [  272.079672] RDX: 0000000000000000 RSI: 0000000000000282 RDI: ffff969580b68c00 [  272.086804] RBP: 00000000fffffdfb R08: 0000000000000000 R09: 0000000000000000 [  272.093936] R10: 0000000000000000 R11: ffffffffc0600000 R12: 0000000000000000 [  272.101067] R13: ffffffffa666fbb8 R14: ffffffffc05b5528 R15: ffff969580b68c10 [  272.108198] FS:  00007b930906fc40(0000) GS:ffff969603149000(0000) knlGS:0000000000000000 [  272.116282] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  272.122024] CR2: 0000000000000058 CR3: 000000012631c000 CR4: 00000000003506f0 [  272.129155] Call Trace: [  272.131606]  <TASK> [  272.133709]  ? acpi_dev_pm_attach+0xdd/0x110 [  272.137985]  platform_probe+0x69/0xa0 [  272.141652]  really_probe+0x152/0x310 [  272.145318]  __driver_probe_device+0x77/0x110 [  272.149678]  driver_probe_device+0x1e/0x190 [  272.153864]  __driver_attach+0x10b/0x1e0 [  272.157790]  ? driver_attach+0x20/0x20 [  272.161542]  bus_for_each_dev+0x107/0x150 [  272.165553]  bus_add_driver+0x15d/0x270 [  272.169392]  driver_register+0x65/0x110 [  272.173232]  ? cleanup_module+0xa80/0xa80 [i2c_cros_ec_tunnel 3a00532f3f4af4a9eade753f86b0f8dd4e4e5698] [  272.182617]  do_one_initcall+0x110/0x350 [  272.186543]  ? security_kernfs_init_security+0x49/0xd0 [  272.191682]  ? __kernfs_new_node+0x1b9/0x240 [  272.195954]  ? security_kernfs_init_security+0x49/0xd0 [  272.201093]  ? __kernfs_new_node+0x1b9/0x240 [  272.205365]  ? kernfs_link_sibling+0x105/0x130 [  272.209810]  ? kernfs_next_descendant_post+0x1c/0xa0 [  272.214773]  ? kernfs_activate+0x57/0x70 [  272.218699]  ? kernfs_add_one+0x118/0x160 [  272.222710]  ? __kernfs_create_file+0x71/0xa0 [  272.227069]  ? sysfs_add_bin_file_mode_ns+0xd6/0x110 [  272.232033]  ? internal_create_group+0x453/0x4a0 [  272.236651]  ? __vunmap_range_noflush+0x214/0x2d0 [  272.241355]  ? __free_frozen_pages+0x1dc/0x420 [  272.245799]  ? free_vmap_area_noflush+0x10a/0x1c0 [  272.250505]  ? load_module+0x1509/0x16f0 [  272.254431]  do_init_module+0x60/0x230 [  272.258181]  __se_sys_finit_module+0x27a/0x370 [  272.262627]  do_syscall_64+0x6a/0xf0 [  272.266206]  ? do_syscall_64+0x76/0xf0 [  272.269956]  ? irqentry_exit_to_user_mode+0x79/0x90 [  272.274836]  entry_SYSCALL_64_after_hwframe+0x55/0x5d [  272.279887] RIP: 0033:0x7b9309168d39 [  272.283466] Code: 5b 41 5c 5d c3 66 2e 0f 1f 84 00 00 00 00 00 66 90 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d af 40 0c 00 f7 d8 64 89 01 8 [  272.302210] RSP: 002b:00007fff50f1a288 EFLAGS: 00000246 ORIG_RAX: 000 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37780?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37780" src="https://img.shields.io/badge/CVE--2025--37780-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  isofs: Prevent the use of too small fid  syzbot reported a slab-out-of-bounds Read in isofs_fh_to_parent. [1]  The handle_bytes value passed in by the reproducing program is equal to 12. In handle_to_path(), only 12 bytes of memory are allocated for the structure file_handle->f_handle member, which causes an out-of-bounds access when accessing the member parent_block of the structure isofs_fid in isofs, because accessing parent_block requires at least 16 bytes of f_handle. Here, fh_len is used to indirectly confirm that the value of handle_bytes is greater than 3 before accessing parent_block.  [1] BUG: KASAN: slab-out-of-bounds in isofs_fh_to_parent+0x1b8/0x210 fs/isofs/export.c:183 Read of size 4 at addr ffff0000cc030d94 by task syz-executor215/6466 CPU: 1 UID: 0 PID: 6466 Comm: syz-executor215 Not tainted 6.14.0-rc7-syzkaller-ga2392f333575 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 02/12/2025 Call trace: show_stack+0x2c/0x3c arch/arm64/kernel/stacktrace.c:466 (C) __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0xe4/0x150 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:408 [inline] print_report+0x198/0x550 mm/kasan/report.c:521 kasan_report+0xd8/0x138 mm/kasan/report.c:634 __asan_report_load4_noabort+0x20/0x2c mm/kasan/report_generic.c:380 isofs_fh_to_parent+0x1b8/0x210 fs/isofs/export.c:183 exportfs_decode_fh_raw+0x2dc/0x608 fs/exportfs/expfs.c:523 do_handle_to_path+0xa0/0x198 fs/fhandle.c:257 handle_to_path fs/fhandle.c:385 [inline] do_handle_open+0x8cc/0xb8c fs/fhandle.c:403 __do_sys_open_by_handle_at fs/fhandle.c:443 [inline] __se_sys_open_by_handle_at fs/fhandle.c:434 [inline] __arm64_sys_open_by_handle_at+0x80/0x94 fs/fhandle.c:434 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x98/0x2b8 arch/arm64/kernel/syscall.c:49 el0_svc_common+0x130/0x23c arch/arm64/kernel/syscall.c:132 do_el0_svc+0x48/0x58 arch/arm64/kernel/syscall.c:151 el0_svc+0x54/0x168 arch/arm64/kernel/entry-common.c:744 el0t_64_sync_handler+0x84/0x108 arch/arm64/kernel/entry-common.c:762 el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:600  Allocated by task 6466: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x40/0x78 mm/kasan/common.c:68 kasan_save_alloc_info+0x40/0x50 mm/kasan/generic.c:562 poison_kmalloc_redzone mm/kasan/common.c:377 [inline] __kasan_kmalloc+0xac/0xc4 mm/kasan/common.c:394 kasan_kmalloc include/linux/kasan.h:260 [inline] __do_kmalloc_node mm/slub.c:4294 [inline] __kmalloc_noprof+0x32c/0x54c mm/slub.c:4306 kmalloc_noprof include/linux/slab.h:905 [inline] handle_to_path fs/fhandle.c:357 [inline] do_handle_open+0x5a4/0xb8c fs/fhandle.c:403 __do_sys_open_by_handle_at fs/fhandle.c:443 [inline] __se_sys_open_by_handle_at fs/fhandle.c:434 [inline] __arm64_sys_open_by_handle_at+0x80/0x94 fs/fhandle.c:434 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x98/0x2b8 arch/arm64/kernel/syscall.c:49 el0_svc_common+0x130/0x23c arch/arm64/kernel/syscall.c:132 do_el0_svc+0x48/0x58 arch/arm64/kernel/syscall.c:151 el0_svc+0x54/0x168 arch/arm64/kernel/entry-common.c:744 el0t_64_sync_handler+0x84/0x108 arch/arm64/kernel/entry-common.c:762 el0t_64_sync+0x198/0x19c arch/arm64/kernel/entry.S:600

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37773?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37773" src="https://img.shields.io/badge/CVE--2025--37773-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  virtiofs: add filesystem context source name check  In certain scenarios, for example, during fuzz testing, the source name may be NULL, which could lead to a kernel panic. Therefore, an extra check for the source name should be added.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37771?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37771" src="https://img.shields.io/badge/CVE--2025--37771-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/pm: Prevent division by zero  The user can set any speed value. If speed is greater than UINT_MAX/8, division by zero is possible.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37770?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37770" src="https://img.shields.io/badge/CVE--2025--37770-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/pm: Prevent division by zero  The user can set any speed value. If speed is greater than UINT_MAX/8, division by zero is possible.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37768?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37768" src="https://img.shields.io/badge/CVE--2025--37768-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/pm: Prevent division by zero  The user can set any speed value. If speed is greater than UINT_MAX/8, division by zero is possible.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37767?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37767" src="https://img.shields.io/badge/CVE--2025--37767-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/pm: Prevent division by zero  The user can set any speed value. If speed is greater than UINT_MAX/8, division by zero is possible.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37766?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37766" src="https://img.shields.io/badge/CVE--2025--37766-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amd/pm: Prevent division by zero  The user can set any speed value. If speed is greater than UINT_MAX/8, division by zero is possible.  Found by Linux Verification Center (linuxtesting.org) with SVACE.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37765?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37765" src="https://img.shields.io/badge/CVE--2025--37765-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/nouveau: prime: fix ttm_bo_delayed_delete oops  Fix an oops in ttm_bo_delayed_delete which results from dererencing a dangling pointer:  Oops: general protection fault, probably for non-canonical address 0x6b6b6b6b6b6b6b7b: 0000 [#1] PREEMPT SMP CPU: 4 UID: 0 PID: 1082 Comm: kworker/u65:2 Not tainted 6.14.0-rc4-00267-g505460b44513-dirty #216 Hardware name: LENOVO 82N6/LNVNB161216, BIOS GKCN65WW 01/16/2024 Workqueue: ttm ttm_bo_delayed_delete [ttm] RIP: 0010:dma_resv_iter_first_unlocked+0x55/0x290 Code: 31 f6 48 c7 c7 00 2b fa aa e8 97 bd 52 ff e8 a2 c1 53 00 5a 85 c0 74 48 e9 88 01 00 00 4c 89 63 20 4d 85 e4 0f 84 30 01 00 00 <41> 8b 44 24 10 c6 43 2c 01 48 89 df 89 43 28 e8 97 fd ff ff 4c 8b RSP: 0018:ffffbf9383473d60 EFLAGS: 00010202 RAX: 0000000000000001 RBX: ffffbf9383473d88 RCX: 0000000000000000 RDX: 0000000000000000 RSI: 0000000000000000 RDI: 0000000000000000 RBP: ffffbf9383473d78 R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000000 R12: 6b6b6b6b6b6b6b6b R13: ffffa003bbf78580 R14: ffffa003a6728040 R15: 00000000000383cc FS:  0000000000000000(0000) GS:ffffa00991c00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000758348024dd0 CR3: 000000012c259000 CR4: 0000000000f50ef0 PKRU: 55555554 Call Trace: <TASK> ? __die_body.cold+0x19/0x26 ? die_addr+0x3d/0x70 ? exc_general_protection+0x159/0x460 ? asm_exc_general_protection+0x27/0x30 ? dma_resv_iter_first_unlocked+0x55/0x290 dma_resv_wait_timeout+0x56/0x100 ttm_bo_delayed_delete+0x69/0xb0 [ttm] process_one_work+0x217/0x5c0 worker_thread+0x1c8/0x3d0 ? apply_wqattrs_cleanup.part.0+0xc0/0xc0 kthread+0x10b/0x240 ? kthreads_online_cpu+0x140/0x140 ret_from_fork+0x40/0x70 ? kthreads_online_cpu+0x140/0x140 ret_from_fork_asm+0x11/0x20 </TASK>  The cause of this is:  - drm_prime_gem_destroy calls dma_buf_put(dma_buf) which releases the reference to the shared dma_buf. The reference count is 0, so the dma_buf is destroyed, which in turn decrements the corresponding amdgpu_bo reference count to 0, and the amdgpu_bo is destroyed - calling drm_gem_object_release then dma_resv_fini (which destroys the reservation object), then finally freeing the amdgpu_bo.  - nouveau_bo obj->bo.base.resv is now a dangling pointer to the memory formerly allocated to the amdgpu_bo.  - nouveau_gem_object_del calls ttm_bo_put(&nvbo->bo) which calls ttm_bo_release, which schedules ttm_bo_delayed_delete.  - ttm_bo_delayed_delete runs and dereferences the dangling resv pointer, resulting in a general protection fault.  Fix this by moving the drm_prime_gem_destroy call from nouveau_gem_object_del to nouveau_bo_del_ttm. This ensures that it will be run after ttm_bo_delayed_delete.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37758?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37758" src="https://img.shields.io/badge/CVE--2025--37758-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ata: pata_pxa: Fix potential NULL pointer dereference in pxa_ata_probe()  devm_ioremap() returns NULL on error. Currently, pxa_ata_probe() does not check for this case, which can result in a NULL pointer dereference.  Add NULL check after devm_ioremap() to prevent this issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37757?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37757" src="https://img.shields.io/badge/CVE--2025--37757-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tipc: fix memory leak in tipc_link_xmit  In case the backlog transmit queue for system-importance messages is overloaded, tipc_link_xmit() returns -ENOBUFS but the skb list is not purged. This leads to memory leak and failure when a skb is allocated.  This commit fixes this issue by purging the skb list before tipc_link_xmit() returns.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37756?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37756" src="https://img.shields.io/badge/CVE--2025--37756-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: tls: explicitly disallow disconnect  syzbot discovered that it can disconnect a TLS socket and then run into all sort of unexpected corner cases. I have a vague recollection of Eric pointing this out to us a long time ago. Supporting disconnect is really hard, for one thing if offload is enabled we'd need to wait for all packets to be _acked_. Disconnect is not commonly used, disallow it.  The immediate problem syzbot run into is the warning in the strp, but that's just the easiest bug to trigger:  WARNING: CPU: 0 PID: 5834 at net/tls/tls_strp.c:486 tls_strp_msg_load+0x72e/0xa80 net/tls/tls_strp.c:486 RIP: 0010:tls_strp_msg_load+0x72e/0xa80 net/tls/tls_strp.c:486 Call Trace: <TASK> tls_rx_rec_wait+0x280/0xa60 net/tls/tls_sw.c:1363 tls_sw_recvmsg+0x85c/0x1c30 net/tls/tls_sw.c:2043 inet6_recvmsg+0x2c9/0x730 net/ipv6/af_inet6.c:678 sock_recvmsg_nosec net/socket.c:1023 [inline] sock_recvmsg+0x109/0x280 net/socket.c:1045 __sys_recvfrom+0x202/0x380 net/socket.c:2237

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37749?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37749" src="https://img.shields.io/badge/CVE--2025--37749-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: ppp: Add bound checking for skb data on ppp_sync_txmung  Ensure we have enough data in linear buffer from skb before accessing initial bytes. This prevents potential out-of-bounds accesses when processing short packets.  When ppp_sync_txmung receives an incoming package with an empty payload: (remote) gef➤  p *(struct pppoe_hdr *) (skb->head + skb->network_header) $18 = { type = 0x1, ver = 0x1, code = 0x0, sid = 0x2, length = 0x0, tag = 0xffff8880371cdb96 }  from the skb struct (trimmed) tail = 0x16, end = 0x140, head = 0xffff88803346f400 "4", data = 0xffff88803346f416 ":\377", truesize = 0x380, len = 0x0, data_len = 0x0, mac_len = 0xe, hdr_len = 0x0,  it is not safe to access data[2].  [pabeni@redhat.com: fixed subj typo]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37742?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37742" src="https://img.shields.io/badge/CVE--2025--37742-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jfs: Fix uninit-value access of imap allocated in the diMount() function  syzbot reports that hex_dump_to_buffer is using uninit-value:  ===================================================== BUG: KMSAN: uninit-value in hex_dump_to_buffer+0x888/0x1100 lib/hexdump.c:171 hex_dump_to_buffer+0x888/0x1100 lib/hexdump.c:171 print_hex_dump+0x13d/0x3e0 lib/hexdump.c:276 diFree+0x5ba/0x4350 fs/jfs/jfs_imap.c:876 jfs_evict_inode+0x510/0x550 fs/jfs/inode.c:156 evict+0x723/0xd10 fs/inode.c:796 iput_final fs/inode.c:1946 [inline] iput+0x97b/0xdb0 fs/inode.c:1972 txUpdateMap+0xf3e/0x1150 fs/jfs/jfs_txnmgr.c:2367 txLazyCommit fs/jfs/jfs_txnmgr.c:2664 [inline] jfs_lazycommit+0x627/0x11d0 fs/jfs/jfs_txnmgr.c:2733 kthread+0x6b9/0xef0 kernel/kthread.c:464 ret_from_fork+0x6d/0x90 arch/x86/kernel/process.c:148 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244  Uninit was created at: slab_post_alloc_hook mm/slub.c:4121 [inline] slab_alloc_node mm/slub.c:4164 [inline] __kmalloc_cache_noprof+0x8e3/0xdf0 mm/slub.c:4320 kmalloc_noprof include/linux/slab.h:901 [inline] diMount+0x61/0x7f0 fs/jfs/jfs_imap.c:105 jfs_mount+0xa8e/0x11d0 fs/jfs/jfs_mount.c:176 jfs_fill_super+0xa47/0x17c0 fs/jfs/super.c:523 get_tree_bdev_flags+0x6ec/0x910 fs/super.c:1636 get_tree_bdev+0x37/0x50 fs/super.c:1659 jfs_get_tree+0x34/0x40 fs/jfs/super.c:635 vfs_get_tree+0xb1/0x5a0 fs/super.c:1814 do_new_mount+0x71f/0x15e0 fs/namespace.c:3560 path_mount+0x742/0x1f10 fs/namespace.c:3887 do_mount fs/namespace.c:3900 [inline] __do_sys_mount fs/namespace.c:4111 [inline] __se_sys_mount+0x71f/0x800 fs/namespace.c:4088 __x64_sys_mount+0xe4/0x150 fs/namespace.c:4088 x64_sys_call+0x39bf/0x3c30 arch/x86/include/generated/asm/syscalls_64.h:166 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xcd/0x1e0 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f =====================================================  The reason is that imap is not properly initialized after memory allocation. It will cause the snprintf() function to write uninitialized data into linebuf within hex_dump_to_buffer().  Fix this by using kzalloc instead of kmalloc to clear its content at the beginning in diMount().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37741?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37741" src="https://img.shields.io/badge/CVE--2025--37741-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jfs: Prevent copying of nlink with value 0 from disk inode  syzbot report a deadlock in diFree. [1]  When calling "ioctl$LOOP_SET_STATUS64", the offset value passed in is 4, which does not match the mounted loop device, causing the mapping of the mounted loop device to be invalidated.  When creating the directory and creating the inode of iag in diReadSpecial(), read the page of fixed disk inode (AIT) in raw mode in read_metapage(), the metapage data it returns is corrupted, which causes the nlink value of 0 to be assigned to the iag inode when executing copy_from_dinode(), which ultimately causes a deadlock when entering diFree().  To avoid this, first check the nlink value of dinode before setting iag inode.  [1] WARNING: possible recursive locking detected 6.12.0-rc7-syzkaller-00212-g4a5df3796467 #0 Not tainted -------------------------------------------- syz-executor301/5309 is trying to acquire lock: ffff888044548920 (&(imap->im_aglock[index])){+.+.}-{3:3}, at: diFree+0x37c/0x2fb0 fs/jfs/jfs_imap.c:889  but task is already holding lock: ffff888044548920 (&(imap->im_aglock[index])){+.+.}-{3:3}, at: diAlloc+0x1b6/0x1630  other info that might help us debug this: Possible unsafe locking scenario:  CPU0 ---- lock(&(imap->im_aglock[index])); lock(&(imap->im_aglock[index]));  *** DEADLOCK ***  May be due to missing lock nesting notation  5 locks held by syz-executor301/5309: #0: ffff8880422a4420 (sb_writers#9){.+.+}-{0:0}, at: mnt_want_write+0x3f/0x90 fs/namespace.c:515 #1: ffff88804755b390 (&type->i_mutex_dir_key#6/1){+.+.}-{3:3}, at: inode_lock_nested include/linux/fs.h:850 [inline] #1: ffff88804755b390 (&type->i_mutex_dir_key#6/1){+.+.}-{3:3}, at: filename_create+0x260/0x540 fs/namei.c:4026 #2: ffff888044548920 (&(imap->im_aglock[index])){+.+.}-{3:3}, at: diAlloc+0x1b6/0x1630 #3: ffff888044548890 (&imap->im_freelock){+.+.}-{3:3}, at: diNewIAG fs/jfs/jfs_imap.c:2460 [inline] #3: ffff888044548890 (&imap->im_freelock){+.+.}-{3:3}, at: diAllocExt fs/jfs/jfs_imap.c:1905 [inline] #3: ffff888044548890 (&imap->im_freelock){+.+.}-{3:3}, at: diAllocAG+0x4b7/0x1e50 fs/jfs/jfs_imap.c:1669 #4: ffff88804755a618 (&jfs_ip->rdwrlock/1){++++}-{3:3}, at: diNewIAG fs/jfs/jfs_imap.c:2477 [inline] #4: ffff88804755a618 (&jfs_ip->rdwrlock/1){++++}-{3:3}, at: diAllocExt fs/jfs/jfs_imap.c:1905 [inline] #4: ffff88804755a618 (&jfs_ip->rdwrlock/1){++++}-{3:3}, at: diAllocAG+0x869/0x1e50 fs/jfs/jfs_imap.c:1669  stack backtrace: CPU: 0 UID: 0 PID: 5309 Comm: syz-executor301 Not tainted 6.12.0-rc7-syzkaller-00212-g4a5df3796467 #0 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS 1.16.3-debian-1.16.3-2~bpo12+1 04/01/2014 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_deadlock_bug+0x483/0x620 kernel/locking/lockdep.c:3037 check_deadlock kernel/locking/lockdep.c:3089 [inline] validate_chain+0x15e2/0x5920 kernel/locking/lockdep.c:3891 __lock_acquire+0x1384/0x2050 kernel/locking/lockdep.c:5202 lock_acquire+0x1ed/0x550 kernel/locking/lockdep.c:5825 __mutex_lock_common kernel/locking/mutex.c:608 [inline] __mutex_lock+0x136/0xd70 kernel/locking/mutex.c:752 diFree+0x37c/0x2fb0 fs/jfs/jfs_imap.c:889 jfs_evict_inode+0x32d/0x440 fs/jfs/inode.c:156 evict+0x4e8/0x9b0 fs/inode.c:725 diFreeSpecial fs/jfs/jfs_imap.c:552 [inline] duplicateIXtree+0x3c6/0x550 fs/jfs/jfs_imap.c:3022 diNewIAG fs/jfs/jfs_imap.c:2597 [inline] diAllocExt fs/jfs/jfs_imap.c:1905 [inline] diAllocAG+0x17dc/0x1e50 fs/jfs/jfs_imap.c:1669 diAlloc+0x1d2/0x1630 fs/jfs/jfs_imap.c:1590 ialloc+0x8f/0x900 fs/jfs/jfs_inode.c:56 jfs_mkdir+0x1c5/0xba0 fs/jfs/namei.c:225 vfs_mkdir+0x2f9/0x4f0 fs/namei.c:4257 do_mkdirat+0x264/0x3a0 fs/namei.c:4280 __do_sys_mkdirat fs/namei.c:4295 [inline] __se_sys_mkdirat fs/namei.c:4293 [inline] __x64_sys_mkdirat+0x87/0xa0 fs/namei.c:4293 do_syscall_x64 arch/x86/en ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37740?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37740" src="https://img.shields.io/badge/CVE--2025--37740-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  jfs: add sanity check for agwidth in dbMount  The width in dmapctl of the AG is zero, it trigger a divide error when calculating the control page level in dbAllocAG.  To avoid this issue, add a check for agwidth in dbAllocAG.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37739?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37739" src="https://img.shields.io/badge/CVE--2025--37739-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  f2fs: fix to avoid out-of-bounds access in f2fs_truncate_inode_blocks()  syzbot reports an UBSAN issue as below:  ------------[ cut here ]------------ UBSAN: array-index-out-of-bounds in fs/f2fs/node.h:381:10 index 18446744073709550692 is out of range for type '__le32[5]' (aka 'unsigned int[5]') CPU: 0 UID: 0 PID: 5318 Comm: syz.0.0 Not tainted 6.14.0-rc3-syzkaller-00060-g6537cfb395f3 #0 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 ubsan_epilogue lib/ubsan.c:231 [inline] __ubsan_handle_out_of_bounds+0x121/0x150 lib/ubsan.c:429 get_nid fs/f2fs/node.h:381 [inline] f2fs_truncate_inode_blocks+0xa5e/0xf60 fs/f2fs/node.c:1181 f2fs_do_truncate_blocks+0x782/0x1030 fs/f2fs/file.c:808 f2fs_truncate_blocks+0x10d/0x300 fs/f2fs/file.c:836 f2fs_truncate+0x417/0x720 fs/f2fs/file.c:886 f2fs_file_write_iter+0x1bdb/0x2550 fs/f2fs/file.c:5093 aio_write+0x56b/0x7c0 fs/aio.c:1633 io_submit_one+0x8a7/0x18a0 fs/aio.c:2052 __do_sys_io_submit fs/aio.c:2111 [inline] __se_sys_io_submit+0x171/0x2e0 fs/aio.c:2081 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7f238798cde9  index 18446744073709550692 (decimal, unsigned long long) = 0xfffffffffffffc64 (hexadecimal, unsigned long long) = -924 (decimal, long long)  In f2fs_truncate_inode_blocks(), UBSAN detects that get_nid() tries to access .i_nid[-924], it means both offset[0] and level should zero.  The possible case should be in f2fs_do_truncate_blocks(), we try to truncate inode size to zero, however, dn.ofs_in_node is zero and dn.node_page is not an inode page, so it fails to truncate inode page, and then pass zeroed free_from to f2fs_truncate_inode_blocks(), result in this issue.  if (dn.ofs_in_node || IS_INODE(dn.node_page)) { f2fs_truncate_data_blocks_range(&dn, count); free_from += count; }  I guess the reason why dn.node_page is not an inode page could be: there are multiple nat entries share the same node block address, once the node block address was reused, f2fs_get_node_page() may load a non-inode block.  Let's add a sanity check for such condition to avoid out-of-bounds access issue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-37738?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--37738" src="https://img.shields.io/badge/CVE--2025--37738-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ext4: ignore xattrs past end  Once inside 'ext4_xattr_inode_dec_ref_all' we should ignore xattrs entries past the 'end' entry.  This fixes the following KASAN reported issue:  ================================================================== BUG: KASAN: slab-use-after-free in ext4_xattr_inode_dec_ref_all+0xb8c/0xe90 Read of size 4 at addr ffff888012c120c4 by task repro/2065  CPU: 1 UID: 0 PID: 2065 Comm: repro Not tainted 6.13.0-rc2+ #11 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.16.3-0-ga6ed6b701f0a-prebuilt.qemu.org 04/01/2014 Call Trace: <TASK> dump_stack_lvl+0x1fd/0x300 ? tcp_gro_dev_warn+0x260/0x260 ? _printk+0xc0/0x100 ? read_lock_is_recursive+0x10/0x10 ? irq_work_queue+0x72/0xf0 ? __virt_addr_valid+0x17b/0x4b0 print_address_description+0x78/0x390 print_report+0x107/0x1f0 ? __virt_addr_valid+0x17b/0x4b0 ? __virt_addr_valid+0x3ff/0x4b0 ? __phys_addr+0xb5/0x160 ? ext4_xattr_inode_dec_ref_all+0xb8c/0xe90 kasan_report+0xcc/0x100 ? ext4_xattr_inode_dec_ref_all+0xb8c/0xe90 ext4_xattr_inode_dec_ref_all+0xb8c/0xe90 ? ext4_xattr_delete_inode+0xd30/0xd30 ? __ext4_journal_ensure_credits+0x5f0/0x5f0 ? __ext4_journal_ensure_credits+0x2b/0x5f0 ? inode_update_timestamps+0x410/0x410 ext4_xattr_delete_inode+0xb64/0xd30 ? ext4_truncate+0xb70/0xdc0 ? ext4_expand_extra_isize_ea+0x1d20/0x1d20 ? __ext4_mark_inode_dirty+0x670/0x670 ? ext4_journal_check_start+0x16f/0x240 ? ext4_inode_is_fast_symlink+0x2f2/0x3a0 ext4_evict_inode+0xc8c/0xff0 ? ext4_inode_is_fast_symlink+0x3a0/0x3a0 ? do_raw_spin_unlock+0x53/0x8a0 ? ext4_inode_is_fast_symlink+0x3a0/0x3a0 evict+0x4ac/0x950 ? proc_nr_inodes+0x310/0x310 ? trace_ext4_drop_inode+0xa2/0x220 ? _raw_spin_unlock+0x1a/0x30 ? iput+0x4cb/0x7e0 do_unlinkat+0x495/0x7c0 ? try_break_deleg+0x120/0x120 ? 0xffffffff81000000 ? __check_object_size+0x15a/0x210 ? strncpy_from_user+0x13e/0x250 ? getname_flags+0x1dc/0x530 __x64_sys_unlinkat+0xc8/0xf0 do_syscall_64+0x65/0x110 entry_SYSCALL_64_after_hwframe+0x67/0x6f RIP: 0033:0x434ffd Code: 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 8 RSP: 002b:00007ffc50fa7b28 EFLAGS: 00000246 ORIG_RAX: 0000000000000107 RAX: ffffffffffffffda RBX: 00007ffc50fa7e18 RCX: 0000000000434ffd RDX: 0000000000000000 RSI: 0000000020000240 RDI: 0000000000000005 RBP: 00007ffc50fa7be0 R08: 0000000000000000 R09: 0000000000000000 R10: 0000000000000000 R11: 0000000000000246 R12: 0000000000000001 R13: 00007ffc50fa7e08 R14: 00000000004bbf30 R15: 0000000000000001 </TASK>  The buggy address belongs to the object at ffff888012c12000 which belongs to the cache filp of size 360 The buggy address is located 196 bytes inside of freed 360-byte region [ffff888012c12000, ffff888012c12168)  The buggy address belongs to the physical page: page: refcount:1 mapcount:0 mapping:0000000000000000 index:0x0 pfn:0x12c12 head: order:1 mapcount:0 entire_mapcount:0 nr_pages_mapped:0 pincount:0 flags: 0x40(head|node=0|zone=0) page_type: f5(slab) raw: 0000000000000040 ffff888000ad7640 ffffea0000497a00 dead000000000004 raw: 0000000000000000 0000000000100010 00000001f5000000 0000000000000000 head: 0000000000000040 ffff888000ad7640 ffffea0000497a00 dead000000000004 head: 0000000000000000 0000000000100010 00000001f5000000 0000000000000000 head: 0000000000000001 ffffea00004b0481 ffffffffffffffff 0000000000000000 head: 0000000000000002 0000000000000000 00000000ffffffff 0000000000000000 page dumped because: kasan: bad access detected  Memory state around the buggy address: ffff888012c11f80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ffff888012c12000: fa fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb > ffff888012c12080: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb ^ ffff888012c12100: fb fb fb fb fb fb fb fb fb fb fb fb fb fc fc fc ffff888012c12180: fc fc fc fc fc fc fc fc fc ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23163?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23163" src="https://img.shields.io/badge/CVE--2025--23163-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: vlan: don't propagate flags on open  With the device instance lock, there is now a possibility of a deadlock:  [    1.211455] ============================================ [    1.211571] WARNING: possible recursive locking detected [    1.211687] 6.14.0-rc5-01215-g032756b4ca7a-dirty #5 Not tainted [    1.211823] -------------------------------------------- [    1.211936] ip/184 is trying to acquire lock: [    1.212032] ffff8881024a4c30 (&dev->lock){+.+.}-{4:4}, at: dev_set_allmulti+0x4e/0xb0 [    1.212207] [    1.212207] but task is already holding lock: [    1.212332] ffff8881024a4c30 (&dev->lock){+.+.}-{4:4}, at: dev_open+0x50/0xb0 [    1.212487] [    1.212487] other info that might help us debug this: [    1.212626]  Possible unsafe locking scenario: [    1.212626] [    1.212751]        CPU0 [    1.212815]        ---- [    1.212871]   lock(&dev->lock); [    1.212944]   lock(&dev->lock); [    1.213016] [    1.213016]  *** DEADLOCK *** [    1.213016] [    1.213143]  May be due to missing lock nesting notation [    1.213143] [    1.213294] 3 locks held by ip/184: [    1.213371]  #0: ffffffff838b53e0 (rtnl_mutex){+.+.}-{4:4}, at: rtnl_nets_lock+0x1b/0xa0 [    1.213543]  #1: ffffffff84e5fc70 (&net->rtnl_mutex){+.+.}-{4:4}, at: rtnl_nets_lock+0x37/0xa0 [    1.213727]  #2: ffff8881024a4c30 (&dev->lock){+.+.}-{4:4}, at: dev_open+0x50/0xb0 [    1.213895] [    1.213895] stack backtrace: [    1.213991] CPU: 0 UID: 0 PID: 184 Comm: ip Not tainted 6.14.0-rc5-01215-g032756b4ca7a-dirty #5 [    1.213993] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS Arch Linux 1.16.3-1-1 04/01/2014 [    1.213994] Call Trace: [    1.213995]  <TASK> [    1.213996]  dump_stack_lvl+0x8e/0xd0 [    1.214000]  print_deadlock_bug+0x28b/0x2a0 [    1.214020]  lock_acquire+0xea/0x2a0 [    1.214027]  __mutex_lock+0xbf/0xd40 [    1.214038]  dev_set_allmulti+0x4e/0xb0 # real_dev->flags & IFF_ALLMULTI [    1.214040]  vlan_dev_open+0xa5/0x170 # ndo_open on vlandev [    1.214042]  __dev_open+0x145/0x270 [    1.214046]  __dev_change_flags+0xb0/0x1e0 [    1.214051]  netif_change_flags+0x22/0x60 # IFF_UP vlandev [    1.214053]  dev_change_flags+0x61/0xb0 # for each device in group from dev->vlan_info [    1.214055]  vlan_device_event+0x766/0x7c0 # on netdevsim0 [    1.214058]  notifier_call_chain+0x78/0x120 [    1.214062]  netif_open+0x6d/0x90 [    1.214064]  dev_open+0x5b/0xb0 # locks netdevsim0 [    1.214066]  bond_enslave+0x64c/0x1230 [    1.214075]  do_set_master+0x175/0x1e0 # on netdevsim0 [    1.214077]  do_setlink+0x516/0x13b0 [    1.214094]  rtnl_newlink+0xaba/0xb80 [    1.214132]  rtnetlink_rcv_msg+0x440/0x490 [    1.214144]  netlink_rcv_skb+0xeb/0x120 [    1.214150]  netlink_unicast+0x1f9/0x320 [    1.214153]  netlink_sendmsg+0x346/0x3f0 [    1.214157]  __sock_sendmsg+0x86/0xb0 [    1.214160]  ____sys_sendmsg+0x1c8/0x220 [    1.214164]  ___sys_sendmsg+0x28f/0x2d0 [    1.214179]  __x64_sys_sendmsg+0xef/0x140 [    1.214184]  do_syscall_64+0xec/0x1d0 [    1.214190]  entry_SYSCALL_64_after_hwframe+0x77/0x7f [    1.214191] RIP: 0033:0x7f2d1b4a7e56  Device setup:  netdevsim0 (down) ^        ^ bond        netdevsim1.100@netdevsim1 allmulticast=on (down)  When we enslave the lower device (netdevsim0) which has a vlan, we propagate vlan's allmuti/promisc flags during ndo_open. This causes (re)locking on of the real_dev.  Propagate allmulti/promisc on flags change, not on the open. There is a slight semantics change that vlans that are down now propagate the flags, but this seems unlikely to result in the real issues.  Reproducer:  echo 0 1 > /sys/bus/netdevsim/new_device  dev_path=$(ls -d /sys/bus/netdevsim/devices/netdevsim0/net/*) dev=$(echo $dev_path | rev | cut -d/ -f1 | rev)  ip link set dev $dev name netdevsim0 ip link set dev netdevsim0 up  ip link add link netdevsim0 name netdevsim0.100 type vlan id 100 ip link set dev netdevsim0.100 allm ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23161?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23161" src="https://img.shields.io/badge/CVE--2025--23161-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  PCI: vmd: Make vmd_dev::cfg_lock a raw_spinlock_t type  The access to the PCI config space via pci_ops::read and pci_ops::write is a low-level hardware access. The functions can be accessed with disabled interrupts even on PREEMPT_RT. The pci_lock is a raw_spinlock_t for this purpose.  A spinlock_t becomes a sleeping lock on PREEMPT_RT, so it cannot be acquired with disabled interrupts. The vmd_dev::cfg_lock is accessed in the same context as the pci_lock.  Make vmd_dev::cfg_lock a raw_spinlock_t type so it can be used with interrupts disabled.  This was reported as:  BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48 Call Trace: rt_spin_lock+0x4e/0x130 vmd_pci_read+0x8d/0x100 [vmd] pci_user_read_config_byte+0x6f/0xe0 pci_read_config+0xfe/0x290 sysfs_kf_bin_read+0x68/0x90  [bigeasy: reword commit message] Tested-off-by: Luis Claudio R. Goncalves <lgoncalv@redhat.com> [kwilczynski: commit log] [bhelgaas: add back report info from https://lore.kernel.org/lkml/20241218115951.83062-1-ryotkkr98@gmail.com/]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23159?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23159" src="https://img.shields.io/badge/CVE--2025--23159-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: venus: hfi: add a check to handle OOB in sfr region  sfr->buf_size is in shared memory and can be modified by malicious user. OOB write is possible when the size is made higher than actual sfr data buffer. Cap the size to allocated size for such cases.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23158?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23158" src="https://img.shields.io/badge/CVE--2025--23158-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: venus: hfi: add check to handle incorrect queue size  qsize represents size of shared queued between driver and video firmware. Firmware can modify this value to an invalid large value. In such situation, empty_space will be bigger than the space actually available. Since new_wr_idx is not checked, so the following code will result in an OOB write. ... qsize = qhdr->q_size  if (wr_idx >= rd_idx) empty_space = qsize - (wr_idx - rd_idx) .... if (new_wr_idx < qsize) { memcpy(wr_ptr, packet, dwords << 2) --> OOB write  Add check to ensure qsize is within the allocated size while reading and writing packets into the queue.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23157?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23157" src="https://img.shields.io/badge/CVE--2025--23157-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: venus: hfi_parser: add check to avoid out of bound access  There is a possibility that init_codecs is invoked multiple times during manipulated payload from video firmware. In such case, if codecs_count can get incremented to value more than MAX_CODEC_NUM, there can be OOB access. Reset the count so that it always starts from beginning.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23156?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23156" src="https://img.shields.io/badge/CVE--2025--23156-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: venus: hfi_parser: refactor hfi packet parsing logic  words_count denotes the number of words in total payload, while data points to payload of various property within it. When words_count reaches last word, data can access memory beyond the total payload. This can lead to OOB access. With this patch, the utility api for handling individual properties now returns the size of data consumed. Accordingly remaining bytes are calculated before parsing the payload, thereby eliminates the OOB access possibilities.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23151?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23151" src="https://img.shields.io/badge/CVE--2025--23151-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bus: mhi: host: Fix race between unprepare and queue_buf  A client driver may use mhi_unprepare_from_transfer() to quiesce incoming data during the client driver's tear down. The client driver might also be processing data at the same time, resulting in a call to mhi_queue_buf() which will invoke mhi_gen_tre(). If mhi_gen_tre() runs after mhi_unprepare_from_transfer() has torn down the channel, a panic will occur due to an invalid dereference leading to a page fault.  This occurs because mhi_gen_tre() does not verify the channel state after locking it. Fix this by having mhi_gen_tre() confirm the channel state is valid, or return error to avoid accessing deinitialized data.  [mani: added stable tag]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23150?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23150" src="https://img.shields.io/badge/CVE--2025--23150-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ext4: fix off-by-one error in do_split  Syzkaller detected a use-after-free issue in ext4_insert_dentry that was caused by out-of-bounds access due to incorrect splitting in do_split.  BUG: KASAN: use-after-free in ext4_insert_dentry+0x36a/0x6d0 fs/ext4/namei.c:2109 Write of size 251 at addr ffff888074572f14 by task syz-executor335/5847  CPU: 0 UID: 0 PID: 5847 Comm: syz-executor335 Not tainted 6.12.0-rc6-syzkaller-00318-ga9cda7c0ffed #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 10/30/2024 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:377 [inline] print_report+0x169/0x550 mm/kasan/report.c:488 kasan_report+0x143/0x180 mm/kasan/report.c:601 kasan_check_range+0x282/0x290 mm/kasan/generic.c:189 __asan_memcpy+0x40/0x70 mm/kasan/shadow.c:106 ext4_insert_dentry+0x36a/0x6d0 fs/ext4/namei.c:2109 add_dirent_to_buf+0x3d9/0x750 fs/ext4/namei.c:2154 make_indexed_dir+0xf98/0x1600 fs/ext4/namei.c:2351 ext4_add_entry+0x222a/0x25d0 fs/ext4/namei.c:2455 ext4_add_nondir+0x8d/0x290 fs/ext4/namei.c:2796 ext4_symlink+0x920/0xb50 fs/ext4/namei.c:3431 vfs_symlink+0x137/0x2e0 fs/namei.c:4615 do_symlinkat+0x222/0x3a0 fs/namei.c:4641 __do_sys_symlink fs/namei.c:4662 [inline] __se_sys_symlink fs/namei.c:4660 [inline] __x64_sys_symlink+0x7a/0x90 fs/namei.c:4660 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f </TASK>  The following loop is located right above 'if' statement.  for (i = count-1; i >= 0; i--) { /* is more than half of this entry in 2nd half of the block? */ if (size + map[i].size/2 > blocksize/2) break; size += map[i].size; move++; }  'i' in this case could go down to -1, in which case sum of active entries wouldn't exceed half the block size, but previous behaviour would also do split in half if sum would exceed at the very last block, which in case of having too many long name files in a single block could lead to out-of-bounds access and following use-after-free.  Found by Linux Verification Center (linuxtesting.org) with Syzkaller.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23148?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23148" src="https://img.shields.io/badge/CVE--2025--23148-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  soc: samsung: exynos-chipid: Add NULL pointer check in exynos_chipid_probe()  soc_dev_attr->revision could be NULL, thus, a pointer check is added to prevent potential NULL pointer dereference. This is similar to the fix in commit 3027e7b15b02 ("ice: Fix some null pointer dereference issues in ice_ptp.c").  This issue is found by our static analysis tool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23147?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23147" src="https://img.shields.io/badge/CVE--2025--23147-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.061%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  i3c: Add NULL pointer check in i3c_master_queue_ibi()  The I3C master driver may receive an IBI from a target device that has not been probed yet. In such cases, the master calls `i3c_master_queue_ibi()` to queue an IBI work task, leading to "Unable to handle kernel read from unreadable memory" and resulting in a kernel panic.  Typical IBI handling flow: 1. The I3C master scans target devices and probes their respective drivers. 2. The target device driver calls `i3c_device_request_ibi()` to enable IBI and assigns `dev->ibi = ibi`. 3. The I3C master receives an IBI from the target device and calls `i3c_master_queue_ibi()` to queue the target device driver’s IBI handler task.  However, since target device events are asynchronous to the I3C probe sequence, step 3 may occur before step 2, causing `dev->ibi` to be `NULL`, leading to a kernel panic.  Add a NULL pointer check in `i3c_master_queue_ibi()` to prevent accessing an uninitialized `dev->ibi`, ensuring stability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23146?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23146" src="https://img.shields.io/badge/CVE--2025--23146-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mfd: ene-kb3930: Fix a potential NULL pointer dereference  The off_gpios could be NULL. Add missing check in the kb3930_probe(). This is similar to the issue fixed in commit b1ba8bcb2d1f ("backlight: hx8357: Fix potential NULL pointer dereference").  This was detected by our static analysis tool.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23145?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23145" src="https://img.shields.io/badge/CVE--2025--23145-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: fix NULL pointer in can_accept_new_subflow  When testing valkey benchmark tool with MPTCP, the kernel panics in 'mptcp_can_accept_new_subflow' because subflow_req->msk is NULL.  Call trace:  mptcp_can_accept_new_subflow (./net/mptcp/subflow.c:63 (discriminator 4)) (P) subflow_syn_recv_sock (./net/mptcp/subflow.c:854) tcp_check_req (./net/ipv4/tcp_minisocks.c:863) tcp_v4_rcv (./net/ipv4/tcp_ipv4.c:2268) ip_protocol_deliver_rcu (./net/ipv4/ip_input.c:207) ip_local_deliver_finish (./net/ipv4/ip_input.c:234) ip_local_deliver (./net/ipv4/ip_input.c:254) ip_rcv_finish (./net/ipv4/ip_input.c:449) ...  According to the debug log, the same req received two SYN-ACK in a very short time, very likely because the client retransmits the syn ack due to multiple reasons.  Even if the packets are transmitted with a relevant time interval, they can be processed by the server on different CPUs concurrently). The 'subflow_req->msk' ownership is transferred to the subflow the first, and there will be a risk of a null pointer dereference here.  This patch fixes this issue by moving the 'subflow_req->msk' under the `own_req == true` conditional.  Note that the !msk check in subflow_hmac_valid() can be dropped, because the same check already exists under the own_req mpj branch where the code has been moved to.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23144?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23144" src="https://img.shields.io/badge/CVE--2025--23144-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  backlight: led_bl: Hold led_access lock when calling led_sysfs_disable()  Lockdep detects the following issue on led-backlight removal: [  142.315935] ------------[ cut here ]------------ [  142.315954] WARNING: CPU: 2 PID: 292 at drivers/leds/led-core.c:455 led_sysfs_enable+0x54/0x80 ... [  142.500725] Call trace: [  142.503176]  led_sysfs_enable+0x54/0x80 (P) [  142.507370]  led_bl_remove+0x80/0xa8 [led_bl] [  142.511742]  platform_remove+0x30/0x58 [  142.515501]  device_remove+0x54/0x90 ...  Indeed, led_sysfs_enable() has to be called with the led_access lock held.  Hold the lock when calling led_sysfs_disable().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23142?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23142" src="https://img.shields.io/badge/CVE--2025--23142-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: detect and prevent references to a freed transport in sendmsg  sctp_sendmsg() re-uses associations and transports when possible by doing a lookup based on the socket endpoint and the message destination address, and then sctp_sendmsg_to_asoc() sets the selected transport in all the message chunks to be sent.  There's a possible race condition if another thread triggers the removal of that selected transport, for instance, by explicitly unbinding an address with setsockopt(SCTP_SOCKOPT_BINDX_REM), after the chunks have been set up and before the message is sent. This can happen if the send buffer is full, during the period when the sender thread temporarily releases the socket lock in sctp_wait_for_sndbuf().  This causes the access to the transport data in sctp_outq_select_transport(), when the association outqueue is flushed, to result in a use-after-free read.  This change avoids this scenario by having sctp_transport_free() signal the freeing of the transport, tagging it as "dead". In order to do this, the patch restores the "dead" bit in struct sctp_transport, which was removed in commit 47faa1e4c50e ("sctp: remove the dead field of sctp_transport").  Then, in the scenario where the sender thread has released the socket lock in sctp_wait_for_sndbuf(), the bit is checked again after re-acquiring the socket lock to detect the deletion. This is done while holding a reference to the transport to prevent it from being freed in the process.  If the transport was deleted while the socket lock was relinquished, sctp_sendmsg_to_asoc() will return -EAGAIN to let userspace retry the send.  The bug was found by a private syzbot instance (see the error report [1] and the C reproducer that triggers it [2]).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-23140?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--23140" src="https://img.shields.io/badge/CVE--2025--23140-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  misc: pci_endpoint_test: Avoid issue of interrupts remaining after request_irq error  After devm_request_irq() fails with error in pci_endpoint_test_request_irq(), the pci_endpoint_test_free_irq_vectors() is called assuming that all IRQs have been released.  However, some requested IRQs remain unreleased, so there are still /proc/irq/* entries remaining, and this results in WARN() with the following message:  remove_proc_entry: removing non-empty directory 'irq/30', leaking at least 'pci-endpoint-test.0' WARNING: CPU: 0 PID: 202 at fs/proc/generic.c:719 remove_proc_entry +0x190/0x19c  To solve this issue, set the number of remaining IRQs to test->num_irqs, and release IRQs in advance by calling pci_endpoint_test_release_irq().  [kwilczynski: commit log]

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
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
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

<a href="https://scout.docker.com/v/CVE-2025-21839?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2025--21839" src="https://img.shields.io/badge/CVE--2025--21839-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.093%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  KVM: x86: Load DR6 with guest value only before entering .vcpu_run() loop  Move the conditional loading of hardware DR6 with the guest's DR6 value out of the core .vcpu_run() loop to fix a bug where KVM can load hardware with a stale vcpu->arch.dr6.  When the guest accesses a DR and host userspace isn't debugging the guest, KVM disables DR interception and loads the guest's values into hardware on VM-Enter and saves them on VM-Exit.  This allows the guest to access DRs at will, e.g. so that a sequence of DR accesses to configure a breakpoint only generates one VM-Exit.  For DR0-DR3, the logic/behavior is identical between VMX and SVM, and also identical between KVM_DEBUGREG_BP_ENABLED (userspace debugging the guest) and KVM_DEBUGREG_WONT_EXIT (guest using DRs), and so KVM handles loading DR0-DR3 in common code, _outside_ of the core kvm_x86_ops.vcpu_run() loop.  But for DR6, the guest's value doesn't need to be loaded into hardware for KVM_DEBUGREG_BP_ENABLED, and SVM provides a dedicated VMCB field whereas VMX requires software to manually load the guest value, and so loading the guest's value into DR6 is handled by {svm,vmx}_vcpu_run(), i.e. is done _inside_ the core run loop.  Unfortunately, saving the guest values on VM-Exit is initiated by common x86, again outside of the core run loop.  If the guest modifies DR6 (in hardware, when DR interception is disabled), and then the next VM-Exit is a fastpath VM-Exit, KVM will reload hardware DR6 with vcpu->arch.dr6 and clobber the guest's actual value.  The bug shows up primarily with nested VMX because KVM handles the VMX preemption timer in the fastpath, and the window between hardware DR6 being modified (in guest context) and DR6 being read by guest software is orders of magnitude larger in a nested setup.  E.g. in non-nested, the VMX preemption timer would need to fire precisely between #DB injection and the #DB handler's read of DR6, whereas with a KVM-on-KVM setup, the window where hardware DR6 is "dirty" extends all the way from L1 writing DR6 to VMRESUME (in L1).  L1's view: ========== <L1 disables DR interception> CPU 0/KVM-7289    [023] d....  2925.640961: kvm_entry: vcpu 0 A:  L1 Writes DR6 CPU 0/KVM-7289    [023] d....  2925.640963: <hack>: Set DRs, DR6 = 0xffff0ff1  B:        CPU 0/KVM-7289    [023] d....  2925.640967: kvm_exit: vcpu 0 reason EXTERNAL_INTERRUPT intr_info 0x800000ec  D: L1 reads DR6, arch.dr6 = 0 CPU 0/KVM-7289    [023] d....  2925.640969: <hack>: Sync DRs, DR6 = 0xffff0ff0  CPU 0/KVM-7289    [023] d....  2925.640976: kvm_entry: vcpu 0 L2 reads DR6, L1 disables DR interception CPU 0/KVM-7289    [023] d....  2925.640980: kvm_exit: vcpu 0 reason DR_ACCESS info1 0x0000000000000216 CPU 0/KVM-7289    [023] d....  2925.640983: kvm_entry: vcpu 0  CPU 0/KVM-7289    [023] d....  2925.640983: <hack>: Set DRs, DR6 = 0xffff0ff0  L2 detects failure CPU 0/KVM-7289    [023] d....  2925.640987: kvm_exit: vcpu 0 reason HLT L1 reads DR6 (confirms failure) CPU 0/KVM-7289    [023] d....  2925.640990: <hack>: Sync DRs, DR6 = 0xffff0ff0  L0's view: ========== L2 reads DR6, arch.dr6 = 0 CPU 23/KVM-5046    [001] d....  3410.005610: kvm_exit: vcpu 23 reason DR_ACCESS info1 0x0000000000000216 CPU 23/KVM-5046    [001] .....  3410.005610: kvm_nested_vmexit: vcpu 23 reason DR_ACCESS info1 0x0000000000000216  L2 => L1 nested VM-Exit CPU 23/KVM-5046    [001] .....  3410.005610: kvm_nested_vmexit_inject: reason: DR_ACCESS ext_inf1: 0x0000000000000216  CPU 23/KVM-5046    [001] d....  3410.005610: kvm_entry: vcpu 23 CPU 23/KVM-5046    [001] d....  3410.005611: kvm_exit: vcpu 23 reason VMREAD CPU 23/KVM-5046    [001] d....  3410.005611: kvm_entry: vcpu 23 CPU 23/KVM-5046    [001] d....  3410. ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54458?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2024--54458" src="https://img.shields.io/badge/CVE--2024--54458-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: ufs: bsg: Set bsg_queue to NULL after removal  Currently, this does not cause any issues, but I believe it is necessary to set bsg_queue to NULL after removing it to prevent potential use-after-free (UAF) access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53144?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2024--53144" src="https://img.shields.io/badge/CVE--2024--53144-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.098%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>28th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: hci_event: Align BR/EDR JUST_WORKS paring with LE  This aligned BR/EDR JUST_WORKS method with LE which since 92516cd97fd4 ("Bluetooth: Always request for user confirmation for Just Works") always request user confirmation with confirm_hint set since the likes of bluetoothd have dedicated policy around JUST_WORKS method (e.g. main.conf:JustWorksRepairing).  CVE: CVE-2024-8805

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50280?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2024--50280" src="https://img.shields.io/badge/CVE--2024--50280-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dm cache: fix flushing uninitialized delayed_work on cache_ctr error  An unexpected WARN_ON from flush_work() may occur when cache creation fails, caused by destroying the uninitialized delayed_work waker in the error path of cache_create(). For example, the warning appears on the superblock checksum error.  Reproduce steps:  dmsetup create cmeta --table "0 8192 linear /dev/sdc 0" dmsetup create cdata --table "0 65536 linear /dev/sdc 8192" dmsetup create corig --table "0 524288 linear /dev/sdc 262144" dd if=/dev/urandom of=/dev/mapper/cmeta bs=4k count=1 oflag=direct dmsetup create cache --table "0 524288 cache /dev/mapper/cmeta \ /dev/mapper/cdata /dev/mapper/corig 128 2 metadata2 writethrough smq 0"  Kernel logs:  (snip) WARNING: CPU: 0 PID: 84 at kernel/workqueue.c:4178 __flush_work+0x5d4/0x890  Fix by pulling out the cancel_delayed_work_sync() from the constructor's error path. This patch doesn't affect the use-after-free fix for concurrent dm_resume and dm_destroy (commit 6a459d8edbdb ("dm cache: Fix UAF in destroy()")) as cache_dtr is not changed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-46753?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2024--46753" src="https://img.shields.io/badge/CVE--2024--46753-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.174%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>39th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: handle errors from btrfs_dec_ref() properly  In walk_up_proc() we BUG_ON(ret) from btrfs_dec_ref().  This is incorrect, we have proper error handling here, return the error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-42322?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2024--42322" src="https://img.shields.io/badge/CVE--2024--42322-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.286%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>52nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipvs: properly dereference pe in ip_vs_add_service  Use pe directly to resolve sparse warning:  net/netfilter/ipvs/ip_vs_ctl.c:1471:27: warning: dereference of noderef expression

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38541?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2024--38541" src="https://img.shields.io/badge/CVE--2024--38541-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.067%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>21st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: of: module: add buffer overflow check in of_modalias() In of_modalias(), if the buffer happens to be too small even for the 1st snprintf() call, the len parameter will become negative and str parameter (if not NULL initially) will point beyond the buffer's end. Add the buffer overflow check after the 1st snprintf() call and fix such check after the strlen() call (accounting for the terminating NUL char).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38540?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2024--38540" src="https://img.shields.io/badge/CVE--2024--38540-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.011%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: bnxt_re: avoid shift undefined behavior in bnxt_qplib_alloc_init_hwq Undefined behavior is triggered when bnxt_qplib_alloc_init_hwq is called with hwq_attr->aux_depth != 0 and hwq_attr->aux_stride == 0. In that case, "roundup_pow_of_two(hwq_attr->aux_stride)" gets called. roundup_pow_of_two is documented as undefined for 0. Fix it in the one caller that had this combination. The undefined behavior was detected by UBSAN: UBSAN: shift-out-of-bounds in ./include/linux/log2.h:57:13 shift exponent 64 is too large for 64-bit type 'long unsigned int' CPU: 24 PID: 1075 Comm: (udev-worker) Not tainted 6.9.0-rc6+ #4 Hardware name: Abacus electric, s.r.o. - servis@abacus.cz Super Server/H12SSW-iN, BIOS 2.7 10/25/2023 Call Trace: <TASK> dump_stack_lvl+0x5d/0x80 ubsan_epilogue+0x5/0x30 __ubsan_handle_shift_out_of_bounds.cold+0x61/0xec __roundup_pow_of_two+0x25/0x35 [bnxt_re] bnxt_qplib_alloc_init_hwq+0xa1/0x470 [bnxt_re] bnxt_qplib_create_qp+0x19e/0x840 [bnxt_re] bnxt_re_create_qp+0x9b1/0xcd0 [bnxt_re] ? srso_alias_return_thunk+0x5/0xfbef5 ? srso_alias_return_thunk+0x5/0xfbef5 ? __kmalloc+0x1b6/0x4f0 ? create_qp.part.0+0x128/0x1c0 [ib_core] ? __pfx_bnxt_re_create_qp+0x10/0x10 [bnxt_re] create_qp.part.0+0x128/0x1c0 [ib_core] ib_create_qp_kernel+0x50/0xd0 [ib_core] create_mad_qp+0x8e/0xe0 [ib_core] ? __pfx_qp_event_handler+0x10/0x10 [ib_core] ib_mad_init_device+0x2be/0x680 [ib_core] add_client_context+0x10d/0x1a0 [ib_core] enable_device_and_get+0xe0/0x1d0 [ib_core] ib_register_device+0x53c/0x630 [ib_core] ? srso_alias_return_thunk+0x5/0xfbef5 bnxt_re_probe+0xbd8/0xe50 [bnxt_re] ? __pfx_bnxt_re_probe+0x10/0x10 [bnxt_re] auxiliary_bus_probe+0x49/0x80 ? driver_sysfs_add+0x57/0xc0 really_probe+0xde/0x340 ? pm_runtime_barrier+0x54/0x90 ? __pfx___driver_attach+0x10/0x10 __driver_probe_device+0x78/0x110 driver_probe_device+0x1f/0xa0 __driver_attach+0xba/0x1c0 bus_for_each_dev+0x8f/0xe0 bus_add_driver+0x146/0x220 driver_register+0x72/0xd0 __auxiliary_driver_register+0x6e/0xd0 ? __pfx_bnxt_re_mod_init+0x10/0x10 [bnxt_re] bnxt_re_mod_init+0x3e/0xff0 [bnxt_re] ? __pfx_bnxt_re_mod_init+0x10/0x10 [bnxt_re] do_one_initcall+0x5b/0x310 do_init_module+0x90/0x250 init_module_from_file+0x86/0xc0 idempotent_init_module+0x121/0x2b0 __x64_sys_finit_module+0x5e/0xb0 do_syscall_64+0x82/0x160 ? srso_alias_return_thunk+0x5/0xfbef5 ? syscall_exit_to_user_mode_prepare+0x149/0x170 ? srso_alias_return_thunk+0x5/0xfbef5 ? syscall_exit_to_user_mode+0x75/0x230 ? srso_alias_return_thunk+0x5/0xfbef5 ? do_syscall_64+0x8e/0x160 ? srso_alias_return_thunk+0x5/0xfbef5 ? __count_memcg_events+0x69/0x100 ? srso_alias_return_thunk+0x5/0xfbef5 ? count_memcg_events.constprop.0+0x1a/0x30 ? srso_alias_return_thunk+0x5/0xfbef5 ? handle_mm_fault+0x1f0/0x300 ? srso_alias_return_thunk+0x5/0xfbef5 ? do_user_addr_fault+0x34e/0x640 ? srso_alias_return_thunk+0x5/0xfbef5 ? srso_alias_return_thunk+0x5/0xfbef5 entry_SYSCALL_64_after_hwframe+0x76/0x7e RIP: 0033:0x7f4e5132821d Code: ff c3 66 2e 0f 1f 84 00 00 00 00 00 90 f3 0f 1e fa 48 89 f8 48 89 f7 48 89 d6 48 89 ca 4d 89 c2 4d 89 c8 4c 8b 4c 24 08 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 8b 0d e3 db 0c 00 f7 d8 64 89 01 48 RSP: 002b:00007ffca9c906a8 EFLAGS: 00000246 ORIG_RAX: 0000000000000139 RAX: ffffffffffffffda RBX: 0000563ec8a8f130 RCX: 00007f4e5132821d RDX: 0000000000000000 RSI: 00007f4e518fa07d RDI: 000000000000003b RBP: 00007ffca9c90760 R08: 00007f4e513f6b20 R09: 00007ffca9c906f0 R10: 0000563ec8a8faa0 R11: 0000000000000246 R12: 00007f4e518fa07d R13: 0000000000020000 R14: 0000563ec8409e90 R15: 0000563ec8a8fa60 </TASK> ---[ end trace ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36945?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-142.152"><img alt="medium : CVE--2024--36945" src="https://img.shields.io/badge/CVE--2024--36945-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-142.152</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-142.152</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.063%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: net/smc: fix neighbour and rtable leak in smc_ib_find_route() In smc_ib_find_route(), the neighbour found by neigh_lookup() and rtable resolved by ip_route_output_flow() are not released or put before return. It may cause the refcount leak, so fix it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36908?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2024--36908" src="https://img.shields.io/badge/CVE--2024--36908-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.009%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: blk-iocost: do not WARN if iocg was already offlined In iocg_pay_debt(), warn is triggered if 'active_list' is empty, which is intended to confirm iocg is active when it has debt. However, warn can be triggered during a blkcg or disk removal, if iocg_waitq_timer_fn() is run at that time: WARNING: CPU: 0 PID: 2344971 at block/blk-iocost.c:1402 iocg_pay_debt+0x14c/0x190 Call trace: iocg_pay_debt+0x14c/0x190 iocg_kick_waitq+0x438/0x4c0 iocg_waitq_timer_fn+0xd8/0x130 __run_hrtimer+0x144/0x45c __hrtimer_run_queues+0x16c/0x244 hrtimer_interrupt+0x2cc/0x7b0 The warn in this situation is meaningless. Since this iocg is being removed, the state of the 'active_list' is irrelevant, and 'waitq_timer' is canceled after removing 'active_list' in ioc_pd_free(), which ensures iocg is freed after iocg_waitq_timer_fn() returns. Therefore, add the check if iocg was already offlined to avoid warn when removing a blkcg or disk.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-35943?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2024--35943" src="https://img.shields.io/badge/CVE--2024--35943-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.145%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>36th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: pmdomain: ti: Add a null pointer check to the omap_prm_domain_init devm_kasprintf() returns a pointer to dynamically allocated memory which can be NULL upon failure. Ensure the allocation was successful by checking the pointer validity.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-27402?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2024--27402" src="https://img.shields.io/badge/CVE--2024--27402-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: phonet/pep: fix racy skb_queue_empty() use The receive queues are protected by their respective spin-lock, not the socket lock. This could lead to skb_peek() unexpectedly returning NULL or a pointer to an already dequeued socket buffer.

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

<a href="https://scout.docker.com/v/CVE-2022-49535?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2022--49535" src="https://img.shields.io/badge/CVE--2022--49535-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: lpfc: Fix null pointer dereference after failing to issue FLOGI and PLOGI  If lpfc_issue_els_flogi() fails and returns non-zero status, the node reference count is decremented to trigger the release of the nodelist structure. However, if there is a prior registration or dev-loss-evt work pending, the node may be released prematurely.  When dev-loss-evt completes, the released node is referenced causing a use-after-free null pointer dereference.  Similarly, when processing non-zero ELS PLOGI completion status in lpfc_cmpl_els_plogi(), the ndlp flags are checked for a transport registration before triggering node removal.  If dev-loss-evt work is pending, the node may be released prematurely and a subsequent call to lpfc_dev_loss_tmo_handler() results in a use after free ndlp dereference.  Add test for pending dev-loss before decrementing the node reference count for FLOGI, PLOGI, PRLI, and ADISC handling.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-49168?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2022--49168" src="https://img.shields.io/badge/CVE--2022--49168-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.009%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: do not clean up repair bio if submit fails  The submit helper will always run bio_endio() on the bio if it fails to submit, so cleaning up the bio just leads to a variety of use-after-free and NULL pointer dereference bugs because we race with the endio function that is cleaning up the bio.  Instead just return BLK_STS_OK as the repair function has to continue to process the rest of the pages, and the endio for the repair bio will do the appropriate cleanup for the page that it was given.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-49063?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2022--49063" src="https://img.shields.io/badge/CVE--2022--49063-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ice: arfs: fix use-after-free when freeing @rx_cpu_rmap  The CI testing bots triggered the following splat:  [  718.203054] BUG: KASAN: use-after-free in free_irq_cpu_rmap+0x53/0x80 [  718.206349] Read of size 4 at addr ffff8881bd127e00 by task sh/20834 [  718.212852] CPU: 28 PID: 20834 Comm: sh Kdump: loaded Tainted: G S W IOE     5.17.0-rc8_nextqueue-devqueue-02643-g23f3121aca93 #1 [  718.219695] Hardware name: Intel Corporation S2600WFT/S2600WFT, BIOS SE5C620.86B.02.01.0012.070720200218 07/07/2020 [  718.223418] Call Trace: [  718.227139] [  718.230783]  dump_stack_lvl+0x33/0x42 [  718.234431]  print_address_description.constprop.9+0x21/0x170 [  718.238177]  ? free_irq_cpu_rmap+0x53/0x80 [  718.241885]  ? free_irq_cpu_rmap+0x53/0x80 [  718.245539]  kasan_report.cold.18+0x7f/0x11b [  718.249197]  ? free_irq_cpu_rmap+0x53/0x80 [  718.252852]  free_irq_cpu_rmap+0x53/0x80 [  718.256471]  ice_free_cpu_rx_rmap.part.11+0x37/0x50 [ice] [  718.260174]  ice_remove_arfs+0x5f/0x70 [ice] [  718.263810]  ice_rebuild_arfs+0x3b/0x70 [ice] [  718.267419]  ice_rebuild+0x39c/0xb60 [ice] [  718.270974]  ? asm_sysvec_apic_timer_interrupt+0x12/0x20 [  718.274472]  ? ice_init_phy_user_cfg+0x360/0x360 [ice] [  718.278033]  ? delay_tsc+0x4a/0xb0 [  718.281513]  ? preempt_count_sub+0x14/0xc0 [  718.284984]  ? delay_tsc+0x8f/0xb0 [  718.288463]  ice_do_reset+0x92/0xf0 [ice] [  718.292014]  ice_pci_err_resume+0x91/0xf0 [ice] [  718.295561]  pci_reset_function+0x53/0x80 <...> [  718.393035] Allocated by task 690: [  718.433497] Freed by task 20834: [  718.495688] Last potentially related work creation: [  718.568966] The buggy address belongs to the object at ffff8881bd127e00 which belongs to the cache kmalloc-96 of size 96 [  718.574085] The buggy address is located 0 bytes inside of 96-byte region [ffff8881bd127e00, ffff8881bd127e60) [  718.579265] The buggy address belongs to the page: [  718.598905] Memory state around the buggy address: [  718.601809]  ffff8881bd127d00: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc [  718.604796]  ffff8881bd127d80: 00 00 00 00 00 00 00 00 00 00 fc fc fc fc fc fc [  718.607794] >ffff8881bd127e00: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc [  718.610811]                    ^ [  718.613819]  ffff8881bd127e80: 00 00 00 00 00 00 00 00 00 00 00 00 fc fc fc fc [  718.617107]  ffff8881bd127f00: fa fb fb fb fb fb fb fb fb fb fb fb fc fc fc fc  This is due to that free_irq_cpu_rmap() is always being called *after* (devm_)free_irq() and thus it tries to work with IRQ descs already freed. For example, on device reset the driver frees the rmap right before allocating a new one (the splat above). Make rmap creation and freeing function symmetrical with {request,free}_irq() calls i.e. do that on ifup/ifdown instead of device probe/remove/resume. These operations can be performed independently from the actual device aRFS configuration. Also, make sure ice_vsi_free_irq() clears IRQ affinity notifiers only when aRFS is disabled -- otherwise, CPU rmap sets and clears its own and they must not be touched manually.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2022-21546?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="medium : CVE--2022--21546" src="https://img.shields.io/badge/CVE--2022--21546-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.051%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: target: Fix WRITE_SAME No Data Buffer crash  In newer version of the SBC specs, we have a NDOB bit that indicates there is no data buffer that gets written out. If this bit is set using commands like "sg_write_same --ndob" we will crash in target_core_iblock/file's execute_write_same handlers when we go to access the se_cmd->t_data_sg because its NULL.  This patch adds a check for the NDOB bit in the common WRITE SAME code because we don't support it. And, it adds a check for zero SG elements in each handler in case the initiator tries to send a normal WRITE SAME with no data buffer.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53128?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.15.0-144.157"><img alt="low 5.5: CVE--2024--53128" src="https://img.shields.io/badge/CVE--2024--53128-lightgrey?label=low%205.5&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.15.0-144.157</code></td></tr>
<tr><td>Fixed version</td><td><code>5.15.0-144.157</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.073%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>23rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sched/task_stack: fix object_is_on_stack() for KASAN tagged pointers  When CONFIG_KASAN_SW_TAGS and CONFIG_KASAN_STACK are enabled, the object_is_on_stack() function may produce incorrect results due to the presence of tags in the obj pointer, while the stack pointer does not have tags.  This discrepancy can lead to incorrect stack object detection and subsequently trigger warnings if CONFIG_DEBUG_OBJECTS is also enabled.  Example of the warning:  ODEBUG: object 3eff800082ea7bb0 is NOT on stack ffff800082ea0000, but annotated. ------------[ cut here ]------------ WARNING: CPU: 0 PID: 1 at lib/debugobjects.c:557 __debug_object_init+0x330/0x364 Modules linked in: CPU: 0 UID: 0 PID: 1 Comm: swapper/0 Not tainted 6.12.0-rc5 #4 Hardware name: linux,dummy-virt (DT) pstate: 600000c5 (nZCv daIF -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : __debug_object_init+0x330/0x364 lr : __debug_object_init+0x330/0x364 sp : ffff800082ea7b40 x29: ffff800082ea7b40 x28: 98ff0000c0164518 x27: 98ff0000c0164534 x26: ffff800082d93ec8 x25: 0000000000000001 x24: 1cff0000c00172a0 x23: 0000000000000000 x22: ffff800082d93ed0 x21: ffff800081a24418 x20: 3eff800082ea7bb0 x19: efff800000000000 x18: 0000000000000000 x17: 00000000000000ff x16: 0000000000000047 x15: 206b63617473206e x14: 0000000000000018 x13: ffff800082ea7780 x12: 0ffff800082ea78e x11: 0ffff800082ea790 x10: 0ffff800082ea79d x9 : 34d77febe173e800 x8 : 34d77febe173e800 x7 : 0000000000000001 x6 : 0000000000000001 x5 : feff800082ea74b8 x4 : ffff800082870a90 x3 : ffff80008018d3c4 x2 : 0000000000000001 x1 : ffff800082858810 x0 : 0000000000000050 Call trace: __debug_object_init+0x330/0x364 debug_object_init_on_stack+0x30/0x3c schedule_hrtimeout_range_clock+0xac/0x26c schedule_hrtimeout+0x1c/0x30 wait_task_inactive+0x1d4/0x25c kthread_bind_mask+0x28/0x98 init_rescuer+0x1e8/0x280 workqueue_init+0x1a0/0x3cc kernel_init_freeable+0x118/0x200 kernel_init+0x28/0x1f0 ret_from_fork+0x10/0x20 ---[ end trace 0000000000000000 ]--- ODEBUG: object 3eff800082ea7bb0 is NOT on stack ffff800082ea0000, but annotated. ------------[ cut here ]------------

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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>openjdk-8</strong> <code>8u452-ga~us1-0ubuntu1~22.04</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/openjdk-8@8u452-ga~us1-0ubuntu1~22.04?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-50106?s=ubuntu&n=openjdk-8&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C8u462-ga%7Eus1-0ubuntu2%7E22.04.2"><img alt="medium : CVE--2025--50106" src="https://img.shields.io/badge/CVE--2025--50106-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><8u462-ga~us1-0ubuntu2~22.04.2</code></td></tr>
<tr><td>Fixed version</td><td><code>8u462-ga~us1-0ubuntu2~22.04.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 2D).  Supported versions that are affected are Oracle Java SE: 8u451, 8u451-perf, 11.0.27, 17.0.15, 21.0.7, 24.0.1; Oracle GraalVM for JDK: 17.0.15, 21.0.7 and 24.0.1; Oracle GraalVM Enterprise Edition: 21.3.14. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-30761?s=ubuntu&n=openjdk-8&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C8u462-ga%7Eus1-0ubuntu2%7E22.04.2"><img alt="medium : CVE--2025--30761" src="https://img.shields.io/badge/CVE--2025--30761-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><8u462-ga~us1-0ubuntu2~22.04.2</code></td></tr>
<tr><td>Fixed version</td><td><code>8u462-ga~us1-0ubuntu2~22.04.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Scripting).  Supported versions that are affected are Oracle Java SE: 8u451, 8u451-perf and  11.0.27; Oracle GraalVM Enterprise Edition: 21.3.14. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM Enterprise Edition. Successful attacks of this vulnerability can result in  unauthorized creation, deletion or modification access to critical data or all Oracle Java SE, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability can be exploited by using APIs in the specified Component, e.g., through a web service which supplies data to the APIs. This vulnerability also applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. CVSS 3.1 Base Score 5.9 (Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-30754?s=ubuntu&n=openjdk-8&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C8u462-ga%7Eus1-0ubuntu2%7E22.04.2"><img alt="medium : CVE--2025--30754" src="https://img.shields.io/badge/CVE--2025--30754-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><8u462-ga~us1-0ubuntu2~22.04.2</code></td></tr>
<tr><td>Fixed version</td><td><code>8u462-ga~us1-0ubuntu2~22.04.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.035%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: JSSE).  Supported versions that are affected are Oracle Java SE: 8u451, 8u451-perf, 11.0.27, 17.0.15, 21.0.7, 24.0.1; Oracle GraalVM for JDK: 17.0.15, 21.0.7 and 24.0.1; Oracle GraalVM Enterprise Edition: 21.3.14. Difficult to exploit vulnerability allows unauthenticated attacker with network access via TLS to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data as well as  unauthorized read access to a subset of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition accessible data. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 4.8 (Confidentiality and Integrity impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-30749?s=ubuntu&n=openjdk-8&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C8u462-ga%7Eus1-0ubuntu2%7E22.04.2"><img alt="medium : CVE--2025--30749" src="https://img.shields.io/badge/CVE--2025--30749-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><8u462-ga~us1-0ubuntu2~22.04.2</code></td></tr>
<tr><td>Fixed version</td><td><code>8u462-ga~us1-0ubuntu2~22.04.2</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: 2D).  Supported versions that are affected are Oracle Java SE: 8u451, 8u451-perf, 11.0.27, 17.0.15, 21.0.7, 24.0.1; Oracle GraalVM for JDK: 17.0.15, 21.0.7 and 24.0.1; Oracle GraalVM Enterprise Edition: 21.3.14. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition.  Successful attacks of this vulnerability can result in takeover of Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition. Note: This vulnerability applies to Java deployments, typically in clients running sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g., code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed by an administrator). CVSS 3.1 Base Score 8.1 (Confidentiality, Integrity and Availability impacts).  CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H).

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>libssh</strong> <code>0.9.6-2ubuntu0.22.04.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/libssh@0.9.6-2ubuntu0.22.04.3?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-5372?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.4"><img alt="medium : CVE--2025--5372" src="https://img.shields.io/badge/CVE--2025--5372-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.041%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in libssh versions built with OpenSSL versions older than 3.0, specifically in the ssh_kdf() function responsible for key derivation. Due to inconsistent interpretation of return values where OpenSSL uses 0 to indicate failure and libssh uses 0 for success—the function may mistakenly return a success status even when key derivation fails. This results in uninitialized cryptographic key buffers being used in subsequent communication, potentially compromising SSH sessions' confidentiality, integrity, and availability.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-5318?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.4"><img alt="medium : CVE--2025--5318" src="https://img.shields.io/badge/CVE--2025--5318-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.047%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the libssh library. An out-of-bounds read can be triggered in the sftp_handle function due to an incorrect comparison check that permits the function to access memory beyond the valid handle list and to return an invalid pointer, which is used in further processing. This vulnerability allows an authenticated remote attacker to potentially read unintended memory regions, exposing sensitive information or affect service behavior.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4878?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.4"><img alt="medium : CVE--2025--4878" src="https://img.shields.io/badge/CVE--2025--4878-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability was found in libssh, where an uninitialized variable exists under certain conditions in the privatekey_from_file() function. This flaw can be triggered if the file specified by the filename doesn't exist and may lead to possible signing failures or heap corruption.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-4877?s=ubuntu&n=libssh&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C0.9.6-2ubuntu0.22.04.4"><img alt="medium : CVE--2025--4877" src="https://img.shields.io/badge/CVE--2025--4877-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><0.9.6-2ubuntu0.22.04.4</code></td></tr>
<tr><td>Fixed version</td><td><code>0.9.6-2ubuntu0.22.04.4</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

Write beyond bounds in binary to base64 conversion functions

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 4" src="https://img.shields.io/badge/M-4-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gnutls28</strong> <code>3.7.3-4ubuntu1.6</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gnutls28@3.7.3-4ubuntu1.6?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6395?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.7"><img alt="medium : CVE--2025--6395" src="https://img.shields.io/badge/CVE--2025--6395-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A NULL pointer dereference flaw was found in the GnuTLS software in _gnutls_figure_common_ciphersuite(). When it reads certain settings from a template file, it can allow an attacker to cause an out-of-bounds (OOB) NULL pointer write, resulting in memory corruption and a denial of service (DoS) that could crash the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-32990?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.7"><img alt="medium : CVE--2025--32990" src="https://img.shields.io/badge/CVE--2025--32990-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.059%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>19th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-buffer-overflow (off-by-one) flaw was found in the GnuTLS software in the template parsing logic within the certtool utility. When it reads certain settings from a template file, it allows an attacker to cause an out-of-bounds (OOB) NULL pointer write, resulting in memory corruption and a denial-of-service (DoS) that could potentially crash the system.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-32989?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.7"><img alt="medium : CVE--2025--32989" src="https://img.shields.io/badge/CVE--2025--32989-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A heap-buffer-overread vulnerability was found in GnuTLS in how it handles the Certificate Transparency (CT) Signed Certificate Timestamp (SCT) extension during X.509 certificate parsing. This flaw allows a malicious user to create a certificate containing a malformed SCT extension (OID 1.3.6.1.4.1.11129.2.4.2) that contains sensitive data. This issue leads to the exposure of confidential information when GnuTLS verifies certificates from certain websites when the certificate (SCT) is not checked correctly.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-32988?s=ubuntu&n=gnutls28&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.7.3-4ubuntu1.7"><img alt="medium : CVE--2025--32988" src="https://img.shields.io/badge/CVE--2025--32988-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>Fixed version</td><td><code>3.7.3-4ubuntu1.7</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in GnuTLS. A double-free vulnerability exists in GnuTLS due to incorrect ownership handling in the export logic of Subject Alternative Name (SAN) entries containing an otherName. If the type-id OID is invalid or malformed, GnuTLS will call asn1_delete_structure() on an ASN.1 node it does not own, leading to a double-free condition when the parent function or caller later attempts to free the same structure.  This vulnerability can be triggered using only public GnuTLS APIs and may result in denial of service or memory corruption, depending on allocator behavior.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 2" src="https://img.shields.io/badge/M-2-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>gdk-pixbuf</strong> <code>2.42.8+dfsg-1ubuntu0.3</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/gdk-pixbuf@2.42.8%2Bdfsg-1ubuntu0.3?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-7345?s=ubuntu&n=gdk-pixbuf&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.42.8%2Bdfsg-1ubuntu0.4"><img alt="medium : CVE--2025--7345" src="https://img.shields.io/badge/CVE--2025--7345-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.42.8+dfsg-1ubuntu0.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.42.8+dfsg-1ubuntu0.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.083%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>25th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw exists in gdk‑pixbuf within the gdk_pixbuf__jpeg_image_load_increment function (io-jpeg.c) and in glib’s g_base64_encode_step (glib/gbase64.c). When processing maliciously crafted JPEG images, a heap buffer overflow can occur during Base64 encoding, allowing out-of-bounds reads from heap memory, potentially causing application crashes or arbitrary code execution.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-6199?s=ubuntu&n=gdk-pixbuf&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C2.42.8%2Bdfsg-1ubuntu0.4"><img alt="medium : CVE--2025--6199" src="https://img.shields.io/badge/CVE--2025--6199-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><2.42.8+dfsg-1ubuntu0.4</code></td></tr>
<tr><td>Fixed version</td><td><code>2.42.8+dfsg-1ubuntu0.4</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in the GIF parser of GdkPixbuf’s LZW decoder. When an invalid symbol is encountered during decompression, the decoder sets the reported output size to the full buffer length rather than the actual number of written bytes. This logic error results in uninitialized sections of the buffer being included in the output, potentially leaking arbitrary memory contents in the processed image.

</blockquote>
</details>
</details></td></tr>

<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>sqlite3</strong> <code>3.37.2-2ubuntu0.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/sqlite3@3.37.2-2ubuntu0.4?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6965?s=ubuntu&n=sqlite3&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C3.37.2-2ubuntu0.5"><img alt="medium 9.8: CVE--2025--6965" src="https://img.shields.io/badge/CVE--2025--6965-lightgrey?label=medium%209.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><3.37.2-2ubuntu0.5</code></td></tr>
<tr><td>Fixed version</td><td><code>3.37.2-2ubuntu0.5</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>perl</strong> <code>5.34.0-3ubuntu1.4</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/perl@5.34.0-3ubuntu1.4?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-40909?s=ubuntu&n=perl&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C5.34.0-3ubuntu1.5"><img alt="medium : CVE--2025--40909" src="https://img.shields.io/badge/CVE--2025--40909-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><5.34.0-3ubuntu1.5</code></td></tr>
<tr><td>Fixed version</td><td><code>5.34.0-3ubuntu1.5</code></td></tr>
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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>pam</strong> <code>1.4.0-11ubuntu2.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/pam@1.4.0-11ubuntu2.5?os_distro=jammy&os_name=ubuntu&os_version=22.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-6020?s=ubuntu&n=pam&ns=ubuntu&t=deb&osn=ubuntu&osv=22.04&vr=%3C1.4.0-11ubuntu2.6"><img alt="medium : CVE--2025--6020" src="https://img.shields.io/badge/CVE--2025--6020-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.4.0-11ubuntu2.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1.4.0-11ubuntu2.6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in linux-pam. The module pam_namespace may use access user-controlled paths without proper protection, allowing local users to elevate their privileges to root via multiple symlink attacks and race conditions.

</blockquote>
</details>
</details></td></tr>
</table>