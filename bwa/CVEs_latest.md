# Vulnerability Report for getwilds/bwa:latest

Report generated on 2025-06-20 15:55:04 PST

<h2>:mag: Vulnerabilities of <code>getwilds/bwa:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/bwa:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:c0e6812079e06a6ce990f940a1ee86b7f1251bfc2ca214c737cf8a8850295562</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 134" src="https://img.shields.io/badge/medium-134-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/low-2-fce1a9"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>156 MB</td></tr>
<tr><td>packages</td><td>235</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 131" src="https://img.shields.io/badge/M-131-fbb552"/> <img alt="low: 2" src="https://img.shields.io/badge/L-2-fce1a9"/> <!-- unspecified: 0 --><strong>linux</strong> <code>6.8.0-59.61</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@6.8.0-59.61?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2024-58087?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 8.1: CVE--2024--58087" src="https://img.shields.io/badge/CVE--2024--58087-lightgrey?label=medium%208.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>8.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.100%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>29th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: fix racy issue from session lookup and expire  Increment the session reference count within the lock for lookup to avoid racy issue with session expire.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21652?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2025--21652" src="https://img.shields.io/badge/CVE--2025--21652-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ipvlan: Fix use-after-free in ipvlan_get_iflink().  syzbot presented an use-after-free report [0] regarding ipvlan and linkwatch.  ipvlan does not hold a refcnt of the lower device unlike vlan and macvlan.  If the linkwatch work is triggered for the ipvlan dev, the lower dev might have already been freed, resulting in UAF of ipvlan->phy_dev in ipvlan_get_iflink().  We can delay the lower dev unregistration like vlan and macvlan by holding the lower dev's refcnt in dev->netdev_ops->ndo_init() and releasing it in dev->priv_destructor().  Jakub pointed out calling .ndo_XXX after unregister_netdevice() has returned is error prone and suggested [1] addressing this UAF in the core by taking commit 750e51603395 ("net: avoid potential UAF in default_operstate()") further.  Let's assume unregistering devices DOWN and use RCU protection in default_operstate() not to race with the device unregistration.  [0]: BUG: KASAN: slab-use-after-free in ipvlan_get_iflink+0x84/0x88 drivers/net/ipvlan/ipvlan_main.c:353 Read of size 4 at addr ffff0000d768c0e0 by task kworker/u8:35/6944  CPU: 0 UID: 0 PID: 6944 Comm: kworker/u8:35 Not tainted 6.13.0-rc2-g9bc5c9515b48 #12 4c3cb9e8b4565456f6a355f312ff91f4f29b3c47 Hardware name: linux,dummy-virt (DT) Workqueue: events_unbound linkwatch_event Call trace: show_stack+0x38/0x50 arch/arm64/kernel/stacktrace.c:484 (C) __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0xbc/0x108 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x16c/0x6f0 mm/kasan/report.c:489 kasan_report+0xc0/0x120 mm/kasan/report.c:602 __asan_report_load4_noabort+0x20/0x30 mm/kasan/report_generic.c:380 ipvlan_get_iflink+0x84/0x88 drivers/net/ipvlan/ipvlan_main.c:353 dev_get_iflink+0x7c/0xd8 net/core/dev.c:674 default_operstate net/core/link_watch.c:45 [inline] rfc2863_policy+0x144/0x360 net/core/link_watch.c:72 linkwatch_do_dev+0x60/0x228 net/core/link_watch.c:175 __linkwatch_run_queue+0x2f4/0x5b8 net/core/link_watch.c:239 linkwatch_event+0x64/0xa8 net/core/link_watch.c:282 process_one_work+0x700/0x1398 kernel/workqueue.c:3229 process_scheduled_works kernel/workqueue.c:3310 [inline] worker_thread+0x8c4/0xe10 kernel/workqueue.c:3391 kthread+0x2b0/0x360 kernel/kthread.c:389 ret_from_fork+0x10/0x20 arch/arm64/kernel/entry.S:862  Allocated by task 9303: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x30/0x68 mm/kasan/common.c:68 kasan_save_alloc_info+0x44/0x58 mm/kasan/generic.c:568 poison_kmalloc_redzone mm/kasan/common.c:377 [inline] __kasan_kmalloc+0x84/0xa0 mm/kasan/common.c:394 kasan_kmalloc include/linux/kasan.h:260 [inline] __do_kmalloc_node mm/slub.c:4283 [inline] __kmalloc_node_noprof+0x2a0/0x560 mm/slub.c:4289 __kvmalloc_node_noprof+0x9c/0x230 mm/util.c:650 alloc_netdev_mqs+0xb4/0x1118 net/core/dev.c:11209 rtnl_create_link+0x2b8/0xb60 net/core/rtnetlink.c:3595 rtnl_newlink_create+0x19c/0x868 net/core/rtnetlink.c:3771 __rtnl_newlink net/core/rtnetlink.c:3896 [inline] rtnl_newlink+0x122c/0x15c0 net/core/rtnetlink.c:4011 rtnetlink_rcv_msg+0x61c/0x918 net/core/rtnetlink.c:6901 netlink_rcv_skb+0x1dc/0x398 net/netlink/af_netlink.c:2542 rtnetlink_rcv+0x34/0x50 net/core/rtnetlink.c:6928 netlink_unicast_kernel net/netlink/af_netlink.c:1321 [inline] netlink_unicast+0x618/0x838 net/netlink/af_netlink.c:1347 netlink_sendmsg+0x5fc/0x8b0 net/netlink/af_netlink.c:1891 sock_sendmsg_nosec net/socket.c:711 [inline] __sock_sendmsg net/socket.c:726 [inline] __sys_sendto+0x2ec/0x438 net/socket.c:2197 __do_sys_sendto net/socket.c:2204 [inline] __se_sys_sendto net/socket.c:2200 [inline] __arm64_sys_sendto+0xe4/0x110 net/socket.c:2200 __invoke_syscall arch/arm64/kernel/syscall.c:35 [inline] invoke_syscall+0x90/0x278 arch/arm64/kernel/syscall.c:49 el0_svc_common+0x13c/0x250 arch/arm64/kernel/syscall.c:132 do_el0_svc+0x54/0x70 arch/arm64/kernel/syscall.c:151 el ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21650?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2025--21650" src="https://img.shields.io/badge/CVE--2025--21650-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hns3: fixed hclge_fetch_pf_reg accesses bar space out of bounds issue  The TQP BAR space is divided into two segments. TQPs 0-1023 and TQPs 1024-1279 are in different BAR space addresses. However, hclge_fetch_pf_reg does not distinguish the tqp space information when reading the tqp space information. When the number of TQPs is greater than 1024, access bar space overwriting occurs. The problem of different segments has been considered during the initialization of tqp.io_base. Therefore, tqp.io_base is directly used when the queue is read in hclge_fetch_pf_reg.  The error message:  Unable to handle kernel paging request at virtual address ffff800037200000 pc : hclge_fetch_pf_reg+0x138/0x250 [hclge] lr : hclge_get_regs+0x84/0x1d0 [hclge] Call trace: hclge_fetch_pf_reg+0x138/0x250 [hclge] hclge_get_regs+0x84/0x1d0 [hclge] hns3_get_regs+0x2c/0x50 [hns3] ethtool_get_regs+0xf4/0x270 dev_ethtool+0x674/0x8a0 dev_ioctl+0x270/0x36c sock_do_ioctl+0x110/0x2a0 sock_ioctl+0x2ac/0x530 __arm64_sys_ioctl+0xa8/0x100 invoke_syscall+0x4c/0x124 el0_svc_common.constprop.0+0x140/0x15c do_el0_svc+0x30/0xd0 el0_svc+0x1c/0x2c el0_sync_handler+0xb0/0xb4 el0_sync+0x168/0x180

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21631?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2025--21631" src="https://img.shields.io/badge/CVE--2025--21631-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  block, bfq: fix waker_bfqq UAF after bfq_split_bfqq()  Our syzkaller report a following UAF for v6.6:  BUG: KASAN: slab-use-after-free in bfq_init_rq+0x175d/0x17a0 block/bfq-iosched.c:6958 Read of size 8 at addr ffff8881b57147d8 by task fsstress/232726  CPU: 2 PID: 232726 Comm: fsstress Not tainted 6.6.0-g3629d1885222 #39 Call Trace: <TASK> __dump_stack lib/dump_stack.c:88 [inline] dump_stack_lvl+0x91/0xf0 lib/dump_stack.c:106 print_address_description.constprop.0+0x66/0x300 mm/kasan/report.c:364 print_report+0x3e/0x70 mm/kasan/report.c:475 kasan_report+0xb8/0xf0 mm/kasan/report.c:588 hlist_add_head include/linux/list.h:1023 [inline] bfq_init_rq+0x175d/0x17a0 block/bfq-iosched.c:6958 bfq_insert_request.isra.0+0xe8/0xa20 block/bfq-iosched.c:6271 bfq_insert_requests+0x27f/0x390 block/bfq-iosched.c:6323 blk_mq_insert_request+0x290/0x8f0 block/blk-mq.c:2660 blk_mq_submit_bio+0x1021/0x15e0 block/blk-mq.c:3143 __submit_bio+0xa0/0x6b0 block/blk-core.c:639 __submit_bio_noacct_mq block/blk-core.c:718 [inline] submit_bio_noacct_nocheck+0x5b7/0x810 block/blk-core.c:747 submit_bio_noacct+0xca0/0x1990 block/blk-core.c:847 __ext4_read_bh fs/ext4/super.c:205 [inline] ext4_read_bh+0x15e/0x2e0 fs/ext4/super.c:230 __read_extent_tree_block+0x304/0x6f0 fs/ext4/extents.c:567 ext4_find_extent+0x479/0xd20 fs/ext4/extents.c:947 ext4_ext_map_blocks+0x1a3/0x2680 fs/ext4/extents.c:4182 ext4_map_blocks+0x929/0x15a0 fs/ext4/inode.c:660 ext4_iomap_begin_report+0x298/0x480 fs/ext4/inode.c:3569 iomap_iter+0x3dd/0x1010 fs/iomap/iter.c:91 iomap_fiemap+0x1f4/0x360 fs/iomap/fiemap.c:80 ext4_fiemap+0x181/0x210 fs/ext4/extents.c:5051 ioctl_fiemap.isra.0+0x1b4/0x290 fs/ioctl.c:220 do_vfs_ioctl+0x31c/0x11a0 fs/ioctl.c:811 __do_sys_ioctl fs/ioctl.c:869 [inline] __se_sys_ioctl+0xae/0x190 fs/ioctl.c:857 do_syscall_x64 arch/x86/entry/common.c:51 [inline] do_syscall_64+0x70/0x120 arch/x86/entry/common.c:81 entry_SYSCALL_64_after_hwframe+0x78/0xe2  Allocated by task 232719: kasan_save_stack+0x22/0x50 mm/kasan/common.c:45 kasan_set_track+0x25/0x30 mm/kasan/common.c:52 __kasan_slab_alloc+0x87/0x90 mm/kasan/common.c:328 kasan_slab_alloc include/linux/kasan.h:188 [inline] slab_post_alloc_hook mm/slab.h:768 [inline] slab_alloc_node mm/slub.c:3492 [inline] kmem_cache_alloc_node+0x1b8/0x6f0 mm/slub.c:3537 bfq_get_queue+0x215/0x1f00 block/bfq-iosched.c:5869 bfq_get_bfqq_handle_split+0x167/0x5f0 block/bfq-iosched.c:6776 bfq_init_rq+0x13a4/0x17a0 block/bfq-iosched.c:6938 bfq_insert_request.isra.0+0xe8/0xa20 block/bfq-iosched.c:6271 bfq_insert_requests+0x27f/0x390 block/bfq-iosched.c:6323 blk_mq_insert_request+0x290/0x8f0 block/blk-mq.c:2660 blk_mq_submit_bio+0x1021/0x15e0 block/blk-mq.c:3143 __submit_bio+0xa0/0x6b0 block/blk-core.c:639 __submit_bio_noacct_mq block/blk-core.c:718 [inline] submit_bio_noacct_nocheck+0x5b7/0x810 block/blk-core.c:747 submit_bio_noacct+0xca0/0x1990 block/blk-core.c:847 __ext4_read_bh fs/ext4/super.c:205 [inline] ext4_read_bh_nowait+0x15a/0x240 fs/ext4/super.c:217 ext4_read_bh_lock+0xac/0xd0 fs/ext4/super.c:242 ext4_bread_batch+0x268/0x500 fs/ext4/inode.c:958 __ext4_find_entry+0x448/0x10f0 fs/ext4/namei.c:1671 ext4_lookup_entry fs/ext4/namei.c:1774 [inline] ext4_lookup.part.0+0x359/0x6f0 fs/ext4/namei.c:1842 ext4_lookup+0x72/0x90 fs/ext4/namei.c:1839 __lookup_slow+0x257/0x480 fs/namei.c:1696 lookup_slow fs/namei.c:1713 [inline] walk_component+0x454/0x5c0 fs/namei.c:2004 link_path_walk.part.0+0x773/0xda0 fs/namei.c:2331 link_path_walk fs/namei.c:3826 [inline] path_openat+0x1b9/0x520 fs/namei.c:3826 do_filp_open+0x1b7/0x400 fs/namei.c:3857 do_sys_openat2+0x5dc/0x6e0 fs/open.c:1428 do_sys_open fs/open.c:1443 [inline] __do_sys_openat fs/open.c:1459 [inline] __se_sys_openat fs/open.c:1454 [inline] __x64_sys_openat+0x148/0x200 fs/open.c:1454 do_syscall_x64 arch/x86/entry/common.c:51 [inline] do_syscall_6 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57926?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--57926" src="https://img.shields.io/badge/CVE--2024--57926-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/mediatek: Set private->all_drm_private[i]->drm to NULL if mtk_drm_bind returns err  The pointer need to be set to NULL, otherwise KASAN complains about use-after-free. Because in mtk_drm_bind, all private's drm are set as follows.  private->all_drm_private[i]->drm = drm;  And drm will be released by drm_dev_put in case mtk_drm_kms_init returns failure. However, the shutdown path still accesses the previous allocated memory in drm_atomic_helper_shutdown.  [   84.874820] watchdog: watchdog0: watchdog did not stop! [   86.512054] ================================================================== [   86.513162] BUG: KASAN: use-after-free in drm_atomic_helper_shutdown+0x33c/0x378 [   86.514258] Read of size 8 at addr ffff0000d46fc068 by task shutdown/1 [   86.515213] [   86.515455] CPU: 1 UID: 0 PID: 1 Comm: shutdown Not tainted 6.13.0-rc1-mtk+gfa1a78e5d24b-dirty #55 [   86.516752] Hardware name: Unknown Product/Unknown Product, BIOS 2022.10 10/01/2022 [   86.517960] Call trace: [   86.518333]  show_stack+0x20/0x38 (C) [   86.518891]  dump_stack_lvl+0x90/0xd0 [   86.519443]  print_report+0xf8/0x5b0 [   86.519985]  kasan_report+0xb4/0x100 [   86.520526]  __asan_report_load8_noabort+0x20/0x30 [   86.521240]  drm_atomic_helper_shutdown+0x33c/0x378 [   86.521966]  mtk_drm_shutdown+0x54/0x80 [   86.522546]  platform_shutdown+0x64/0x90 [   86.523137]  device_shutdown+0x260/0x5b8 [   86.523728]  kernel_restart+0x78/0xf0 [   86.524282]  __do_sys_reboot+0x258/0x2f0 [   86.524871]  __arm64_sys_reboot+0x90/0xd8 [   86.525473]  invoke_syscall+0x74/0x268 [   86.526041]  el0_svc_common.constprop.0+0xb0/0x240 [   86.526751]  do_el0_svc+0x4c/0x70 [   86.527251]  el0_svc+0x4c/0xc0 [   86.527719]  el0t_64_sync_handler+0x144/0x168 [   86.528367]  el0t_64_sync+0x198/0x1a0 [   86.528920] [   86.529157] The buggy address belongs to the physical page: [   86.529972] page: refcount:0 mapcount:0 mapping:0000000000000000 index:0xffff0000d46fd4d0 pfn:0x1146fc [   86.531319] flags: 0xbfffc0000000000(node=0|zone=2|lastcpupid=0xffff) [   86.532267] raw: 0bfffc0000000000 0000000000000000 dead000000000122 0000000000000000 [   86.533390] raw: ffff0000d46fd4d0 0000000000000000 00000000ffffffff 0000000000000000 [   86.534511] page dumped because: kasan: bad access detected [   86.535323] [   86.535559] Memory state around the buggy address: [   86.536265]  ffff0000d46fbf00: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.537314]  ffff0000d46fbf80: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.538363] >ffff0000d46fc000: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.544733]                                                           ^ [   86.551057]  ffff0000d46fc080: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.557510]  ffff0000d46fc100: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff [   86.563928] ================================================================== [   86.571093] Disabling lock debugging due to kernel taint [   86.577642] Unable to handle kernel paging request at virtual address e0e9c0920000000b [   86.581834] KASAN: maybe wild-memory-access in range [0x0752049000000058-0x075204900000005f] ...

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57900?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--57900" src="https://img.shields.io/badge/CVE--2024--57900-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ila: serialize calls to nf_register_net_hooks()  syzbot found a race in ila_add_mapping() [1]  commit 031ae72825ce ("ila: call nf_unregister_net_hooks() sooner") attempted to fix a similar issue.  Looking at the syzbot repro, we have concurrent ILA_CMD_ADD commands.  Add a mutex to make sure at most one thread is calling nf_register_net_hooks().  [1] BUG: KASAN: slab-use-after-free in rht_key_hashfn include/linux/rhashtable.h:159 [inline] BUG: KASAN: slab-use-after-free in __rhashtable_lookup.constprop.0+0x426/0x550 include/linux/rhashtable.h:604 Read of size 4 at addr ffff888028f40008 by task dhcpcd/5501  CPU: 1 UID: 0 PID: 5501 Comm: dhcpcd Not tainted 6.13.0-rc4-syzkaller-00054-gd6ef8b40d075 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Call Trace: <IRQ> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x116/0x1f0 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0xc3/0x620 mm/kasan/report.c:489 kasan_report+0xd9/0x110 mm/kasan/report.c:602 rht_key_hashfn include/linux/rhashtable.h:159 [inline] __rhashtable_lookup.constprop.0+0x426/0x550 include/linux/rhashtable.h:604 rhashtable_lookup include/linux/rhashtable.h:646 [inline] rhashtable_lookup_fast include/linux/rhashtable.h:672 [inline] ila_lookup_wildcards net/ipv6/ila/ila_xlat.c:127 [inline] ila_xlat_addr net/ipv6/ila/ila_xlat.c:652 [inline] ila_nf_input+0x1ee/0x620 net/ipv6/ila/ila_xlat.c:185 nf_hook_entry_hookfn include/linux/netfilter.h:154 [inline] nf_hook_slow+0xbb/0x200 net/netfilter/core.c:626 nf_hook.constprop.0+0x42e/0x750 include/linux/netfilter.h:269 NF_HOOK include/linux/netfilter.h:312 [inline] ipv6_rcv+0xa4/0x680 net/ipv6/ip6_input.c:309 __netif_receive_skb_one_core+0x12e/0x1e0 net/core/dev.c:5672 __netif_receive_skb+0x1d/0x160 net/core/dev.c:5785 process_backlog+0x443/0x15f0 net/core/dev.c:6117 __napi_poll.constprop.0+0xb7/0x550 net/core/dev.c:6883 napi_poll net/core/dev.c:6952 [inline] net_rx_action+0xa94/0x1010 net/core/dev.c:7074 handle_softirqs+0x213/0x8f0 kernel/softirq.c:561 __do_softirq kernel/softirq.c:595 [inline] invoke_softirq kernel/softirq.c:435 [inline] __irq_exit_rcu+0x109/0x170 kernel/softirq.c:662 irq_exit_rcu+0x9/0x30 kernel/softirq.c:678 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline] sysvec_apic_timer_interrupt+0xa4/0xc0 arch/x86/kernel/apic/apic.c:1049

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57896?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--57896" src="https://img.shields.io/badge/CVE--2024--57896-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: flush delalloc workers queue before stopping cleaner kthread during unmount  During the unmount path, at close_ctree(), we first stop the cleaner kthread, using kthread_stop() which frees the associated task_struct, and then stop and destroy all the work queues. However after we stopped the cleaner we may still have a worker from the delalloc_workers queue running inode.c:submit_compressed_extents(), which calls btrfs_add_delayed_iput(), which in turn tries to wake up the cleaner kthread - which was already destroyed before, resulting in a use-after-free on the task_struct.  Syzbot reported this with the following stack traces:  BUG: KASAN: slab-use-after-free in __lock_acquire+0x78/0x2100 kernel/locking/lockdep.c:5089 Read of size 8 at addr ffff8880259d2818 by task kworker/u8:3/52  CPU: 1 UID: 0 PID: 52 Comm: kworker/u8:3 Not tainted 6.13.0-rc1-syzkaller-00002-gcdd30ebb1b9f #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Workqueue: btrfs-delalloc btrfs_work_helper Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 print_address_description mm/kasan/report.c:378 [inline] print_report+0x169/0x550 mm/kasan/report.c:489 kasan_report+0x143/0x180 mm/kasan/report.c:602 __lock_acquire+0x78/0x2100 kernel/locking/lockdep.c:5089 lock_acquire+0x1ed/0x550 kernel/locking/lockdep.c:5849 __raw_spin_lock_irqsave include/linux/spinlock_api_smp.h:110 [inline] _raw_spin_lock_irqsave+0xd5/0x120 kernel/locking/spinlock.c:162 class_raw_spinlock_irqsave_constructor include/linux/spinlock.h:551 [inline] try_to_wake_up+0xc2/0x1470 kernel/sched/core.c:4205 submit_compressed_extents+0xdf/0x16e0 fs/btrfs/inode.c:1615 run_ordered_work fs/btrfs/async-thread.c:288 [inline] btrfs_work_helper+0x96f/0xc40 fs/btrfs/async-thread.c:324 process_one_work kernel/workqueue.c:3229 [inline] process_scheduled_works+0xa66/0x1840 kernel/workqueue.c:3310 worker_thread+0x870/0xd30 kernel/workqueue.c:3391 kthread+0x2f0/0x390 kernel/kthread.c:389 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK>  Allocated by task 2: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68 unpoison_slab_object mm/kasan/common.c:319 [inline] __kasan_slab_alloc+0x66/0x80 mm/kasan/common.c:345 kasan_slab_alloc include/linux/kasan.h:250 [inline] slab_post_alloc_hook mm/slub.c:4104 [inline] slab_alloc_node mm/slub.c:4153 [inline] kmem_cache_alloc_node_noprof+0x1d9/0x380 mm/slub.c:4205 alloc_task_struct_node kernel/fork.c:180 [inline] dup_task_struct+0x57/0x8c0 kernel/fork.c:1113 copy_process+0x5d1/0x3d50 kernel/fork.c:2225 kernel_clone+0x223/0x870 kernel/fork.c:2807 kernel_thread+0x1bc/0x240 kernel/fork.c:2869 create_kthread kernel/kthread.c:412 [inline] kthreadd+0x60d/0x810 kernel/kthread.c:767 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244  Freed by task 24: kasan_save_stack mm/kasan/common.c:47 [inline] kasan_save_track+0x3f/0x80 mm/kasan/common.c:68 kasan_save_free_info+0x40/0x50 mm/kasan/generic.c:582 poison_slab_object mm/kasan/common.c:247 [inline] __kasan_slab_free+0x59/0x70 mm/kasan/common.c:264 kasan_slab_free include/linux/kasan.h:233 [inline] slab_free_hook mm/slub.c:2338 [inline] slab_free mm/slub.c:4598 [inline] kmem_cache_free+0x195/0x410 mm/slub.c:4700 put_task_struct include/linux/sched/task.h:144 [inline] delayed_put_task_struct+0x125/0x300 kernel/exit.c:227 rcu_do_batch kernel/rcu/tree.c:2567 [inline] rcu_core+0xaaa/0x17a0 kernel/rcu/tree.c:2823 handle_softirqs+0x2d4/0x9b0 kernel/softirq.c:554 run_ksoftirqd+0xca/0x130 kernel/softirq.c:943  ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57892?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--57892" src="https://img.shields.io/badge/CVE--2024--57892-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ocfs2: fix slab-use-after-free due to dangling pointer dqi_priv  When mounting ocfs2 and then remounting it as read-only, a slab-use-after-free occurs after the user uses a syscall to quota_getnextquota.  Specifically, sb_dqinfo(sb, type)->dqi_priv is the dangling pointer.  During the remounting process, the pointer dqi_priv is freed but is never set as null leaving it to be accessed.  Additionally, the read-only option for remounting sets the DQUOT_SUSPENDED flag instead of setting the DQUOT_USAGE_ENABLED flags.  Moreover, later in the process of getting the next quota, the function ocfs2_get_next_id is called and only checks the quota usage flags and not the quota suspended flags.  To fix this, I set dqi_priv to null when it is freed after remounting with read-only and put a check for DQUOT_SUSPENDED in ocfs2_get_next_id.  [akpm@linux-foundation.org: coding-style cleanups]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57887?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--57887" src="https://img.shields.io/badge/CVE--2024--57887-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm: adv7511: Fix use-after-free in adv7533_attach_dsi()  The host_node pointer was assigned and freed in adv7533_parse_dt(), and later, adv7533_attach_dsi() uses the same. Fix this use-after-free issue by dropping of_node_put() in adv7533_parse_dt() and calling of_node_put() in error path of probe() and also in the remove().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57801?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--57801" src="https://img.shields.io/badge/CVE--2024--57801-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5e: Skip restore TC rules for vport rep without loaded flag  During driver unload, unregister_netdev is called after unloading vport rep. So, the mlx5e_rep_priv is already freed while trying to get rpriv->netdev, or walk rpriv->tc_ht, which results in use-after-free. So add the checking to make sure access the data of vport rep which is still loaded.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56764?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--56764" src="https://img.shields.io/badge/CVE--2024--56764-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ublk: detach gendisk from ublk device if add_disk() fails  Inside ublk_abort_requests(), gendisk is grabbed for aborting all inflight requests. And ublk_abort_requests() is called when exiting the uring context or handling timeout.  If add_disk() fails, the gendisk may have been freed when calling ublk_abort_requests(), so use-after-free can be caused when getting disk's reference in ublk_abort_requests().  Fixes the bug by detaching gendisk from ublk device if add_disk() fails.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56759?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--56759" src="https://img.shields.io/badge/CVE--2024--56759-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: fix use-after-free when COWing tree bock and tracing is enabled  When a COWing a tree block, at btrfs_cow_block(), and we have the tracepoint trace_btrfs_cow_block() enabled and preemption is also enabled (CONFIG_PREEMPT=y), we can trigger a use-after-free in the COWed extent buffer while inside the tracepoint code. This is because in some paths that call btrfs_cow_block(), such as btrfs_search_slot(), we are holding the last reference on the extent buffer @buf so btrfs_force_cow_block() drops the last reference on the @buf extent buffer when it calls free_extent_buffer_stale(buf), which schedules the release of the extent buffer with RCU. This means that if we are on a kernel with preemption, the current task may be preempted before calling trace_btrfs_cow_block() and the extent buffer already released by the time trace_btrfs_cow_block() is called, resulting in a use-after-free.  Fix this by moving the trace_btrfs_cow_block() from btrfs_cow_block() to btrfs_force_cow_block() before the COWed extent buffer is freed. This also has a side effect of invoking the tracepoint in the tree defrag code, at defrag.c:btrfs_realloc_node(), since btrfs_force_cow_block() is called there, but this is fine and it was actually missing there.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56675?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--56675" src="https://img.shields.io/badge/CVE--2024--56675-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Fix UAF via mismatching bpf_prog/attachment RCU flavors  Uprobes always use bpf_prog_run_array_uprobe() under tasks-trace-RCU protection. But it is possible to attach a non-sleepable BPF program to a uprobe, and non-sleepable BPF programs are freed via normal RCU (see __bpf_prog_put_noref()). This leads to UAF of the bpf_prog because a normal RCU grace period does not imply a tasks-trace-RCU grace period.  Fix it by explicitly waiting for a tasks-trace-RCU grace period after removing the attachment of a bpf_prog to a perf_event.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56652?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--56652" src="https://img.shields.io/badge/CVE--2024--56652-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/xe/reg_sr: Remove register pool  That pool implementation doesn't really work: if the krealloc happens to move the memory and return another address, the entries in the xarray become invalid, leading to use-after-free later:  BUG: KASAN: slab-use-after-free in xe_reg_sr_apply_mmio+0x570/0x760 [xe] Read of size 4 at addr ffff8881244b2590 by task modprobe/2753  Allocated by task 2753: kasan_save_stack+0x39/0x70 kasan_save_track+0x14/0x40 kasan_save_alloc_info+0x37/0x60 __kasan_kmalloc+0xc3/0xd0 __kmalloc_node_track_caller_noprof+0x200/0x6d0 krealloc_noprof+0x229/0x380  Simplify the code to fix the bug. A better pooling strategy may be added back later if needed.  (cherry picked from commit e5283bd4dfecbd3335f43b62a68e24dae23f59e4)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53179?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.8: CVE--2024--53179" src="https://img.shields.io/badge/CVE--2024--53179-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix use-after-free of signing key  Customers have reported use-after-free in @ses->auth_key.response with SMB2.1 + sign mounts which occurs due to following race:  task A                         task B cifs_mount() dfs_mount_share() get_session() cifs_mount_get_session()    cifs_send_recv() cifs_get_smb_ses()          compound_send_recv() cifs_setup_session()        smb2_setup_request() kfree_sensitive()           smb2_calc_signature() crypto_shash_setkey() *UAF*  Fix this by ensuring that we have a valid @ses->auth_key.response by checking whether @ses->ses_status is SES_GOOD or SES_EXITING with @ses->ses_lock held.  After commit 24a9799aa8ef ("smb: client: fix UAF in smb2_reconnect_server()"), we made sure to call ->logoff() only when @ses was known to be good (e.g. valid ->auth_key.response), so it's safe to access signing key when @ses->ses_status == SES_EXITING.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57925?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.1: CVE--2024--57925" src="https://img.shields.io/badge/CVE--2024--57925-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: fix a missing return value check bug  In the smb2_send_interim_resp(), if ksmbd_alloc_work_struct() fails to allocate a node, it returns a NULL pointer to the in_work pointer. This can lead to an illegal memory write of in_work->response_buf when allocate_interim_rsp_buf() attempts to perform a kzalloc() on it.  To address this issue, incorporating a check for the return value of ksmbd_alloc_work_struct() ensures that the function returns immediately upon allocation failure, thereby preventing the aforementioned illegal memory access.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57912?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.1: CVE--2024--57912" src="https://img.shields.io/badge/CVE--2024--57912-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: pressure: zpa2326: fix information leak in triggered buffer  The 'sample' local struct is used to push data to user space from a triggered buffer, but it has a hole between the temperature and the timestamp (u32 pressure, u16 temperature, GAP, u64 timestamp). This hole is never initialized.  Initialize the struct to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57911?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.1: CVE--2024--57911" src="https://img.shields.io/badge/CVE--2024--57911-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: dummy: iio_simply_dummy_buffer: fix information leak in triggered buffer  The 'data' array is allocated via kmalloc() and it is used to push data to user space from a triggered buffer, but it does not set values for inactive channels, as it only uses iio_for_each_active_channel() to assign new values.  Use kzalloc for the memory allocation to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57910?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.1: CVE--2024--57910" src="https://img.shields.io/badge/CVE--2024--57910-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: light: vcnl4035: fix information leak in triggered buffer  The 'buffer' local array is used to push data to userspace from a triggered buffer, but it does not set an initial value for the single data element, which is an u16 aligned to 8 bytes. That leaves at least 4 bytes uninitialized even after writing an integer value with regmap_read().  Initialize the array to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57908?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.1: CVE--2024--57908" src="https://img.shields.io/badge/CVE--2024--57908-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: imu: kmx61: fix information leak in triggered buffer  The 'buffer' local array is used to push data to user space from a triggered buffer, but it does not set values for inactive channels, as it only uses iio_for_each_active_channel() to assign new values.  Initialize the array to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57907?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.1: CVE--2024--57907" src="https://img.shields.io/badge/CVE--2024--57907-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: adc: rockchip_saradc: fix information leak in triggered buffer  The 'data' local struct is used to push data to user space from a triggered buffer, but it does not set values for inactive channels, as it only uses iio_for_each_active_channel() to assign new values.  Initialize the struct to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57906?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.1: CVE--2024--57906" src="https://img.shields.io/badge/CVE--2024--57906-lightgrey?label=medium%207.1&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.1</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: adc: ti-ads8688: fix information leak in triggered buffer  The 'buffer' local array is used to push data to user space from a triggered buffer, but it does not set values for inactive channels, as it only uses iio_for_each_active_channel() to assign new values.  Initialize the array to zero before using it to avoid pushing uninitialized information to userspace.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56664?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 7.0: CVE--2024--56664" src="https://img.shields.io/badge/CVE--2024--56664-lightgrey?label=medium%207.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
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

<a href="https://scout.docker.com/v/CVE-2024-56662?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 6.0: CVE--2024--56662" src="https://img.shields.io/badge/CVE--2024--56662-lightgrey?label=medium%206.0&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>6</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  acpi: nfit: vmalloc-out-of-bounds Read in acpi_nfit_ctl  Fix an issue detected by syzbot with KASAN:  BUG: KASAN: vmalloc-out-of-bounds in cmd_to_func drivers/acpi/nfit/ core.c:416 [inline] BUG: KASAN: vmalloc-out-of-bounds in acpi_nfit_ctl+0x20e8/0x24a0 drivers/acpi/nfit/core.c:459  The issue occurs in cmd_to_func when the call_pkg->nd_reserved2 array is accessed without verifying that call_pkg points to a buffer that is appropriately sized as a struct nd_cmd_pkg. This can lead to out-of-bounds access and undefined behavior if the buffer does not have sufficient space.  To address this, a check was added in acpi_nfit_ctl() to ensure that buf is not NULL and that buf_len is less than sizeof(*call_pkg) before accessing it. This ensures safe access to the members of call_pkg, including the nd_reserved2 array.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21658?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21658" src="https://img.shields.io/badge/CVE--2025--21658-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: avoid NULL pointer dereference if no valid extent tree  [BUG] Syzbot reported a crash with the following call trace:  BTRFS info (device loop0): scrub: started on devid 1 BUG: kernel NULL pointer dereference, address: 0000000000000208 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD 106e70067 P4D 106e70067 PUD 107143067 PMD 0 Oops: Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 1 UID: 0 PID: 689 Comm: repro Kdump: loaded Tainted: G           O 6.13.0-rc4-custom+ #206 Tainted: [O]=OOT_MODULE Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS unknown 02/02/2022 RIP: 0010:find_first_extent_item+0x26/0x1f0 [btrfs] Call Trace: <TASK> scrub_find_fill_first_stripe+0x13d/0x3b0 [btrfs] scrub_simple_mirror+0x175/0x260 [btrfs] scrub_stripe+0x5d4/0x6c0 [btrfs] scrub_chunk+0xbb/0x170 [btrfs] scrub_enumerate_chunks+0x2f4/0x5f0 [btrfs] btrfs_scrub_dev+0x240/0x600 [btrfs] btrfs_ioctl+0x1dc8/0x2fa0 [btrfs] ? do_sys_openat2+0xa5/0xf0 __x64_sys_ioctl+0x97/0xc0 do_syscall_64+0x4f/0x120 entry_SYSCALL_64_after_hwframe+0x76/0x7e </TASK>  [CAUSE] The reproducer is using a corrupted image where extent tree root is corrupted, thus forcing to use "rescue=all,ro" mount option to mount the image.  Then it triggered a scrub, but since scrub relies on extent tree to find where the data/metadata extents are, scrub_find_fill_first_stripe() relies on an non-empty extent root.  But unfortunately scrub_find_fill_first_stripe() doesn't really expect an NULL pointer for extent root, it use extent_root to grab fs_info and triggered a NULL pointer dereference.  [FIX] Add an extra check for a valid extent root at the beginning of scrub_find_fill_first_stripe().  The new error path is introduced by 42437a6386ff ("btrfs: introduce mount option rescue=ignorebadroots"), but that's pretty old, and later commit b979547513ff ("btrfs: scrub: introduce helper to find and fill sector info for a scrub_stripe") changed how we do scrub.  So for kernels older than 6.6, the fix will need manual backport.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21649?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21649" src="https://img.shields.io/badge/CVE--2025--21649-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hns3: fix kernel crash when 1588 is sent on HIP08 devices  Currently, HIP08 devices does not register the ptp devices, so the hdev->ptp is NULL. But the tx process would still try to set hardware time stamp info with SKBTX_HW_TSTAMP flag and cause a kernel crash.  [  128.087798] Unable to handle kernel NULL pointer dereference at virtual address 0000000000000018 ... [  128.280251] pc : hclge_ptp_set_tx_info+0x2c/0x140 [hclge] [  128.286600] lr : hclge_ptp_set_tx_info+0x20/0x140 [hclge] [  128.292938] sp : ffff800059b93140 [  128.297200] x29: ffff800059b93140 x28: 0000000000003280 [  128.303455] x27: ffff800020d48280 x26: ffff0cb9dc814080 [  128.309715] x25: ffff0cb9cde93fa0 x24: 0000000000000001 [  128.315969] x23: 0000000000000000 x22: 0000000000000194 [  128.322219] x21: ffff0cd94f986000 x20: 0000000000000000 [  128.328462] x19: ffff0cb9d2a166c0 x18: 0000000000000000 [  128.334698] x17: 0000000000000000 x16: ffffcf1fc523ed24 [  128.340934] x15: 0000ffffd530a518 x14: 0000000000000000 [  128.347162] x13: ffff0cd6bdb31310 x12: 0000000000000368 [  128.353388] x11: ffff0cb9cfbc7070 x10: ffff2cf55dd11e02 [  128.359606] x9 : ffffcf1f85a212b4 x8 : ffff0cd7cf27dab0 [  128.365831] x7 : 0000000000000a20 x6 : ffff0cd7cf27d000 [  128.372040] x5 : 0000000000000000 x4 : 000000000000ffff [  128.378243] x3 : 0000000000000400 x2 : ffffcf1f85a21294 [  128.384437] x1 : ffff0cb9db520080 x0 : ffff0cb9db500080 [  128.390626] Call trace: [  128.393964]  hclge_ptp_set_tx_info+0x2c/0x140 [hclge] [  128.399893]  hns3_nic_net_xmit+0x39c/0x4c4 [hns3] [  128.405468]  xmit_one.constprop.0+0xc4/0x200 [  128.410600]  dev_hard_start_xmit+0x54/0xf0 [  128.415556]  sch_direct_xmit+0xe8/0x634 [  128.420246]  __dev_queue_xmit+0x224/0xc70 [  128.425101]  dev_queue_xmit+0x1c/0x40 [  128.429608]  ovs_vport_send+0xac/0x1a0 [openvswitch] [  128.435409]  do_output+0x60/0x17c [openvswitch] [  128.440770]  do_execute_actions+0x898/0x8c4 [openvswitch] [  128.446993]  ovs_execute_actions+0x64/0xf0 [openvswitch] [  128.453129]  ovs_dp_process_packet+0xa0/0x224 [openvswitch] [  128.459530]  ovs_vport_receive+0x7c/0xfc [openvswitch] [  128.465497]  internal_dev_xmit+0x34/0xb0 [openvswitch] [  128.471460]  xmit_one.constprop.0+0xc4/0x200 [  128.476561]  dev_hard_start_xmit+0x54/0xf0 [  128.481489]  __dev_queue_xmit+0x968/0xc70 [  128.486330]  dev_queue_xmit+0x1c/0x40 [  128.490856]  ip_finish_output2+0x250/0x570 [  128.495810]  __ip_finish_output+0x170/0x1e0 [  128.500832]  ip_finish_output+0x3c/0xf0 [  128.505504]  ip_output+0xbc/0x160 [  128.509654]  ip_send_skb+0x58/0xd4 [  128.513892]  udp_send_skb+0x12c/0x354 [  128.518387]  udp_sendmsg+0x7a8/0x9c0 [  128.522793]  inet_sendmsg+0x4c/0x8c [  128.527116]  __sock_sendmsg+0x48/0x80 [  128.531609]  __sys_sendto+0x124/0x164 [  128.536099]  __arm64_sys_sendto+0x30/0x5c [  128.540935]  invoke_syscall+0x50/0x130 [  128.545508]  el0_svc_common.constprop.0+0x10c/0x124 [  128.551205]  do_el0_svc+0x34/0xdc [  128.555347]  el0_svc+0x20/0x30 [  128.559227]  el0_sync_handler+0xb8/0xc0 [  128.563883]  el0_sync+0x160/0x180

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21642?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21642" src="https://img.shields.io/badge/CVE--2025--21642-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: sysctl: sched: avoid using current->nsproxy  Using the 'net' structure via 'current' is not recommended for different reasons.  First, if the goal is to use it to read or write per-netns data, this is inconsistent with how the "generic" sysctl entries are doing: directly by only using pointers set to the table entry, e.g. table->data. Linked to that, the per-netns data should always be obtained from the table linked to the netns it had been created for, which may not coincide with the reader's or writer's netns.  Another reason is that access to current->nsproxy->netns can oops if attempted when current->nsproxy had been dropped when the current task is exiting. This is what syzbot found, when using acct(2):  Oops: general protection fault, probably for non-canonical address 0xdffffc0000000005: 0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range [0x0000000000000028-0x000000000000002f] CPU: 1 UID: 0 PID: 5924 Comm: syz-executor Not tainted 6.13.0-rc5-syzkaller-00004-gccb98ccef0e5 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:proc_scheduler+0xc6/0x3c0 net/mptcp/ctrl.c:125 Code: 03 42 80 3c 38 00 0f 85 fe 02 00 00 4d 8b a4 24 08 09 00 00 48 b8 00 00 00 00 00 fc ff df 49 8d 7c 24 28 48 89 fa 48 c1 ea 03 <80> 3c 02 00 0f 85 cc 02 00 00 4d 8b 7c 24 28 48 8d 84 24 c8 00 00 RSP: 0018:ffffc900034774e8 EFLAGS: 00010206  RAX: dffffc0000000000 RBX: 1ffff9200068ee9e RCX: ffffc90003477620 RDX: 0000000000000005 RSI: ffffffff8b08f91e RDI: 0000000000000028 RBP: 0000000000000001 R08: ffffc90003477710 R09: 0000000000000040 R10: 0000000000000040 R11: 00000000726f7475 R12: 0000000000000000 R13: ffffc90003477620 R14: ffffc90003477710 R15: dffffc0000000000 FS:  0000000000000000(0000) GS:ffff8880b8700000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fee3cd452d8 CR3: 000000007d116000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> proc_sys_call_handler+0x403/0x5d0 fs/proc/proc_sysctl.c:601 __kernel_write_iter+0x318/0xa80 fs/read_write.c:612 __kernel_write+0xf6/0x140 fs/read_write.c:632 do_acct_process+0xcb0/0x14a0 kernel/acct.c:539 acct_pin_kill+0x2d/0x100 kernel/acct.c:192 pin_kill+0x194/0x7c0 fs/fs_pin.c:44 mnt_pin_kill+0x61/0x1e0 fs/fs_pin.c:81 cleanup_mnt+0x3ac/0x450 fs/namespace.c:1366 task_work_run+0x14e/0x250 kernel/task_work.c:239 exit_task_work include/linux/task_work.h:43 [inline] do_exit+0xad8/0x2d70 kernel/exit.c:938 do_group_exit+0xd3/0x2a0 kernel/exit.c:1087 get_signal+0x2576/0x2610 kernel/signal.c:3017 arch_do_signal_or_restart+0x90/0x7e0 arch/x86/kernel/signal.c:337 exit_to_user_mode_loop kernel/entry/common.c:111 [inline] exit_to_user_mode_prepare include/linux/entry-common.h:329 [inline] __syscall_exit_to_user_mode_work kernel/entry/common.c:207 [inline] syscall_exit_to_user_mode+0x150/0x2a0 kernel/entry/common.c:218 do_syscall_64+0xda/0x250 arch/x86/entry/common.c:89 entry_SYSCALL_64_after_hwframe+0x77/0x7f RIP: 0033:0x7fee3cb87a6a Code: Unable to access opcode bytes at 0x7fee3cb87a40. RSP: 002b:00007fffcccac688 EFLAGS: 00000202 ORIG_RAX: 0000000000000037 RAX: 0000000000000000 RBX: 00007fffcccac710 RCX: 00007fee3cb87a6a RDX: 0000000000000041 RSI: 0000000000000000 RDI: 0000000000000003 RBP: 0000000000000003 R08: 00007fffcccac6ac R09: 00007fffcccacac7 R10: 00007fffcccac710 R11: 0000000000000202 R12: 00007fee3cd49500 R13: 00007fffcccac6ac R14: 0000000000000000 R15: 00007fee3cd4b000 </TASK> Modules linked in: ---[ end trace 0000000000000000 ]--- RIP: 0010:proc_scheduler+0xc6/0x3c0 net/mptcp/ctrl.c:125 Code: 03 42 80 3c 38 00 0f 85 fe 02 00 00 4d 8b a4 24 08 09 00 00 48 b8 00 00 00 00 00 fc ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21640?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21640" src="https://img.shields.io/badge/CVE--2025--21640-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: cookie_hmac_alg: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, as this is the only member needed from the 'net' structure, but that would increase the size of this fix, to use '*data' everywhere 'net->sctp.sctp_hmac_alg' is used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21639?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21639" src="https://img.shields.io/badge/CVE--2025--21639-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: rto_min/max: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, as this is the only member needed from the 'net' structure, but that would increase the size of this fix, to use '*data' everywhere 'net->sctp.rto_min/max' is used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21638?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21638" src="https://img.shields.io/badge/CVE--2025--21638-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: auth_enable: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, but that would increase the size of this fix, while 'sctp.ctl_sock' still needs to be retrieved from 'net' structure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21637?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21637" src="https://img.shields.io/badge/CVE--2025--21637-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: udp_port: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, but that would increase the size of this fix, while 'sctp.ctl_sock' still needs to be retrieved from 'net' structure.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21636?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21636" src="https://img.shields.io/badge/CVE--2025--21636-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.025%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sctp: sysctl: plpmtud_probe_interval: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The 'net' structure can be obtained from the table->data using container_of().  Note that table->data could also be used directly, as this is the only member needed from the 'net' structure, but that would increase the size of this fix, to use '*data' everywhere 'net->sctp.probe_interval' is used.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21635?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21635" src="https://img.shields.io/badge/CVE--2025--21635-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  rds: sysctl: rds_tcp_{rcv,snd}buf: avoid using current->nsproxy  As mentioned in a previous commit of this series, using the 'net' structure via 'current' is not recommended for different reasons:  - Inconsistency: getting info from the reader's/writer's netns vs only from the opener's netns.  - current->nsproxy can be NULL in some cases, resulting in an 'Oops' (null-ptr-deref), e.g. when the current task is exiting, as spotted by syzbot [1] using acct(2).  The per-netns structure can be obtained from the table->data using container_of(), then the 'net' one can be retrieved from the listen socket (if available).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21634?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2025--21634" src="https://img.shields.io/badge/CVE--2025--21634-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cgroup/cpuset: remove kernfs active break  A warning was found:  WARNING: CPU: 10 PID: 3486953 at fs/kernfs/file.c:828 CPU: 10 PID: 3486953 Comm: rmdir Kdump: loaded Tainted: G RIP: 0010:kernfs_should_drain_open_files+0x1a1/0x1b0 RSP: 0018:ffff8881107ef9e0 EFLAGS: 00010202 RAX: 0000000080000002 RBX: ffff888154738c00 RCX: dffffc0000000000 RDX: 0000000000000007 RSI: 0000000000000004 RDI: ffff888154738c04 RBP: ffff888154738c04 R08: ffffffffaf27fa15 R09: ffffed102a8e7180 R10: ffff888154738c07 R11: 0000000000000000 R12: ffff888154738c08 R13: ffff888750f8c000 R14: ffff888750f8c0e8 R15: ffff888154738ca0 FS:  00007f84cd0be740(0000) GS:ffff8887ddc00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000555f9fbe00c8 CR3: 0000000153eec001 CR4: 0000000000370ee0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: kernfs_drain+0x15e/0x2f0 __kernfs_remove+0x165/0x300 kernfs_remove_by_name_ns+0x7b/0xc0 cgroup_rm_file+0x154/0x1c0 cgroup_addrm_files+0x1c2/0x1f0 css_clear_dir+0x77/0x110 kill_css+0x4c/0x1b0 cgroup_destroy_locked+0x194/0x380 cgroup_rmdir+0x2a/0x140  It can be explained by: rmdir 				echo 1 > cpuset.cpus kernfs_fop_write_iter // active=0 cgroup_rm_file kernfs_remove_by_name_ns	kernfs_get_active // active=1 __kernfs_remove					  // active=0x80000002 kernfs_drain			cpuset_write_resmask wait_event //waiting (active == 0x80000001) kernfs_break_active_protection // active = 0x80000001 // continue kernfs_unbreak_active_protection // active = 0x80000002 ... kernfs_should_drain_open_files // warning occurs kernfs_put_active  This warning is caused by 'kernfs_break_active_protection' when it is writing to cpuset.cpus, and the cgroup is removed concurrently.  The commit 3a5a6d0c2b03 ("cpuset: don't nest cgroup_mutex inside get_online_cpus()") made cpuset_hotplug_workfn asynchronous, This change involves calling flush_work(), which can create a multiple processes circular locking dependency that involve cgroup_mutex, potentially leading to a deadlock. To avoid deadlock. the commit 76bb5ab8f6e3 ("cpuset: break kernfs active protection in cpuset_write_resmask()") added 'kernfs_break_active_protection' in the cpuset_write_resmask. This could lead to this warning.  After the commit 2125c0034c5d ("cgroup/cpuset: Make cpuset hotplug processing synchronous"), the cpuset_write_resmask no longer needs to wait the hotplug to finish, which means that concurrent hotplug and cpuset operations are no longer possible. Therefore, the deadlock doesn't exist anymore and it does not have to 'break active protection' now. To fix this warning, just remove kernfs_break_active_protection operation in the 'cpuset_write_resmask'.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57946?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57946" src="https://img.shields.io/badge/CVE--2024--57946-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  virtio-blk: don't keep queue frozen during system suspend  Commit 4ce6e2db00de ("virtio-blk: Ensure no requests in virtqueues before deleting vqs.") replaces queue quiesce with queue freeze in virtio-blk's PM callbacks. And the motivation is to drain inflight IOs before suspending.  block layer's queue freeze looks very handy, but it is also easy to cause deadlock, such as, any attempt to call into bio_queue_enter() may run into deadlock if the queue is frozen in current context. There are all kinds of ->suspend() called in suspend context, so keeping queue frozen in the whole suspend context isn't one good idea. And Marek reported lockdep warning[1] caused by virtio-blk's freeze queue in virtblk_freeze().  [1] https://lore.kernel.org/linux-block/ca16370e-d646-4eee-b9cc-87277c89c43c@samsung.com/  Given the motivation is to drain in-flight IOs, it can be done by calling freeze & unfreeze, meantime restore to previous behavior by keeping queue quiesced during suspend.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57940?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57940" src="https://img.shields.io/badge/CVE--2024--57940-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  exfat: fix the infinite loop in exfat_readdir()  If the file system is corrupted so that a cluster is linked to itself in the cluster chain, and there is an unused directory entry in the cluster, 'dentry' will not be incremented, causing condition 'dentry < max_dentries' unable to prevent an infinite loop.  This infinite loop causes s_lock not to be released, and other tasks will hang, such as exfat_sync_fs().  This commit stops traversing the cluster chain when there is unused directory entry in the cluster to avoid this infinite loop.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57939?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57939" src="https://img.shields.io/badge/CVE--2024--57939-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  riscv: Fix sleeping in invalid context in die()  die() can be called in exception handler, and therefore cannot sleep. However, die() takes spinlock_t which can sleep with PREEMPT_RT enabled. That causes the following warning:  BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48 in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 285, name: mutex preempt_count: 110001, expected: 0 RCU nest depth: 0, expected: 0 CPU: 0 UID: 0 PID: 285 Comm: mutex Not tainted 6.12.0-rc7-00022-ge19049cf7d56-dirty #234 Hardware name: riscv-virtio,qemu (DT) Call Trace: dump_backtrace+0x1c/0x24 show_stack+0x2c/0x38 dump_stack_lvl+0x5a/0x72 dump_stack+0x14/0x1c __might_resched+0x130/0x13a rt_spin_lock+0x2a/0x5c die+0x24/0x112 do_trap_insn_illegal+0xa0/0xea _new_vmalloc_restore_context_a0+0xcc/0xd8 Oops - illegal instruction [#1]  Switch to use raw_spinlock_t, which does not sleep even with PREEMPT_RT enabled.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57938?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57938" src="https://img.shields.io/badge/CVE--2024--57938-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/sctp: Prevent autoclose integer overflow in sctp_association_init()  While by default max_autoclose equals to INT_MAX / HZ, one may set net.sctp.max_autoclose to UINT_MAX. There is code in sctp_association_init() that can consequently trigger overflow.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57933?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57933" src="https://img.shields.io/badge/CVE--2024--57933-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gve: guard XSK operations on the existence of queues  This patch predicates the enabling and disabling of XSK pools on the existence of queues. As it stands, if the interface is down, disabling or enabling XSK pools would result in a crash, as the RX queue pointer would be NULL. XSK pool registration will occur as part of the next interface up.  Similarly, xsk_wakeup needs be guarded against queues disappearing while the function is executing, so a check against the GVE_PRIV_FLAGS_NAPI_ENABLED flag is added to synchronize with the disabling of the bit and the synchronize_net() in gve_turndown.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57916?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57916" src="https://img.shields.io/badge/CVE--2024--57916-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.021%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  misc: microchip: pci1xxxx: Resolve kernel panic during GPIO IRQ handling  Resolve kernel panic caused by improper handling of IRQs while accessing GPIO values. This is done by replacing generic_handle_irq with handle_nested_irq.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57902?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57902" src="https://img.shields.io/badge/CVE--2024--57902-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  af_packet: fix vlan_get_tci() vs MSG_PEEK  Blamed commit forgot MSG_PEEK case, allowing a crash [1] as found by syzbot.  Rework vlan_get_tci() to not touch skb at all, so that it can be used from many cpus on the same skb.  Add a const qualifier to skb argument.  [1] skbuff: skb_under_panic: text:ffffffff8a8da482 len:32 put:14 head:ffff88807a1d5800 data:ffff88807a1d5810 tail:0x14 end:0x140 dev:<NULL> ------------[ cut here ]------------ kernel BUG at net/core/skbuff.c:206 ! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 0 UID: 0 PID: 5880 Comm: syz-executor172 Not tainted 6.13.0-rc3-syzkaller-00762-g9268abe611b0 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:skb_panic net/core/skbuff.c:206 [inline] RIP: 0010:skb_under_panic+0x14b/0x150 net/core/skbuff.c:216 Code: 0b 8d 48 c7 c6 9e 6c 26 8e 48 8b 54 24 08 8b 0c 24 44 8b 44 24 04 4d 89 e9 50 41 54 41 57 41 56 e8 3a 5a 79 f7 48 83 c4 20 90 <0f> 0b 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 RSP: 0018:ffffc90003baf5b8 EFLAGS: 00010286 RAX: 0000000000000087 RBX: dffffc0000000000 RCX: 8565c1eec37aa000 RDX: 0000000000000000 RSI: 0000000080000000 RDI: 0000000000000000 RBP: ffff88802616fb50 R08: ffffffff817f0a4c R09: 1ffff92000775e50 R10: dffffc0000000000 R11: fffff52000775e51 R12: 0000000000000140 R13: ffff88807a1d5800 R14: ffff88807a1d5810 R15: 0000000000000014 FS:  00007fa03261f6c0(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffd65753000 CR3: 0000000031720000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> skb_push+0xe5/0x100 net/core/skbuff.c:2636 vlan_get_tci+0x272/0x550 net/packet/af_packet.c:565 packet_recvmsg+0x13c9/0x1ef0 net/packet/af_packet.c:3616 sock_recvmsg_nosec net/socket.c:1044 [inline] sock_recvmsg+0x22f/0x280 net/socket.c:1066 ____sys_recvmsg+0x1c6/0x480 net/socket.c:2814 ___sys_recvmsg net/socket.c:2856 [inline] do_recvmmsg+0x426/0xab0 net/socket.c:2951 __sys_recvmmsg net/socket.c:3025 [inline] __do_sys_recvmmsg net/socket.c:3048 [inline] __se_sys_recvmmsg net/socket.c:3041 [inline] __x64_sys_recvmmsg+0x199/0x250 net/socket.c:3041 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57901?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57901" src="https://img.shields.io/badge/CVE--2024--57901-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  af_packet: fix vlan_get_protocol_dgram() vs MSG_PEEK  Blamed commit forgot MSG_PEEK case, allowing a crash [1] as found by syzbot.  Rework vlan_get_protocol_dgram() to not touch skb at all, so that it can be used from many cpus on the same skb.  Add a const qualifier to skb argument.  [1] skbuff: skb_under_panic: text:ffffffff8a8ccd05 len:29 put:14 head:ffff88807fc8e400 data:ffff88807fc8e3f4 tail:0x11 end:0x140 dev:<NULL> ------------[ cut here ]------------ kernel BUG at net/core/skbuff.c:206 ! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 1 UID: 0 PID: 5892 Comm: syz-executor883 Not tainted 6.13.0-rc4-syzkaller-00054-gd6ef8b40d075 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:skb_panic net/core/skbuff.c:206 [inline] RIP: 0010:skb_under_panic+0x14b/0x150 net/core/skbuff.c:216 Code: 0b 8d 48 c7 c6 86 d5 25 8e 48 8b 54 24 08 8b 0c 24 44 8b 44 24 04 4d 89 e9 50 41 54 41 57 41 56 e8 5a 69 79 f7 48 83 c4 20 90 <0f> 0b 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 RSP: 0018:ffffc900038d7638 EFLAGS: 00010282 RAX: 0000000000000087 RBX: dffffc0000000000 RCX: 609ffd18ea660600 RDX: 0000000000000000 RSI: 0000000080000000 RDI: 0000000000000000 RBP: ffff88802483c8d0 R08: ffffffff817f0a8c R09: 1ffff9200071ae60 R10: dffffc0000000000 R11: fffff5200071ae61 R12: 0000000000000140 R13: ffff88807fc8e400 R14: ffff88807fc8e3f4 R15: 0000000000000011 FS:  00007fbac5e006c0(0000) GS:ffff8880b8700000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007fbac5e00d58 CR3: 000000001238e000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> skb_push+0xe5/0x100 net/core/skbuff.c:2636 vlan_get_protocol_dgram+0x165/0x290 net/packet/af_packet.c:585 packet_recvmsg+0x948/0x1ef0 net/packet/af_packet.c:3552 sock_recvmsg_nosec net/socket.c:1033 [inline] sock_recvmsg+0x22f/0x280 net/socket.c:1055 ____sys_recvmsg+0x1c6/0x480 net/socket.c:2803 ___sys_recvmsg net/socket.c:2845 [inline] do_recvmmsg+0x426/0xab0 net/socket.c:2940 __sys_recvmmsg net/socket.c:3014 [inline] __do_sys_recvmmsg net/socket.c:3037 [inline] __se_sys_recvmmsg net/socket.c:3030 [inline] __x64_sys_recvmmsg+0x199/0x250 net/socket.c:3030 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57895?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57895" src="https://img.shields.io/badge/CVE--2024--57895-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: set ATTR_CTIME flags when setting mtime  David reported that the new warning from setattr_copy_mgtime is coming like the following.  [  113.215316] ------------[ cut here ]------------ [  113.215974] WARNING: CPU: 1 PID: 31 at fs/attr.c:300 setattr_copy+0x1ee/0x200 [  113.219192] CPU: 1 UID: 0 PID: 31 Comm: kworker/1:1 Not tainted 6.13.0-rc1+ #234 [  113.220127] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.2-3-gd478f380-rebuilt.opensuse.org 04/01/2014 [  113.221530] Workqueue: ksmbd-io handle_ksmbd_work [ksmbd] [  113.222220] RIP: 0010:setattr_copy+0x1ee/0x200 [  113.222833] Code: 24 28 49 8b 44 24 30 48 89 53 58 89 43 6c 5b 41 5c 41 5d 41 5e 41 5f 5d c3 cc cc cc cc 48 89 df e8 77 d6 ff ff e9 cd fe ff ff <0f> 0b e9 be fe ff ff 66 0 [  113.225110] RSP: 0018:ffffaf218010fb68 EFLAGS: 00010202 [  113.225765] RAX: 0000000000000120 RBX: ffffa446815f8568 RCX: 0000000000000003 [  113.226667] RDX: ffffaf218010fd38 RSI: ffffa446815f8568 RDI: ffffffff94eb03a0 [  113.227531] RBP: ffffaf218010fb90 R08: 0000001a251e217d R09: 00000000675259fa [  113.228426] R10: 0000000002ba8a6d R11: ffffa4468196c7a8 R12: ffffaf218010fd38 [  113.229304] R13: 0000000000000120 R14: ffffffff94eb03a0 R15: 0000000000000000 [  113.230210] FS:  0000000000000000(0000) GS:ffffa44739d00000(0000) knlGS:0000000000000000 [  113.231215] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  113.232055] CR2: 00007efe0053d27e CR3: 000000000331a000 CR4: 00000000000006b0 [  113.232926] DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 [  113.233812] DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 [  113.234797] Call Trace: [  113.235116]  <TASK> [  113.235393]  ? __warn+0x73/0xd0 [  113.235802]  ? setattr_copy+0x1ee/0x200 [  113.236299]  ? report_bug+0xf3/0x1e0 [  113.236757]  ? handle_bug+0x4d/0x90 [  113.237202]  ? exc_invalid_op+0x13/0x60 [  113.237689]  ? asm_exc_invalid_op+0x16/0x20 [  113.238185]  ? setattr_copy+0x1ee/0x200 [  113.238692]  btrfs_setattr+0x80/0x820 [btrfs] [  113.239285]  ? get_stack_info_noinstr+0x12/0xf0 [  113.239857]  ? __module_address+0x22/0xa0 [  113.240368]  ? handle_ksmbd_work+0x6e/0x460 [ksmbd] [  113.240993]  ? __module_text_address+0x9/0x50 [  113.241545]  ? __module_address+0x22/0xa0 [  113.242033]  ? unwind_next_frame+0x10e/0x920 [  113.242600]  ? __pfx_stack_trace_consume_entry+0x10/0x10 [  113.243268]  notify_change+0x2c2/0x4e0 [  113.243746]  ? stack_depot_save_flags+0x27/0x730 [  113.244339]  ? set_file_basic_info+0x130/0x2b0 [ksmbd] [  113.244993]  set_file_basic_info+0x130/0x2b0 [ksmbd] [  113.245613]  ? process_scheduled_works+0xbe/0x310 [  113.246181]  ? worker_thread+0x100/0x240 [  113.246696]  ? kthread+0xc8/0x100 [  113.247126]  ? ret_from_fork+0x2b/0x40 [  113.247606]  ? ret_from_fork_asm+0x1a/0x30 [  113.248132]  smb2_set_info+0x63f/0xa70 [ksmbd]  ksmbd is trying to set the atime and mtime via notify_change without also setting the ctime. so This patch add ATTR_CTIME flags when setting mtime to avoid a warning.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57890?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57890" src="https://img.shields.io/badge/CVE--2024--57890-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/uverbs: Prevent integer overflow issue  In the expression "cmd.wqe_size * cmd.wr_count", both variables are u32 values that come from the user so the multiplication can lead to integer wrapping.  Then we pass the result to uverbs_request_next_ptr() which also could potentially wrap.  The "cmd.sge_count * sizeof(struct ib_uverbs_sge)" multiplication can also overflow on 32bit systems although it's fine on 64bit systems.  This patch does two things.  First, I've re-arranged the condition in uverbs_request_next_ptr() so that the use controlled variable "len" is on one side of the comparison by itself without any math.  Then I've modified all the callers to use size_mul() for the multiplications.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57882?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57882" src="https://img.shields.io/badge/CVE--2024--57882-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: fix TCP options overflow.  Syzbot reported the following splat:  Oops: general protection fault, probably for non-canonical address 0xdffffc0000000001: 0000 [#1] PREEMPT SMP KASAN PTI KASAN: null-ptr-deref in range [0x0000000000000008-0x000000000000000f] CPU: 1 UID: 0 PID: 5836 Comm: sshd Not tainted 6.13.0-rc3-syzkaller #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 11/25/2024 RIP: 0010:_compound_head include/linux/page-flags.h:242 [inline] RIP: 0010:put_page+0x23/0x260 include/linux/mm.h:1552 Code: 90 90 90 90 90 90 90 55 41 57 41 56 53 49 89 fe 48 bd 00 00 00 00 00 fc ff df e8 f8 5e 12 f8 49 8d 5e 08 48 89 d8 48 c1 e8 03 <80> 3c 28 00 74 08 48 89 df e8 8f c7 78 f8 48 8b 1b 48 89 de 48 83 RSP: 0000:ffffc90003916c90 EFLAGS: 00010202 RAX: 0000000000000001 RBX: 0000000000000008 RCX: ffff888030458000 RDX: 0000000000000100 RSI: 0000000000000000 RDI: 0000000000000000 RBP: dffffc0000000000 R08: ffffffff898ca81d R09: 1ffff110054414ac R10: dffffc0000000000 R11: ffffed10054414ad R12: 0000000000000007 R13: ffff88802a20a542 R14: 0000000000000000 R15: 0000000000000000 FS:  00007f34f496e800(0000) GS:ffff8880b8700000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f9d6ec9ec28 CR3: 000000004d260000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> skb_page_unref include/linux/skbuff_ref.h:43 [inline] __skb_frag_unref include/linux/skbuff_ref.h:56 [inline] skb_release_data+0x483/0x8a0 net/core/skbuff.c:1119 skb_release_all net/core/skbuff.c:1190 [inline] __kfree_skb+0x55/0x70 net/core/skbuff.c:1204 tcp_clean_rtx_queue net/ipv4/tcp_input.c:3436 [inline] tcp_ack+0x2442/0x6bc0 net/ipv4/tcp_input.c:4032 tcp_rcv_state_process+0x8eb/0x44e0 net/ipv4/tcp_input.c:6805 tcp_v4_do_rcv+0x77d/0xc70 net/ipv4/tcp_ipv4.c:1939 tcp_v4_rcv+0x2dc0/0x37f0 net/ipv4/tcp_ipv4.c:2351 ip_protocol_deliver_rcu+0x22e/0x440 net/ipv4/ip_input.c:205 ip_local_deliver_finish+0x341/0x5f0 net/ipv4/ip_input.c:233 NF_HOOK+0x3a4/0x450 include/linux/netfilter.h:314 NF_HOOK+0x3a4/0x450 include/linux/netfilter.h:314 __netif_receive_skb_one_core net/core/dev.c:5672 [inline] __netif_receive_skb+0x2bf/0x650 net/core/dev.c:5785 process_backlog+0x662/0x15b0 net/core/dev.c:6117 __napi_poll+0xcb/0x490 net/core/dev.c:6883 napi_poll net/core/dev.c:6952 [inline] net_rx_action+0x89b/0x1240 net/core/dev.c:7074 handle_softirqs+0x2d4/0x9b0 kernel/softirq.c:561 __do_softirq kernel/softirq.c:595 [inline] invoke_softirq kernel/softirq.c:435 [inline] __irq_exit_rcu+0xf7/0x220 kernel/softirq.c:662 irq_exit_rcu+0x9/0x30 kernel/softirq.c:678 instr_sysvec_apic_timer_interrupt arch/x86/kernel/apic/apic.c:1049 [inline] sysvec_apic_timer_interrupt+0x57/0xc0 arch/x86/kernel/apic/apic.c:1049 asm_sysvec_apic_timer_interrupt+0x1a/0x20 arch/x86/include/asm/idtentry.h:702 RIP: 0033:0x7f34f4519ad5 Code: 85 d2 74 0d 0f 10 02 48 8d 54 24 20 0f 11 44 24 20 64 8b 04 25 18 00 00 00 85 c0 75 27 41 b8 08 00 00 00 b8 0f 01 00 00 0f 05 <48> 3d 00 f0 ff ff 76 75 48 8b 15 24 73 0d 00 f7 d8 64 89 02 48 83 RSP: 002b:00007ffec5b32ce0 EFLAGS: 00000246 RAX: 0000000000000001 RBX: 00000000000668a0 RCX: 00007f34f4519ad5 RDX: 00007ffec5b32d00 RSI: 0000000000000004 RDI: 0000564f4bc6cae0 RBP: 0000564f4bc6b5a0 R08: 0000000000000008 R09: 0000000000000000 R10: 00007ffec5b32de8 R11: 0000000000000246 R12: 0000564f48ea8aa4 R13: 0000000000000001 R14: 0000564f48ea93e8 R15: 00007ffec5b32d68 </TASK>  Eric noted a probable shinfo->nr_frags corruption, which indeed occurs.  The root cause is a buggy MPTCP option len computation in some circumstances: the ADD_ADDR option should be mutually exclusive with DSS since the blamed commit.  Still, mptcp_established_options_add_addr() tries to set the relevant info in mptcp_out_options, if ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57841?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57841" src="https://img.shields.io/badge/CVE--2024--57841-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fix memory leak in tcp_conn_request()  If inet_csk_reqsk_queue_hash_add() return false, tcp_conn_request() will return without free the dst memory, which allocated in af_ops->route_req.  Here is the kmemleak stack:  unreferenced object 0xffff8881198631c0 (size 240): comm "softirq", pid 0, jiffies 4299266571 (age 1802.392s) hex dump (first 32 bytes): 00 10 9b 03 81 88 ff ff 80 98 da bc ff ff ff ff  ................ 81 55 18 bb ff ff ff ff 00 00 00 00 00 00 00 00  .U.............. backtrace: [<ffffffffb93e8d4c>] kmem_cache_alloc+0x60c/0xa80 [<ffffffffba11b4c5>] dst_alloc+0x55/0x250 [<ffffffffba227bf6>] rt_dst_alloc+0x46/0x1d0 [<ffffffffba23050a>] __mkroute_output+0x29a/0xa50 [<ffffffffba23456b>] ip_route_output_key_hash+0x10b/0x240 [<ffffffffba2346bd>] ip_route_output_flow+0x1d/0x90 [<ffffffffba254855>] inet_csk_route_req+0x2c5/0x500 [<ffffffffba26b331>] tcp_conn_request+0x691/0x12c0 [<ffffffffba27bd08>] tcp_rcv_state_process+0x3c8/0x11b0 [<ffffffffba2965c6>] tcp_v4_do_rcv+0x156/0x3b0 [<ffffffffba299c98>] tcp_v4_rcv+0x1cf8/0x1d80 [<ffffffffba239656>] ip_protocol_deliver_rcu+0xf6/0x360 [<ffffffffba2399a6>] ip_local_deliver_finish+0xe6/0x1e0 [<ffffffffba239b8e>] ip_local_deliver+0xee/0x360 [<ffffffffba239ead>] ip_rcv+0xad/0x2f0 [<ffffffffba110943>] __netif_receive_skb_one_core+0x123/0x140  Call dst_release() to free the dst memory when inet_csk_reqsk_queue_hash_add() return false in tcp_conn_request().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57807?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57807" src="https://img.shields.io/badge/CVE--2024--57807-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: megaraid_sas: Fix for a potential deadlock  This fixes a 'possible circular locking dependency detected' warning CPU0                    CPU1 ----                    ---- lock(&instance->reset_mutex); lock(&shost->scan_mutex); lock(&instance->reset_mutex); lock(&shost->scan_mutex);  Fix this by temporarily releasing the reset_mutex.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57802?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--57802" src="https://img.shields.io/badge/CVE--2024--57802-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netrom: check buffer length before accessing it  Syzkaller reports an uninit value read from ax25cmp when sending raw message through ieee802154 implementation.  ===================================================== BUG: KMSAN: uninit-value in ax25cmp+0x3a5/0x460 net/ax25/ax25_addr.c:119 ax25cmp+0x3a5/0x460 net/ax25/ax25_addr.c:119 nr_dev_get+0x20e/0x450 net/netrom/nr_route.c:601 nr_route_frame+0x1a2/0xfc0 net/netrom/nr_route.c:774 nr_xmit+0x5a/0x1c0 net/netrom/nr_dev.c:144 __netdev_start_xmit include/linux/netdevice.h:4940 [inline] netdev_start_xmit include/linux/netdevice.h:4954 [inline] xmit_one net/core/dev.c:3548 [inline] dev_hard_start_xmit+0x247/0xa10 net/core/dev.c:3564 __dev_queue_xmit+0x33b8/0x5130 net/core/dev.c:4349 dev_queue_xmit include/linux/netdevice.h:3134 [inline] raw_sendmsg+0x654/0xc10 net/ieee802154/socket.c:299 ieee802154_sock_sendmsg+0x91/0xc0 net/ieee802154/socket.c:96 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745 [inline] ____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638 __sys_sendmsg net/socket.c:2667 [inline] __do_sys_sendmsg net/socket.c:2676 [inline] __se_sys_sendmsg net/socket.c:2674 [inline] __x64_sys_sendmsg+0x307/0x490 net/socket.c:2674 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0x44/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b  Uninit was created at: slab_post_alloc_hook+0x129/0xa70 mm/slab.h:768 slab_alloc_node mm/slub.c:3478 [inline] kmem_cache_alloc_node+0x5e9/0xb10 mm/slub.c:3523 kmalloc_reserve+0x13d/0x4a0 net/core/skbuff.c:560 __alloc_skb+0x318/0x740 net/core/skbuff.c:651 alloc_skb include/linux/skbuff.h:1286 [inline] alloc_skb_with_frags+0xc8/0xbd0 net/core/skbuff.c:6334 sock_alloc_send_pskb+0xa80/0xbf0 net/core/sock.c:2780 sock_alloc_send_skb include/net/sock.h:1884 [inline] raw_sendmsg+0x36d/0xc10 net/ieee802154/socket.c:282 ieee802154_sock_sendmsg+0x91/0xc0 net/ieee802154/socket.c:96 sock_sendmsg_nosec net/socket.c:730 [inline] __sock_sendmsg net/socket.c:745 [inline] ____sys_sendmsg+0x9c2/0xd60 net/socket.c:2584 ___sys_sendmsg+0x28d/0x3c0 net/socket.c:2638 __sys_sendmsg net/socket.c:2667 [inline] __do_sys_sendmsg net/socket.c:2676 [inline] __se_sys_sendmsg net/socket.c:2674 [inline] __x64_sys_sendmsg+0x307/0x490 net/socket.c:2674 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0x44/0x110 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x63/0x6b  CPU: 0 PID: 5037 Comm: syz-executor166 Not tainted 6.7.0-rc7-syzkaller-00003-gfbafc3e621c3 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 11/17/2023 =====================================================  This issue occurs because the skb buffer is too small, and it's actual allocation is aligned. This hides an actual issue, which is that nr_route_frame does not validate the buffer size before using it.  Fix this issue by checking skb->len before accessing any fields in skb->data.  Found by Linux Verification Center (linuxtesting.org) with Syzkaller.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56770?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56770" src="https://img.shields.io/badge/CVE--2024--56770-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/sched: netem: account for backlog updates from child qdisc  In general, 'qlen' of any classful qdisc should keep track of the number of packets that the qdisc itself and all of its children holds. In case of netem, 'qlen' only accounts for the packets in its internal tfifo. When netem is used with a child qdisc, the child qdisc can use 'qdisc_tree_reduce_backlog' to inform its parent, netem, about created or dropped SKBs. This function updates 'qlen' and the backlog statistics of netem, but netem does not account for changes made by a child qdisc. 'qlen' then indicates the wrong number of packets in the tfifo. If a child qdisc creates new SKBs during enqueue and informs its parent about this, netem's 'qlen' value is increased. When netem dequeues the newly created SKBs from the child, the 'qlen' in netem is not updated. If 'qlen' reaches the configured sch->limit, the enqueue function stops working, even though the tfifo is not full.  Reproduce the bug: Ensure that the sender machine has GSO enabled. Configure netem as root qdisc and tbf as its child on the outgoing interface of the machine as follows: $ tc qdisc add dev <oif> root handle 1: netem delay 100ms limit 100 $ tc qdisc add dev <oif> parent 1:0 tbf rate 50Mbit burst 1542 latency 50ms  Send bulk TCP traffic out via this interface, e.g., by running an iPerf3 client on the machine. Check the qdisc statistics: $ tc -s qdisc show dev <oif>  Statistics after 10s of iPerf3 TCP test before the fix (note that netem's backlog > limit, netem stopped accepting packets): qdisc netem 1: root refcnt 2 limit 1000 delay 100ms Sent 2767766 bytes 1848 pkt (dropped 652, overlimits 0 requeues 0) backlog 4294528236b 1155p requeues 0 qdisc tbf 10: parent 1:1 rate 50Mbit burst 1537b lat 50ms Sent 2767766 bytes 1848 pkt (dropped 327, overlimits 7601 requeues 0) backlog 0b 0p requeues 0  Statistics after the fix: qdisc netem 1: root refcnt 2 limit 1000 delay 100ms Sent 37766372 bytes 24974 pkt (dropped 9, overlimits 0 requeues 0) backlog 0b 0p requeues 0 qdisc tbf 10: parent 1:1 rate 50Mbit burst 1537b lat 50ms Sent 37766372 bytes 24974 pkt (dropped 327, overlimits 96017 requeues 0) backlog 0b 0p requeues 0  tbf segments the GSO SKBs (tbf_segment) and updates the netem's 'qlen'. The interface fully stops transferring packets and "locks". In this case, the child qdisc and tfifo are empty, but 'qlen' indicates the tfifo is at its limit and no more packets are accepted.  This patch adds a counter for the entries in the tfifo. Netem's 'qlen' is only decreased when a packet is returned by its dequeue function, and not during enqueuing into the child qdisc. External updates to 'qlen' are thus accounted for and only the behavior of the backlog statistics changes. As in other qdiscs, 'qlen' then keeps track of  how many packets are held in netem and all of its children. As before, sch->limit remains as the maximum number of packets in the tfifo. The same applies to netem's backlog statistics.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56769?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56769" src="https://img.shields.io/badge/CVE--2024--56769-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  media: dvb-frontends: dib3000mb: fix uninit-value in dib3000_write_reg  Syzbot reports [1] an uninitialized value issue found by KMSAN in dib3000_read_reg().  Local u8 rb[2] is used in i2c_transfer() as a read buffer; in case that call fails, the buffer may end up with some undefined values.  Since no elaborate error handling is expected in dib3000_write_reg(), simply zero out rb buffer to mitigate the problem.  [1] Syzkaller report dvb-usb: bulk message failed: -22 (6/0) ===================================================== BUG: KMSAN: uninit-value in dib3000mb_attach+0x2d8/0x3c0 drivers/media/dvb-frontends/dib3000mb.c:758 dib3000mb_attach+0x2d8/0x3c0 drivers/media/dvb-frontends/dib3000mb.c:758 dibusb_dib3000mb_frontend_attach+0x155/0x2f0 drivers/media/usb/dvb-usb/dibusb-mb.c:31 dvb_usb_adapter_frontend_init+0xed/0x9a0 drivers/media/usb/dvb-usb/dvb-usb-dvb.c:290 dvb_usb_adapter_init drivers/media/usb/dvb-usb/dvb-usb-init.c:90 [inline] dvb_usb_init drivers/media/usb/dvb-usb/dvb-usb-init.c:186 [inline] dvb_usb_device_init+0x25a8/0x3760 drivers/media/usb/dvb-usb/dvb-usb-init.c:310 dibusb_probe+0x46/0x250 drivers/media/usb/dvb-usb/dibusb-mb.c:110 ... Local variable rb created at: dib3000_read_reg+0x86/0x4e0 drivers/media/dvb-frontends/dib3000mb.c:54 dib3000mb_attach+0x123/0x3c0 drivers/media/dvb-frontends/dib3000mb.c:758 ...

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56767?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56767" src="https://img.shields.io/badge/CVE--2024--56767-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dmaengine: at_xdmac: avoid null_prt_deref in at_xdmac_prep_dma_memset  The at_xdmac_memset_create_desc may return NULL, which will lead to a null pointer dereference. For example, the len input is error, or the atchan->free_descs_list is empty and memory is exhausted. Therefore, add check to avoid this.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56763?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56763" src="https://img.shields.io/badge/CVE--2024--56763-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  tracing: Prevent bad count for tracing_cpumask_write  If a large count is provided, it will trigger a warning in bitmap_parse_user. Also check zero for it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56761?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56761" src="https://img.shields.io/badge/CVE--2024--56761-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  x86/fred: Clear WFE in missing-ENDBRANCH #CPs  An indirect branch instruction sets the CPU indirect branch tracker (IBT) into WAIT_FOR_ENDBRANCH (WFE) state and WFE stays asserted across the instruction boundary.  When the decoder finds an inappropriate instruction while WFE is set ENDBR, the CPU raises a #CP fault.  For the "kernel IBT no ENDBR" selftest where #CPs are deliberately triggered, the WFE state of the interrupted context needs to be cleared to let execution continue.  Otherwise when the CPU resumes from the instruction that just caused the previous #CP, another missing-ENDBRANCH #CP is raised and the CPU enters a dead loop.  This is not a problem with IDT because it doesn't preserve WFE and IRET doesn't set WFE.  But FRED provides space on the entry stack (in an expanded CS area) to save and restore the WFE state, thus the WFE state is no longer clobbered, so software must clear it.  Clear WFE to avoid dead looping in ibt_clear_fred_wfe() and the !ibt_fatal code path when execution is allowed to continue.  Clobbering WFE in any other circumstance is a security-relevant bug.  [ dhansen: changelog rewording ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56760?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56760" src="https://img.shields.io/badge/CVE--2024--56760-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  PCI/MSI: Handle lack of irqdomain gracefully  Alexandre observed a warning emitted from pci_msi_setup_msi_irqs() on a RISCV platform which does not provide PCI/MSI support:  WARNING: CPU: 1 PID: 1 at drivers/pci/msi/msi.h:121 pci_msi_setup_msi_irqs+0x2c/0x32 __pci_enable_msix_range+0x30c/0x596 pci_msi_setup_msi_irqs+0x2c/0x32 pci_alloc_irq_vectors_affinity+0xb8/0xe2  RISCV uses hierarchical interrupt domains and correctly does not implement the legacy fallback. The warning triggers from the legacy fallback stub.  That warning is bogus as the PCI/MSI layer knows whether a PCI/MSI parent domain is associated with the device or not. There is a check for MSI-X, which has a legacy assumption. But that legacy fallback assumption is only valid when legacy support is enabled, but otherwise the check should simply return -ENOTSUPP.  Loongarch tripped over the same problem and blindly enabled legacy support without implementing the legacy fallbacks. There are weak implementations which return an error, so the problem was papered over.  Correct pci_msi_domain_supports() to evaluate the legacy mode and add the missing supported check into the MSI enable path to complete it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56758?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56758" src="https://img.shields.io/badge/CVE--2024--56758-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: check folio mapping after unlock in relocate_one_folio()  When we call btrfs_read_folio() to bring a folio uptodate, we unlock the folio. The result of that is that a different thread can modify the mapping (like remove it with invalidate) before we call folio_lock(). This results in an invalid page and we need to try again.  In particular, if we are relocating concurrently with aborting a transaction, this can result in a crash like the following:  BUG: kernel NULL pointer dereference, address: 0000000000000000 PGD 0 P4D 0 Oops: 0000 [#1] SMP CPU: 76 PID: 1411631 Comm: kworker/u322:5 Workqueue: events_unbound btrfs_reclaim_bgs_work RIP: 0010:set_page_extent_mapped+0x20/0xb0 RSP: 0018:ffffc900516a7be8 EFLAGS: 00010246 RAX: ffffea009e851d08 RBX: ffffea009e0b1880 RCX: 0000000000000000 RDX: 0000000000000000 RSI: ffffc900516a7b90 RDI: ffffea009e0b1880 RBP: 0000000003573000 R08: 0000000000000001 R09: ffff88c07fd2f3f0 R10: 0000000000000000 R11: 0000194754b575be R12: 0000000003572000 R13: 0000000003572fff R14: 0000000000100cca R15: 0000000005582fff FS:  0000000000000000(0000) GS:ffff88c07fd00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 0000000000000000 CR3: 000000407d00f002 CR4: 00000000007706f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> ? __die+0x78/0xc0 ? page_fault_oops+0x2a8/0x3a0 ? __switch_to+0x133/0x530 ? wq_worker_running+0xa/0x40 ? exc_page_fault+0x63/0x130 ? asm_exc_page_fault+0x22/0x30 ? set_page_extent_mapped+0x20/0xb0 relocate_file_extent_cluster+0x1a7/0x940 relocate_data_extent+0xaf/0x120 relocate_block_group+0x20f/0x480 btrfs_relocate_block_group+0x152/0x320 btrfs_relocate_chunk+0x3d/0x120 btrfs_reclaim_bgs_work+0x2ae/0x4e0 process_scheduled_works+0x184/0x370 worker_thread+0xc6/0x3e0 ? blk_add_timer+0xb0/0xb0 kthread+0xae/0xe0 ? flush_tlb_kernel_range+0x90/0x90 ret_from_fork+0x2f/0x40 ? flush_tlb_kernel_range+0x90/0x90 ret_from_fork_asm+0x11/0x20 </TASK>  This occurs because cleanup_one_transaction() calls destroy_delalloc_inodes() which calls invalidate_inode_pages2() which takes the folio_lock before setting mapping to NULL. We fail to check this, and subsequently call set_extent_mapping(), which assumes that mapping != NULL (in fact it asserts that in debug mode)  Note that the "fixes" patch here is not the one that introduced the race (the very first iteration of this code from 2009) but a more recent change that made this particular crash happen in practice.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56718?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56718" src="https://img.shields.io/badge/CVE--2024--56718-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/smc: protect link down work from execute after lgr freed  link down work may be scheduled before lgr freed but execute after lgr freed, which may result in crash. So it is need to hold a reference before shedule link down work, and put the reference after work executed or canceled.  The relevant crash call stack as follows: list_del corruption. prev->next should be ffffb638c9c0fe20, but was 0000000000000000 ------------[ cut here ]------------ kernel BUG at lib/list_debug.c:51! invalid opcode: 0000 [#1] SMP NOPTI CPU: 6 PID: 978112 Comm: kworker/6:119 Kdump: loaded Tainted: G #1 Hardware name: Alibaba Cloud Alibaba Cloud ECS, BIOS 2221b89 04/01/2014 Workqueue: events smc_link_down_work [smc] RIP: 0010:__list_del_entry_valid.cold+0x31/0x47 RSP: 0018:ffffb638c9c0fdd8 EFLAGS: 00010086 RAX: 0000000000000054 RBX: ffff942fb75e5128 RCX: 0000000000000000 RDX: ffff943520930aa0 RSI: ffff94352091fc80 RDI: ffff94352091fc80 RBP: 0000000000000000 R08: 0000000000000000 R09: ffffb638c9c0fc38 R10: ffffb638c9c0fc30 R11: ffffffffa015eb28 R12: 0000000000000002 R13: ffffb638c9c0fe20 R14: 0000000000000001 R15: ffff942f9cd051c0 FS:  0000000000000000(0000) GS:ffff943520900000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f4f25214000 CR3: 000000025fbae004 CR4: 00000000007706e0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: rwsem_down_write_slowpath+0x17e/0x470 smc_link_down_work+0x3c/0x60 [smc] process_one_work+0x1ac/0x350 worker_thread+0x49/0x2f0 ? rescuer_thread+0x360/0x360 kthread+0x118/0x140 ? __kthread_bind_mask+0x60/0x60 ret_from_fork+0x1f/0x30

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56717?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56717" src="https://img.shields.io/badge/CVE--2024--56717-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: mscc: ocelot: fix incorrect IFH SRC_PORT field in ocelot_ifh_set_basic()  Packets injected by the CPU should have a SRC_PORT field equal to the CPU port module index in the Analyzer block (ocelot->num_phys_ports).  The blamed commit copied the ocelot_ifh_set_basic() call incorrectly from ocelot_xmit_common() in net/dsa/tag_ocelot.c. Instead of calling with "x", it calls with BIT_ULL(x), but the field is not a port mask, but rather a single port index.  [ side note: this is the technical debt of code duplication :( ]  The error used to be silent and doesn't appear to have other user-visible manifestations, but with new changes in the packing library, it now fails loudly as follows:  ------------[ cut here ]------------ Cannot store 0x40 inside bits 46-43 - will truncate sja1105 spi2.0: xmit timed out WARNING: CPU: 1 PID: 102 at lib/packing.c:98 __pack+0x90/0x198 sja1105 spi2.0: timed out polling for tstamp CPU: 1 UID: 0 PID: 102 Comm: felix_xmit Tainted: G        W        N 6.13.0-rc1-00372-gf706b85d972d-dirty #2605 Call trace: __pack+0x90/0x198 (P) __pack+0x90/0x198 (L) packing+0x78/0x98 ocelot_ifh_set_basic+0x260/0x368 ocelot_port_inject_frame+0xa8/0x250 felix_port_deferred_xmit+0x14c/0x258 kthread_worker_fn+0x134/0x350 kthread+0x114/0x138  The code path pertains to the ocelot switchdev driver and to the felix secondary DSA tag protocol, ocelot-8021q. Here seen with ocelot-8021q.  The messenger (packing) is not really to blame, so fix the original commit instead.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56716?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56716" src="https://img.shields.io/badge/CVE--2024--56716-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netdevsim: prevent bad user input in nsim_dev_health_break_write()  If either a zero count or a large one is provided, kernel can crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56715?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56715" src="https://img.shields.io/badge/CVE--2024--56715-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.036%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>9th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ionic: Fix netdev notifier unregister on failure  If register_netdev() fails, then the driver leaks the netdev notifier. Fix this by calling ionic_lif_unregister() on register_netdev() failure. This will also call ionic_lif_unregister_phc() if it has already been registered.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56710?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56710" src="https://img.shields.io/badge/CVE--2024--56710-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ceph: fix memory leak in ceph_direct_read_write()  The bvecs array which is allocated in iter_get_bvecs_alloc() is leaked and pages remain pinned if ceph_alloc_sparse_ext_map() fails.  There is no need to delay the allocation of sparse_ext map until after the bvecs array is set up, so fix this by moving sparse_ext allocation a bit earlier.  Also, make a similar adjustment in __ceph_sync_read() for consistency (a leak of the same kind in __ceph_sync_read() has been addressed differently).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56670?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56670" src="https://img.shields.io/badge/CVE--2024--56670-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: u_serial: Fix the issue that gs_start_io crashed due to accessing null pointer  Considering that in some extreme cases, when u_serial driver is accessed by multiple threads, Thread A is executing the open operation and calling the gs_open, Thread B is executing the disconnect operation and calling the gserial_disconnect function,The port->port_usb pointer will be set to NULL.  E.g. Thread A                                 Thread B gs_open()                                gadget_unbind_driver() gs_start_io()                            composite_disconnect() gs_start_rx()                            gserial_disconnect() ...                                      ... spin_unlock(&port->port_lock) status = usb_ep_queue()                  spin_lock(&port->port_lock) spin_lock(&port->port_lock)              port->port_usb = NULL gs_free_requests(port->port_usb->in)     spin_unlock(&port->port_lock) Crash  This causes thread A to access a null pointer (port->port_usb is null) when calling the gs_free_requests function, causing a crash.  If port_usb is NULL, the release request will be skipped as it will be done by gserial_disconnect.  So add a null pointer check to gs_start_io before attempting to access the value of the pointer port->port_usb.  Call trace: gs_start_io+0x164/0x25c gs_open+0x108/0x13c tty_open+0x314/0x638 chrdev_open+0x1b8/0x258 do_dentry_open+0x2c4/0x700 vfs_open+0x2c/0x3c path_openat+0xa64/0xc60 do_filp_open+0xb8/0x164 do_sys_openat2+0x84/0xf0 __arm64_sys_openat+0x70/0x9c invoke_syscall+0x58/0x114 el0_svc_common+0x80/0xe0 do_el0_svc+0x1c/0x28 el0_svc+0x38/0x68

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56667?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56667" src="https://img.shields.io/badge/CVE--2024--56667-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/i915: Fix NULL pointer dereference in capture_engine  When the intel_context structure contains NULL, it raises a NULL pointer dereference error in drm_info().  (cherry picked from commit 754302a5bc1bd8fd3b7d85c168b0a1af6d4bba4d)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56665?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56665" src="https://img.shields.io/badge/CVE--2024--56665-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.033%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf,perf: Fix invalid prog_array access in perf_event_detach_bpf_prog  Syzbot reported [1] crash that happens for following tracing scenario:  - create tracepoint perf event with attr.inherit=1, attach it to the process and set bpf program to it - attached process forks -> chid creates inherited event  the new child event shares the parent's bpf program and tp_event (hence prog_array) which is global for tracepoint  - exit both process and its child -> release both events - first perf_event_detach_bpf_prog call will release tp_event->prog_array and second perf_event_detach_bpf_prog will crash, because tp_event->prog_array is NULL  The fix makes sure the perf_event_detach_bpf_prog checks prog_array is valid before it tries to remove the bpf program from it.  [1] https://lore.kernel.org/bpf/Z1MR6dCIKajNS6nU@krava/T/#m91dbf0688221ec7a7fc95e896a7ef9ff93b0b8ad

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56660?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56660" src="https://img.shields.io/badge/CVE--2024--56660-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.033%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: DR, prevent potential error pointer dereference  The dr_domain_add_vport_cap() function generally returns NULL on error but sometimes we want it to return ERR_PTR(-EBUSY) so the caller can retry.  The problem here is that "ret" can be either -EBUSY or -ENOMEM and if it's and -ENOMEM then the error pointer is propogated back and eventually dereferenced in dr_ste_v0_build_src_gvmi_qpn_tag().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56659?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56659" src="https://img.shields.io/badge/CVE--2024--56659-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: lapb: increase LAPB_HEADER_LEN  It is unclear if net/lapb code is supposed to be ready for 8021q.  We can at least avoid crashes like the following :  skbuff: skb_under_panic: text:ffffffff8aabe1f6 len:24 put:20 head:ffff88802824a400 data:ffff88802824a3fe tail:0x16 end:0x140 dev:nr0.2 ------------[ cut here ]------------ kernel BUG at net/core/skbuff.c:206 ! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 1 UID: 0 PID: 5508 Comm: dhcpcd Not tainted 6.12.0-rc7-syzkaller-00144-g66418447d27b #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 10/30/2024 RIP: 0010:skb_panic net/core/skbuff.c:206 [inline] RIP: 0010:skb_under_panic+0x14b/0x150 net/core/skbuff.c:216 Code: 0d 8d 48 c7 c6 2e 9e 29 8e 48 8b 54 24 08 8b 0c 24 44 8b 44 24 04 4d 89 e9 50 41 54 41 57 41 56 e8 1a 6f 37 02 48 83 c4 20 90 <0f> 0b 0f 1f 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 f3 RSP: 0018:ffffc90002ddf638 EFLAGS: 00010282 RAX: 0000000000000086 RBX: dffffc0000000000 RCX: 7a24750e538ff600 RDX: 0000000000000000 RSI: 0000000000000201 RDI: 0000000000000000 RBP: ffff888034a86650 R08: ffffffff8174b13c R09: 1ffff920005bbe60 R10: dffffc0000000000 R11: fffff520005bbe61 R12: 0000000000000140 R13: ffff88802824a400 R14: ffff88802824a3fe R15: 0000000000000016 FS:  00007f2a5990d740(0000) GS:ffff8880b8700000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000000110c2631fd CR3: 0000000029504000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> skb_push+0xe5/0x100 net/core/skbuff.c:2636 nr_header+0x36/0x320 net/netrom/nr_dev.c:69 dev_hard_header include/linux/netdevice.h:3148 [inline] vlan_dev_hard_header+0x359/0x480 net/8021q/vlan_dev.c:83 dev_hard_header include/linux/netdevice.h:3148 [inline] lapbeth_data_transmit+0x1f6/0x2a0 drivers/net/wan/lapbether.c:257 lapb_data_transmit+0x91/0xb0 net/lapb/lapb_iface.c:447 lapb_transmit_buffer+0x168/0x1f0 net/lapb/lapb_out.c:149 lapb_establish_data_link+0x84/0xd0 lapb_device_event+0x4e0/0x670 notifier_call_chain+0x19f/0x3e0 kernel/notifier.c:93 __dev_notify_flags+0x207/0x400 dev_change_flags+0xf0/0x1a0 net/core/dev.c:8922 devinet_ioctl+0xa4e/0x1aa0 net/ipv4/devinet.c:1188 inet_ioctl+0x3d7/0x4f0 net/ipv4/af_inet.c:1003 sock_do_ioctl+0x158/0x460 net/socket.c:1227 sock_ioctl+0x626/0x8e0 net/socket.c:1346 vfs_ioctl fs/ioctl.c:51 [inline] __do_sys_ioctl fs/ioctl.c:907 [inline] __se_sys_ioctl+0xf9/0x170 fs/ioctl.c:893 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56657?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56657" src="https://img.shields.io/badge/CVE--2024--56657-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ALSA: control: Avoid WARN() for symlink errors  Using WARN() for showing the error of symlink creations don't give more information than telling that something goes wrong, since the usual code path is a lregister callback from each control element creation.  More badly, the use of WARN() rather confuses fuzzer as if it were serious issues.  This patch downgrades the warning messages to use the normal dev_err() instead of WARN().  For making it clearer, add the function name to the prefix, too.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56656?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56656" src="https://img.shields.io/badge/CVE--2024--56656-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bnxt_en: Fix aggregation ID mask to prevent oops on 5760X chips  The 5760X (P7) chip's HW GRO/LRO interface is very similar to that of the previous generation (5750X or P5).  However, the aggregation ID fields in the completion structures on P7 have been redefined from 16 bits to 12 bits.  The freed up 4 bits are redefined for part of the metadata such as the VLAN ID.  The aggregation ID mask was not modified when adding support for P7 chips.  Including the extra 4 bits for the aggregation ID can potentially cause the driver to store or fetch the packet header of GRO/LRO packets in the wrong TPA buffer.  It may hit the BUG() condition in __skb_pull() because the SKB contains no valid packet header:  kernel BUG at include/linux/skbuff.h:2766! Oops: invalid opcode: 0000 1 PREEMPT SMP NOPTI CPU: 4 UID: 0 PID: 0 Comm: swapper/4 Kdump: loaded Tainted: G           OE 6.12.0-rc2+ #7 Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE Hardware name: Dell Inc. PowerEdge R760/0VRV9X, BIOS 1.0.1 12/27/2022 RIP: 0010:eth_type_trans+0xda/0x140 Code: 80 00 00 00 eb c1 8b 47 70 2b 47 74 48 8b 97 d0 00 00 00 83 f8 01 7e 1b 48 85 d2 74 06 66 83 3a ff 74 09 b8 00 04 00 00 eb a5 <0f> 0b b8 00 01 00 00 eb 9c 48 85 ff 74 eb 31 f6 b9 02 00 00 00 48 RSP: 0018:ff615003803fcc28 EFLAGS: 00010283 RAX: 00000000000022d2 RBX: 0000000000000003 RCX: ff2e8c25da334040 RDX: 0000000000000040 RSI: ff2e8c25c1ce8000 RDI: ff2e8c25869f9000 RBP: ff2e8c258c31c000 R08: ff2e8c25da334000 R09: 0000000000000001 R10: ff2e8c25da3342c0 R11: ff2e8c25c1ce89c0 R12: ff2e8c258e0990b0 R13: ff2e8c25bb120000 R14: ff2e8c25c1ce89c0 R15: ff2e8c25869f9000 FS:  0000000000000000(0000) GS:ff2e8c34be300000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000055f05317e4c8 CR3: 000000108bac6006 CR4: 0000000000773ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe07f0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <IRQ> ? die+0x33/0x90 ? do_trap+0xd9/0x100 ? eth_type_trans+0xda/0x140 ? do_error_trap+0x65/0x80 ? eth_type_trans+0xda/0x140 ? exc_invalid_op+0x4e/0x70 ? eth_type_trans+0xda/0x140 ? asm_exc_invalid_op+0x16/0x20 ? eth_type_trans+0xda/0x140 bnxt_tpa_end+0x10b/0x6b0 [bnxt_en] ? bnxt_tpa_start+0x195/0x320 [bnxt_en] bnxt_rx_pkt+0x902/0xd90 [bnxt_en] ? __bnxt_tx_int.constprop.0+0x89/0x300 [bnxt_en] ? kmem_cache_free+0x343/0x440 ? __bnxt_tx_int.constprop.0+0x24f/0x300 [bnxt_en] __bnxt_poll_work+0x193/0x370 [bnxt_en] bnxt_poll_p5+0x9a/0x300 [bnxt_en] ? try_to_wake_up+0x209/0x670 __napi_poll+0x29/0x1b0  Fix it by redefining the aggregation ID mask for P5_PLUS chips to be 12 bits.  This will work because the maximum aggregation ID is less than 4096 on all P5_PLUS chips.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56654?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56654" src="https://img.shields.io/badge/CVE--2024--56654-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: hci_event: Fix using rcu_read_(un)lock while iterating  The usage of rcu_read_(un)lock while inside list_for_each_entry_rcu is not safe since for the most part entries fetched this way shall be treated as rcu_dereference:  Note that the value returned by rcu_dereference() is valid only within the enclosing RCU read-side critical section [1]_. For example, the following is **not** legal::  rcu_read_lock(); p = rcu_dereference(head.next); rcu_read_unlock(); x = p->address;	/* BUG!!! */ rcu_read_lock(); y = p->data;	/* BUG!!! */ rcu_read_unlock();

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56369?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--56369" src="https://img.shields.io/badge/CVE--2024--56369-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.017%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/modes: Avoid divide by zero harder in drm_mode_vrefresh()  drm_mode_vrefresh() is trying to avoid divide by zero by checking whether htotal or vtotal are zero. But we may still end up with a div-by-zero of vtotal*htotal*...

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-55916?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--55916" src="https://img.shields.io/badge/CVE--2024--55916-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Drivers: hv: util: Avoid accessing a ringbuffer not initialized yet  If the KVP (or VSS) daemon starts before the VMBus channel's ringbuffer is fully initialized, we can hit the panic below:  hv_utils: Registering HyperV Utility Driver hv_vmbus: registering driver hv_utils ... BUG: kernel NULL pointer dereference, address: 0000000000000000 CPU: 44 UID: 0 PID: 2552 Comm: hv_kvp_daemon Tainted: G E 6.11.0-rc3+ #1 RIP: 0010:hv_pkt_iter_first+0x12/0xd0 Call Trace: ... vmbus_recvpacket hv_kvp_onchannelcallback vmbus_on_event tasklet_action_common tasklet_action handle_softirqs irq_exit_rcu sysvec_hyperv_stimer0 </IRQ> <TASK> asm_sysvec_hyperv_stimer0 ... kvp_register_done hvt_op_read vfs_read ksys_read __x64_sys_read  This can happen because the KVP/VSS channel callback can be invoked even before the channel is fully opened: 1) as soon as hv_kvp_init() -> hvutil_transport_init() creates /dev/vmbus/hv_kvp, the kvp daemon can open the device file immediately and register itself to the driver by writing a message KVP_OP_REGISTER1 to the file (which is handled by kvp_on_msg() ->kvp_handle_handshake()) and reading the file for the driver's response, which is handled by hvt_op_read(), which calls hvt->on_read(), i.e. kvp_register_done().  2) the problem with kvp_register_done() is that it can cause the channel callback to be called even before the channel is fully opened, and when the channel callback is starting to run, util_probe()-> vmbus_open() may have not initialized the ringbuffer yet, so the callback can hit the panic of NULL pointer dereference.  To reproduce the panic consistently, we can add a "ssleep(10)" for KVP in __vmbus_open(), just before the first hv_ringbuffer_init(), and then we unload and reload the driver hv_utils, and run the daemon manually within the 10 seconds.  Fix the panic by reordering the steps in util_probe() so the char dev entry used by the KVP or VSS daemon is not created until after vmbus_open() has completed. This reordering prevents the race condition from happening.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54683?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--54683" src="https://img.shields.io/badge/CVE--2024--54683-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.013%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: IDLETIMER: Fix for possible ABBA deadlock  Deletion of the last rule referencing a given idletimer may happen at the same time as a read of its file in sysfs:  | ====================================================== | WARNING: possible circular locking dependency detected | 6.12.0-rc7-01692-g5e9a28f41134-dirty #594 Not tainted | ------------------------------------------------------ | iptables/3303 is trying to acquire lock: | ffff8881057e04b8 (kn->active#48){++++}-{0:0}, at: __kernfs_remove+0x20 | | but task is already holding lock: | ffffffffa0249068 (list_mutex){+.+.}-{3:3}, at: idletimer_tg_destroy_v] | | which lock already depends on the new lock.  A simple reproducer is:  | #!/bin/bash | | while true; do |         iptables -A INPUT -i foo -j IDLETIMER --timeout 10 --label "testme" |         iptables -D INPUT -i foo -j IDLETIMER --timeout 10 --label "testme" | done & | while true; do |         cat /sys/class/xt_idletimer/timers/testme >/dev/null | done  Avoid this by freeing list_mutex right after deleting the element from the list, then continuing with the teardown.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54460?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--54460" src="https://img.shields.io/badge/CVE--2024--54460-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: iso: Fix circular lock in iso_listen_bis  This fixes the circular locking dependency warning below, by releasing the socket lock before enterning iso_listen_bis, to avoid any potential deadlock with hdev lock.  [   75.307983] ====================================================== [   75.307984] WARNING: possible circular locking dependency detected [   75.307985] 6.12.0-rc6+ #22 Not tainted [   75.307987] ------------------------------------------------------ [   75.307987] kworker/u81:2/2623 is trying to acquire lock: [   75.307988] ffff8fde1769da58 (sk_lock-AF_BLUETOOTH-BTPROTO_ISO) at: iso_connect_cfm+0x253/0x840 [bluetooth] [   75.308021] but task is already holding lock: [   75.308022] ffff8fdd61a10078 (&hdev->lock) at: hci_le_per_adv_report_evt+0x47/0x2f0 [bluetooth] [   75.308053] which lock already depends on the new lock.  [   75.308054] the existing dependency chain (in reverse order) is: [   75.308055] -> #1 (&hdev->lock){+.+.}-{3:3}: [   75.308057]        __mutex_lock+0xad/0xc50 [   75.308061]        mutex_lock_nested+0x1b/0x30 [   75.308063]        iso_sock_listen+0x143/0x5c0 [bluetooth] [   75.308085]        __sys_listen_socket+0x49/0x60 [   75.308088]        __x64_sys_listen+0x4c/0x90 [   75.308090]        x64_sys_call+0x2517/0x25f0 [   75.308092]        do_syscall_64+0x87/0x150 [   75.308095]        entry_SYSCALL_64_after_hwframe+0x76/0x7e [   75.308098] -> #0 (sk_lock-AF_BLUETOOTH-BTPROTO_ISO){+.+.}-{0:0}: [   75.308100]        __lock_acquire+0x155e/0x25f0 [   75.308103]        lock_acquire+0xc9/0x300 [   75.308105]        lock_sock_nested+0x32/0x90 [   75.308107]        iso_connect_cfm+0x253/0x840 [bluetooth] [   75.308128]        hci_connect_cfm+0x6c/0x190 [bluetooth] [   75.308155]        hci_le_per_adv_report_evt+0x27b/0x2f0 [bluetooth] [   75.308180]        hci_le_meta_evt+0xe7/0x200 [bluetooth] [   75.308206]        hci_event_packet+0x21f/0x5c0 [bluetooth] [   75.308230]        hci_rx_work+0x3ae/0xb10 [bluetooth] [   75.308254]        process_one_work+0x212/0x740 [   75.308256]        worker_thread+0x1bd/0x3a0 [   75.308258]        kthread+0xe4/0x120 [   75.308259]        ret_from_fork+0x44/0x70 [   75.308261]        ret_from_fork_asm+0x1a/0x30 [   75.308263] other info that might help us debug this:  [   75.308264]  Possible unsafe locking scenario:  [   75.308264]        CPU0                CPU1 [   75.308265]        ----                ---- [   75.308265]   lock(&hdev->lock); [   75.308267]                            lock(sk_lock- AF_BLUETOOTH-BTPROTO_ISO); [   75.308268]                            lock(&hdev->lock); [   75.308269]   lock(sk_lock-AF_BLUETOOTH-BTPROTO_ISO); [   75.308270] *** DEADLOCK ***  [   75.308271] 4 locks held by kworker/u81:2/2623: [   75.308272]  #0: ffff8fdd66e52148 ((wq_completion)hci0#2){+.+.}-{0:0}, at: process_one_work+0x443/0x740 [   75.308276]  #1: ffffafb488b7fe48 ((work_completion)(&hdev->rx_work)), at: process_one_work+0x1ce/0x740 [   75.308280]  #2: ffff8fdd61a10078 (&hdev->lock){+.+.}-{3:3} at: hci_le_per_adv_report_evt+0x47/0x2f0 [bluetooth] [   75.308304]  #3: ffffffffb6ba4900 (rcu_read_lock){....}-{1:2}, at: hci_connect_cfm+0x29/0x190 [bluetooth]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-47736?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--47736" src="https://img.shields.io/badge/CVE--2024--47736-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  erofs: handle overlapped pclusters out of crafted images properly  syzbot reported a task hang issue due to a deadlock case where it is waiting for the folio lock of a cached folio that will be used for cache I/Os.  After looking into the crafted fuzzed image, I found it's formed with several overlapped big pclusters as below:  Ext:   logical offset   |  length :     physical offset    |  length 0:        0..   16384 |   16384 :     151552..    167936 |   16384 1:    16384..   32768 |   16384 :     155648..    172032 |   16384 2:    32768..   49152 |   16384 :  537223168.. 537239552 |   16384 ...  Here, extent 0/1 are physically overlapped although it's entirely _impossible_ for normal filesystem images generated by mkfs.  First, managed folios containing compressed data will be marked as up-to-date and then unlocked immediately (unlike in-place folios) when compressed I/Os are complete.  If physical blocks are not submitted in the incremental order, there should be separate BIOs to avoid dependency issues.  However, the current code mis-arranges z_erofs_fill_bio_vec() and BIO submission which causes unexpected BIO waits.  Second, managed folios will be connected to their own pclusters for efficient inter-queries.  However, this is somewhat hard to implement easily if overlapped big pclusters exist.  Again, these only appear in fuzzed images so let's simply fall back to temporary short-lived pages for correctness.  Additionally, it justifies that referenced managed folios cannot be truncated for now and reverts part of commit 2080ca1ed3e4 ("erofs: tidy up `struct z_erofs_bvec`") for simplicity although it shouldn't be any difference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-38608?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--38608" src="https://img.shields.io/badge/CVE--2024--38608-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved: net/mlx5e: Fix netif state handling mlx5e_suspend cleans resources only if netif_device_present() returns true. However, mlx5e_resume changes the state of netif, via mlx5e_nic_enable, only if reg_state == NETREG_REGISTERED. In the below case, the above leads to NULL-ptr Oops[1] and memory leaks: mlx5e_probe _mlx5e_resume mlx5e_attach_netdev mlx5e_nic_enable <-- netdev not reg, not calling netif_device_attach() register_netdev <-- failed for some reason. ERROR_FLOW: _mlx5e_suspend <-- netif_device_present return false, resources aren't freed :( Hence, clean resources in this case as well. [1] BUG: kernel NULL pointer dereference, address: 0000000000000000 PGD 0 P4D 0 Oops: 0010 [#1] SMP CPU: 2 PID: 9345 Comm: test-ovs-ct-gen Not tainted 6.5.0_for_upstream_min_debug_2023_09_05_16_01 #1 Hardware name: QEMU Standard PC (Q35 + ICH9, 2009), BIOS rel-1.13.0-0-gf21b5a4aeb02-prebuilt.qemu.org 04/01/2014 RIP: 0010:0x0 Code: Unable to access opcode bytes at0xffffffffffffffd6. RSP: 0018:ffff888178aaf758 EFLAGS: 00010246 Call Trace: <TASK> ? __die+0x20/0x60 ? page_fault_oops+0x14c/0x3c0 ? exc_page_fault+0x75/0x140 ? asm_exc_page_fault+0x22/0x30 notifier_call_chain+0x35/0xb0 blocking_notifier_call_chain+0x3d/0x60 mlx5_blocking_notifier_call_chain+0x22/0x30 [mlx5_core] mlx5_core_uplink_netdev_event_replay+0x3e/0x60 [mlx5_core] mlx5_mdev_netdev_track+0x53/0x60 [mlx5_ib] mlx5_ib_roce_init+0xc3/0x340 [mlx5_ib] __mlx5_ib_add+0x34/0xd0 [mlx5_ib] mlx5r_probe+0xe1/0x210 [mlx5_ib] ? auxiliary_match_id+0x6a/0x90 auxiliary_bus_probe+0x38/0x80 ? driver_sysfs_add+0x51/0x80 really_probe+0xc9/0x3e0 ? driver_probe_device+0x90/0x90 __driver_probe_device+0x80/0x160 driver_probe_device+0x1e/0x90 __device_attach_driver+0x7d/0x100 bus_for_each_drv+0x80/0xd0 __device_attach+0xbc/0x1f0 bus_probe_device+0x86/0xa0 device_add+0x637/0x840 __auxiliary_device_add+0x3b/0xa0 add_adev+0xc9/0x140 [mlx5_core] mlx5_rescan_drivers_locked+0x22a/0x310 [mlx5_core] mlx5_register_device+0x53/0xa0 [mlx5_core] mlx5_init_one_devl_locked+0x5c4/0x9c0 [mlx5_core] mlx5_init_one+0x3b/0x60 [mlx5_core] probe_one+0x44c/0x730 [mlx5_core] local_pci_probe+0x3e/0x90 pci_device_probe+0xbf/0x210 ? kernfs_create_link+0x5d/0xa0 ? sysfs_do_create_link_sd+0x60/0xc0 really_probe+0xc9/0x3e0 ? driver_probe_device+0x90/0x90 __driver_probe_device+0x80/0x160 driver_probe_device+0x1e/0x90 __device_attach_driver+0x7d/0x100 bus_for_each_drv+0x80/0xd0 __device_attach+0xbc/0x1f0 pci_bus_add_device+0x54/0x80 pci_iov_add_virtfn+0x2e6/0x320 sriov_enable+0x208/0x420 mlx5_core_sriov_configure+0x9e/0x200 [mlx5_core] sriov_numvfs_store+0xae/0x1a0 kernfs_fop_write_iter+0x10c/0x1a0 vfs_write+0x291/0x3c0 ksys_write+0x5f/0xe0 do_syscall_64+0x3d/0x90 entry_SYSCALL_64_after_hwframe+0x46/0xb0 CR2: 0000000000000000 ---[ end trace 0000000000000000 ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-36476?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 5.5: CVE--2024--36476" src="https://img.shields.io/badge/CVE--2024--36476-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.023%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/rtrs: Ensure 'ib_sge list' is accessible  Move the declaration of the 'ib_sge list' variable outside the 'always_invalidate' block to ensure it remains accessible for use throughout the function.  Previously, 'ib_sge list' was declared within the 'always_invalidate' block, limiting its accessibility, then caused a 'BUG: kernel NULL pointer dereference'[1]. ? __die_body.cold+0x19/0x27 ? page_fault_oops+0x15a/0x2d0 ? search_module_extables+0x19/0x60 ? search_bpf_extables+0x5f/0x80 ? exc_page_fault+0x7e/0x180 ? asm_exc_page_fault+0x26/0x30 ? memcpy_orig+0xd5/0x140 rxe_mr_copy+0x1c3/0x200 [rdma_rxe] ? rxe_pool_get_index+0x4b/0x80 [rdma_rxe] copy_data+0xa5/0x230 [rdma_rxe] rxe_requester+0xd9b/0xf70 [rdma_rxe] ? finish_task_switch.isra.0+0x99/0x2e0 rxe_sender+0x13/0x40 [rdma_rxe] do_task+0x68/0x1e0 [rdma_rxe] process_one_work+0x177/0x330 worker_thread+0x252/0x390 ? __pfx_worker_thread+0x10/0x10  This change ensures the variable is available for subsequent operations that require it.  [1] https://lore.kernel.org/linux-rdma/6a1f3e8f-deb0-49f9-bc69-a9b03ecfcda7@fujitsu.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57913?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium 4.7: CVE--2024--57913" src="https://img.shields.io/badge/CVE--2024--57913-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.026%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  usb: gadget: f_fs: Remove WARN_ON in functionfs_bind  This commit addresses an issue related to below kernel panic where panic_on_warn is enabled. It is caused by the unnecessary use of WARN_ON in functionsfs_bind, which easily leads to the following scenarios.  1.adb_write in adbd               2. UDC write via configfs =================	             =====================  ->usb_ffs_open_thread()           ->UDC write ->open_functionfs()               ->configfs_write_iter() ->adb_open()                      ->gadget_dev_desc_UDC_store() ->adb_write()                     ->usb_gadget_register_driver_owner ->driver_register() ->StartMonitor()                       ->bus_add_driver() ->adb_read()                           ->gadget_bind_driver() <times-out without BIND event>           ->configfs_composite_bind() ->usb_add_function() ->open_functionfs()                        ->ffs_func_bind() ->adb_open()                               ->functionfs_bind() <ffs->state !=FFS_ACTIVE>  The adb_open, adb_read, and adb_write operations are invoked from the daemon, but trying to bind the function is a process that is invoked by UDC write through configfs, which opens up the possibility of a race condition between the two paths. In this race scenario, the kernel panic occurs due to the WARN_ON from functionfs_bind when panic_on_warn is enabled. This commit fixes the kernel panic by removing the unnecessary WARN_ON.  Kernel panic - not syncing: kernel: panic_on_warn set ... [   14.542395] Call trace: [   14.542464]  ffs_func_bind+0x1c8/0x14a8 [   14.542468]  usb_add_function+0xcc/0x1f0 [   14.542473]  configfs_composite_bind+0x468/0x588 [   14.542478]  gadget_bind_driver+0x108/0x27c [   14.542483]  really_probe+0x190/0x374 [   14.542488]  __driver_probe_device+0xa0/0x12c [   14.542492]  driver_probe_device+0x3c/0x220 [   14.542498]  __driver_attach+0x11c/0x1fc [   14.542502]  bus_for_each_dev+0x104/0x160 [   14.542506]  driver_attach+0x24/0x34 [   14.542510]  bus_add_driver+0x154/0x270 [   14.542514]  driver_register+0x68/0x104 [   14.542518]  usb_gadget_register_driver_owner+0x48/0xf4 [   14.542523]  gadget_dev_desc_UDC_store+0xf8/0x144 [   14.542526]  configfs_write_iter+0xf0/0x138

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21971?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21971" src="https://img.shields.io/badge/CVE--2025--21971-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.053%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>17th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: Prevent creation of classes with TC_H_ROOT  The function qdisc_tree_reduce_backlog() uses TC_H_ROOT as a termination condition when traversing up the qdisc tree to update parent backlog counters. However, if a class is created with classid TC_H_ROOT, the traversal terminates prematurely at this class instead of reaching the actual root qdisc, causing parent statistics to be incorrectly maintained. In case of DRR, this could lead to a crash as reported by Mingi Cho.  Prevent the creation of any Qdisc class with classid TC_H_ROOT (0xFFFFFFFF) across all qdisc types, as suggested by Jamal.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21938?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21938" src="https://img.shields.io/badge/CVE--2025--21938-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mptcp: fix 'scheduling while atomic' in mptcp_pm_nl_append_new_local_addr  If multiple connection requests attempt to create an implicit mptcp endpoint in parallel, more than one caller may end up in mptcp_pm_nl_append_new_local_addr because none found the address in local_addr_list during their call to mptcp_pm_nl_get_local_id.  In this case, the concurrent new_local_addr calls may delete the address entry created by the previous caller.  These deletes use synchronize_rcu, but this is not permitted in some of the contexts where this function may be called.  During packet recv, the caller may be in a rcu read critical section and have preemption disabled.  An example stack:  BUG: scheduling while atomic: swapper/2/0/0x00000302  Call Trace: <IRQ> dump_stack_lvl (lib/dump_stack.c:117 (discriminator 1)) dump_stack (lib/dump_stack.c:124) __schedule_bug (kernel/sched/core.c:5943) schedule_debug.constprop.0 (arch/x86/include/asm/preempt.h:33 kernel/sched/core.c:5970) __schedule (arch/x86/include/asm/jump_label.h:27 include/linux/jump_label.h:207 kernel/sched/features.h:29 kernel/sched/core.c:6621) schedule (arch/x86/include/asm/preempt.h:84 kernel/sched/core.c:6804 kernel/sched/core.c:6818) schedule_timeout (kernel/time/timer.c:2160) wait_for_completion (kernel/sched/completion.c:96 kernel/sched/completion.c:116 kernel/sched/completion.c:127 kernel/sched/completion.c:148) __wait_rcu_gp (include/linux/rcupdate.h:311 kernel/rcu/update.c:444) synchronize_rcu (kernel/rcu/tree.c:3609) mptcp_pm_nl_append_new_local_addr (net/mptcp/pm_netlink.c:966 net/mptcp/pm_netlink.c:1061) mptcp_pm_nl_get_local_id (net/mptcp/pm_netlink.c:1164) mptcp_pm_get_local_id (net/mptcp/pm.c:420) subflow_check_req (net/mptcp/subflow.c:98 net/mptcp/subflow.c:213) subflow_v4_route_req (net/mptcp/subflow.c:305) tcp_conn_request (net/ipv4/tcp_input.c:7216) subflow_v4_conn_request (net/mptcp/subflow.c:651) tcp_rcv_state_process (net/ipv4/tcp_input.c:6709) tcp_v4_do_rcv (net/ipv4/tcp_ipv4.c:1934) tcp_v4_rcv (net/ipv4/tcp_ipv4.c:2334) ip_protocol_deliver_rcu (net/ipv4/ip_input.c:205 (discriminator 1)) ip_local_deliver_finish (include/linux/rcupdate.h:813 net/ipv4/ip_input.c:234) ip_local_deliver (include/linux/netfilter.h:314 include/linux/netfilter.h:308 net/ipv4/ip_input.c:254) ip_sublist_rcv_finish (include/net/dst.h:461 net/ipv4/ip_input.c:580) ip_sublist_rcv (net/ipv4/ip_input.c:640) ip_list_rcv (net/ipv4/ip_input.c:675) __netif_receive_skb_list_core (net/core/dev.c:5583 net/core/dev.c:5631) netif_receive_skb_list_internal (net/core/dev.c:5685 net/core/dev.c:5774) napi_complete_done (include/linux/list.h:37 include/net/gro.h:449 include/net/gro.h:444 net/core/dev.c:6114) igb_poll (drivers/net/ethernet/intel/igb/igb_main.c:8244) igb __napi_poll (net/core/dev.c:6582) net_rx_action (net/core/dev.c:6653 net/core/dev.c:6787) handle_softirqs (kernel/softirq.c:553) __irq_exit_rcu (kernel/softirq.c:588 kernel/softirq.c:427 kernel/softirq.c:636) irq_exit_rcu (kernel/softirq.c:651) common_interrupt (arch/x86/kernel/irq.c:247 (discriminator 14)) </IRQ>  This problem seems particularly prevalent if the user advertises an endpoint that has a different external vs internal address.  In the case where the external address is advertised and multiple connections already exist, multiple subflow SYNs arrive in parallel which tends to trigger the race during creation of the first local_addr_list entries which have the internal address instead.  Fix by skipping the replacement of an existing implicit local address if called via mptcp_pm_nl_get_local_id.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21664?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21664" src="https://img.shields.io/badge/CVE--2025--21664-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.068%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dm thin: make get_first_thin use rcu-safe list first function  The documentation in rculist.h explains the absence of list_empty_rcu() and cautions programmers against relying on a list_empty() -> list_first() sequence in RCU safe code.  This is because each of these functions performs its own READ_ONCE() of the list head.  This can lead to a situation where the list_empty() sees a valid list entry, but the subsequent list_first() sees a different view of list head state after a modification.  In the case of dm-thin, this author had a production box crash from a GP fault in the process_deferred_bios path.  This function saw a valid list head in get_first_thin() but when it subsequently dereferenced that and turned it into a thin_c, it got the inside of the struct pool, since the list was now empty and referring to itself.  The kernel on which this occurred printed both a warning about a refcount_t being saturated, and a UBSAN error for an out-of-bounds cpuid access in the queued spinlock, prior to the fault itself.  When the resulting kdump was examined, it was possible to see another thread patiently waiting in thin_dtr's synchronize_rcu.  The thin_dtr call managed to pull the thin_c out of the active thins list (and have it be the last entry in the active_thins list) at just the wrong moment which lead to this crash.  Fortunately, the fix here is straight forward.  Switch get_first_thin() function to use list_first_or_null_rcu() which performs just a single READ_ONCE() and returns NULL if the list is already empty.  This was run against the devicemapper test suite's thin-provisioning suites for delete and suspend and no regressions were observed.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21663?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21663" src="https://img.shields.io/badge/CVE--2025--21663-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: stmmac: dwmac-tegra: Read iommu stream id from device tree  Nvidia's Tegra MGBE controllers require the IOMMU "Stream ID" (SID) to be written to the MGBE_WRAP_AXI_ASID0_CTRL register.  The current driver is hard coded to use MGBE0's SID for all controllers. This causes softirq time outs and kernel panics when using controllers other than MGBE0.  Example dmesg errors when an ethernet cable is connected to MGBE1:  [  116.133290] tegra-mgbe 6910000.ethernet eth1: Link is Up - 1Gbps/Full - flow control rx/tx [  121.851283] tegra-mgbe 6910000.ethernet eth1: NETDEV WATCHDOG: CPU: 5: transmit queue 0 timed out 5690 ms [  121.851782] tegra-mgbe 6910000.ethernet eth1: Reset adapter. [  121.892464] tegra-mgbe 6910000.ethernet eth1: Register MEM_TYPE_PAGE_POOL RxQ-0 [  121.905920] tegra-mgbe 6910000.ethernet eth1: PHY [stmmac-1:00] driver [Aquantia AQR113] (irq=171) [  121.907356] tegra-mgbe 6910000.ethernet eth1: Enabling Safety Features [  121.907578] tegra-mgbe 6910000.ethernet eth1: IEEE 1588-2008 Advanced Timestamp supported [  121.908399] tegra-mgbe 6910000.ethernet eth1: registered PTP clock [  121.908582] tegra-mgbe 6910000.ethernet eth1: configuring for phy/10gbase-r link mode [  125.961292] tegra-mgbe 6910000.ethernet eth1: Link is Up - 1Gbps/Full - flow control rx/tx [  181.921198] rcu: INFO: rcu_preempt detected stalls on CPUs/tasks: [  181.921404] rcu: 	7-....: (1 GPs behind) idle=540c/1/0x4000000000000002 softirq=1748/1749 fqs=2337 [  181.921684] rcu: 	(detected by 4, t=6002 jiffies, g=1357, q=1254 ncpus=8) [  181.921878] Sending NMI from CPU 4 to CPUs 7: [  181.921886] NMI backtrace for cpu 7 [  181.922131] CPU: 7 UID: 0 PID: 0 Comm: swapper/7 Kdump: loaded Not tainted 6.13.0-rc3+ #6 [  181.922390] Hardware name: NVIDIA CTI Forge + Orin AGX/Jetson, BIOS 202402.1-Unknown 10/28/2024 [  181.922658] pstate: 40400009 (nZcv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) [  181.922847] pc : handle_softirqs+0x98/0x368 [  181.922978] lr : __do_softirq+0x18/0x20 [  181.923095] sp : ffff80008003bf50 [  181.923189] x29: ffff80008003bf50 x28: 0000000000000008 x27: 0000000000000000 [  181.923379] x26: ffffce78ea277000 x25: 0000000000000000 x24: 0000001c61befda0 [  181.924486] x23: 0000000060400009 x22: ffffce78e99918bc x21: ffff80008018bd70 [  181.925568] x20: ffffce78e8bb00d8 x19: ffff80008018bc20 x18: 0000000000000000 [  181.926655] x17: ffff318ebe7d3000 x16: ffff800080038000 x15: 0000000000000000 [  181.931455] x14: ffff000080816680 x13: ffff318ebe7d3000 x12: 000000003464d91d [  181.938628] x11: 0000000000000040 x10: ffff000080165a70 x9 : ffffce78e8bb0160 [  181.945804] x8 : ffff8000827b3160 x7 : f9157b241586f343 x6 : eeb6502a01c81c74 [  181.953068] x5 : a4acfcdd2e8096bb x4 : ffffce78ea277340 x3 : 00000000ffffd1e1 [  181.960329] x2 : 0000000000000101 x1 : ffffce78ea277340 x0 : ffff318ebe7d3000 [  181.967591] Call trace: [  181.970043]  handle_softirqs+0x98/0x368 (P) [  181.974240]  __do_softirq+0x18/0x20 [  181.977743]  ____do_softirq+0x14/0x28 [  181.981415]  call_on_irq_stack+0x24/0x30 [  181.985180]  do_softirq_own_stack+0x20/0x30 [  181.989379]  __irq_exit_rcu+0x114/0x140 [  181.993142]  irq_exit_rcu+0x14/0x28 [  181.996816]  el1_interrupt+0x44/0xb8 [  182.000316]  el1h_64_irq_handler+0x14/0x20 [  182.004343]  el1h_64_irq+0x80/0x88 [  182.007755]  cpuidle_enter_state+0xc4/0x4a8 (P) [  182.012305]  cpuidle_enter+0x3c/0x58 [  182.015980]  cpuidle_idle_call+0x128/0x1c0 [  182.020005]  do_idle+0xe0/0xf0 [  182.023155]  cpu_startup_entry+0x3c/0x48 [  182.026917]  secondary_start_kernel+0xdc/0x120 [  182.031379]  __secondary_switched+0x74/0x78 [  212.971162] rcu: INFO: rcu_preempt detected expedited stalls on CPUs/tasks: { 7-.... } 6103 jiffies s: 417 root: 0x80/. [  212.985935] rcu: blocking rcu_node structures (internal RCU debug): [  212.992758] Sending NMI from CPU 0 to CPUs 7: [  212.998539] NMI backtrace for cpu 7 [  213.004304] CPU: 7 UID: 0 PI ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21662?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21662" src="https://img.shields.io/badge/CVE--2025--21662-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.037%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: Fix variable not being completed when function returns  When cmd_alloc_index(), fails cmd_work_handler() needs to complete ent->slotted before returning early. Otherwise the task which issued the command may hang:  mlx5_core 0000:01:00.0: cmd_work_handler:877:(pid 3880418): failed to allocate command entry INFO: task kworker/13:2:4055883 blocked for more than 120 seconds. Not tainted 4.19.90-25.44.v2101.ky10.aarch64 #1 "echo 0 > /proc/sys/kernel/hung_task_timeout_secs" disables this message. kworker/13:2    D    0 4055883      2 0x00000228 Workqueue: events mlx5e_tx_dim_work [mlx5_core] Call trace: __switch_to+0xe8/0x150 __schedule+0x2a8/0x9b8 schedule+0x2c/0x88 schedule_timeout+0x204/0x478 wait_for_common+0x154/0x250 wait_for_completion+0x28/0x38 cmd_exec+0x7a0/0xa00 [mlx5_core] mlx5_cmd_exec+0x54/0x80 [mlx5_core] mlx5_core_modify_cq+0x6c/0x80 [mlx5_core] mlx5_core_modify_cq_moderation+0xa0/0xb8 [mlx5_core] mlx5e_tx_dim_work+0x54/0x68 [mlx5_core] process_one_work+0x1b0/0x448 worker_thread+0x54/0x468 kthread+0x134/0x138 ret_from_fork+0x10/0x18

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21660?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21660" src="https://img.shields.io/badge/CVE--2025--21660-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.037%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ksmbd: fix unexpectedly changed path in ksmbd_vfs_kern_path_locked  When `ksmbd_vfs_kern_path_locked` met an error and it is not the last entry, it will exit without restoring changed path buffer. But later this buffer may be used as the filename for creation.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21659?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21659" src="https://img.shields.io/badge/CVE--2025--21659-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.064%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>20th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netdev: prevent accessing NAPI instances from another namespace  The NAPI IDs were not fully exposed to user space prior to the netlink API, so they were never namespaced. The netlink API must ensure that at the very least NAPI instance belongs to the same netns as the owner of the genl sock.  napi_by_id() can become static now, but it needs to move because of dev_get_by_napi_id().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21656?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21656" src="https://img.shields.io/badge/CVE--2025--21656-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  hwmon: (drivetemp) Fix driver producing garbage data when SCSI errors occur  scsi_execute_cmd() function can return both negative (linux codes) and positive (scsi_cmnd result field) error codes.  Currently the driver just passes error codes of scsi_execute_cmd() to hwmon core, which is incorrect because hwmon only checks for negative error codes. This leads to hwmon reporting uninitialized data to userspace in case of SCSI errors (for example if the disk drive was disconnected).  This patch checks scsi_execute_cmd() output and returns -EIO if it's error code is positive.  [groeck: Avoid inline variable declaration for portability]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21655?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21655" src="https://img.shields.io/badge/CVE--2025--21655-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.056%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>18th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  io_uring/eventfd: ensure io_eventfd_signal() defers another RCU period  io_eventfd_do_signal() is invoked from an RCU callback, but when dropping the reference to the io_ev_fd, it calls io_eventfd_free() directly if the refcount drops to zero. This isn't correct, as any potential freeing of the io_ev_fd should be deferred another RCU grace period.  Just call io_eventfd_put() rather than open-code the dec-and-test and free, which will correctly defer it another RCU grace period.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21654?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21654" src="https://img.shields.io/badge/CVE--2025--21654-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ovl: support encoding fid from inode with no alias  Dmitry Safonov reported that a WARN_ON() assertion can be trigered by userspace when calling inotify_show_fdinfo() for an overlayfs watched inode, whose dentry aliases were discarded with drop_caches.  The WARN_ON() assertion in inotify_show_fdinfo() was removed, because it is possible for encoding file handle to fail for other reason, but the impact of failing to encode an overlayfs file handle goes beyond this assertion.  As shown in the LTP test case mentioned in the link below, failure to encode an overlayfs file handle from a non-aliased inode also leads to failure to report an fid with FAN_DELETE_SELF fanotify events.  As Dmitry notes in his analyzis of the problem, ovl_encode_fh() fails if it cannot find an alias for the inode, but this failure can be fixed. ovl_encode_fh() seldom uses the alias and in the case of non-decodable file handles, as is often the case with fanotify fid info, ovl_encode_fh() never needs to use the alias to encode a file handle.  Defer finding an alias until it is actually needed so ovl_encode_fh() will not fail in the common case of FAN_DELETE_SELF fanotify events.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21653?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21653" src="https://img.shields.io/badge/CVE--2025--21653-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net_sched: cls_flow: validate TCA_FLOW_RSHIFT attribute  syzbot found that TCA_FLOW_RSHIFT attribute was not validated. Right shitfing a 32bit integer is undefined for large shift values.  UBSAN: shift-out-of-bounds in net/sched/cls_flow.c:329:23 shift exponent 9445 is too large for 32-bit type 'u32' (aka 'unsigned int') CPU: 1 UID: 0 PID: 54 Comm: kworker/u8:3 Not tainted 6.13.0-rc3-syzkaller-00180-g4f619d518db9 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Workqueue: ipv6_addrconf addrconf_dad_work Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 ubsan_epilogue lib/ubsan.c:231 [inline] __ubsan_handle_shift_out_of_bounds+0x3c8/0x420 lib/ubsan.c:468 flow_classify+0x24d5/0x25b0 net/sched/cls_flow.c:329 tc_classify include/net/tc_wrapper.h:197 [inline] __tcf_classify net/sched/cls_api.c:1771 [inline] tcf_classify+0x420/0x1160 net/sched/cls_api.c:1867 sfb_classify net/sched/sch_sfb.c:260 [inline] sfb_enqueue+0x3ad/0x18b0 net/sched/sch_sfb.c:318 dev_qdisc_enqueue+0x4b/0x290 net/core/dev.c:3793 __dev_xmit_skb net/core/dev.c:3889 [inline] __dev_queue_xmit+0xf0e/0x3f50 net/core/dev.c:4400 dev_queue_xmit include/linux/netdevice.h:3168 [inline] neigh_hh_output include/net/neighbour.h:523 [inline] neigh_output include/net/neighbour.h:537 [inline] ip_finish_output2+0xd41/0x1390 net/ipv4/ip_output.c:236 iptunnel_xmit+0x55d/0x9b0 net/ipv4/ip_tunnel_core.c:82 udp_tunnel_xmit_skb+0x262/0x3b0 net/ipv4/udp_tunnel_core.c:173 geneve_xmit_skb drivers/net/geneve.c:916 [inline] geneve_xmit+0x21dc/0x2d00 drivers/net/geneve.c:1039 __netdev_start_xmit include/linux/netdevice.h:5002 [inline] netdev_start_xmit include/linux/netdevice.h:5011 [inline] xmit_one net/core/dev.c:3590 [inline] dev_hard_start_xmit+0x27a/0x7d0 net/core/dev.c:3606 __dev_queue_xmit+0x1b73/0x3f50 net/core/dev.c:4434

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21651?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21651" src="https://img.shields.io/badge/CVE--2025--21651-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: hns3: don't auto enable misc vector  Currently, there is a time window between misc irq enabled and service task inited. If an interrupte is reported at this time, it will cause warning like below:  [   16.324639] Call trace: [   16.324641]  __queue_delayed_work+0xb8/0xe0 [   16.324643]  mod_delayed_work_on+0x78/0xd0 [   16.324655]  hclge_errhand_task_schedule+0x58/0x90 [hclge] [   16.324662]  hclge_misc_irq_handle+0x168/0x240 [hclge] [   16.324666]  __handle_irq_event_percpu+0x64/0x1e0 [   16.324667]  handle_irq_event+0x80/0x170 [   16.324670]  handle_fasteoi_edge_irq+0x110/0x2bc [   16.324671]  __handle_domain_irq+0x84/0xfc [   16.324673]  gic_handle_irq+0x88/0x2c0 [   16.324674]  el1_irq+0xb8/0x140 [   16.324677]  arch_cpu_idle+0x18/0x40 [   16.324679]  default_idle_call+0x5c/0x1bc [   16.324682]  cpuidle_idle_call+0x18c/0x1c4 [   16.324684]  do_idle+0x174/0x17c [   16.324685]  cpu_startup_entry+0x30/0x6c [   16.324687]  secondary_start_kernel+0x1a4/0x280 [   16.324688] ---[ end trace 6aa0bff672a964aa ]---  So don't auto enable misc vector when request irq..

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21648?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21648" src="https://img.shields.io/badge/CVE--2025--21648-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfilter: conntrack: clamp maximum hashtable size to INT_MAX  Use INT_MAX as maximum size for the conntrack hashtable. Otherwise, it is possible to hit WARN_ON_ONCE in __kvmalloc_node_noprof() when resizing hashtable because __GFP_NOWARN is unset. See:  0708a0afe291 ("mm: Consider __GFP_NOWARN flag for oversized kvmalloc() calls")  Note: hashtable resize is only possible from init_netns.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21647?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21647" src="https://img.shields.io/badge/CVE--2025--21647-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.087%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>26th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  sched: sch_cake: add bounds checks to host bulk flow fairness counts  Even though we fixed a logic error in the commit cited below, syzbot still managed to trigger an underflow of the per-host bulk flow counters, leading to an out of bounds memory access.  To avoid any such logic errors causing out of bounds memory accesses, this commit factors out all accesses to the per-host bulk flow counters to a series of helpers that perform bounds-checking before any increments and decrements. This also has the benefit of improving readability by moving the conditional checks for the flow mode into these helpers, instead of having them spread out throughout the code (which was the cause of the original logic error).  As part of this change, the flow quantum calculation is consolidated into a helper function, which means that the dithering applied to the ost load scaling is now applied both in the DRR rotation and when a sparse flow's quantum is first initiated. The only user-visible effect of this is that the maximum packet size that can be sent while a flow stays sparse will now vary with +/- one byte in some cases. This should not make a noticeable difference in practice, and thus it's not worth complicating the code to preserve the old behaviour.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21646?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21646" src="https://img.shields.io/badge/CVE--2025--21646-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  afs: Fix the maximum cell name length  The kafs filesystem limits the maximum length of a cell to 256 bytes, but a problem occurs if someone actually does that: kafs tries to create a directory under /proc/net/afs/ with the name of the cell, but that fails with a warning:  WARNING: CPU: 0 PID: 9 at fs/proc/generic.c:405  because procfs limits the maximum filename length to 255.  However, the DNS limits the maximum lookup length and, by extension, the maximum cell name, to 255 less two (length count and trailing NUL).  Fix this by limiting the maximum acceptable cellname length to 253.  This also allows us to be sure we can create the "/afs/.<cell>/" mountpoint too.  Further, split the YFS VL record cell name maximum to be the 256 allowed by the protocol and ignore the record retrieved by YFSVL.GetCellName if it exceeds 253.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21643?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21643" src="https://img.shields.io/badge/CVE--2025--21643-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  netfs: Fix kernel async DIO  Netfslib needs to be able to handle kernel-initiated asynchronous DIO that is supplied with a bio_vec[] array.  Currently, because of the async flag, this gets passed to netfs_extract_user_iter() which throws a warning and fails because it only handles IOVEC and UBUF iterators.  This can be triggered through a combination of cifs and a loopback blockdev with something like:  mount //my/cifs/share /foo dd if=/dev/zero of=/foo/m0 bs=4K count=1K losetup --sector-size 4096 --direct-io=on /dev/loop2046 /foo/m0 echo hello >/dev/loop2046  This causes the following to appear in syslog:  WARNING: CPU: 2 PID: 109 at fs/netfs/iterator.c:50 netfs_extract_user_iter+0x170/0x250 [netfs]  and the write to fail.  Fix this by removing the check in netfs_unbuffered_write_iter_locked() that causes async kernel DIO writes to be handled as userspace writes.  Note that this change relies on the kernel caller maintaining the existence of the bio_vec array (or kvec[] or folio_queue) until the op is complete.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21632?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2025--21632" src="https://img.shields.io/badge/CVE--2025--21632-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  x86/fpu: Ensure shadow stack is active before "getting" registers  The x86 shadow stack support has its own set of registers. Those registers are XSAVE-managed, but they are "supervisor state components" which means that userspace can not touch them with XSAVE/XRSTOR.  It also means that they are not accessible from the existing ptrace ABI for XSAVE state. Thus, there is a new ptrace get/set interface for it.  The regset code that ptrace uses provides an ->active() handler in addition to the get/set ones. For shadow stack this ->active() handler verifies that shadow stack is enabled via the ARCH_SHSTK_SHSTK bit in the thread struct. The ->active() handler is checked from some call sites of the regset get/set handlers, but not the ptrace ones. This was not understood when shadow stack support was put in place.  As a result, both the set/get handlers can be called with XFEATURE_CET_USER in its init state, which would cause get_xsave_addr() to return NULL and trigger a WARN_ON(). The ssp_set() handler luckily has an ssp_active() check to avoid surprising the kernel with shadow stack behavior when the kernel is not ready for it (ARCH_SHSTK_SHSTK==0). That check just happened to avoid the warning.  But the ->get() side wasn't so lucky. It can be called with shadow stacks disabled, triggering the warning in practice, as reported by Christina Schimpe:  WARNING: CPU: 5 PID: 1773 at arch/x86/kernel/fpu/regset.c:198 ssp_get+0x89/0xa0 [...] Call Trace: <TASK> ? show_regs+0x6e/0x80 ? ssp_get+0x89/0xa0 ? __warn+0x91/0x150 ? ssp_get+0x89/0xa0 ? report_bug+0x19d/0x1b0 ? handle_bug+0x46/0x80 ? exc_invalid_op+0x1d/0x80 ? asm_exc_invalid_op+0x1f/0x30 ? __pfx_ssp_get+0x10/0x10 ? ssp_get+0x89/0xa0 ? ssp_get+0x52/0xa0 __regset_get+0xad/0xf0 copy_regset_to_user+0x52/0xc0 ptrace_regset+0x119/0x140 ptrace_request+0x13c/0x850 ? wait_task_inactive+0x142/0x1d0 ? do_syscall_64+0x6d/0x90 arch_ptrace+0x102/0x300 [...]  Ensure that shadow stacks are active in a thread before looking them up in the XSAVE buffer. Since ARCH_SHSTK_SHSTK and user_ssp[SHSTK_EN] are set at the same time, the active check ensures that there will be something to find in the XSAVE buffer.  [ dhansen: changelog/subject tweaks ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57945?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57945" src="https://img.shields.io/badge/CVE--2024--57945-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  riscv: mm: Fix the out of bound issue of vmemmap address  In sparse vmemmap model, the virtual address of vmemmap is calculated as: ((struct page *)VMEMMAP_START - (phys_ram_base >> PAGE_SHIFT)). And the struct page's va can be calculated with an offset: (vmemmap + (pfn)).  However, when initializing struct pages, kernel actually starts from the first page from the same section that phys_ram_base belongs to. If the first page's physical address is not (phys_ram_base >> PAGE_SHIFT), then we get an va below VMEMMAP_START when calculating va for it's struct page.  For example, if phys_ram_base starts from 0x82000000 with pfn 0x82000, the first page in the same section is actually pfn 0x80000. During init_unavailable_range(), we will initialize struct page for pfn 0x80000 with virtual address ((struct page *)VMEMMAP_START - 0x2000), which is below VMEMMAP_START as well as PCI_IO_END.  This commit fixes this bug by introducing a new variable 'vmemmap_start_pfn' which is aligned with memory section size and using it to calculate vmemmap address instead of phys_ram_base.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57932?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57932" src="https://img.shields.io/badge/CVE--2024--57932-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gve: guard XDP xmit NDO on existence of xdp queues  In GVE, dedicated XDP queues only exist when an XDP program is installed and the interface is up. As such, the NDO XDP XMIT callback should return early if either of these conditions are false.  In the case of no loaded XDP program, priv->num_xdp_queues=0 which can cause a divide-by-zero error, and in the case of interface down, num_xdp_queues remains untouched to persist XDP queue count for the next interface up, but the TX pointer itself would be NULL.  The XDP xmit callback also needs to synchronize with a device transitioning from open to close. This synchronization will happen via the GVE_PRIV_FLAGS_NAPI_ENABLED bit along with a synchronize_net() call, which waits for any RCU critical sections at call-time to complete.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57931?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57931" src="https://img.shields.io/badge/CVE--2024--57931-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  selinux: ignore unknown extended permissions  When evaluating extended permissions, ignore unknown permissions instead of calling BUG(). This commit ensures that future permissions can be added without interfering with older kernels.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57929?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57929" src="https://img.shields.io/badge/CVE--2024--57929-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  dm array: fix releasing a faulty array block twice in dm_array_cursor_end  When dm_bm_read_lock() fails due to locking or checksum errors, it releases the faulty block implicitly while leaving an invalid output pointer behind. The caller of dm_bm_read_lock() should not operate on this invalid dm_block pointer, or it will lead to undefined result. For example, the dm_array_cursor incorrectly caches the invalid pointer on reading a faulty array block, causing a double release in dm_array_cursor_end(), then hitting the BUG_ON in dm-bufio cache_put().  Reproduce steps:  1. initialize a cache device  dmsetup create cmeta --table "0 8192 linear /dev/sdc 0" dmsetup create cdata --table "0 65536 linear /dev/sdc 8192" dmsetup create corig --table "0 524288 linear /dev/sdc $262144" dd if=/dev/zero of=/dev/mapper/cmeta bs=4k count=1 dmsetup create cache --table "0 524288 cache /dev/mapper/cmeta \ /dev/mapper/cdata /dev/mapper/corig 128 2 metadata2 writethrough smq 0"  2. wipe the second array block offline  dmsteup remove cache cmeta cdata corig mapping_root=$(dd if=/dev/sdc bs=1c count=8 skip=192 \ 2>/dev/null | hexdump -e '1/8 "%u\n"') ablock=$(dd if=/dev/sdc bs=1c count=8 skip=$((4096*mapping_root+2056)) \ 2>/dev/null | hexdump -e '1/8 "%u\n"') dd if=/dev/zero of=/dev/sdc bs=4k count=1 seek=$ablock  3. try reopen the cache device  dmsetup create cmeta --table "0 8192 linear /dev/sdc 0" dmsetup create cdata --table "0 65536 linear /dev/sdc 8192" dmsetup create corig --table "0 524288 linear /dev/sdc $262144" dmsetup create cache --table "0 524288 cache /dev/mapper/cmeta \ /dev/mapper/cdata /dev/mapper/corig 128 2 metadata2 writethrough smq 0"  Kernel logs:  (snip) device-mapper: array: array_block_check failed: blocknr 0 != wanted 10 device-mapper: block manager: array validator check failed for block 10 device-mapper: array: get_ablock failed device-mapper: cache metadata: dm_array_cursor_next for mapping failed ------------[ cut here ]------------ kernel BUG at drivers/md/dm-bufio.c:638!  Fix by setting the cached block pointer to NULL on errors.  In addition to the reproducer described above, this fix can be verified using the "array_cursor/damaged" test in dm-unit: dm-unit run /pdata/array_cursor/damaged --kernel-dir <KERNEL_DIR>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57917?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57917" src="https://img.shields.io/badge/CVE--2024--57917-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.049%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  topology: Keep the cpumask unchanged when printing cpumap  During fuzz testing, the following warning was discovered:  different return values (15 and 11) from vsnprintf("%*pbl ", ...)  test:keyward is WARNING in kvasprintf WARNING: CPU: 55 PID: 1168477 at lib/kasprintf.c:30 kvasprintf+0x121/0x130 Call Trace: kvasprintf+0x121/0x130 kasprintf+0xa6/0xe0 bitmap_print_to_buf+0x89/0x100 core_siblings_list_read+0x7e/0xb0 kernfs_file_read_iter+0x15b/0x270 new_sync_read+0x153/0x260 vfs_read+0x215/0x290 ksys_read+0xb9/0x160 do_syscall_64+0x56/0x100 entry_SYSCALL_64_after_hwframe+0x78/0xe2  The call trace shows that kvasprintf() reported this warning during the printing of core_siblings_list. kvasprintf() has several steps:  (1) First, calculate the length of the resulting formatted string.  (2) Allocate a buffer based on the returned length.  (3) Then, perform the actual string formatting.  (4) Check whether the lengths of the formatted strings returned in steps (1) and (2) are consistent.  If the core_cpumask is modified between steps (1) and (3), the lengths obtained in these two steps may not match. Indeed our test includes cpu hotplugging, which should modify core_cpumask while printing.  To fix this issue, cache the cpumask into a temporary variable before calling cpumap_print_{list, cpumask}_to_buf(), to keep it unchanged during the printing process.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57904?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57904" src="https://img.shields.io/badge/CVE--2024--57904-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iio: adc: at91: call input_free_device() on allocated iio_dev  Current implementation of at91_ts_register() calls input_free_deivce() on st->ts_input, however, the err label can be reached before the allocated iio_dev is stored to st->ts_input. Thus call input_free_device() on input instead of st->ts_input.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57903?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57903" src="https://img.shields.io/badge/CVE--2024--57903-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: restrict SO_REUSEPORT to inet sockets  After blamed commit, crypto sockets could accidentally be destroyed from RCU call back, as spotted by zyzbot [1].  Trying to acquire a mutex in RCU callback is not allowed.  Restrict SO_REUSEPORT socket option to inet sockets.  v1 of this patch supported TCP, UDP and SCTP sockets, but fcnal-test.sh test needed RAW and ICMP support.  [1] BUG: sleeping function called from invalid context at kernel/locking/mutex.c:562 in_atomic(): 1, irqs_disabled(): 0, non_block: 0, pid: 24, name: ksoftirqd/1 preempt_count: 100, expected: 0 RCU nest depth: 0, expected: 0 1 lock held by ksoftirqd/1/24: #0: ffffffff8e937ba0 (rcu_callback){....}-{0:0}, at: rcu_lock_acquire include/linux/rcupdate.h:337 [inline] #0: ffffffff8e937ba0 (rcu_callback){....}-{0:0}, at: rcu_do_batch kernel/rcu/tree.c:2561 [inline] #0: ffffffff8e937ba0 (rcu_callback){....}-{0:0}, at: rcu_core+0xa37/0x17a0 kernel/rcu/tree.c:2823 Preemption disabled at: [<ffffffff8161c8c8>] softirq_handle_begin kernel/softirq.c:402 [inline] [<ffffffff8161c8c8>] handle_softirqs+0x128/0x9b0 kernel/softirq.c:537 CPU: 1 UID: 0 PID: 24 Comm: ksoftirqd/1 Not tainted 6.13.0-rc3-syzkaller-00174-ga024e377efed #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 Call Trace: <TASK> __dump_stack lib/dump_stack.c:94 [inline] dump_stack_lvl+0x241/0x360 lib/dump_stack.c:120 __might_resched+0x5d4/0x780 kernel/sched/core.c:8758 __mutex_lock_common kernel/locking/mutex.c:562 [inline] __mutex_lock+0x131/0xee0 kernel/locking/mutex.c:735 crypto_put_default_null_skcipher+0x18/0x70 crypto/crypto_null.c:179 aead_release+0x3d/0x50 crypto/algif_aead.c:489 alg_do_release crypto/af_alg.c:118 [inline] alg_sock_destruct+0x86/0xc0 crypto/af_alg.c:502 __sk_destruct+0x58/0x5f0 net/core/sock.c:2260 rcu_do_batch kernel/rcu/tree.c:2567 [inline] rcu_core+0xaaa/0x17a0 kernel/rcu/tree.c:2823 handle_softirqs+0x2d4/0x9b0 kernel/softirq.c:561 run_ksoftirqd+0xca/0x130 kernel/softirq.c:950 smpboot_thread_fn+0x544/0xa30 kernel/smpboot.c:164 kthread+0x2f0/0x390 kernel/kthread.c:389 ret_from_fork+0x4b/0x80 arch/x86/kernel/process.c:147 ret_from_fork_asm+0x1a/0x30 arch/x86/entry/entry_64.S:244 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57899?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57899" src="https://img.shields.io/badge/CVE--2024--57899-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: mac80211: fix mbss changed flags corruption on 32 bit systems  On 32-bit systems, the size of an unsigned long is 4 bytes, while a u64 is 8 bytes. Therefore, when using or_each_set_bit(bit, &bits, sizeof(changed) * BITS_PER_BYTE), the code is incorrectly searching for a bit in a 32-bit variable that is expected to be 64 bits in size, leading to incorrect bit finding.  Solution: Ensure that the size of the bits variable is correctly adjusted for each architecture.  Call Trace: ? show_regs+0x54/0x58 ? __warn+0x6b/0xd4 ? ieee80211_link_info_change_notify+0xcc/0xd4 [mac80211] ? report_bug+0x113/0x150 ? exc_overflow+0x30/0x30 ? handle_bug+0x27/0x44 ? exc_invalid_op+0x18/0x50 ? handle_exception+0xf6/0xf6 ? exc_overflow+0x30/0x30 ? ieee80211_link_info_change_notify+0xcc/0xd4 [mac80211] ? exc_overflow+0x30/0x30 ? ieee80211_link_info_change_notify+0xcc/0xd4 [mac80211] ? ieee80211_mesh_work+0xff/0x260 [mac80211] ? cfg80211_wiphy_work+0x72/0x98 [cfg80211] ? process_one_work+0xf1/0x1fc ? worker_thread+0x2c0/0x3b4 ? kthread+0xc7/0xf0 ? mod_delayed_work_on+0x4c/0x4c ? kthread_complete_and_exit+0x14/0x14 ? ret_from_fork+0x24/0x38 ? kthread_complete_and_exit+0x14/0x14 ? ret_from_fork_asm+0xf/0x14 ? entry_INT80_32+0xf0/0xf0  [restore no-op path for no changes]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57898?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57898" src="https://img.shields.io/badge/CVE--2024--57898-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.037%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>10th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  wifi: cfg80211: clear link ID from bitmap during link delete after clean up  Currently, during link deletion, the link ID is first removed from the valid_links bitmap before performing any clean-up operations. However, some functions require the link ID to remain in the valid_links bitmap. One such example is cfg80211_cac_event(). The flow is -  nl80211_remove_link() cfg80211_remove_link() ieee80211_del_intf_link() ieee80211_vif_set_links() ieee80211_vif_update_links() ieee80211_link_stop() cfg80211_cac_event()  cfg80211_cac_event() requires link ID to be present but it is cleared already in cfg80211_remove_link(). Ultimately, WARN_ON() is hit.  Therefore, clear the link ID from the bitmap only after completing the link clean-up.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57897?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57897" src="https://img.shields.io/badge/CVE--2024--57897-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.045%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/amdkfd: Correct the migration DMA map direction  The SVM DMA device map direction should be set the same as the DMA unmap setting, otherwise the DMA core will report the following warning.  Before finialize this solution, there're some discussion on the DMA mapping type(stream-based or coherent) in this KFD migration case, followed by https://lore.kernel.org/all/04d4ab32 -45a1-4b88-86ee-fb0f35a0ca40@amd.com/T/.  As there's no dma_sync_single_for_*() in the DMA buffer accessed that because this migration operation should be sync properly and automatically. Give that there's might not be a performance problem in various cache sync policy of DMA sync. Therefore, in order to simplify the DMA direction setting alignment, let's set the DMA map direction as BIDIRECTIONAL.  [  150.834218] WARNING: CPU: 8 PID: 1812 at kernel/dma/debug.c:1028 check_unmap+0x1cc/0x930 [  150.834225] Modules linked in: amdgpu(OE) amdxcp drm_exec(OE) gpu_sched drm_buddy(OE) drm_ttm_helper(OE) ttm(OE) drm_suballoc_helper(OE) drm_display_helper(OE) drm_kms_helper(OE) i2c_algo_bit rpcsec_gss_krb5 auth_rpcgss nfsv4 nfs lockd grace netfs xt_conntrack xt_MASQUERADE nf_conntrack_netlink xfrm_user xfrm_algo iptable_nat xt_addrtype iptable_filter br_netfilter nvme_fabrics overlay nfnetlink_cttimeout nfnetlink openvswitch nsh nf_conncount nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 libcrc32c bridge stp llc sch_fq_codel intel_rapl_msr amd_atl intel_rapl_common snd_hda_codec_realtek snd_hda_codec_generic snd_hda_scodec_component snd_hda_codec_hdmi snd_hda_intel snd_intel_dspcfg edac_mce_amd snd_pci_acp6x snd_hda_codec snd_acp_config snd_hda_core snd_hwdep snd_soc_acpi kvm_amd sunrpc snd_pcm kvm binfmt_misc snd_seq_midi crct10dif_pclmul snd_seq_midi_event ghash_clmulni_intel sha512_ssse3 snd_rawmidi nls_iso8859_1 sha256_ssse3 sha1_ssse3 snd_seq aesni_intel snd_seq_device crypto_simd snd_timer cryptd input_leds [  150.834310]  wmi_bmof serio_raw k10temp rapl snd sp5100_tco ipmi_devintf soundcore ccp ipmi_msghandler cm32181 industrialio mac_hid msr parport_pc ppdev lp parport efi_pstore drm(OE) ip_tables x_tables pci_stub crc32_pclmul nvme ahci libahci i2c_piix4 r8169 nvme_core i2c_designware_pci realtek i2c_ccgx_ucsi video wmi hid_generic cdc_ether usbnet usbhid hid r8152 mii [  150.834354] CPU: 8 PID: 1812 Comm: rocrtst64 Tainted: G           OE 6.10.0-custom #492 [  150.834358] Hardware name: AMD Majolica-RN/Majolica-RN, BIOS RMJ1009A 06/13/2021 [  150.834360] RIP: 0010:check_unmap+0x1cc/0x930 [  150.834363] Code: c0 4c 89 4d c8 e8 34 bf 86 00 4c 8b 4d c8 4c 8b 45 c0 48 8b 4d b8 48 89 c6 41 57 4c 89 ea 48 c7 c7 80 49 b4 84 e8 b4 81 f3 ff <0f> 0b 48 c7 c7 04 83 ac 84 e8 76 ba fc ff 41 8b 76 4c 49 8d 7e 50 [  150.834365] RSP: 0018:ffffaac5023739e0 EFLAGS: 00010086 [  150.834368] RAX: 0000000000000000 RBX: ffffffff8566a2e0 RCX: 0000000000000027 [  150.834370] RDX: ffff8f6a8f621688 RSI: 0000000000000001 RDI: ffff8f6a8f621680 [  150.834372] RBP: ffffaac502373a30 R08: 00000000000000c9 R09: ffffaac502373850 [  150.834373] R10: ffffaac502373848 R11: ffffffff84f46328 R12: ffffaac502373a40 [  150.834375] R13: ffff8f6741045330 R14: ffff8f6741a77700 R15: ffffffff84ac831b [  150.834377] FS:  00007faf0fc94c00(0000) GS:ffff8f6a8f600000(0000) knlGS:0000000000000000 [  150.834379] CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 [  150.834381] CR2: 00007faf0b600020 CR3: 000000010a52e000 CR4: 0000000000350ef0 [  150.834383] Call Trace: [  150.834385]  <TASK> [  150.834387]  ? show_regs+0x6d/0x80 [  150.834393]  ? __warn+0x8c/0x140 [  150.834397]  ? check_unmap+0x1cc/0x930 [  150.834400]  ? report_bug+0x193/0x1a0 [  150.834406]  ? handle_bug+0x46/0x80 [  150.834410]  ? exc_invalid_op+0x1d/0x80 [  150.834413]  ? asm_exc_invalid_op+0x1f/0x30 [  150.834420]  ? check_unmap+0x1cc/0x930 [  150.834425]  debug_dma_unmap_page+0x86/0x90 [  150.834431]  ? srso_return_thunk+0x5/0x5f [  150.834435] ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57893?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57893" src="https://img.shields.io/badge/CVE--2024--57893-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ALSA: seq: oss: Fix races at processing SysEx messages  OSS sequencer handles the SysEx messages split in 6 bytes packets, and ALSA sequencer OSS layer tries to combine those.  It stores the data in the internal buffer and this access is racy as of now, which may lead to the out-of-bounds access.  As a temporary band-aid fix, introduce a mutex for serializing the process of the SysEx message packets.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57889?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57889" src="https://img.shields.io/badge/CVE--2024--57889-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pinctrl: mcp23s08: Fix sleeping in atomic context due to regmap locking  If a device uses MCP23xxx IO expander to receive IRQs, the following bug can happen:  BUG: sleeping function called from invalid context at kernel/locking/mutex.c:283 in_atomic(): 1, irqs_disabled(): 1, non_block: 0, ... preempt_count: 1, expected: 0 ... Call Trace: ... __might_resched+0x104/0x10e __might_sleep+0x3e/0x62 mutex_lock+0x20/0x4c regmap_lock_mutex+0x10/0x18 regmap_update_bits_base+0x2c/0x66 mcp23s08_irq_set_type+0x1ae/0x1d6 __irq_set_trigger+0x56/0x172 __setup_irq+0x1e6/0x646 request_threaded_irq+0xb6/0x160 ...  We observed the problem while experimenting with a touchscreen driver which used MCP23017 IO expander (I2C).  The regmap in the pinctrl-mcp23s08 driver uses a mutex for protection from concurrent accesses, which is the default for regmaps without .fast_io, .disable_locking, etc.  mcp23s08_irq_set_type() calls regmap_update_bits_base(), and the latter locks the mutex.  However, __setup_irq() locks desc->lock spinlock before calling these functions. As a result, the system tries to lock the mutex whole holding the spinlock.  It seems, the internal regmap locks are not needed in this driver at all. mcp->lock seems to protect the regmap from concurrent accesses already, except, probably, in mcp_pinconf_get/set.  mcp23s08_irq_set_type() and mcp23s08_irq_mask/unmask() are called under chip_bus_lock(), which calls mcp23s08_irq_bus_lock(). The latter takes mcp->lock and enables regmap caching, so that the potentially slow I2C accesses are deferred until chip_bus_unlock().  The accesses to the regmap from mcp23s08_probe_one() do not need additional locking.  In all remaining places where the regmap is accessed, except mcp_pinconf_get/set(), the driver already takes mcp->lock.  This patch adds locking in mcp_pinconf_get/set() and disables internal locking in the regmap config. Among other things, it fixes the sleeping in atomic context described above.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57888?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57888" src="https://img.shields.io/badge/CVE--2024--57888-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  workqueue: Do not warn when cancelling WQ_MEM_RECLAIM work from !WQ_MEM_RECLAIM worker  After commit 746ae46c1113 ("drm/sched: Mark scheduler work queues with WQ_MEM_RECLAIM") amdgpu started seeing the following warning:  [ ] workqueue: WQ_MEM_RECLAIM sdma0:drm_sched_run_job_work [gpu_sched] is flushing !WQ_MEM_RECLAIM events:amdgpu_device_delay_enable_gfx_off [amdgpu] ... [ ] Workqueue: sdma0 drm_sched_run_job_work [gpu_sched] ... [ ] Call Trace: [ ]  <TASK> ... [ ]  ? check_flush_dependency+0xf5/0x110 ... [ ]  cancel_delayed_work_sync+0x6e/0x80 [ ]  amdgpu_gfx_off_ctrl+0xab/0x140 [amdgpu] [ ]  amdgpu_ring_alloc+0x40/0x50 [amdgpu] [ ]  amdgpu_ib_schedule+0xf4/0x810 [amdgpu] [ ]  ? drm_sched_run_job_work+0x22c/0x430 [gpu_sched] [ ]  amdgpu_job_run+0xaa/0x1f0 [amdgpu] [ ]  drm_sched_run_job_work+0x257/0x430 [gpu_sched] [ ]  process_one_work+0x217/0x720 ... [ ]  </TASK>  The intent of the verifcation done in check_flush_depedency is to ensure forward progress during memory reclaim, by flagging cases when either a memory reclaim process, or a memory reclaim work item is flushed from a context not marked as memory reclaim safe.  This is correct when flushing, but when called from the cancel(_delayed)_work_sync() paths it is a false positive because work is either already running, or will not be running at all. Therefore cancelling it is safe and we can relax the warning criteria by letting the helper know of the calling context.  References: 746ae46c1113 ("drm/sched: Mark scheduler work queues with WQ_MEM_RECLAIM")

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57885?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57885" src="https://img.shields.io/badge/CVE--2024--57885-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm/kmemleak: fix sleeping function called from invalid context at print message  Address a bug in the kernel that triggers a "sleeping function called from invalid context" warning when /sys/kernel/debug/kmemleak is printed under specific conditions: - CONFIG_PREEMPT_RT=y - Set SELinux as the LSM for the system - Set kptr_restrict to 1 - kmemleak buffer contains at least one item  BUG: sleeping function called from invalid context at kernel/locking/spinlock_rt.c:48 in_atomic(): 1, irqs_disabled(): 1, non_block: 0, pid: 136, name: cat preempt_count: 1, expected: 0 RCU nest depth: 2, expected: 2 6 locks held by cat/136: #0: ffff32e64bcbf950 (&p->lock){+.+.}-{3:3}, at: seq_read_iter+0xb8/0xe30 #1: ffffafe6aaa9dea0 (scan_mutex){+.+.}-{3:3}, at: kmemleak_seq_start+0x34/0x128 #3: ffff32e6546b1cd0 (&object->lock){....}-{2:2}, at: kmemleak_seq_show+0x3c/0x1e0 #4: ffffafe6aa8d8560 (rcu_read_lock){....}-{1:2}, at: has_ns_capability_noaudit+0x8/0x1b0 #5: ffffafe6aabbc0f8 (notif_lock){+.+.}-{2:2}, at: avc_compute_av+0xc4/0x3d0 irq event stamp: 136660 hardirqs last  enabled at (136659): [<ffffafe6a80fd7a0>] _raw_spin_unlock_irqrestore+0xa8/0xd8 hardirqs last disabled at (136660): [<ffffafe6a80fd85c>] _raw_spin_lock_irqsave+0x8c/0xb0 softirqs last  enabled at (0): [<ffffafe6a5d50b28>] copy_process+0x11d8/0x3df8 softirqs last disabled at (0): [<0000000000000000>] 0x0 Preemption disabled at: [<ffffafe6a6598a4c>] kmemleak_seq_show+0x3c/0x1e0 CPU: 1 UID: 0 PID: 136 Comm: cat Tainted: G            E      6.11.0-rt7+ #34 Tainted: [E]=UNSIGNED_MODULE Hardware name: linux,dummy-virt (DT) Call trace: dump_backtrace+0xa0/0x128 show_stack+0x1c/0x30 dump_stack_lvl+0xe8/0x198 dump_stack+0x18/0x20 rt_spin_lock+0x8c/0x1a8 avc_perm_nonode+0xa0/0x150 cred_has_capability.isra.0+0x118/0x218 selinux_capable+0x50/0x80 security_capable+0x7c/0xd0 has_ns_capability_noaudit+0x94/0x1b0 has_capability_noaudit+0x20/0x30 restricted_pointer+0x21c/0x4b0 pointer+0x298/0x760 vsnprintf+0x330/0xf70 seq_printf+0x178/0x218 print_unreferenced+0x1a4/0x2d0 kmemleak_seq_show+0xd0/0x1e0 seq_read_iter+0x354/0xe30 seq_read+0x250/0x378 full_proxy_read+0xd8/0x148 vfs_read+0x190/0x918 ksys_read+0xf0/0x1e0 __arm64_sys_read+0x70/0xa8 invoke_syscall.constprop.0+0xd4/0x1d8 el0_svc+0x50/0x158 el0t_64_sync+0x17c/0x180  %pS and %pK, in the same back trace line, are redundant, and %pS can void %pK service in certain contexts.  %pS alone already provides the necessary information, and if it cannot resolve the symbol, it falls back to printing the raw address voiding the original intent behind the %pK.  Additionally, %pK requires a privilege check CAP_SYSLOG enforced through the LSM, which can trigger a "sleeping function called from invalid context" warning under RT_PREEMPT kernels when the check occurs in an atomic context. This issue may also affect other LSMs.  This change avoids the unnecessary privilege check and resolves the sleeping function warning without any loss of information.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57884?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57884" src="https://img.shields.io/badge/CVE--2024--57884-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm: vmscan: account for free pages to prevent infinite Loop in throttle_direct_reclaim()  The task sometimes continues looping in throttle_direct_reclaim() because allow_direct_reclaim(pgdat) keeps returning false.  #0 [ffff80002cb6f8d0] __switch_to at ffff8000080095ac #1 [ffff80002cb6f900] __schedule at ffff800008abbd1c #2 [ffff80002cb6f990] schedule at ffff800008abc50c #3 [ffff80002cb6f9b0] throttle_direct_reclaim at ffff800008273550 #4 [ffff80002cb6fa20] try_to_free_pages at ffff800008277b68 #5 [ffff80002cb6fae0] __alloc_pages_nodemask at ffff8000082c4660 #6 [ffff80002cb6fc50] alloc_pages_vma at ffff8000082e4a98 #7 [ffff80002cb6fca0] do_anonymous_page at ffff80000829f5a8 #8 [ffff80002cb6fce0] __handle_mm_fault at ffff8000082a5974 #9 [ffff80002cb6fd90] handle_mm_fault at ffff8000082a5bd4  At this point, the pgdat contains the following two zones:  NODE: 4  ZONE: 0  ADDR: ffff00817fffe540  NAME: "DMA32" SIZE: 20480  MIN/LOW/HIGH: 11/28/45 VM_STAT: NR_FREE_PAGES: 359 NR_ZONE_INACTIVE_ANON: 18813 NR_ZONE_ACTIVE_ANON: 0 NR_ZONE_INACTIVE_FILE: 50 NR_ZONE_ACTIVE_FILE: 0 NR_ZONE_UNEVICTABLE: 0 NR_ZONE_WRITE_PENDING: 0 NR_MLOCK: 0 NR_BOUNCE: 0 NR_ZSPAGES: 0 NR_FREE_CMA_PAGES: 0  NODE: 4  ZONE: 1  ADDR: ffff00817fffec00  NAME: "Normal" SIZE: 8454144  PRESENT: 98304  MIN/LOW/HIGH: 68/166/264 VM_STAT: NR_FREE_PAGES: 146 NR_ZONE_INACTIVE_ANON: 94668 NR_ZONE_ACTIVE_ANON: 3 NR_ZONE_INACTIVE_FILE: 735 NR_ZONE_ACTIVE_FILE: 78 NR_ZONE_UNEVICTABLE: 0 NR_ZONE_WRITE_PENDING: 0 NR_MLOCK: 0 NR_BOUNCE: 0 NR_ZSPAGES: 0 NR_FREE_CMA_PAGES: 0  In allow_direct_reclaim(), while processing ZONE_DMA32, the sum of inactive/active file-backed pages calculated in zone_reclaimable_pages() based on the result of zone_page_state_snapshot() is zero.  Additionally, since this system lacks swap, the calculation of inactive/ active anonymous pages is skipped.  crash> p nr_swap_pages nr_swap_pages = $1937 = { counter = 0 }  As a result, ZONE_DMA32 is deemed unreclaimable and skipped, moving on to the processing of the next zone, ZONE_NORMAL, despite ZONE_DMA32 having free pages significantly exceeding the high watermark.  The problem is that the pgdat->kswapd_failures hasn't been incremented.  crash> px ((struct pglist_data *) 0xffff00817fffe540)->kswapd_failures $1935 = 0x0  This is because the node deemed balanced.  The node balancing logic in balance_pgdat() evaluates all zones collectively.  If one or more zones (e.g., ZONE_DMA32) have enough free pages to meet their watermarks, the entire node is deemed balanced.  This causes balance_pgdat() to exit early before incrementing the kswapd_failures, as it considers the overall memory state acceptable, even though some zones (like ZONE_NORMAL) remain under significant pressure.   The patch ensures that zone_reclaimable_pages() includes free pages (NR_FREE_PAGES) in its calculation when no other reclaimable pages are available (e.g., file-backed or anonymous pages).  This change prevents zones like ZONE_DMA32, which have sufficient free pages, from being mistakenly deemed unreclaimable.  By doing so, the patch ensures proper node balancing, avoids masking pressure on other zones like ZONE_NORMAL, and prevents infinite loops in throttle_direct_reclaim() caused by allow_direct_reclaim(pgdat) repeatedly returning false.   The kernel hangs due to a task stuck in throttle_direct_reclaim(), caused by a node being incorrectly deemed balanced despite pressure in certain zones, such as ZONE_NORMAL.  This issue arises from zone_reclaimable_pages ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57883?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57883" src="https://img.shields.io/badge/CVE--2024--57883-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mm: hugetlb: independent PMD page table shared count  The folio refcount may be increased unexpectly through try_get_folio() by caller such as split_huge_pages.  In huge_pmd_unshare(), we use refcount to check whether a pmd page table is shared.  The check is incorrect if the refcount is increased by the above caller, and this can cause the page table leaked:  BUG: Bad page state in process sh  pfn:109324 page: refcount:0 mapcount:0 mapping:0000000000000000 index:0x66 pfn:0x109324 flags: 0x17ffff800000000(node=0|zone=2|lastcpupid=0xfffff) page_type: f2(table) raw: 017ffff800000000 0000000000000000 0000000000000000 0000000000000000 raw: 0000000000000066 0000000000000000 00000000f2000000 0000000000000000 page dumped because: nonzero mapcount ... CPU: 31 UID: 0 PID: 7515 Comm: sh Kdump: loaded Tainted: G    B 6.13.0-rc2master+ #7 Tainted: [B]=BAD_PAGE Hardware name: QEMU KVM Virtual Machine, BIOS 0.0.0 02/06/2015 Call trace: show_stack+0x20/0x38 (C) dump_stack_lvl+0x80/0xf8 dump_stack+0x18/0x28 bad_page+0x8c/0x130 free_page_is_bad_report+0xa4/0xb0 free_unref_page+0x3cc/0x620 __folio_put+0xf4/0x158 split_huge_pages_all+0x1e0/0x3e8 split_huge_pages_write+0x25c/0x2d8 full_proxy_write+0x64/0xd8 vfs_write+0xcc/0x280 ksys_write+0x70/0x110 __arm64_sys_write+0x24/0x38 invoke_syscall+0x50/0x120 el0_svc_common.constprop.0+0xc8/0xf0 do_el0_svc+0x24/0x38 el0_svc+0x34/0x128 el0t_64_sync_handler+0xc8/0xd0 el0t_64_sync+0x190/0x198  The issue may be triggered by damon, offline_page, page_idle, etc, which will increase the refcount of page table.  1. The page table itself will be discarded after reporting the "nonzero mapcount".  2. The HugeTLB page mapped by the page table miss freeing since we treat the page table as shared and a shared page table will not be unmapped.  Fix it by introducing independent PMD page table shared count.  As described by comment, pt_index/pt_mm/pt_frag_refcount are used for s390 gmap, x86 pgds and powerpc, pt_share_count is used for x86/arm64/riscv pmds, so we can reuse the field as pt_share_count.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57879?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57879" src="https://img.shields.io/badge/CVE--2024--57879-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Bluetooth: iso: Always release hdev at the end of iso_listen_bis  Since hci_get_route holds the device before returning, the hdev should be released with hci_dev_put at the end of iso_listen_bis even if the function returns with an error.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57806?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57806" src="https://img.shields.io/badge/CVE--2024--57806-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  btrfs: fix transaction atomicity bug when enabling simple quotas  Set squota incompat bit before committing the transaction that enables the feature.  With the config CONFIG_BTRFS_ASSERT enabled, an assertion failure occurs regarding the simple quota feature.  [5.596534] assertion failed: btrfs_fs_incompat(fs_info, SIMPLE_QUOTA), in fs/btrfs/qgroup.c:365 [5.597098] ------------[ cut here ]------------ [5.597371] kernel BUG at fs/btrfs/qgroup.c:365! [5.597946] CPU: 1 UID: 0 PID: 268 Comm: mount Not tainted 6.13.0-rc2-00031-gf92f4749861b #146 [5.598450] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.16.2-debian-1.16.2-1 04/01/2014 [5.599008] RIP: 0010:btrfs_read_qgroup_config+0x74d/0x7a0 [5.604303]  <TASK> [5.605230]  ? btrfs_read_qgroup_config+0x74d/0x7a0 [5.605538]  ? exc_invalid_op+0x56/0x70 [5.605775]  ? btrfs_read_qgroup_config+0x74d/0x7a0 [5.606066]  ? asm_exc_invalid_op+0x1f/0x30 [5.606441]  ? btrfs_read_qgroup_config+0x74d/0x7a0 [5.606741]  ? btrfs_read_qgroup_config+0x74d/0x7a0 [5.607038]  ? try_to_wake_up+0x317/0x760 [5.607286]  open_ctree+0xd9c/0x1710 [5.607509]  btrfs_get_tree+0x58a/0x7e0 [5.608002]  vfs_get_tree+0x2e/0x100 [5.608224]  fc_mount+0x16/0x60 [5.608420]  btrfs_get_tree+0x2f8/0x7e0 [5.608897]  vfs_get_tree+0x2e/0x100 [5.609121]  path_mount+0x4c8/0xbc0 [5.609538]  __x64_sys_mount+0x10d/0x150  The issue can be easily reproduced using the following reproducer:  root@q:linux# cat repro.sh set -e  mkfs.btrfs -q -f /dev/sdb mount /dev/sdb /mnt/btrfs btrfs quota enable -s /mnt/btrfs umount /mnt/btrfs mount /dev/sdb /mnt/btrfs  The issue is that when enabling quotas, at btrfs_quota_enable(), we set BTRFS_QGROUP_STATUS_FLAG_SIMPLE_MODE at fs_info->qgroup_flags and persist it in the quota root in the item with the key BTRFS_QGROUP_STATUS_KEY, but we only set the incompat bit BTRFS_FEATURE_INCOMPAT_SIMPLE_QUOTA after we commit the transaction used to enable simple quotas.  This means that if after that transaction commit we unmount the filesystem without starting and committing any other transaction, or we have a power failure, the next time we mount the filesystem we will find the flag BTRFS_QGROUP_STATUS_FLAG_SIMPLE_MODE set in the item with the key BTRFS_QGROUP_STATUS_KEY but we will not find the incompat bit BTRFS_FEATURE_INCOMPAT_SIMPLE_QUOTA set in the superblock, triggering an assertion failure at:  btrfs_read_qgroup_config() -> qgroup_read_enable_gen()  To fix this issue, set the BTRFS_FEATURE_INCOMPAT_SIMPLE_QUOTA flag immediately after setting the BTRFS_QGROUP_STATUS_FLAG_SIMPLE_MODE. This ensures that both flags are flushed to disk within the same transaction.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57805?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57805" src="https://img.shields.io/badge/CVE--2024--57805-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ASoC: SOF: Intel: hda-dai: Do not release the link DMA on STOP  The linkDMA should not be released on stop trigger since a stream re-start might happen without closing of the stream. This leaves a short time for other streams to 'steal' the linkDMA since it has been released.  This issue is not easy to reproduce under normal conditions as usually after stop the stream is closed, or the same stream is restarted, but if another stream got in between the stop and start, like this: aplay -Dhw:0,3 -c2 -r48000 -fS32_LE /dev/zero -d 120 CTRL+z aplay -Dhw:0,0 -c2 -r48000 -fS32_LE /dev/zero -d 120  then the link DMA channels will be mixed up, resulting firmware error or crash.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57804?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57804" src="https://img.shields.io/badge/CVE--2024--57804-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: mpi3mr: Fix corrupt config pages PHY state is switched in sysfs  The driver, through the SAS transport, exposes a sysfs interface to enable/disable PHYs in a controller/expander setup.  When multiple PHYs are disabled and enabled in rapid succession, the persistent and current config pages related to SAS IO unit/SAS Expander pages could get corrupted.  Use separate memory for each config request.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57793?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57793" src="https://img.shields.io/badge/CVE--2024--57793-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  virt: tdx-guest: Just leak decrypted memory on unrecoverable errors  In CoCo VMs it is possible for the untrusted host to cause set_memory_decrypted() to fail such that an error is returned and the resulting memory is shared. Callers need to take care to handle these errors to avoid returning decrypted (shared) memory to the page allocator, which could lead to functional or security issues.  Leak the decrypted memory when set_memory_decrypted() fails, and don't need to print an error since set_memory_decrypted() will call WARN_ONCE().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57792?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57792" src="https://img.shields.io/badge/CVE--2024--57792-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  power: supply: gpio-charger: Fix set charge current limits  Fix set charge current limits for devices which allow to set the lowest charge current limit to be greater zero. If requested charge current limit is below lowest limit, the index equals current_limit_map_size which leads to accessing memory beyond allocated memory.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57791?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--57791" src="https://img.shields.io/badge/CVE--2024--57791-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/smc: check return value of sock_recvmsg when draining clc data  When receiving clc msg, the field length in smc_clc_msg_hdr indicates the length of msg should be received from network and the value should not be fully trusted as it is from the network. Once the value of length exceeds the value of buflen in function smc_clc_wait_msg it may run into deadloop when trying to drain the remaining data exceeding buflen.  This patch checks the return value of sock_recvmsg when draining data in case of deadloop in draining.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56709?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--56709" src="https://img.shields.io/badge/CVE--2024--56709-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.048%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>15th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  io_uring: check if iowq is killed before queuing  task work can be executed after the task has gone through io_uring termination, whether it's the final task_work run or the fallback path. In this case, task work will find ->io_wq being already killed and null'ed, which is a problem if it then tries to forward the request to io_queue_iowq(). Make io_queue_iowq() fail requests in this case.  Note that it also checks PF_KTHREAD, because the user can first close a DEFER_TASKRUN ring and shortly after kill the task, in which case ->iowq check would race.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-56372?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--56372" src="https://img.shields.io/badge/CVE--2024--56372-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: tun: fix tun_napi_alloc_frags()  syzbot reported the following crash [1]  Issue came with the blamed commit. Instead of going through all the iov components, we keep using the first one and end up with a malformed skb.  [1]  kernel BUG at net/core/skbuff.c:2849 ! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 0 UID: 0 PID: 6230 Comm: syz-executor132 Not tainted 6.13.0-rc1-syzkaller-00407-g96b6fcc0ee41 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 11/25/2024 RIP: 0010:__pskb_pull_tail+0x1568/0x1570 net/core/skbuff.c:2848 Code: 38 c1 0f 8c 32 f1 ff ff 4c 89 f7 e8 92 96 74 f8 e9 25 f1 ff ff e8 e8 ae 09 f8 48 8b 5c 24 08 e9 eb fb ff ff e8 d9 ae 09 f8 90 <0f> 0b 66 0f 1f 44 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 RSP: 0018:ffffc90004cbef30 EFLAGS: 00010293 RAX: ffffffff8995c347 RBX: 00000000fffffff2 RCX: ffff88802cf45a00 RDX: 0000000000000000 RSI: 00000000fffffff2 RDI: 0000000000000000 RBP: ffff88807df0c06a R08: ffffffff8995b084 R09: 1ffff1100fbe185c R10: dffffc0000000000 R11: ffffed100fbe185d R12: ffff888076e85d50 R13: ffff888076e85c80 R14: ffff888076e85cf4 R15: ffff888076e85c80 FS:  00007f0dca6ea6c0(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f0dca6ead58 CR3: 00000000119da000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> skb_cow_data+0x2da/0xcb0 net/core/skbuff.c:5284 tipc_aead_decrypt net/tipc/crypto.c:894 [inline] tipc_crypto_rcv+0x402/0x24e0 net/tipc/crypto.c:1844 tipc_rcv+0x57e/0x12a0 net/tipc/node.c:2109 tipc_l2_rcv_msg+0x2bd/0x450 net/tipc/bearer.c:668 __netif_receive_skb_list_ptype net/core/dev.c:5720 [inline] __netif_receive_skb_list_core+0x8b7/0x980 net/core/dev.c:5762 __netif_receive_skb_list net/core/dev.c:5814 [inline] netif_receive_skb_list_internal+0xa51/0xe30 net/core/dev.c:5905 gro_normal_list include/net/gro.h:515 [inline] napi_complete_done+0x2b5/0x870 net/core/dev.c:6256 napi_complete include/linux/netdevice.h:567 [inline] tun_get_user+0x2ea0/0x4890 drivers/net/tun.c:1982 tun_chr_write_iter+0x10d/0x1f0 drivers/net/tun.c:2057 do_iter_readv_writev+0x600/0x880 vfs_writev+0x376/0xba0 fs/read_write.c:1050 do_writev+0x1b6/0x360 fs/read_write.c:1096 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-55881?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--55881" src="https://img.shields.io/badge/CVE--2024--55881-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.034%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  KVM: x86: Play nice with protected guests in complete_hypercall_exit()  Use is_64_bit_hypercall() instead of is_64_bit_mode() to detect a 64-bit hypercall when completing said hypercall.  For guests with protected state, e.g. SEV-ES and SEV-SNP, KVM must assume the hypercall was made in 64-bit mode as the vCPU state needed to detect 64-bit mode is unavailable.  Hacking the sev_smoke_test selftest to generate a KVM_HC_MAP_GPA_RANGE hypercall via VMGEXIT trips the WARN:  ------------[ cut here ]------------ WARNING: CPU: 273 PID: 326626 at arch/x86/kvm/x86.h:180 complete_hypercall_exit+0x44/0xe0 [kvm] Modules linked in: kvm_amd kvm ... [last unloaded: kvm] CPU: 273 UID: 0 PID: 326626 Comm: sev_smoke_test Not tainted 6.12.0-smp--392e932fa0f3-feat #470 Hardware name: Google Astoria/astoria, BIOS 0.20240617.0-0 06/17/2024 RIP: 0010:complete_hypercall_exit+0x44/0xe0 [kvm] Call Trace: <TASK> kvm_arch_vcpu_ioctl_run+0x2400/0x2720 [kvm] kvm_vcpu_ioctl+0x54f/0x630 [kvm] __se_sys_ioctl+0x6b/0xc0 do_syscall_64+0x83/0x160 entry_SYSCALL_64_after_hwframe+0x76/0x7e </TASK> ---[ end trace 0000000000000000 ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-55639?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--55639" src="https://img.shields.io/badge/CVE--2024--55639-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: renesas: rswitch: avoid use-after-put for a device tree node  The device tree node saved in the rswitch_device structure is used at several driver locations. So passing this node to of_node_put() after the first use is wrong.  Move of_node_put() for this node to exit paths.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54455?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--54455" src="https://img.shields.io/badge/CVE--2024--54455-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  accel/ivpu: Fix general protection fault in ivpu_bo_list()  Check if ctx is not NULL before accessing its fields.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-54193?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--54193" src="https://img.shields.io/badge/CVE--2024--54193-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.028%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  accel/ivpu: Fix WARN in ivpu_ipc_send_receive_internal()  Move pm_runtime_set_active() to ivpu_pm_init() so when ivpu_ipc_send_receive_internal() is executed before ivpu_pm_enable() it already has correct runtime state, even if last resume was not successful.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53690?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--53690" src="https://img.shields.io/badge/CVE--2024--53690-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.046%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>14th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  nilfs2: prevent use of deleted inode  syzbot reported a WARNING in nilfs_rmdir. [1]  Because the inode bitmap is corrupted, an inode with an inode number that should exist as a ".nilfs" file was reassigned by nilfs_mkdir for "file0", causing an inode duplication during execution.  And this causes an underflow of i_nlink in rmdir operations.  The inode is used twice by the same task to unmount and remove directories ".nilfs" and "file0", it trigger warning in nilfs_rmdir.  Avoid to this issue, check i_nlink in nilfs_iget(), if it is 0, it means that this inode has been deleted, and iput is executed to reclaim it.  [1] WARNING: CPU: 1 PID: 5824 at fs/inode.c:407 drop_nlink+0xc4/0x110 fs/inode.c:407 ... Call Trace: <TASK> nilfs_rmdir+0x1b0/0x250 fs/nilfs2/namei.c:342 vfs_rmdir+0x3a3/0x510 fs/namei.c:4394 do_rmdir+0x3b5/0x580 fs/namei.c:4453 __do_sys_rmdir fs/namei.c:4472 [inline] __se_sys_rmdir fs/namei.c:4470 [inline] __x64_sys_rmdir+0x47/0x50 fs/namei.c:4470 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53687?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--53687" src="https://img.shields.io/badge/CVE--2024--53687-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  riscv: Fix IPIs usage in kfence_protect_page()  flush_tlb_kernel_range() may use IPIs to flush the TLBs of all the cores, which triggers the following warning when the irqs are disabled:  [    3.455330] WARNING: CPU: 1 PID: 0 at kernel/smp.c:815 smp_call_function_many_cond+0x452/0x520 [    3.456647] Modules linked in: [    3.457218] CPU: 1 UID: 0 PID: 0 Comm: swapper/1 Not tainted 6.12.0-rc7-00010-g91d3de7240b8 #1 [    3.457416] Hardware name: QEMU QEMU Virtual Machine, BIOS [    3.457633] epc : smp_call_function_many_cond+0x452/0x520 [    3.457736]  ra : on_each_cpu_cond_mask+0x1e/0x30 [    3.457786] epc : ffffffff800b669a ra : ffffffff800b67c2 sp : ff2000000000bb50 [    3.457824]  gp : ffffffff815212b8 tp : ff6000008014f080 t0 : 000000000000003f [    3.457859]  t1 : ffffffff815221e0 t2 : 000000000000000f s0 : ff2000000000bc10 [    3.457920]  s1 : 0000000000000040 a0 : ffffffff815221e0 a1 : 0000000000000001 [    3.457953]  a2 : 0000000000010000 a3 : 0000000000000003 a4 : 0000000000000000 [    3.458006]  a5 : 0000000000000000 a6 : ffffffffffffffff a7 : 0000000000000000 [    3.458042]  s2 : ffffffff815223be s3 : 00fffffffffff000 s4 : ff600001ffe38fc0 [    3.458076]  s5 : ff600001ff950d00 s6 : 0000000200000120 s7 : 0000000000000001 [    3.458109]  s8 : 0000000000000001 s9 : ff60000080841ef0 s10: 0000000000000001 [    3.458141]  s11: ffffffff81524812 t3 : 0000000000000001 t4 : ff60000080092bc0 [    3.458172]  t5 : 0000000000000000 t6 : ff200000000236d0 [    3.458203] status: 0000000200000100 badaddr: ffffffff800b669a cause: 0000000000000003 [    3.458373] [<ffffffff800b669a>] smp_call_function_many_cond+0x452/0x520 [    3.458593] [<ffffffff800b67c2>] on_each_cpu_cond_mask+0x1e/0x30 [    3.458625] [<ffffffff8000e4ca>] __flush_tlb_range+0x118/0x1ca [    3.458656] [<ffffffff8000e6b2>] flush_tlb_kernel_range+0x1e/0x26 [    3.458683] [<ffffffff801ea56a>] kfence_protect+0xc0/0xce [    3.458717] [<ffffffff801e9456>] kfence_guarded_free+0xc6/0x1c0 [    3.458742] [<ffffffff801e9d6c>] __kfence_free+0x62/0xc6 [    3.458764] [<ffffffff801c57d8>] kfree+0x106/0x32c [    3.458786] [<ffffffff80588cf2>] detach_buf_split+0x188/0x1a8 [    3.458816] [<ffffffff8058708c>] virtqueue_get_buf_ctx+0xb6/0x1f6 [    3.458839] [<ffffffff805871da>] virtqueue_get_buf+0xe/0x16 [    3.458880] [<ffffffff80613d6a>] virtblk_done+0x5c/0xe2 [    3.458908] [<ffffffff8058766e>] vring_interrupt+0x6a/0x74 [    3.458930] [<ffffffff800747d8>] __handle_irq_event_percpu+0x7c/0xe2 [    3.458956] [<ffffffff800748f0>] handle_irq_event+0x3c/0x86 [    3.458978] [<ffffffff800786cc>] handle_simple_irq+0x9e/0xbe [    3.459004] [<ffffffff80073934>] generic_handle_domain_irq+0x1c/0x2a [    3.459027] [<ffffffff804bf87c>] imsic_handle_irq+0xba/0x120 [    3.459056] [<ffffffff80073934>] generic_handle_domain_irq+0x1c/0x2a [    3.459080] [<ffffffff804bdb76>] riscv_intc_aia_irq+0x24/0x34 [    3.459103] [<ffffffff809d0452>] handle_riscv_irq+0x2e/0x4c [    3.459133] [<ffffffff809d923e>] call_on_irq_stack+0x32/0x40  So only flush the local TLB and let the lazy kfence page fault handling deal with the faults which could happen when a core has an old protected pte version cached in its TLB. That leads to potential inaccuracies which can be tolerated when using kfence.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53685?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--53685" src="https://img.shields.io/badge/CVE--2024--53685-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  ceph: give up on paths longer than PATH_MAX  If the full path to be built by ceph_mdsc_build_path() happens to be longer than PATH_MAX, then this function will enter an endless (retry) loop, effectively blocking the whole task.  Most of the machine becomes unusable, making this a very simple and effective DoS vulnerability.  I cannot imagine why this retry was ever implemented, but it seems rather useless and harmful to me.  Let's remove it and fail with ENAMETOOLONG instead.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53125?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--53125" src="https://img.shields.io/badge/CVE--2024--53125-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.091%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: sync_linked_regs() must preserve subreg_def  Range propagation must not affect subreg_def marks, otherwise the following example is rewritten by verifier incorrectly when BPF_F_TEST_RND_HI32 flag is set:  0: call bpf_ktime_get_ns                   call bpf_ktime_get_ns 1: r0 &= 0x7fffffff       after verifier   r0 &= 0x7fffffff 2: w1 = w0                rewrites         w1 = w0 3: if w0 < 10 goto +0     -------------->  r11 = 0x2f5674a6     (r) 4: r1 >>= 32                               r11 <<= 32           (r) 5: r0 = r1                                 r1 |= r11            (r) 6: exit;                                   if w0 < 0xa goto pc+0 r1 >>= 32 r0 = r1 exit  (or zero extension of w1 at (2) is missing for architectures that require zero extension for upper register half).  The following happens w/o this patch: - r0 is marked as not a subreg at (0); - w1 is marked as subreg at (2); - w1 subreg_def is overridden at (3) by copy_register_state(); - w1 is read at (5) but mark_insn_zext() does not mark (2) for zero extension, because w1 subreg_def is not set; - because of BPF_F_TEST_RND_HI32 flag verifier inserts random value for hi32 bits of (2) (marked (r)); - this random value is read at (5).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49571?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--49571" src="https://img.shields.io/badge/CVE--2024--49571-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.052%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>16th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/smc: check iparea_offset and ipv6_prefixes_cnt when receiving proposal msg  When receiving proposal msg in server, the field iparea_offset and the field ipv6_prefixes_cnt in proposal msg are from the remote client and can not be fully trusted. Especially the field iparea_offset, once exceed the max value, there has the chance to access wrong address, and crash may happen.  This patch checks iparea_offset and ipv6_prefixes_cnt before using them.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-49568?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--49568" src="https://img.shields.io/badge/CVE--2024--49568-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/smc: check v2_ext_offset/eid_cnt/ism_gid_cnt when receiving proposal msg  When receiving proposal msg in server, the fields v2_ext_offset/ eid_cnt/ism_gid_cnt in proposal msg are from the remote client and can not be fully trusted. Especially the field v2_ext_offset, once exceed the max value, there has the chance to access wrong address, and crash may happen.  This patch checks the fields v2_ext_offset/eid_cnt/ism_gid_cnt before using them.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-47408?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--47408" src="https://img.shields.io/badge/CVE--2024--47408-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.039%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/smc: check smcd_v2_ext_offset when receiving proposal msg  When receiving proposal msg in server, the field smcd_v2_ext_offset in proposal msg is from the remote client and can not be fully trusted. Once the value of smcd_v2_ext_offset exceed the max value, there has the chance to access wrong address, and crash may happen.  This patch checks the value of smcd_v2_ext_offset before using it.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-41013?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--41013" src="https://img.shields.io/badge/CVE--2024--41013-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.093%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>27th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  xfs: don't walk off the end of a directory data block  This adds sanity checks for xfs_dir2_data_unused and xfs_dir2_data_entry to make sure don't stray beyond valid memory region. Before patching, the loop simply checks that the start offset of the dup and dep is within the range. So in a crafted image, if last entry is xfs_dir2_data_unused, we can change dup->length to dup->length-1 and leave 1 byte of space. In the next traversal, this space will be considered as dup or dep. We may encounter an out of bound read when accessing the fixed members.  In the patch, we make sure that the remaining bytes large enough to hold an unused entry before accessing xfs_dir2_data_unused and xfs_dir2_data_unused is XFS_DIR2_DATA_ALIGN byte aligned. We also make sure that the remaining bytes large enough to hold a dirent with a single-byte name before accessing xfs_dir2_data_entry.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-39282?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="medium : CVE--2024--39282" src="https://img.shields.io/badge/CVE--2024--39282-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.033%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>8th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: wwan: t7xx: Fix FSM command timeout issue  When driver processes the internal state change command, it use an asynchronous thread to process the command operation. If the main thread detects that the task has timed out, the asynchronous thread will panic when executing the completion notification because the main thread completion object has been released.  BUG: unable to handle page fault for address: fffffffffffffff8 PGD 1f283a067 P4D 1f283a067 PUD 1f283c067 PMD 0 Oops: 0000 [#1] PREEMPT SMP NOPTI RIP: 0010:complete_all+0x3e/0xa0 [...] Call Trace: <TASK> ? __die_body+0x68/0xb0 ? page_fault_oops+0x379/0x3e0 ? exc_page_fault+0x69/0xa0 ? asm_exc_page_fault+0x22/0x30 ? complete_all+0x3e/0xa0 fsm_main_thread+0xa3/0x9c0 [mtk_t7xx (HASH:1400 5)] ? __pfx_autoremove_wake_function+0x10/0x10 kthread+0xd8/0x110 ? __pfx_fsm_main_thread+0x10/0x10 [mtk_t7xx (HASH:1400 5)] ? __pfx_kthread+0x10/0x10 ret_from_fork+0x38/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1b/0x30 </TASK> [...] CR2: fffffffffffffff8 ---[ end trace 0000000000000000 ]---  Use the reference counter to ensure safe release as Sergey suggests: https://lore.kernel.org/all/da90f64c-260a-4329-87bf-1f9ff20a5951@gmail.com/

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21645?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="low : CVE--2025--21645" src="https://img.shields.io/badge/CVE--2025--21645-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.042%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  platform/x86/amd/pmc: Only disable IRQ1 wakeup where i8042 actually enabled it  Wakeup for IRQ1 should be disabled only in cases where i8042 had actually enabled it, otherwise "wake_depth" for this IRQ will try to drop below zero and there will be an unpleasant WARN() logged:  kernel: atkbd serio0: Disabling IRQ1 wakeup source to avoid platform firmware bug kernel: ------------[ cut here ]------------ kernel: Unbalanced IRQ 1 wake disable kernel: WARNING: CPU: 10 PID: 6431 at kernel/irq/manage.c:920 irq_set_irq_wake+0x147/0x1a0  The PMC driver uses DEFINE_SIMPLE_DEV_PM_OPS() to define its dev_pm_ops which sets amd_pmc_suspend_handler() to the .suspend, .freeze, and .poweroff handlers. i8042_pm_suspend(), however, is only set as the .suspend handler.  Fix the issue by call PMC suspend handler only from the same set of dev_pm_ops handlers as i8042_pm_suspend(), which currently means just the .suspend handler.  To reproduce this issue try hibernating (S4) the machine after a fresh boot without putting it into s2idle first.  [ij: edited the commit message.]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-58237?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-60.63"><img alt="low : CVE--2024--58237" src="https://img.shields.io/badge/CVE--2024--58237-lightgrey?label=low%20&labelColor=fce1a9"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-60.63</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-60.63</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.024%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>5th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: consider that tail calls invalidate packet pointers  Tail-called programs could execute any of the helpers that invalidate packet pointers. Hence, conservatively assume that each tail call invalidates packet pointers.  Making the change in bpf_helper_changes_pkt_data() automatically makes use of check_cfg() logic that computes 'changes_pkt_data' effect for global sub-programs, such that the following program could be rejected:  int tail_call(struct __sk_buff *sk) { bpf_tail_call_static(sk, &jmp_table, 0); return 0; }  SEC("tc") int not_safe(struct __sk_buff *sk) { int *p = (void *)(long)sk->data; ... make p valid ... tail_call(sk); *p = 42; /* this is unsafe */ ... }  The tc_bpf2bpf.c:subprog_tc() needs change: mark it as a function that can invalidate packet pointers. Otherwise, it can't be freplaced with tailcall_freplace.c:entry_freplace() that does a tail call.

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
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 1" src="https://img.shields.io/badge/M-1-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>krb5</strong> <code>1.20.1-6ubuntu2.5</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/krb5@1.20.1-6ubuntu2.5?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-3576?s=ubuntu&n=krb5&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C1.20.1-6ubuntu2.6"><img alt="medium : CVE--2025--3576" src="https://img.shields.io/badge/CVE--2025--3576-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><1.20.1-6ubuntu2.6</code></td></tr>
<tr><td>Fixed version</td><td><code>1.20.1-6ubuntu2.6</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.012%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A vulnerability in the MIT Kerberos implementation allows GSSAPI-protected messages using RC4-HMAC-MD5 to be spoofed due to weaknesses in the MD5 checksum design. If RC4 is preferred over stronger encryption types, an attacker could exploit MD5 collisions to forge message integrity codes. This may lead to unauthorized message tampering.

</blockquote>
</details>
</details></td></tr>
</table>