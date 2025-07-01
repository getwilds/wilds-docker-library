# Vulnerability Report for getwilds/bedtools:latest

Report generated on 2025-07-01 09:40:35 PST

<h2>:mag: Vulnerabilities of <code>getwilds/bedtools:latest</code></h2>

<details open="true"><summary>:package: Image Reference</strong> <code>getwilds/bedtools:latest</code></summary>
<table>
<tr><td>digest</td><td><code>sha256:24516c43b5f8bd9aef5d4d882df277ea1969d8f1c4b243b5c624bd8e26e10123</code></td><tr><tr><td>vulnerabilities</td><td><img alt="critical: 0" src="https://img.shields.io/badge/critical-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/high-0-lightgrey"/> <img alt="medium: 35" src="https://img.shields.io/badge/medium-35-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/low-0-lightgrey"/> <!-- unspecified: 0 --></td></tr>
<tr><td>platform</td><td>linux/amd64</td></tr>
<tr><td>size</td><td>195 MB</td></tr>
<tr><td>packages</td><td>230</td></tr>
</table>
</details></table>
</details>

<table>
<tr><td valign="top">
<details><summary><img alt="critical: 0" src="https://img.shields.io/badge/C-0-lightgrey"/> <img alt="high: 0" src="https://img.shields.io/badge/H-0-lightgrey"/> <img alt="medium: 33" src="https://img.shields.io/badge/M-33-fbb552"/> <img alt="low: 0" src="https://img.shields.io/badge/L-0-lightgrey"/> <!-- unspecified: 0 --><strong>linux</strong> <code>6.8.0-60.63</code> (deb)</summary>

<small><code>pkg:deb/ubuntu/linux@6.8.0-60.63?os_distro=noble&os_name=ubuntu&os_version=24.04</code></small><br/>
<a href="https://scout.docker.com/v/CVE-2025-21692?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 7.8: CVE--2025--21692" src="https://img.shields.io/badge/CVE--2025--21692-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.030%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: sched: fix ets qdisc OOB Indexing  Haowei Yan <g1042620637@gmail.com> found that ets_class_from_arg() can index an Out-Of-Bound class in ets_class_from_arg() when passed clid of 0. The overflow may cause local privilege escalation.  [   18.852298] ------------[ cut here ]------------ [   18.853271] UBSAN: array-index-out-of-bounds in net/sched/sch_ets.c:93:20 [   18.853743] index 18446744073709551615 is out of range for type 'ets_class [16]' [   18.854254] CPU: 0 UID: 0 PID: 1275 Comm: poc Not tainted 6.12.6-dirty #17 [   18.854821] Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 [   18.856532] Call Trace: [   18.857441]  <TASK> [   18.858227]  dump_stack_lvl+0xc2/0xf0 [   18.859607]  dump_stack+0x10/0x20 [   18.860908]  __ubsan_handle_out_of_bounds+0xa7/0xf0 [   18.864022]  ets_class_change+0x3d6/0x3f0 [   18.864322]  tc_ctl_tclass+0x251/0x910 [   18.864587]  ? lock_acquire+0x5e/0x140 [   18.865113]  ? __mutex_lock+0x9c/0xe70 [   18.866009]  ? __mutex_lock+0xa34/0xe70 [   18.866401]  rtnetlink_rcv_msg+0x170/0x6f0 [   18.866806]  ? __lock_acquire+0x578/0xc10 [   18.867184]  ? __pfx_rtnetlink_rcv_msg+0x10/0x10 [   18.867503]  netlink_rcv_skb+0x59/0x110 [   18.867776]  rtnetlink_rcv+0x15/0x30 [   18.868159]  netlink_unicast+0x1c3/0x2b0 [   18.868440]  netlink_sendmsg+0x239/0x4b0 [   18.868721]  ____sys_sendmsg+0x3e2/0x410 [   18.869012]  ___sys_sendmsg+0x88/0xe0 [   18.869276]  ? rseq_ip_fixup+0x198/0x260 [   18.869563]  ? rseq_update_cpu_node_id+0x10a/0x190 [   18.869900]  ? trace_hardirqs_off+0x5a/0xd0 [   18.870196]  ? syscall_exit_to_user_mode+0xcc/0x220 [   18.870547]  ? do_syscall_64+0x93/0x150 [   18.870821]  ? __memcg_slab_free_hook+0x69/0x290 [   18.871157]  __sys_sendmsg+0x69/0xd0 [   18.871416]  __x64_sys_sendmsg+0x1d/0x30 [   18.871699]  x64_sys_call+0x9e2/0x2670 [   18.871979]  do_syscall_64+0x87/0x150 [   18.873280]  ? do_syscall_64+0x93/0x150 [   18.874742]  ? lock_release+0x7b/0x160 [   18.876157]  ? do_user_addr_fault+0x5ce/0x8f0 [   18.877833]  ? irqentry_exit_to_user_mode+0xc2/0x210 [   18.879608]  ? irqentry_exit+0x77/0xb0 [   18.879808]  ? clear_bhb_loop+0x15/0x70 [   18.880023]  ? clear_bhb_loop+0x15/0x70 [   18.880223]  ? clear_bhb_loop+0x15/0x70 [   18.880426]  entry_SYSCALL_64_after_hwframe+0x76/0x7e [   18.880683] RIP: 0033:0x44a957 [   18.880851] Code: ff ff e8 fc 00 00 00 66 2e 0f 1f 84 00 00 00 00 00 66 90 f3 0f 1e fa 64 8b 04 25 18 00 00 00 85 c0 75 10 b8 2e 00 00 00 0f 05 <48> 3d 00 f0 ff ff 77 51 c3 48 83 ec 28 89 54 24 1c 48 8974 24 10 [   18.881766] RSP: 002b:00007ffcdd00fad8 EFLAGS: 00000246 ORIG_RAX: 000000000000002e [   18.882149] RAX: ffffffffffffffda RBX: 00007ffcdd010db8 RCX: 000000000044a957 [   18.882507] RDX: 0000000000000000 RSI: 00007ffcdd00fb70 RDI: 0000000000000003 [   18.885037] RBP: 00007ffcdd010bc0 R08: 000000000703c770 R09: 000000000703c7c0 [   18.887203] R10: 0000000000000080 R11: 0000000000000246 R12: 0000000000000001 [   18.888026] R13: 00007ffcdd010da8 R14: 00000000004ca7d0 R15: 0000000000000001 [   18.888395]  </TASK> [   18.888610] ---[ end trace ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21680?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 7.8: CVE--2025--21680" src="https://img.shields.io/badge/CVE--2025--21680-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
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

<a href="https://scout.docker.com/v/CVE-2024-57951?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 7.8: CVE--2024--57951" src="https://img.shields.io/badge/CVE--2024--57951-lightgrey?label=medium%207.8&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>7.8</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  hrtimers: Handle CPU state correctly on hotplug  Consider a scenario where a CPU transitions from CPUHP_ONLINE to halfway through a CPU hotunplug down to CPUHP_HRTIMERS_PREPARE, and then back to CPUHP_ONLINE:  Since hrtimers_prepare_cpu() does not run, cpu_base.hres_active remains set to 1 throughout. However, during a CPU unplug operation, the tick and the clockevents are shut down at CPUHP_AP_TICK_DYING. On return to the online state, for instance CFS incorrectly assumes that the hrtick is already active, and the chance of the clockevent device to transition to oneshot mode is also lost forever for the CPU, unless it goes back to a lower state than CPUHP_HRTIMERS_PREPARE once.  This round-trip reveals another issue; cpu_base.online is not set to 1 after the transition, which appears as a WARN_ON_ONCE in enqueue_hrtimer().  Aside of that, the bulk of the per CPU state is not reset either, which means there are dangling pointers in the worst case.  Address this by adding a corresponding startup() callback, which resets the stale per CPU state and sets the online flag.  [ tglx: Make the new callback unconditionally available, remove the online modification in the prepare() callback and clear the remaining state in the starting callback instead of the prepare callback ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21699?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21699" src="https://img.shields.io/badge/CVE--2025--21699-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gfs2: Truncate address space when flipping GFS2_DIF_JDATA flag  Truncate an inode's address space when flipping the GFS2_DIF_JDATA flag: depending on that flag, the pages in the address space will either use buffer heads or iomap_folio_state structs, and we cannot mix the two.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21697?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21697" src="https://img.shields.io/badge/CVE--2025--21697-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  drm/v3d: Ensure job pointer is set to NULL after job completion  After a job completes, the corresponding pointer in the device must be set to NULL. Failing to do so triggers a warning when unloading the driver, as it appears the job is still active. To prevent this, assign the job pointer to NULL after completing the job, indicating the job has finished.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21694?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21694" src="https://img.shields.io/badge/CVE--2025--21694-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs/proc: fix softlockup in __read_vmcore (part 2)  Since commit 5cbcb62dddf5 ("fs/proc: fix softlockup in __read_vmcore") the number of softlockups in __read_vmcore at kdump time have gone down, but they still happen sometimes.  In a memory constrained environment like the kdump image, a softlockup is not just a harmless message, but it can interfere with things like RCU freeing memory, causing the crashdump to get stuck.  The second loop in __read_vmcore has a lot more opportunities for natural sleep points, like scheduling out while waiting for a data write to happen, but apparently that is not always enough.  Add a cond_resched() to the second loop in __read_vmcore to (hopefully) get rid of the softlockups.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21690?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21690" src="https://img.shields.io/badge/CVE--2025--21690-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.071%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>22nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  scsi: storvsc: Ratelimit warning logs to prevent VM denial of service  If there's a persistent error in the hypervisor, the SCSI warning for failed I/O can flood the kernel log and max out CPU utilization, preventing troubleshooting from the VM side. Ratelimit the warning so it doesn't DoS the VM.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21689?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21689" src="https://img.shields.io/badge/CVE--2025--21689-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.029%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  USB: serial: quatech2: fix null-ptr-deref in qt2_process_read_urb()  This patch addresses a null-ptr-deref in qt2_process_read_urb() due to an incorrect bounds check in the following:  if (newport > serial->num_ports) { dev_err(&port->dev, "%s - port change to invalid port: %i\n", __func__, newport); break; }  The condition doesn't account for the valid range of the serial->port buffer, which is from 0 to serial->num_ports - 1. When newport is equal to serial->num_ports, the assignment of "port" in the following code is out-of-bounds and NULL:  serial_priv->current_port = newport; port = serial->port[serial_priv->current_port];  The fix checks if newport is greater than or equal to serial->num_ports indicating it is out-of-bounds.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21684?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21684" src="https://img.shields.io/badge/CVE--2025--21684-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.009%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>1st percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gpio: xilinx: Convert gpio_lock to raw spinlock  irq_chip functions may be called in raw spinlock context. Therefore, we must also use a raw spinlock for our own internal locking.  This fixes the following lockdep splat:  [    5.349336] ============================= [    5.353349] [ BUG: Invalid wait context ] [    5.357361] 6.13.0-rc5+ #69 Tainted: G        W [    5.363031] ----------------------------- [    5.367045] kworker/u17:1/44 is trying to lock: [    5.371587] ffffff88018b02c0 (&chip->gpio_lock){....}-{3:3}, at: xgpio_irq_unmask (drivers/gpio/gpio-xilinx.c:433 (discriminator 8)) [    5.380079] other info that might help us debug this: [    5.385138] context-{5:5} [    5.387762] 5 locks held by kworker/u17:1/44: [    5.392123] #0: ffffff8800014958 ((wq_completion)events_unbound){+.+.}-{0:0}, at: process_one_work (kernel/workqueue.c:3204) [    5.402260] #1: ffffffc082fcbdd8 (deferred_probe_work){+.+.}-{0:0}, at: process_one_work (kernel/workqueue.c:3205) [    5.411528] #2: ffffff880172c900 (&dev->mutex){....}-{4:4}, at: __device_attach (drivers/base/dd.c:1006) [    5.419929] #3: ffffff88039c8268 (request_class#2){+.+.}-{4:4}, at: __setup_irq (kernel/irq/internals.h:156 kernel/irq/manage.c:1596) [    5.428331] #4: ffffff88039c80c8 (lock_class#2){....}-{2:2}, at: __setup_irq (kernel/irq/manage.c:1614) [    5.436472] stack backtrace: [    5.439359] CPU: 2 UID: 0 PID: 44 Comm: kworker/u17:1 Tainted: G W          6.13.0-rc5+ #69 [    5.448690] Tainted: [W]=WARN [    5.451656] Hardware name: xlnx,zynqmp (DT) [    5.455845] Workqueue: events_unbound deferred_probe_work_func [    5.461699] Call trace: [    5.464147] show_stack+0x18/0x24 C [    5.467821] dump_stack_lvl (lib/dump_stack.c:123) [    5.471501] dump_stack (lib/dump_stack.c:130) [    5.474824] __lock_acquire (kernel/locking/lockdep.c:4828 kernel/locking/lockdep.c:4898 kernel/locking/lockdep.c:5176) [    5.478758] lock_acquire (arch/arm64/include/asm/percpu.h:40 kernel/locking/lockdep.c:467 kernel/locking/lockdep.c:5851 kernel/locking/lockdep.c:5814) [    5.482429] _raw_spin_lock_irqsave (include/linux/spinlock_api_smp.h:111 kernel/locking/spinlock.c:162) [    5.486797] xgpio_irq_unmask (drivers/gpio/gpio-xilinx.c:433 (discriminator 8)) [    5.490737] irq_enable (kernel/irq/internals.h:236 kernel/irq/chip.c:170 kernel/irq/chip.c:439 kernel/irq/chip.c:432 kernel/irq/chip.c:345) [    5.494060] __irq_startup (kernel/irq/internals.h:241 kernel/irq/chip.c:180 kernel/irq/chip.c:250) [    5.497645] irq_startup (kernel/irq/chip.c:270) [    5.501143] __setup_irq (kernel/irq/manage.c:1807) [    5.504728] request_threaded_irq (kernel/irq/manage.c:2208)

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21683?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21683" src="https://img.shields.io/badge/CVE--2025--21683-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  bpf: Fix bpf_sk_select_reuseport() memory leak  As pointed out in the original comment, lookup in sockmap can return a TCP ESTABLISHED socket. Such TCP socket may have had SO_ATTACH_REUSEPORT_EBPF set before it was ESTABLISHED. In other words, a non-NULL sk_reuseport_cb does not imply a non-refcounted socket.  Drop sk's reference in both error paths.  unreferenced object 0xffff888101911800 (size 2048): comm "test_progs", pid 44109, jiffies 4297131437 hex dump (first 32 bytes): 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ 80 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00  ................ backtrace (crc 9336483b): __kmalloc_noprof+0x3bf/0x560 __reuseport_alloc+0x1d/0x40 reuseport_alloc+0xca/0x150 reuseport_attach_prog+0x87/0x140 sk_reuseport_attach_bpf+0xc8/0x100 sk_setsockopt+0x1181/0x1990 do_sock_setsockopt+0x12b/0x160 __sys_setsockopt+0x7b/0xc0 __x64_sys_setsockopt+0x1b/0x30 do_syscall_64+0x93/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21682?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21682" src="https://img.shields.io/badge/CVE--2025--21682-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  eth: bnxt: always recalculate features after XDP clearing, fix null-deref  Recalculate features when XDP is detached.  Before: # ip li set dev eth0 xdp obj xdp_dummy.bpf.o sec xdp # ip li set dev eth0 xdp off # ethtool -k eth0 | grep gro rx-gro-hw: off [requested on]  After: # ip li set dev eth0 xdp obj xdp_dummy.bpf.o sec xdp # ip li set dev eth0 xdp off # ethtool -k eth0 | grep gro rx-gro-hw: on  The fact that HW-GRO doesn't get re-enabled automatically is just a minor annoyance. The real issue is that the features will randomly come back during another reconfiguration which just happens to invoke netdev_update_features(). The driver doesn't handle reconfiguring two things at a time very robustly.  Starting with commit 98ba1d931f61 ("bnxt_en: Fix RSS logic in __bnxt_reserve_rings()") we only reconfigure the RSS hash table if the "effective" number of Rx rings has changed. If HW-GRO is enabled "effective" number of rings is 2x what user sees. So if we are in the bad state, with HW-GRO re-enablement "pending" after XDP off, and we lower the rings by / 2 - the HW-GRO rings doing 2x and the ethtool -L doing / 2 may cancel each other out, and the:  if (old_rx_rings != bp->hw_resc.resv_rx_rings &&  condition in __bnxt_reserve_rings() will be false. The RSS map won't get updated, and we'll crash with:  BUG: kernel NULL pointer dereference, address: 0000000000000168 RIP: 0010:__bnxt_hwrm_vnic_set_rss+0x13a/0x1a0 bnxt_hwrm_vnic_rss_cfg_p5+0x47/0x180 __bnxt_setup_vnic_p5+0x58/0x110 bnxt_init_nic+0xb72/0xf50 __bnxt_open_nic+0x40d/0xab0 bnxt_open_nic+0x2b/0x60 ethtool_set_channels+0x18c/0x1d0  As we try to access a freed ring.  The issue is present since XDP support was added, really, but prior to commit 98ba1d931f61 ("bnxt_en: Fix RSS logic in __bnxt_reserve_rings()") it wasn't causing major issues.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21681?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21681" src="https://img.shields.io/badge/CVE--2025--21681-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  openvswitch: fix lockup on tx to unregistering netdev with carrier  Commit in a fixes tag attempted to fix the issue in the following sequence of calls:  do_output -> ovs_vport_send -> dev_queue_xmit -> __dev_queue_xmit -> netdev_core_pick_tx -> skb_tx_hash  When device is unregistering, the 'dev->real_num_tx_queues' goes to zero and the 'while (unlikely(hash >= qcount))' loop inside the 'skb_tx_hash' becomes infinite, locking up the core forever.  But unfortunately, checking just the carrier status is not enough to fix the issue, because some devices may still be in unregistering state while reporting carrier status OK.  One example of such device is a net/dummy.  It sets carrier ON on start, but it doesn't implement .ndo_stop to set the carrier off. And it makes sense, because dummy doesn't really have a carrier. Therefore, while this device is unregistering, it's still easy to hit the infinite loop in the skb_tx_hash() from the OVS datapath.  There might be other drivers that do the same, but dummy by itself is important for the OVS ecosystem, because it is frequently used as a packet sink for tcpdump while debugging OVS deployments.  And when the issue is hit, the only way to recover is to reboot.  Fix that by also checking if the device is running.  The running state is handled by the net core during unregistering, so it covers unregistering case better, and we don't really need to send packets to devices that are not running anyway.  While only checking the running state might be enough, the carrier check is preserved.  The running and the carrier states seem disjoined throughout the code and different drivers.  And other core functions like __dev_direct_xmit() check both before attempting to transmit a packet.  So, it seems safer to check both flags in OVS as well.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21676?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21676" src="https://img.shields.io/badge/CVE--2025--21676-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fec: handle page_pool_dev_alloc_pages error  The fec_enet_update_cbd function calls page_pool_dev_alloc_pages but did not handle the case when it returned NULL. There was a WARN_ON(!new_page) but it would still proceed to use the NULL pointer and then crash.  This case does seem somewhat rare but when the system is under memory pressure it can happen. One case where I can duplicate this with some frequency is when writing over a smbd share to a SATA HDD attached to an imx6q.  Setting /proc/sys/vm/min_free_kbytes to higher values also seems to solve the problem for my test case. But it still seems wrong that the fec driver ignores the memory allocation error and can crash.  This commit handles the allocation error by dropping the current packet.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21675?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21675" src="https://img.shields.io/badge/CVE--2025--21675-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5: Clear port select structure when fail to create  Clear the port select structure on error so no stale values left after definers are destroyed. That's because the mlx5_lag_destroy_definers() always try to destroy all lag definers in the tt_map, so in the flow below lag definers get double-destroyed and cause kernel crash:  mlx5_lag_port_sel_create() mlx5_lag_create_definers() mlx5_lag_create_definer()     <- Failed on tt 1 mlx5_lag_destroy_definers() <- definers[tt=0] gets destroyed mlx5_lag_port_sel_create() mlx5_lag_create_definers() mlx5_lag_create_definer()     <- Failed on tt 0 mlx5_lag_destroy_definers() <- definers[tt=0] gets double-destroyed  Unable to handle kernel NULL pointer dereference at virtual address 0000000000000008 Mem abort info: ESR = 0x0000000096000005 EC = 0x25: DABT (current EL), IL = 32 bits SET = 0, FnV = 0 EA = 0, S1PTW = 0 FSC = 0x05: level 1 translation fault Data abort info: ISV = 0, ISS = 0x00000005, ISS2 = 0x00000000 CM = 0, WnR = 0, TnD = 0, TagAccess = 0 GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0 user pgtable: 64k pages, 48-bit VAs, pgdp=0000000112ce2e00 [0000000000000008] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000 Internal error: Oops: 0000000096000005 [#1] PREEMPT SMP Modules linked in: iptable_raw bonding ip_gre ip6_gre gre ip6_tunnel tunnel6 geneve ip6_udp_tunnel udp_tunnel ipip tunnel4 ip_tunnel rdma_ucm(OE) rdma_cm(OE) iw_cm(OE) ib_ipoib(OE) ib_cm(OE) ib_umad(OE) mlx5_ib(OE) ib_uverbs(OE) mlx5_fwctl(OE) fwctl(OE) mlx5_core(OE) mlxdevm(OE) ib_core(OE) mlxfw(OE) memtrack(OE) mlx_compat(OE) openvswitch nsh nf_conncount psample xt_conntrack xt_MASQUERADE nf_conntrack_netlink nfnetlink xfrm_user xfrm_algo xt_addrtype iptable_filter iptable_nat nf_nat nf_conntrack nf_defrag_ipv6 nf_defrag_ipv4 br_netfilter bridge stp llc netconsole overlay efi_pstore sch_fq_codel zram ip_tables crct10dif_ce qemu_fw_cfg fuse ipv6 crc_ccitt [last unloaded: mlx_compat(OE)] CPU: 3 UID: 0 PID: 217 Comm: kworker/u53:2 Tainted: G           OE 6.11.0+ #2 Tainted: [O]=OOT_MODULE, [E]=UNSIGNED_MODULE Hardware name: QEMU KVM Virtual Machine, BIOS 0.0.0 02/06/2015 Workqueue: mlx5_lag mlx5_do_bond_work [mlx5_core] pstate: 60400005 (nZCv daif +PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : mlx5_del_flow_rules+0x24/0x2c0 [mlx5_core] lr : mlx5_lag_destroy_definer+0x54/0x100 [mlx5_core] sp : ffff800085fafb00 x29: ffff800085fafb00 x28: ffff0000da0c8000 x27: 0000000000000000 x26: ffff0000da0c8000 x25: ffff0000da0c8000 x24: ffff0000da0c8000 x23: ffff0000c31f81a0 x22: 0400000000000000 x21: ffff0000da0c8000 x20: 0000000000000000 x19: 0000000000000001 x18: 0000000000000000 x17: 0000000000000000 x16: 0000000000000000 x15: 0000ffff8b0c9350 x14: 0000000000000000 x13: ffff800081390d18 x12: ffff800081dc3cc0 x11: 0000000000000001 x10: 0000000000000b10 x9 : ffff80007ab7304c x8 : ffff0000d00711f0 x7 : 0000000000000004 x6 : 0000000000000190 x5 : ffff00027edb3010 x4 : 0000000000000000 x3 : 0000000000000000 x2 : ffff0000d39b8000 x1 : ffff0000d39b8000 x0 : 0400000000000000 Call trace: mlx5_del_flow_rules+0x24/0x2c0 [mlx5_core] mlx5_lag_destroy_definer+0x54/0x100 [mlx5_core] mlx5_lag_destroy_definers+0xa0/0x108 [mlx5_core] mlx5_lag_port_sel_create+0x2d4/0x6f8 [mlx5_core] mlx5_activate_lag+0x60c/0x6f8 [mlx5_core] mlx5_do_bond_work+0x284/0x5c8 [mlx5_core] process_one_work+0x170/0x3e0 worker_thread+0x2d8/0x3e0 kthread+0x11c/0x128 ret_from_fork+0x10/0x20 Code: a9025bf5 aa0003f6 a90363f7 f90023f9 (f9400400) ---[ end trace 0000000000000000 ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21674?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21674" src="https://img.shields.io/badge/CVE--2025--21674-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.014%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net/mlx5e: Fix inversion dependency warning while enabling IPsec tunnel  Attempt to enable IPsec packet offload in tunnel mode in debug kernel generates the following kernel panic, which is happening due to two issues: 1. In SA add section, the should be _bh() variant when marking SA mode. 2. There is not needed flush_workqueue in SA delete routine. It is not needed as at this stage as it is removed from SADB and the running work will be canceled later in SA free.  ===================================================== WARNING: SOFTIRQ-safe -> SOFTIRQ-unsafe lock order detected 6.12.0+ #4 Not tainted ----------------------------------------------------- charon/1337 [HC0[0]:SC0[4]:HE1:SE0] is trying to acquire: ffff88810f365020 (&xa->xa_lock#24){+.+.}-{3:3}, at: mlx5e_xfrm_del_state+0xca/0x1e0 [mlx5_core]  and this task is already holding: ffff88813e0f0d48 (&x->lock){+.-.}-{3:3}, at: xfrm_state_delete+0x16/0x30 which would create a new lock dependency: (&x->lock){+.-.}-{3:3} -> (&xa->xa_lock#24){+.+.}-{3:3}  but this new dependency connects a SOFTIRQ-irq-safe lock: (&x->lock){+.-.}-{3:3}  ... which became SOFTIRQ-irq-safe at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_timer_handler+0x91/0xd70 __hrtimer_run_queues+0x1dd/0xa60 hrtimer_run_softirq+0x146/0x2e0 handle_softirqs+0x266/0x860 irq_exit_rcu+0x115/0x1a0 sysvec_apic_timer_interrupt+0x6e/0x90 asm_sysvec_apic_timer_interrupt+0x16/0x20 default_idle+0x13/0x20 default_idle_call+0x67/0xa0 do_idle+0x2da/0x320 cpu_startup_entry+0x50/0x60 start_secondary+0x213/0x2a0 common_startup_64+0x129/0x138  to a SOFTIRQ-irq-unsafe lock: (&xa->xa_lock#24){+.+.}-{3:3}  ... which became SOFTIRQ-irq-unsafe at: ... lock_acquire+0x1be/0x520 _raw_spin_lock+0x2c/0x40 xa_set_mark+0x70/0x110 mlx5e_xfrm_add_state+0xe48/0x2290 [mlx5_core] xfrm_dev_state_add+0x3bb/0xd70 xfrm_add_sa+0x2451/0x4a90 xfrm_user_rcv_msg+0x493/0x880 netlink_rcv_skb+0x12e/0x380 xfrm_netlink_rcv+0x6d/0x90 netlink_unicast+0x42f/0x740 netlink_sendmsg+0x745/0xbe0 __sock_sendmsg+0xc5/0x190 __sys_sendto+0x1fe/0x2c0 __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x6d/0x140 entry_SYSCALL_64_after_hwframe+0x4b/0x53  other info that might help us debug this:  Possible interrupt unsafe locking scenario:  CPU0                    CPU1 ----                    ---- lock(&xa->xa_lock#24); local_irq_disable(); lock(&x->lock); lock(&xa->xa_lock#24); <Interrupt> lock(&x->lock);  *** DEADLOCK ***  2 locks held by charon/1337: #0: ffffffff87f8f858 (&net->xfrm.xfrm_cfg_mutex){+.+.}-{4:4}, at: xfrm_netlink_rcv+0x5e/0x90 #1: ffff88813e0f0d48 (&x->lock){+.-.}-{3:3}, at: xfrm_state_delete+0x16/0x30  the dependencies between SOFTIRQ-irq-safe lock and the holding lock: -> (&x->lock){+.-.}-{3:3} ops: 29 { HARDIRQ-ON-W at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_alloc_spi+0xc0/0xe60 xfrm_alloc_userspi+0x5f6/0xbc0 xfrm_user_rcv_msg+0x493/0x880 netlink_rcv_skb+0x12e/0x380 xfrm_netlink_rcv+0x6d/0x90 netlink_unicast+0x42f/0x740 netlink_sendmsg+0x745/0xbe0 __sock_sendmsg+0xc5/0x190 __sys_sendto+0x1fe/0x2c0 __x64_sys_sendto+0xdc/0x1b0 do_syscall_64+0x6d/0x140 entry_SYSCALL_64_after_hwframe+0x4b/0x53 IN-SOFTIRQ-W at: lock_acquire+0x1be/0x520 _raw_spin_lock_bh+0x34/0x40 xfrm_timer_handler+0x91/0xd70 __hrtimer_run_queues+0x1dd/0xa60  ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21673?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21673" src="https://img.shields.io/badge/CVE--2025--21673-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  smb: client: fix double free of TCP_Server_Info::hostname  When shutting down the server in cifs_put_tcp_session(), cifsd thread might be reconnecting to multiple DFS targets before it realizes it should exit the loop, so @server->hostname can't be freed as long as cifsd thread isn't done.  Otherwise the following can happen:  RIP: 0010:__slab_free+0x223/0x3c0 Code: 5e 41 5f c3 cc cc cc cc 4c 89 de 4c 89 cf 44 89 44 24 08 4c 89 1c 24 e8 fb cf 8e 00 44 8b 44 24 08 4c 8b 1c 24 e9 5f fe ff ff <0f> 0b 41 f7 45 08 00 0d 21 00 0f 85 2d ff ff ff e9 1f ff ff ff 80 RSP: 0018:ffffb26180dbfd08 EFLAGS: 00010246 RAX: ffff8ea34728e510 RBX: ffff8ea34728e500 RCX: 0000000000800068 RDX: 0000000000800068 RSI: 0000000000000000 RDI: ffff8ea340042400 RBP: ffffe112041ca380 R08: 0000000000000001 R09: 0000000000000000 R10: 6170732e31303000 R11: 70726f632e786563 R12: ffff8ea34728e500 R13: ffff8ea340042400 R14: ffff8ea34728e500 R15: 0000000000800068 FS: 0000000000000000(0000) GS:ffff8ea66fd80000(0000) 000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffc25376080 CR3: 000000012a2ba001 CR4: PKRU: 55555554 Call Trace: <TASK> ? show_trace_log_lvl+0x1c4/0x2df ? show_trace_log_lvl+0x1c4/0x2df ? __reconnect_target_unlocked+0x3e/0x160 [cifs] ? __die_body.cold+0x8/0xd ? die+0x2b/0x50 ? do_trap+0xce/0x120 ? __slab_free+0x223/0x3c0 ? do_error_trap+0x65/0x80 ? __slab_free+0x223/0x3c0 ? exc_invalid_op+0x4e/0x70 ? __slab_free+0x223/0x3c0 ? asm_exc_invalid_op+0x16/0x20 ? __slab_free+0x223/0x3c0 ? extract_hostname+0x5c/0xa0 [cifs] ? extract_hostname+0x5c/0xa0 [cifs] ? __kmalloc+0x4b/0x140 __reconnect_target_unlocked+0x3e/0x160 [cifs] reconnect_dfs_server+0x145/0x430 [cifs] cifs_handle_standard+0x1ad/0x1d0 [cifs] cifs_demultiplex_thread+0x592/0x730 [cifs] ? __pfx_cifs_demultiplex_thread+0x10/0x10 [cifs] kthread+0xdd/0x100 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x29/0x50 </TASK>

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21672?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21672" src="https://img.shields.io/badge/CVE--2025--21672-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.016%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>2nd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  afs: Fix merge preference rule failure condition  syzbot reported a lock held when returning to userspace[1].  This is because if argc is less than 0 and the function returns directly, the held inode lock is not released.  Fix this by store the error in ret and jump to done to clean up instead of returning directly.  [dh: Modified Lizhi Xu's original patch to make it honour the error code from afs_split_string()]  [1] WARNING: lock held when returning to user space! 6.13.0-rc3-syzkaller-00209-g499551201b5f #0 Not tainted ------------------------------------------------ syz-executor133/5823 is leaving the kernel with locks still held! 1 lock held by syz-executor133/5823: #0: ffff888071cffc00 (&sb->s_type->i_mutex_key#9){++++}-{4:4}, at: inode_lock include/linux/fs.h:818 [inline] #0: ffff888071cffc00 (&sb->s_type->i_mutex_key#9){++++}-{4:4}, at: afs_proc_addr_prefs_write+0x2bb/0x14e0 fs/afs/addr_prefs.c:388

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21670?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21670" src="https://img.shields.io/badge/CVE--2025--21670-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock/bpf: return early if transport is not assigned  Some of the core functions can only be called if the transport has been assigned.  As Michal reported, a socket might have the transport at NULL, for example after a failed connect(), causing the following trace:  BUG: kernel NULL pointer dereference, address: 00000000000000a0 #PF: supervisor read access in kernel mode #PF: error_code(0x0000) - not-present page PGD 12faf8067 P4D 12faf8067 PUD 113670067 PMD 0 Oops: Oops: 0000 [#1] PREEMPT SMP NOPTI CPU: 15 UID: 0 PID: 1198 Comm: a.out Not tainted 6.13.0-rc2+ RIP: 0010:vsock_connectible_has_data+0x1f/0x40 Call Trace: vsock_bpf_recvmsg+0xca/0x5e0 sock_recvmsg+0xb9/0xc0 __sys_recvfrom+0xb3/0x130 __x64_sys_recvfrom+0x20/0x30 do_syscall_64+0x93/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e  So we need to check the `vsk->transport` in vsock_bpf_recvmsg(), especially for connected sockets (stream/seqpacket) as we already do in __vsock_connectible_recvmsg().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21669?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21669" src="https://img.shields.io/badge/CVE--2025--21669-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock/virtio: discard packets if the transport changes  If the socket has been de-assigned or assigned to another transport, we must discard any packets received because they are not expected and would cause issues when we access vsk->transport.  A possible scenario is described by Hyunwoo Kim in the attached link, where after a first connect() interrupted by a signal, and a second connect() failed, we can find `vsk->transport` at NULL, leading to a NULL pointer dereference.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21667?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21667" src="https://img.shields.io/badge/CVE--2025--21667-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.018%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  iomap: avoid avoid truncating 64-bit offset to 32 bits  on 32-bit kernels, iomap_write_delalloc_scan() was inadvertently using a 32-bit position due to folio_next_index() returning an unsigned long. This could lead to an infinite loop when writing to an xfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21666?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21666" src="https://img.shields.io/badge/CVE--2025--21666-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.027%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>6th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  vsock: prevent null-ptr-deref in vsock_*[has_data|has_space]  Recent reports have shown how we sometimes call vsock_*_has_data() when a vsock socket has been de-assigned from a transport (see attached links), but we shouldn't.  Previous commits should have solved the real problems, but we may have more in the future, so to avoid null-ptr-deref, we can return 0 (no space, no data available) but with a warning.  This way the code should continue to run in a nearly consistent state and have a warning that allows us to debug future problems.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21665?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2025--21665" src="https://img.shields.io/badge/CVE--2025--21665-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.022%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  filemap: avoid truncating 64-bit offset to 32 bits  On 32-bit kernels, folio_seek_hole_data() was inadvertently truncating a 64-bit value to 32 bits, leading to a possible infinite loop when writing to an xfs filesystem.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57952?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2024--57952" src="https://img.shields.io/badge/CVE--2024--57952-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.031%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  Revert "libfs: fix infinite directory reads for offset dir"  The current directory offset allocator (based on mtree_alloc_cyclic) stores the next offset value to return in octx->next_offset. This mechanism typically returns values that increase monotonically over time. Eventually, though, the newly allocated offset value wraps back to a low number (say, 2) which is smaller than other already- allocated offset values.  Yu Kuai <yukuai3@huawei.com> reports that, after commit 64a7ce76fb90 ("libfs: fix infinite directory reads for offset dir"), if a directory's offset allocator wraps, existing entries are no longer visible via readdir/getdents because offset_readdir() stops listing entries once an entry's offset is larger than octx->next_offset. These entries vanish persistently -- they can be looked up, but will never again appear in readdir(3) output.  The reason for this is that the commit treats directory offsets as monotonically increasing integer values rather than opaque cookies, and introduces this comparison:  if (dentry2offset(dentry) >= last_index) {  On 64-bit platforms, the directory offset value upper bound is 2^63 - 1. Directory offsets will monotonically increase for millions of years without wrapping.  On 32-bit platforms, however, LONG_MAX is 2^31 - 1. The allocator can wrap after only a few weeks (at worst).  Revert commit 64a7ce76fb90 ("libfs: fix infinite directory reads for offset dir") to prepare for a fix that can work properly on 32-bit systems and might apply to recent LTS kernels where shmem employs the simple_offset mechanism.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57949?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2024--57949" src="https://img.shields.io/badge/CVE--2024--57949-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.007%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>0th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  irqchip/gic-v3-its: Don't enable interrupts in its_irq_set_vcpu_affinity()  The following call-chain leads to enabling interrupts in a nested interrupt disabled section:  irq_set_vcpu_affinity() irq_get_desc_lock() raw_spin_lock_irqsave()   <--- Disable interrupts its_irq_set_vcpu_affinity() guard(raw_spinlock_irq)   <--- Enables interrupts when leaving the guard() irq_put_desc_unlock()        <--- Warns because interrupts are enabled  This was broken in commit b97e8a2f7130, which replaced the original raw_spin_[un]lock() pair with guard(raw_spinlock_irq).  Fix the issue by using guard(raw_spinlock).  [ tglx: Massaged change log ]

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-50157?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 5.5: CVE--2024--50157" src="https://img.shields.io/badge/CVE--2024--50157-lightgrey?label=medium%205.5&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>5.5</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.032%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>7th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  RDMA/bnxt_re: Avoid CPU lockups due fifo occupancy check loop  Driver waits indefinitely for the fifo occupancy to go below a threshold as soon as the pacing interrupt is received. This can cause soft lockup on one of the processors, if the rate of DB is very high.  Add a loop count for FPGA and exit the __wait_for_fifo_occupancy_below_th if the loop is taking more time. Pacing will be continuing until the occupancy is below the threshold. This is ensured by the checks in bnxt_re_pacing_timer_exp and further scheduling the work for pacing based on the fifo occupancy.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21943?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 4.7: CVE--2025--21943" src="https://img.shields.io/badge/CVE--2025--21943-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.020%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>4th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gpio: aggregator: protect driver attr handlers against module unload  Both new_device_store and delete_device_store touch module global resources (e.g. gpio_aggregator_lock). To prevent race conditions with module unload, a reference needs to be held.  Add try_module_get() in these handlers.  For new_device_store, this eliminates what appears to be the most dangerous scenario: if an id is allocated from gpio_aggregator_idr but platform_device_register has not yet been called or completed, a concurrent module unload could fail to unregister/delete the device, leaving behind a dangling platform device/GPIO forwarder. This can result in various issues. The following simple reproducer demonstrates these problems:  #!/bin/bash while :; do # note: whether 'gpiochip0 0' exists or not does not matter. echo 'gpiochip0 0' > /sys/bus/platform/drivers/gpio-aggregator/new_device done & while :; do modprobe gpio-aggregator modprobe -r gpio-aggregator done & wait  Starting with the following warning, several kinds of warnings will appear and the system may become unstable:  ------------[ cut here ]------------ list_del corruption, ffff888103e2e980->next is LIST_POISON1 (dead000000000100) WARNING: CPU: 1 PID: 1327 at lib/list_debug.c:56 __list_del_entry_valid_or_report+0xa3/0x120 [...] RIP: 0010:__list_del_entry_valid_or_report+0xa3/0x120 [...] Call Trace: <TASK> ? __list_del_entry_valid_or_report+0xa3/0x120 ? __warn.cold+0x93/0xf2 ? __list_del_entry_valid_or_report+0xa3/0x120 ? report_bug+0xe6/0x170 ? __irq_work_queue_local+0x39/0xe0 ? handle_bug+0x58/0x90 ? exc_invalid_op+0x13/0x60 ? asm_exc_invalid_op+0x16/0x20 ? __list_del_entry_valid_or_report+0xa3/0x120 gpiod_remove_lookup_table+0x22/0x60 new_device_store+0x315/0x350 [gpio_aggregator] kernfs_fop_write_iter+0x137/0x1f0 vfs_write+0x262/0x430 ksys_write+0x60/0xd0 do_syscall_64+0x6c/0x180 entry_SYSCALL_64_after_hwframe+0x76/0x7e [...] </TASK> ---[ end trace 0000000000000000 ]---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-53124?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium 4.7: CVE--2024--53124" src="https://img.shields.io/badge/CVE--2024--53124-lightgrey?label=medium%204.7&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>CVSS Score</td><td><code>4.7</code></td></tr>
<tr><td>CVSS Vector</td><td><code>CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.043%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>12th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  net: fix data-races around sk->sk_forward_alloc  Syzkaller reported this warning: ------------[ cut here ]------------ WARNING: CPU: 0 PID: 16 at net/ipv4/af_inet.c:156 inet_sock_destruct+0x1c5/0x1e0 Modules linked in: CPU: 0 UID: 0 PID: 16 Comm: ksoftirqd/0 Not tainted 6.12.0-rc5 #26 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.15.0-1 04/01/2014 RIP: 0010:inet_sock_destruct+0x1c5/0x1e0 Code: 24 12 4c 89 e2 5b 48 c7 c7 98 ec bb 82 41 5c e9 d1 18 17 ff 4c 89 e6 5b 48 c7 c7 d0 ec bb 82 41 5c e9 bf 18 17 ff 0f 0b eb 83 <0f> 0b eb 97 0f 0b eb 87 0f 0b e9 68 ff ff ff 66 66 2e 0f 1f 84 00 RSP: 0018:ffffc9000008bd90 EFLAGS: 00010206 RAX: 0000000000000300 RBX: ffff88810b172a90 RCX: 0000000000000007 RDX: 0000000000000002 RSI: 0000000000000300 RDI: ffff88810b172a00 RBP: ffff88810b172a00 R08: ffff888104273c00 R09: 0000000000100007 R10: 0000000000020000 R11: 0000000000000006 R12: ffff88810b172a00 R13: 0000000000000004 R14: 0000000000000000 R15: ffff888237c31f78 FS:  0000000000000000(0000) GS:ffff888237c00000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007ffc63fecac8 CR3: 000000000342e000 CR4: 00000000000006f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> ? __warn+0x88/0x130 ? inet_sock_destruct+0x1c5/0x1e0 ? report_bug+0x18e/0x1a0 ? handle_bug+0x53/0x90 ? exc_invalid_op+0x18/0x70 ? asm_exc_invalid_op+0x1a/0x20 ? inet_sock_destruct+0x1c5/0x1e0 __sk_destruct+0x2a/0x200 rcu_do_batch+0x1aa/0x530 ? rcu_do_batch+0x13b/0x530 rcu_core+0x159/0x2f0 handle_softirqs+0xd3/0x2b0 ? __pfx_smpboot_thread_fn+0x10/0x10 run_ksoftirqd+0x25/0x30 smpboot_thread_fn+0xdd/0x1d0 kthread+0xd3/0x100 ? __pfx_kthread+0x10/0x10 ret_from_fork+0x34/0x50 ? __pfx_kthread+0x10/0x10 ret_from_fork_asm+0x1a/0x30 </TASK> ---[ end trace 0000000000000000 ]---  Its possible that two threads call tcp_v6_do_rcv()/sk_forward_alloc_add() concurrently when sk->sk_state == TCP_LISTEN with sk->sk_lock unlocked, which triggers a data-race around sk->sk_forward_alloc: tcp_v6_rcv tcp_v6_do_rcv skb_clone_and_charge_r sk_rmem_schedule __sk_mem_schedule sk_forward_alloc_add() skb_set_owner_r sk_mem_charge sk_forward_alloc_add() __kfree_skb skb_release_all skb_release_head_state sock_rfree sk_mem_uncharge sk_forward_alloc_add() sk_mem_reclaim // set local var reclaimable __sk_mem_reclaim sk_forward_alloc_add()  In this syzkaller testcase, two threads call tcp_v6_do_rcv() with skb->truesize=768, the sk_forward_alloc changes like this: (cpu 1)             | (cpu 2)             | sk_forward_alloc ...                 | ...                 | 0 __sk_mem_schedule() |                     | +4096 = 4096 | __sk_mem_schedule() | +4096 = 8192 sk_mem_charge()     |                     | -768  = 7424 | sk_mem_charge()     | -768  = 6656 ...                 |    ...              | sk_mem_uncharge()   |                     | +768  = 7424 reclaimable=7424    |                     | | sk_mem_uncharge()   | +768  = 8192 | reclaimable=8192    | __sk_mem_reclaim()  |                     | -4096 = 4096 | __sk_mem_reclaim()  | -8192 = -4096 != 0  The skb_clone_and_charge_r() should not be called in tcp_v6_do_rcv() when sk->sk_state is TCP_LISTEN, it happens later in tcp_v6_syn_recv_sock(). Fix the same issue in dccp_v6_do_rcv().

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-2312?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2025--2312" src="https://img.shields.io/badge/CVE--2025--2312-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.019%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>3rd percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

A flaw was found in cifs-utils. When trying to obtain Kerberos credentials, the cifs.upcall program from the cifs-utils package makes an upcall to the wrong namespace in containerized environments. This issue may lead to disclosing sensitive data from the host's Kerberos credentials cache.

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21691?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2025--21691" src="https://img.shields.io/badge/CVE--2025--21691-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  cachestat: fix page cache statistics permission checking  When the 'cachestat()' system call was added in commit cf264e1329fb ("cachestat: implement cachestat syscall"), it was meant to be a much more convenient (and performant) version of mincore() that didn't need mapping things into the user virtual address space in order to work.  But it ended up missing the "check for writability or ownership" fix for mincore(), done in commit 134fca9063ad ("mm/mincore.c: make mincore() more conservative").  This just adds equivalent logic to 'cachestat()', modified for the file context (rather than vma).

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21678?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2025--21678" src="https://img.shields.io/badge/CVE--2025--21678-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  gtp: Destroy device along with udp socket's netns dismantle.  gtp_newlink() links the device to a list in dev_net(dev) instead of src_net, where a udp tunnel socket is created.  Even when src_net is removed, the device stays alive on dev_net(dev). Then, removing src_net triggers the splat below. [0]  In this example, gtp0 is created in ns2, and the udp socket is created in ns1.  ip netns add ns1 ip netns add ns2 ip -n ns1 link add netns ns2 name gtp0 type gtp role sgsn ip netns del ns1  Let's link the device to the socket's netns instead.  Now, gtp_net_exit_batch_rtnl() needs another netdev iteration to remove all gtp devices in the netns.  [0]: ref_tracker: net notrefcnt@000000003d6e7d05 has 1/2 users at sk_alloc (./include/net/net_namespace.h:345 net/core/sock.c:2236) inet_create (net/ipv4/af_inet.c:326 net/ipv4/af_inet.c:252) __sock_create (net/socket.c:1558) udp_sock_create4 (net/ipv4/udp_tunnel_core.c:18) gtp_create_sock (./include/net/udp_tunnel.h:59 drivers/net/gtp.c:1423) gtp_create_sockets (drivers/net/gtp.c:1447) gtp_newlink (drivers/net/gtp.c:1507) rtnl_newlink (net/core/rtnetlink.c:3786 net/core/rtnetlink.c:3897 net/core/rtnetlink.c:4012) rtnetlink_rcv_msg (net/core/rtnetlink.c:6922) netlink_rcv_skb (net/netlink/af_netlink.c:2542) netlink_unicast (net/netlink/af_netlink.c:1321 net/netlink/af_netlink.c:1347) netlink_sendmsg (net/netlink/af_netlink.c:1891) ____sys_sendmsg (net/socket.c:711 net/socket.c:726 net/socket.c:2583) ___sys_sendmsg (net/socket.c:2639) __sys_sendmsg (net/socket.c:2669) do_syscall_64 (arch/x86/entry/common.c:52 arch/x86/entry/common.c:83)  WARNING: CPU: 1 PID: 60 at lib/ref_tracker.c:179 ref_tracker_dir_exit (lib/ref_tracker.c:179) Modules linked in: CPU: 1 UID: 0 PID: 60 Comm: kworker/u16:2 Not tainted 6.13.0-rc5-00147-g4c1224501e9d #5 Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS rel-1.16.0-0-gd239552ce722-prebuilt.qemu.org 04/01/2014 Workqueue: netns cleanup_net RIP: 0010:ref_tracker_dir_exit (lib/ref_tracker.c:179) Code: 00 00 00 fc ff df 4d 8b 26 49 bd 00 01 00 00 00 00 ad de 4c 39 f5 0f 85 df 00 00 00 48 8b 74 24 08 48 89 df e8 a5 cc 12 02 90 <0f> 0b 90 48 8d 6b 44 be 04 00 00 00 48 89 ef e8 80 de 67 ff 48 89 RSP: 0018:ff11000009a07b60 EFLAGS: 00010286 RAX: 0000000000002bd3 RBX: ff1100000f4e1aa0 RCX: 1ffffffff0e40ac6 RDX: 0000000000000000 RSI: 0000000000000000 RDI: ffffffff8423ee3c RBP: ff1100000f4e1af0 R08: 0000000000000001 R09: fffffbfff0e395ae R10: 0000000000000001 R11: 0000000000036001 R12: ff1100000f4e1af0 R13: dead000000000100 R14: ff1100000f4e1af0 R15: dffffc0000000000 FS:  0000000000000000(0000) GS:ff1100006ce80000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 00007f9b2464bd98 CR3: 0000000005286005 CR4: 0000000000771ef0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe07f0 DR7: 0000000000000400 PKRU: 55555554 Call Trace: <TASK> ? __warn (kernel/panic.c:748) ? ref_tracker_dir_exit (lib/ref_tracker.c:179) ? report_bug (lib/bug.c:201 lib/bug.c:219) ? handle_bug (arch/x86/kernel/traps.c:285) ? exc_invalid_op (arch/x86/kernel/traps.c:309 (discriminator 1)) ? asm_exc_invalid_op (./arch/x86/include/asm/idtentry.h:621) ? _raw_spin_unlock_irqrestore (./arch/x86/include/asm/irqflags.h:42 ./arch/x86/include/asm/irqflags.h:97 ./arch/x86/include/asm/irqflags.h:155 ./include/linux/spinlock_api_smp.h:151 kernel/locking/spinlock.c:194) ? ref_tracker_dir_exit (lib/ref_tracker.c:179) ? __pfx_ref_tracker_dir_exit (lib/ref_tracker.c:158) ? kfree (mm/slub.c:4613 mm/slub.c:4761) net_free (net/core/net_namespace.c:476 net/core/net_namespace.c:467) cleanup_net (net/core/net_namespace.c:664 (discriminator 3)) process_one_work (kernel/workqueue.c:3229) worker_thread (kernel/workqueue.c:3304 kernel/workqueue.c:3391 ---truncated---

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2025-21668?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2025--21668" src="https://img.shields.io/badge/CVE--2025--21668-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.044%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>13th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  pmdomain: imx8mp-blk-ctrl: add missing loop break condition  Currently imx8mp_blk_ctrl_remove() will continue the for loop until an out-of-bounds exception occurs.  pstate: 60000005 (nZCv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--) pc : dev_pm_domain_detach+0x8/0x48 lr : imx8mp_blk_ctrl_shutdown+0x58/0x90 sp : ffffffc084f8bbf0 x29: ffffffc084f8bbf0 x28: ffffff80daf32ac0 x27: 0000000000000000 x26: ffffffc081658d78 x25: 0000000000000001 x24: ffffffc08201b028 x23: ffffff80d0db9490 x22: ffffffc082340a78 x21: 00000000000005b0 x20: ffffff80d19bc180 x19: 000000000000000a x18: ffffffffffffffff x17: ffffffc080a39e08 x16: ffffffc080a39c98 x15: 4f435f464f006c72 x14: 0000000000000004 x13: ffffff80d0172110 x12: 0000000000000000 x11: ffffff80d0537740 x10: ffffff80d05376c0 x9 : ffffffc0808ed2d8 x8 : ffffffc084f8bab0 x7 : 0000000000000000 x6 : 0000000000000000 x5 : ffffff80d19b9420 x4 : fffffffe03466e60 x3 : 0000000080800077 x2 : 0000000000000000 x1 : 0000000000000001 x0 : 0000000000000000 Call trace: dev_pm_domain_detach+0x8/0x48 platform_shutdown+0x2c/0x48 device_shutdown+0x158/0x268 kernel_restart_prepare+0x40/0x58 kernel_kexec+0x58/0xe8 __do_sys_reboot+0x198/0x258 __arm64_sys_reboot+0x2c/0x40 invoke_syscall+0x5c/0x138 el0_svc_common.constprop.0+0x48/0xf0 do_el0_svc+0x24/0x38 el0_svc+0x38/0xc8 el0t_64_sync_handler+0x120/0x130 el0t_64_sync+0x190/0x198 Code: 8128c2d0 ffffffc0 aa1e03e9 d503201f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57948?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2024--57948" src="https://img.shields.io/badge/CVE--2024--57948-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.076%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>24th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  mac802154: check local interfaces before deleting sdata list  syzkaller reported a corrupted list in ieee802154_if_remove. [1]  Remove an IEEE 802.15.4 network interface after unregister an IEEE 802.15.4 hardware device from the system.  CPU0					CPU1 ====					==== genl_family_rcv_msg_doit		ieee802154_unregister_hw ieee802154_del_iface			ieee802154_remove_interfaces rdev_del_virtual_intf_deprecated	list_del(&sdata->list) ieee802154_if_remove list_del_rcu  The net device has been unregistered, since the rcu grace period, unregistration must be run before ieee802154_if_remove.  To avoid this issue, add a check for local->interfaces before deleting sdata list.  [1] kernel BUG at lib/list_debug.c:58! Oops: invalid opcode: 0000 [#1] PREEMPT SMP KASAN PTI CPU: 0 UID: 0 PID: 6277 Comm: syz-executor157 Not tainted 6.12.0-rc6-syzkaller-00005-g557329bcecc2 #0 Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 09/13/2024 RIP: 0010:__list_del_entry_valid_or_report+0xf4/0x140 lib/list_debug.c:56 Code: e8 a1 7e 00 07 90 0f 0b 48 c7 c7 e0 37 60 8c 4c 89 fe e8 8f 7e 00 07 90 0f 0b 48 c7 c7 40 38 60 8c 4c 89 fe e8 7d 7e 00 07 90 <0f> 0b 48 c7 c7 a0 38 60 8c 4c 89 fe e8 6b 7e 00 07 90 0f 0b 48 c7 RSP: 0018:ffffc9000490f3d0 EFLAGS: 00010246 RAX: 000000000000004e RBX: dead000000000122 RCX: d211eee56bb28d00 RDX: 0000000000000000 RSI: 0000000080000000 RDI: 0000000000000000 RBP: ffff88805b278dd8 R08: ffffffff8174a12c R09: 1ffffffff2852f0d R10: dffffc0000000000 R11: fffffbfff2852f0e R12: dffffc0000000000 R13: dffffc0000000000 R14: dead000000000100 R15: ffff88805b278cc0 FS:  0000555572f94380(0000) GS:ffff8880b8600000(0000) knlGS:0000000000000000 CS:  0010 DS: 0000 ES: 0000 CR0: 0000000080050033 CR2: 000056262e4a3000 CR3: 0000000078496000 CR4: 00000000003526f0 DR0: 0000000000000000 DR1: 0000000000000000 DR2: 0000000000000000 DR3: 0000000000000000 DR6: 00000000fffe0ff0 DR7: 0000000000000400 Call Trace: <TASK> __list_del_entry_valid include/linux/list.h:124 [inline] __list_del_entry include/linux/list.h:215 [inline] list_del_rcu include/linux/rculist.h:157 [inline] ieee802154_if_remove+0x86/0x1e0 net/mac802154/iface.c:687 rdev_del_virtual_intf_deprecated net/ieee802154/rdev-ops.h:24 [inline] ieee802154_del_iface+0x2c0/0x5c0 net/ieee802154/nl-phy.c:323 genl_family_rcv_msg_doit net/netlink/genetlink.c:1115 [inline] genl_family_rcv_msg net/netlink/genetlink.c:1195 [inline] genl_rcv_msg+0xb14/0xec0 net/netlink/genetlink.c:1210 netlink_rcv_skb+0x1e3/0x430 net/netlink/af_netlink.c:2551 genl_rcv+0x28/0x40 net/netlink/genetlink.c:1219 netlink_unicast_kernel net/netlink/af_netlink.c:1331 [inline] netlink_unicast+0x7f6/0x990 net/netlink/af_netlink.c:1357 netlink_sendmsg+0x8e4/0xcb0 net/netlink/af_netlink.c:1901 sock_sendmsg_nosec net/socket.c:729 [inline] __sock_sendmsg+0x221/0x270 net/socket.c:744 ____sys_sendmsg+0x52a/0x7e0 net/socket.c:2607 ___sys_sendmsg net/socket.c:2661 [inline] __sys_sendmsg+0x292/0x380 net/socket.c:2690 do_syscall_x64 arch/x86/entry/common.c:52 [inline] do_syscall_64+0xf3/0x230 arch/x86/entry/common.c:83 entry_SYSCALL_64_after_hwframe+0x77/0x7f

</blockquote>
</details>

<a href="https://scout.docker.com/v/CVE-2024-57924?s=ubuntu&n=linux&ns=ubuntu&t=deb&osn=ubuntu&osv=24.04&vr=%3C6.8.0-62.65"><img alt="medium : CVE--2024--57924" src="https://img.shields.io/badge/CVE--2024--57924-lightgrey?label=medium%20&labelColor=fbb552"/></a> 

<table>
<tr><td>Affected range</td><td><code><6.8.0-62.65</code></td></tr>
<tr><td>Fixed version</td><td><code>6.8.0-62.65</code></td></tr>
<tr><td>EPSS Score</td><td><code>0.040%</code></td></tr>
<tr><td>EPSS Percentile</td><td><code>11th percentile</code></td></tr>
</table>

<details><summary>Description</summary>
<blockquote>

In the Linux kernel, the following vulnerability has been resolved:  fs: relax assertions on failure to encode file handles  Encoding file handles is usually performed by a filesystem >encode_fh() method that may fail for various reasons.  The legacy users of exportfs_encode_fh(), namely, nfsd and name_to_handle_at(2) syscall are ready to cope with the possibility of failure to encode a file handle.  There are a few other users of exportfs_encode_{fh,fid}() that currently have a WARN_ON() assertion when ->encode_fh() fails. Relax those assertions because they are wrong.  The second linked bug report states commit 16aac5ad1fa9 ("ovl: support encoding non-decodable file handles") in v6.6 as the regressing commit, but this is not accurate.  The aforementioned commit only increases the chances of the assertion and allows triggering the assertion with the reproducer using overlayfs, inotify and drop_caches.  Triggering this assertion was always possible with other filesystems and other reasons of ->encode_fh() failures and more particularly, it was also possible with the exact same reproducer using overlayfs that is mounted with options index=on,nfs_export=on also on kernels < v6.6. Therefore, I am not listing the aforementioned commit as a Fixes commit.  Backport hint: this patch will have a trivial conflict applying to v6.6.y, and other trivial conflicts applying to stable kernels < v6.6.

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
</table>