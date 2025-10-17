/*
 * sysctl.c: General linux system control interface
 *
 * Begun 24 March 1995, Stephen Tweedie
 * Added /proc support, Dec 1995
 * Added bdflush entry and intvec min/max checking, 2/23/96, Tom Dyas.
 * Added hooks for /proc/sys/net (minor, minor patch), 96/4/1, Mike Shaver.
 * Added kernel/java-{interpreter,appletviewer}, 96/5/10, Mike Shaver.
 * Dynamic registration fixes, Stephen Tweedie.
 * Added kswapd-interval, ctrl-alt-del, printk stuff, 1/8/97, Chris Horn.
 * Made sysctl support optional via CONFIG_SYSCTL, 1/10/97, Chris
 *  Horn.
 * Added proc_doulongvec_ms_jiffies_minmax, 09/08/99, Carlos H. Bauer.
 * Added proc_doulongvec_minmax, 09/08/99, Carlos H. Bauer.
 * Changed linked lists to use list.h instead of lists.h, 02/24/00, Bill
 *  Wendling.
 * The list_for_each() macro wasn't appropriate for the sysctl loop.
 *  Removed it and replaced it with older style, 03/23/00, Bill Wendling
 */

#include <linux/module.h>
#include <linux/aio.h>
#include <linux/mm.h>
#include <linux/swap.h>
#include <linux/slab.h>
#include <linux/sysctl.h>
#include <linux/bitmap.h>
#include <linux/signal.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <linux/security.h>
#include <linux/ctype.h>
#include <linux/kmemcheck.h>
#include <linux/kmemleak.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/net.h>
#include <linux/sysrq.h>
#include <linux/highuid.h>
#include <linux/writeback.h>
#include <linux/ratelimit.h>
#include <linux/compaction.h>
#include <linux/hugetlb.h>
#include <linux/initrd.h>
#include <linux/key.h>
#include <linux/times.h>
#include <linux/limits.h>
#include <linux/dcache.h>
#include <linux/dnotify.h>
#include <linux/syscalls.h>
#include <linux/vmstat.h>
#include <linux/nfs_fs.h>
#include <linux/acpi.h>
#include <linux/reboot.h>
#include <linux/ftrace.h>
#include <linux/perf_event.h>
#include <linux/kprobes.h>
#include <linux/pipe_fs_i.h>
#include <linux/oom.h>
#include <linux/kmod.h>
#include <linux/capability.h>
#include <linux/binfmts.h>
#include <linux/sched/sysctl.h>
#include <linux/kexec.h>
#include <linux/bpf.h>
#include <linux/mount.h>

#include <asm/uaccess.h>
#include <asm/processor.h>

#ifdef CONFIG_X86
#include <asm/nmi.h>
#include <asm/stacktrace.h>
#include <asm/io.h>
#endif
#ifdef CONFIG_SPARC
#include <asm/setup.h>
#endif
#ifdef CONFIG_BSD_PROCESS_ACCT
#include <linux/acct.h>
#endif
#ifdef CONFIG_RT_MUTEXES
#include <linux/rtmutex.h>
#endif
#if defined(CONFIG_PROVE_LOCKING) || defined(CONFIG_LOCK_STAT)
#include <linux/lockdep.h>
#endif
#ifdef CONFIG_CHR_DEV_SG
#include <scsi/sg.h>
#endif

#ifdef CONFIG_LOCKUP_DETECTOR
#include <linux/nmi.h>
#endif

#if defined(CONFIG_SYSCTL)

/* External variables not in a header file. */
extern int suid_dumpable;
#ifdef CONFIG_COREDUMP
extern int core_uses_pid;
extern char core_pattern[];
extern unsigned int core_pipe_limit;
#endif
extern int pid_max;
extern int pid_max_min, pid_max_max;
extern int percpu_pagelist_fraction;
extern int latencytop_enabled;
extern unsigned int sysctl_nr_open_min, sysctl_nr_open_max;
#ifndef CONFIG_MMU
extern int sysctl_nr_trim_pages;
#endif

/* Constants used for minimum and  maximum */
#ifdef CONFIG_LOCKUP_DETECTOR
static int sixty = 60;
#endif

static int __maybe_unused neg_one = -1;

static int zero;
static int __maybe_unused one = 1;
static int __maybe_unused two = 2;
static int __maybe_unused three = 3;
static int __maybe_unused four = 4;
static unsigned long zero_ul;
static unsigned long one_ul = 1;
static unsigned long long_max = LONG_MAX;
static int one_hundred = 100;
static int __maybe_unused one_thousand = 1000;
#ifdef CONFIG_SCHED_WALT
static int two_million = 2000000;
#endif
#ifdef CONFIG_PRINTK
static int ten_thousand = 10000;
#endif
#ifdef CONFIG_PERF_EVENTS
static int six_hundred_forty_kb = 640 * 1024;
#endif
static int two_hundred_fifty_five = 255;

/* this is needed for the proc_doulongvec_minmax of vm_dirty_bytes */
static unsigned long dirty_bytes_min = 2 * PAGE_SIZE;

/* this is needed for the proc_dointvec_minmax for [fs_]overflow UID and GID */
static int maxolduid = 65535;
static int minolduid;

static int ngroups_max = NGROUPS_MAX;
static const int cap_last_cap = CAP_LAST_CAP;

/*this is needed for proc_doulongvec_minmax of sysctl_hung_task_timeout_secs */
#ifdef CONFIG_DETECT_HUNG_TASK
static unsigned long hung_task_timeout_max = (LONG_MAX/HZ);
#endif

#ifdef CONFIG_INOTIFY_USER
#include <linux/inotify.h>
#endif
#ifdef CONFIG_SPARC
#endif

#ifdef __hppa__
extern int pwrsw_enabled;
#endif

#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_ALLOW
extern int unaligned_enabled;
#endif

#ifdef CONFIG_IA64
extern int unaligned_dump_stack;
#endif

#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_NO_WARN
extern int no_unaligned_warning;
#endif

#ifdef CONFIG_PROC_SYSCTL

#define SYSCTL_WRITES_LEGACY	-1
#define SYSCTL_WRITES_WARN	 0
#define SYSCTL_WRITES_STRICT	 1

static int sysctl_writes_strict = SYSCTL_WRITES_STRICT;

static int proc_do_cad_pid(struct ctl_table *table, int write,
		  void __user *buffer, size_t *lenp, loff_t *ppos);
static int proc_taint(struct ctl_table *table, int write,
			       void __user *buffer, size_t *lenp, loff_t *ppos);
#endif

#ifdef CONFIG_PRINTK
static int proc_dointvec_minmax_sysadmin(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp, loff_t *ppos);
#endif

static int proc_dointvec_minmax_coredump(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);
#ifdef CONFIG_COREDUMP
static int proc_dostring_coredump(struct ctl_table *table, int write,
		void __user *buffer, size_t *lenp, loff_t *ppos);
#endif

#ifdef CONFIG_MAGIC_SYSRQ
/* Note: sysrq code uses it's own private copy */
static int __sysrq_enabled = CONFIG_MAGIC_SYSRQ_DEFAULT_ENABLE;

static int sysrq_sysctl_handler(struct ctl_table *table, int write,
				void __user *buffer, size_t *lenp,
				loff_t *ppos)
{
	int error;

	error = proc_dointvec(table, write, buffer, lenp, ppos);
	if (error)
		return error;

	if (write)
		sysrq_toggle_support(__sysrq_enabled);

	return 0;
}

#endif

#ifdef CONFIG_BPF_SYSCALL

void __weak unpriv_ebpf_notify(int new_state)
{
}

static int bpf_unpriv_handler(struct ctl_table *table, int write,
                             void *buffer, size_t *lenp, loff_t *ppos)
{
	int ret, unpriv_enable = *(int *)table->data;
	bool locked_state = unpriv_enable == 1;
	struct ctl_table tmp = *table;

	if (write && !capable(CAP_SYS_ADMIN))
		return -EPERM;

	tmp.data = &unpriv_enable;
	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (write && !ret) {
		if (locked_state && unpriv_enable != 1)
			return -EPERM;
		*(int *)table->data = unpriv_enable;
	}

	unpriv_ebpf_notify(unpriv_enable);

	return ret;
}
#endif

static struct ctl_table kern_table[];
static struct ctl_table vm_table[];
static struct ctl_table fs_table[];
static struct ctl_table debug_table[];
static struct ctl_table dev_table[];
extern struct ctl_table random_table[];
#ifdef CONFIG_EPOLL
extern struct ctl_table epoll_table[];
#endif

#ifdef HAVE_ARCH_PICK_MMAP_LAYOUT
int sysctl_legacy_va_layout;
#endif

/* The default sysctl tables: */

static struct ctl_table sysctl_base_table[] = {
	{
		.procname	= "kernel",
		.mode		= 0555,
		.child		= kern_table,
	},
	{
		.procname	= "vm",
		.mode		= 0555,
		.child		= vm_table,
	},
	{
		.procname	= "fs",
		.mode		= 0555,
		.child		= fs_table,
	},
	{
		.procname	= "debug",
		.mode		= 0555,
		.child		= debug_table,
	},
	{
		.procname	= "dev",
		.mode		= 0555,
		.child		= dev_table,
	},
	{ }
};

#ifdef CONFIG_SCHED_DEBUG
static int min_sched_granularity_ns = 100000;		/* 100 usecs */
static int max_sched_granularity_ns = NSEC_PER_SEC;	/* 1 second */
static int min_wakeup_granularity_ns;			/* 0 usecs */
static int max_wakeup_granularity_ns = NSEC_PER_SEC;	/* 1 second */
#ifdef CONFIG_SMP
static int min_sched_tunable_scaling = SCHED_TUNABLESCALING_NONE;
static int max_sched_tunable_scaling = SCHED_TUNABLESCALING_END-1;
#endif /* CONFIG_SMP */
#endif /* CONFIG_SCHED_DEBUG */

#ifdef CONFIG_COMPACTION
static int min_extfrag_threshold;
static int max_extfrag_threshold = 1000;
#endif

static struct ctl_table kern_table[] = {
	{
		.procname	= "sched_child_runs_first",
		.data		= &sysctl_sched_child_runs_first,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#if defined(CONFIG_PREEMPT_TRACER) || defined(CONFIG_IRQSOFF_TRACER)
	{
		.procname       = "preemptoff_tracing_threshold_ns",
		.data           = &sysctl_preemptoff_tracing_threshold_ns,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname       = "irqsoff_tracing_threshold_ns",
		.data           = &sysctl_irqsoff_tracing_threshold_ns,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
#endif
#ifdef CONFIG_SCHED_WALT
	{
		.procname       = "sched_cpu_high_irqload",
		.data           = &sysctl_sched_cpu_high_irqload,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec,
	},
	{
		.procname	= "sched_group_upmigrate",
		.data		= &sysctl_sched_group_upmigrate_pct,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= walt_proc_update_handler,
		.extra1		= &sysctl_sched_group_downmigrate_pct,
	},
	{
		.procname	= "sched_group_downmigrate",
		.data		= &sysctl_sched_group_downmigrate_pct,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= walt_proc_update_handler,
		.extra1		= &zero,
		.extra2		= &sysctl_sched_group_upmigrate_pct,
	},
	{
		.procname	= "sched_boost",
		.data		= &sysctl_sched_boost,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_boost_handler,
		.extra1         = &zero,
		.extra2		= &three,
	},
	{
		.procname	= "sched_walt_rotate_big_tasks",
		.data		= &sysctl_sched_walt_rotate_big_tasks,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "sched_initial_task_util",
		.data		= &sysctl_sched_init_task_load_pct,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "sched_min_task_util_for_boost_colocation",
		.data		= &sysctl_sched_min_task_util_for_boost_colocation,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one_thousand,
	},
	{
		.procname	= "sched_little_cluster_coloc_fmin_khz",
		.data		= &sysctl_sched_little_cluster_coloc_fmin_khz,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_little_cluster_coloc_fmin_khz_handler,
		.extra1		= &zero,
		.extra2		= &two_million,
	},
#endif
	{
		.procname	= "sched_upmigrate",
		.data		= &sysctl_sched_capacity_margin,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_updown_migrate_handler,
	},
	{
		.procname	= "sched_downmigrate",
		.data		= &sysctl_sched_capacity_margin_down,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_updown_migrate_handler,
	},
#ifdef CONFIG_SCHED_DEBUG
	{
		.procname	= "sched_min_granularity_ns",
		.data		= &sysctl_sched_min_granularity,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_proc_update_handler,
		.extra1		= &min_sched_granularity_ns,
		.extra2		= &max_sched_granularity_ns,
	},
	{
		.procname	= "sched_latency_ns",
		.data		= &sysctl_sched_latency,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_proc_update_handler,
		.extra1		= &min_sched_granularity_ns,
		.extra2		= &max_sched_granularity_ns,
	},
	{
		.procname	= "sched_sync_hint_enable",
		.data		= &sysctl_sched_sync_hint_enable,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "sched_cstate_aware",
		.data		= &sysctl_sched_cstate_aware,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "sched_wakeup_granularity_ns",
		.data		= &sysctl_sched_wakeup_granularity,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_proc_update_handler,
		.extra1		= &min_wakeup_granularity_ns,
		.extra2		= &max_wakeup_granularity_ns,
	},
#ifdef CONFIG_SMP
	{
		.procname	= "sched_tunable_scaling",
		.data		= &sysctl_sched_tunable_scaling,
		.maxlen		= sizeof(enum sched_tunable_scaling),
		.mode		= 0644,
		.proc_handler	= sched_proc_update_handler,
		.extra1		= &min_sched_tunable_scaling,
		.extra2		= &max_sched_tunable_scaling,
	},
	{
		.procname	= "sched_migration_cost_ns",
		.data		= &sysctl_sched_migration_cost,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "sched_nr_migrate",
		.data		= &sysctl_sched_nr_migrate,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "sched_time_avg_ms",
		.data		= &sysctl_sched_time_avg,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
	},
	{
		.procname	= "sched_shares_window_ns",
		.data		= &sysctl_sched_shares_window,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_SCHEDSTATS
	{
		.procname	= "sched_schedstats",
		.data		= NULL,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_schedstats,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif /* CONFIG_SCHEDSTATS */
#endif /* CONFIG_SMP */
#ifdef CONFIG_NUMA_BALANCING
	{
		.procname	= "numa_balancing_scan_delay_ms",
		.data		= &sysctl_numa_balancing_scan_delay,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "numa_balancing_scan_period_min_ms",
		.data		= &sysctl_numa_balancing_scan_period_min,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "numa_balancing_scan_period_max_ms",
		.data		= &sysctl_numa_balancing_scan_period_max,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "numa_balancing_scan_size_mb",
		.data		= &sysctl_numa_balancing_scan_size,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
	},
	{
		.procname	= "numa_balancing",
		.data		= NULL, /* filled in by handler */
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_numa_balancing,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif /* CONFIG_NUMA_BALANCING */
#endif /* CONFIG_SCHED_DEBUG */
	{
		.procname	= "sched_rt_period_us",
		.data		= &sysctl_sched_rt_period,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sched_rt_handler,
	},
	{
		.procname	= "sched_rt_runtime_us",
		.data		= &sysctl_sched_rt_runtime,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sched_rt_handler,
	},
	{
		.procname	= "sched_rr_timeslice_ms",
		.data		= &sysctl_sched_rr_timeslice,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sched_rr_handler,
	},
#ifdef CONFIG_UCLAMP_TASK
	{
		.procname	= "sched_util_clamp_min",
		.data		= &sysctl_sched_uclamp_util_min,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_sched_uclamp_handler,
	},
	{
		.procname	= "sched_util_clamp_max",
		.data		= &sysctl_sched_uclamp_util_max,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_sched_uclamp_handler,
	},
	{
		.procname	= "sched_util_clamp_min_rt_default",
		.data		= &sysctl_sched_uclamp_util_min_rt_default,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= sysctl_sched_uclamp_handler,
	},
#endif
#ifdef CONFIG_SCHED_AUTOGROUP
	{
		.procname	= "sched_autogroup_enabled",
		.data		= &sysctl_sched_autogroup_enabled,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
#endif
#ifdef CONFIG_CFS_BANDWIDTH
	{
		.procname	= "sched_cfs_bandwidth_slice_us",
		.data		= &sysctl_sched_cfs_bandwidth_slice,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
	},
#endif
	{
		.procname	= "sched_lib_name",
		.data		= sched_lib_name,
		.maxlen		= LIB_PATH_LENGTH,
		.mode		= 0644,
		.proc_handler	= sysctl_sched_lib_name_handler,
	},
	{
		.procname	= "sched_lib_mask_force",
		.data		= &sched_lib_mask_force,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &two_hundred_fifty_five,
	},
#ifdef CONFIG_PROVE_LOCKING
	{
		.procname	= "prove_locking",
		.data		= &prove_locking,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_LOCK_STAT
	{
		.procname	= "lock_stat",
		.data		= &lock_stat,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "panic",
		.data		= &panic_timeout,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_COREDUMP
	{
		.procname	= "core_uses_pid",
		.data		= &core_uses_pid,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "core_pattern",
		.data		= core_pattern,
		.maxlen		= CORENAME_MAX_SIZE,
		.mode		= 0644,
		.proc_handler	= proc_dostring_coredump,
	},
	{
		.procname	= "core_pipe_limit",
		.data		= &core_pipe_limit,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_PROC_SYSCTL
	{
		.procname	= "tainted",
		.maxlen 	= sizeof(long),
		.mode		= 0644,
		.proc_handler	= proc_taint,
	},
	{
		.procname	= "sysctl_writes_strict",
		.data		= &sysctl_writes_strict,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &neg_one,
		.extra2		= &one,
	},
#endif
#ifdef CONFIG_LATENCYTOP
	{
		.procname	= "latencytop",
		.data		= &latencytop_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= sysctl_latencytop,
	},
#endif
#ifdef CONFIG_BLK_DEV_INITRD
	{
		.procname	= "real-root-dev",
		.data		= &real_root_dev,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "print-fatal-signals",
		.data		= &print_fatal_signals,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_SPARC
	{
		.procname	= "reboot-cmd",
		.data		= reboot_command,
		.maxlen		= 256,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "stop-a",
		.data		= &stop_a_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "scons-poweroff",
		.data		= &scons_pwroff,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_SPARC64
	{
		.procname	= "tsb-ratio",
		.data		= &sysctl_tsb_ratio,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef __hppa__
	{
		.procname	= "soft-power",
		.data		= &pwrsw_enabled,
		.maxlen		= sizeof (int),
	 	.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
#ifdef CONFIG_SYSCTL_ARCH_UNALIGN_ALLOW
	{
		.procname	= "unaligned-trap",
		.data		= &unaligned_enabled,
		.maxlen		= sizeof (int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#endif
	{
		.procname	= "ctrl-alt-del",
		.data		= &C_A_D,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
#ifdef CONFIG_FUNCTION_TRACER
	{
		.procname	= "ftrace_enabled",
		.data		= &ftrace_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= ftrace_enable_sysctl,
	},
#endif
#ifdef CONFIG_STACK_TRACER
	{
		.procname	= "stack_tracer_enabled",
		.data		= &stack_tracer_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= stack_trace_sysctl,
	},
#endif
#ifdef CONFIG_TRACING
	{
		.procname	= "ftra
