#include "linux/printk.h"
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <linux/tracepoint.h>
#include <asm/syscall.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <trace/events/syscalls.h>

#include <linux/version.h>
#include <linux/sched/task_stack.h>
#include <linux/compat.h>

#include "arch.h"
#include "klog.h" // IWYU pragma: keep
#include "hook/syscall_hook_manager.h"
#include "hook/tp_marker.h"
#include "feature/sucompat.h"
#include "hook/setuid_hook.h"
#include "hook/syscall_hook.h"
#include "hook/syscall_event_bridge.h"
#if defined(__riscv)
#include "hook/riscv64/syscall_regs.h"
#endif

#ifdef CONFIG_KRETPROBES

static struct kretprobe *init_kretprobe(const char *name, kretprobe_handler_t handler)
{
    struct kretprobe *rp = kzalloc(sizeof(struct kretprobe), GFP_KERNEL);
    if (!rp)
        return NULL;
    rp->kp.symbol_name = name;
    rp->handler = handler;
    rp->data_size = 0;
    rp->maxactive = 0;

    int ret = register_kretprobe(rp);
    pr_info("hook_manager: register_%s kretprobe: %d\n", name, ret);
    if (ret) {
        kfree(rp);
        return NULL;
    }

    return rp;
}

static void destroy_kretprobe(struct kretprobe **rp_ptr)
{
    struct kretprobe *rp = *rp_ptr;
    if (!rp)
        return;
    unregister_kretprobe(rp);
    synchronize_rcu();
    kfree(rp);
    *rp_ptr = NULL;
}

static int syscall_regfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    xfg_tp_marker_lock(&flags);
    if (xfg_tp_marker_reg_count() < 1) {
        // while install our tracepoint, mark our processes
        xfg_mark_running_process_locked();
    } else if (xfg_tp_marker_reg_count() == 1) {
        // while other tracepoint first added, mark all processes
        xfg_mark_all_process();
    }
    xfg_tp_marker_inc_reg_count();
    xfg_tp_marker_unlock(&flags);
    return 0;
}

static int syscall_unregfunc_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    unsigned long flags;
    xfg_tp_marker_lock(&flags);
    xfg_tp_marker_dec_reg_count();
    if (xfg_tp_marker_reg_count() <= 0) {
        // while no tracepoint left, unmark all processes
        xfg_unmark_all_process();
    } else if (xfg_tp_marker_reg_count() == 1) {
        // while just our tracepoint left, unmark disallowed processes
        xfg_mark_running_process_locked();
    }
    xfg_tp_marker_unlock(&flags);
    return 0;
}

static struct kretprobe *syscall_regfunc_rp = NULL;
static struct kretprobe *syscall_unregfunc_rp = NULL;
#endif

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
// sys_enter handler: redirect hooked syscalls to the dispatcher
static void xfg_sys_enter_handler(void *data, struct pt_regs *regs, long id)
{
#if defined(__x86_64__)
    if (unlikely(in_compat_syscall()))
#elif defined(__aarch64__) || defined(__riscv)
    if (unlikely(is_compat_task()))
#endif
        return;

    if (xfg_dispatcher_nr < 0)
        return;

    if (xfg_has_syscall_hook(id)) {
        struct pt_regs *current_regs = task_pt_regs(current);

#if defined(__x86_64__)
        // Stash the original syscall number in ax.
        // We use ax because it currently just holds -ENOSYS and is safe to overwrite.
        current_regs->ax = id;
        current_regs->orig_ax = xfg_dispatcher_nr;
#elif defined(__aarch64__)
        PT_REGS_ORIG_SYSCALL(current_regs) = id;
        current_regs->syscallno = xfg_dispatcher_nr;
#elif defined(__riscv)
        /* orig_a0 retains argument zero; a0 is the -ENOSYS return slot. */
        xfg_riscv_redirect_syscall(current_regs, id, xfg_dispatcher_nr);
#endif
    }
}
#endif

void __init xfg_syscall_hook_manager_init(void)
{
    int ret;
    pr_info("hook_manager: xfg_hook_manager_init called\n");

#ifdef CONFIG_KRETPROBES
    syscall_regfunc_rp = init_kretprobe("syscall_regfunc", syscall_regfunc_handler);
    syscall_unregfunc_rp = init_kretprobe("syscall_unregfunc", syscall_unregfunc_handler);
#endif

    // Register syscall hooks via dispatcher
    xfg_register_syscall_hook(__NR_setresuid, xfg_hook_setresuid);
    xfg_register_syscall_hook(__NR_execve, xfg_hook_execve);
    xfg_register_syscall_hook(__NR_execveat, xfg_hook_execveat);
    xfg_register_syscall_hook(__NR_newfstatat, xfg_hook_newfstatat);
    xfg_register_syscall_hook(__NR_faccessat, xfg_hook_faccessat);

#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    ret = register_trace_prio_sys_enter(xfg_sys_enter_handler, NULL, INT_MIN);
#ifndef CONFIG_KRETPROBES
    xfg_mark_running_process_locked();
#endif
    if (ret) {
        pr_err("hook_manager: failed to register sys_enter tracepoint: %d\n", ret);
    } else {
        pr_info("hook_manager: sys_enter tracepoint registered\n");
    }
#endif

    xfg_setuid_hook_init();
    xfg_sucompat_init();
    xfg_avc_spoof_init();
}

void __exit xfg_syscall_hook_manager_exit(void)
{
    pr_info("hook_manager: xfg_hook_manager_exit called\n");
#ifdef CONFIG_HAVE_SYSCALL_TRACEPOINTS
    unregister_trace_sys_enter(xfg_sys_enter_handler, NULL);
    tracepoint_synchronize_unregister();
    pr_info("hook_manager: sys_enter tracepoint unregistered\n");
#endif

#ifdef CONFIG_KRETPROBES
    destroy_kretprobe(&syscall_regfunc_rp);
    destroy_kretprobe(&syscall_unregfunc_rp);
#endif

    xfg_unregister_syscall_hook(__NR_setresuid);
    xfg_unregister_syscall_hook(__NR_execve);
    xfg_unregister_syscall_hook(__NR_execveat);
    xfg_unregister_syscall_hook(__NR_newfstatat);
    xfg_unregister_syscall_hook(__NR_faccessat);

    xfg_syscall_hook_exit();

    xfg_sucompat_exit();
    xfg_setuid_hook_exit();
    xfg_avc_spoof_exit();
}
