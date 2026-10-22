#include <linux/export.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/workqueue.h>

#include "policy/allowlist.h"
#include "policy/app_profile.h"
#include "policy/feature.h"
#include "klog.h" // IWYU pragma: keep
#include "manager/manager_observer.h"
#include "manager/throne_tracker.h"
#include "hook/syscall_hook_manager.h"
#include "hook/lsm_hook.h"
#include "runtime/xfgd.h"
#include "runtime/xfgd_boot.h"
#include "supercall/supercall.h"
#include "xfg.h"
#include "infra/file_wrapper.h"
#include "selinux/selinux.h"
#include "hook/syscall_hook.h"
#include "feature/adb_root.h"
#include "feature/selinux_hide.h"
#include "feature/module_blacklist.h"
#include "feature/shell_su_adb_only.h"
#include "feature/sulog.h"
#include "infra/symbol_resolver.h"
#include "preinit/preinit.h"

#if defined(__x86_64__) && !defined(CONFIG_XFG_X86_PATCH_SYSCALL_DISPATCHER)
#include <asm/cpufeature.h>
#include <linux/version.h>
#ifndef X86_FEATURE_INDIRECT_SAFE
#error "FATAL: Your kernel is missing the indirect syscall bypass patches!"
#endif
#endif

// workaround for A12-5.10 kernel
// Some third-party kernel (e.g. linegaeOS) uses wrong toolchain, which supports
// CC_HAVE_STACKPROTECTOR_SYSREG while gki's toolchain doesn't.
// Therefore, xfg lkm, which uses gki toolchain, requires this __stack_chk_guard,
// while those third-party kernel can't provide.
// Thus, we manually provide it instead of using kernel's
#if defined(CONFIG_STACKPROTECTOR) &&                                          \
    (defined(CONFIG_ARM64) && defined(MODULE) &&                               \
     !defined(CONFIG_STACKPROTECTOR_PER_TASK))
#include <linux/stackprotector.h>
#include <linux/random.h>
unsigned long __stack_chk_guard __ro_after_init
    __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init xfg_setup_stack_chk_guard()
{
    unsigned long canary;

    /* Try to get a semi random initial value. */
    get_random_bytes(&canary, sizeof(canary));
    canary ^= LINUX_VERSION_CODE;
    canary &= CANARY_MASK;
    __stack_chk_guard = canary;
}

__attribute__((naked)) int __init xiaofeng_init_early(void)
{
    asm("mov x19, x30;\n"
        "bl xfg_setup_stack_chk_guard;\n"
        "mov x30, x19;\n"
        "b xiaofeng_init;\n");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif

struct cred *xfg_cred;
bool xfg_late_loaded;

#ifdef CONFIG_XFG_DEBUG
bool allow_shell = true;
#else
bool allow_shell = false;
#endif
module_param(allow_shell, bool, 0);

bool xfg_no_custom_rc = false;
module_param_named(norc, xfg_no_custom_rc, bool, 0);

#ifdef MODULE
bool xfg_bundled = false;
module_param_named(bundled, xfg_bundled, bool, 0);
#endif

int __init xiaofeng_init(void)
{
#ifdef XFG_MANAGER_PACKAGE
	pr_info("welcome to XiaoFeng version " __stringify(KERNEL_SU_VERSION) ", package name " XFG_MANAGER_PACKAGE "\n");
#else
	pr_info("welcome to XiaoFeng version " __stringify(KERNEL_SU_VERSION) "\n");
#endif
#if defined(__x86_64__) && !defined(CONFIG_XFG_X86_PATCH_SYSCALL_DISPATCHER)
    // If the kernel has the hardening patch, X86_FEATURE_INDIRECT_SAFE must be set
    if (!boot_cpu_has(X86_FEATURE_INDIRECT_SAFE)) {
        pr_alert("*************************************************************");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("**                                                         **");
        pr_alert("**        X86_FEATURE_INDIRECT_SAFE is not enabled!        **");
        pr_alert("**      XiaoFeng will abort initialization to prevent      **");
        pr_alert("**                     kernel panic.                       **");
        pr_alert("**                                                         **");
        pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
        pr_alert("*************************************************************");
        return -ENOSYS;
    }
#endif

#ifdef MODULE
	xfg_late_loaded = (current->pid != 1);
#else
	xfg_late_loaded = false;
#endif

#ifdef CONFIG_XFG_DEBUG
	pr_alert("*************************************************************");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("**                                                         **");
	pr_alert("**         You are running XiaoFeng in DEBUG mode          **");
	pr_alert("**                                                         **");
	pr_alert("**     NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE    **");
	pr_alert("*************************************************************");
#endif
	if (allow_shell) {
		pr_alert("shell is allowed at init!");
	}

	xfg_cred = prepare_creds();
	if (!xfg_cred) {
		pr_err("prepare cred failed!\n");
		return -ENOSYS;
	}

	xfg_init_symbol_resolver();
	xfg_syscall_hook_init();

	// Block modules early, before vendor modules are loaded in second stage.
	xfg_module_blacklist_init();

	xfg_feature_init();
	xfg_sulog_init();
	xfg_adb_root_init();
	xfg_lsm_hook_init();
	xfg_selinux_hide_init();
	xfg_shell_su_adb_only_init();

	xfg_supercalls_init();
	xfg_app_profile_init();

	if (xfg_late_loaded) {
		pr_info("late load mode, skipping kprobe hooks\n");

		apply_xiaofeng_rules();
		cache_sid();
		setup_xfg_cred();

		// Grant current process (xfgd late-load) root
		// with XFG SELinux domain before enforcing SELinux, so it
		// can continue to access /data/app etc. after enforcement.
		escape_to_root_for_init();

		xfg_allowlist_init();
		xfg_load_allow_list();

		xfg_syscall_hook_manager_init();

		xfg_throne_tracker_init();
		xfg_observer_init();
		xfg_file_wrapper_init();

		xfg_boot_completed = true;
		track_throne(false);

		xfg_feature_apply_forced();

		if (!getenforce()) {
			pr_info("Permissive SELinux, enforcing\n");
			setenforce(true);
		}

	} else {
		xfg_syscall_hook_manager_init();

		xfg_allowlist_init();

		xfg_throne_tracker_init();

		xfg_xfgd_init();

		xfg_preinit_init();

		xfg_file_wrapper_init();
	}

#ifdef MODULE
#ifndef CONFIG_XFG_DEBUG
	kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
#endif
	return 0;
}

void __exit xiaofeng_exit(void)
{
	// Phase 1: Stop all hooks first to prevent new callbacks
	xfg_syscall_hook_manager_exit();

	xfg_supercalls_exit();

	if (!xfg_late_loaded) {
		xfg_xfgd_exit();
		xfg_preinit_exit();
	}

	// Wait for any in-flight RCU readers (e.g. handler traversing allow_list)
	synchronize_rcu();

	// Phase 2: Now safe to release data structures
	xfg_observer_exit();

	xfg_throne_tracker_exit();

	xfg_allowlist_exit();

	xfg_shell_su_adb_only_exit();
	xfg_selinux_hide_exit();
	xfg_lsm_hook_exit();
	xfg_adb_root_exit();
	xfg_sulog_exit();
	xfg_feature_exit();
	xfg_module_blacklist_exit();

	put_cred(xfg_cred);
}

#if NEED_OWN_STACKPROTECTOR
module_init(xiaofeng_init_early);
#else
module_init(xiaofeng_init);
#endif
module_exit(xiaofeng_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("XiaoFeng");
MODULE_DESCRIPTION("Android XiaoFeng");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
