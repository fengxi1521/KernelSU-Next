// SPDX-License-Identifier: GPL-2.0

/* issue #34: the hide gates ask XiaoFeng whether it would umount modules for a uid, instead of the
 * old `uid >= 10000` proxy that hid from the manager and from su-granted apps too.
 *
 * The address is resolved ONCE, at load, by name through kallsyms (kernel/symbol_resolver.c) and kept
 * in a function pointer - it is not imported from xiaofeng.ko, for two reasons:
 *
 *   - an import would have to be strong.  A __weak one is emitted as a GOT entry
 *     (R_AARCH64_ADR_GOT_PAGE + R_AARCH64_LD64_GOT_LO12_NC), and arm64's module relocator implements
 *     neither, so the module would refuse to load at all - measured on the artifacts, including with
 *     visibility("hidden") and with -fno-pic, neither of which removes that entry (it comes from the
 *     weak reference itself, not from PIC);
 *   - resolving by name answers the environment question directly: the symbol is there or it is not.
 *     Nothing here depends on which loader ran the module or on the SELinux domain it ran in, so no
 *     loader-side detection is needed either.
 *
 * The answer is decided once, here, and the gates only read the flag afterwards.  Two consequences
 * worth knowing.  A XiaoFeng loaded AFTER this module is not noticed until this module is reloaded
 * (the warning below says so).  A XiaoFeng that is UNLOADED leaves the saved address dangling - a call
 * would jump into freed module text; the strong import this replaced had exactly the same exposure,
 * since nothing holds a reference for us either, so that is a known residual rather than a new one. */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include "xfg_umount_gate.h"
#include "symbol_resolver.h"
#include "susfs_log.h"

#define XFG_UMOUNT_GATE_SYMBOL	"xfg_uid_should_umount"

/* Fail-safe default: the pre-#34 answer, until the init below proves that XiaoFeng's symbol exists.
 * A path that skips that init entirely - the fail_layer=1 diagnostic in susfs_main.c is one, and this
 * layer is deliberately not fatal - therefore leaves the gates on the safe branch instead of calling
 * through a NULL pointer.  Only a successful resolve turns it off. */
bool susfs_xfg_umount_gate_off = true;

/* Written once in init, read by every gate through susfs_xfg_umount_ask().  Non-NULL exactly while
 * the gate is off == false, which is the invariant the helper relies on instead of testing the
 * pointer on every call; the default above is what makes that invariant hold even when init is
 * skipped. */
static bool (*xfg_uid_should_umount_fn)(uid_t uid);

/* noinline __nocfi: an indirect call through a resolved address.  CFI checks indirect call sites, and
 * LTO would otherwise inline a small static helper back into a caller that is not marked. */
bool __nocfi noinline susfs_xfg_umount_ask(uid_t uid)
{
	return xfg_uid_should_umount_fn(uid);
}

int susfs_xfg_umount_gate_init(void)
{
	unsigned long addr = xfg_kallsyms_lookup_name(XFG_UMOUNT_GATE_SYMBOL);

	if (!addr) {
		susfs_xfg_umount_gate_off = true;
		/* pr_warn, not SUSFS_LOGI: "issue #34's fix is not in effect on this device" is something an
		 * operator has to be able to see, and the load is otherwise silent about it. */
		pr_warn("susfs_guard_lkm: %s is not in kallsyms - the hide gates keep the uid >= 10000 rule, so issue #34's fix (hiding follows XiaoFeng's exclusion list) is NOT in effect here.  A XiaoFeng loaded after this module needs this module reloaded to be picked up.\n",
			XFG_UMOUNT_GATE_SYMBOL);
		return 0;
	}

	xfg_uid_should_umount_fn = (bool (*)(uid_t))addr;
	susfs_xfg_umount_gate_off = false;	/* only now is there something to ask */
	SUSFS_LOGI("xfg_umount_gate: resolved %s at %px - the hide gates now answer XiaoFeng (issue #34)\n",
		   XFG_UMOUNT_GATE_SYMBOL, (void *)addr);
	return 0;
}
