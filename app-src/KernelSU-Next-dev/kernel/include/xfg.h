#ifndef __XFG_H_XFG
#define __XFG_H_XFG

#include <linux/types.h>
#include <linux/cred.h>
#include <linux/workqueue.h>

#define KERNEL_SU_VERSION XFG_VERSION
#define KERNEL_SU_VERSION_TAG XFG_VERSION_TAG

extern struct cred *xfg_cred;
extern bool xfg_late_loaded;
extern bool allow_shell;
#ifdef MODULE
extern bool xfg_bundled;
#endif
extern struct selinux_policy *backup_sepolicy;
extern bool xfg_no_custom_rc;

#ifdef CONFIG_ANDROID
#include <linux/security.h>
#define xfg_security_secctx_to_secid security_secctx_to_secid
#else
int xfg_security_secctx_to_secid(const char *secdata, u32 seclen, u32 *secid);
#endif

static inline int startswith(char *s, char *prefix)
{
	return strncmp(s, prefix, strlen(prefix));
}

static inline int endswith(const char *s, const char *t)
{
	size_t slen = strlen(s);
	size_t tlen = strlen(t);
	if (tlen > slen)
		return 1;
	return strcmp(s + slen - tlen, t);
}

#endif
