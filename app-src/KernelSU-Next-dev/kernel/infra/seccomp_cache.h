#ifndef __XFG_H_KERNEL_COMPAT
#define __XFG_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>

extern void xfg_seccomp_clear_cache(struct seccomp_filter *filter, int nr);
extern void xfg_seccomp_allow_cache(struct seccomp_filter *filter, int nr);

#endif
