#ifndef __XFG_H_KLOG
#define __XFG_H_KLOG

#include <linux/printk.h>

#ifdef pr_fmt
#undef pr_fmt
#define pr_fmt(fmt) "XiaoFeng: " fmt
#endif

#ifdef CONFIG_XFG_DEBUG
#define xfg_dbg(fmt, ...) pr_info(fmt, ##__VA_ARGS__)
#else
#define xfg_dbg(fmt, ...) no_printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#endif

#endif
