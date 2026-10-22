#ifndef __XFG_H_SULOG
#define __XFG_H_SULOG

#include <linux/types.h>
#include <linux/init.h>

bool xfg_sulog_is_enabled(void);
void __init xfg_sulog_init(void);
void __exit xfg_sulog_exit(void);

#endif
