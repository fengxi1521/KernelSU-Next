#ifndef __XFG_H_XFGD_BOOT
#define __XFG_H_XFGD_BOOT

#include <linux/types.h>

void on_post_fs_data(void);
void on_module_mounted(void);
void on_boot_completed(void);

bool xfg_is_safe_mode(void);

int nuke_ext4_sysfs(const char *mnt);

extern bool xfg_module_mounted;
extern bool xfg_boot_completed;

#endif // __XFG_H_XFGD_BOOT
