#ifndef __XFG_H_SELINUX_HIDE
#define __XFG_H_SELINUX_HIDE

void xfg_selinux_hide_init();
void xfg_selinux_hide_exit();
void xfg_selinux_hide_drop_backup_if_unused();
void xfg_selinux_hide_handle_second_stage();
void xfg_selinux_hide_handle_post_fs_data();

#endif
