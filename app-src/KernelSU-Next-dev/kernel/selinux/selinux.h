#ifndef __XFG_H_SELINUX
#define __XFG_H_SELINUX

#include <linux/types.h>
#include <linux/version.h>
#include <linux/cred.h>

#define KERNEL_SU_DOMAIN "xfg"
#define KERNEL_SU_FILE "xfg_file"

#define KERNEL_SU_CONTEXT "u:r:" KERNEL_SU_DOMAIN ":s0"
#define XFG_FILE_CONTEXT "u:object_r:" KERNEL_SU_FILE ":s0"
#define ZYGOTE_CONTEXT "u:r:zygote:s0"
#define INIT_CONTEXT "u:r:init:s0"
#define ADBD_CONTEXT "u:r:adbd:s0"

void setup_selinux(const char *, struct cred *);

void setenforce(bool);

bool getenforce();

void cache_sid(void);

bool is_task_xfg_domain(const struct cred *cred);

bool is_xfg_domain();

bool is_zygote(const struct cred *cred);

bool is_init(const struct cred *cred);

bool is_adbd(const struct cred *cred);

void apply_xiaofeng_rules();

int handle_sepolicy(void __user *user_data, u64 data_len);

void setup_xfg_cred();

void escape_to_root_for_adb_root();

extern u32 xfg_file_sid;

#endif
