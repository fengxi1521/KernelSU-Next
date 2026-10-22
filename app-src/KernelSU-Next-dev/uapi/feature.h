#ifndef __XFG_UAPI_FEATURE_H
#define __XFG_UAPI_FEATURE_H

enum xfg_feature_id {
    XFG_FEATURE_SU_COMPAT = 0,
    XFG_FEATURE_KERNEL_UMOUNT = 1,
    XFG_FEATURE_SULOG = 2,
    XFG_FEATURE_ADB_ROOT = 3,
    XFG_FEATURE_SELINUX_HIDE = 4,
    // 5 was webview_zygote_umount (v3.3.0), keep it unused so stale configs don't apply
    XFG_FEATURE_SHELL_SU_ADB_ONLY = 6,

    // custom extensions
    XFG_FEATURE_AVC_SPOOF = 10003,

    XFG_FEATURE_MAX
};

#endif
