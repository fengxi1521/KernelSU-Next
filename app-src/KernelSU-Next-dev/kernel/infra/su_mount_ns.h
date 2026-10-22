#ifndef __XFG_SU_MOUNT_NS_H
#define __XFG_SU_MOUNT_NS_H

#include <linux/types.h>

#define XFG_NS_INHERITED 0
#define XFG_NS_GLOBAL 1
#define XFG_NS_INDIVIDUAL 2

struct xfg_mns_tw {
    struct callback_head cb;
    int32_t ns_mode;
};

void setup_mount_ns(int32_t ns_mode);

#endif
