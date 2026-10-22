#ifndef __XFG_UAPI_SULOG_H
#define __XFG_UAPI_SULOG_H

#include <linux/sched.h>
#include <linux/types.h>

#define XFG_SULOG_EVENT_VERSION 1
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

enum xfg_sulog_event_type {
    XFG_SULOG_EVENT_ROOT_EXECVE = 1,
    XFG_SULOG_EVENT_SUCOMPAT = 2,
    XFG_SULOG_EVENT_IOCTL_GRANT_ROOT = 3,
};

struct xfg_sulog_event {
    __u16 version;
    __u16 event_type;
    __s32 retval;
    __u32 pid;
    __u32 tgid;
    __u32 ppid;
    __u32 uid;
    __u32 euid;
    char comm[TASK_COMM_LEN];
    __u32 filename_len;
    __u32 argv_len;
} __packed;

#endif
