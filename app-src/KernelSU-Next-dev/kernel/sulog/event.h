#ifndef __XFG_H_SULOG_EVENT
#define __XFG_H_SULOG_EVENT

#include <linux/compiler_types.h>
#include <linux/gfp.h>
#include <linux/types.h>
#include "uapi/sulog.h" // IWYU pragma: keep

struct xfg_event_queue;
struct xfg_sulog_pending_event;

int __init xfg_sulog_events_init(void);
void __exit xfg_sulog_events_exit(void);

struct xfg_sulog_pending_event *xfg_sulog_capture_root_execve(const char __user *filename_user,
                                                              const char __user *const __user *argv_user, gfp_t gfp);
struct xfg_sulog_pending_event *xfg_sulog_capture_sucompat(const char __user *filename_user,
                                                           const char __user *const __user *argv_user, gfp_t gfp);
void xfg_sulog_emit_pending(struct xfg_sulog_pending_event *pending, int retval, gfp_t gfp);
int xfg_sulog_emit_grant_root(int retval, __u32 uid, __u32 euid, gfp_t gfp);

void xfg_compat_sulog(uint8_t sym);

int xfg_sulog_handle_compat_dump(void __user *uptr);

struct xfg_event_queue *xfg_sulog_get_queue(void);

#endif
