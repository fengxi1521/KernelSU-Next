#include <asm/current.h>
#include <linux/compat.h>
#include <linux/cred.h>
#include <linux/gfp.h>
#include <linux/minmax.h>
#include <linux/overflow.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <linux/version.h>
#if defined(__x86_64__) && LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
#include <linux/mm.h>
#endif

#include "feature/sulog.h"
#include "infra/event_queue.h"
#include "klog.h" // IWYU pragma: keep
#include "sulog/event.h"

#define XFG_SULOG_MAX_QUEUED 256U
#define XFG_SULOG_MAX_PAYLOAD_LEN 2048U
#define XFG_SULOG_MAX_ARG_STRINGS 0x7FFFFFFF
#define XFG_SULOG_MAX_ARG_CHUNK 256U
#define XFG_SULOG_MAX_FILENAME_LEN 256U

struct user_arg_ptr {
#ifdef CONFIG_COMPAT
    bool is_compat;
#endif
    union {
        const char __user *const __user *native;
#ifdef CONFIG_COMPAT
        const compat_uptr_t __user *compat;
#endif
    } ptr;
};

static struct xfg_event_queue sulog_queue;

// Compat bridge for xfg_toolkit (SULog)
struct compat_sulog_entry {
    uint32_t s_time;
    uint32_t data;
} __attribute__((packed));

#define COMPAT_SULOG_MAX 250
static struct compat_sulog_entry compat_sulog_buf[COMPAT_SULOG_MAX];
static uint8_t compat_sulog_idx = 0;
static DEFINE_SPINLOCK(compat_sulog_lock);

void xfg_compat_sulog(uint8_t sym)
{
    struct compat_sulog_entry entry = {0};
    unsigned int uid = current_uid().val;
    struct timespec64 ts;

    ktime_get_boottime_ts64(&ts);
    entry.s_time = (uint32_t)ts.tv_sec;
    entry.data = (uint32_t)uid;
    memcpy((void *)&entry.data + 3, &sym, 1);

    spin_lock(&compat_sulog_lock);
    compat_sulog_buf[compat_sulog_idx] = entry;
    compat_sulog_idx = (compat_sulog_idx + 1) % COMPAT_SULOG_MAX;
    spin_unlock(&compat_sulog_lock);
}

struct sulog_entry_rcv_ptr {
    uint64_t index_ptr;
    uint64_t buf_ptr;
    uint64_t uptime_ptr;
};

int xfg_sulog_handle_compat_dump(void __user *uptr)
{
    struct sulog_entry_rcv_ptr sbuf = {0};
    uint32_t uptime;
    uint8_t local_idx;
    struct timespec64 ts;
    struct compat_sulog_entry *local_buf;

    if (copy_from_user(&sbuf, uptr, sizeof(sbuf)))
        return 1;

    if (!sbuf.index_ptr || !sbuf.buf_ptr || !sbuf.uptime_ptr)
        return 1;

    ktime_get_boottime_ts64(&ts);
    uptime = (uint32_t)ts.tv_sec;
    if (copy_to_user((void __user *)(uintptr_t)sbuf.uptime_ptr, &uptime, sizeof(uptime)))
        return 1;

    local_buf = kmalloc(sizeof(compat_sulog_buf), GFP_ATOMIC);
    if (!local_buf)
        return 1;

    spin_lock(&compat_sulog_lock);
    local_idx = compat_sulog_idx;
    memcpy(local_buf, compat_sulog_buf, sizeof(compat_sulog_buf));
    spin_unlock(&compat_sulog_lock);

    if (copy_to_user((void __user *)(uintptr_t)sbuf.index_ptr, &local_idx, sizeof(local_idx))) {
        kfree(local_buf);
        return 1;
    }

    if (copy_to_user((void __user *)(uintptr_t)sbuf.buf_ptr, local_buf, sizeof(compat_sulog_buf))) {
        kfree(local_buf);
        return 1;
    }

    kfree(local_buf);
    return 0;
}

struct xfg_sulog_pending_event {
    __u16 event_type;
    void *payload;
    __u32 payload_len;
};

struct xfg_sulog_identity {
    __u32 uid;
    __u32 euid;
};

static struct user_arg_ptr xfg_sulog_user_argv(const char __user *const __user *argv_user)
{
    struct user_arg_ptr argv;

#ifdef CONFIG_COMPAT
    if (unlikely(in_compat_syscall())) {
        argv.is_compat = true;
        argv.ptr.compat = (const compat_uptr_t __user *)argv_user;
        return argv;
    }

    argv.is_compat = false;
#endif
    argv.ptr.native = argv_user;
    return argv;
}

static const char __user *xfg_sulog_get_user_arg_ptr(struct user_arg_ptr argv, int nr)
{
    const char __user *native;

#ifdef CONFIG_COMPAT
    if (unlikely(argv.is_compat)) {
        compat_uptr_t compat;

        if (get_user(compat, argv.ptr.compat + nr))
            return ERR_PTR(-EFAULT);

        return compat_ptr(compat);
    }
#endif

    if (get_user(native, argv.ptr.native + nr))
        return ERR_PTR(-EFAULT);

    return native;
}

static void xfg_sulog_fill_task_info(struct xfg_sulog_event *event, __u16 event_type, int retval)
{
    event->version = XFG_SULOG_EVENT_VERSION;
    event->event_type = event_type;
    event->retval = retval;
    event->pid = task_pid_nr(current);
    event->tgid = task_tgid_nr(current);
    event->ppid = task_ppid_nr(current);
    event->uid = current_uid().val;
    event->euid = current_euid().val;
    get_task_comm(event->comm, current);
}

static void xfg_sulog_set_identity(struct xfg_sulog_event *event, const struct xfg_sulog_identity *identity)
{
    if (!identity)
        return;

    event->uid = identity->uid;
    event->euid = identity->euid;
}

static __u32 xfg_sulog_copy_empty_string(char *dst)
{
    dst[0] = '\0';
    return 1;
}

static __u32 xfg_sulog_copy_filename(const char __user *filename_user, char *dst, __u32 dst_len)
{
    long ret;

    if (!dst_len)
        return 0;

    if (!filename_user)
        return xfg_sulog_copy_empty_string(dst);

    ret = strncpy_from_user_nofault(dst, (const void __user *)untagged_addr((unsigned long)filename_user), dst_len);
    if (ret <= 0)
        return xfg_sulog_copy_empty_string(dst);

    if (ret >= dst_len) {
        dst[dst_len - 1] = '\0';
        return dst_len;
    }

    return ret + 1;
}

static __u32 xfg_sulog_flatten_argv(const char __user *const __user *argv_user, char *dst, __u32 dst_len)
{
    struct user_arg_ptr argv = xfg_sulog_user_argv(argv_user);
    char arg[XFG_SULOG_MAX_ARG_CHUNK];
    __u32 used = 0;
    int i;

    if (!dst_len)
        return 0;

    if (!argv_user)
        return xfg_sulog_copy_empty_string(dst);

    for (i = 0; i < XFG_SULOG_MAX_ARG_STRINGS; i++) {
        const char __user *arg_user;
        long copied;
        size_t arg_len;

        if (fatal_signal_pending(current))
            break;

        arg_user = xfg_sulog_get_user_arg_ptr(argv, i);
        if (!arg_user)
            break;
        if (IS_ERR(arg_user))
            return xfg_sulog_copy_empty_string(dst);

        copied =
            strncpy_from_user_nofault(arg, (const void __user *)untagged_addr((unsigned long)arg_user), sizeof(arg));
        if (copied <= 0)
            return xfg_sulog_copy_empty_string(dst);

        if (copied >= sizeof(arg))
            arg[sizeof(arg) - 1] = '\0';

        arg_len = strnlen(arg, sizeof(arg));
        if (!arg_len)
            continue;

        if (used && used < dst_len - 1)
            dst[used++] = ' ';

        if (used >= dst_len - 1)
            break;

        arg_len = min_t(size_t, arg_len, dst_len - used - 1);
        memcpy(dst + used, arg, arg_len);
        used += arg_len;

        if (used >= dst_len - 1)
            break;
    }

    dst[used] = '\0';
    return used + 1;
}

static struct xfg_sulog_pending_event *xfg_sulog_capture(__u16 event_type, const char __user *filename_user,
                                                         const char __user *const __user *argv_user, gfp_t gfp)
{
    struct xfg_sulog_pending_event *pending = NULL;
    struct xfg_sulog_event *event;
    void *payload = NULL;
    __u32 payload_len;
    __u32 filename_len;
    __u32 argv_len;
    __u32 remaining;
    char *filename_buf;
    char *argv_buf;
    if (!xfg_sulog_is_enabled())
        return NULL;

    pending = kzalloc(sizeof(*pending), gfp);
    if (!pending)
        goto out_drop;

    payload = kzalloc(XFG_SULOG_MAX_PAYLOAD_LEN, gfp);
    if (!payload)
        goto out_free_pending;

    event = payload;
    xfg_sulog_fill_task_info(event, event_type, 0);

    remaining = XFG_SULOG_MAX_PAYLOAD_LEN - sizeof(*event);
    filename_buf = (char *)payload + sizeof(*event);
    filename_len = xfg_sulog_copy_filename(filename_user, filename_buf, min(remaining, XFG_SULOG_MAX_FILENAME_LEN));
    if (!filename_len)
        goto out_free_payload;

    remaining -= filename_len;
    argv_buf = filename_buf + filename_len;
    argv_len = xfg_sulog_flatten_argv(argv_user, argv_buf, remaining);
    if (!argv_len)
        goto out_free_payload;

    event->filename_len = filename_len;
    event->argv_len = argv_len;

    if (check_add_overflow((__u32)sizeof(*event), filename_len, &payload_len) ||
        check_add_overflow(payload_len, argv_len, &payload_len))
        goto out_free_payload;

    pending->event_type = event_type;
    pending->payload = payload;
    pending->payload_len = payload_len;
    return pending;

out_free_payload:
    kfree(payload);
out_free_pending:
    kfree(pending);
out_drop:
    xfg_event_queue_drop(&sulog_queue);
    return NULL;
}

static struct xfg_sulog_pending_event *xfg_sulog_capture_grant_root(const struct xfg_sulog_identity *identity,
                                                                    gfp_t gfp)
{
    struct xfg_sulog_pending_event *pending;
    struct xfg_sulog_event *event;

    pending = xfg_sulog_capture(XFG_SULOG_EVENT_IOCTL_GRANT_ROOT, NULL, NULL, gfp);
    if (!pending)
        return NULL;

    event = pending->payload;
    xfg_sulog_set_identity(event, identity);
    return pending;
}

int __init xfg_sulog_events_init(void)
{
    xfg_event_queue_init(&sulog_queue, XFG_SULOG_MAX_QUEUED, XFG_SULOG_MAX_PAYLOAD_LEN);
    return 0;
}

void __exit xfg_sulog_events_exit(void)
{
    xfg_event_queue_destroy(&sulog_queue);
}

static void xfg_sulog_free_pending(struct xfg_sulog_pending_event *pending)
{
    if (!pending)
        return;
    kfree(pending->payload);
    kfree(pending);
}

struct xfg_sulog_pending_event *xfg_sulog_capture_root_execve(const char __user *filename_user,
                                                              const char __user *const __user *argv_user, gfp_t gfp)
{
    return xfg_sulog_capture(XFG_SULOG_EVENT_ROOT_EXECVE, filename_user, argv_user, gfp);
}

struct xfg_sulog_pending_event *xfg_sulog_capture_sucompat(const char __user *filename_user,
                                                           const char __user *const __user *argv_user, gfp_t gfp)
{
    return xfg_sulog_capture(XFG_SULOG_EVENT_SUCOMPAT, filename_user, argv_user, gfp);
}

void xfg_sulog_emit_pending(struct xfg_sulog_pending_event *pending, int retval, gfp_t gfp)
{
    struct xfg_sulog_event *event;

    if (!pending)
        return;

    event = pending->payload;
    event->retval = retval;
    xfg_event_queue_push(&sulog_queue, pending->event_type, 0, pending->payload, pending->payload_len, gfp);
    xfg_sulog_free_pending(pending);
}

int xfg_sulog_emit_grant_root(int retval, __u32 uid, __u32 euid, gfp_t gfp)
{
    struct xfg_sulog_pending_event *pending;
    struct xfg_sulog_identity identity = {
        .uid = uid,
        .euid = euid,
    };

    pending = xfg_sulog_capture_grant_root(&identity, gfp);
    if (!pending)
        return 0;

    xfg_sulog_emit_pending(pending, retval, gfp);
    return 0;
}

struct xfg_event_queue *xfg_sulog_get_queue(void)
{
    return &sulog_queue;
}
