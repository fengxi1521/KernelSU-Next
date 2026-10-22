#ifndef XFG_EVENT_QUEUE_H
#define XFG_EVENT_QUEUE_H

#include <linux/fs.h>
#include <linux/gfp.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/spinlock.h>
#include <linux/types.h>
#include <linux/wait.h>

#define XFG_EVENT_RECORD_FLAG_INTERNAL (1U << 0)
#define XFG_EVENT_QUEUE_TYPE_DROPPED ((__u16)0xFFFF)

struct xfg_event_record_hdr {
    __u16 type;
    __u16 flags;
    __u32 len;
    __u64 seq;
    __u64 ts_ns;
};

struct xfg_event_queue_dropped_info {
    __u64 dropped;
    __u64 first_seq;
    __u64 last_seq;
};

struct xfg_event_queue {
    spinlock_t lock;
    /* The first implementation supports a single reader. */
    struct mutex read_lock;
    struct list_head pending;
    wait_queue_head_t read_wait;
    __u32 queued;
    __u32 max_queued;
    __u32 max_payload_len;
    __u64 next_seq;
    __u64 dropped_total;
    __u64 dropped_pending;
    __u64 dropped_first_seq;
    __u64 dropped_last_seq;
    __u64 dropped_inflight;
    __u64 dropped_inflight_first_seq;
    __u64 dropped_inflight_last_seq;
    bool closed;
};

void xfg_event_queue_init(struct xfg_event_queue *queue, __u32 max_queued, __u32 max_payload_len);
void xfg_event_queue_destroy(struct xfg_event_queue *queue);

int xfg_event_queue_push(struct xfg_event_queue *queue, __u16 type, __u16 flags, const void *payload, __u32 len,
                         gfp_t gfp);
void xfg_event_queue_drop(struct xfg_event_queue *queue);

ssize_t xfg_event_queue_read(struct xfg_event_queue *queue, char __user *buf, size_t count, int file_flags);
__poll_t xfg_event_queue_poll(struct xfg_event_queue *queue, struct file *file, poll_table *wait);

void xfg_event_queue_close(struct xfg_event_queue *queue);
bool xfg_event_queue_has_data(struct xfg_event_queue *queue);

#endif // XFG_EVENT_QUEUE_H
