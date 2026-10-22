#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/sched.h>

#include "infra/event_queue.h"
#include "klog.h" // IWYU pragma: keep
#include "sulog/event.h"

static DEFINE_MUTEX(xfg_sulog_fd_lock);
static bool xfg_sulog_fd_active;

static ssize_t xfg_sulog_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    return xfg_event_queue_read(xfg_sulog_get_queue(), buf, count, file->f_flags);
}

static __poll_t xfg_sulog_poll(struct file *file, poll_table *wait)
{
    return xfg_event_queue_poll(xfg_sulog_get_queue(), file, wait);
}

static int xfg_sulog_release(struct inode *inode, struct file *file)
{
    mutex_lock(&xfg_sulog_fd_lock);
    xfg_sulog_fd_active = false;
    mutex_unlock(&xfg_sulog_fd_lock);

    pr_info("sulog: fd released\n");
    return 0;
}

static const struct file_operations xfg_sulog_fops = {
    .owner = THIS_MODULE,
    .read = xfg_sulog_read,
    .poll = xfg_sulog_poll,
    .release = xfg_sulog_release,
    .llseek = noop_llseek,
};

int xfg_install_sulog_fd(void)
{
    struct file *filp;
    int fd;

    mutex_lock(&xfg_sulog_fd_lock);

    if (xfg_sulog_fd_active) {
        fd = -EBUSY;
        goto out_unlock;
    }

    if (READ_ONCE(xfg_sulog_get_queue()->closed)) {
        fd = -EPIPE;
        goto out_unlock;
    }

    fd = get_unused_fd_flags(O_CLOEXEC);
    if (fd < 0)
        goto out_unlock;

    filp = anon_inode_getfile("[xfg_sulog]", &xfg_sulog_fops, NULL, O_RDONLY | O_CLOEXEC);
    if (IS_ERR(filp)) {
        put_unused_fd(fd);
        fd = PTR_ERR(filp);
        goto out_unlock;
    }

    xfg_sulog_fd_active = true;
    fd_install(fd, filp);
    pr_info("sulog: fd installed %d for pid %d\n", fd, current->pid);

out_unlock:
    mutex_unlock(&xfg_sulog_fd_lock);
    return fd;
}

void __init xfg_sulog_fd_init(void)
{
    mutex_lock(&xfg_sulog_fd_lock);
    xfg_sulog_fd_active = false;
    mutex_unlock(&xfg_sulog_fd_lock);
}

void __exit xfg_sulog_fd_exit(void)
{
    mutex_lock(&xfg_sulog_fd_lock);
    xfg_sulog_fd_active = false;
    mutex_unlock(&xfg_sulog_fd_lock);

    xfg_event_queue_close(xfg_sulog_get_queue());
}
