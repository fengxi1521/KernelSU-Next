#ifndef __XFG_H_KERNEL_UMOUNT
#define __XFG_H_KERNEL_UMOUNT

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rwsem.h>

void xfg_kernel_umount_init(void);
void xfg_kernel_umount_exit(void);

// Handler function to be called from setresuid hook
int xfg_handle_umount(uid_t old_uid, uid_t new_uid);

// for the umount list
struct mount_entry {
    char *umountable;
    unsigned int flags;
    struct list_head list;
};
extern struct list_head mount_list;
extern struct rw_semaphore mount_list_lock;

#endif
