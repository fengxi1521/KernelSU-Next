#ifndef __XFG_H_SUPERCALL
#define __XFG_H_SUPERCALL

#include <linux/fs.h>
#include <linux/types.h>
#include <linux/uaccess.h>

// IOCTL handler types
typedef int (*xfg_ioctl_handler_t)(void __user *arg);
typedef bool (*xfg_perm_check_t)(void);

// IOCTL command mapping
struct xfg_ioctl_cmd_map {
    unsigned int cmd;
    const char *name;
    xfg_ioctl_handler_t handler;
    xfg_perm_check_t perm_check; // Permission check function
    bool allow_su_session;
};

// Install XFG fd to current process
int xfg_install_fd(void);
// Install a XFG fd that authorizes operations required while starting su.
int xfg_install_su_fd(void);
bool xfg_is_su_session_fd(const struct file *filp);

void xfg_supercalls_init(void);
void xfg_supercalls_exit(void);
#endif // __XFG_H_SUPERCALL
