#ifndef __XFG_H_MANAGER_IDENTITY
#define __XFG_H_MANAGER_IDENTITY

#include <linux/cred.h>
#include <linux/types.h>

#define XFG_INVALID_APPID -1
#define XFG_PER_USER_RANGE 100000

#ifdef CONFIG_XFG_DISABLE_MANAGER
static inline bool xfg_is_manager_appid_valid()
{
    return true;
}

static inline bool is_manager()
{
    return current_uid().val == 0;
}

static inline bool is_uid_manager(uid_t uid)
{
    return uid == 0;
}

static inline uid_t xfg_get_manager_appid()
{
    return 0;
}

static inline void xfg_set_manager_appid(uid_t appid)
{
    (void)appid;
}

static inline void xfg_invalidate_manager_uid()
{
}
#else
extern uid_t xfg_manager_appid; // DO NOT DIRECT USE

static inline bool xfg_is_manager_appid_valid()
{
    return xfg_manager_appid != XFG_INVALID_APPID;
}

static inline bool is_manager()
{
    return unlikely(xfg_manager_appid == current_uid().val % XFG_PER_USER_RANGE);
}

static inline bool is_uid_manager(uid_t uid)
{
    return unlikely(xfg_manager_appid == uid % XFG_PER_USER_RANGE);
}

static inline uid_t xfg_get_manager_appid()
{
    return xfg_manager_appid;
}

static inline void xfg_set_manager_appid(uid_t appid)
{
    xfg_manager_appid = appid;
}

static inline void xfg_invalidate_manager_uid()
{
    xfg_manager_appid = XFG_INVALID_APPID;
}
#endif

#endif // __XFG_H_MANAGER_IDENTITY
