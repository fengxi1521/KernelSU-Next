#ifndef __XFG_H_UID_OBSERVER
#define __XFG_H_UID_OBSERVER

#include <linux/types.h>
#ifdef CONFIG_XFG_DISABLE_MANAGER
static inline void xfg_throne_tracker_init()
{
}

static inline void xfg_throne_tracker_exit()
{
}

static inline void track_throne(bool prune_only)
{
    (void)prune_only;
}
#else
void xfg_throne_tracker_init();

void xfg_throne_tracker_exit();

void track_throne(bool prune_only);
#endif

#endif
