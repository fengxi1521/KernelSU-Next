#ifndef __XFG_H_MANAGER_OBSERVER
#define __XFG_H_MANAGER_OBSERVER

#ifdef CONFIG_XFG_DISABLE_MANAGER
static inline int xfg_observer_init(void)
{
    return 0;
}

static inline void xfg_observer_exit(void)
{
}
#else
int xfg_observer_init(void);
void xfg_observer_exit(void);
#endif

#endif // __XFG_H_MANAGER_OBSERVER
