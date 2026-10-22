#include <linux/cache.h>
#include <linux/compiler_types.h>

#include "feature/sulog.h"
#include "klog.h" // IWYU pragma: keep
#include "policy/feature.h"
#include "sulog/event.h"
#include "sulog/fd.h"

static bool xfg_sulog_enabled __read_mostly = false;

static int sulog_feature_get(u64 *value)
{
    *value = xfg_sulog_enabled ? 1 : 0;
    return 0;
}

static int sulog_feature_set(u64 value)
{
    bool enable = value != 0;

    xfg_sulog_enabled = enable;
    pr_info("sulog: set to %d\n", enable);
    return 0;
}

static const struct xfg_feature_handler sulog_handler = {
    .feature_id = XFG_FEATURE_SULOG,
    .name = "sulog",
    .get_handler = sulog_feature_get,
    .set_handler = sulog_feature_set,
};

bool xfg_sulog_is_enabled(void)
{
    return xfg_sulog_enabled;
}

void __init xfg_sulog_init(void)
{
    int ret;

    xfg_sulog_enabled = false;

    ret = xfg_register_feature_handler(&sulog_handler);
    if (ret) {
        pr_err("Failed to register sulog feature handler\n");
        return;
    }

    ret = xfg_sulog_events_init();
    if (ret) {
        pr_err("Failed to initialize sulog events: %d\n", ret);
        xfg_unregister_feature_handler(XFG_FEATURE_SULOG);
        return;
    }

    xfg_sulog_fd_init();
}

void __exit xfg_sulog_exit(void)
{
    xfg_sulog_fd_exit();
    xfg_sulog_events_exit();
    xfg_unregister_feature_handler(XFG_FEATURE_SULOG);
}
