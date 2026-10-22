#ifndef __XFG_H_FEATURE
#define __XFG_H_FEATURE

#include <linux/types.h>
#include "uapi/feature.h" // IWYU pragma: keep

typedef int (*xfg_feature_get_t)(u64 *value);
typedef int (*xfg_feature_set_t)(u64 value);

struct xfg_feature_handler {
	u32 feature_id;
	const char *name;
	xfg_feature_get_t get_handler;
	xfg_feature_set_t set_handler;
};

int xfg_register_feature_handler(const struct xfg_feature_handler *handler);

int xfg_unregister_feature_handler(u32 feature_id);

int xfg_get_feature(u32 feature_id, u64 *value, bool *supported);

int xfg_set_feature(u32 feature_id, u64 value);

// Whether the feature is forced by the force_feature module param, in which
// case xfg_set_feature() refuses to change it.
bool xfg_feature_is_forced(u32 feature_id);

// Apply forced feature values not applied yet. Called at several boot stages
// since some handlers can only succeed late (e.g. selinux_hide needs the
// sepolicy backup).
void xfg_feature_apply_forced(void);

void xfg_feature_init(void);

void xfg_feature_exit(void);

#endif // __XFG_H_FEATURE
