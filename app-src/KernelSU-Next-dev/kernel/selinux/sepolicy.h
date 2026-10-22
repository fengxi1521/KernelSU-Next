#ifndef __XFG_H_SEPOLICY
#define __XFG_H_SEPOLICY

#include <linux/types.h>

#include "ss/policydb.h"

struct selinux_policy *xfg_dup_sepolicy(struct selinux_policy *old_pol);

int xfg_policydb_fixup_len(struct policydb *db, const char *tag);

void xfg_destroy_sepolicy(struct selinux_policy *orig);

// Operation on types
bool xfg_type(struct policydb *db, const char *name, const char *attr);
bool xfg_attribute(struct policydb *db, const char *name);
bool xfg_permissive(struct policydb *db, const char *type);
bool xfg_enforce(struct policydb *db, const char *type);
bool xfg_typeattribute(struct policydb *db, const char *type, const char *attr);
bool xfg_exists(struct policydb *db, const char *type);

// Access vector rules
bool xfg_allow(struct policydb *db, const char *src, const char *tgt,
               const char *cls, const char *perm);
bool xfg_deny(struct policydb *db, const char *src, const char *tgt,
              const char *cls, const char *perm);
bool xfg_auditallow(struct policydb *db, const char *src, const char *tgt,
                    const char *cls, const char *perm);
bool xfg_dontaudit(struct policydb *db, const char *src, const char *tgt,
                   const char *cls, const char *perm);

// Extended permissions access vector rules
bool xfg_allowxperm(struct policydb *db, const char *src, const char *tgt,
                    const char *cls, const char *range);
bool xfg_auditallowxperm(struct policydb *db, const char *src, const char *tgt,
                         const char *cls, const char *range);
bool xfg_dontauditxperm(struct policydb *db, const char *src, const char *tgt,
                        const char *cls, const char *range);

// Type rules
bool xfg_type_transition(struct policydb *db, const char *src, const char *tgt,
                         const char *cls, const char *def, const char *obj);
bool xfg_type_change(struct policydb *db, const char *src, const char *tgt,
                     const char *cls, const char *def);
bool xfg_type_member(struct policydb *db, const char *src, const char *tgt,
                     const char *cls, const char *def);

// File system labeling
bool xfg_genfscon(struct policydb *db, const char *fs_name, const char *path,
                  const char *ctx);

#endif