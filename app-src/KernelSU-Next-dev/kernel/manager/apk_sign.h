#ifndef __XFG_H_APK_V2_SIGN
#define __XFG_H_APK_V2_SIGN

#include <linux/types.h>

bool is_manager_apk(char *path);
int get_pkg_from_apk_dir_path(char *pkg, const char *path);

#endif
