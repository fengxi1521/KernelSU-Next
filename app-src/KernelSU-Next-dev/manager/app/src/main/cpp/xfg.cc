//
// Created by XiaoFeng on 2022/12/9.
//

#include <sys/prctl.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <unistd.h>
#include <utility>
#include <android/log.h>
#include <dirent.h>
#include <cstdlib>

#include <unistd.h>
#include <climits>
#include <sys/syscall.h>
#include <cerrno>
#include "xfg.h"

static int fd = -1;

static inline int scan_driver_fd() {
    const char *kName = "[xfg_driver]";
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) {
        return -1;
    }

    int found = -1;
    struct dirent *de;
    char path[64];
    char target[PATH_MAX];

    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') {
            continue;
        }

        char *endptr = NULL;
        long fd_long = strtol(de->d_name, &endptr, 10);
        if (!de->d_name[0] || *endptr != '\0' || fd_long < 0 || fd_long > INT_MAX) {
            continue;
        }

        snprintf(path, sizeof(path), "/proc/self/fd/%s", de->d_name);
        ssize_t n = readlink(path, target, sizeof(target) - 1);
        if (n < 0) {
            continue;
        }
        target[n] = '\0';

        const char *base = strrchr(target, '/');
        base = base ? base + 1 : target;

        if (strstr(base, kName)) {
            found = (int)fd_long;
            break;
        }
    }

    closedir(dir);
    return found;
}

template<typename... Args>
static int xfgctl(unsigned long op, Args &&... args) {

    if (fd < 0) {
        fd = scan_driver_fd();
    }

    static_assert(sizeof...(Args) <= 1, "ioctl expects at most one extra argument");

    return ioctl(fd, op, std::forward<Args>(args)...);
}

static struct xfg_get_info_cmd g_version {};

struct xfg_get_info_cmd get_info() {
    if (!g_version.version) {
        if (xfgctl(XFG_IOCTL_GET_INFO, &g_version) < 0) {
            xfgctl(XFG_IOCTL_GET_INFO_LEGACY, &g_version);
            g_version.uapi_version = 0;
        }
    }
    return g_version;
}

uint32_t get_kernel_uapi_version() {
    auto info = get_info();
    return info.uapi_version;
}

uint32_t get_manager_uapi_version() {
    return KERNEL_SU_UAPI_VERSION;
}

uint32_t get_version() {
    auto info = get_info();
    return info.version;
}

bool get_allow_list(struct xfg_new_get_allow_list_cmd *cmd) {
    return xfgctl(XFG_IOCTL_NEW_GET_ALLOW_LIST, cmd) == 0;
}

bool is_safe_mode() {
    struct xfg_check_safemode_cmd cmd = {};
    xfgctl(XFG_IOCTL_CHECK_SAFEMODE, &cmd);
    return cmd.in_safe_mode;
}

bool is_lkm_mode() {
    auto info = get_info();
    if (info.version > 0) {
        return (info.flags & XFG_GET_INFO_FLAG_LKM) != 0;
    }
    return (legacy_get_info().second & XFG_GET_INFO_FLAG_LKM) != 0;
}

bool is_lkm_bundled() {
    auto info = get_info();
    return (info.flags & XFG_GET_INFO_FLAG_LKM) != 0 &&
           (info.flags & XFG_GET_INFO_FLAG_BUNDLED) != 0;
}

bool is_late_load_mode() {
    auto info = get_info();
    if (info.version > 0) {
        return (info.flags & XFG_GET_INFO_FLAG_LATE_LOAD) != 0;
    }
    return false;
}

bool is_manager() {
    auto info = get_info();
    if (info.version > 0) {
        return (info.flags & XFG_GET_INFO_FLAG_MANAGER) != 0;
    }
    return legacy_get_info().first > 0;
}

bool uid_should_umount(int uid) {
    struct xfg_uid_should_umount_cmd cmd = {};
    cmd.uid = uid;
    xfgctl(XFG_IOCTL_UID_SHOULD_UMOUNT, &cmd);
    return cmd.should_umount;
}

bool set_app_profile(const app_profile *profile) {
    struct xfg_set_app_profile_cmd cmd = {};
    cmd.profile = *profile;
    return xfgctl(XFG_IOCTL_SET_APP_PROFILE, &cmd) == 0;
}

int get_app_profile(app_profile *profile) {
    struct xfg_get_app_profile_cmd cmd = {.profile = *profile};
    int ret = xfgctl(XFG_IOCTL_GET_APP_PROFILE, &cmd);
    *profile = cmd.profile;
    return ret;
}

bool set_su_enabled(bool enabled) {
    struct xfg_set_feature_cmd cmd = {};
    cmd.feature_id = XFG_FEATURE_SU_COMPAT;
    cmd.value = enabled ? 1 : 0;
    return xfgctl(XFG_IOCTL_SET_FEATURE, &cmd) == 0;
}

bool is_su_enabled() {
    struct xfg_get_feature_cmd cmd = {};
    cmd.feature_id = XFG_FEATURE_SU_COMPAT;
    if (xfgctl(XFG_IOCTL_GET_FEATURE, &cmd) != 0) {
        return false;
    }
    if (!(cmd.supported & XFG_FEATURE_FLAG_SUPPORTED)) {
        return false;
    }
    return cmd.value != 0;
}

static inline bool get_feature(uint32_t feature_id, uint64_t *out_value, bool *out_supported) {
    struct xfg_get_feature_cmd cmd = {};
    cmd.feature_id = feature_id;
    if (xfgctl(XFG_IOCTL_GET_FEATURE, &cmd) != 0) {
        return false;
    }
    if (out_value) *out_value = cmd.value;
    if (out_supported) *out_supported = cmd.supported & XFG_FEATURE_FLAG_SUPPORTED;
    return true;
}

static inline bool set_feature(uint32_t feature_id, uint64_t value) {
    struct xfg_set_feature_cmd cmd = {};
    cmd.feature_id = feature_id;
    cmd.value = value;
    return xfgctl(XFG_IOCTL_SET_FEATURE, &cmd) == 0;
}

bool set_kernel_umount_enabled(bool enabled) {
    return set_feature(XFG_FEATURE_KERNEL_UMOUNT, enabled ? 1 : 0);
}

bool is_kernel_umount_enabled() {
    uint64_t value = 0;
    bool supported = false;
    if (!get_feature(XFG_FEATURE_KERNEL_UMOUNT, &value, &supported)) {
        return false;
    }
    if (!supported) {
        return false;
    }
    return value != 0;
}

bool set_adb_root_enabled(bool enabled) {
    return set_feature(XFG_FEATURE_ADB_ROOT, enabled ? 1 : 0);
}

bool is_adb_root_enabled() {
    uint64_t value = 0;
    bool supported = false;
    if (!get_feature(XFG_FEATURE_ADB_ROOT, &value, &supported)) {
        return false;
    }
    if (!supported) {
        return false;
    }
    return value != 0;
}

int set_selinux_hide_enabled(bool enabled) {
    if (!set_feature(XFG_FEATURE_SELINUX_HIDE, enabled ? 1 : 0)) {
        return -errno;
    }
    return 0;
}

bool is_selinux_hide_enabled() {
    uint64_t value = 0;
    bool supported = false;
    if (!get_feature(XFG_FEATURE_SELINUX_HIDE, &value, &supported)) {
        return false;
    }
    if (!supported) {
        return false;
    }
    return value != 0;
}

bool set_avc_spoof_enabled(bool enabled) {
    struct xfg_set_feature_cmd cmd = {};
    cmd.feature_id = XFG_FEATURE_AVC_SPOOF;
    cmd.value = enabled ? 1 : 0;
    return xfgctl(XFG_IOCTL_SET_FEATURE, &cmd) == 0;
}

bool is_avc_spoof_enabled() {
    struct xfg_get_feature_cmd cmd = {};
    cmd.feature_id = XFG_FEATURE_AVC_SPOOF;
    if (xfgctl(XFG_IOCTL_GET_FEATURE, &cmd) != 0) {
        return false;
    }
    if (!cmd.supported) {
        return false;
    }
    return cmd.value != 0;
}

const char* get_hook_mode(void)
{
    static struct xfg_get_hook_mode_cmd cmd = {0};

    if (xfgctl(XFG_IOCTL_GET_HOOK_MODE, &cmd) == 0)
        return cmd.mode;

    return "Unknown";
}

uid_t get_manager_appid(void)
{
    static struct xfg_get_manager_appid_cmd cmd = {0};

    if (xfgctl(XFG_IOCTL_GET_MANAGER_APPID, &cmd) == 0)
        return cmd.appid;

    return 0;
}

const char* get_version_tag(void)
{
    static struct xfg_get_version_tag_cmd cmd = {0};

    if (xfgctl(XFG_IOCTL_GET_VERSION_TAG, &cmd) == 0)
        return cmd.tag;

    return "Unknown";
}

bool is_zygisk_enabled() {
    return !!getenv("ZYGISK_ENABLED");
}
