/**
 * Landlock LSM N-API binding for Node.js
 *
 * Exposes landlock_create_ruleset(), landlock_add_rule(), and
 * landlock_restrict_self() syscalls to JavaScript via N-API.
 *
 * Build: node-gyp rebuild
 * Requires: Linux >= 5.13, glibc headers
 */

#include <node_api.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/types.h>

/* Landlock syscall numbers — not yet in glibc headers on all distros */
#ifndef __NR_landlock_create_ruleset
#if defined(__x86_64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule      445
#define __NR_landlock_restrict_self 446
#elif defined(__aarch64__)
#define __NR_landlock_create_ruleset 444
#define __NR_landlock_add_rule      445
#define __NR_landlock_restrict_self 446
#else
#error "Unsupported architecture for Landlock syscall numbers"
#endif
#endif

/* Landlock access flags */
#define LANDLOCK_ACCESS_FS_EXECUTE       (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE    (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE     (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR      (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR    (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE   (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR     (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR      (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG      (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK     (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO     (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK    (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM      (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER         (1ULL << 13)  /* ABI v2 */
#define LANDLOCK_ACCESS_FS_TRUNCATE      (1ULL << 14)  /* ABI v3 */

#define LANDLOCK_RULE_PATH_BENEATH 1

struct landlock_ruleset_attr {
    __u64 handled_access_fs;
};

struct landlock_path_beneath_attr {
    __u64 allowed_access;
    __s32 parent_fd;
} __attribute__((packed));

static inline int landlock_create_ruleset(
    const struct landlock_ruleset_attr *attr, size_t size, __u32 flags) {
    return (int)syscall(__NR_landlock_create_ruleset, attr, size, flags);
}

static inline int landlock_add_rule(
    int ruleset_fd, int rule_type,
    const void *rule_attr, __u32 flags) {
    return (int)syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
                        rule_attr, flags);
}

static inline int landlock_restrict_self(int ruleset_fd, __u32 flags) {
    return (int)syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}

/* Get ABI version by passing NULL attr with size 0 and flags 0 */
static napi_value LandlockGetAbiVersion(napi_env env, napi_callback_info info) {
    int abi = landlock_create_ruleset(NULL, 0, (1U << 0) /* LANDLOCK_CREATE_RULESET_VERSION */);
    napi_value result;
    if (abi < 0) {
        napi_create_int32(env, -1, &result);
    } else {
        napi_create_int32(env, abi, &result);
    }
    return result;
}

/* landlockCreateRuleset(handledAccessFs: bigint) => rulesetFd: number */
static napi_value LandlockCreateRuleset(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    uint64_t handled_access;
    bool lossless;
    napi_get_value_bigint_uint64(env, args[0], &handled_access, &lossless);

    struct landlock_ruleset_attr attr = { .handled_access_fs = handled_access };
    int fd = landlock_create_ruleset(&attr, sizeof(attr), 0);

    napi_value result;
    if (fd < 0) {
        napi_throw_error(env, NULL, strerror(errno));
        napi_get_undefined(env, &result);
    } else {
        napi_create_int32(env, fd, &result);
    }
    return result;
}

/* landlockAddRule(rulesetFd: number, path: string, allowedAccess: bigint) => void */
static napi_value LandlockAddRule(napi_env env, napi_callback_info info) {
    size_t argc = 3;
    napi_value args[3];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    int32_t ruleset_fd;
    napi_get_value_int32(env, args[0], &ruleset_fd);

    char path_buf[4096];
    size_t path_len;
    napi_get_value_string_utf8(env, args[1], path_buf, sizeof(path_buf), &path_len);

    uint64_t allowed_access;
    bool lossless;
    napi_get_value_bigint_uint64(env, args[2], &allowed_access, &lossless);

    int parent_fd = open(path_buf, O_PATH | O_CLOEXEC);
    if (parent_fd < 0) {
        /* Path doesn't exist — skip rule instead of failing */
        napi_value result;
        napi_get_undefined(env, &result);
        return result;
    }

    struct landlock_path_beneath_attr rule = {
        .allowed_access = allowed_access,
        .parent_fd = parent_fd,
    };

    int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
    close(parent_fd);

    if (ret < 0) {
        napi_throw_error(env, NULL, strerror(errno));
    }

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

/* landlockRestrictSelf(rulesetFd: number) => void */
static napi_value LandlockRestrictSelf(napi_env env, napi_callback_info info) {
    size_t argc = 1;
    napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    int32_t ruleset_fd;
    napi_get_value_int32(env, args[0], &ruleset_fd);

    /* Required: no_new_privs must be set before landlock_restrict_self */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        napi_throw_error(env, NULL, "prctl(PR_SET_NO_NEW_PRIVS) failed");
        napi_value result;
        napi_get_undefined(env, &result);
        return result;
    }

    int ret = landlock_restrict_self(ruleset_fd, 0);
    close(ruleset_fd);

    if (ret < 0) {
        napi_throw_error(env, NULL, strerror(errno));
    }

    napi_value result;
    napi_get_undefined(env, &result);
    return result;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor props[] = {
        { "landlockGetAbiVersion", NULL, LandlockGetAbiVersion, NULL, NULL, NULL, napi_default, NULL },
        { "landlockCreateRuleset", NULL, LandlockCreateRuleset, NULL, NULL, NULL, napi_default, NULL },
        { "landlockAddRule",       NULL, LandlockAddRule,       NULL, NULL, NULL, napi_default, NULL },
        { "landlockRestrictSelf",  NULL, LandlockRestrictSelf,  NULL, NULL, NULL, napi_default, NULL },
    };
    napi_define_properties(env, exports, 4, props);

    /* Export access flag constants as BigInt values */
    napi_value val;
    #define EXPORT_CONST(name, v) \
        napi_create_bigint_uint64(env, v, &val); \
        napi_set_named_property(env, exports, name, val);

    EXPORT_CONST("LANDLOCK_ACCESS_FS_EXECUTE",     LANDLOCK_ACCESS_FS_EXECUTE);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_WRITE_FILE",  LANDLOCK_ACCESS_FS_WRITE_FILE);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_READ_FILE",   LANDLOCK_ACCESS_FS_READ_FILE);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_READ_DIR",    LANDLOCK_ACCESS_FS_READ_DIR);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_REMOVE_DIR",  LANDLOCK_ACCESS_FS_REMOVE_DIR);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_REMOVE_FILE", LANDLOCK_ACCESS_FS_REMOVE_FILE);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_MAKE_CHAR",   LANDLOCK_ACCESS_FS_MAKE_CHAR);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_MAKE_DIR",    LANDLOCK_ACCESS_FS_MAKE_DIR);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_MAKE_REG",    LANDLOCK_ACCESS_FS_MAKE_REG);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_MAKE_SOCK",   LANDLOCK_ACCESS_FS_MAKE_SOCK);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_MAKE_FIFO",   LANDLOCK_ACCESS_FS_MAKE_FIFO);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_MAKE_BLOCK",  LANDLOCK_ACCESS_FS_MAKE_BLOCK);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_MAKE_SYM",    LANDLOCK_ACCESS_FS_MAKE_SYM);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_REFER",       LANDLOCK_ACCESS_FS_REFER);
    EXPORT_CONST("LANDLOCK_ACCESS_FS_TRUNCATE",    LANDLOCK_ACCESS_FS_TRUNCATE);

    #undef EXPORT_CONST

    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
