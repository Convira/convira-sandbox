/**
 * seccomp BPF profile compiler — N-API binding
 *
 * Converts OCI/Docker-format JSON seccomp profiles into raw BPF
 * bytecode that can be passed to bubblewrap's --seccomp <fd>.
 *
 * Requires: libseccomp-dev (apt install libseccomp-dev)
 * Build: node-gyp rebuild
 */

#include <node_api.h>
#include <seccomp.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/**
 * compileSeccompToFd(syscallNames: string[], defaultAction: string) => fd: number
 *
 * Takes an array of allowed syscall names and a default action string,
 * creates a seccomp-bpf filter, and returns an fd to the exported BPF
 * program (via memfd_create or a temp file).
 */
static napi_value CompileSeccompToFd(napi_env env, napi_callback_info info) {
    size_t argc = 2;
    napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);

    /* arg 0: string[] of syscall names */
    uint32_t array_len;
    napi_get_array_length(env, args[0], &array_len);

    /* arg 1: default action string ("SCMP_ACT_ERRNO" or "SCMP_ACT_KILL") */
    char action_buf[64];
    size_t action_len;
    napi_get_value_string_utf8(env, args[1], action_buf, sizeof(action_buf), &action_len);

    uint32_t default_action = SCMP_ACT_ERRNO(EPERM);
    if (strcmp(action_buf, "SCMP_ACT_KILL") == 0) {
        default_action = SCMP_ACT_KILL;
    } else if (strcmp(action_buf, "SCMP_ACT_KILL_PROCESS") == 0) {
        default_action = SCMP_ACT_KILL_PROCESS;
    } else if (strcmp(action_buf, "SCMP_ACT_LOG") == 0) {
        default_action = SCMP_ACT_LOG;
    }

    scmp_filter_ctx ctx = seccomp_init(default_action);
    if (ctx == NULL) {
        napi_throw_error(env, NULL, "seccomp_init failed");
        napi_value undef;
        napi_get_undefined(env, &undef);
        return undef;
    }

    /* Add architecture support */
    seccomp_arch_add(ctx, SCMP_ARCH_X86_64);
    seccomp_arch_add(ctx, SCMP_ARCH_AARCH64);

    /* Add allow rules for each syscall name */
    for (uint32_t i = 0; i < array_len; i++) {
        napi_value elem;
        napi_get_element(env, args[0], i, &elem);

        char name[128];
        size_t name_len;
        napi_get_value_string_utf8(env, elem, name, sizeof(name), &name_len);

        int syscall_nr = seccomp_syscall_resolve_name(name);
        if (syscall_nr == __NR_SCMP_ERROR) {
            /* Unknown syscall — skip silently (may be arch-specific) */
            continue;
        }

        int ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
        if (ret < 0 && ret != -EEXIST) {
            /* Rule add failed but not a duplicate — skip */
            continue;
        }
    }

    /* Export to a file descriptor via memfd_create */
#if defined(__aarch64__)
    int memfd = (int)syscall(279 /* __NR_memfd_create (aarch64) */, "seccomp_bpf", 1 /* MFD_CLOEXEC */);
#else
    int memfd = (int)syscall(319 /* __NR_memfd_create (x86_64) */, "seccomp_bpf", 1 /* MFD_CLOEXEC */);
#endif
    if (memfd < 0) {
        /* Fallback: use a temp file */
        char tmppath[] = "/tmp/convira-seccomp-XXXXXX";
        memfd = mkstemp(tmppath);
        if (memfd < 0) {
            seccomp_release(ctx);
            napi_throw_error(env, NULL, "Failed to create temp file for BPF export");
            napi_value undef;
            napi_get_undefined(env, &undef);
            return undef;
        }
        unlink(tmppath);
    }

    int ret = seccomp_export_bpf(ctx, memfd);
    seccomp_release(ctx);

    if (ret < 0) {
        close(memfd);
        napi_throw_error(env, NULL, "seccomp_export_bpf failed");
        napi_value undef;
        napi_get_undefined(env, &undef);
        return undef;
    }

    /* Rewind fd to start so the consumer can read the BPF program */
    lseek(memfd, 0, SEEK_SET);

    napi_value result;
    napi_create_int32(env, memfd, &result);
    return result;
}

/**
 * isSeccompSupported() => boolean
 *
 * Checks whether seccomp is available on this system.
 */
static napi_value IsSeccompSupported(napi_env env, napi_callback_info info) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    napi_value result;
    if (ctx) {
        seccomp_release(ctx);
        napi_get_boolean(env, true, &result);
    } else {
        napi_get_boolean(env, false, &result);
    }
    return result;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_property_descriptor props[] = {
        { "compileSeccompToFd", NULL, CompileSeccompToFd, NULL, NULL, NULL, napi_default, NULL },
        { "isSeccompSupported", NULL, IsSeccompSupported, NULL, NULL, NULL, napi_default, NULL },
    };
    napi_define_properties(env, exports, 2, props);
    return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
