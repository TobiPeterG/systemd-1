/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/fs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/xattr.h>

#include "errno-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "homework-gocryptfs.h"
#include "homework-mount.h"
#include "homework-quota.h"
#include "memory-util.h"
#include "missing_keyctl.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "mount-util.h"
#include "nulstr-util.h"
#include "openssl-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "random-util.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "xattr-util.h"

static int is_gocryptfs_directory_fd(int dir_fd){
        /* Check if the directory is already a gocryptfs encrypted directory.
           This can be done by checking for the presence of the gocryptfs.conf file */
        struct stat st;
        if (fstatat(dir_fd, "gocryptfs.conf", &st, 0) < 0) {
                if (errno == ENOENT) {
                        return errno;
                } else
                        return -errno;
        }
        return 0;
}

static int gocryptfs_run_command(const char *command, const char *input) {
        assert(command);
        assert(input);

        FILE *fp = popen(command, "w");
        if (!fp)
                return log_error_errno(errno, "Failed to run command: %s: %m", command);

        fputs(input, fp);

        int ret = pclose(fp);
        if (ret == -1)
                return log_error_errno(errno, "Failed to close command stream: %m");

        return ret;
}

static int gocryptfs_setup(const char *image_path, char **password) {
        assert(image_path);
        assert(password);
        int r;

        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        char command[1024];
        char input[1024];

        // Construct the gocryptfs init command
        snprintf(command, sizeof(command), "gocryptfs -init %s", image_path);
        snprintf(input, sizeof(input), "y\n%s\n%s", password[0], password[0]);

        // We'll pass the password to stdin of the gocryptfs process
        int result = gocryptfs_run_command(command, input);
        if (result != 0)
                return log_error_errno(errno, "Failed to initialize gocryptfs at %s: %m", image_path);

        return 0;
}

static int gocryptfs_mount(const char *image_path, const char *root_path, char **passwords) {
        assert(image_path);
        assert(passwords);

        char command[1024];
        snprintf(command, sizeof(command), "gocryptfs %s %s", image_path, root_path);

        STRV_FOREACH(pp, passwords) {
                // Attempt to mount using the current password
                int result = gocryptfs_run_command(command, *pp);
                if (result == 0) {
                        // Mount was successful with this password
                        return 0;
                }

                // Log the failed attempt but don't return yet; try the next password
                log_debug_errno(result,
                                "Password %zu didn't work for mounting gocryptfs directory %s at %s: %m",
                                (size_t) (pp - passwords),
                                image_path,
                                root_path);
        }

        // None of the passwords worked, return an error
        return log_error_errno(
                        ENOKEY,
                        "Failed to mount gocryptfs directory %s at %s using provided passwords.",
                        image_path,
                        root_path);
}


static int gocryptfs_set_password(const char *config_path, char **old_passwords, char **new_password) {
        assert(config_path);
        assert(old_passwords);
        assert(new_password);

        char command[1024];
        snprintf(command, sizeof(command), "gocryptfs -config %s -passwd", config_path);

        STRV_FOREACH(pp, old_passwords) {
                char combined_passwords[1024];
                snprintf(combined_passwords, sizeof(combined_passwords), "%s\n%s", *pp, new_password[0]);

                int result = gocryptfs_run_command(command, combined_passwords);
                if (result == 0) {
                        // Password change was successful with this old password
                        return 0;
                }

                // Log the failed attempt but don't return yet; try the next old password
                log_debug_errno(result,
                                "Password %zu didn't work for unlocking gocryptfs at %s: %m",
                                (size_t) (pp - old_passwords),
                                config_path);
        }

        // None of the old passwords worked, return an error
        return -ENOKEY; // No key available error
}


int home_setup_gocryptfs(UserRecord *h, HomeSetup *setup) {

        const char *ip;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_GOCRYPTFS);
        assert(setup);
        assert(setup->root_fd < 0);

        assert_se(ip = user_record_image_path(h));

        setup->root_fd = open(ip, O_RDONLY | O_CLOEXEC | O_DIRECTORY);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open home directory: %m");

        r = is_gocryptfs_directory_fd(setup->image_fd);
        if (r < 0)
                return log_error_errno(errno, "Home directory %s is not encrypted: %m.", ip);
        if (r > 0)
                return log_error_errno(
                                        errno, "Failed to check if home directory %s is encrypted: %m", ip);

        r = gocryptfs_mount(ip, user_record_home_directory(h), h->password);
        if (r < 0)
                return log_error_errno(errno, "Failed to mount gocryptfs encrypted directory %s: %m.", ip);

        /* Post-mount steps, such as binding the mounted directory, adjusting flags, etc. */
        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        r = mount_follow_verbose(LOG_ERR, ip, HOME_RUNTIME_WORK_DIR, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        setup->undo_mount = true;

        r = mount_nofollow_verbose(LOG_ERR, NULL, HOME_RUNTIME_WORK_DIR, NULL, MS_PRIVATE, NULL);
        if (r < 0)
                return r;

        r = mount_nofollow_verbose(
                        LOG_ERR,
                        NULL,
                        HOME_RUNTIME_WORK_DIR,
                        NULL,
                        MS_BIND | MS_REMOUNT | user_record_mount_flags(h),
                        NULL);
        if (r < 0)
                return r;

        safe_close(setup->root_fd);
        setup->root_fd = open(HOME_RUNTIME_WORK_DIR, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
        if (setup->root_fd < 0)
                return log_error_errno(errno, "Failed to open home directory: %m");

        return 0;
}

int home_create_gocryptfs(UserRecord *h, HomeSetup *setup, char **effective_passwords, UserRecord **ret_home) {

        _cleanup_(user_record_unrefp) UserRecord *new_home = NULL;
        _cleanup_free_ char *d = NULL;
        const char *ip;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_GOCRYPTFS);
        assert(setup);
        assert(ret_home);

        assert_se(ip = user_record_image_path(h));

        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        // Initialize gocryptfs on the directory
        r = gocryptfs_setup(ip, effective_passwords);
        if (r < 0)
                return r;

        r = gocryptfs_mount(ip, user_record_home_directory(h), effective_passwords);
        if (r < 0)
                return log_error_errno(errno, "Failed to mount gocryptfs encrypted directory %s: %m.", ip);

        r = home_populate(h, setup->root_fd);
        if (r < 0)
                return r;

        r = home_sync_and_statfs(setup->root_fd, NULL);
        if (r < 0)
                return r;

        r = user_record_clone(h, USER_RECORD_LOAD_MASK_SECRET | USER_RECORD_PERMISSIVE, &new_home);
        if (r < 0)
                return log_error_errno(r, "Failed to clone record: %m");

        r = user_record_add_binding(
                        new_home,
                        USER_GOCRYPTFS,
                        ip,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        SD_ID128_NULL,
                        NULL,
                        NULL,
                        UINT64_MAX,
                        NULL,
                        NULL,
                        h->uid,
                        (gid_t) h->uid);
        if (r < 0)
                return log_error_errno(r, "Failed to add binding to record: %m");

        setup->root_fd = safe_close(setup->root_fd);

        log_info("Everything completed.");

        *ret_home = TAKE_PTR(new_home);
        return 0;
}

int home_passwd_gocryptfs(UserRecord *h, HomeSetup *setup, char **new_passwords) {

        _cleanup_free_ char *config_path = NULL;
        const char *ip;
        int r;

        assert(h);
        assert(user_record_storage(h) == USER_GOCRYPTFS);
        assert(setup);
        assert_se(ip = user_record_image_path(h));

        /* Generate the path to the gocryptfs.conf file */
        r = asprintf(&config_path, "%s/gocryptfs.conf", ip);
        if (r < 0)
                return log_error_errno(r, "Failed to determine gocryptfs config path: %m");

        r = gocryptfs_set_password(config_path, h->password, new_passwords);
        if (r < 0)
                return log_error_errno(r, "Failed to change gocryptfs password: %m");

        return 0;
}
