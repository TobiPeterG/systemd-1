/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "homework.h"
#include "user-record.h"

int home_setup_gocryptfs(UserRecord *h, HomeSetup *setup);

int home_create_gocryptfs(UserRecord *h, HomeSetup *setup, char **effective_passwords, UserRecord **ret_home);

int home_passwd_gocryptfs(UserRecord *h, HomeSetup *setup, char **effective_passwords);
