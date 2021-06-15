/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _OPENCRYPT_H
#define _OPENCRYPT_H

#include <openssl/rsa.h>
#include <openssl/x509.h>

struct opencrypt_ctx {
	RSA *key;
};

#endif
