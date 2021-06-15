/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "opencrypt.h"

crypto_wrapper_err_t opencrypt_cleanup(crypto_wrapper_ctx_t *ctx)
{
	struct opencrypt_ctx *octx = ctx->crypto_private;
	free(octx);
	return CRYPTO_WRAPPER_ERR_NONE;
}
