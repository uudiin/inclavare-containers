/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/tls_wrapper.h>
#include "wolfssl_sgx.h"

tls_wrapper_err_t wolfssl_sgx_cleanup(tls_wrapper_ctx_t *ctx)
{
	ETLS_DEBUG("called\n");

	tls_wrapper_err_t err = 0;
	ETLS_DEBUG("enclave_id = %d\n", (int)ctx->enclave_id);
	sgx_status_t sgxret = ecall_wolfssl_cleanup((sgx_enclave_id_t)ctx->enclave_id, &err, ctx);
    if (sgxret != SGX_SUCCESS) {
        ETLS_ERR("ecall_wolfssl_cleanup(), sgxret = %d\n", sgxret);
        return -TLS_WRAPPER_ERR_UNKNOWN;
    }

	return err;
}
