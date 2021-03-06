/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/enclave_quote.h>

enclave_quote_err_t nullquote_collect_evidence(enclave_quote_ctx_t *ctx,
					       attestation_evidence_t *evidence,
					       enclave_tls_cert_algo_t algo,
					       uint8_t *hash)
{
	ETLS_DEBUG("ctx %p, evidence %p, algo %d, hash %p\n",
		   ctx, evidence, algo, hash);

	return ENCLAVE_QUOTE_ERR_NONE;
}
