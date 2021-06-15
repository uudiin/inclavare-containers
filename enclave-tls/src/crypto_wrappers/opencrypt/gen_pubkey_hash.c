/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "opencrypt.h"

#define RSA_PUBKEY_3072_RAW_LEN		398

crypto_wrapper_err_t opencrypt_gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
 			enclave_tls_cert_algo_t algo, uint8_t *hash)
{
	struct opencrypt_ctx *octx;
	unsigned char buffer[4096];
	unsigned char *der = buffer;
	SHA256_CTX md;
	int len;

	if (!ctx || !hash)
		return -CRYPTO_WRAPPER_ERR_INVALID;
	if (algo != ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;

	octx = ctx->crypto_private;

	len = i2d_RSAPublicKey(&octx->key, &der);
	if (len != RSA_PUBKEY_3072_RAW_LEN)
		return -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;

	SHA256(buffer, len, hash);

	return CRYPTO_WRAPPER_ERR_NONE;
}
