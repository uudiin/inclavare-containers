/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "opencrypt.h"

crypto_wrapper_err_t __secured opencrypt_gen_privkey(crypto_wrapper_ctx_t *ctx,
				enclave_tls_cert_algo_t algo,
				uint8_t *privkey_buf, unsigned int *privkey_len)
{
	struct opencrypt_ctx *octx;
	unsigned char buffer[4096];
	unsigned char *der = buffer;
	BIGNUM e;
	int len;
	int ret;

	if (!ctx || !privkey_len)
		return -CRYPTO_WRAPPER_ERR_INVALID;
	if (privkey_buf == NULL && *privkey_len == 0)
		return -CRYPTO_WRAPPER_ERR_INVALID;
	if (algo != ENCLAVE_TLS_CERT_ALGO_RSA_3072_SHA256)
		return -CRYPTO_WRAPPER_ERR_UNSUPPORTED_ALGO;

	octx = ctx->crypto_private;

	ret = -CRYPTO_WRAPPER_ERR_NO_MEM;
	octx->key = RSA_new();
	if (octx->key == NULL)
		goto err;

	ret = -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;
	BN_set_word(&e, 65537);
	if (!RSA_generate_key_ex(octx->key, 3072, &e, NULL))
		goto err;

	ret = -CRYPTO_WRAPPER_ERR_RSA_KEY_LEN;
	if (privkey_buf)
		der = privkey_buf;
	len = i2d_RSAPrivateKey(&octx->key, &der);
	if (len < 0)
		goto err;

	*privkey_len = len;
	return CRYPTO_WRAPPER_ERR_NONE;

err:
	if (octx->key) {
		RSA_free(octx->key);
		octx->key = NULL;
	}
	return ret;
}
