/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <enclave-tls/crypto_wrapper.h>
#include <enclave-tls/log.h>
#include <enclave-tls/cert.h>

#define RSA_PUBKEY_3072_RAW_LEN		398

#define OID(N) { 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N) }

static const unsigned char iasAttestationReportOid[] = OID(0x02);
static const unsigned char iasSigCACertOid[] = OID(0x03);
static const unsigned char iasSigCertOid[] = OID(0x04);
static const unsigned char iasSigOid[] = OID(0x05);
static const unsigned char quoteOid[] = OID(0x06);
static const unsigned char lareportOid[] = OID(0x0e);

struct opencrypt_ctx {
	RSA *key;
};

static crypto_wrapper_err_t init(crypto_wrapper_ctx_t *ctx)
{
	struct opencrypt_ctx *octx;

	octx = calloc(1, sizeof(*octx));
	if (!octx)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	ctx->crypto_private = octx;

	return CRYPTO_WRAPPER_ERR_NONE;
}

static crypto_wrapper_err_t __secured gen_privkey(crypto_wrapper_ctx_t *ctx,
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

static crypto_wrapper_err_t gen_pubkey_hash(crypto_wrapper_ctx_t *ctx,
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

static crypto_wrapper_err_t gen_cert(crypto_wrapper_ctx_t *ctx,
 			       enclave_tls_cert_info_t *cert_info)
{
	struct opencrypt_ctx *octx;
	cert_subject_t *subject;
	X509 *cert = NULL;
	X509_NAME *name;
	EVP_PKEY *pkey = NULL;
	ASN1_OBJECT obj;
	ASN1_OBJECT_STRING v;
	X509_EXTENSION ext;
	unsigned char *der;
	int len;
	int ret;

	if (!ctx || !cert_info)
		return -CRYPTO_WRAPPER_ERR_INVALID;

	octx = ctx->crypto_private;

	pkey = EVP_PKEY_new();
	if (!pkey)
		return -CRYPTO_WRAPPER_ERR_NO_MEM;

	ret = -CRYPTO_WRAPPER_ERR_PRIV_KEY_LEN;
	if (!EVP_PKEY_assign_RSA(pkey, octx->key))
		goto err;

	ret = -CRYPTO_WRAPPER_ERR_NO_MEM;
	cert = X509_new();
	if (!cert)
		goto err;

	X509_set_version(cert, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x509), 9527);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	/* 10 years */
	X509_gmtime_adj(X509_get_notAfter(x509), 3600 * 24 * 365 * 10);

	ret = -CRYPTO_WRAPPER_ERR_PUB_KEY_LEN;
	if (!X509_set_pubkey(cert, pkey))
		goto err;

	/* subject name */
	name = X509_get_subject_name(cert);
	if (!name)
		goto err;

	subject = &cert_info->subject;
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
			subject->organization, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC,
			subject->organization_unit, -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
			subject->common_name, -1, -1, 0);
	if (!X509_set_issuer_name(cert, name))
		goto err;

	obj.length = sizeof(iasAttestationReportOid);
	ext.object = &obj;
	ext.critical = 0;
	ext.value = &v;

	ret = -CRYPTO_WRAPPER_ERR_PUB_KEY_DECODE;

	if (strcmp(cert_info->evidence.type, "sgx_epid") == 0) {
		attestation_verification_report_t *epid = &cert_info->evidence.epid;

		obj.data = iasAttestationReportOid;
		v.data = epid->ias_report;
		v.length = epid->ias_report_len;
		if (!X509_add_ext(cert, &ext, -1))
			goto err;

		obj.data = iasSigCACertOid;
		v.data = epid->ias_sign_ca_cert;
		v.length = epid->ias_sign_ca_cert_len;
		if (!X509_add_ext(cert, &ext, -1))
			goto err;

		obj.data = iasSigCertOid;
		v.data = epid->ias_sign_cert;
		v.length = epid->ias_sign_cert_len;
		if (!X509_add_ext(cert, &ext, -1))
			goto err;

		obj.data = iasSigOid;
		v.data = epid->ias_report_signature;
		v.length = epid->ias_report_signature_len;
		if (!X509_add_ext(cert, &ext, -1))
			goto err;
	} else if (strcmp(cert_info->evidence.type, "sgx_ecdsa") == 0) {
		ecdsa_attestation_evidence_t *ecdsa = &cert_info->evidence.ecdsa;

		obj.data = quoteOid;
		v.data = ecdsa->quote;
		v.length = ecdsa->quote_len;
		if (!X509_add_ext(cert, &ext, -1))
			goto err;
	} else if (strcmp(cert_info->evidence.type, "sgx_la") == 0) {
		la_attestation_evidence_t *la = &cert_info->evidence.la;

		obj.data = lareportOid;
		v.data = la->report;
		v.length = la->report_len;
		if (!X509_add_ext(cert, &ext, -1))
			goto err;
	}

	ret = -CRYPTO_WRAPPER_ERR_CERT;
	if (!X509_sign(cert, pkey, EVP_sha256()))
		goto err;

	der = cert_info->cert_buf;
	len = i2d_X509(cert, &der);
	if (len < 0)
		goto err;
	cert_info->cert_len = len;

	ret = CRYPTO_WRAPPER_ERR_NONE;

err:
	if (cert)
		X509_free(cert);
	if (pkey)
		EVP_PKEY_free(pkey);
	return ret;
}

static crypto_wrapper_err_t cleanup(crypto_wrapper_ctx_t *ctx)
{
	struct opencrypt_ctx *octx = ctx->crypto_private;
	free(octx);
	return CRYPTO_WRAPPER_ERR_NONE;
}

static const crypto_wrapper_opts_t opencrypt_opts = {
	.api_version		= CRYPTO_WRAPPER_API_VERSION_DEFAULT,
	.name			= "opencrypt",
	.priority		= 20,
	.init			= init,
	.gen_privkey		= gen_privkey,
	.gen_pubkey_hash	= gen_pubkey_hash,
	.gen_cert		= gen_cert,
	.cleanup		= cleanup,
};

static void __attribute__((constructor)) libcrypto_wrapper_wolfcrypt_init(void)
{
	ETLS_DEBUG("called\n");

	crypto_wrapper_err_t err = crypto_wrapper_register(&opencrypt_opts);
	if (err != CRYPTO_WRAPPER_ERR_NONE)
		ETLS_ERR("failed to register the crypto wrapper 'opencrypt' %#x\n", err);
}
