/* Copyright (c) 2020-2021 Alibaba Cloud and Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <enclave-tls/log.h>
#include <enclave-tls/crypto_wrapper.h>
#include "opencrypt.h"

#define OID(N) { 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x8A, 0x39, (N) }

static const unsigned char iasAttestationReportOid[] = OID(0x02);
static const unsigned char iasSigCACertOid[] = OID(0x03);
static const unsigned char iasSigCertOid[] = OID(0x04);
static const unsigned char iasSigOid[] = OID(0x05);
static const unsigned char quoteOid[] = OID(0x06);
static const unsigned char lareportOid[] = OID(0x0e);

crypto_wrapper_err_t opencrypt_gen_cert(crypto_wrapper_ctx_t *ctx,
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
