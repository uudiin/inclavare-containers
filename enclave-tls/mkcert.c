
#include <stdio.h>
#include <assert.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/asn1.h>


static void hex_dump(const char *prefix, const void *p, unsigned int len)
{
    char buffer[256];
    int i = 0;
    const unsigned char *buf = p;

    for ( ; len > 0; len--) {
        sprintf(&buffer[i * 2], "%02x", *buf++);
        i += 1;
        if (i == 32) {
            buffer[i * 2] = '\0';
            fprintf(stdout, "%s%s\n", prefix, buffer);
            i = 0;
        }
    }
    if (i > 0) {
        buffer[i * 2] = '\0';
        fprintf(stdout, "%s%s\n", prefix, buffer);
    }
}

static RSA *gen_privkey(void)
{
    RSA *key;
    BIGNUM *e;
    unsigned char buffer[4096];
    unsigned char *der;
    int len;

    e = BN_new();
    BN_set_word(e, RSA_F4);

    key = RSA_new();
    RSA_generate_key_ex(key, 3072, e, NULL);

    der = buffer;
    len = i2d_RSAPrivateKey(key, &der);
    assert(len > 0);

    hex_dump("privkey: ", buffer, len);

    BN_free(e);

    /*****************************************/
    /* gen_pubkey_hash */

    der = buffer;
    len = i2d_RSAPublicKey(key, &der);
    assert(len > 0);

    fprintf(stdout, "pubkey length = %d, expected = 398\n", len);
    hex_dump("pubkey:  ", buffer, len);

    SHA256(buffer, len, buffer);
    hex_dump("pubkey_hash: ", buffer, 32);
    /*****************************************/

    return key;
}

static int x509_extension_add(X509 *cert, const char *oid,
        const void *data, size_t data_len)
{
    int nid;
    ASN1_OCTET_STRING *octet;
    X509_EXTENSION *ext;
    int ret;

    nid = OBJ_create(oid, NULL, NULL);
    assert(nid != NID_undef);

    octet = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(octet, data, data_len);
    ext = X509_EXTENSION_create_by_NID(NULL, nid, 0, octet);
    assert(ext);

    ret = X509_add_ext(cert, ext, -1);
    assert(ret);

    X509_EXTENSION_free(ext);
    ASN1_OCTET_STRING_free(octet);
    return 0;
}

static void gen_cert(RSA *key)
{
    EVP_PKEY *pkey;
    X509 *cert;
    X509_NAME *name;
    int ret;

    pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, key);

    cert = X509_new();
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 9527);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    /* 10 years */
    X509_gmtime_adj(X509_get_notAfter(cert), 3600 * 24 * 365 * 10);

    X509_set_pubkey(cert, pkey);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, "Alibaba", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, "Cloud", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, "Linux", -1, -1, 0);
    ret = X509_set_issuer_name(cert, name);
    assert(ret);

    x509_extension_add(cert, "1.2.840.113741.1337.2", "iasReport", 9);
    x509_extension_add(cert, "1.2.840.113741.1337.6", "quote", 5);
    x509_extension_add(cert, "1.2.840.113741.1337.14", "laReport", 8);

    ret = X509_sign(cert, pkey, EVP_sha256());
    assert(ret);

    do {
        unsigned char buffer[4096];
        unsigned char *der = buffer;
        int len;

        len = i2d_X509(cert, &der);
        assert(len > 0);

        hex_dump("x509: ", buffer, len);
    } while (0);

    /*******************************************/
    do {
        FILE *fp;

        fp = fopen("priv.key", "r+b");;
        PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
        fclose(fp);

        fp = fopen("cert.pem", "r+b");;
        PEM_write_X509(fp, cert);
        fclose(fp);
    } while (0);
    /*******************************************/

    X509_free(cert);
    EVP_PKEY_free(pkey);
}

int main(int argc, char *argv[])
{
    RSA *key;

    key = gen_privkey();
    gen_cert(key);

    RSA_free(key);

    return 0;
}
