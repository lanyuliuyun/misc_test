
/*
 gcc selfsign_cert.c -o selfsign_cert -lcrypto
 */

#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <time.h>

int generate_selfsign_cert
(
    const char *common_name,
    int life_time,
    X509 **out_x509,
    EVP_PKEY **out_key
)
{
    /* 1,先产生一个 RSA key pair */
    EVP_PKEY *key;
    BIGNUM *bn;

    key = EVP_PKEY_new();
    if (1)
    {
        RSA *rsa = RSA_new();
        bn = BN_new();
        /* 此处给RSA提供一个exponet，是一个奇数，通常为 3/17/65537 之一 */
        BN_set_word(bn, 65537);
        /* 此处 RSA key长度固定写为 1024bits */
        RSA_generate_key_ex(rsa, 2048, bn, NULL);

        EVP_PKEY_assign_RSA(key, rsa);
        BN_free(bn);
    }
    else
    {
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

        // Ensure curve name is included when EC key is serialized.
        // Without this call, OpenSSL versions before 1.1.0 will create
        // certificates that don't work for TLS.
        // This is a no-op for BoringSSL and OpenSSL 1.1.0+
        EC_KEY_set_asn1_flag(ec_key, OPENSSL_EC_NAMED_CURVE);

        EC_KEY_generate_key(ec_key);
        EVP_PKEY_assign_EC_KEY(key, ec_key);
    }

    /* 2, 新建一个证书并进行自签名 */
    X509 *x509 = X509_new();
    
    X509_set_pubkey(x509, key);

    bn = BN_new();
    BN_pseudo_rand(bn, 64, 0, 0);
    ASN1_INTEGER *asn1_sn = X509_get_serialNumber(x509);
    BN_to_ASN1_INTEGER(bn, asn1_sn);
    BN_free(bn);

    /* version 3 */
    X509_set_version(x509, 2L);

    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_UTF8, common_name, -1, -1, 0);
    X509_set_subject_name(x509, name);
    X509_set_issuer_name(x509, name);
    X509_NAME_free(name);

    time_t ts = time(NULL);
    long not_before_ts = (long)ts;
    long not_after_ts = not_before_ts + life_time;
    X509_time_adj(X509_get_notBefore(x509), not_before_ts, &ts);
    X509_time_adj(X509_get_notAfter(x509), not_after_ts, &ts);
    X509_sign(x509, key, EVP_sha256());

    *out_key = key;
    *out_x509 = x509;

    return 0;
}

#include <stdio.h>

#include <openssl/pem.h>
DECLARE_PEM_write_fp(X509, X509)

int main(int argc, char *argv[])
{
    X509 *x509 = NULL;
    EVP_PKEY *key = NULL;
    int life_time = 60 * 60 * 24 * 30;
    
    generate_selfsign_cert("self_sign_cert", life_time, &x509, &key);
    
    FILE *fp = fopen("self.crt", "w");
    PEM_write_X509(fp, x509);
    fclose(fp);

    BIO *bio = BIO_new_fp(stdout, BIO_NOCLOSE);
    X509_print(bio, x509);
    BIO_free(bio);

    X509_free(x509);
    EVP_PKEY_free(key);
    
    return 0;
}