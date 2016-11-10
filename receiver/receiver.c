#define _GNU_SOURCE  // because of getdelim, before stdio.h
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <stdio.h> // getdelim
#include <string.h>
#include "signer_pub.h" // xxd -i signer_pub.pem > signer_pub.h
#include "enc_priv.h"

char* verify(char* msg);
char* decrypt(char* msg);
int main(void);


char* decrypt(char* msg){
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    PKCS7 *p7 = NULL;
    int ret = 1;
    char *rs = NULL, *rs_bio; // return string

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate and private key */
    // tbio = BIO_new_file("signer.pem", "r");
    tbio = BIO_new_mem_buf((void*)enc_priv_pem, enc_priv_pem_len);

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!rcert || !rkey)
        goto err;

    /* Open content being signed */

    // in = BIO_new_file("smout.txt", "r");
    in = BIO_new_mem_buf((void*)msg, strlen(msg));

    if (!in)
        goto err;

    /* Sign content */
    p7 = SMIME_read_PKCS7(in, NULL);

    if (!p7)
        goto err;

    // out = BIO_new_file("encrout.txt", "w");
    out = BIO_new(BIO_s_mem());
    if (!out)
        goto err;

    /* Decrypt S/MIME message */
    if (!PKCS7_decrypt(p7, rkey, rcert, out, 0))
        goto err;

    // rs_bio is pointer in BIO structure, that would be deleted by BIO_free()
    // I create nem memory buffer rs and copy data from rs_bio
    long data_len = BIO_get_mem_data(out, &rs_bio);
    if (data_len > 0){
        rs = malloc(data_len + 1);
        memcpy (rs, rs_bio, data_len);
        rs[data_len] = '\0';
    }

    ret = 0;

 err:
    if (ret) {
        fprintf(stderr, "Receiver: Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }
    PKCS7_free(p7);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);

    return rs;
}

char* verify(char* msg){
    BIO *in = NULL, *tbio = NULL, *cont = NULL;
    X509_STORE *st = NULL;
    X509 *cacert = NULL;
    PKCS7 *p7 = NULL;
    char *rs = NULL, *rs_bio = NULL; // return string

    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Set up trusted CA certificate store */

    st = X509_STORE_new();

    /* Read in signer certificate and private key */
    // tbio = BIO_new_file("cacert.pem", "r");
    tbio = BIO_new_mem_buf((void*)signer_pub_pem, signer_pub_pem_len);

    if (!tbio)
        goto err;

    cacert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!cacert)
        goto err;

    if (!X509_STORE_add_cert(st, cacert))
        goto err;

    /* Open content being signed */

    // in = BIO_new_file("smout.txt", "r");
    in = BIO_new_mem_buf((void*)msg, strlen(msg));

    if (!in)
        goto err;

    /* Sign content */
    p7 = SMIME_read_PKCS7(in, &cont);

    if (!p7)
        goto err;

    // if (!PKCS7_verify(p7, NULL, st, cont, out, 0)) {
    if (!PKCS7_verify(p7, NULL, st, cont, NULL, 0)) {
        fprintf(stderr, "Receiver: Verification Failure\n");
        goto err;
    }

    // fprintf(stderr, "Receiver: Verification Successful\n");

    // rs_bio is pointer in BIO structure, that would be deleted by BIO_free()
    // I create nem memory buffer rs and copy data from rs_bio
    long data_len = BIO_get_mem_data(cont, &rs_bio);
    if (data_len > 0){
        rs = malloc(data_len + 1);
        memcpy (rs, rs_bio, data_len);
        rs[data_len] = '\0';
    }

    ret = 0;

 err:
    if (ret) {
        fprintf(stderr, "Receiver: Error Verifying Data\n");
        ERR_print_errors_fp(stderr);
    }
    PKCS7_free(p7);
    X509_free(cacert);
    BIO_free(in);
    BIO_free(tbio);
    return rs;
}

int main(){
    char *msg = NULL;
    size_t len = 0;
    ssize_t read = getdelim(&msg, &len, -1, stdin);
    fprintf(stderr, "Receiver: Input message length:%i\n", read);
    char *buff = verify(decrypt(msg));
    if (buff == NULL)
        return -1;
    printf(buff);
    return 0;
}
