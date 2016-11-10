#define _GNU_SOURCE  // because of getdelim, begore stdio
#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <stdio.h>  // getdelim
#include <string.h> // strcpy, strlen
#include "signer_priv.h" // xxd -i signer_priv.pem > signer_priv.h
#include "enc_pub.h"

int main(void);
char* sign(char* msg);
char* encrypt(char* msg);

char * sign(char* msg){
    if (msg == NULL){
        fprintf(stderr, "Sender: Error: Cannot sign NULL \n");
        return NULL;
    }
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *scert = NULL;
    EVP_PKEY *skey = NULL;
    PKCS7 *p7 = NULL;
    int ret = 1;
    char *rs = NULL, *rs_bio; // return string

    /*
     * For simple S/MIME signing use PKCS7_DETACHED. On OpenSSL 0.9.9 only:
     * for streaming detached set PKCS7_DETACHED|PKCS7_STREAM for streaming
     * non-detached set PKCS7_STREAM
     */
    int flags = PKCS7_DETACHED | PKCS7_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in signer certificate and private key */
    // tbio = BIO_new_file("signer.pem", "r");
    tbio = BIO_new_mem_buf((void*)signer_priv_pem, signer_priv_pem_len);

    if (!tbio)
        goto err;

    scert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    BIO_reset(tbio);

    skey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);

    if (!scert || !skey)
        goto err;

    /* Open content being signed */
    // in = BIO_new_file("sign.txt", "r");
    in = BIO_new_mem_buf((void*)msg, strlen(msg));

    if (!in)
        goto err;

    /* Sign content */
    p7 = PKCS7_sign(scert, skey, NULL, in, flags);

    if (!p7)
        goto err;

    // out = BIO_new_file("smout.txt", "w");
    out = BIO_new(BIO_s_mem());
    if (!out)
        goto err;

    if (!(flags & PKCS7_STREAM))
        BIO_reset(in);

    /* Write out S/MIME message */
    if (!SMIME_write_PKCS7(out, p7, in, flags))
        goto err;

    // rs_bio is pointer in BIO structure, that would be deleted by BIO_free(out)
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
        fprintf(stderr, "Sender: Error Signing Data\n");
        ERR_print_errors_fp(stderr);
    }
    PKCS7_free(p7);
    X509_free(scert);
    EVP_PKEY_free(skey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);

    return rs;
}

char* encrypt(char* msg){
    if (msg == NULL){
        fprintf(stderr, "Sender: Error: Cannot encode NULL \n");
        return NULL;
    }
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    STACK_OF(X509) *recips = NULL;
    PKCS7 *p7 = NULL;
    char *rs = NULL, *rs_bio; // return string
    int ret = 1;

    /*
     * On OpenSSL 0.9.9 only:
     * for streaming set PKCS7_STREAM
     */
    int flags = PKCS7_STREAM;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate */
    // tbio = BIO_new_file("enc_pub.pem", "r");
    tbio = BIO_new_mem_buf((void*)enc_pub_pem, enc_pub_pem_len);

    if (!tbio)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);

    if (!rcert)
        goto err;

    /* Create recipient STACK and add recipient cert to it */
    recips = sk_X509_new_null();

    if (!recips || !sk_X509_push(recips, rcert))
        goto err;

    /*
     * sk_X509_pop_free will free up recipient STACK and its contents so set
     * rcert to NULL so it isn't freed up twice.
     */
    rcert = NULL;

    /* Open content being encrypted */

    // in = BIO_new_file("encr.txt", "r");
    in = BIO_new_mem_buf((void*)msg, strlen(msg));

    if (!in)
        goto err;

    /* encrypt content */
    p7 = PKCS7_encrypt(recips, in, EVP_des_ede3_cbc(), flags);

    if (!p7)
        goto err;

    // out = BIO_new_file("smencr.txt", "w");
    out = BIO_new(BIO_s_mem());
    if (!out)
        goto err;

    /* Write out S/MIME message */
    if (!SMIME_write_PKCS7(out, p7, in, flags))
        goto err;

    // rs_bio is pointer in BIO structure, that would be deleted by BIO_free(out)
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
        fprintf(stderr, "Sender: Error Encrypting Data\n");
        ERR_print_errors_fp(stderr);
    }
    PKCS7_free(p7);
    X509_free(rcert);
    sk_X509_pop_free(recips, X509_free);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return rs;

}

int main(){
    char* msg = NULL;
    size_t len = 0;
    getdelim(&msg, &len, -1, stdin);
    fprintf(stderr, "Sender: Input message:%s\n", msg);
    char *buff = encrypt(sign(msg));
    if (buff == NULL)
        return -1;
    printf(buff);
    return 0;
}
