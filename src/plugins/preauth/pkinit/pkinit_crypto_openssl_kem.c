/* -*- mode: c; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/* plugins/preauth/pkinit/pkinit_crypto_openssl_kem.c */
/*
 * Copyright (C) 2025 by Red Hat, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * KEM (Key Encapsulation Mechanism) crypto operations for PKINIT,
 * implementing draft-bokovoy-kitten-pkinit-pqc.  Requires OpenSSL 3.5+
 * for ML-KEM support.
 */

#include "k5-int.h"
#include "pkinit.h"

#if OPENSSL_VERSION_NUMBER >= 0x30500000L

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

typedef enum {
    PKINIT_KEM_NONE = 0,
    PKINIT_KEM_MLKEM_512,
    PKINIT_KEM_MLKEM_768,
    PKINIT_KEM_MLKEM_1024,
    PKINIT_KEM_COMP_MLKEM768_P256,
    PKINIT_KEM_COMP_MLKEM768_X25519,
    PKINIT_KEM_COMP_MLKEM1024_P384
} pkinit_kem_alg_id;

typedef struct {
    pkinit_kem_alg_id id;
    const char *ossl_name;
    const krb5_data *oid;
    size_t ct_len;
    size_t ss_len;
    int strength;
    const char *desc;
} pkinit_kem_alg_info;

/*
 * Supported KEM algorithms, ordered by increasing strength.
 * Ciphertext and shared-secret sizes are fixed by FIPS 203 for pure ML-KEM.
 * For composite algorithms, sizes are determined at runtime by OpenSSL so
 * ct_len and ss_len are set to 0 (meaning: query OpenSSL for the actual size).
 */
static const pkinit_kem_alg_info kem_algorithms[] = {
    { PKINIT_KEM_MLKEM_512, "ML-KEM-512", &mlkem_512_oid,
      768, 32, PKINIT_PQC_MLKEM512_BITS, "ML-KEM-512" },
    { PKINIT_KEM_MLKEM_768, "ML-KEM-768", &mlkem_768_oid,
      1088, 32, PKINIT_PQC_MLKEM768_BITS, "ML-KEM-768" },
    { PKINIT_KEM_MLKEM_1024, "ML-KEM-1024", &mlkem_1024_oid,
      1568, 32, PKINIT_PQC_MLKEM1024_BITS, "ML-KEM-1024" },
    { PKINIT_KEM_COMP_MLKEM768_P256, "MLKEM768-ECDH-P256",
      &comp_mlkem768_p256_oid,
      0, 0, PKINIT_PQC_COMP_MLKEM768_BITS, "Composite ML-KEM-768+P-256" },
    { PKINIT_KEM_COMP_MLKEM768_X25519, "MLKEM768-X25519",
      &comp_mlkem768_x25519_oid,
      0, 0, PKINIT_PQC_COMP_MLKEM768_BITS, "Composite ML-KEM-768+X25519" },
    { PKINIT_KEM_COMP_MLKEM1024_P384, "MLKEM1024-ECDH-P384",
      &comp_mlkem1024_p384_oid,
      0, 0, PKINIT_PQC_COMP_MLKEM1024_BITS, "Composite ML-KEM-1024+P-384" },
    { PKINIT_KEM_NONE, NULL, NULL, 0, 0, 0, NULL }
};


/* Look up a KEM algorithm by its PKINIT_PQC_*_BITS strength level.
 * Returns the first algorithm at or above the requested strength. */
static const pkinit_kem_alg_info *
choose_kem_algorithm(int min_strength)
{
    const pkinit_kem_alg_info *alg;

    for (alg = kem_algorithms; alg->id != PKINIT_KEM_NONE; alg++) {
        if (alg->strength >= min_strength)
            return alg;
    }
    return NULL;
}

/*
 * Extract the algorithm OID from a SubjectPublicKeyInfo and check if it
 * matches a known KEM algorithm.  Returns the matching algorithm info or
 * NULL.
 */
static const pkinit_kem_alg_info *
kem_alg_from_pkey(EVP_PKEY *pkey)
{
    const pkinit_kem_alg_info *alg;

    if (pkey == NULL)
        return NULL;

    for (alg = kem_algorithms; alg->id != PKINIT_KEM_NONE; alg++) {
        if (EVP_PKEY_is_a(pkey, alg->ossl_name))
            return alg;
    }
    return NULL;
}

krb5_boolean
is_pqc_algorithm_oid(const krb5_data *oid)
{
    if (oid == NULL || oid->length == 0)
        return FALSE;
    if (data_eq(*oid, mlkem_512_oid) ||
        data_eq(*oid, mlkem_768_oid) ||
        data_eq(*oid, mlkem_1024_oid) ||
        data_eq(*oid, comp_mlkem768_x25519_oid) ||
        data_eq(*oid, comp_mlkem768_p256_oid) ||
        data_eq(*oid, comp_mlkem1024_p384_oid))
        return TRUE;
    return FALSE;
}

krb5_boolean
is_kem_algorithm(const krb5_data *spki)
{
    EVP_PKEY *pkey;
    const uint8_t *inptr;
    const pkinit_kem_alg_info *alg;

    if (spki == NULL || spki->length == 0)
        return FALSE;

    inptr = (const uint8_t *)spki->data;
    pkey = d2i_PUBKEY(NULL, &inptr, spki->length);
    if (pkey == NULL)
        return FALSE;

    alg = kem_alg_from_pkey(pkey);
    EVP_PKEY_free(pkey);
    return (alg != NULL);
}

/* Generate an ephemeral KEM key pair.  Store the private key in the request
 * crypto context and return the public key encoded as SubjectPublicKeyInfo. */
krb5_error_code
client_create_kem(krb5_context context,
                  pkinit_plg_crypto_context plg_cryptoctx,
                  pkinit_req_crypto_context req_cryptoctx,
                  pkinit_identity_crypto_context id_cryptoctx,
                  int kem_alg_strength, krb5_data *spki_out)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    const pkinit_kem_alg_info *alg;
    EVP_PKEY *pkey = NULL;
    int len;
    uint8_t *outptr;

    *spki_out = empty_data();

    alg = choose_kem_algorithm(kem_alg_strength);
    if (alg == NULL) {
        pkiDebug("no KEM algorithm at strength %d\n", kem_alg_strength);
        goto cleanup;
    }

    TRACE_PKINIT_KEM_PROPOSING_ALG(context, alg->desc);

    pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg->ossl_name);
    if (pkey == NULL) {
        pkiDebug("EVP_PKEY_Q_keygen(%s) failed\n", alg->ossl_name);
        goto cleanup;
    }

    /* Encode as SubjectPublicKeyInfo. */
    len = i2d_PUBKEY(pkey, NULL);
    if (len <= 0)
        goto cleanup;
    retval = alloc_data(spki_out, len);
    if (retval)
        goto cleanup;
    outptr = (uint8_t *)spki_out->data;
    (void)i2d_PUBKEY(pkey, &outptr);

    /* Store the full key pair for later decapsulation. */
    EVP_PKEY_free(req_cryptoctx->client_pkey);
    req_cryptoctx->client_pkey = pkey;
    pkey = NULL;
    retval = 0;

cleanup:
    EVP_PKEY_free(pkey);
    return retval;
}

/* Validate the client's KEM public key from a SubjectPublicKeyInfo.  Check
 * that the algorithm is known and meets the minimum strength policy.  Store
 * the decoded public key in the request crypto context for later
 * encapsulation. */
krb5_error_code
server_check_kem(krb5_context context,
                 pkinit_plg_crypto_context plg_cryptoctx,
                 pkinit_req_crypto_context req_cryptoctx,
                 pkinit_identity_crypto_context id_cryptoctx,
                 const krb5_data *client_spki, int min_strength)
{
    krb5_error_code retval =
        KRB5KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED;
    EVP_PKEY *client_pkey = NULL;
    const pkinit_kem_alg_info *alg;
    const uint8_t *inptr;

    inptr = (const uint8_t *)client_spki->data;
    client_pkey = d2i_PUBKEY(NULL, &inptr, client_spki->length);
    if (client_pkey == NULL) {
        pkiDebug("failed to decode KEM SPKI\n");
        goto cleanup;
    }

    alg = kem_alg_from_pkey(client_pkey);
    if (alg == NULL) {
        pkiDebug("unrecognized KEM algorithm in SPKI\n");
        goto cleanup;
    }

    if (alg->strength < min_strength) {
        const pkinit_kem_alg_info *min_alg =
            choose_kem_algorithm(min_strength);
        TRACE_PKINIT_KEM_REJECTING_ALG(context, alg->desc,
                                        min_alg ? min_alg->desc : "(none)");
        goto cleanup;
    }

    TRACE_PKINIT_KEM_RECEIVED_ALG(context, alg->desc);

    /* Store the client's public key for encapsulation. */
    EVP_PKEY_free(req_cryptoctx->client_pkey);
    req_cryptoctx->client_pkey = client_pkey;
    client_pkey = NULL;
    retval = 0;

cleanup:
    EVP_PKEY_free(client_pkey);
    return retval;
}

/* Perform KEM encapsulation against the client's public key stored in the
 * request crypto context.  Returns the ciphertext and shared secret. */
krb5_error_code
server_process_kem(krb5_context context,
                   pkinit_plg_crypto_context plg_cryptoctx,
                   pkinit_req_crypto_context req_cryptoctx,
                   pkinit_identity_crypto_context id_cryptoctx,
                   unsigned char **kemct_out, unsigned int *kemct_len_out,
                   unsigned char **server_key_out,
                   unsigned int *server_key_len_out)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ct = NULL, *ss = NULL;
    size_t ct_len = 0, ss_len = 0;

    *kemct_out = *server_key_out = NULL;
    *kemct_len_out = *server_key_len_out = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, req_cryptoctx->client_pkey, NULL);
    if (ctx == NULL)
        goto cleanup;

    if (EVP_PKEY_encapsulate_init(ctx, NULL) <= 0)
        goto cleanup;

    /* Query output sizes. */
    if (EVP_PKEY_encapsulate(ctx, NULL, &ct_len, NULL, &ss_len) <= 0)
        goto cleanup;

    ct = malloc(ct_len);
    ss = malloc(ss_len);
    if (ct == NULL || ss == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }

    if (EVP_PKEY_encapsulate(ctx, ct, &ct_len, ss, &ss_len) <= 0) {
        pkiDebug("EVP_PKEY_encapsulate failed\n");
        goto cleanup;
    }

    *kemct_out = ct;
    *kemct_len_out = ct_len;
    *server_key_out = ss;
    *server_key_len_out = ss_len;
    ct = ss = NULL;
    retval = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    free(ct);
    if (ss != NULL) {
        OPENSSL_cleanse(ss, ss_len);
        free(ss);
    }
    return retval;
}

/* Perform KEM decapsulation using the ephemeral private key stored in the
 * request crypto context.  The private key is zeroized immediately after
 * decapsulation per RFC requirements for dk hygiene. */
krb5_error_code
client_process_kem(krb5_context context,
                   pkinit_plg_crypto_context plg_cryptoctx,
                   pkinit_req_crypto_context req_cryptoctx,
                   pkinit_identity_crypto_context id_cryptoctx,
                   unsigned char *kemct, unsigned int kemct_len,
                   unsigned char **client_key_out,
                   unsigned int *client_key_len_out)
{
    krb5_error_code retval = KRB5KDC_ERR_PREAUTH_FAILED;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *ss = NULL;
    size_t ss_len = 0;

    *client_key_out = NULL;
    *client_key_len_out = 0;

    ctx = EVP_PKEY_CTX_new_from_pkey(NULL, req_cryptoctx->client_pkey, NULL);
    if (ctx == NULL)
        goto cleanup;

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
        goto cleanup;

    /* Query output size. */
    if (EVP_PKEY_decapsulate(ctx, NULL, &ss_len, kemct, kemct_len) <= 0)
        goto cleanup;

    ss = malloc(ss_len);
    if (ss == NULL) {
        retval = ENOMEM;
        goto cleanup;
    }

    if (EVP_PKEY_decapsulate(ctx, ss, &ss_len, kemct, kemct_len) <= 0) {
        pkiDebug("EVP_PKEY_decapsulate failed\n");
        goto cleanup;
    }

    *client_key_out = ss;
    *client_key_len_out = ss_len;
    ss = NULL;
    retval = 0;

cleanup:
    EVP_PKEY_CTX_free(ctx);
    if (ss != NULL) {
        OPENSSL_cleanse(ss, ss_len);
        free(ss);
    }

    /* Zeroize the ephemeral decapsulation key immediately. */
    EVP_PKEY_free(req_cryptoctx->client_pkey);
    req_cryptoctx->client_pkey = NULL;

    return retval;
}

/*
 * Derive the AS reply key using HKDF-SHA-512 per
 * draft-bokovoy-kitten-pkinit-pqc Section 9.
 *
 *   reply_key_material = HKDF-SHA-512(
 *       IKM  = ss,
 *       salt = <not provided>,
 *       info = DER(PkinitKEMSuppPubInfo),
 *       L    = random-to-key input length for enctype
 *   )
 *   reply_key = random-to-key(reply_key_material)
 */
krb5_error_code
pkinit_kem_kdf(krb5_context context, krb5_data *secret,
               const krb5_data *kdf_alg_oid, krb5_enctype enctype,
               const krb5_data *as_req, const krb5_data *kem_signed_data,
               krb5_keyblock *key_block)
{
    krb5_error_code ret;
    size_t rand_len = 0, key_len = 0;
    krb5_pkinit_kem_supp_pub_info supp_pub_info_fields;
    krb5_data *supp_pub_info = NULL;
    krb5_data random_data = empty_data();
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[5], *p;
    char kdf_name[80];

    ret = krb5_c_keylengths(context, enctype, &rand_len, &key_len);
    if (ret)
        goto cleanup;

    key_block->magic = 0;
    key_block->enctype = enctype;
    key_block->length = key_len;
    key_block->contents = k5calloc(key_block->length, 1, &ret);
    if (key_block->contents == NULL)
        goto cleanup;

    /* Build and DER-encode PkinitKEMSuppPubInfo. */
    supp_pub_info_fields.enctype = enctype;
    supp_pub_info_fields.as_req = *as_req;
    supp_pub_info_fields.kemSignedData = *kem_signed_data;
    ret = k5int_encode_krb5_pkinit_kem_supp_pub_info(&supp_pub_info_fields,
                                                      &supp_pub_info);
    if (ret)
        goto cleanup;

    /* Perform HKDF-SHA-512. */
    kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    if (kdf == NULL) {
        ret = KRB5_CRYPTO_INTERNAL;
        goto cleanup;
    }

    kctx = EVP_KDF_CTX_new(kdf);
    if (kctx == NULL) {
        ret = ENOMEM;
        goto cleanup;
    }

    ret = alloc_data(&random_data, rand_len);
    if (ret)
        goto cleanup;

    p = params;
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST,
                                            "SHA512", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY,
                                             secret->data,
                                             secret->length);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO,
                                             supp_pub_info->data,
                                             supp_pub_info->length);
    /* salt is omitted (defaults to HashLen zero bytes per RFC 5869). */
    *p = OSSL_PARAM_construct_end();

    if (EVP_KDF_derive(kctx, (unsigned char *)random_data.data,
                       rand_len, params) <= 0) {
        ret = KRB5_CRYPTO_INTERNAL;
        goto cleanup;
    }

    ret = krb5_c_random_to_key(context, enctype, &random_data, key_block);
    if (ret)
        goto cleanup;

    TRACE_PKINIT_KEM_KDF(context,
        pkinit_algoid_to_name(kdf_alg_oid,
                              kdf_name, sizeof(kdf_name)),
        key_block);

cleanup:
    if (ret)
        krb5_free_keyblock_contents(context, key_block);
    zapfree(random_data.data, random_data.length);
    krb5_free_data(context, supp_pub_info);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    return ret;
}

/* Parse pkinit_pqc_min_algorithm config string to a PKINIT_PQC_*_BITS
 * strength value.  Returns 0 if the string is not recognized. */
int
parse_pqc_min_algorithm(krb5_context context, const char *str)
{
    if (str == NULL)
        return 0;
    if (strcasecmp(str, "ML-KEM-512") == 0 ||
        strcasecmp(str, "mlkem512") == 0)
        return PKINIT_PQC_MLKEM512_BITS;
    if (strcasecmp(str, "ML-KEM-768") == 0 ||
        strcasecmp(str, "mlkem768") == 0)
        return PKINIT_PQC_MLKEM768_BITS;
    if (strcasecmp(str, "ML-KEM-1024") == 0 ||
        strcasecmp(str, "mlkem1024") == 0)
        return PKINIT_PQC_MLKEM1024_BITS;
    if (strcasecmp(str, "Composite-ML-KEM-768") == 0)
        return PKINIT_PQC_COMP_MLKEM768_BITS;
    if (strcasecmp(str, "Composite-ML-KEM-1024") == 0)
        return PKINIT_PQC_COMP_MLKEM1024_BITS;
    return 0;
}

/*
 * Check if the received certificate uses a quantum-resistant signature
 * algorithm (ML-DSA, composite ML-DSA).  Used for downgrade prevention.
 */
krb5_boolean
is_pqc_signing_algorithm(pkinit_req_crypto_context req_cryptoctx)
{
    X509 *cert;
    int nid;

    if (req_cryptoctx == NULL)
        return FALSE;

    cert = req_cryptoctx->received_cert;
    if (cert == NULL)
        return FALSE;

    nid = X509_get_signature_nid(cert);

    /*
     * Check for ML-DSA and composite ML-DSA signature
     * algorithms.  Use the long name (e.g. "ML-DSA-65")
     * since the short name uses a different format
     * (e.g. "id-ml-dsa-65").
     */
    if (nid != NID_undef) {
        const char *ln = OBJ_nid2ln(nid);

        if (ln != NULL && strstr(ln, "ML-DSA") != NULL)
            return TRUE;
    }

    return FALSE;
}

/*
 * Extract the algorithm OID from the client's stored public key (which has
 * been decoded and stored in req_cryptoctx->client_pkey by server_check_kem)
 * and populate an AlgorithmIdentifier with the OID and empty parameters.
 */
krb5_error_code
server_get_kem_algorithm_oid(pkinit_req_crypto_context req_cryptoctx,
                             krb5_algorithm_identifier *alg_id_out)
{
    const pkinit_kem_alg_info *alg;

    memset(alg_id_out, 0, sizeof(*alg_id_out));

    if (req_cryptoctx == NULL || req_cryptoctx->client_pkey == NULL)
        return KRB5KDC_ERR_PREAUTH_FAILED;

    alg = kem_alg_from_pkey(req_cryptoctx->client_pkey);
    if (alg == NULL)
        return KRB5KDC_ERR_PREAUTH_FAILED;

    alg_id_out->algorithm = *alg->oid;
    alg_id_out->parameters = empty_data();
    return 0;
}

#else /* OPENSSL_VERSION_NUMBER < 0x30500000L */

/* Stub implementations when OpenSSL < 3.5 (no ML-KEM support). */

krb5_boolean
is_pqc_algorithm_oid(const krb5_data *oid)
{
    return FALSE;
}

krb5_boolean
is_kem_algorithm(const krb5_data *spki)
{
    return FALSE;
}

krb5_error_code
client_create_kem(krb5_context context,
                  pkinit_plg_crypto_context plg_cryptoctx,
                  pkinit_req_crypto_context req_cryptoctx,
                  pkinit_identity_crypto_context id_cryptoctx,
                  int kem_alg_strength, krb5_data *spki_out)
{
    *spki_out = empty_data();
    k5_setmsg(context, KRB5_CRYPTO_INTERNAL,
              _("ML-KEM requires OpenSSL 3.5 or later"));
    return KRB5_CRYPTO_INTERNAL;
}

krb5_error_code
server_check_kem(krb5_context context,
                 pkinit_plg_crypto_context plg_cryptoctx,
                 pkinit_req_crypto_context req_cryptoctx,
                 pkinit_identity_crypto_context id_cryptoctx,
                 const krb5_data *client_spki, int min_strength)
{
    return KRB5KDC_ERR_EPHEMERAL_KEY_PARAMS_NOT_ACCEPTED;
}

krb5_error_code
server_process_kem(krb5_context context,
                   pkinit_plg_crypto_context plg_cryptoctx,
                   pkinit_req_crypto_context req_cryptoctx,
                   pkinit_identity_crypto_context id_cryptoctx,
                   unsigned char **kemct_out, unsigned int *kemct_len_out,
                   unsigned char **server_key_out,
                   unsigned int *server_key_len_out)
{
    return KRB5_CRYPTO_INTERNAL;
}

krb5_error_code
client_process_kem(krb5_context context,
                   pkinit_plg_crypto_context plg_cryptoctx,
                   pkinit_req_crypto_context req_cryptoctx,
                   pkinit_identity_crypto_context id_cryptoctx,
                   unsigned char *kemct, unsigned int kemct_len,
                   unsigned char **client_key_out,
                   unsigned int *client_key_len_out)
{
    return KRB5_CRYPTO_INTERNAL;
}

krb5_error_code
pkinit_kem_kdf(krb5_context context, krb5_data *secret,
               const krb5_data *kdf_alg_oid, krb5_enctype enctype,
               const krb5_data *as_req, const krb5_data *kem_signed_data,
               krb5_keyblock *key_block)
{
    return KRB5_CRYPTO_INTERNAL;
}

int
parse_pqc_min_algorithm(krb5_context context, const char *str)
{
    return 0;
}

krb5_boolean
is_pqc_signing_algorithm(pkinit_req_crypto_context req_cryptoctx)
{
    return FALSE;
}

krb5_error_code
server_get_kem_algorithm_oid(pkinit_req_crypto_context req_cryptoctx,
                             krb5_algorithm_identifier *alg_id_out)
{
    return KRB5KDC_ERR_PREAUTH_FAILED;
}

#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */
