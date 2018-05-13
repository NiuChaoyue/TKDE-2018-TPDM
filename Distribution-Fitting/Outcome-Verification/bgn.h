#ifndef BGN_H
#define BGN_H

#include <stdio.h>
#include <pbc.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BGN_MAX_PLAINTEXT 1000000000


typedef struct
{
    unsigned int bits;
    pbc_param_t param;
    mpz_t n;     /* used for random r in [1, n] */
    element_t P; /* public key */
    element_t Q; /* public key */
    mpz_t q;     /* private key */
    /* online generation */
    pairing_t pairing;
    element_t g; /* g = e(P, P), */
    element_t k; /* k = g^q, used in decrypt2 */
    element_t h; /* h = e(Q, Q), h^q = 1, used in ciphertext_add */
    element_t T; /* T = [q]P, used in decrypt */
} bgn_key_t;

typedef struct
{
    mpz_t m;
} bgn_plaintext_t;

/* we can not init ciphertext without the knowledge of level */
typedef struct
{
    int level;
    element_t c;
} bgn_ciphertext_t;

int bgn_key_init(bgn_key_t *key);
int bgn_key_generate(bgn_key_t *key, int bits);
int bgn_key_init_set(bgn_key_t *r, bgn_key_t *a, int set_sk);
int bgn_key_init_set_str(bgn_key_t *key, const char *str, int set_sk);
int bgn_key_to_str(bgn_key_t *key, char *buf, size_t buflen, int out_sk);
int bgn_key_print(FILE *fp, bgn_key_t *key);
void bgn_key_cleanup(bgn_key_t *key);

int bgn_encrypt(bgn_ciphertext_t *c, bgn_plaintext_t *m, bgn_key_t *key);
int bgn_decrypt(bgn_plaintext_t *m, bgn_ciphertext_t *c, bgn_key_t *key);

int bgn_plaintext_init(bgn_plaintext_t *m);
int bgn_plaintext_set_word(bgn_plaintext_t *m, unsigned long a);
int bgn_plaintext_set_hex(bgn_plaintext_t *m, const char *str);
int bgn_plaintext_init_set_word(bgn_plaintext_t *m, unsigned long a);
int bgn_plaintext_init_set_hex(bgn_plaintext_t *m, const char *str);
int bgn_plaintext_to_word(bgn_plaintext_t *m, unsigned long *a);
int bgn_plaintext_to_hex(bgn_plaintext_t *m, char *buf, size_t buflen);
void bgn_plaintext_cleanup(bgn_plaintext_t *m);

int bgn_ciphertext_init(bgn_ciphertext_t *c, int level, bgn_key_t *key);
int bgn_ciphertext_init_set_str(bgn_ciphertext_t *c, const char *str, bgn_key_t *key);
int bgn_ciphertext_to_str(bgn_ciphertext_t *c, char *buf, size_t len);
int bgn_ciphertext_print(FILE *fp, bgn_ciphertext_t *c);
int bgn_ciphertext_get_level(bgn_ciphertext_t *c);
int bgn_ciphertext_add(bgn_ciphertext_t *r, bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key);
int bgn_ciphertext_mul(bgn_ciphertext_t *r, bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key);
int bgn_ciphertext_sub(bgn_ciphertext_t *r, bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key);
void bgn_ciphertext_cleanup(bgn_ciphertext_t *c);


#ifdef __cplusplus
}
#endif
#endif
