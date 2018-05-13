/******
  This is an implementation of somewhat homomorphic cryptosystem, called Boneh-Goh-Nissim (BGN) scheme.
  Reference Paper: D. Boneh, E. Goh, and K. Nissim, "Evaluating 2-dnf formulas on ciphertexts", in TCC, 2005.
******/

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "bgn.h"


static int bin2hex(const void *bin, size_t binlen, char *buf, size_t buflen)
{
    int outlen = binlen * 2;
    char *HEX = "0123456789ABCDEF";
    const unsigned char *in = bin;
    char *p = buf;
    int i;

    if (!buf)
        return outlen;

    if (buflen <= outlen)
    {
        fprintf(stderr, "%s (%s %d): buffer too small\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    for (i = 0; i < binlen; i++)
    {
        *p++ = HEX[in[i] >> 4];
        *p++ = HEX[in[i] & 0x0f];
    }
    *p = 0;

    return outlen;
}

static int hex2int(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    fprintf(stderr, "%s (%s %d): invalid char `%d'\n",
            __FUNCTION__, __FILE__, __LINE__, c);
    return -1;
}

static int hex2bin(const char *hex, unsigned char *buf, size_t buflen)
{
    int outlen, i;
    int len = strlen(hex);

    if (len == 0 || len % 2)
    {
        fprintf(stderr, "%s (%s %d): invalid hex length `%d'\n",
                __FUNCTION__, __FILE__, __LINE__, len);
        return -1;
    }

    for (i = 0; i < len; i++)
    {
        if (!isxdigit(hex[i]))
        {
            fprintf(stderr, "%s (%s %d): invalid hex `%s'\n",
                    __FUNCTION__, __FILE__, __LINE__, hex);
            return -1;
        }
    }

    outlen = len/2;

    if (!buf)
        return outlen;

    if (buflen < outlen)
    {
        fprintf(stderr, "%s (%s %d): invalid buffer length\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    for (i = 0; i < outlen; i++)
    {
        buf[i] = hex2int(hex[i * 2]) * 16 + hex2int(hex[i * 2 + 1]);
    }

    return outlen;
}

static void bgn_element_init_set(element_t r, element_t a)
{
    element_init_same_as(r, a);
    element_set(r, a);
}


static int bgn_G1_element_to_str(element_t e, char *buf, size_t buflen)
{
    unsigned char bytes[4096];
    int nbytes = element_length_in_bytes_compressed(e);
    int outlen = nbytes * 2;

    if (!buf)
    {
        return outlen;
    }

    if (buflen <= outlen)
    {
        fprintf(stderr, "%s (%s %d): buffer too small\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    element_to_bytes_compressed(bytes, e);
    return bin2hex(bytes, nbytes, buf, buflen);
}

static int bgn_GT_element_to_str(element_t e, char *buf, size_t buflen)
{
    unsigned char bytes[4096];
    int nbytes = element_length_in_bytes(e);
    int outlen = nbytes * 2;

    if (!buf)
    {
        return outlen;
    }

    if (buflen <= outlen)
    {
        fprintf(stderr, "%s (%s %d): buffer too small\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    element_to_bytes(bytes, e);
    return bin2hex(bytes, nbytes, buf, buflen);
}

static int bgn_G1_element_set_str(element_t e, const char *str)
{
    unsigned char bytes[4096];
    int nbytes;

    //printf("%s %d: length = %d\n", __FILE__, __LINE__, strlen(str));

    if ((nbytes = hex2bin(str, bytes, sizeof(bytes))) < 0)
    {
        fprintf(stderr, "%s (%s %d): parse hex `%s' failed\n",
                __FUNCTION__, __FILE__, __LINE__, str);
        return -1;
    }

    //printf("%s %d: nbytes = %d\n", __FILE__, __LINE__, nbytes);

    if (nbytes != element_length_in_bytes_compressed(e))
    {
        fprintf(stderr, "%s (%s %d): invalid length in bytes `%d' failed\n",
                __FUNCTION__, __FILE__, __LINE__, nbytes);
        return -1;
    }

    element_from_bytes_compressed(e, bytes);
    return 0;
}

static int bgn_GT_element_set_str(element_t e, const char *str)
{
    unsigned char bytes[4096];
    int nbytes;

    if ((nbytes = hex2bin(str, bytes, sizeof(bytes))) < 0)
    {
        fprintf(stderr, "%s (%s %d): parse hex `%s' failed\n",
                __FUNCTION__, __FILE__, __LINE__, str);
        return -1;
    }

    if (nbytes != element_length_in_bytes(e))
    {
        fprintf(stderr, "%s (%s %d): invalid length in bytes `%d' failed\n",
                __FUNCTION__, __FILE__, __LINE__, nbytes);
        return -1;
    }

    element_from_bytes(e, bytes);
    return 0;
}

static int bgn_pbc_param_to_str(pbc_param_t param, char *buf, size_t buflen)
{
    FILE *fp = NULL;
    int outlen, i;

    if (!(fp = tmpfile()))
    {
        fprintf(stderr, "%s: failed, %s %d\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    pbc_param_out_str(fp, param);
    (void)fflush(fp);
    outlen = ftell(fp);

    if (!buf)
    {
        fclose(fp);
        return outlen;
    }

    if (buflen <= outlen)
    {
        fprintf(stderr, "%s (%s %d): buffer not enough\n",
                __FUNCTION__, __FILE__, __LINE__);
        fclose(fp);
        return -1;
    }

    (void)fseek(fp, 0, SEEK_SET);
    fread(buf, 1, outlen, fp);
    buf[outlen] = 0;

    for (i = 0; i < outlen; i++)
    {
        if (buf[i] ==  ' ') buf[i] = '=';
        if (buf[i] == '\r') buf[i] = '=';
        if (buf[i] == '\n') buf[i] = ';';
    }

    return outlen;
}

static int bgn_pbc_param_init_set_str(pbc_param_t r, const char *str)
{
    int ret = -1;
    char *buf = NULL;
    int i;

    if (!(buf = strdup(str)))
    {
        fprintf(stderr, "%s (%s %d): malloc failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    for (i = 0; i < strlen(buf); i++)
    {
        if (buf[i] == '=') buf[i] = ' ';
        if (buf[i] == ';') buf[i] = '\n';
    }

    if (pbc_param_init_set_str(r, buf))
    {
        fprintf(stderr, "%s (%s %d): parse failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        goto end;
    }

    ret = 0;

end:
    free(buf);
    return ret;
}

static int bgn_pbc_param_init_set(pbc_param_t r, pbc_param_t a)
{
    char buf[40960];
    if (bgn_pbc_param_to_str(a, buf, sizeof(buf)) < 0)
    {
        fprintf(stderr, "%s (%s %d): bgn_pbc_param_to_str() failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }
    if (bgn_pbc_param_init_set_str(r, buf))
    {
        fprintf(stderr, "%s (%s %d): bgn_pbc_param_init_set_str() failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    return 0;
}

int bgn_key_init(bgn_key_t *key)
{
    memset(key, 0, sizeof(bgn_key_t));
    return 0;
}

int bgn_key_generate(bgn_key_t *key, int bits)
{
    mpz_t r;
    key->bits = bits;

    /* random prime q */
    mpz_init(key->q);
    pbc_mpz_randomb(key->q, key->bits / 2);
    mpz_nextprime(key->q, key->q);

    /* random prime r */
    mpz_init(r);
    pbc_mpz_randomb(r, key->bits / 2);
    mpz_nextprime(r, r);

    /* n = q * r , is used to generate pairing */
    mpz_init(key->n);
    mpz_mul(key->n, key->q, r);

    /* generate pairing */
    pbc_param_init_a1_gen(key->param, key->n);
    pairing_init_pbc_param(key->pairing, key->param);

    /* random P in G1, #P = n */
    element_init_G1(key->P, key->pairing);
    element_random(key->P);

    /* g = e(P, P) */
    element_init_GT(key->g, key->pairing);
    pairing_apply(key->g, key->P, key->P, key->pairing);

    /* k = g^q */
    element_init_GT(key->k, key->pairing);
    element_pow_mpz(key->k, key->g, key->q);

    /* random Q' in G2, Q = [r]Q', #Q = q */
    element_init_G1(key->Q, key->pairing);
    element_random(key->Q);
    element_mul_mpz(key->Q, key->Q, r);

    /* h = e(Q, Q) */
    element_init_GT(key->h, key->pairing);
    pairing_apply(key->h, key->Q, key->Q, key->pairing);

    /* T = [q]P */
    element_init_G1(key->T, key->pairing);
    element_mul_mpz(key->T, key->P, key->q);

    mpz_clear(r);
    return 0;
}

int bgn_key_init_set(bgn_key_t *r, bgn_key_t *a, int set_sk)
{
    r->bits = a->bits;

    bgn_pbc_param_init_set(r->param, a->param);
    pairing_init_pbc_param(r->pairing, r->param);

    mpz_init_set(r->n, a->n);
    bgn_element_init_set(r->P, a->P);
    bgn_element_init_set(r->Q, a->Q);

    if (set_sk)
        mpz_init_set(r->q, a->q);
    else	mpz_init(r->q);

    bgn_element_init_set(r->g, a->g);
    bgn_element_init_set(r->k, a->k);
    bgn_element_init_set(r->h, a->h);

    if (set_sk)
        bgn_element_init_set(r->T, a->T);
    else	element_init_same_as(r->T, a->T);


    /*
    fprintf(stderr, "DEBUG: %s (%s %d): key: \n", __FUNCTION__, __FILE__, __LINE__);
    bgn_key_print(stderr, a);
    bgn_key_print(stderr, r);
    fprintf(stderr, "\n");
    */

    return 0;
}

int bgn_key_to_str(bgn_key_t *key, char *buf, size_t buflen, int out_sk)
{
    int outlen, len;

    outlen = 0;
    outlen += snprintf(NULL, 0, "%d ", key->bits);
    outlen += bgn_pbc_param_to_str(key->param, NULL, 0);
    outlen += gmp_snprintf(NULL, 0, " %ZX ", key->n);
    outlen += bgn_G1_element_to_str(key->P, NULL, 0);
    outlen += strlen(" ");
    outlen += bgn_G1_element_to_str(key->Q, NULL, 0);
    if (out_sk)
        outlen += gmp_snprintf(NULL, 0, ":%ZX", key->q);

    if (!buf)
        return outlen;

    if (buflen <= outlen)
    {
        fprintf(stderr, "%s (%s %d): buffer too small\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    /* key->bits */
    len = snprintf(buf, buflen, "%d ", key->bits);
    buf += len;
    buflen -= len;

    /* key->param */
    if ((len = bgn_pbc_param_to_str(key->param, buf, buflen)) < 0)
    {
        fprintf(stderr, "%s (%s %d): bgn_pbc_param_to_str() failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }
    buf += len;
    buflen -= len;

    /* key->n */
    len = gmp_snprintf(buf, buflen, " %ZX ", key->n);
    buf += len;
    buflen -= len;

    /* key->P */
    if ((len = bgn_G1_element_to_str(key->P, buf, buflen)) < 0)
    {
        fprintf(stderr, "%s (%s %d): bgn_G1_element_to_str() failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }
    buf += len;
    buflen -= len;

    *buf++ = ' ';
    buflen--;

    /* key->Q */
    if ((len = bgn_G1_element_to_str(key->Q, buf, buflen)) < 0)
    {
        fprintf(stderr, "%s (%s %d): bgn_G1_element_to_str() failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }
    buf += len;
    buflen -= len;

    /* key->q */
    if (out_sk)
    {
        len = gmp_snprintf(buf, buflen, ":%ZX", key->q);
        buf += len;
        buflen -= len;
    }

    *buf = 0;
    return 0;
}

int bgn_key_print(FILE *fp, bgn_key_t *key)
{
    fprintf(fp, "bits: %d\n", key->bits);
    fprintf(fp, "param: \n");
    pbc_param_out_str(fp, key->param);
    gmp_fprintf(fp, "n: %ZX\n", key->n);
    element_fprintf(fp, "P: %B\n", key->P);
    element_fprintf(fp, "Q: %B\n", key->Q);
    gmp_fprintf(fp, "q: %ZX\n", key->q);
    element_fprintf(fp, "g = e(P,P): %B\n", key->g);
    element_fprintf(fp, "k = g^q: %B\n", key->k);
    element_fprintf(fp, "h = e(Q, Q): %B\n", key->h);
    element_fprintf(fp, "T = [q]P: %B\n", key->T);
    return 0;
}

int bgn_key_init_set_str(bgn_key_t *key, const char *str, int set_sk)
{
    int ret = -1;
    char *buf = NULL;
    char *p;
    char *bits;
    char *param;
    char *n;
    char *P;
    char *Q;
    char *q;

    if (!(buf = strdup(str)))
    {
        fprintf(stderr, "%s (%s %d): malloc failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }
    p = buf;

    /* key->bits */
    bits = p;
    if (!(p = strchr(p, ' ')))
    {
        fprintf(stderr, "%s (%s %d): parse failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        goto end;
    }
    *p++ = 0;
    key->bits = atoi(bits);

    /* key->param */
    param = p;
    if (!(p = strchr(p, ' ')))
    {
        fprintf(stderr, "%s (%s %d): parse failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        goto end;
    }
    *p++ = 0;
    if (bgn_pbc_param_init_set_str(key->param, param) < 0)
    {
        fprintf(stderr, "%s (%s %d): parse failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        goto end;
    }
    pairing_init_pbc_param(key->pairing, key->param);

    /* key->n */
    n = p;
    if (!(p = strchr(p, ' ')))
    {
        fprintf(stderr, "%s (%s %d): parse failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        goto end;
    }
    *p++ = 0;
    mpz_init_set_str(key->n, n, 16);

    /* key->P */
    P = p;
    if (!(p = strchr(p, ' ')))
    {
        fprintf(stderr, "%s (%s %d): parse failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        goto end;
    }
    *p++ = 0;
    element_init_G1(key->P, key->pairing);
    if (bgn_G1_element_set_str(key->P, P) < 0)
    {
        fprintf(stderr, "%s (%s %d): parse key->P in G1 failed `%s'\n",
                __FUNCTION__, __FILE__, __LINE__, P);
        goto end;
    }

    /* key->Q */
    Q = p;

    if (set_sk)
    {

        /* key->q */

        if (!(p = strchr(p, ':')))
        {
            fprintf(stderr, "%s (%s %d): parse failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            goto end;
        }
        *p++ = 0;
        q = p;

        mpz_init_set_str(key->q, q, 16);

    }

    element_init_G1(key->Q, key->pairing);
    if (bgn_G1_element_set_str(key->Q, Q) < 0)
    {
        fprintf(stderr, "%s (%s %d): parse failed\n",
                __FUNCTION__, __FILE__, __LINE__);
        goto end;
    }


    /* g = e(P, P) */
    element_init_GT(key->g, key->pairing);
    pairing_apply(key->g, key->P, key->P, key->pairing);

    /* k = g^q */
    element_init_GT(key->k, key->pairing);
    element_pow_mpz(key->k, key->g, key->q);

    /* h = e(Q, Q) */
    element_init_GT(key->h, key->pairing);
    pairing_apply(key->h, key->Q, key->Q, key->pairing);

    /* T = [q]P */
    element_init_G1(key->T, key->pairing);
    if (set_sk)
        element_mul_mpz(key->T, key->P, key->q);

    /*
    fprintf(stderr, "DEBUG: %s (%s %d): key: \n", __FUNCTION__, __FILE__, __LINE__);
    bgn_key_print(stderr, key);
    fprintf(stderr, "\n");
    */

    ret = 0;

end:
    if (buf) free(buf);
    return ret;
}


void bgn_key_cleanup(bgn_key_t *key)
{
    assert(key);
    assert(key->param);
    assert(key->n);
    assert(key->P);
    assert(key->Q);
    assert(key->q);
    assert(key->pairing);
    assert(key->g);
    assert(key->k);
    assert(key->h);
    assert(key->T);

    key->bits = 0;
    mpz_clear(key->n);
    element_clear(key->P);
    element_clear(key->Q);
    mpz_clear(key->q);
    element_clear(key->g);
    element_clear(key->k);
    element_clear(key->h);
    element_clear(key->T);
    pairing_clear(key->pairing); /* Do NOT pairing_clear() before element_clear() */
    pbc_param_clear(key->param);
    memset(key, 0, sizeof(bgn_key_t));
}

/*****************************************************************************
 *                          Encrypt/Decrypt
 ****************************************************************************/

/*
 * t = rand[1, n)
 * C = [m]P + [t]Q,
 */
int bgn_encrypt(bgn_ciphertext_t *c, bgn_plaintext_t *m, bgn_key_t *key)
{
    mpz_t t;
    element_t R;

    mpz_init(t);
    /*do {
    	pbc_mpz_randomb(t, key->bits);
    }  while (mpz_cmp(t, key->n) >= 0);*/
    pbc_mpz_random(t, key->n);

    element_init_G1(R, key->pairing);
    element_mul_mpz(R, key->Q, t);

    element_init_G1(c->c, key->pairing);
    element_mul_mpz(c->c, key->P, m->m);
    element_add(c->c, c->c, R);
    c->level = 0;

    mpz_clear(t);
    element_clear(R);
    return 0;
}

/*
 * we need to solve DLP and ECDLP
 * use:
 *	element_dlog_brute_force
 * or	element_dlog_pollar_rho
 *
 * R = [q]C
 * T = [q]P
 * R = [m]T, use element_dlog
 *
 */
// g, h in some group of order r
// finds x such that g^x = h
// will hang if no such x exists
// x in some field_t that set_mpz makes sense for
//void element_dlog_brute_force(element_t x, element_t g, element_t h)
static int bgn_decrypt_level0(bgn_plaintext_t *m, bgn_ciphertext_t *c,
                              bgn_key_t *key)
{
    int ret = -1;
    unsigned long i;
    element_t C;
    element_t R;

    /*
    {
    	char buf[40960];

    	fprintf(stderr, "DEBUG: %s (%s %d): private key: \n", __FUNCTION__, __FILE__, __LINE__);
    	bgn_key_print(stderr, key);
    	fprintf(stderr, "\n");

    	fprintf(stderr, "DEBGU: %s (%s %d): c->level = %d\n", __FUNCTION__, __FILE__, __LINE__, c->level);
    	bgn_ciphertext_to_str(c, buf, sizeof(buf));
    	fprintf(stderr, "DEBUG: %s (%s %d): ciphertext = %s\n", __FUNCTION__, __FILE__, __LINE__, buf);
    }
    */

    element_init_same_as(C, c->c);
    element_mul_mpz(C, c->c, key->q);

    element_init_same_as(R, c->c);
    element_set0(R);
    if(element_cmp(C, R) == 0)
    {
        i = -1;
    }

    if(i != -1)
    {
        element_add(R, R, key->T);
        for (i = 1; i < BGN_MAX_PLAINTEXT && element_cmp(R, C) != 0; i++)
        {
            element_add(R, R, key->T);
        }
    }
    else
    {
        i = 0;
    }

    mpz_init(m->m);

    if (i < BGN_MAX_PLAINTEXT)
    {
        mpz_set_ui(m->m, i);
        ret = 0;

    }
    else
    {
        mpz_set_ui(m->m, 0);
        fprintf(stderr, "%s (%s %d): plaintext too large\n",
                __FUNCTION__, __FILE__, __LINE__);
        ret = -1;
    }

    element_clear(C);
    element_clear(R);
    return ret;
}

static int bgn_decrypt_level1(bgn_plaintext_t *m, bgn_ciphertext_t *c,
                              bgn_key_t *key)
{
    int ret = -1;
    unsigned long i;
    element_t D;
    element_t R;

    element_init_same_as(D, c->c);
    element_pow_mpz(D, c->c, key->q);

    element_init_same_as(R, key->k);
    element_set1(R);

    if(element_cmp(D, R) == 0)
    {
        i = -1;
    }

    if(i != -1)
    {
        //element_add(R, R, key->k);
        //element_init_same_as(R, key->k);
        element_mul(R,R,key->k);
        for (i = 1; i < BGN_MAX_PLAINTEXT && element_cmp(R, D) != 0; i++)
        {
            element_mul(R, R, key->k);
        }
    }
    else
    {
        i = 0;
    }

    mpz_init(m->m);

    if (i < BGN_MAX_PLAINTEXT)
    {
        mpz_set_ui(m->m, i);
        ret = 0;

    }
    else
    {
        mpz_set_ui(m->m, 0);
        fprintf(stderr, "%s (%s %d): plaintext too large\n",
                __FUNCTION__, __FILE__, __LINE__);
        ret = -1;
    }

    element_clear(D);
    element_clear(R);
    return ret;
}

/*void element_dlog_brute_force(element_t x, element_t g, element_t h)*/
//g^x = h in BGN: h = c^q, g = key->k
static int bgn_decrypt_level1_0(bgn_plaintext_t *m, bgn_ciphertext_t *c,
                                bgn_key_t *key)
{
    //int ret = -1;
    unsigned long i;
    element_t D;

    element_init_same_as(D, c->c);
    element_pow_mpz(D, c->c, key->q);

    element_t x;
    element_init_Zr(x,key->pairing);
    element_random(x);
    printf("\nThe group order is %d\n",element_length_in_bytes(x));

    element_dlog_brute_force(x,key->k,D);

    mpz_t xt;
    mpz_init(xt);

    element_to_mpz(xt,x);
    mpz_init_set(m->m,xt);
    element_clear(D);

    /*element_t g0,g;
    mpz_t count;

    mpz_init(count);
    element_init_same_as(g0, key->k);
    element_set(g0, key->k);
    element_init_same_as(g, key->k);
    element_set(g, key->k);
    mpz_set_ui(count, 1);
    while (element_cmp(g0, D) != 0) {
      element_mul(g0, g0, g);
      //element_printf("g0^%Zd = %B\n", count, g0);
      mpz_add_ui(count, count, 1);
    }
    //element_set_mpz(x, count);

    mpz_init_set(m->m,count);
           mpz_clear(count);
           element_clear(g);
           element_clear(g0);
    element_clear(D);*/
    return 0;
}

/*void element_dlog_pollard_rho(element_t x, element_t g, element_t h)*/
//g^x = h in BGN: h = c^q, g = key->k
int bgn_decrypt(bgn_plaintext_t *m, bgn_ciphertext_t *c, bgn_key_t *key)
{
    if (bgn_ciphertext_get_level(c) == 0)
    {
        return bgn_decrypt_level0(m, c, key);
    }
    else	return bgn_decrypt_level1(m, c, key);
}



/*****************************************************************************
 *                      Plaintext Operations
 ****************************************************************************/

int bgn_plaintext_init(bgn_plaintext_t *m)
{
    mpz_init(m->m);
    return 0;
}

int bgn_plaintext_set_word(bgn_plaintext_t *m, unsigned long a)
{
    mpz_set_ui(m->m, a);
    return 0;
}

int bgn_plaintext_set_hex(bgn_plaintext_t *m, const char *str)
{
    if (mpz_set_str(m->m, (char *)str, 16) < 0)
    {
        fprintf(stderr, "%s (%s %d): invalid hex `%s'\n",
                __FUNCTION__, __FILE__, __LINE__, str);
        return -1;
    }
    return 0;
}

int bgn_plaintext_init_set_word(bgn_plaintext_t *m, unsigned long a)
{
    mpz_init_set_ui(m->m, a);
    return 0;
}

int bgn_plaintext_init_set_hex(bgn_plaintext_t *m, const char *str)
{
    if (mpz_init_set_str(m->m, (char *)str, 16) < 0)
    {
        fprintf(stderr, "%s (%s %d): invalid hex `%s'\n",
                __FUNCTION__, __FILE__, __LINE__, str);
        return -1;
    }
    return 0;
}

int bgn_plaintext_to_word(bgn_plaintext_t *m, unsigned long *a)
{
    assert(m);
    assert(a);

    // FIXME: we need to check if m is less than the max unsigned lon
    *a = mpz_get_ui(m->m);
    return 0;
}

int bgn_plaintext_to_hex(bgn_plaintext_t *m, char *buf, size_t buflen)
{
    int outlen = mpz_sizeinbase(m->m, -16);

    if (!buf)
    {
        return outlen;
    }

    if (buflen <= outlen)
    {
        fprintf(stderr, "%s (%s %d): buffer too small\n", __FUNCTION__,
                __FILE__, __LINE__);
        return -1;
    }

    if (!mpz_get_str(buf, -16, m->m))
    {
        fprintf(stderr, "%s (%s %d): convert failed\n", __FUNCTION__,
                __FILE__, __LINE__);
        return -1;
    }

    return outlen;
}

void bgn_plaintext_cleanup(bgn_plaintext_t *m)
{
    mpz_clear(m->m);
    memset(m, 0, sizeof(bgn_plaintext_t));
}


/*****************************************************************************
 *                       Ciphertext Operations
 ****************************************************************************/

int bgn_ciphertext_init(bgn_ciphertext_t *c, int level, bgn_key_t *key)
{

    if (level == 0)
    {
        c->level = 0;
        element_init_G1(c->c, key->pairing);
        element_set0(c->c);

    }
    else if (level == 1)
    {
        c->level = 1;
        element_init_GT(c->c, key->pairing);
        element_set1(c->c);

    }
    else
    {
        fprintf(stderr, "%s (%s %d): invalid level `%d'\n",
                __FUNCTION__, __FILE__, __LINE__, level);
        return -1;
    }

    return 0;
}

int bgn_ciphertext_init_set_str(bgn_ciphertext_t *c, const char *str, bgn_key_t *key)
{

    if (str[0] == '0')
        c->level = 0;
    else if (str[0] == '1')
        c->level = 1;
    else
    {
        fprintf(stderr, "%s (%s %d): invalid ciphertext `%s'\n",
                __FUNCTION__, __FILE__, __LINE__, str);
        return -1;
    }

    if (str[1] != ' ')
    {
        fprintf(stderr, "%s (%s %d): invalid ciphertext `%s'\n",
                __FUNCTION__, __FILE__, __LINE__, str);
        return -1;
    }

    if (c->level == 0)
    {
        element_init_G1(c->c, key->pairing);
        if (bgn_G1_element_set_str(c->c, str + 2) < 0)
        {
            fprintf(stderr, "%s (%s %d): parse G1 elememt failed `%s'\n",
                    __FUNCTION__, __FILE__, __LINE__, str + 2);
            return -1;
        }
        return 0;
    }

    if (c->level == 1)
    {
        element_init_GT(c->c, key->pairing);
        if (bgn_GT_element_set_str(c->c, str + 2) < 0)
        {
            fprintf(stderr, "%s (%s %d): parse G1 elememt failed `%s'\n",
                    __FUNCTION__, __FILE__, __LINE__, str + 2);
            return -1;
        }
        return 0;
    }

    return -1;
}

int bgn_ciphertext_to_str(bgn_ciphertext_t *c, char *buf, size_t buflen)
{
    int outlen;

    if (c->level == 0)
    {
        outlen = 2 + bgn_G1_element_to_str(c->c, NULL, 0);

        /*
        fprintf(stderr, "DEBGU: %s (%s %d): ", __FUNCTION__, __FILE__, __LINE__);
        element_out_str(stderr, -16, c->c);
        fprintf(stderr, "\n");
        */

    }
    else if (c->level == 1)
    {
        outlen = 2 + bgn_GT_element_to_str(c->c, NULL, 0);

        /*
        printf("%s (%s %d): ", __FUNCTION__, __FILE__, __LINE__);
        element_out_str(stdout, -16, c->c);
        printf("\n");
        */

    }
    else
    {
        fprintf(stderr, "%s (%s %d): invlid bgn_ciphertext_t\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    if (!buf)
    {
        return outlen;
    }

    if (buflen <= outlen)
    {
        fprintf(stderr, "%s (%s %d): buffer too small\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    buf[0] = c->level ? '1' : '0';
    buf[1] = ' ';

    if (c->level == 0)
    {
        if (bgn_G1_element_to_str(c->c, buf + 2, buflen - 2) < 0)
        {
            fprintf(stderr, "%s (%s %d): output G1 element failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            return -1;
        }
    }
    else
    {
        if (bgn_GT_element_to_str(c->c, buf + 2, buflen - 2) < 0)
        {
            fprintf(stderr, "%s (%s %d): output GT element failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            return -1;
        }
    }

    buf[outlen] = 0;
    return outlen;
}

int bgn_ciphertext_print(FILE *fp, bgn_ciphertext_t *c)
{
    fprintf(stderr, "%d ", c->level);
    element_fprintf(stderr, "%B\n", c->c);
    return 0;
}

int bgn_ciphertext_get_level(bgn_ciphertext_t *c)
{
    return c->level;
}

static int bgn_ciphertext_add_level0(bgn_ciphertext_t *r,
                                     bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key)
{
    mpz_t t;
    element_t c;

    r->level = 0;

    mpz_init(t);
    /*do {
    	pbc_mpz_randomb(t, key->bits);
    }  while (mpz_cmp(t, key->n) >= 0);*/
    pbc_mpz_random(t, key->n);

    element_init_G1(c, key->pairing);
    element_mul_mpz(c, key->h, t);
    element_add(c, c, a->c);
    element_add(c, c, b->c);

    element_init_same_as(r->c, c);
    element_set0(r->c);
    element_add(r->c, r->c, c);

    mpz_clear(t);
    element_clear(c);
    return 0;
}

static int bgn_ciphertext_add_level1(bgn_ciphertext_t *r,
                                     bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key)
{
    mpz_t t;
    element_t c;

    r->level = 1;

    mpz_init(t);
    /*do {
    	pbc_mpz_randomb(t, key->bits);
    }  while (mpz_cmp(t, key->n) >= 0);*/
    pbc_mpz_random(t, key->n);

    element_init_GT(c, key->pairing);
    element_pow_mpz(c, key->h, t);
    element_mul(c, c, a->c);
    element_mul(c, c, b->c);

    element_init_same_as(r->c, c);
    element_set0(r->c);
    element_add(r->c, r->c, c);

    mpz_clear(t);
    element_clear(c);
    return 0;
}

int bgn_ciphertext_up_level(bgn_ciphertext_t *r, bgn_ciphertext_t *c, bgn_key_t *key)
{
    if (r == c)
    {
        fprintf(stderr, "%s: operand and result should not be the same: %s %d\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }
    element_init_GT(r->c, key->pairing);
    pairing_apply(r->c, c->c, key->P, key->pairing);
    return 0;
}

int bgn_ciphertext_add(bgn_ciphertext_t *r,
                       bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key)
{

    if (a->level == 0 && b->level == 0)
    {
        if (bgn_ciphertext_add_level0(r, a, b, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): add two level0 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            return -1;
        }

        return 0;
    }

    if (a->level == 1 && b->level == 1)
    {
        if (bgn_ciphertext_add_level1(r, a, b, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): add two level1 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            return -1;
        }

        return 0;
    }

    if (a->level ==0 && b->level == 1)
    {
        bgn_ciphertext_t t;

        if (bgn_ciphertext_up_level(&t, a, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): up level op1 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            return -1;
        }

        if (bgn_ciphertext_add_level1(r, &t, b, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): add two level1 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            bgn_ciphertext_cleanup(&t);
            return -1;
        }

        bgn_ciphertext_cleanup(&t);
        return 0;
    }

    if (a->level == 1 && b->level == 0)
    {
        bgn_ciphertext_t t;

        if (bgn_ciphertext_up_level(&t, b, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): up level op2 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            return -1;
        }

        if (bgn_ciphertext_add_level1(r, a, &t, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): add two level1 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            bgn_ciphertext_cleanup(&t);
            return -1;
        }

        bgn_ciphertext_cleanup(&t);
        return 0;

    }

    /* we will never arrive here */
    return -1;
}

static int bgn_ciphertext_sub_level0(bgn_ciphertext_t *r,
                                     bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key)
{

    assert(a->level == 0 && b->level == 0);

    mpz_t t;
    element_t c;

    r->level = 0;

    mpz_init(t);
    /*do {
    	pbc_mpz_randomb(t, key->bits);
    }  while (mpz_cmp(t, key->n) >= 0);*/
    pbc_mpz_random(t, key->n);

    element_init_G1(c, key->pairing);
    element_mul_mpz(c, key->h, t);
    element_add(c, c, a->c);
    element_sub(c, c, b->c);

    element_init_same_as(r->c, c);
    element_set0(r->c);
    element_add(r->c, r->c, c);

    mpz_clear(t);
    element_clear(c);
    return 0;

}

static int bgn_ciphertext_sub_level1(bgn_ciphertext_t *r,
                                     bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key)
{
    assert(a->level == 1 && b->level == 1);

    mpz_t t;
    element_t c;

    r->level = 1;

    mpz_init(t);
    /*do {
    	pbc_mpz_randomb(t, key->bits);
    }  while (mpz_cmp(t, key->n) >= 0);*/
    pbc_mpz_random(t, key->n);

    element_init_GT(c, key->pairing);
    element_pow_mpz(c, key->h, t);
    element_mul(c, c, a->c);
    element_div(c, c, b->c);

    element_init_same_as(r->c, c);
    element_set0(r->c);
    element_add(r->c, r->c, c);

    mpz_clear(t);
    element_clear(c);
    return 0;
}

int bgn_ciphertext_sub(bgn_ciphertext_t *r,
                       bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key)
{


    if (a->level == 0 && b->level == 0)
    {

        if (bgn_ciphertext_sub_level0(r, a, b, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): sub level0 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            return -1;
        }

        return 0;
    }

    if (a->level == 1 && b->level == 1)
    {

        if (bgn_ciphertext_sub_level1(r, a, b, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): sub level0 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            return -1;
        }

        return 0;
    }

    if (a->level == 1 && b->level == 0)
    {

        bgn_ciphertext_t t;
        bgn_ciphertext_init(&t, 0, key);

        if (bgn_ciphertext_up_level(&t, b, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): sub level0 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            bgn_ciphertext_cleanup(&t);
            return -1;
        }

        if (bgn_ciphertext_sub_level1(r, a, &t, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): sub level0 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            bgn_ciphertext_cleanup(&t);
            return -1;
        }

        bgn_ciphertext_cleanup(&t);
        return 0;
    }

    if (a->level == 0 && b->level == 1)
    {

        bgn_ciphertext_t t;
        bgn_ciphertext_init(&t, 0, key);

        if (bgn_ciphertext_up_level(&t, a, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): sub level0 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            bgn_ciphertext_cleanup(&t);
            return -1;
        }

        if (bgn_ciphertext_sub_level1(r, &t, b, key) < 0)
        {
            fprintf(stderr, "%s (%s %d): sub level0 failed\n",
                    __FUNCTION__, __FILE__, __LINE__);
            bgn_ciphertext_cleanup(&t);
            return -1;
        }

        bgn_ciphertext_cleanup(&t);
        return 0;
    }

    return -1;
}

/* e(C1, C2) * e(Q,Q)^t
 * e(Q,Q) == h
 * make sure C1, C2 are point, element_item_count() == 2
 */
int bgn_ciphertext_mul(bgn_ciphertext_t *r,
                       bgn_ciphertext_t *a, bgn_ciphertext_t *b, bgn_key_t *key)
{
    mpz_t t;
    element_t e;
    element_t c;

    if (a->level != 0)
    {
        fprintf(stderr, "%s (%s %d): op1 is not level 0\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    if (b->level != 0)
    {
        fprintf(stderr, "%s (%s %d): op2 is not level 0\n",
                __FUNCTION__, __FILE__, __LINE__);
        return -1;
    }

    mpz_init(t);
    /*do {
    	pbc_mpz_randomb(t, key->bits);
    }  while (mpz_cmp(t, key->n) >= 0);*/
    pbc_mpz_random(t, key->n);

    element_init_GT(c, key->pairing);

    pairing_apply(c, a->c, b->c, key->pairing);
    element_init_GT(e, key->pairing);
    element_pow_mpz(e, key->h, t);
    element_mul(c, c, e);

    element_init_same_as(r->c, c);
    element_set0(r->c);
    element_add(r->c, c, r->c);
    r->level = 1;

    mpz_clear(t);
    element_clear(e);
    element_clear(c);

    return 0;
}

void bgn_ciphertext_cleanup(bgn_ciphertext_t *c)
{
    c->level = 0;
    element_clear(c->c);
}

