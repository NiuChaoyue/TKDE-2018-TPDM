/******
Data Service: Multivariate Gaussian Distribution Fitting
Phase: Outcome Verification (Sampling based method)
@Author: Chaoyue Niu
@Email: rvincency@gmail.com
@References: C. Niu, Z. Zheng, F. Wu, X. Gao, and G. Chen, "Achieving Data Truthfulness and Privacy Preservation in Data Markets", in TKDE, 2018.
             C. Niu, Z. Zheng, F. Wu, X. Gao, and G. Chen, "Trading Data in Good Faith: Integrating Truthfulness and Privacy Preservation in Data Markets", in ICDE, 2017
@Links: https://ieeexplore.ieee.org/document/8330057/
        https://ieeexplore.ieee.org/document/7929976/
@CMDs: gcc -c bgn.c -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
       gcc -Wall -static bgn.o DistributionFittingVer.c -o test -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
       ./test
******/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <libgen.h>
#include <pbc.h>
#include "pbc_test.h"
#include "bgn.h"



#define num_homes 10000
#define num_types 2

int spend[num_homes][8];
bgn_ciphertext_t cipher_spend[num_homes][num_types];
bgn_ciphertext_t cipher_AA[num_homes][num_types];

bgn_ciphertext_t muM[num_types];
bgn_ciphertext_t SigmaM[num_types];

/** Read data from the RECS dataset**/
void readfromefile()
{
    int i, j;
    FILE *fp = fopen("./data/8x10000", "r");
    for(i = 0; i < num_homes; ++i)
    {
        for(j = 0; j < 8; ++j)
        {
            double raw_value;
            fscanf(fp, "%lf", &raw_value);
            spend[i][j] = raw_value/1000;
        }
    }
    fclose(fp);
}

int main(int argc, char **argv)
{
    /** BGN key generation **/
    int flag;
    bgn_key_t sk, pk;
    flag = bgn_key_generate(&sk, 1024);
    flag = bgn_key_init_set(&pk, &sk, 0);

    /**Read RECS dataset from file**/
    readfromefile();

    int i, j;

    /** Data encryption **/
    //Encryption by the data contributor for mean vector
    for(i = 0; i < num_homes; ++i)
    {
        for(j = 0; j < num_types; ++j)
        {
            //judge 0?
            if(spend[i][j] != 0)
            {
                bgn_plaintext_t tmp_plain;
                flag = bgn_plaintext_init_set_word(&tmp_plain, spend[i][j]);
                //E(u_{ij})
                flag = bgn_encrypt(&cipher_spend[i][j], &tmp_plain, &pk);
            }
            else
            {
                bgn_ciphertext_init(&cipher_spend[i][j], 0, &pk);
            }
        }
    }

    //Encryption by the data contributor for <diagonal elements> in covariance matrix
    for(i = 0; i < num_homes; ++i)
    {
        for(j = 0; j < num_types; ++j)
        {
            if(spend[i][j] != 0)
            {
                bgn_plaintext_t tmp_plain;
                flag = bgn_plaintext_init_set_word(&tmp_plain, spend[i][j] * spend[i][j]);
                flag = bgn_encrypt(&cipher_AA[i][j], &tmp_plain, &pk);
            }
            else
            {
                bgn_ciphertext_init(&cipher_AA[i][j], 0, &pk);
            }
        }
    }

    /** Verifying mean vector \mu **/
    for(j = 0; j < num_types; ++j)
    {
        bgn_ciphertext_init(&muM[j], 0, &pk);
        for(i = 0; i < num_homes; ++i)
        {
            bgn_ciphertext_add(&muM[j], &muM[j], &cipher_spend[i][j], &pk);
        }
    }

    /** Verifying diagonal elements of covariance matrix \Sigma **/
    for(j = 0; j < num_types; ++j)
    {
        bgn_ciphertext_init(&SigmaM[j], 0, &pk);
        for(i = 0; i < num_homes; ++i)
        {
            bgn_ciphertext_add(&SigmaM[j], &SigmaM[j], &cipher_AA[i][j], &pk);
        }
    }

    /** Cleanup **/
    bgn_key_cleanup(&pk);
    bgn_key_cleanup(&sk);

    return 0;
}
