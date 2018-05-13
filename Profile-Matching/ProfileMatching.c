/******
Data Service: Profile Matching
Phases: Data Processing and Outcome Verification
@Author: Chaoyue Niu
@Email: rvincency@gmail.com
@References: C. Niu, Z. Zheng, F. Wu, X. Gao, and G. Chen, "Achieving Data Truthfulness and Privacy Preservation in Data Markets", in TKDE, 2018.
             C. Niu, Z. Zheng, F. Wu, X. Gao, and G. Chen, "Trading Data in Good Faith: Integrating Truthfulness and Privacy Preservation in Data Markets", in ICDE, 2017
@Links: https://ieeexplore.ieee.org/document/8330057/
        https://ieeexplore.ieee.org/document/7929976/
@CMDs: gcc -c bgn.c -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
       gcc -Wall -static bgn.o ProfileMatching.c -o test -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
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


const int Attributes = 35;
const int InterestLevel = 10;
const int NumDataOwners = 1000;


int main(int argc, char **argv)
{
    int flag;
    /**BGN Key Generation**/
    bgn_key_t sk, pk;

    flag = bgn_key_generate(&sk, 1024);
    flag = bgn_key_init_set(&pk, &sk, 0);


    int i = 0;
    int j = 0;
    int arr[NumDataOwners + 1][Attributes];  //i = 0 for the data consumer

    /**Table-based Decryption**/
    /*
    int T = InterestLevel * InterestLevel * Attributes + 1;
    element_init_same_as(mytable[0],sk.k);
    element_set1(mytable[0]);
    for(i = 1;i < T;++i)
    {
       element_init_same_as(mytable[i],sk.k);
       element_mul(mytable[i],mytable[i-1],sk.k);
    }
    */

    /**Reading Profiles from File**/
    memset(arr,0,sizeof(arr));

    char filename[1024];
    snprintf(filename, sizeof(filename), "%s%d%s", "./data/Profile", Attributes, "x10000");
    FILE *fp = fopen(filename, "r");  //Attributes
    int interest = 0;
    if(fp == NULL)
    {
        printf("Failed to open the file!\n");
        return 1;
    }
    for(i = 0; i < NumDataOwners + 1; ++i)
    {
        for(j = 0; j < Attributes; ++j)
        {
            fscanf(fp, "%d", &interest);
            arr[i][j] = interest;
        }
    }
    fclose(fp);

    /**Encryption for the data consumer**/
    int delta = 12;
    int vj = 0;
    int vj2 = 0;

    bgn_plaintext_t V[Attributes][2];
    bgn_ciphertext_t VC[Attributes][2];

    for(j = 0; j < Attributes; ++j)
    {
        vj = arr[0][j];
        vj2 = vj * vj;
        flag = bgn_plaintext_init_set_word(&V[j][0], vj2);
        flag = bgn_plaintext_init_set_word(&V[j][1], 2 * vj);
        //E(vj^2), E(T - 2vj)
        flag = bgn_encrypt(&VC[j][0], &V[j][0], &pk);
        flag = bgn_encrypt(&VC[j][1], &V[j][1], &pk);
    }

    /**Encryption for data owners**/
    int uij = 0;
    int uij2 = 0;
    bgn_plaintext_t Ui[Attributes][2];
    bgn_ciphertext_t UCi[Attributes][2];
    bgn_ciphertext_t RCi[Attributes];

    bgn_plaintext_t plain1;
    flag = bgn_plaintext_init_set_word(&plain1, 1);
    bgn_ciphertext_t cipher1;
    flag = bgn_encrypt(&cipher1, &plain1, &pk);

    int totalflag = 1;
    int calflag = 1;
    int thresholdflag = 1;

    for(i = 1; i <= NumDataOwners; ++i)
    {
        printf("\n------* %d-th data owner starts! *------\n", i);
        totalflag = 1;
        calflag = 1;
        thresholdflag = 1;
        //Data owner i
        for(j = 0; j < Attributes; ++j)
        {
            uij = arr[i][j];
            uij2 = uij * uij;
            flag = bgn_plaintext_init_set_word(&Ui[j][0], uij);
            flag = bgn_plaintext_init_set_word(&Ui[j][1], uij2);
            //E(uij), E(uij^2)
            flag = bgn_encrypt(&UCi[j][0], &Ui[j][0], &pk);
            flag = bgn_encrypt(&UCi[j][1], &Ui[j][1], &pk);
        }

        //Profile Matching
        bgn_ciphertext_t sumC;
        bgn_ciphertext_init(&sumC,1,&pk);
        for(j = 0; j < Attributes; ++j)
        {
            bgn_ciphertext_t tmpC0;
            bgn_ciphertext_t tmpC1;
            bgn_ciphertext_t tmpC2;

            bgn_ciphertext_mul(&tmpC0, &VC[j][0], &cipher1, &pk);
            bgn_ciphertext_mul(&tmpC1, &VC[j][1], &UCi[j][0], &pk);
            bgn_ciphertext_mul(&tmpC2, &cipher1, &UCi[j][1], &pk);

            bgn_ciphertext_t tmpC01;

            //Here is sub!!!
            bgn_ciphertext_sub(&tmpC01, &tmpC0, &tmpC1, &pk);
            bgn_ciphertext_add(&RCi[j], &tmpC01, &tmpC2, &pk);
            bgn_ciphertext_add(&sumC, &sumC, &RCi[j], &pk);
        }


        /**BGN Decryption**/
        unsigned long sum_P = 0;
        //Brute Force
        bgn_plaintext_t sumP;
        flag = bgn_decrypt(&sumP, &sumC, &sk);

        assert(flag >= 0);
        bgn_plaintext_to_word(&sumP, &sum_P);

        //Table Searching
        /*element_t sumCQ;
        element_init_same_as(sumCQ, sumC.c);
        element_pow_mpz(sumCQ, sumC.c, sk.q);
        int k = 0;
        for(k = 0; k < T;++k)
        {
           if(element_cmp(sumCQ, mytable[k]) == 0)
           {
               break;
           }
        }
        sum_P = k;
        */

        printf("Squared similarity difference = %lu\n", sum_P);

        //Decryption Checking
        unsigned long sum_P2 = 0;
        for(j = 0; j < Attributes; ++j)
        {
            sum_P2 += (arr[i][j] - arr[0][j]) * (arr[i][j] - arr[0][j]);
        }
        if(sum_P != sum_P2)
        {
            calflag = 0;
            printf("Decryption 1 Failure!\n");
            printf("True value %lu != sum_P   %lu\n", sum_P2, sum_P);
        }
        else
        {
            printf("True value %lu = sum_P = %lu\n", sum_P2, sum_P);
        }
        if(calflag == 1 && sum_P >= delta * delta)
        {
            thresholdflag = 0;
            printf("Data owner %d over the threshold!\n", i);
        }
        totalflag = calflag && thresholdflag;
        if(totalflag == 1)
        {
            printf("Data owner %d matched!\n",i);
        }
        else
        {
            printf("Data owner %d unmatched!\n",i);
        }

        /**Outcome Verification**/
        bgn_ciphertext_t sumCV;
        bgn_ciphertext_init(&sumCV,0,&pk);

        bgn_ciphertext_t tmpSub;
        tmpSub.level = 0;
        element_t tmpSubEle;
        element_init_G1(tmpSubEle, pk.pairing);
        element_init_same_as(tmpSub.c, tmpSubEle);

        for(j = 0; j < Attributes; ++j)
        {

            //UCi[j][0]   V[j][1]
            element_mul_mpz(tmpSubEle, UCi[j][0].c, V[j][1].m);
            element_set(tmpSub.c, tmpSubEle);

            bgn_ciphertext_add(&sumCV, &sumCV, &UCi[j][1], &pk);
            bgn_ciphertext_add(&sumCV, &sumCV, &VC[j][0], &pk);
            bgn_ciphertext_sub(&sumCV, &sumCV, &tmpSub, &pk);
        }

        bgn_plaintext_t sumPV;

        flag = bgn_decrypt(&sumPV, &sumCV, &sk);

        unsigned long sum_PV = 0;
        bgn_plaintext_to_word(&sumPV, &sum_PV);
        printf("Verified squared similarity difference = %lu\n", sum_PV);
        if(sum_PV != sum_P2)
        {
            printf("Decryption in outcome verification fails!\n");
            printf("True value %lu != sum_PV %lu\n", sum_P2, sum_PV);
        }
        else
        {
            printf("Yeah! Data owner %d outcome verification succeeds!\n", i);
        }
        printf("\n------* %d-th data owner ends! *------\n", i);
    }

    /** Cleanup **/
    bgn_key_cleanup(&pk);
    bgn_key_cleanup(&sk);
    return 0;
}
