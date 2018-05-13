/******
Identity-Based Batch Signature Verification
Curve: SS15 or MNT 159
@Author: Chaoyue Niu
@Email: rvincency@gmail.com
@References: C. Niu, Z. Zheng, F. Wu, X. Gao, and G. Chen, "Achieving Data Truthfulness and Privacy Preservation in Data Markets", in TKDE, 2018.
             C. Niu, Z. Zheng, F. Wu, X. Gao, and G. Chen, "Trading Data in Good Faith: Integrating Truthfulness and Privacy Preservation in Data Markets", in ICDE, 2017
@Links: https://ieeexplore.ieee.org/document/8330057/
        https://ieeexplore.ieee.org/document/7929976/
@CMDs: gcc -c sha1.c
       gcc -c utils.c
       gcc -Wall -static sha1.o utils.o BatchVerification.c -o test -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
       ./test < param/a.param
       or
       ./test < param/d159.param
******/

#include <pbc.h>
#include <gmp.h>
#include "pbc_test.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "utils.h"


#define SIZE 100    //for the D2
const int Num_Data_owners = 10000;


int main(int argc, char **argv)
{
    pairing_t pairing;
    element_t g1, g2;     //g1 is the generator of G1; g2 is the generator of G2.

    element_t s1, s2;
    /*P0 = g1^s1, P1 = g2^s1, P3 = g2^s2*/
    element_t P0, P1, P2;

    pbc_demo_pairing_init(pairing, argc, argv);

    element_init_G1(g1, pairing);
    element_init_G2(g2, pairing);
    element_init_Zr(s1, pairing);
    element_init_Zr(s2, pairing);
    element_init_G1(P0, pairing);
    element_init_G2(P1, pairing);
    element_init_G2(P2, pairing);

    //printf("MNT Curve Batch Signature Verification\n");
    /** Initialization **/
    element_random(g1);
    element_random(g2);

    //element_printf("Two generators g1 = %B, length = %d ; g2 = %B, len = %d \n", g1,element_length_in_bytes(g1), g2, element_length_in_bytes(g2));

    //generate two master keys s1, s2
    element_random(s1);
    element_random(s2);
    //element_printf("Two master keys s1 = %B; s2 = %B\n", s1, s2);

    //compute corresponding public key P0, P1, P2
    element_pow_zn(P0, g1, s1);
    element_pow_zn(P1, g2, s1);
    element_pow_zn(P2, g2, s2);

    /*printf("\n\n------------G1-begin-----------\n");
    int G1len_0 = 0;
    G1len_0 = element_length_in_bytes(P0);
    printf("G1 element_length_in_bytes %d\n",G1len_0);
    int G1len_1 = 0;
    G1len_1 = element_length_in_bytes_compressed(P0);
    printf("G1 element_length_in_bytes_compressed %d\n",G1len_1);
    int G1item = 0;
    G1item = element_item_count(P0);
    printf("G1 element_item_count %d\n\n",G1item);

    element_printf("\nG1: element_printf: %B\n", P0);
    printf("\n\n------------G1-end-----------\n");

    printf("\n\n------------G2-begin-----------\n");
    int G2len_0 = 0;
    G2len_0 = element_length_in_bytes(g2);
    printf("G2 element_length_in_bytes %d\n",G2len_0);
    int G2len_1 = 0;
    G2len_1 = element_length_in_bytes_compressed(g2);
    printf("G2 element_length_in_bytes_compressed %d\n",G2len_1);
    int G2item = 0;
    G2item = element_item_count(g2);
    printf("G2 element_item_count %d\n\n",G2item);

    element_printf("\nG2: element_printf: %B\n", g2);
    printf("\n\n------------G2-end-----------\n");*/

    //element_printf("Public key P0 = %B; P1 = %B; P2 = %B\n", P0, P1, P2);
    //printf("\n\nKeys Generation Time %f\n\n",setupt1 - setupt0);


    /** Pseudo identity and Signing Key Generation **/
    //PID1 = g1^r and PID2 = RID xor P0^r
    //SK1 = PID1^s1 and SK2 = H(PID2)^s2
    element_t SIGMA[Num_Data_owners];   //G1
    element_t PID1[Num_Data_owners];    //G1
    element_t hD2[Num_Data_owners];   //Zr
    element_t HPID2[Num_Data_owners];    //G1
    element_t r, RID, P0r, SK1, SK2, SK2hD2;

    element_init_Zr(r, pairing);
    element_init_G1(RID, pairing);
    element_init_G1(P0r, pairing);
    element_init_G1(SK1, pairing);
    element_init_G1(SK2, pairing);
    element_init_G1(SK2hD2, pairing);

    char PID2[320];
    unsigned char C1PID[320];    //RID to string
    //char sha1PID[SIZE];   //40 RID
    unsigned char C2PID[320];      //P0 ^r to string
    //char sha2PID[SIZE];     //40 P0r
    char hD22[SIZE];
    char xor_result[SIZE] = "6CB3C72FD046A502AA1DE40C63B67377A604CD4E";     //Data2
    //sha_fun(xor_result, hD22);   !!!Pay Attention!!Not here

    int cnt = 0;
    for(cnt = 0; cnt < Num_Data_owners; ++cnt)
    {
        memset(PID2,0,sizeof(char)*SIZE);
        memset(C1PID,0,sizeof(unsigned char)*SIZE);
        //memset(sha1PID,0,SIZE);
        memset(C2PID,0,sizeof(unsigned char)*SIZE);
        //memset(sha2PID,0,SIZE);
        memset(hD22,0,sizeof(char)*SIZE);

        element_random(r);
        element_random(RID);

        element_init_G1(PID1[cnt], pairing);

        element_pow_zn(PID1[cnt], g1, r);
        element_pow_zn(P0r, P0, r);

        element_to_bytes(C1PID, RID);
        //sha_fun(C1PID, sha1PID);
        element_to_bytes(C2PID, P0r);
        //sha_fun(C2PID, sha2PID);
        int i;
        for (i = 0; i < 40; i++)
        {
            xor_operation(C1PID[i], C2PID[i], PID2);
        }
        element_pow_zn(SK1, PID1[cnt], s1);

        element_init_G1(HPID2[cnt], pairing);
        element_from_hash(HPID2[cnt], PID2, 40);

        element_pow_zn(SK2, HPID2[cnt], s2);

        //Signing on the encrypted data
        //sigma = SK1 x SK2 ^ h(D2)
        element_init_Zr(hD2[cnt], pairing);
        sha_fun(xor_result, hD22);
        element_set_str(hD2[cnt], hD22, 10);

        element_pow_zn(SK2hD2, SK2, hD2[cnt]);

        element_init_G1(SIGMA[cnt], pairing);
        element_mul(SIGMA[cnt], SK1, SK2hD2);
    }

    /** Batch Signature Verification (SS512 or MNT159)**/
    //e(sigma, g2) = e(PID1, P1) . e(H(PID2)^hD2, P2)
    element_t lhs, rhs1, rhs2, rhs, SIGMA_MUL, PID1MUL, HPID2hD2, HPID2hD2MUL;
    element_init_GT(lhs, pairing);
    element_init_GT(rhs1, pairing);
    element_init_GT(rhs2, pairing);
    element_init_GT(rhs, pairing);

    element_init_G1(HPID2hD2, pairing);
    element_init_G1(SIGMA_MUL, pairing);
    element_init_G1(PID1MUL, pairing);
    element_init_G1(HPID2hD2MUL, pairing);

    element_set1(SIGMA_MUL);
    element_set1(PID1MUL);
    element_set1(HPID2hD2MUL);
    for(cnt = 0; cnt < Num_Data_owners; ++cnt)
    {
        element_mul(SIGMA_MUL,SIGMA_MUL,SIGMA[cnt]);
        element_mul(PID1MUL,PID1MUL,PID1[cnt]);

        element_pow_zn(HPID2hD2, HPID2[cnt], hD2[cnt]);

        element_mul(HPID2hD2MUL,HPID2hD2MUL,HPID2hD2);
    }

    element_pairing(lhs, SIGMA_MUL, g2);
    element_pairing(rhs1, PID1MUL, P1);
    element_pairing(rhs2, HPID2hD2MUL, P2);

    element_mul(rhs, rhs1, rhs2);

    if(element_cmp(lhs,rhs) == 0)
    {
        printf("Batch verification succeeds!\n");
    }
    else
    {
        printf("Batch verification fails!\n");
    }

    /*printf("\n\n------------GT-begin-----------\n");
    int GTlen_0 = 0;
    GTlen_0 = element_length_in_bytes(rhs2);
    printf("GT element_length_in_bytes %d\n",GTlen_0);
    int GTlen_1 = 0;
    GTlen_1 = element_length_in_bytes_compressed(rhs2);
    printf("GT element_length_in_bytes_compressed %d\n",GTlen_1);
    int GTitem = 0;
    GTitem = element_item_count(rhs2);
    printf("GT element_item_count %d\n\n",GTitem);

    element_printf("\nGT: element_printf: %B\n", rhs2);
    printf("\n\n------------GT-end-----------\n\n");*/

    /*element_printf("\nGT rhs= %B, len = %d\n", rhs,element_length_in_bytes(rhs));
    element_printf("\nGT rhs1= %B, len = %d\n", rhs1,element_length_in_bytes(rhs1));
    element_printf("\nGT rhs2= %B, len = %d\n", rhs2,element_length_in_bytes(rhs2));
    element_printf("\nGT lhs= %B, len = %d\n", lhs,element_length_in_bytes(lhs));*/

    /** Free Space **/
    element_clear(g1);
    element_clear(g2);
    element_clear(s1);
    element_clear(s2);
    element_clear(P0);
    element_clear(P1);
    element_clear(P2);

    for(cnt = 0; cnt < Num_Data_owners; ++cnt)
    {
        element_clear(SIGMA[cnt]);
        element_clear(PID1[cnt]);
        element_clear(hD2[cnt]);
        element_clear(HPID2[cnt]);
    }
    element_clear(r);
    element_clear(RID);
    element_clear(P0r);
    element_clear(SK1);
    element_clear(SK2);
    element_clear(SK2hD2);

    element_clear(lhs);
    element_clear(rhs1);
    element_clear(rhs2);
    element_clear(rhs);
    element_clear(SIGMA_MUL);
    element_clear(PID1MUL);
    element_clear(HPID2hD2);
    element_clear(HPID2hD2MUL);
    pairing_clear(pairing);
    return 0;
}


