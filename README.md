1. This is the source code for our papers:
     C. Niu, Z. Zheng, F. Wu, X. Gao, and G. Chen, "Achieving Data Truthfulness and Privacy Preservation in Data Markets", in TKDE, 2018. (Link: https://ieeexplore.ieee.org/document/8330057/)
     C. Niu, Z. Zheng, F. Wu, X. Gao, and G. Chen, "Trading Data in Good Faith: Integrating Truthfulness and Privacy Preservation in Data Markets", in ICDE, 2017. (Link: https://ieeexplore.ieee.org/document/7929976/)
   and the referenced paper:
     D. Boneh, E. Goh, and K. Nissim, "Evaluating 2-dnf formulas on ciphertexts", in TCC, 2005.
	
2. Keywords: 
   Identity-Based Signature Batch Verification (SS512 and MNT159 elliptic curves), 
   Boneh-Goh-Nissim (BGN )Homomorphic Cryptosystem,
   Profile Matching,
   Multivariate Gaussian Distribution Fitting

3. Required library
   pbc-0.5.14 (https://crypto.stanford.edu/pbc/)
   how to install? https://crypto.stanford.edu/pbc/manual/ch01.html
   
3. Compile commands:
   #Signature Verification
   gcc -c sha1.c
   gcc -c utils.c
   gcc -Wall -static sha1.o utils.o BatchVerification.c -o test -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
   ./test < param/a.param
   or
   ./test < param/d159.param

   #Data Processing and Outcome Verification
   gcc -c bgn.c -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
   gcc -Wall -static bgn.o ProfileMatching.c -o test -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
   or
   gcc -Wall -static bgn.o DistributionFitting.c -o test -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
   or
   gcc -Wall -static bgn.o DistributionFittingVer.c -o test -I/usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp
   ./test
   
4. To record run time, use the function from pbc library: pbc_get_time()