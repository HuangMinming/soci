# soci
SOCI is a Secure Outsourced Computation on Integers based on the Paillier cryptosystem and a twin-server architecture.
Soci mainly focus on how a cloud server provides secure computation services for a data owner that outsources encrypted data to the cloud server. It consists of a Data Owner (DO) and two servers, i.e., a Cloud Platform (CP) and a Computation Service Provider (CSP). 

# ROLES
- DO: DO takes charge of generating and distributing keys to CP and CSP securely. Specifically, DO calls the KeyGen algorithm to generate a PaillierTD public/private key pair (pk; sk) and then splits sk into two partially private keys (sk1; sk2). Next, DO distributes (pk; sk1) and (pk; sk2) to CP and CSP, respectively. To protect data privacy, DO encrypts data with pk and outsources encrypted data to CP. Besides, DO outsources computation services over encrypted data to CP and CSP.
- CP: CP stores and manages the encrypted data sent from DO, and produces the intermediate results and the final results in an encrypted form. In addition, CP can directly execute certain calculations over encrypted data such as homomorphic addition and homomorphic scalarmultiplication. CP interacts with CSP to perform SMUL,SCMP, SSBA, and SDIV over encrypted data.
- CSP: CSP only provides online computation services and does not store any encrypted data. Specifically, CSP cooperates with CP to perform secure computations (e.g., multiplication, comparison, division) on encrypted data

## GMP
GMP is a free library for arbitrary precision arithmetic, operating on signed integers, rational numbers, and floating-point numbers. [https://gmplib.org/](https://gmplib.org/)

## build Dependencies

* OS: Ubuntu 20.04 LTS.




## build
```sh
cd gmp-6.2.0
./configure --prefix=/usr --enable-cxx
make
make check
make install
cd ..
make
```

## run
```sh
./soci
```
## output:
    set x = -99, y = -789
    run add function, its running time is  ------  0.004000 ms
    x + y = -888
    ---------------------------
    set x = -99, y = -789
    compute scl_mul function, its running time is  ------  0.044000 ms
    x*y = 78111
    ---------------------------
    Secure computation protocols
    set x = -99, y = -789
    compute SMUL function, its running time is  ------  15.234000 ms
    x*y = 78111
    ---------------------------
    set x = -99, y = -789
    compute SCMP function, its running time is  ------  7.397000 ms
    x>=y? = 0
    ---------------------------
    set x = -99
    compute SSBA function, its running time is  ------  23.278000 ms
    s_x = 1 u_x = 99
    ---------------------------
    set x = 5429496723, y = 9949672
    compute SDIV function, its running time is  ------  739.991000 ms
    q = 545 r = 6925483
    ---------------------------
