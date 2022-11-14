# soci
SOCI is a Secure Outsourced Computation on Integers based on the Paillier cryptosystem and a twin-server architecture.
Soci mainly focus on how a cloud server provides secure computation services for a data owner that outsources encrypted data to the cloud server. It consists of a Data Owner (DO) and two servers, i.e., a Cloud Platform (CP) and a Computation Service Provider (CSP). 

# ROLES
- DO: DO takes charge of generating and distributing keys to CP and CSP securely. Specifically, DO calls the KeyGen algorithm to generate a PaillierTD public/private key pair (pk; sk) and then splits sk into two partially private keys (sk1; sk2). Next, DO distributes (pk; sk1) and (pk; sk2) to CP and CSP, respectively. To protect data privacy, DO encrypts data with pk and outsources encrypted data to CP. Besides, DO outsources computation services over encrypted data to CP and CSP.
- CP: CP stores and manages the encrypted data sent from DO, and produces the intermediate results and the final results in an encrypted form. In addition, CP can directly execute certain calculations over encrypted data such as homomorphic addition and homomorphic scalarmultiplication. CP interacts with CSP to perform SMUL,SCMP, SSBA, and SDIV over encrypted data.
- CSP: CSP only provides online computation services and does not store any encrypted data. Specifically, CSP cooperates with CP to perform secure computations (e.g., multiplication, comparison, division) on encrypted data


## build Dependencies

* OS: Ubuntu 20.04 LTS.
* make,g++
* gmp

# GMP
GMP is a free library for arbitrary precision arithmetic, operating on signed integers, rational numbers, and floating-point numbers.


## install gmp
Download gmp from [GMP](https://ftp.gnu.org/gnu/gmp/) . you can choose “gmp-6.2.0.tar.xz”.
* Unzip it

Click terminal and type
```sh
tar -xvf gmp-6.2.0.tar.xz
```
* Installing
Go to gmp-6.2.0
```sh
cd gmp-6.2.0
```
* config
```sh
./configure --prefix=/usr --enable-cxx
```

* make
```sh
make
make check
sudo make install
```

# build soci
```sh
make
```

## run soci
```sh
./bin/soci
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


# Benchmark
in src/Main.cpp, you can change the value of KEY_LEN_BIT and SIGMA_LEN_BIT . KEY_LEN_BIT determine the big prime's length in bit, and  SIGMA_LEN_BIT determine sk1's length in bit.

# Interface function description

## Paillier
| Function Name | Description | Input | Output |
| ------ | ------ | ------ | ------ |
| keygen(unsigned long bitLen) | generate a PaillierTD public/private key pair (pk; sk) | bitLen – the intense of key | NULL |
| encrypt(mpz_t c, mpz_t m) | encpyt message m to c using public key pk | m – a plaintext, which is mpz_t type. mpz_t  is a GMP data type which is a multiple precision integer(same below). | c – encrypted result, is a ciphertext and mpz_t type. |
| decrypt(mpz_t m, mpz_t c) | decpyt ciphertext c to plaintext m using private key sk | c – a ciphertext, which is mpz_t type. | m – decrypted result, is a plaintext and mpz_t type. |
| add(mpz_t res, mpz_t c1, mpz_t c2)  | additive homomorphism operation | c1 –augend, is a ciphertext and mpz_t type, which must be less than n^2. c2 –another augend, is a ciphertext and mpz_t type, which must be less than n^2  | res – the result of additive homomorphism of c1 and c2, is a ciphertext, also mpz_t type.|
| scl_mul(mpz_t res, mpz_t c, mpz_t e) | scalar-multiplication homomorphism operation | c – is a ciphertext and mpz_t type, which must be less than n^2.e – is a plaintext and mpz_t type, which must be less than n.| res – the result of scalar-multiplication homomorphism of c and e, is a ciphertext, also mpz_t type. |