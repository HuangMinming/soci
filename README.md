# <center>Secure Computation on Integers Scheme -- C/C++ Project

# SOCI

The Secure Outsourced Computation on Integers (SOCI) scheme employs a twin-server architecture that is based on the Paillier cryptosystem. This framework enables secure outsourced computation involving encrypted integers, as opposed to being limited to natural numbers [1]. Notably, SOCI achieves significant improvements in computational efficiency compared to fully homomorphic encryption mechanisms. Within the SOCI framework, a comprehensive set of efficient secure computation protocols has been developed, encompassing secure multiplication ($\textsf{SMUL}$), secure comparison ($\textsf{SCMP}$), secure sign bit-acquisition ($\textsf{SSBA}$), and secure division ($\textsf{SDIV}$). These protocols have been designed to facilitate secure computations on both non-negative integers and negative integers, providing a versatile and robust solution for secure outsourced computation.


# Preliminary

The protocols within the SOCI framework are constructed upon the foundation of the Paillier cryptosystem with threshold decryption (PaillierTD). This variant of the conventional Paillier cryptosystem divides the private key into two partially private keys. Importantly, neither of these partially private keys alone possesses the capability to effectively decrypt a ciphertext that has been encrypted using the Paillier cryptosystem. The PaillierTD scheme comprises the following algorithms.

$\textbf{Key Generation} (\textsf{KeyGen})$: Let $p,q$ be two strong prime numbers (i.e., $p=2p'+1$ and $q=2q'+1$, where $p'$ and $q'$ are prime numbers) with $\kappa$ bits (e.g., $\kappa=512$). Compute $N=p\cdot q$, $\lambda=lcm(p-1,q-1)$ and $\mu=\lambda^{-1}\mod N$. Let the generator $g=N+1$, the public key $pk=(g,N)$ and the private key $sk=\lambda$.

The private key $\lambda$ is split into two parts denoted by $sk_1=\lambda_1$ and $sk_2=\lambda_2$, s.t., $\lambda_1+\lambda_2=0\mod\lambda$ and $\lambda_1+\lambda_2=1\mod N$. According to the Chinese remainder theorem, we can calculate $\sigma=\lambda_1+\lambda_2=\lambda\cdot\mu\mod(\lambda\cdot\mu)$ to make $\delta=0\mod\lambda$ and $\delta=1\mod N$ hold at the same time, where $\lambda_1$ can be a $\sigma$-bit random number and $\lambda_2=\lambda\cdot\mu+\eta\cdot\lambda N-\lambda_1$ ($\eta$ is a non-negative integer).

$\textbf{Encryption} (\textsf{Enc})$: Taken as input a message $m\in\mathbb{Z}_N$, this algorithm outputs $[m]\leftarrow\textsf{Enc}(pk,m)=g^m\cdot r^N\mod N^2$, where $r$ is a random number in $\mathbb{Z}^*_N$ and $[m]=[m\mod N]$. 

$\textbf{Decryption} (\textsf{Dec})$: Taken as input a ciphertext $[m]$ and $sk$, this algorithm outputs $m\leftarrow\textsf{Dec}(sk,[m])=L([m]^{\lambda}\mod N^2)\cdot\mu\mod N$, where $L(x)=\frac{x-1}{N}$.

$\textbf{Partial Decryption} (\textsf{PDec})$: Take as input a ciphertext $[m]$ and a partially private key $sk_i$ ($i\in\{1,2\}$), and outputs $M_i\leftarrow\textsf{PDec}(sk_i,[m])=[m]^{\lambda_i}\mod N^2$.

For brevity, we will omot $\mod N^2$ for $\textsf{Enc}$ algorithm in the rest of the document.

PaillierTD has the additive homomorphism and scalar-multipilication homomorphism as follows.

- Additive homomorphism: $\textsf{Dec}(sk,[m_1+m_2\mod N])=\textsf{Dec}(sk,[m_1]\cdot[m_2])$;

- Scalar-multiplication homomorphism: $\textsf{Dec}(sk,[c\cdot m\mod N])=\textsf{Dec}(sk,[m]^c)$ for $c\in\mathbb{Z}^*_N$. Particularly, when $c=N-1$, $\textsf{Dec}(sk,[m]^c)=-m$ holds.


# System Architecture
![SOCI system architecture](./resource/SOCI_system_architecture.png)

The system architecture of SOCI, depicted in the figure above, comprises a data owner (DO) and two servers: a cloud platform (CP) and a computation service provider (CSP).

- DO: The DO is responsible for securely generating and distributing keys to both CP and CSP. To achieve this, the DO initiates the $\textsf{KeyGen}$ algorithm to create a public/private key pair, denoted as $(pk, sk)$, for the Paillier cryptosystem. Subsequently, the DO splits the private key $sk$ into two partially private keys, labeled as $(sk_1, sk_2)$. Following this, the DO distributes $(pk, sk_1)$ and $(pk, sk_2)$ to CP and CSP, respectively. To safeguard data privacy, the DO encrypts data using the public key $pk$ and then outsources the encrypted data to CP. Additionally, the DO outsources computation services, performed on the encrypted data, to both CP and CSP.
- CP: CP is responsible for storing and managing the encrypted data transmitted by the DO. It also generates intermediate results and final results while keeping them in an encrypted form. Furthermore, CP is capable of directly executing specific calculations over encrypted data, such as homomorphic addition and homomorphic scalar multiplication. CP collaborates with CSP to execute secure operations like $\textsf{SMUL}$, $\textsf{SCMP}$, $\textsf{SSBA}$, and $\textsf{SDIV}$ on encrypted data.
- CSP: CSP exclusively offers online computation services and does not retain any encrypted data. Specifically, CSP works in conjunction with CP to perform secure computations, such as multiplication, comparison, and division, on encrypted data.


# SOCI API Description

The project in this version is written in C/C++.

## Paillier.keygen()

Taken as input a security parameter $\kappa$, this algorithm generates two strong prime numbers $p$, $q$ with $\kappa$ bits. Then, it compute $N = p\cdot q$, $\lambda=lcm(p-1,q-1)$, $\mu=\lambda^{-1}\mod N$ and $g= N+1$. It outputs the public key $pk=(g,N)$ and private key $sk=\lambda$.



## ThirdKeyGen.thdkeygen()
Taken as input the private key  $sk$ , this algorithm computes $sk_1$ and $sk_2$. The cloud platform stores $cp=(pk,sk_1)$ and the computation service provider stores $csp=(pk, sk_2)$.

The private key $sk=\lambda$ is split into two parts denoted by $sk_1 = \lambda_1$ and $sk_2 = \lambda_2$, s.t., $\lambda_1+\lambda_2=0\mod\lambda$ and $\lambda_1+\lambda_2=1\mod N$. 


## Paillier.encrypt()
Taken as input a plaintext $m$ which is mpz_t type,  this algorithm encrypts $m$ into ciphertext $c$ with public $pk$. The output ciphertext $c$ is also mpz_t type. In the computations of SOCI, the value of message $m$ should be between $-N/2$ and $N/2$.

Note: mpz_t is a GMP data type which is a multiple precision integer. 

## Paillier.decrypt()
Taken as input a ciphertext $c$,  this algorithm decrypts $c$ into plaintext $m$ with secret key $sk$. Both $c$ and $m$ are mpz_t type. The input ciphertext $c$ should be between 0 and $N^2$ to guarantee correct decryption.


## PaillierThd.pdec()
Given a ciphertext $c$, this algorithm partial decrypts $c$ into partially decrypted ciphertext $C_1$ with partial secret key $sk_1$, or partial decrypts $c$ into $C_2$ with $sk_2$. Both $C_1$ and $C_2$ are and mpz_t type.

## PaillierThd.fdec()
Given partially decrypted ciphtexts $C_1$ and $C_2$ are partially decrypted ciphertext of $c$, this algorithm outputs the plaintext $m$ of $c$. The output plaintext $m$ is mpz_t type.

## Paillier.add()
Given two ciphertext $c_1$ and $c_2$,  this algorithm computes the additive homomorphism and output the result $res$. Suppose $c_1=[m_1]$ and $c_2=[m_2]$. Then, the result $res=[m_1+m_2]$. The input ciphertexts $c_1$ and $c_2$ should be mpz_t type and the values should between 0 and $N^2$. The outputresult $res$ is also mpz_t type.

## Paillier.scl_mul()
Given a ciphertext $c_1$ and a plaintext integer $e$,  this algorithm computes the scalar-multiplication homomorphism and output the result $res$. Suppose $c_1=[m_1]$. Then, the result $res=[m_1]^e$.
 The input ciphertext $c_1$ should between 0 and $N^2$, $e$ is a plaintext and should be between 0 and $N$. Both of $c_1$ and $e$ should be mpz_t type. The result $res$ is also mpz_t type.

## PaillierThd.smul()
Given ciphertexts $ex$ and $ey$, this algorithm computes the multiplication homomorphism and outputs the result $res$. Suppose $ex=[x]$ and $ey=[y]$. Then, the result $res=[x\cdot y]$. The result $res$ is mpz_t type.

## PaillierThd.scmp()
Given ciphertexts $ex$ and $ey$, this algorithm computes the secure comparison result $res$. Suppose $ex=[x]$ and $ey=[y]$. Then, the result $res=[1]$ if $x \lt y$, and $res=[0]$ if $x\geq y$.  The result $res$ is mpz_t type.

## PaillierThd.ssba()
Given a ciphertext $ex$, this algorithm computes the secure sign bit-acquisition result $s_x$ and $u_x$. Suppose $ex=[x]$. Then, the result $s_x=[1]$ and $u_x=[-x]$ if $x<0$, and $s_x=[0]$ and $u_x=[x]$ if $x\geq 0$.  Both $s_x$ and $u_x$ are mpz_t type ciphertext.

## PaillierThd.sdiv()

Given ciphertexts $ex$ and $ey$ (say $ex=[x]$ and $ey=[y]$), this algorithm computes the encrypted quotient $eq$ and the encrypted remainder $er$ of $x$ divided by $y$. Another input is a ciphertext $el$ ($el=[\ell]$), where $\ell$ is a constant (e.g., $\ell$ = 32) used to control the domain size of plaintext.


# build Dependencies

* OS: Ubuntu 20.04 LTS.
* make,g++
* GMP

# GMP
[GMP](https://gmplib.org/) is a free library for arbitrary precision arithmetic, operating on signed integers, rational numbers, and floating-point numbers.


## install GMP
Download GMP from [GMP](https://ftp.gnu.org/gnu/gmp/) . you can choose “gmp-6.2.0.tar.xz”.
* Unzip it

Click terminal and type
```sh
tar -xvf gmp-6.2.0.tar.xz
```
* Go to gmp-6.2.0
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

# Build SOCI
```sh
make
```

## Run SOCI
```sh
./bin/soci
```
## Output:
    set x = 99, y = 789
    run add function, its running time is  ------  0.010000 ms
    x + y = 888
    ---------------------------
    set x = 99, y = 789
    compute scl_mul function, its running time is  ------  0.018000 ms
    x*y = 78111
    ---------------------------
    Secure computation protocols
    set x = 99, y = 789
    compute SMUL function, its running time is  ------  13.986000 ms
    x*y = 78111
    ---------------------------
    set x = 99, y = 789
    compute SCMP function, its running time is  ------  7.919000 ms
    x>=y? = 1
    ---------------------------
    set x = 99
    compute SSBA function, its running time is  ------  21.188000 ms
    s_x = 0 u_x = 99
    ---------------------------
    set x = 5429496723, y = 9949672
    compute SDIV function, its running time is  ------  742.709000 ms
    q = 545 r = 6925483
    ---------------------------

# Performance
We employed varying values of KEY_LEN_BIT to assess the performance of each function. The experiments were conducted on a laptop equipped with a 10th Gen Intel(R) Core(TM) i5-10210U CPU, consisting of 2 cores running at 2.70 GHz and 2 cores running at 2.69 GHz, with 16GB of RAM. The obtained experimental results are detailed below:
|**Length of key in bit**| **KEY_LEN_BIT**|**256**|**384**|**512**|**640**| **768** | **896** | **1024**|
| ------ | ------ | ------ | ------ |------ |------ |  ------ |------ |------ |
| 	PaillierTD Encryption		| 	encrypt	| 	0.31015	| 	0.5553	| 	1.21225	| 	2.1346	| 	3.76635	| 	5.97745	| 	8.01885	| 
| 	PaillierTD Decryption		| 	decrypt	| 	0.24085	| 	0.54355	| 	1.2006	| 	2.1238	| 	3.8087	| 	5.73475	| 	7.98915	| 
| 	Secure Addition		| 	add	| 	0.0007	| 	0.001	| 	0.0014	| 	0.00205	| 	0.0029	| 	0.0046	| 	0.0045	| 
| 	Secure Scalar Multiplication		| 	scl_mul	| 	0.0146	| 	0.0245	| 	0.0374	| 	0.0529	| 	0.0775	| 	0.11135	| 	0.1269	| 
| 	Secure Multiplication		| 	SMUL	| 	2.0798	| 	5.6713	| 	12.12965	| 	20.92335	| 	37.91795	| 	54.50355	| 	82.22075	| 
| 	Secure Comparison		| 	SCMP	| 	0.9691	| 	2.87705	| 	6.0354	| 	10.9546	| 	18.1335	| 	28.78905	| 	40.70935	| 
| 	Secure Sign Bit-Acquisition		| 	SSBA	| 	2.8683	| 	8.49485	| 	18.34195	| 	31.9929	| 	54.5122	| 	83.05835	| 	124.2594	| 
| 	Secure Division		| 	SDIV	| 	93.91275	| 	281.39765	| 	613.20965	| 	1090.61045	| 	1870.91515	| 	2863.31305	| 	4056.85975	| 

The time unit is ms.


# Benchmark

In the Main.cpp source code file, you have the flexibility to modify the values of two important parameters: KEY_LEN_BIT and SIGMA_LEN_BIT.

(1) KEY_LEN_BIT governs the bit-length of the large prime used in the computation.

(2) SIGMA_LEN_BIT dictates the bit-length of the variable denoted as $sk_1$ in the program.

# Reference

1. Bowen Zhao, Jiaming Yuan, Ximeng Liu, Yongdong Wu, Hwee Hwa Pang, and Robert H. Deng. SOCI: A toolkit for secure outsourced computation on integers. IEEE Transactions on Information Forensics and Security, 2022, 17: 3637-3648.
