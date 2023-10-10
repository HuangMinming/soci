#pragma once
#include <stdio.h>
#include "gmp.h"


extern gmp_randstate_t gmp_rand;
gmp_randstate_t gmp_rand;

namespace phe {

	const int sigma = 128;

	class PaillierKey {

	public:
		mpz_t g, n, nsquare, half_n;

		PaillierKey() {
			mpz_inits(this->g, this->n, this->nsquare, this->half_n, NULL);
		}

		PaillierKey(mpz_t p, mpz_t q) {
			mpz_t two;
			mpz_inits(this->g, this->n, this->nsquare, this->half_n, two, NULL);

			mpz_mul(this->n, p, q);		// n = p * q
			mpz_add_ui(this->g, this->n, 1);	// g = n + 1
			mpz_mul(this->nsquare, this->n, this->n); // nsqaure = n * n
			mpz_set_ui(two, 2);
			mpz_fdiv_q(this->half_n, this->n, two);	  // half_n = n / 2	
			mpz_clear(two);
		}

		PaillierKey(mpz_t n) {
			mpz_t two;
			mpz_inits(this->g, this->n, this->nsquare, this->half_n, two, NULL);

			mpz_set(this->n, n);
			mpz_add_ui(this->g, this->n, 1);	// g = n + 1;
			mpz_mul(this->nsquare, this->n, this->n); // nsqaure = n * n;
			mpz_set_ui(two, 2);
			mpz_fdiv_q(this->half_n, this->n, two);	  // half_n = n / 2	
			mpz_clear(two);
		}

		PaillierKey(mpz_t g, mpz_t n, mpz_t nsqaure) {
			mpz_t two;
			mpz_inits(this->g, this->n, this->nsquare, this->half_n, two, NULL);

			mpz_set(this->g, g);
			mpz_set(this->n, n);
			mpz_set(this->nsquare, nsqaure);
			mpz_set_ui(two, 2);
			mpz_fdiv_q(this->half_n, this->n, two);	  // half_n = n / 2	
			mpz_clear(two);
		}

		PaillierKey(const PaillierKey &p) {
			mpz_inits(this->g, this->n, this->nsquare, this->half_n, NULL);

			mpz_set(this->n, p.n);
			mpz_set(this->g, p.g);
			mpz_set(this->nsquare, p.nsquare);
			mpz_set(this->half_n, p.half_n);
		}

		PaillierKey& operator=(const PaillierKey& p) {
			mpz_clears(this->g, this->n, this->nsquare, this->half_n, NULL);
			mpz_inits(this->g, this->n, this->nsquare, this->half_n, NULL);

			mpz_set(this->n, p.n);
			mpz_set(this->g, p.g);
			mpz_set(this->nsquare, p.nsquare);
			mpz_set(this->half_n, p.half_n);
			return *this;
		}
		
		~PaillierKey() {
			mpz_clears(this->g,this->n,this->nsquare,this->half_n, NULL);
		}
	};

	class PaillierPrivateKey : public PaillierKey {

	public:
		mpz_t lambda, lmdInv;

		PaillierPrivateKey() : PaillierKey() {
			mpz_inits(this->lambda, this->lmdInv, NULL);
		}

		PaillierPrivateKey(mpz_t p, mpz_t q, mpz_t lambda) : PaillierKey(p, q) {
			mpz_inits(this->lambda, this->lmdInv, NULL);

			mpz_set(this->lambda, lambda);
			mpz_invert(this->lmdInv, this->lambda, this->n);
		}

		PaillierPrivateKey(mpz_t n, mpz_t lambda) : PaillierKey(n) {
			mpz_inits(this->lambda, this->lmdInv, NULL);

			mpz_set(this->lambda, lambda);
			mpz_invert(this->lmdInv, this->lambda, this->n);
		}

		PaillierPrivateKey(const PaillierPrivateKey &p) : PaillierKey(p){
			mpz_inits(this->lambda, this->lmdInv, NULL);

			mpz_set(this->lambda, p.lambda);
			mpz_set(this->lmdInv, p.lmdInv);
		}

		PaillierPrivateKey& operator=(const PaillierPrivateKey& p){
			mpz_clears(this->lambda, this->lmdInv, NULL);
			mpz_inits(this->lambda, this->lmdInv, NULL);

			PaillierKey::operator=(p);
			mpz_set(this->lambda, p.lambda);
			mpz_set(this->lmdInv, p.lmdInv);
			return *this;
		}

		/*
		Free the space occupied by lambda, lmdInv
		*/
		~PaillierPrivateKey() {
			mpz_clears(this->lambda, this->lmdInv, NULL);
		}
	};

	class PaillierThdPrivateKey {

	public:
		mpz_t sk, n, nsqaure;

		PaillierThdPrivateKey() {
			mpz_inits(this->sk, this->n, this->nsqaure, NULL);
		}

		PaillierThdPrivateKey(mpz_t sk, mpz_t n, mpz_t nsqaure) {
			mpz_inits(this->sk, this->n, this->nsqaure, NULL);

			mpz_set(this->sk, sk);
			mpz_set(this->n, n);
			mpz_set(this->nsqaure, nsqaure);
		}

		PaillierThdPrivateKey(const PaillierThdPrivateKey &p) {
			mpz_inits(this->sk, this->n, this->nsqaure, NULL);

			mpz_set(this->sk, p.sk);
			mpz_set(this->n, p.n);
			mpz_set(this->nsqaure, p.nsqaure);
		}

		PaillierThdPrivateKey& operator=(const PaillierThdPrivateKey& p) {
			mpz_clears(this->sk, this->n, this->nsqaure, NULL);
			mpz_inits(this->sk, this->n, this->nsqaure, NULL);

			mpz_set(this->sk, p.sk);
			mpz_set(this->n, p.n);
			mpz_set(this->nsqaure, p.nsqaure);
			return *this;
		}

		~PaillierThdPrivateKey() {
			mpz_clears(this->sk, this->n, this->nsqaure,NULL);
		}

	};

	class Paillier {

	public:
		PaillierKey pubkey;
		PaillierPrivateKey prikey;

		Paillier() {
		}

		Paillier(PaillierKey pubkey) {
			this->pubkey = pubkey;
		}

		Paillier(PaillierPrivateKey prikey) {
			this->pubkey = PaillierKey(prikey.g, prikey.n, prikey.nsquare);
			this->prikey = prikey;
			
		}

		Paillier(const PaillierKey &pubkey, const PaillierPrivateKey & prikey) {
			this->pubkey = pubkey;
			this->prikey = prikey;
		}

		Paillier(const Paillier &p) {
			this->pubkey = p.pubkey;
			this->prikey = p.prikey;
		}

		Paillier& operator=(const Paillier& p) {
			this->pubkey = p.pubkey;
			this->prikey = p.prikey;
			return *this;
		}
		

		~Paillier() {
		}

		void keygen(mpz_t p, mpz_t q);
		void keygen(unsigned long bitLen);
		void encrypt(mpz_t c, mpz_t m);
		void encrypt(mpz_t c, mpz_t m, mpz_t r);
		void decrypt(mpz_t m, mpz_t c);
		void add(mpz_t res, mpz_t c1, mpz_t c2);
		void scl_mul(mpz_t resc, mpz_t c, mpz_t e);
		void scl_mul(mpz_t res, mpz_t c, int e);

		};

	class PaillierThd {

	public:
		PaillierThdPrivateKey psk;
		Paillier pai;
		mpz_t eone, ezero;

		PaillierThd() {
			mpz_inits(ezero, eone, NULL);
		};
		
		PaillierThd(PaillierThdPrivateKey psk) : psk(psk) {
			mpz_inits(ezero, eone, NULL);
		};
		PaillierThd(PaillierThdPrivateKey psk, PaillierKey pubkey) : psk(psk), pai(pubkey) {
			mpz_t zero, one;
			mpz_inits(ezero, eone, zero, one, NULL);

			mpz_set_ui(zero, 0);
			mpz_set_ui(one, 1);
			this->pai.encrypt(this->ezero, zero);
			this->pai.encrypt(this->eone, one);
			mpz_clears(zero, one, NULL);
		};

		PaillierThd(const PaillierThd& p) {
			mpz_inits(ezero, eone, NULL);

			mpz_set(ezero, p.ezero);
			mpz_set(eone, p.eone);
			psk = p.psk;
			pai = p.pai;
		};

		PaillierThd & operator=(const PaillierThd& p) {
			mpz_inits(ezero, eone, NULL);

			mpz_set(ezero, p.ezero);
			mpz_set(eone, p.eone);
			psk = p.psk;
			pai = p.pai;
			return *this;
		};

		~PaillierThd() {
			mpz_clears(ezero, eone, NULL);
		};
		void pdec(mpz_t pc, mpz_t c);
		void fdec(mpz_t m, mpz_t c1, mpz_t c2);
	};

	void setrandom() {

		gmp_randinit_default(gmp_rand);
	}

	void Paillier::keygen(unsigned long bitLen) {

		mpz_t r, p, q, pp, qq, quotient,remainder;
		mpz_inits(r, p, q, pp, qq, quotient,remainder, NULL);

		mpz_rrandomb(r, gmp_rand, bitLen);
		/*generate p = 2p'+1*/
		while(1) {
			mpz_nextprime(p, r);
			mpz_sub_ui(pp, p, 1);
			mpz_fdiv_qr_ui(quotient, remainder, pp, 2);
			if(mpz_cmp_ui(remainder, 0) != 0) /*remainder is not 0, p must be even number*/
			{
				continue;
			}	
			
			if(mpz_probab_prime_p(quotient, 20) !=0) /*quotient is prime, break*/
			{
				break;
			}
			mpz_set(r, p);
			//gmp_printf("p = %Zd, quotient = %Zd, remainder = %Zd\n", p, quotient, remainder);

		}
		mpz_set(r, p);
		/*generate q = 2q'+1, and q > p*/
		while(1) {
			mpz_nextprime(q, r);
			mpz_sub_ui(qq, q, 1);
			mpz_fdiv_qr_ui(quotient, remainder, qq, 2);
			if(mpz_cmp_ui(remainder, 0) != 0) /*remainder is not 0, p must be even number*/
			{
				continue;
			}	
			
			if(mpz_probab_prime_p(quotient, 20) !=0) /*quotient is prime, break*/
			{
				break;
			}
			mpz_set(r, q);
			//gmp_printf("q = %Zd, quotient = %Zd, remainder = %Zd\n", q, quotient, remainder);


		}
		keygen(p, q);

		mpz_clears(r, p, q, pp, qq, quotient,remainder, NULL);
	}
	/*
	void Paillier::keygen(unsigned long bitLen) {

		mpz_t p, q;
		mpz_inits(p, q, NULL);

		mpz_rrandomb(p, gmp_rand, bitLen);
		mpz_nextprime(p, p);
		mpz_nextprime(q, p);
		keygen(p, q);

		mpz_clears(p, q, NULL);
	}*/

	void Paillier::keygen(mpz_t p, mpz_t q) {

		mpz_t n, lambda;
		mpz_inits(n, lambda, NULL);

		mpz_mul(n, p, q);
		pubkey = PaillierKey(n);
		mpz_sub_ui(p, p, 1);
		mpz_sub_ui(q, q, 1);
		mpz_mul(lambda, p, q);

		prikey = PaillierPrivateKey(n, lambda);

		mpz_clears(n, lambda, NULL);
	}



	/*
	void Paillier::encrypt(mpz_t c, mpz_t m) {

		if (mpz_cmp(m, pubkey.n) >= 0) {

			throw("m must be less than n");
			return;
		}

		mpz_t m1;
		mpz_init(m1);
		mpz_set(m1, m);
		
		if (mpz_cmp_si(m1, 0) < 0) {
			//if m is negative, its absolute value must be less than n/2
			// get the absolute value of m
			mpz_abs(m1, m1);
			if (mpz_cmp(m1, pubkey.half_n) > 0) {
				throw("abs(m) must be less than n/2 or equal to n/2");
				return;
			}
			
			//then , transfer to negative number in soci
			mpz_sub(m1, this->prikey.n, m1);
		}

		mpz_t r;
		mpz_init(r);
		mpz_urandomm(r, gmp_rand, pubkey.n);
		encrypt(c, m1, r);
		mpz_clears(r, m1, NULL);
	}*/

	void Paillier::encrypt(mpz_t c, mpz_t m) {

		if (mpz_cmp(m, pubkey.n) >= 0) {

			throw("m must be less than n");
			return;
		}

		mpz_t r;
		mpz_init(r);
		mpz_urandomm(r, gmp_rand, pubkey.n);
		encrypt(c, m, r);
		mpz_clears(r, NULL);
	}
	/*
	void Paillier::encrypt(mpz_t c, mpz_t m, mpz_t r) {

		if (mpz_cmp(m, pubkey.n) >= 0) {
			throw("m must be less than n");
			return;
		}
		mpz_t m1;
		mpz_init(m1);
		mpz_set(m1, m);
		
		if (mpz_cmp_si(m, 0) < 0) {
			//if m is negative, its absolute value must be less than n/2
			// get the absolute value of m
			mpz_abs(m1, m1);
			if (mpz_cmp(m1, pubkey.half_n) > 0) {
				throw("abs(m) must be less than n/2 or equal to n/2");
				return;
			}

			//then , transfer to negative number in soci
			mpz_sub(m1, this->prikey.n, m1);
		}

		// g^m * r^n mod n^2
		//mpz_mul(c, m, puk.e1);			 // m�n
		//mpz_add_ui(c, c, 1);			 // 1 + m�n
		//mpz_powm(r, r, puk.e1, puk.e3);  // r^n mod n^2
		//mpz_mul(c, c, r);                // (1+m�N)�r^n
		//mpz_mod(c, c, puk.e3);			 // (1+m�N)�r^n mod n^2
		
		mpz_powm(c, pubkey.g, m1, pubkey.nsquare);
		mpz_powm(r, r, pubkey.n, pubkey.nsquare);
		mpz_mul(c, c, r);
		mpz_mod(c, c, pubkey.nsquare);
	}*/

	void Paillier::encrypt(mpz_t c, mpz_t m, mpz_t r) {

		if (mpz_cmp(m, pubkey.n) >= 0) {
			throw("m must be less than n");
			return;
		}

		// g^m * r^n mod n^2
		/*mpz_mul(c, m, puk.e1);			 // m·n
		mpz_add_ui(c, c, 1);			 // 1 + m·n
		mpz_powm(r, r, puk.e1, puk.e3);  // r^n mod n^2
		mpz_mul(c, c, r);                // (1+m·N)·r^n
		mpz_mod(c, c, puk.e3);			 // (1+m·N)·r^n mod n^2
		*/
		mpz_powm(c, pubkey.g, m, pubkey.nsquare);
		mpz_powm(r, r, pubkey.n, pubkey.nsquare);
		mpz_mul(c, c, r);
		mpz_mod(c, c, pubkey.nsquare);
	}
	/*
	void Paillier::decrypt(mpz_t m, mpz_t c) {
		if (mpz_cmp(c, prikey.nsquare) >= 0) {
			throw("ciphertext must be less than n^2");
			return;
		}

		// c=c^lambda mod n^2
		mpz_powm(m, c, prikey.lambda, prikey.nsquare);

		// (c - 1) / n * lambda^(-1) mod n
		mpz_sub_ui(m, m, 1);			// c=c-1
		mpz_fdiv_q(m, m, prikey.n);		// c=(c-1)/n
		mpz_mul(m, m, prikey.lmdInv);	// c=c*lambda^(-1)
		mpz_mod(m, m, prikey.n);		// m=c mod n
		
		//if m > n/2, then it is a negative number in soci
		if (mpz_cmp(m, prikey.half_n) > 0) {
			mpz_sub(m, m, prikey.n);
		}
	}
	*/
	void Paillier::decrypt(mpz_t m, mpz_t c) {
		if (mpz_cmp(c, prikey.nsquare) >= 0) {
			throw("ciphertext must be less than n^2");
			return;
		}

		// c=c^lambda mod n^2
		
		mpz_powm(m, c, prikey.lambda, prikey.nsquare);

		// (c - 1) / n * lambda^(-1) mod n
		mpz_sub_ui(m, m, 1);			// c=c-1
		mpz_fdiv_q(m, m, prikey.n);		// c=(c-1)/n
		mpz_mul(m, m, prikey.lmdInv);	// c=c*lambda^(-1)
		mpz_mod(m, m, prikey.n);		// m=c mod n
	}

	void Paillier::add(mpz_t res, mpz_t c1, mpz_t c2) {

		if (mpz_cmp(c1, pubkey.nsquare) >= 0) {
			throw("ciphertext must be less than n^2");
			return;
		}
		if (mpz_cmp(c2, pubkey.nsquare) >= 0) {
			throw("ciphertext must be less than n^2");
			return;
		}
		mpz_mul(res, c1, c2);
		mpz_mod(res, res, pubkey.nsquare);
	}

	void Paillier::scl_mul(mpz_t res, mpz_t c, mpz_t e) {

		if (mpz_cmp(c, pubkey.nsquare) >= 0) {
			throw("ciphertext must be less than n^2");
			return;
		}
		if (mpz_cmp(e, pubkey.n) >= 0) {
			throw("exponent must be less than n");
		}
		mpz_powm(res, c, e, pubkey.nsquare);
	}

	void Paillier::scl_mul(mpz_t res, mpz_t c, int e) {

		mpz_t mp_e;
		mpz_init(mp_e);
		mpz_set_si(mp_e, e);
		scl_mul(res, c, mp_e);
		mpz_clears(mp_e, NULL);
	}

	void PaillierThd::pdec(mpz_t pc, mpz_t c) {
		// c^sk % n^2
		mpz_powm(pc, c, psk.sk, psk.nsqaure);
	}

	void PaillierThd::fdec(mpz_t m, mpz_t c1, mpz_t c2) {

		// (c1 * c2 % n^2 - 1)/n
		mpz_mul(m, c1, c2);
		mpz_mod(m, m, psk.nsqaure);
		mpz_sub_ui(m, m, 1);
		mpz_fdiv_q(m, m, psk.n);
	}

	class ThirdKeyGen {
	public:
		void thdkeygen(Paillier &pai, int sigma,
			PaillierThd* cp, PaillierThd* csp);
	};

	void ThirdKeyGen::thdkeygen(Paillier &pai, int sigma,
		PaillierThd* cp, PaillierThd* csp) {

		mpz_t sk1, sk2;
		mpz_inits(sk1, sk2, NULL);

		mpz_rrandomb(sk1, gmp_rand, sigma);	// sk1 is a ranodm number with sigma bits
		mpz_mul(sk2, pai.prikey.lambda, pai.prikey.lmdInv);
		mpz_sub(sk2, sk2, sk1);				// sk2 = lambda · mu - sk1
		PaillierThdPrivateKey* tmpPSK = NULL;
		tmpPSK = new PaillierThdPrivateKey(sk1, pai.prikey.n, pai.prikey.nsquare);
		*cp = PaillierThd(*tmpPSK, pai.pubkey);
		delete tmpPSK;

		tmpPSK = new PaillierThdPrivateKey(sk2, pai.prikey.n, pai.prikey.nsquare);
		*csp = PaillierThd(*tmpPSK, pai.pubkey);
		delete tmpPSK;

		mpz_clears(sk1, sk2, NULL);

	}
}