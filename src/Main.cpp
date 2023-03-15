#include <iostream>
#include <gmp.h>
#include <ctime>

#include "paillier.h"
#include "soci.h"

using namespace std;
using namespace phe;
using namespace soci;

#define KEY_LEN_BIT 512
#define SIGMA_LEN_BIT 128

int main() {
	/*
	* start initialize.
	*/
	/*
	Initialize gmp randstate with a default algorithm, 
	in order to generate a random integer later.
	*/
	setrandom();
	Paillier pai;
	/*
	generate a PaillierTD public/private key pair pai(pk; sk)
	*/
	pai.keygen(KEY_LEN_BIT);

	/*
	* splits sk into two partially private keys (sk1; sk2), 
	while sk is the private key of pai. 
	Distributes (pk; sk1) and (pk; sk2) to CP and CSP, respectively
	*/
	int sigma = SIGMA_LEN_BIT;
	PaillierThd cp;
	PaillierThd csp;
	ThirdKeyGen tkg;
	tkg.thdkeygen(pai, sigma, &cp, &csp);

	clock_t start_time;
	clock_t end_time;

	/*
	* After initialization, we get pai, cp, csp.
	* Then we can use these parameters to complete kinds of algorithm
	*/

	mpz_t x, y, z, cx, cy, cz, px, py;
	mpz_inits(x, y, z, cx, cy, cz, px, py, NULL);

	//set x, y
	mpz_set_si(x, 99);
	mpz_set_si(y, 789);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx, y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	
	start_time = clock();
	//run add function, cz is the result which is a ciphertext
	pai.add(cz, cx, cy);
	end_time = clock();
	//decrypt cz to z
	pai.decrypt(z, cz);
	printf("run add function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("x + y = %Zd\n", z);
	cout << "---------------------------" << endl;

	mpz_t c1, c2;
	mpz_inits(c1, c2, NULL);
	//set x,y
	mpz_set_si(x, 99);
	mpz_set_si(y, 789);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx,y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	start_time = clock();

	//run scl_mul function, cz is the result which is a ciphertext
	pai.scl_mul(cz, cx, y);
	end_time = clock();
	//decrypt cz to z
	pai.decrypt(z, cz);
	printf("compute scl_mul function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("x*y = %Zd\n", z);
	cout << "---------------------------" << endl;

	printf("Secure computation protocols\n");
	seccomp sc;
	//set x, y
	mpz_set_si(x, 99);
	mpz_set_si(y, 789);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx,y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	start_time = clock();
	//run smul function, cz is the result which is a ciphertext
	sc.smul(cz, cx, cy, cp, csp);
	end_time = clock();
	//decrypt cz to z
	pai.decrypt(z, cz);
	printf("compute SMUL function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("x*y = %Zd\n", z);
	cout << "---------------------------" << endl;

	//set x, y
	mpz_set_si(x, 99);
	mpz_set_si(y, 789);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx,y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	start_time = clock();
	//run scmp function, cz is the result which is a ciphertext
	sc.scmp(cz, cx, cy, cp, csp);
	end_time = clock();
	//decrypt cz to z
	pai.decrypt(z, cz);
	printf("compute SCMP function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("x>=y? = %Zd\n", z);
	cout << "---------------------------" << endl;

	mpz_t s_x, u_x;
	mpz_inits(s_x, u_x, NULL);
	//set x
	mpz_set_si(x, 99);
	gmp_printf("set x = %Zd\n", x);
	//encrypt x to cx
	pai.encrypt(cx, x);
	start_time = clock();
	//run add function, s_x, u_x are the results which are ciphertexts
	//s_x is the sign bit of x
	//u_x is the magnitude of x
	sc.ssba(s_x, u_x, cx, cp, csp);
	end_time = clock();
	//decrypt s_x to x, u_x to y
	pai.decrypt(x, s_x);
	pai.decrypt(y, u_x);
	printf("compute SSBA function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("s_x = %Zd u_x = %Zd\n", x, y);
	cout << "---------------------------" << endl;

	//set x, y
	mpz_set_si(x, 5429496723);
	mpz_set_si(y, 9949672);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx,y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	mpz_t eq, er;
	mpz_inits(eq, er, NULL);
	start_time = clock();
	//run add function, eq and er are the results which are ciphertexts
	//eq is the quotient of x divided by y
	//er is the remainder of x divided by y
	sc.sdiv(eq, er, cx, cy, 32, cp, csp, pai);
	end_time = clock();
	//decrypt eq to x, er to y
	pai.decrypt(x, eq);
	pai.decrypt(y, er);
	printf("compute SDIV function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("q = %Zd r = %Zd\n", x, y);
	cout << "---------------------------" << endl;

	mpz_clears(x, y, z, cx, cy, cz, px, py, NULL);
	mpz_clears(c1, c2, NULL);
	mpz_clears(s_x, u_x, NULL);
	mpz_clears(eq, er, NULL);

	/*
	//set x, y
	mpz_set_si(x, -99);
	mpz_set_si(y, -789);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx, y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	
	start_time = clock();
	//run add function, cz is the result which is a ciphertext
	pai.add(cz, cx, cy);
	end_time = clock();
	//decrypt cz to z
	pai.decrypt(z, cz);
	printf("run add function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("x + y = %Zd\n", z);
	cout << "---------------------------" << endl;

	mpz_t c1, c2;
	mpz_inits(c1, c2, NULL);
	//set x,y
	mpz_set_si(x, -99);
	mpz_set_si(y, -789);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx,y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	start_time = clock();

	//run scl_mul function, cz is the result which is a ciphertext
	pai.scl_mul(cz, cx, y);
	end_time = clock();
	//decrypt cz to z
	pai.decrypt(z, cz);
	printf("compute scl_mul function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("x*y = %Zd\n", z);
	cout << "---------------------------" << endl;

	printf("Secure computation protocols\n");
	seccomp sc;
	//set x, y
	mpz_set_si(x, -99);
	mpz_set_si(y, -789);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx,y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	start_time = clock();
	//run smul function, cz is the result which is a ciphertext
	sc.smul(cz, cx, cy, cp, csp);
	end_time = clock();
	//decrypt cz to z
	pai.decrypt(z, cz);
	printf("compute SMUL function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("x*y = %Zd\n", z);
	cout << "---------------------------" << endl;

	//set x, y
	mpz_set_si(x, -99);
	mpz_set_si(y, -789);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx,y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	start_time = clock();
	//run scmp function, cz is the result which is a ciphertext
	sc.scmp(cz, cx, cy, cp, csp);
	end_time = clock();
	//decrypt cz to z
	pai.decrypt(z, cz);
	printf("compute SCMP function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("x>=y? = %Zd\n", z);
	cout << "---------------------------" << endl;

	mpz_t s_x, u_x;
	mpz_inits(s_x, u_x, NULL);
	//set x
	mpz_set_si(x, -99);
	gmp_printf("set x = %Zd\n", x);
	//encrypt x to cx
	pai.encrypt(cx, x);
	start_time = clock();
	//run add function, s_x, u_x are the results which are ciphertexts
	//s_x is the sign bit of x
	//u_x is the magnitude of x
	sc.ssba(s_x, u_x, cx, cp, csp);
	end_time = clock();
	//decrypt s_x to x, u_x to y
	pai.decrypt(x, s_x);
	pai.decrypt(y, u_x);
	printf("compute SSBA function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("s_x = %Zd u_x = %Zd\n", x, y);
	cout << "---------------------------" << endl;

	//set x, y
	mpz_set_si(x, 5429496723);
	mpz_set_si(y, 9949672);
	gmp_printf("set x = %Zd, y = %Zd\n", x, y);
	//encrypt x to cx,y to cy
	pai.encrypt(cx, x);
	pai.encrypt(cy, y);
	mpz_t eq, er;
	mpz_inits(eq, er, NULL);
	start_time = clock();
	//run add function, eq and er are the results which are ciphertexts
	//eq is the quotient of x divided by y
	//er is the remainder of x divided by y
	sc.sdiv(eq, er, cx, cy, 32, cp, csp, pai);
	end_time = clock();
	//decrypt eq to x, er to y
	pai.decrypt(x, eq);
	pai.decrypt(y, er);
	printf("compute SDIV function, its running time is  ------  %f ms\n", ((double)(end_time - start_time)) / 1 * 1000 / CLOCKS_PER_SEC);
	gmp_printf("q = %Zd r = %Zd\n", x, y);
	cout << "---------------------------" << endl;

	mpz_clears(x, y, z, cx, cy, cz, px, py, NULL);
	mpz_clears(c1, c2, NULL);
	mpz_clears(s_x, u_x, NULL);
	mpz_clears(eq, er, NULL);*/

	return 0;
}
