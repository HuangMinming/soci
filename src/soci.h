#pragma once

#include "gmp.h"
#include "paillier.h"

using namespace phe;
using namespace std;

namespace soci {

    class seccomp {

    public:
        mpz_t neg_one, neg_two;

        seccomp() {
            mpz_inits(this->neg_one, this->neg_two, NULL);
            mpz_set_si(this->neg_one, -1);
            mpz_set_si(this->neg_two, -2);
        }

        ~seccomp() {
            mpz_clears(this->neg_one, this->neg_two, NULL);
        }

        void smul(mpz_t res, mpz_t ex, mpz_t ey, PaillierThd cp, PaillierThd csp);
        void scmp(mpz_t res, mpz_t ex, mpz_t ey, PaillierThd cp, PaillierThd csp);
        void ssba(mpz_t s_x, mpz_t u_x, mpz_t c, PaillierThd cp, PaillierThd csp);
        void sdiv(mpz_t eq, mpz_t er, mpz_t ex, mpz_t ey, int ell, PaillierThd cp, PaillierThd csp, Paillier pai);
    };
    const int sigma = 128;

    void get_secRandNum(mpz_t r, int sigma) {
    
        mpz_rrandomb(r, gmp_rand, sigma);
    }

    void get_secRandNum(mpz_t r) {

        get_secRandNum(r, sigma);
    }

    /*Secure Multiplication Protocol*/
    void seccomp::smul(mpz_t res, mpz_t ex, mpz_t ey, PaillierThd cp, PaillierThd csp) {
        // step 1
        mpz_t r1, r2, er1, er2, X, Y, X1, Y1, r1r2, er1r2;
        mpz_inits(r1, r2, er1, er2, X, Y, X1, Y1, r1r2, er1r2, NULL);
        get_secRandNum(r1, sigma);
        get_secRandNum(r2, sigma);
        cp.pai.encrypt(er1, r1);
        cp.pai.encrypt(er2, r2);

        cp.pai.add(X, ex, er1);
        cp.pai.add(Y, ey, er2);
        cp.pdec(X1, X);
        cp.pdec(Y1, Y);

        // step 2
        mpz_t X2, Y2, x, y, xy, exy;
        mpz_inits(X2, Y2, x, y, xy, exy, NULL);
        csp.pdec(X2, X);
        csp.pdec(Y2, Y);
        csp.fdec(x, X1, X2);
        csp.fdec(y, Y1, Y2);

        mpz_mul(xy, x, y);
        mpz_mod(xy, xy, csp.pai.pubkey.n);
        csp.pai.encrypt(exy, xy);

        // step 3
        mpz_t exr2, eyr1;
        mpz_inits(exr2, eyr1, NULL);
        mpz_neg(r2, r2);    //-r2
        cp.pai.scl_mul(exr2, ex, r2);       //-x*r2
        mpz_mul(r1r2, r1, r2);              //-r1*r2
        cp.pai.encrypt(er1r2, r1r2);
        mpz_neg(r1, r1); //not in paper??   //-r1
        cp.pai.scl_mul(eyr1, ey, r1);       //-y*r1
        cp.pai.add(res, exy, exr2);
        cp.pai.add(res, res, eyr1);
        cp.pai.add(res, res, er1r2);

        mpz_clears(r1, r2, er1, er2, X, Y, X1, Y1, r1r2, er1r2, NULL);
        mpz_clears(X2, Y2, x, y, xy, exy, NULL);
        mpz_clears(exr2, eyr1, NULL);
    }

    /*Secure Comparison Protocol*/
    void seccomp::scmp(mpz_t res, mpz_t ex, mpz_t ey, PaillierThd cp, PaillierThd csp) {
        //Step-1
        mpz_t r1, r2, r0, er2, D, D1, exr, eyr;
        mpz_inits(r1, r2, r0, er2, D, D1, exr, eyr, NULL);
        get_secRandNum(r0, sigma);
        get_secRandNum(r1, sigma + sigma);
        //gmp_printf("r0 = %Zd\n", r0);
        //gmp_printf("r1 = %Zd\n", r1);
        mpz_sub(r2, cp.pai.pubkey.half_n, r0);
        //gmp_printf("cp.pai.pubkey.half_n = %Zd\n", cp.pai.pubkey.half_n);
        //gmp_printf("r2 = %Zd\n", r2);
        if (mpz_odd_p(r0) == 0) {       // D = [r_1*(x-y+1)+r2]
            mpz_add(r2, r1, r2);        // r2 = r1 + r2
            cp.pai.encrypt(er2, r2);    // er2 = [r1+r2]
            cp.pai.scl_mul(exr, ex, r1); // ex = [r1 * x]
            mpz_neg(r1, r1);
            cp.pai.scl_mul(eyr, ey, r1); // ey = [-r1 * y] 
            cp.pai.add(D, exr, eyr);
            cp.pai.add(D, D, er2);
        }
        else {                          // D = [r_1*(y-x)+r2]
            cp.pai.scl_mul(eyr, ey, r1);
            mpz_neg(r1, r1);
            cp.pai.scl_mul(exr, ex, r1); 
            cp.pai.encrypt(er2, r2);
            cp.pai.add(D, eyr, exr);
            cp.pai.add(D, D, er2);
        }
        cp.pdec(D1, D);

        //Step-2
        mpz_t d, D2;
        mpz_inits(d, D2, NULL);
        csp.pdec(D2, D);
        csp.fdec(d, D1, D2);

        mpz_cmp(d, csp.pai.pubkey.half_n) > 0 ? mpz_set(res, csp.ezero) : mpz_set(res, csp.eone);

        //Step-3
        if (mpz_odd_p(r0) == 0) {
            mpz_set(res, res);
        }
        else {
            cp.pai.scl_mul(res, res, neg_one);
            cp.pai.add(res, cp.eone, res);
        }

        mpz_clears(r1, r2, r0, er2, D, D1, exr, eyr, NULL);
        mpz_clears(d, D2, NULL);
    }

    /*Secure Sign Bit-Acquisition Protocol*/
    void seccomp::ssba(mpz_t s_x, mpz_t u_x, mpz_t c, PaillierThd cp, PaillierThd csp) {
        // Step-1
        scmp(s_x, c, cp.ezero, cp, csp);

        // Step-2
        mpz_t sign;
        mpz_init(sign);
        cp.pai.scl_mul(sign, s_x, neg_two);   // [-2s_x]
        cp.pai.add(sign, cp.eone, sign);    // [1-2s_x]

        // Step-3
        smul(u_x, sign, c, cp, csp);

        mpz_clears(sign, NULL);
    }

    /*Secure Division Protocol*/
    void seccomp::sdiv(mpz_t eq, mpz_t er, mpz_t ex, mpz_t ey, int ell, PaillierThd cp, PaillierThd csp, Paillier pai) {
        mpz_set(eq, cp.ezero);  
        
        mpz_t c, u, e, ue, m, two;
        mpz_inits(c, u, e, ue, m, two, NULL);
        mpz_set_ui(two, 2);
        mpz_set(er, ex);
        for (int i = ell; i >= 0; i--) {
            mpz_pow_ui(e, two, i);      // e=2^i
            cp.pai.scl_mul(c, ey, e);   // [y]^{2^i}

            scmp(u, er, c, cp, csp);
            
            cp.pai.scl_mul(u, u, neg_one);
            cp.pai.add(u, cp.eone, u);//u=u'
            cp.pai.scl_mul(ue, u, e);
            cp.pai.add(eq, eq, ue);

            smul(m, u, c, cp, csp);

            cp.pai.scl_mul(m, m, neg_one);
            cp.pai.add(er, er, m);
        }

        mpz_clears(c, u, e, ue, m, two, NULL);
    }
}
