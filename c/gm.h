//
// Created by saint on 2021/11/14.
//

#ifndef YISECUREBOX_GM_H
#define YISECUREBOX_GM_H

#include <stdint.h>
#include <string.h>

# ifdef  __cplusplus
extern "C" {
# endif

typedef uint64_t gm_bn_t[8];

typedef struct {
    gm_bn_t X;
    gm_bn_t Y;
    gm_bn_t Z;
} gm_point_t;

extern const gm_bn_t GM_BN_P;
extern const gm_bn_t GM_BN_N;
extern const gm_point_t * GM_MONT_G;

#define gm_bn_copy(r, a) memcpy((r), (a), sizeof(gm_bn_t))

void gm_bn_to_bytes(const gm_bn_t a, uint8_t out[32]);
void gm_bn_from_bytes(gm_bn_t r, const uint8_t in[32]);
void gm_bn_to_hex(const gm_bn_t a, char hex[64]);
int gm_bn_from_hex(gm_bn_t r, const char hex[64]);
void gm_bn_to_bits(const gm_bn_t a, char bits[256]);

int gm_bn_cmp(const gm_bn_t a, const gm_bn_t b);

void gm_bn_add(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m);
void gm_bn_sub(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m);

void gm_bn_to_mont(gm_bn_t r, const gm_bn_t a, const gm_bn_t m);
void gm_bn_from_mont(gm_bn_t r, const gm_bn_t a, const gm_bn_t m);
void gm_bn_mont_mul(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m);

void gm_bn_sqr(gm_bn_t r, const gm_bn_t a, const gm_bn_t m);
void gm_bn_exp(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m);
void gm_bn_inv(gm_bn_t r, const gm_bn_t a, const gm_bn_t m);

void gm_bn_set_zero(gm_bn_t r);
void gm_bn_set_mont_one(gm_bn_t r);
int gm_bn_is_mont_one(const gm_bn_t r);
int gm_bn_is_zero(const gm_bn_t r);

#define gm_point_set_infinity(r) gm_point_init(r)
#define gm_point_copy(r, p) memcpy((r), (p), sizeof(gm_point_t))
void gm_point_init(gm_point_t *r);
void gm_point_set_xy(gm_point_t *r, const gm_bn_t x, const gm_bn_t y);
void gm_point_get_xy(const gm_point_t *p, gm_bn_t x, gm_bn_t y);
int gm_is_at_infinity(const gm_point_t *p);

void gm_point_from_hex(gm_point_t *p, const char hex[128]);
void gm_point_to_hex(gm_point_t *r, char hex[128]);
void gm_point_from_bytes(gm_point_t *r, const uint8_t in[64]);
void gm_point_to_bytes(const gm_point_t *p, uint8_t out[64]);

void gm_point_double(gm_point_t * r, const gm_point_t * p);
void gm_point_add(gm_point_t * r, const gm_point_t * a, const gm_point_t * b);
void gm_point_mul(gm_point_t * r, const gm_bn_t k, const gm_point_t * p);

int gm_do_sign(const gm_bn_t key, const gm_bn_t dgst, unsigned char *sig);
int gm_do_sign_for_test(const gm_bn_t key, const gm_bn_t dgst, unsigned char *sig, const gm_bn_t testK);
int gm_do_verify(const gm_point_t *key, const gm_bn_t dgst, const unsigned char *sig);

# ifdef  __cplusplus
}
# endif

#endif //YISECUREBOX_GM_H