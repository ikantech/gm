# include "gm.h"
#include "randombytes.h"
#include <assert.h>
#include <stdio.h>

#ifdef GM_RAND_SM3
#include "sm3.h"
#endif

// 字节转化为字
#define GM_GETU32(p) \
    ((uint32_t)(p)[0] << 24 | \
	 (uint32_t)(p)[1] << 16 | \
	 (uint32_t)(p)[2] <<  8 | \
	 (uint32_t)(p)[3])

// 字转化为字节
#define GM_PUTU32(p,V) \
	((p)[0] = (uint8_t)((V) >> 24), \
	 (p)[1] = (uint8_t)((V) >> 16), \
	 (p)[2] = (uint8_t)((V) >>  8), \
	 (p)[3] = (uint8_t)(V))

// SM2 P
const gm_bn_t GM_BN_P = {
        0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0xFFFFFFFF,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE
};

// SM2 N
const gm_bn_t GM_BN_N = {
        0x39D54123, 0x53BBF409, 0x21C6052B, 0x7203DF6B,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE
};

// 蒙哥马利域转化用参数，(r ^ 2)(mod p)
static const gm_bn_t GM_BN_MONT_PRR = {
        0x00000003, 0x00000002, 0xFFFFFFFF, 0x00000002,
        0x00000001, 0x00000001, 0x00000002, 0x00000004
};

// 蒙哥马利域转化用参数，(r ^ 2)(mod n)
static const gm_bn_t GM_BN_MONT_NRR = {
        0x7C114F20, 0x901192AF, 0xDE6FA2FA, 0x3464504A,
        0x3AFFE0D4, 0x620FC84C, 0xA22B3D3B, 0x1EB5E412
};

// 大数0
static const gm_bn_t GM_BN_ZERO = {
        0x0, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
};

// 大数1
static const gm_bn_t GM_BN_ONE = {
        0x1, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
};

// 大数2
static const gm_bn_t GM_BN_TWO = {
        0x2, 0x0, 0x0, 0x0,
        0x0, 0x0, 0x0, 0x0
};

// 蒙哥马利域 1 (mod p)
static const gm_bn_t GM_BN_MONT_PONE = {
        0x00000001, 0x00000000, 0xFFFFFFFF, 0x00000000,
        0x00000000, 0x00000000, 0x00000000, 0x00000001
};

// 蒙哥马利域 1 (mod n)
static const gm_bn_t GM_BN_MONT_NONE = {
        0xC62ABEDD, 0xAC440BF6, 0xDE39FAD4, 0x8DFC2094,
        0x00000000, 0x00000000, 0x00000000, 0x00000001
};

// 蒙哥马利域, SM2 G
static const gm_point_t _GM_MONT_G = {
        {
                0xF418029E, 0x61328990, 0xDCA6C050, 0x3E7981ED, 0xAC24C3C3, 0xD6A1ED99, 0xE1C13B05, 0x91167A5E
        },
        {
                0x3C2D0DDD, 0xC1354E59, 0x8D3295FA, 0xC1F5E578, 0x6E2A48F8, 0x8D4CFB06, 0x81D735BD, 0x63CD65D4
        },
        {
                0x00000001, 0x00000000, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000001
        }
};
const gm_point_t * GM_MONT_G = &_GM_MONT_G;

// 蒙哥马利域, SM2 A
const gm_bn_t GM_BN_MONT_A = {
    0xFFFFFFFC, 0xFFFFFFFF, 0x00000003, 0xFFFFFFFC,
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFB
};

// 蒙哥马利域, SM2 B
const gm_bn_t GM_BN_MONT_B = {
    0x2BC0DD42, 0x90D23063, 0xE9B537AB, 0x71CF379A, 
    0x5EA51C3C, 0x52798150, 0xBA20E2C8, 0x240FE188
};

#ifdef GM_ASM

void gm_i_bn_add_x(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, int count);
void gm_i_bn_sub(gm_bn_t r, const gm_bn_t a, const gm_bn_t b);
void gm_i_bn_mul(uint64_t * r, const uint64_t * k, const gm_bn_t b);

#else

/**
 * 大数加法，r = (a + b)
 * @param r 存储结果
 * @param a 大数a
 * @param b 大数b
 * @param count 大数的长度
 */
static void gm_i_bn_add_x(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, int count) {
    int i;
    r[0] = a[0] + b[0];
    for(i = 1; i < count; i++) {
        r[i] = a[i] + b[i] + (r[i - 1] >> 32);
        r[i - 1] &= 0x0FFFFFFFFULL;
    }
}

/**
 * 大数减法，r = (a - b)
 * @param r 存储结果
 * @param a 大数a
 * @param b 大数b
 */
static void gm_i_bn_sub(gm_bn_t r, const gm_bn_t a, const gm_bn_t b) {
    int i;
    r[0] = 0x100000000ULL + a[0] - b[0];
    for (i = 1; i < GM_BN_ARR_SIZE_SUB_ONE; i++) {
        r[i] = 0x0FFFFFFFFULL + a[i] - b[i] + (r[i - 1] >> 32);
        r[i - 1] &= 0x0FFFFFFFFULL;
    }
    r[i] = a[i] - b[i] + (r[i - 1] >> 32) - 1;
    r[i - 1] &= 0x0FFFFFFFFULL;
}

/**
 * 大数乘法, r = k[b]
 * @param r 存储结果
 * @param k 8字节数
 * @param b 大数
 */
static void gm_i_bn_mul(uint64_t * r, const uint64_t * k, const gm_bn_t b) {
    int i, j;
    // k0b0, k0b1+k1b0, .. ,k0b7+k1b6, k1b7
    uint64_t t;

    for(i = 0; i < 2; i++) {
        t = 0;
        for (j = 0; j < 8; j++) {
            t = r[i + j] + k[i] * b[j] + t;
            r[i + j] = t & 0x0FFFFFFFFULL;
            t >>= 32;
        }
        r[i + 8] = t;
    }
}

#endif

/**
 * 大数加法，r = (a + b)
 * @param r 存储结果
 * @param a 大数a
 * @param b 大数b
 */
static void gm_i_bn_add(gm_bn_t r, const gm_bn_t a, const gm_bn_t b) {
    gm_i_bn_add_x(r, a, b, 8);
}

// 十六进制转化为int
static int gm_hex2int(char c) {
    if(c >= '0' && c <= '9') {
        return c - '0';
    }else if(c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }else if(c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/**
 * 十六进制转化为二进制
 * @param in 十六进制串
 * @param in_len 十六进制串长度，必须为偶数
 * @param out 二进制缓冲区
 */
int gm_hex2bin(const char * in, int in_len, uint8_t * out) {
    int c = 0;
    if((in_len % 2) != 0) {
        return -1;
    }

    while (in_len) {
        if ((c = gm_hex2int(*in++)) < 0) {
            return -1;
        }
        *out = (uint8_t)c << 4;

        if ((c = gm_hex2int(*in++)) < 0) {
            return -1;
        }
        *out |= (uint8_t)c;

        in_len -= 2;
        out++;
    }
    return 1;
}

/**
 * 将大数转化为二进制串
 * @param a 待转化大数
 * @param out 输出缓冲区
 */
void gm_bn_to_bytes(const gm_bn_t a, uint8_t out[32])
{
    int i;
    for (i = 7; i >= 0; i--) {
        GM_PUTU32(out, a[i]);
        out += 4;
    }
}

/**
 * 将二进制串转化为大数
 * @param r 用于存储转化后的大数
 * @param in 待转化的二进制串
 */
void gm_bn_from_bytes(gm_bn_t r, const uint8_t in[32])
{
    int i;
    for (i = 7; i >= 0; i--) {
        r[i] = GM_GETU32(in);
        in += 4;
    }
}

/**
 * 将大数转化为十六进制串
 * @param a 待转化大数
 * @param hex 输出缓冲区
 */
void gm_bn_to_hex(const gm_bn_t a, char hex[64])
{
    int i;
    for (i = 7; i >= 0; i--) {
        int len;
        len = sprintf(hex, "%08X", (uint32_t)a[i]);
        assert(len == 8);
        hex += 8;
    }
}

/**
 * 将十六进制串转化为大数
 * @param r 用于存储转化后的大数
 * @param hex 待转化十六进制串
 */
int gm_bn_from_hex(gm_bn_t r, const char hex[64])
{
    uint8_t buf[32];
    if (gm_hex2bin(hex, 64, buf) < 0)
        return -1;
    gm_bn_from_bytes(r, buf);
    return 1;
}

/**
 * 将大数转化为比特串
 * @param a 待转化大数
 * @param bits 比特串缓冲区
 */
void gm_bn_to_bits(const gm_bn_t a, char bits[256])
{
    int i, j;
    for (i = 7; i >= 0; i--) {
        uint64_t w = a[i];
        for (j = 0; j < 32; j++) {
            *bits++ = (w & 0x080000000ULL) ? '1' : '0';
            w <<= 1;
        }
    }
}

/**
 * 大数比较
 * @param a 大数a
 * @param b 大数b
 * @return 0 当a等于b，1当a大于b，-1当a小于b
 */
int gm_bn_cmp(const gm_bn_t a, const gm_bn_t b) {
    int i;
    for (i = 7; i >= 0; i--) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            return -1;
    }
    return 0;
}

/**
 * 大数模加，(a + b)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param b 大数b
 * @param m 模m
 */
void gm_bn_add(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m) {
    gm_i_bn_add(r, a, b);
    if(gm_bn_cmp(r, m) >= 0) {
        gm_i_bn_sub(r, r, m);
    }
}

/**
 * 大数模减，(a - b)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param b 大数b
 * @param m 模m
 */
void gm_bn_sub(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m) {
    if (gm_bn_cmp(a, b) >= 0) {
        gm_i_bn_sub(r, a, b);
    } else {
        gm_bn_t t;
        gm_i_bn_sub(t, m, b);
        gm_i_bn_add(r, t, a);
    }
}

/**
 * 蒙哥马利域模乘，(a * b)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param b 大数b
 * @param m 模m
 */
void gm_bn_mont_mul(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m) {
    uint64_t temp_r[11] = {0};
    uint64_t temp_mul[11] = {0};
    uint64_t temp_q[2] = {0};
    int i, j;

    uint64_t mod_t = (m[0] == GM_BN_N[0] ? 0x327F9E8872350975ULL : 0x01);

    for(i = 0; i < 4; i++) {
        // bi*a
        memset(temp_mul, 0, sizeof(uint64_t) * 11);
        gm_i_bn_mul(temp_mul, &b[i * 2], a);
        gm_i_bn_add_x(temp_r, temp_r, temp_mul, 11);

        // cal q
        uint64_t q = (temp_r[0] | temp_r[1] << 32) * mod_t;
        temp_q[0] = q & 0x0FFFFFFFFULL;
        temp_q[1] = q >> 32;

        // q * n
        memset(temp_mul, 0, sizeof(uint64_t) * 11);
        gm_i_bn_mul(temp_mul, temp_q, m);
        gm_i_bn_add_x(temp_r, temp_r, temp_mul, 11);

        // reduce temp_r
        memmove(temp_r, temp_r + 2, sizeof(uint64_t) * 9);
        temp_r[9] = 0;
        temp_r[10] = 0;
    }

    temp_r[7] += temp_r[8] << 32;
    if(gm_bn_cmp(temp_r, m) >= 0) {
        gm_i_bn_sub(temp_r, temp_r, m);
    }
    gm_bn_copy(r, temp_r);
}

/**
 * 将大数转化为蒙哥马利域
 * @param r 计算结果
 * @param a 大数a
 * @param m 模m
 */
void gm_bn_to_mont(gm_bn_t r, const gm_bn_t a, const gm_bn_t m) {
    gm_bn_mont_mul(r, a, (m[0] == GM_BN_N[0] ? GM_BN_MONT_NRR : GM_BN_MONT_PRR), m);
}

/**
 * 将蒙哥马利域转化为普通大数
 * @param r 计算结果
 * @param a 大数a
 * @param m 模m
 */
void gm_bn_from_mont(gm_bn_t r, const gm_bn_t a, const gm_bn_t m) {
    gm_bn_mont_mul(r, a, GM_BN_ONE, m);
}

/**
 * 蒙哥马利域模平方，(a * a)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param m 模m
 */
void gm_bn_sqr(gm_bn_t r, const gm_bn_t a, const gm_bn_t m) {
    gm_bn_mont_mul(r, a, a, m);
}

/**
 * 蒙哥马利域模幂，(a ^ b)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param b 大数b
 * @param m 模m
 */
void gm_bn_exp(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m) {
    gm_bn_t t;
    uint64_t w;
    int i, j;

    // set t to mont one
    gm_bn_to_mont(t, GM_BN_ONE, m);

    for (i = 7; i >= 0; i--) {
        w = b[i];
        for (j = 0; j < 32; j++) {
            gm_bn_sqr(t, t, m);
            if (w & 0x080000000ULL) {
                gm_bn_mont_mul(t, t, a, m);
            }
            w <<= 1;
        }
    }

    gm_bn_copy(r, t);
}

/**
 * 蒙哥马利域模逆，(a ^ -1)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param m 模m
 */
void gm_bn_inv(gm_bn_t r, const gm_bn_t a, const gm_bn_t m) {
    gm_bn_t e;
    gm_i_bn_sub(e, m, GM_BN_TWO);
    gm_bn_exp(r, a, e, m);
}

// 将大数设置为蒙哥马利域1
void gm_bn_set_mont_one(gm_bn_t r) {
    gm_bn_copy(r, GM_BN_MONT_PONE);
}

// 将大数设置为0
void gm_bn_set_zero(gm_bn_t r) {
    gm_bn_copy(r, GM_BN_ZERO);
}

/**
 * 判断大数是否为蒙哥马利域1
 * @return 1为true，否则为false
 */
int gm_bn_is_mont_one(const gm_bn_t r){
    return memcmp(r, GM_BN_MONT_PONE, sizeof(uint64_t) * 8) == 0;
}

/**
 * 判断大数是否为0
 * @return 1为true，否则为false
 */
int gm_bn_is_zero(const gm_bn_t r) {
    return gm_bn_cmp(r, GM_BN_ZERO) == 0;
}

// 初始化点r为无穷远点
void gm_point_init(gm_point_t *r) {
    memset(r, 0, sizeof(gm_point_t));
    gm_bn_set_mont_one(r->X);
    gm_bn_set_mont_one(r->Y);
}

/**
 * 设置点r的x及y坐标，点r为Jacobian加重射影坐标系
 * @param r 用于存储结果
 * @param x x坐标，仿射坐标
 * @param y y坐标，仿射坐标
 */
void gm_point_set_xy(gm_point_t *r, const gm_bn_t x, const gm_bn_t y) {
    gm_bn_to_mont(r->X, x, GM_BN_P);
    gm_bn_to_mont(r->Y, y, GM_BN_P);
    gm_bn_set_mont_one(r->Z);
}

// 停留在蒙哥马利域
static void gm_point_get_xy_mont(const gm_point_t *p, gm_bn_t x, gm_bn_t y) {
    gm_bn_t z_inv;
    if (gm_bn_is_mont_one(p->Z)) {
        if(x) {
            gm_bn_copy(x, p->X);
        }
        if(y) {
            gm_bn_copy(y, p->Y);
        }
    } else {
        // z^{-1}
        gm_bn_inv(z_inv, p->Z, GM_BN_P);
        if (y) {
            gm_bn_mont_mul(y, p->Y, z_inv, GM_BN_P);
        }
        // z^{-2}
        gm_bn_sqr(z_inv, z_inv, GM_BN_P);
        if(x) {
            gm_bn_mont_mul(x, p->X, z_inv, GM_BN_P);
        }
        if (y) {
            gm_bn_mont_mul(y, y, z_inv, GM_BN_P);
        }
    }
}

/**
 * 获取点p的x坐标及y坐标
 * @param p Jacobian加重射影坐标系点p
 * @param x 存储x坐标，仿射坐标
 * @param y 存储y坐标，仿射坐标
 */
void gm_point_get_xy(const gm_point_t *p, gm_bn_t x, gm_bn_t y) {
    gm_point_get_xy_mont(p, x, y);
    if(x) {
        gm_bn_from_mont(x, x, GM_BN_P);
    }
    if(y) {
        gm_bn_from_mont(y, y, GM_BN_P);
    }
}

/**
 * 判断p是否为无穷远点
 * @return 1为无穷远点，否则不是
 */
int gm_is_at_infinity(const gm_point_t *p) {
    return gm_bn_is_zero(p->Z);
}

/**
 * 将十六进制串转化为点
 * @param p 用于存储结果
 * @param hex 十六进制串
 */
void gm_point_from_hex(gm_point_t *p, const char hex[128]) {
    gm_bn_t x;
    gm_bn_t y;
    gm_bn_from_hex(x, hex);
    gm_bn_from_hex(y, hex + 64);
    gm_point_set_xy(p, x, y);
}

/**
 * 将点转化为十六进制串
 * @param r 待转化的点
 * @param hex 十六进制缓冲区
 */
void gm_point_to_hex(const gm_point_t *r, char hex[128]) {
    gm_bn_t x;
    gm_bn_t y;
    gm_point_get_xy(r, x, y);
    gm_bn_to_hex(x, hex);
    gm_bn_to_hex(y, hex + 64);
}

/**
 * 将二进制串转化为点
 * @param r 用于存储结果
 * @param in 二进制串
 */
void gm_point_from_bytes(gm_point_t *r, const uint8_t in[64]) {
    gm_bn_t x;
    gm_bn_t y;
    gm_bn_from_bytes(x, in);
    gm_bn_from_bytes(y, in + 32);
    gm_point_set_xy(r, x, y);
}

/**
 * 将点转化为二进制串
 * @param p 待转化的点
 * @param out 二进制缓冲区
 */
void gm_point_to_bytes(const gm_point_t *p, uint8_t out[64]) {
    gm_bn_t x;
    gm_bn_t y;
    gm_point_get_xy(p, x, y);
    gm_bn_to_bytes(x, out);
    gm_bn_to_bytes(y, out + 32);
}

// 4M+5S
/**
 * 倍点算法，r = p + p
 * @param r 用于存储结果
 * @param p 待计算点p
 */
void gm_point_double(gm_point_t * r, const gm_point_t * p) {
    gm_bn_t tmp1, tmp2;
    gm_bn_t X3, Y3, Z3;

    gm_bn_t R1, R2, R3;

    if (gm_is_at_infinity(p)) {
        gm_point_copy(r, p);
        return;
    }

    // λ1 = 3X^2 + aZ^4 = 3X^2 - 3Z^4 = 3 * ( (X + Z^2) * (X - Z^2) )
    // z^2
    gm_bn_sqr(tmp1, p->Z, GM_BN_P);
    // X + Z^2
    gm_bn_add(tmp2, p->X, tmp1, GM_BN_P);
    // X - Z^2
    gm_bn_sub(tmp1, p->X, tmp1, GM_BN_P);
    // (X + Z^2) * (X - Z^2)
    gm_bn_mont_mul(R1, tmp1, tmp2, GM_BN_P);
    // λ1 = 3 * (X + Z^2) * (X - Z^2)
    gm_bn_add(tmp1, R1, R1, GM_BN_P);
    gm_bn_add(R1, tmp1, R1, GM_BN_P);

    // λ2 = X4Y^2 = X * (2Y)^2
    // Z3 = 2YZ

    // 2Y
    gm_bn_add(tmp1, p->Y, p->Y, GM_BN_P);
    // Z3 = 2YZ
    gm_bn_mont_mul(Z3, tmp1, p->Z, GM_BN_P);

    // λ2 = X * (2Y)^2
    gm_bn_sqr(R2, tmp1, GM_BN_P);

    gm_bn_mont_mul(R2, p->X, R2, GM_BN_P);

    // λ3 = 8Y^4 = 2 * 4Y^4 = 2 * (2 * Y^2) ^ 2
    // Y^2
    gm_bn_sqr(tmp1, p->Y, GM_BN_P);
    // 2Y^2
    gm_bn_add(tmp1, tmp1, tmp1, GM_BN_P);
    // (2 * Y^2) ^ 2
    gm_bn_sqr(tmp1, tmp1, GM_BN_P);
    // λ3 = 2 * (2 * Y^2) ^ 2
    gm_bn_add(R3, tmp1, tmp1, GM_BN_P);

    // X3 = λ1^2 − 2λ2
    // R1^2
    gm_bn_sqr(tmp1, R1, GM_BN_P);
    // 2R2
    gm_bn_add(tmp2, R2, R2, GM_BN_P);
    // X3 = λ1^2 − 2λ2
    gm_bn_sub(X3, tmp1, tmp2, GM_BN_P);

    // Y3 = λ1(λ2 − X3) − λ3
    // λ2 − X3
    gm_bn_sub(tmp1, R2, X3, GM_BN_P);
    // λ1(λ2 − X3)
    gm_bn_mont_mul(tmp2, R1, tmp1, GM_BN_P);
    // Y3 = λ1(λ2 − X3) − λ3
    gm_bn_sub(Y3, tmp2, R3, GM_BN_P);

    // output
    gm_bn_copy(r->X, X3);
    gm_bn_copy(r->Y, Y3);
    gm_bn_copy(r->Z, Z3);
}

/**
 * 点加算法，r = a + b
 * @param r 用于存储结果
 * @param a 待计算点a
 * @param b 待计算点b
 */
void gm_point_add(gm_point_t * r, const gm_point_t * a, const gm_point_t * b) {
    // U1 = X1 * (Z2)^2
    // U2 = X2 * (Z1)^2
    // S1 = Y1 * (Z2)^3
    // S2 = Y2 * (Z1)^3
    // if U1==U2 && S1==S2 return double(a)
    // H = U2 - U1
    // R = S2 - S1
    // X3 = R^2 - H^3 - 2U1 * H^2
    // Y3 = R * ( U1 * H^2 - X3) - S1 * H^3
    // Z3 = H * Z1 * Z2

    gm_bn_t U1, U2;
    gm_bn_t S1, S2;
    gm_bn_t H;
    gm_bn_t R;

    gm_bn_t X3, Y3, Z3;

    if (gm_is_at_infinity(a)) {
        gm_point_copy(r, b);
        return;
    }

    if (gm_is_at_infinity(b)) {
        gm_point_copy(r, a);
        return;
    }

    // Z1 ^ 2
    gm_bn_sqr(H, a->Z, GM_BN_P);
    // Z2 ^ 2
    gm_bn_sqr(R, b->Z, GM_BN_P);
    // U1 = X1 * (Z2)^2
    gm_bn_mont_mul(U1, a->X, R, GM_BN_P);
    // U2 = X2 * (Z1)^2
    gm_bn_mont_mul(U2, b->X, H, GM_BN_P);
    // Z1 ^ 3
    gm_bn_mont_mul(H, H, a->Z, GM_BN_P);
    // Z2 ^ 3
    gm_bn_mont_mul(R, R, b->Z, GM_BN_P);
    // S1 = Y1 * (Z2)^3
    gm_bn_mont_mul(S1, a->Y, R, GM_BN_P);
    // S2 = Y2 * (Z1)^3
    gm_bn_mont_mul(S2, b->Y, H, GM_BN_P);

    if(gm_bn_cmp(U1, U2) == 0 && gm_bn_cmp(S1, S2) == 0) {
        gm_point_double(r, a);
        return;
    }

    // H = U2 - U1
    gm_bn_sub(H, U2, U1, GM_BN_P);
    // R = S2 - S1
    gm_bn_sub(R, S2, S1, GM_BN_P);
    // Z3 = H * Z1 * Z2
    gm_bn_mont_mul(Z3, H, a->Z, GM_BN_P);
    gm_bn_mont_mul(Z3, Z3, b->Z, GM_BN_P);
    // H ^ 2
    gm_bn_sqr(U2, H, GM_BN_P);
    // H ^ 3
    gm_bn_mont_mul(H, U2, H, GM_BN_P);
    // U1 * H ^2
    gm_bn_mont_mul(Y3, U1, U2, GM_BN_P);
    // 2 * U1 * H ^2
    gm_bn_add(U2, Y3, Y3, GM_BN_P);
    // R^2
    gm_bn_sqr(X3, R, GM_BN_P);
    // X3 = R^2 - H^3 - 2U1 * H^2
    gm_bn_sub(X3, X3, H, GM_BN_P);
    gm_bn_sub(X3, X3, U2, GM_BN_P);
    // Y3 = R * ( U1 * H^2 - X3) - S1 * H^3
    // ( U1 * H^2 - X3)
    gm_bn_sub(Y3, Y3, X3, GM_BN_P);
    // R * ( U1 * H^2 - X3)
    gm_bn_mont_mul(Y3, Y3, R, GM_BN_P);
    // S1 * H^3
    gm_bn_mont_mul(S1, S1, H, GM_BN_P);
    // Y3 = R * ( U1 * H^2 - X3) - S1 * H^3
    gm_bn_sub(Y3, Y3, S1, GM_BN_P);

    // output
    gm_bn_copy(r->X, X3);
    gm_bn_copy(r->Y, Y3);
    gm_bn_copy(r->Z, Z3);
}

/**
 * 多倍点算法，r = k[p]，即k个p相加
 * @param r 用于存储结果
 * @param k 大数k
 * @param p 待计算点p
 */
void gm_point_mul(gm_point_t * r, const gm_bn_t k, const gm_point_t * p) {
    char bits[257] = {0};
    gm_point_t _q;
    gm_point_t * q = &_q;
    int i;

    gm_point_set_infinity(q);
    gm_bn_to_bits(k, bits);

    for (i = 0; i < 256; i++) {
        gm_point_double(q, q);
        if (bits[i] == '1') {
            gm_point_add(q, q, p);
        }
    }
    gm_point_copy(r, q);
}

/**
 * 点压缩算法，当需要压缩时，压缩结果表示为：
 * 0x02 + yTile || x
 * 当不需要压缩时，结果为：
 * 0x04 || x || y
 * @param p 待压缩的点
 * @param out 压缩后存储数据的缓存区，压缩时大小为33字节，不压缩时大小为65字节
 * @param compressed 1为需要压缩，非1表示不需要压缩
 */
void gm_point_encode(const gm_point_t *p, uint8_t * out, int compressed) {
    if(compressed) {
        gm_bn_t x, y;
        gm_point_get_xy(p, x, y);

        out[0] = 0x02 + (y[0] & 0x01);
        gm_bn_to_bytes(x, out + 1);
    } else {
        out[0] = 0x04;
        gm_point_to_bytes(p, out + 1);
    }
}

/**
 * 点解压缩
 * @param p 用于存储结果
 * @param in 未压缩的点（65字节）或压缩的点（33字节）
 */
void gm_point_decode(gm_point_t *p, const uint8_t * in) {
    if(in[0] == 0x04) {
        // 未压缩点，直接转化
        gm_point_from_bytes(p, in + 1);
    }else if(in[0] == 0x02 || in[0] == 0x03) {
        int yTile = in[0] - 0x02;
        gm_bn_t x, r;

        // 预计算的 (P + 1) / 4
        gm_bn_t padd1shit2 = {
            0x00000000, 0x40000000, 0xC0000000, 0xFFFFFFFF,
            0xFFFFFFFF, 0xFFFFFFFF, 0xBFFFFFFF, 0x3FFFFFFF
        };

        gm_bn_from_bytes(x, in + 1);
        gm_bn_to_mont(x, x, GM_BN_P);

        // r = x ^ 2
        gm_bn_sqr(r, x, GM_BN_P);

        // r = x^2 + a
        gm_bn_add(r, r, GM_BN_MONT_A, GM_BN_P);

        // r = x^3 + ax
        gm_bn_mont_mul(r, r, x, GM_BN_P);

        // r = x^3 + ax + b
        gm_bn_add(r, r, GM_BN_MONT_B, GM_BN_P);

        // r = sqrt(x^3 + ax + b) = (x^3 + ax + b) ^ ((P + 1) / 4) (mod P)
        gm_bn_exp(r, r, padd1shit2, GM_BN_P);

        gm_bn_from_mont(padd1shit2, r, GM_BN_P);
        if((padd1shit2[0] & 0x01) != yTile) {
            gm_bn_sub(r, GM_BN_P, padd1shit2, GM_BN_P);
            gm_bn_to_mont(r, r, GM_BN_P);
        }

        gm_bn_copy(p->X, x);
        gm_bn_copy(p->Y, r);
        gm_bn_set_mont_one(p->Z);
    }
}

/**
 * SM2签名算法
 * @param key SM2私钥
 * @param dgst 消息摘要
 * @param sig 存储签名结果缓冲区
 * @return 1如果签名成功，否则签名失败
 */
int gm_do_sign(const gm_bn_t key, const gm_bn_t dgst, unsigned char sig[64]) {
    return gm_do_sign_for_test(key, dgst, sig, NULL);
}

/**
 * SM2签名算法，方便单元测试
 * @param key SM2私钥
 * @param dgst 消息摘要
 * @param sig 存储签名结果缓冲区
 * @param testK 随机数
 * @return 1如果签名成功，否则签名失败
 */
int gm_do_sign_for_test(const gm_bn_t key, const gm_bn_t dgst, unsigned char sig[64], const gm_bn_t testK) {
    gm_point_t _P, *P = &_P;
    gm_bn_t d;
    gm_bn_t e;
    gm_bn_t k;
    gm_bn_t x;
    gm_bn_t r;
    gm_bn_t s;

    if (!key || !dgst || !sig) {
        return -1;
    }

    gm_bn_to_mont(d, key, GM_BN_N);

    // e = H(M)
    gm_bn_copy(e, dgst);

retry:
    if(NULL == testK) {
        // rand k in [1, n - 1]
        uint8_t buf[256];
        do {
            do {
                randombytes(buf, 256);
#ifdef GM_RAND_SM3
                gm_sm3(buf, 256, buf);
#endif
                gm_bn_from_bytes(k, buf);
            } while (gm_bn_cmp(k, GM_BN_N) >= 0);
        } while (gm_bn_is_zero(k));
    } else {
        gm_bn_copy(k, testK);
    }

    // (x, y) = kG
    gm_point_mul(P, k, GM_MONT_G);
    gm_point_get_xy(P, x, NULL);


    // r = e + x (mod n)
    gm_bn_add(r, e, x, GM_BN_N);

    /* if r == 0 or r + k == n re-generate k */
    if (gm_bn_is_zero(r)) {
        goto retry;
    }
    gm_bn_add(x, r, k, GM_BN_N);
    if (gm_bn_is_zero(x)) {
        goto retry;
    }

    gm_bn_to_bytes(r, sig);

    /* s = ((1 + d)^-1 * (k - r * d)) mod n */
    gm_bn_to_mont(r, r, GM_BN_N);
    gm_bn_to_mont(k, k, GM_BN_N);

    gm_bn_mont_mul(e, r, d, GM_BN_N);
    gm_bn_sub(k, k, e, GM_BN_N);

    gm_bn_add(x, GM_BN_MONT_NONE, d, GM_BN_N);
    gm_bn_inv(x, x, GM_BN_N);
    gm_bn_mont_mul(s, x, k, GM_BN_N);

    if(gm_bn_is_zero(s)) {
        goto retry;
    }

    gm_bn_from_mont(s, s, GM_BN_N);
    gm_bn_to_bytes(s, sig + 32);
    return 1;
}

/**
 * SM2验签算法
 * @param key SM2私钥
 * @param dgst 消息摘要
 * @param sig 签名结果，用于验签
 * @return 1如果验签成功，否则验签失败
 */
int gm_do_verify(const gm_point_t *key, const gm_bn_t dgst, const unsigned char sig[64]) {
    gm_point_t _P, *P = &_P;
    gm_point_t _Q, *Q = &_Q;
    gm_bn_t r;
    gm_bn_t s;
    gm_bn_t e;
    gm_bn_t x;
    gm_bn_t t;

    if (!key || !dgst || !sig) {
        return -1;
    }

    // parse signature values
    gm_bn_from_bytes(r, (const uint8_t *)sig);
    gm_bn_from_bytes(s, (const uint8_t *)sig + 32);
    if (gm_bn_is_zero(r)
        || gm_bn_cmp(r, GM_BN_N) >= 0
        || gm_bn_is_zero(s)
        || gm_bn_cmp(s, GM_BN_N) >= 0) {
        return -1;
    }

    // parse public key
    gm_point_copy(P, key);

    // t = r + s (mod n)
    // check t != 0
    gm_bn_add(t, r, s, GM_BN_N);
    if (gm_bn_is_zero(t)) {
        return -1;
    }

    // Q = s * G + t * P
    gm_point_mul(Q, s, GM_MONT_G);
    gm_point_mul(P, t, P);
    gm_point_add(Q, Q, P);
    gm_point_get_xy(Q, x, NULL);

    // e  = H(M)
    // r' = e + x (mod n)
    gm_bn_copy(e, dgst);
    gm_bn_add(e, e, x, GM_BN_N);

    // check if r == r'
    if (gm_bn_cmp(e, r) == 0) {
        return 1;
    } else {
        return 0;
    }
}