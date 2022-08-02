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

#define GM_BN_ARR_SIZE 8
#define GM_BN_ARR_SIZE_SUB_ONE 7

// 大数的定义
typedef uint64_t gm_bn_t[8];

// 点的定义，Jacobian加重射影坐标系
typedef struct {
    gm_bn_t X;
    gm_bn_t Y;
    gm_bn_t Z;
} gm_point_t;

// SM2 P
extern const gm_bn_t GM_BN_P;
// SM2 N
extern const gm_bn_t GM_BN_N;
// SM2 蒙哥马利域 G
extern const gm_point_t * GM_MONT_G;

// 蒙哥马利域, SM2 A
extern const gm_bn_t GM_BN_MONT_A;

// 蒙哥马利域, SM2 B
extern const gm_bn_t GM_BN_MONT_B;

// 将大数a拷贝到r
#define gm_bn_copy(r, a) memcpy((r), (a), sizeof(gm_bn_t))

/**
 * 十六进制转化为二进制
 * @param in 十六进制串
 * @param in_len 十六进制串长度，必须为偶数
 * @param out 二进制缓冲区
 */
int gm_hex2bin(const char * in, int in_len, uint8_t * out);

/**
 * 将大数转化为二进制串
 * @param a 待转化大数
 * @param out 输出缓冲区
 */
void gm_bn_to_bytes(const gm_bn_t a, uint8_t out[32]);

/**
 * 将二进制串转化为大数
 * @param r 用于存储转化后的大数
 * @param in 待转化的二进制串
 */
void gm_bn_from_bytes(gm_bn_t r, const uint8_t in[32]);

/**
 * 将大数转化为十六进制串
 * @param a 待转化大数
 * @param hex 输出缓冲区
 */
void gm_bn_to_hex(const gm_bn_t a, char hex[64]);

/**
 * 将十六进制串转化为大数
 * @param r 用于存储转化后的大数
 * @param hex 待转化十六进制串
 */
int gm_bn_from_hex(gm_bn_t r, const char hex[64]);

/**
 * 将大数转化为比特串
 * @param a 待转化大数
 * @param bits 比特串缓冲区
 */
void gm_bn_to_bits(const gm_bn_t a, char bits[256]);

/**
 * 大数比较
 * @param a 大数a
 * @param b 大数b
 * @return 0 当a等于b，1当a大于b，-1当a小于b
 */
int gm_bn_cmp(const gm_bn_t a, const gm_bn_t b);

/**
 * 大数模加，(a + b)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param b 大数b
 * @param m 模m
 */
void gm_bn_add(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m);

/**
 * 大数模减，(a - b)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param b 大数b
 * @param m 模m
 */
void gm_bn_sub(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m);

/**
 * 将大数转化为蒙哥马利域
 * @param r 计算结果
 * @param a 大数a
 * @param m 模m
 */
void gm_bn_to_mont(gm_bn_t r, const gm_bn_t a, const gm_bn_t m);

/**
 * 将蒙哥马利域转化为普通大数
 * @param r 计算结果
 * @param a 大数a
 * @param m 模m
 */
void gm_bn_from_mont(gm_bn_t r, const gm_bn_t a, const gm_bn_t m);

/**
 * 蒙哥马利域模乘，(a * b)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param b 大数b
 * @param m 模m
 */
void gm_bn_mont_mul(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m);

/**
 * 蒙哥马利域模平方，(a * a)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param m 模m
 */
void gm_bn_sqr(gm_bn_t r, const gm_bn_t a, const gm_bn_t m);

/**
 * 蒙哥马利域模幂，(a ^ b)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param b 大数b
 * @param m 模m
 */
void gm_bn_exp(gm_bn_t r, const gm_bn_t a, const gm_bn_t b, const gm_bn_t m);

/**
 * 蒙哥马利域模逆，(a ^ -1)(mod m)
 * @param r 计算结果
 * @param a 大数a
 * @param m 模m
 */
void gm_bn_inv(gm_bn_t r, const gm_bn_t a, const gm_bn_t m);

// 将大数设置为0
void gm_bn_set_zero(gm_bn_t r);

// 将大数设置为蒙哥马利域1
void gm_bn_set_mont_one(gm_bn_t r);

/**
 * 判断大数是否为蒙哥马利域1
 * @return 1为true，否则为false
 */
int gm_bn_is_mont_one(const gm_bn_t r);

/**
 * 判断大数是否为0
 * @return 1为true，否则为false
 */
int gm_bn_is_zero(const gm_bn_t r);

// 将r设置为无穷远点
#define gm_point_set_infinity(r) gm_point_init(r)

// 将点p拷贝到r
#define gm_point_copy(r, p) memcpy((r), (p), sizeof(gm_point_t))

// 初始化点r为无穷远点
void gm_point_init(gm_point_t *r);

/**
 * 设置点r的x及y坐标，点r为Jacobian加重射影坐标系
 * @param r 用于存储结果
 * @param x x坐标，仿射坐标
 * @param y y坐标，仿射坐标
 */
void gm_point_set_xy(gm_point_t *r, const gm_bn_t x, const gm_bn_t y);

/**
 * 获取点p的x坐标及y坐标
 * @param p Jacobian加重射影坐标系点p
 * @param x 存储x坐标，仿射坐标
 * @param y 存储y坐标，仿射坐标
 */
void gm_point_get_xy(const gm_point_t *p, gm_bn_t x, gm_bn_t y);

/**
 * 判断p是否为无穷远点
 * @return 1为无穷远点，否则不是
 */
int gm_is_at_infinity(const gm_point_t *p);

/**
 * 将十六进制串转化为点
 * @param p 用于存储结果
 * @param hex 十六进制串
 */
void gm_point_from_hex(gm_point_t *p, const char hex[128]);

/**
 * 将点转化为十六进制串
 * @param r 待转化的点
 * @param hex 十六进制缓冲区
 */
void gm_point_to_hex(const gm_point_t *r, char hex[128]);

/**
 * 将二进制串转化为点
 * @param r 用于存储结果
 * @param in 二进制串
 */
void gm_point_from_bytes(gm_point_t *r, const uint8_t in[64]);

/**
 * 将点转化为二进制串
 * @param p 待转化的点
 * @param out 二进制缓冲区
 */
void gm_point_to_bytes(const gm_point_t *p, uint8_t out[64]);

/**
 * 点压缩算法，当需要压缩时，压缩结果表示为：
 * 0x02 + yTile || x
 * 当不需要压缩时，结果为：
 * 0x04 || x || y
 * @param p 待压缩的点
 * @param out 压缩后存储数据的缓存区，压缩时大小为33字节，不压缩时大小为65字节
 * @param compressed 1为需要压缩，非1表示不需要压缩
 */
void gm_point_encode(const gm_point_t *p, uint8_t * out, int compressed);

/**
 * 点解压缩
 * @param p 用于存储结果
 * @param in 未压缩的点（65字节）或压缩的点（33字节）
 */
void gm_point_decode(gm_point_t *p, const uint8_t * in);

/**
 * 倍点算法，r = p + p
 * @param r 用于存储结果
 * @param p 待计算点p
 */
void gm_point_double(gm_point_t * r, const gm_point_t * p);

/**
 * 点加算法，r = a + b
 * @param r 用于存储结果
 * @param a 待计算点a
 * @param b 待计算点b
 */
void gm_point_add(gm_point_t * r, const gm_point_t * a, const gm_point_t * b);

/**
 * 多倍点算法，r = k[p]，即k个p相加
 * @param r 用于存储结果
 * @param k 大数k
 * @param p 待计算点p
 */
void gm_point_mul(gm_point_t * r, const gm_bn_t k, const gm_point_t * p);

/**
 * SM2签名算法
 * @param key SM2私钥
 * @param dgst 消息摘要
 * @param sig 存储签名结果缓冲区
 * @return 1如果签名成功，否则签名失败
 */
int gm_do_sign(const gm_bn_t key, const gm_bn_t dgst, unsigned char sig[64]);

/**
 * SM2签名算法，方便单元测试
 * @param key SM2私钥
 * @param dgst 消息摘要
 * @param sig 存储签名结果缓冲区
 * @param testK 随机数
 * @return 1如果签名成功，否则签名失败
 */
int gm_do_sign_for_test(const gm_bn_t key, const gm_bn_t dgst, unsigned char sig[64], const gm_bn_t testK);

/**
 * SM2验签算法
 * @param key SM2私钥
 * @param dgst 消息摘要
 * @param sig 签名结果，用于验签
 * @return 1如果验签成功，否则验签失败
 */
int gm_do_verify(const gm_point_t *key, const gm_bn_t dgst, const unsigned char sig[64]);

# ifdef  __cplusplus
}
# endif

#endif //YISECUREBOX_GM_H