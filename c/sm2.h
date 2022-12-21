//
// Created by saint on 2022/1/11.
//

#ifndef YISECUREBOXCPP_SM2_H
#define YISECUREBOXCPP_SM2_H

#include "gm.h"
#include "sm3.h"

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct {
    gm_bn_t private_key;            // SM2私钥
    gm_point_t public_key;          // SM2公钥

    unsigned char x2y2[64];         // SM2 crypt x2y2

    gm_sm3_context sm3_ctx;         // SM3上下文，用于计算加解密C3

    unsigned char buf[32];          // 缓冲区，32字节为一个数据块
    unsigned int cur_buf_len;       // 当前缓冲区长度
    unsigned int ct;                // SM2 crypt ct，计算KDF
    unsigned int state;             // 标识是否为加密或是否为签名
} gm_sm2_context;

typedef struct {
    gm_bn_t t;                      // tA or tB
    unsigned char xy[64];           // 临时公钥(x1, y1) or (x2, y2)
    unsigned char z[32];            // ZA or ZB
    unsigned char isInitiator;      // 1为发起方，否则为响应方
} gm_sm2_exch_context;

/**
 * 密钥协商初始化
 * @param ctx 上下文
 * @param private_key 用户私钥dA or dB
 * @param public_key 用户公钥PA or PB
 * @param isInitiator 1为发起方，否则为响应方
 * @param id_bytes 用户Id
 * @param idLen 用户Id长度
 * @param output 输出 RA or RB
 */
void gm_sm2_exch_init(gm_sm2_exch_context * ctx, gm_bn_t private_key, const gm_point_t * public_key, 
  unsigned char isInitiator, const unsigned char * id_bytes, unsigned int idLen, unsigned char output[64]);

void gm_sm2_exch_init_for_test(gm_sm2_exch_context * ctx, gm_bn_t private_key, const gm_point_t * public_key, 
  gm_bn_t tmp_private_key, const gm_point_t * tmp_public_key, 
  unsigned char isInitiator, const unsigned char * id_bytes, unsigned int idLen, unsigned char output[64]);

/**
 * 计算密钥K，S1/SB、S2/SA
 * @param ctx 上下文
 * @param peer_p 对方公钥P
 * @param peer_r 对方初始化信息 R，即随机公钥
 * @param id_bytes 对方user id
 * @param idLen 对方user id 长度
 * @param kLen 协商的密钥长度（单位字节）
 * @param output 输出密钥 k || S1/SB || S2/SA，长度为kLen + 64
 */
void gm_sm2_exch_calculate(gm_sm2_exch_context * ctx, const unsigned char * peer_p, const unsigned char * peer_r, 
  const unsigned char * id_bytes, unsigned int idLen, int kLen, unsigned char * output);

/**
 * 签名验签初始化
 * @param ctx SM2上下文
 * @param key 公钥PC||x||y或者yTile||x用于验签，私钥用于签名
 * @param kLen 公钥长度必须为33或65，私钥为32字节
 * @param id_bytes userid二进制串
 * @param idLen userid长度
 * @param forSign 1为签名，否则为验签
 * @return 1返回成功，否则为密钥非法
 */
int gm_sm2_sign_init(gm_sm2_context * ctx, const unsigned char * key, unsigned int kLen, 
  const unsigned char * id_bytes, unsigned int idLen, int forSign);

/**
 * 添加待签名验签数据
 * @param ctx SM2上下文
 * @param input 待处理数据
 * @param iLen 待处理数据长度
 */
void gm_sm2_sign_update(gm_sm2_context * ctx, const unsigned char * input, unsigned int iLen);

/**
 * 结束签名或验签
 * @param ctx SM2上下文
 * @param sig 如果是签名则作为输出缓冲区，如果是验签，则传入签名串用于验签
 * @return 1签名或验签成功，否则为失败
 */
int gm_sm2_sign_done(gm_sm2_context * ctx, unsigned char sig[64]);

int gm_sm2_sign_done_for_test(gm_sm2_context * ctx, unsigned char sig[64], const gm_bn_t testKey);

/**
 * 加解密初始化
 * @param ctx SM2上下文
 * @param key 公钥PC||x||y或者yTile||x用于加密，私钥用于解密
 * @param kLen 公钥长度必须为33或65，私钥为32字节
 * @param forEncryption 1为加密，否则为解密
 * @param c1 解密传入C1的值PC||x||y，加密时作为C1输出缓冲区
 * @return 1返回成功，否则为密钥非法
 */
int gm_sm2_crypt_init(gm_sm2_context * ctx, const unsigned char * key, unsigned int kLen, int forEncryption, unsigned char c1[65]);

/**
 * 加解密初始化，单元测试专用
 * @param ctx SM2上下文
 * @param key 公钥PC||x||y或者yTile||x用于加密，私钥用于解密
 * @param kLen 公钥长度必须为33或65，私钥为32字节
 * @param forEncryption 1为加密，否则为解密
 * @param c1 解密传入C1的值PC||x||y，加密时作为C1输出缓冲区
 * @param test_key 测试用密钥
 * @return 1返回成功，否则为密钥非法
 */
int gm_sm2_crypt_init_for_test(gm_sm2_context * ctx, const unsigned char * key, unsigned int kLen, 
	int forEncryption, unsigned char c1[65], const gm_bn_t test_key);

/**
 * 加解密添加数据
 * @param ctx SM2上下文
 * @param input 待处理数据
 * @param iLen 待处理数据长度
 * @param output 输出缓冲区，必须是32字节的倍数，要比iLen大
 * @return 返回已处理的数据长度
 */
int gm_sm2_crypt_update(gm_sm2_context * ctx, const unsigned char * input, unsigned int iLen, unsigned char * output);

/**
 * 结束加解密
 * @param ctx SM2上下文
 * @param output 输出缓冲区，必须是32字节的倍数，至少为32字节
 * @param c3 加解密都会输出C3，解密时，需要业务层再比较是否一致
 * @return 返回已处理的数据长度
 */
int gm_sm2_crypt_done(gm_sm2_context * ctx, unsigned char * output, unsigned char c3[32]);

/**
 * ZA计算，具体参照规范文档
 * @param id_bytes userid二进制串
 * @param idLen userid长度
 * @param pub_key 公钥
 * @param output 输出缓冲区
 */
void gm_sm2_compute_z_digest(const unsigned char * id_bytes, unsigned int idLen, const gm_point_t * pub_key,
                             unsigned char output[32]);

/**
 * 用于SM2签名验签时消息摘要的计算，output  = SM3(ZA||M)
 * @param input 待计算消息
 * @param iLen 消息长度
 * @param id_bytes userid二进制串
 * @param idLen userid长度
 * @param pub_key 公钥
 * @param output 输出缓冲区
 */
void gm_sm2_compute_msg_hash(const unsigned char * input, unsigned iLen,
                             const unsigned char * id_bytes, unsigned int idLen,
                             const gm_point_t * pub_key, unsigned char output[32]);

/**
 * 生成SM2密钥对
 * @param private_key 私钥输出缓冲区
 * @param public_key 公钥输出缓冲区
 */
void gm_sm2_gen_keypair(gm_bn_t private_key, gm_point_t * public_key);

# ifdef  __cplusplus
}
# endif

#endif //YISECUREBOXCPP_SM2_H
