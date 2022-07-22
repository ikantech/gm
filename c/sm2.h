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

//typedef struct {
//    gm_bn_t private_key;
//    gm_point_t public_key;
//}gm_sm2_context;
//
//void gm_sm2_init(gm_sm2_context * ctx);

/**
 * ZA计算，具体参照规范文档
 * @param id_bytes userid二进制串
 * @param idLen userid长度
 * @param pub_key 公钥
 * @param output 输出缓冲区
 */
void gm_sm2_compute_z_digest(const unsigned char * id_bytes, unsigned int idLen, const gm_point_t * pub_key,
                             unsigned char * output);

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
                             const gm_point_t * pub_key, unsigned char * output);

# ifdef  __cplusplus
}
# endif

#endif //YISECUREBOXCPP_SM2_H
