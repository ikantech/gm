//
// Created by saint on 2022/1/11.
//

#include "sm2.h"

// SM2 a
static const unsigned char GM_ECC_A[] = {
        0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC
};

// SM2 b
static const unsigned char GM_ECC_B[] = {
        0x28, 0xE9, 0xFA, 0x9E, 0x9D, 0x9F, 0x5E, 0x34,
        0x4D, 0x5A, 0x9E, 0x4B, 0xCF, 0x65, 0x09, 0xA7,
        0xF3, 0x97, 0x89, 0xF5, 0x15, 0xAB, 0x8F, 0x92,
        0xDD, 0xBC, 0xBD, 0x41, 0x4D, 0x94, 0x0E, 0x93
};

// SM2 Gx
static const unsigned char GM_ECC_G_X[] = {
        0x32, 0xC4, 0xAE, 0x2C, 0x1F, 0x19, 0x81, 0x19,
        0x5F, 0x99, 0x04, 0x46, 0x6A, 0x39, 0xC9, 0x94,
        0x8F, 0xE3, 0x0B, 0xBF, 0xF2, 0x66, 0x0B, 0xE1,
        0x71, 0x5A, 0x45, 0x89, 0x33, 0x4C, 0x74, 0xC7
};

// SM2 Gy
static const unsigned char GM_ECC_G_Y[] = {
        0xBC, 0x37, 0x36, 0xA2, 0xF4, 0xF6, 0x77, 0x9C,
        0x59, 0xBD, 0xCE, 0xE3, 0x6B, 0x69, 0x21, 0x53,
        0xD0, 0xA9, 0x87, 0x7C, 0xC6, 0x2A, 0x47, 0x40,
        0x02, 0xDF, 0x32, 0xE5, 0x21, 0x39, 0xF0, 0xA0
};

//void gm_sm2_init(gm_sm2_context * ctx) {
//    gm_bn_set_zero(ctx->private_key);
//    gm_point_init(&ctx->public_key)
//}

/**
 * ZA计算，具体参照规范文档
 * @param id_bytes userid二进制串
 * @param idLen userid长度
 * @param pub_key 公钥
 * @param output 输出缓冲区
 */
void gm_sm2_compute_z_digest(const unsigned char * id_bytes, unsigned int idLen, const gm_point_t * pub_key,
        unsigned char * output) {
    gm_sm3_context _ctx;
    gm_sm3_context * ctx = &_ctx;
    gm_bn_t x, y;

    gm_sm3_init(ctx);

    // update idlen，这里的idlen是比特长度，所以移位注意一下
    ctx->buf[0] = ((idLen >> 5) & 0x0FF);
    ctx->buf[1] = ((idLen << 3) & 0x0FF);
    ctx->cur_buf_len = 2;

    // update id
    gm_sm3_update(ctx, id_bytes, idLen);

    // update a
    gm_sm3_update(ctx, GM_ECC_A, 32);

    // update b
    gm_sm3_update(ctx, GM_ECC_B, 32);

    // update Gx
    gm_sm3_update(ctx, GM_ECC_G_X, 32);

    // update Gy
    gm_sm3_update(ctx, GM_ECC_G_Y, 32);

    gm_point_get_xy(pub_key, x, y);

    // update Px
    gm_bn_to_bytes(x, output); // 借用output当缓冲区
    gm_sm3_update(ctx, output, 32);

    // update Py
    gm_bn_to_bytes(y, output); // 借用output当缓冲区
    gm_sm3_update(ctx, output, 32);

    gm_sm3_done(ctx, output);
}

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
        const gm_point_t * pub_key, unsigned char * output) {
    gm_sm3_context _ctx;
    gm_sm3_context * ctx = &_ctx;

    gm_sm3_init(ctx);

    // compute z digest
    gm_sm2_compute_z_digest(id_bytes, idLen, pub_key, output);
    gm_sm3_update(ctx, output, 32);

    gm_sm3_update(ctx, input, iLen);

    gm_sm3_done(ctx, output);
}