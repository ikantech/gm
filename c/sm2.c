//
// Created by saint on 2022/1/11.
//

#include "sm2.h"
#include "randombytes.h"

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

// SM2 N-1
static const gm_bn_t GM_BN_N_SUB_ONE = {
        0x39D54122, 0x53BBF409, 0x21C6052B, 0x7203DF6B,
        0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE
};

static const gm_bn_t GM_BN_2W = {
    0x00000000, 0x00000000, 0x00000000, 0x80000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000
};

static const gm_bn_t GM_BN_2W_SUB_ONE = {
    0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF,
    0x00000000, 0x00000000, 0x00000000, 0x00000000
};

// 字转化为字节
#ifndef GM_PUT_UINT32_BE
#define GM_PUT_UINT32_BE(n, b ,i)                       \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/**
 * ZA计算，具体参照规范文档
 * @param id_bytes userid二进制串
 * @param idLen userid长度
 * @param pub_key 公钥
 * @param output 输出缓冲区
 */
void gm_sm2_compute_z_digest(const unsigned char * id_bytes, unsigned int idLen, const gm_point_t * pub_key,
        unsigned char output[32]) {
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
        const gm_point_t * pub_key, unsigned char output[32]) {
    gm_sm3_context _ctx;
    gm_sm3_context * ctx = &_ctx;

    gm_sm3_init(ctx);

    // compute z digest
    gm_sm2_compute_z_digest(id_bytes, idLen, pub_key, output);
    gm_sm3_update(ctx, output, 32);

    gm_sm3_update(ctx, input, iLen);

    gm_sm3_done(ctx, output);
}

/**
 * 检查公钥是否合法
 * @param pub_key 公钥
 * @return 1合法，否则非法
 */
static int gm_sm2_check_public_key(const gm_point_t * pub_key) {
    if(gm_is_at_infinity(pub_key)) {
        return 0;
    }
    gm_bn_t x, y, r;
    gm_point_get_xy(pub_key, x, y);

    if(gm_bn_is_zero(x) || gm_bn_cmp(x, GM_BN_P) >= 0) {
        return 0;
    }

    if(gm_bn_is_zero(y) || gm_bn_cmp(y, GM_BN_P) >= 0) {
        return 0;
    }

    //y^2 = x^3 + ax + b
    gm_bn_to_mont(x, x, GM_BN_P);
    gm_bn_to_mont(y, y, GM_BN_P);

    // r = x ^ 2
    gm_bn_sqr(r, x, GM_BN_P);

    // r = x^2 + a
    gm_bn_add(r, r, GM_BN_MONT_A, GM_BN_P);

    // r = x^3 + ax
    gm_bn_mont_mul(r, r, x, GM_BN_P);

    // r = x^3 + ax + b
    gm_bn_add(r, r, GM_BN_MONT_B, GM_BN_P);

    gm_bn_sqr(y, y, GM_BN_P);

    if(gm_bn_cmp(r, y) != 0) {
        return 0;
    }

    return 1;
}

/**
 * 恢复私钥
 * @param ctx SM2上下文
 * @param key 私钥
 * @param kLen 长度必须为32
 */
static int recover_private_key(gm_sm2_context * ctx, const unsigned char * key, unsigned int kLen) {
    if(kLen != 32) {
        return 0;
    }
    gm_bn_from_bytes(ctx->private_key, key);
    // check k ∈ [1, n-2]
    if(gm_bn_is_zero(ctx->private_key) || gm_bn_cmp(ctx->private_key, GM_BN_N_SUB_ONE) >= 0) {
        return 0;
    }
    // check public key
    gm_point_mul(&ctx->public_key, ctx->private_key, GM_MONT_G);
    if(gm_sm2_check_public_key(&ctx->public_key) != 1) {
        return 0;
    }
    return 1;
}

/**
 * 恢复公钥
 * @param ctx SM2上下文
 * @param key 公钥PC||x||y或者yTile||x
 * @param kLen 公钥长度必须为33或65
 */
static int recover_public_key(gm_sm2_context * ctx, const unsigned char * key, unsigned int kLen) {
    if((kLen != 33 && kLen != 65) || (key[0] != 0x04 && key[0] != 0x02 && key[0] != 0x03)) {
            return 0;
    }
    // check public key
    gm_point_decode(&ctx->public_key, key);
    if(gm_sm2_check_public_key(&ctx->public_key) != 1) {
        return 0;
    }
    return 1;
}

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
  const unsigned char * id_bytes, unsigned int idLen, int forSign) {
    if(forSign) {
        // 私钥签名
        if(recover_private_key(ctx, key, kLen) == 0) {
            return 0;
        }
    }else {
        // 公钥验签
        if(recover_public_key(ctx, key, kLen) == 0) {
            return 0;
        }
    }
    // compute z digest
    gm_sm2_compute_z_digest(id_bytes, idLen, &ctx->public_key, ctx->buf);
    gm_sm3_init(&ctx->sm3_ctx);
    gm_sm3_update(&ctx->sm3_ctx, ctx->buf, 32);
    ctx->state = forSign;

    return 1;
}

/**
 * 添加待签名验签数据
 * @param ctx SM2上下文
 * @param input 待处理数据
 * @param iLen 待处理数据长度
 */
void gm_sm2_sign_update(gm_sm2_context * ctx, const unsigned char * input, unsigned int iLen) {
    gm_sm3_update(&ctx->sm3_ctx, input, iLen);
}

/**
 * 结束签名或验签
 * @param ctx SM2上下文
 * @param sig 如果是签名则作为输出缓冲区，如果是验签，则传入签名串用于验签
 * @return 1签名或验签成功，否则为失败
 */
int gm_sm2_sign_done(gm_sm2_context * ctx, unsigned char sig[64]) {
    return gm_sm2_sign_done_for_test(ctx, sig, NULL);
}

int gm_sm2_sign_done_for_test(gm_sm2_context * ctx, unsigned char sig[64], const gm_bn_t testKey) {
    gm_bn_t dgst;

    gm_sm3_done(&ctx->sm3_ctx, ctx->buf);

    gm_bn_from_bytes(dgst, ctx->buf);

    if(ctx->state) {
        // forSign
        return gm_do_sign_for_test(ctx->private_key, dgst, sig, testKey);
    }else {
        return gm_do_verify(&ctx->public_key, dgst, sig);
    }
}

/**
 * 加解密初始化
 * @param ctx SM2上下文
 * @param key 公钥PC||x||y或者yTile||x用于加密，私钥用于解密
 * @param kLen 公钥长度必须为33或65，私钥为32字节
 * @param forEncryption 1为加密，否则为解密
 * @return 1返回成功，否则为密钥非法
 */
int gm_sm2_crypt_init(gm_sm2_context * ctx, const unsigned char * key, unsigned int kLen, int forEncryption, unsigned char c1[65]) {
    gm_bn_t k;
    uint8_t buf[256] = {0};
    if(forEncryption) {
        // rand k in [1, n - 1]
        do {
            do {
                randombytes(buf, 256);
#ifdef GM_RAND_SM3
                gm_sm3(buf, 256, buf);
#endif
                gm_bn_from_bytes(k, buf);
            } while (gm_bn_cmp(k, GM_BN_N) >= 0);
        } while (gm_bn_is_zero(k));
    }
    return gm_sm2_crypt_init_for_test(ctx, key, kLen, forEncryption, c1, k);
}

int gm_sm2_crypt_init_for_test(gm_sm2_context * ctx, const unsigned char * key, unsigned int kLen, 
    int forEncryption, unsigned char c1[65], const gm_bn_t test_key) {
    gm_point_t p;

    if(forEncryption) {
        if(recover_public_key(ctx, key, kLen) == 0) {
            return 0;
        }

        gm_point_mul(&p, test_key, GM_MONT_G);
        gm_point_to_bytes(&p, c1 + 1);
        c1[0] = 0x04;

        gm_point_mul(&p, test_key, &ctx->public_key);
        gm_point_to_bytes(&p, ctx->x2y2);
    }else {
        if(recover_private_key(ctx, key, kLen) == 0) {
            return 0;
        }

        if(c1[0] == 0x04) {
            gm_point_from_bytes(&p, c1 + 1);
        }else {
            gm_point_from_bytes(&p, c1);
        }
        gm_point_mul(&p, ctx->private_key, &p);
        gm_point_to_bytes(&p, ctx->x2y2);
    }
    ctx->state = forEncryption;
    ctx->cur_buf_len = 0;
    ctx->ct = 1;
    gm_sm3_init(&ctx->sm3_ctx);
    gm_sm3_update(&ctx->sm3_ctx, ctx->x2y2, 32);
    return 1;
}

/**
 * 加解密一轮
 * @param ctx SM2上下文
 * @param output 输出缓冲区
 * @param len 本轮待处理数据长度
 */
static void crypt_update_one_round(gm_sm2_context * ctx, unsigned char * output, int len) {
    int i;

    // KDF
    gm_sm3_context sm3_ctx;
    gm_sm3_init(&sm3_ctx);
    gm_sm3_update(&sm3_ctx, ctx->x2y2, 64);

    GM_PUT_UINT32_BE(ctx->ct, output, 0);
    gm_sm3_update(&sm3_ctx, output, 4);
    gm_sm3_done(&sm3_ctx, output);

    for(i = 0; i < len; i++) {
        output[i] ^= ctx->buf[i];
    }

    if(ctx->state) {
        // 加密
        gm_sm3_update(&ctx->sm3_ctx, ctx->buf, len);
    }else {
        // 解密
        gm_sm3_update(&ctx->sm3_ctx, output, len);
    }

    ctx->cur_buf_len = 0;
    ctx->ct++;
}

/**
 * 加解密添加数据
 * @param ctx SM2上下文
 * @param input 待处理数据
 * @param iLen 待处理数据长度
 * @param output 输出缓冲区，必须是32字节的倍数，要比iLen大
 * @return 返回已处理的数据长度
 */
int gm_sm2_crypt_update(gm_sm2_context * ctx, const unsigned char * input, unsigned int iLen, unsigned char * output) {
    int rLen = 0;

    while(iLen--) {
        ctx->buf[ctx->cur_buf_len++] = *input++;

        // 是否满一轮
        if(ctx->cur_buf_len == 32) {
            crypt_update_one_round(ctx, output + rLen, 32);
            rLen += 32;
        }
    }


    return rLen;
}

/**
 * 结束加解密
 * @param ctx SM2上下文
 * @param output 输出缓冲区，必须是32字节的倍数，至少为32字节
 * @param c3 加解密都会输出C3，解密时，需要业务层再比较是否一致
 * @return 返回已处理的数据长度
 */
int gm_sm2_crypt_done(gm_sm2_context * ctx, unsigned char * output, unsigned char c3[32]) {
    int rLen = ctx->cur_buf_len;
    crypt_update_one_round(ctx, output, rLen);

    gm_sm3_update(&ctx->sm3_ctx, ctx->x2y2 + 32, 32);
    gm_sm3_done(&ctx->sm3_ctx, c3);
    return rLen;
}

/**
 * 生成SM2密钥对
 * @param private_key 私钥输出缓冲区
 * @param public_key 公钥输出缓冲区
 */
void gm_sm2_gen_keypair(gm_bn_t private_key, gm_point_t * public_key) {
    unsigned char buf[256];
    do {
        // rand private_key in [1, n - 2]
        do {
            do {
                randombytes(buf, 256);
    #ifdef GM_RAND_SM3
                gm_sm3(buf, 256, buf);
    #endif
                gm_bn_from_bytes(private_key, buf);
            } while (gm_bn_cmp(private_key, GM_BN_N_SUB_ONE) >= 0);
        } while (gm_bn_is_zero(private_key));

        // 从私钥中计算公钥
        gm_point_mul(public_key, private_key, GM_MONT_G);

        // check public key
    } while(gm_sm2_check_public_key(public_key) != 1);
}

// 2^w + ( x & ( 2^w − 1 ) )
static void gm_sm2_exch_reduce(gm_bn_t x) {
    int i;
    int num = GM_BN_ARR_SIZE / 2;
    for(i = 0; i < GM_BN_ARR_SIZE; i++) {
        if(i < num) {
            x[i] &= GM_BN_2W_SUB_ONE[i];
            x[i] += GM_BN_2W[i];
        }else {
            x[i] = 0;
        }
    }
}

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
  unsigned char isInitiator, const unsigned char * id_bytes, unsigned int idLen, unsigned char output[64]) {
    gm_bn_t r;
    gm_point_t pr;

    // 生成临时密钥对
    gm_sm2_gen_keypair(r, &pr);

    gm_sm2_exch_init_for_test(ctx, private_key, public_key, r, &pr, isInitiator, id_bytes, idLen, output);
}

void gm_sm2_exch_init_for_test(gm_sm2_exch_context * ctx, gm_bn_t private_key, const gm_point_t * public_key, 
  gm_bn_t tmp_private_key, const gm_point_t * tmp_public_key, 
  unsigned char isInitiator, const unsigned char * id_bytes, unsigned int idLen, unsigned char output[64]) {
    gm_bn_t r, x, y;
    gm_point_t pr;

    gm_bn_copy(r, tmp_private_key);
    gm_point_copy(&pr, tmp_public_key);

    gm_point_get_xy(&pr, x, y);

    // 2^w + ( x & ( 2^w − 1 ) )
    gm_sm2_exch_reduce(x);

    // t = (d + x · r) mod n
    gm_bn_to_mont(x, x, GM_BN_N);
    gm_bn_to_mont(r, r, GM_BN_N);
    // x * r
    gm_bn_mont_mul(r, r, x, GM_BN_N);
    // d + x * r
    gm_bn_from_mont(r, r, GM_BN_N);
    gm_bn_add(ctx->t, r, private_key, GM_BN_N);

    // compute z digest
    gm_sm2_compute_z_digest(id_bytes, idLen, public_key, ctx->z);

    ctx->isInitiator = isInitiator;
    gm_point_to_bytes(&pr, ctx->xy);

    // output R
    memcpy(output, ctx->xy, 64);
}

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
  const unsigned char * id_bytes, unsigned int idLen, int kLen, unsigned char * output) {
    unsigned char buf[100] = {0};
    unsigned char peerZ[32] = {0};
    int i, ki, kn, ct;
    
    gm_bn_t peerTmpX;
    gm_point_t peerPubK, peerTmpPubK;
    gm_sm3_context sm3_ctx;

    gm_bn_from_bytes(peerTmpX, peer_r);
    gm_point_from_bytes(&peerPubK, peer_p);
    gm_point_from_bytes(&peerTmpPubK, peer_r);

    // compute peer z digest
    gm_sm2_compute_z_digest(id_bytes, idLen, &peerPubK, peerZ);

    // 2^w + ( peerTmpX & ( 2^w − 1 ) )
    gm_sm2_exch_reduce(peerTmpX);

    // U = t * (peerPubK + peerTmpX · peerTmpPubK)
    gm_point_mul(&peerTmpPubK, peerTmpX, &peerTmpPubK);
    gm_point_add(&peerPubK, &peerPubK, &peerTmpPubK);

    
    gm_point_mul(&peerPubK, ctx->t, &peerPubK);
    gm_point_to_bytes(&peerPubK, buf);

    // KDF(x_u || y_u || Z_A || Z_B)
    kn = (kLen + 31) / 32;
    ki = 0;
    for(i = 0, ct = 1; i < kn; i++, ct++) {
        
        gm_sm3_init(&sm3_ctx);
        gm_sm3_update(&sm3_ctx, buf, 64);

        if(ctx->isInitiator) {
            gm_sm3_update(&sm3_ctx, ctx->z, 32);
            gm_sm3_update(&sm3_ctx, peerZ, 32);
        }else {
            gm_sm3_update(&sm3_ctx, peerZ, 32);
            gm_sm3_update(&sm3_ctx, ctx->z, 32);
        }

        GM_PUT_UINT32_BE(ct, buf + 64, 0);
        gm_sm3_update(&sm3_ctx, buf + 64, 4);
        gm_sm3_done(&sm3_ctx, buf + 68);

        // output kA or kB
        if(i == (kn - 1)) {
            memcpy(output + ki, buf + 68, (kLen - ki));
        }else {
            memcpy(output + ki, buf + 68, 32);
            ki += 32;
        }
    }

    // Hash(0x02 || y_u || Hash(x_u || Z_A || Z_B || x_1 || y_1 || x_2 || y_2))
    gm_sm3_init(&sm3_ctx);
    gm_sm3_update(&sm3_ctx, buf, 32);
    if(ctx->isInitiator) {
        gm_sm3_update(&sm3_ctx, ctx->z, 32);
        gm_sm3_update(&sm3_ctx, peerZ, 32);
        gm_sm3_update(&sm3_ctx, ctx->xy, 64);
        gm_sm3_update(&sm3_ctx, peer_r, 64);
    }else {
        gm_sm3_update(&sm3_ctx, peerZ, 32);
        gm_sm3_update(&sm3_ctx, ctx->z, 32);
        gm_sm3_update(&sm3_ctx, peer_r, 64);
        gm_sm3_update(&sm3_ctx, ctx->xy, 64);
    }
    gm_sm3_done(&sm3_ctx, buf + 68);

    gm_sm3_init(&sm3_ctx);
    buf[31] = 0x02;
    gm_sm3_update(&sm3_ctx, buf + 31, 33);
    gm_sm3_update(&sm3_ctx, buf + 68, 32);

    // ouput s1 or sB
    gm_sm3_done(&sm3_ctx, output + kLen);

    // Hash(0x03 || y_u || Hash(x_u || Z_A || Z_B || x_1 || y_1 || x_2 || y_2))
    gm_sm3_init(&sm3_ctx);
    buf[31] = 0x03;
    gm_sm3_update(&sm3_ctx, buf + 31, 33);
    gm_sm3_update(&sm3_ctx, buf + 68, 32);

    // ouput s2 or sA
    gm_sm3_done(&sm3_ctx, output + kLen + 32);
}