//
// Created by saint on 2021/12/9.
//

#ifndef YISECUREBOXCPP_SM3_H
#define YISECUREBOXCPP_SM3_H

#include <stdint.h>

# ifdef  __cplusplus
extern "C" {
# endif

typedef struct {
    unsigned int state[8]; // 寄存器中间状态
    unsigned char buf[64]; // 待压缩消息
    uint64_t cur_buf_len; // 当前待压缩消息长度（字节）
    uint64_t compressed_len; // 已压缩消息长度（比特）
} gm_sm3_context;

/**
 * 摘要算法初始化
 * @param ctx 上下文
 */
void gm_sm3_init(gm_sm3_context * ctx);

/**
 * 添加消息
 * @param ctx 上下文
 * @param input 消息
 * @param iLen 消息长度（字节）
 */
void gm_sm3_update(gm_sm3_context * ctx, const unsigned char * input, unsigned int iLen);

/**
 * 计算摘要
 * @param ctx 上下文
 * @param output 输出摘要结果
 */
void gm_sm3_done(gm_sm3_context * ctx, unsigned char output[32]);

/**
 * 重置上下文，以达到复用此上下文的目的
 * @param ctx 上下文
 */
inline void gm_sm3_reset(gm_sm3_context * ctx) {
    gm_sm3_init(ctx);
}

/**
 * 直接计算消息的摘要
 * @param input 消息
 * @param iLen 消息长度（字节）
 * @param output 输出摘要结果
 */
void gm_sm3(const unsigned char * input, unsigned int iLen, unsigned char output[32]);

# ifdef  __cplusplus
}
# endif

#endif //YISECUREBOXCPP_SM3_H
