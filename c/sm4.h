#ifndef YISECUREBOXCPP_SM4_H
#define YISECUREBOXCPP_SM4_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned int rk[32];           // 轮密钥
	unsigned char buf[16];         // 待加密数据
	unsigned char iv[16];          // CBC IV向量
	unsigned int cur_buf_len;      // 当前待压缩消息长度（字节）
	unsigned int total_len;        // 已加密数据长度（字节）
	unsigned int state;            // 0比特标识是否为加密，1比特标识是否为PKCS7填充，2比特标识是否为CBC加密
} gm_sm4_context;

/**
 * sm4加解密算法，此为ECB/NoPadding，且只能处理一轮，勿用
 * 使用init、update(可多次调用)、done三步来代替
 * @param key sm4 密钥
 * @param forEncryption 1为加密，否则为解密
 * @param in 待计算数据, 16字节
 * @param out 输出缓冲区, 16字节
 */
void gm_sm4_crypt(const unsigned char key[16], int forEncryption, const unsigned char in[16], unsigned char out[16]);

/**
 * 初始化sm4算法
 * @param ctx sm4 上下文
 * @param key sm4 密钥
 * @param forEncryption 1为加密，否则为解密
 * @param pkcs7Padding 1为pkcs7填充，否则为不填充
 * @param iv 16字节向量，NULL表示ECB加密，非NULL表示CBC加密
 */
void gm_sm4_init(gm_sm4_context * ctx, const unsigned char key[16], 
	int forEncryption, int pkcs7Padding, const unsigned char iv[16]);

/**
 * 添加待加解密数据，sm4每16字节为一组
 * 此方法每满16字节就会立刻加解密这16字节，所以返回值用来表示已加解密数据的长度
 * @param ctx sm4 上下文
 * @param input 待计算数据
 * @param iLen 待计算数据长度
 * @param output 输出缓冲区，长度 >= ((iLen + 15) / 16) * 16
 * @return 已加解密的数据长度，通常为16的倍数
 */
int gm_sm4_update(gm_sm4_context * ctx, const unsigned char * input, unsigned int iLen, unsigned char * output);

/**
 * 结束加解密计算
 *
 * gm_sm4_update每次都会留一轮放到gm_sm4_done来处理
 * 避免处理文件时，有Padding的情况，如果解密内容已经写到明文文件中，
 * 结果算法告诉你里面有Padding是要去掉的，那不好处理已写的文件，
 * 所以留一轮到最后，不管有没有Padding，算法输出给你结果，无脑写文件就行
 *
 * @param ctx sm4 上下文
 * @param output 输出缓冲区，长度 >= 16字节
 * @return 已加解密的数据长度，通常为16的倍数，-1表示加解失败
 */
int gm_sm4_done(gm_sm4_context * ctx, unsigned char * output);

#ifdef __cplusplus
}
#endif

#endif // YISECUREBOXCPP_SM4_H