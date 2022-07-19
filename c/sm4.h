#ifndef YISECUREBOXCPP_SM4_H
#define YISECUREBOXCPP_SM4_H

#ifdef __cplusplus
extern "C" {
#endif

void gm_sm4_crypt(const unsigned char *key, int mode, const unsigned char *in, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif // YISECUREBOXCPP_SM4_H