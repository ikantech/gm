//
// Created by saint on 2023/7/30.
//
#include <gtest/gtest.h>
#include "sm4.h"

static void my_assert_eq(unsigned char * input, int iLen, const char * expected_str) {
    int i;
    char buf[128] = {0};
    for(i = 0; i < iLen; i++) {
        sprintf(buf + (i * 2), "%02x", input[i]);
    }
    ASSERT_EQ(strncmp(buf, expected_str, iLen * 2), 0);
}

// 与规范文档案例一致
TEST(SM4Test, ecb_once) {
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char buf[32] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    gm_sm4_context ctx;
    int rLen;

    // 加密
    gm_sm4_init(&ctx, key, 1, 0, NULL);
    rLen = gm_sm4_update(&ctx, buf, 16, buf);
    rLen += gm_sm4_done(&ctx, buf + rLen);

    ASSERT_EQ(rLen, 16);
    my_assert_eq(buf, rLen, "681edf34d206965e86b3e94f536e4246");

    // 解密
    gm_sm4_init(&ctx, key, 0, 0, NULL);
    rLen = gm_sm4_update(&ctx, buf, 16, buf);
    rLen += gm_sm4_done(&ctx, buf + rLen);

    ASSERT_EQ(rLen, 16);
    my_assert_eq(buf, rLen, "0123456789abcdeffedcba9876543210");
}

// 与规范文档案例一致
TEST(SM4Test, ecb_one_million) {
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char buf[32] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    gm_sm4_context ctx;
    int i;
    int rLen;

    // 加密
    for(i = 0; i < 1000000; i++) {
        gm_sm4_init(&ctx, key, 1, 0, NULL);
        rLen = gm_sm4_update(&ctx, buf, 16, buf);
        rLen += gm_sm4_done(&ctx, buf + rLen);
        ASSERT_EQ(rLen, 16);
    }

    my_assert_eq(buf, rLen, "595298c7c6fd271f0402f804c33d3f66");

    // 解密
    for(i = 0; i < 1000000; i++) {
        gm_sm4_init(&ctx, key, 0, 0, NULL);
        rLen = gm_sm4_update(&ctx, buf, 16, buf);
        rLen += gm_sm4_done(&ctx, buf + rLen);
        ASSERT_EQ(rLen, 16);
    }

    my_assert_eq(buf, rLen, "0123456789abcdeffedcba9876543210");
}

// 增加TestCase，覆盖输入是16的倍数后+1，原有程序出现段错误情况
/**
 * OPENSSL 获取预期结果，校验算法正确性
 * test.in文件中输入内容：12345678123456712345678123456781112345678123456781
 * 执行以下命令
 * openssl enc -e -sm4-ecb -K 0123456789abcdeffedcba9876543210 -in test.in -out test.out
 * 获取十六进制加密输出结果
 * xxd test.out
 */
TEST(SM4Test, ecb_pkcs7) {
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char plain[24] = {
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };
    unsigned char buf[72] = {0};
    gm_sm4_context ctx;
    int rLen;

    // 加密

    gm_sm4_init(&ctx, key, 1, 1, NULL);
    // 测试输入小于16
    rLen = gm_sm4_update(&ctx, plain, 15, buf);
    ASSERT_EQ(rLen, 0);
    // 测试输入等于16
    rLen += gm_sm4_update(&ctx, plain, 16, buf + rLen);
    ASSERT_EQ(rLen, 16);
    // +1，使其正好是16的倍数，但由于需要留一轮到最后，所以已加密长度应该还是16
    rLen += gm_sm4_update(&ctx, plain, 1, buf + rLen);
    ASSERT_EQ(rLen, 16);
    // +1，使待加密长度为17，应该马上加密一轮，已加密长度应该是32
    rLen += gm_sm4_update(&ctx, plain, 1, buf + rLen);
    ASSERT_EQ(rLen, 32);
    // 测试输入大于16
    rLen += gm_sm4_update(&ctx, plain, 17, buf + rLen);
    ASSERT_EQ(rLen, 48);

    rLen += gm_sm4_done(&ctx, buf + rLen);
    ASSERT_EQ(rLen, 64);

    my_assert_eq(buf, rLen, "09c762eb90cea3e139f23424d16719bf6de42b13d9be636469f544b099187fe073097af93b02088ec511310c8bd3260f002f5ba70b206339abd9f3b66d82c4a5");

    // 解密
    gm_sm4_init(&ctx, key, 0, 1, NULL);
    rLen = gm_sm4_update(&ctx, buf, 64, buf);
    rLen += gm_sm4_done(&ctx, buf + rLen);

    ASSERT_EQ(rLen, 50);
    my_assert_eq(buf, rLen, "3132333435363738313233343536373132333435363738313233343536373831313132333435363738313233343536373831");
}

// 测试非法输入
TEST(SM4Test, ecb_illegal_input) {
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char buf[32] = {0};
    gm_sm4_context ctx;
    int rLen, retCodeOrRLen;

    // 加密
    gm_sm4_init(&ctx, key, 1, 0, NULL);
    rLen = gm_sm4_update(&ctx, key, 5, buf);
    retCodeOrRLen = gm_sm4_done(&ctx, buf + rLen);

    ASSERT_EQ(retCodeOrRLen, -1);
}

// 测试非法填充
TEST(SM4Test, ecb_illegal_pad) {
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    // 填充0的情况
    unsigned char plain_one[16] = {
            0x89, 0x80, 0x87, 0xcd, 0x14, 0x75, 0x07, 0x75,
            0x75, 0x8f, 0xe8, 0x1f, 0x87, 0x2a, 0x92, 0x6a
    };
    // 填充17(十六进制0x11)的情况
    unsigned char plain_two[16] = {
            0xd1, 0xfc, 0x90, 0x64, 0x71, 0xa3, 0x08, 0xc1,
            0x45, 0x10, 0x51, 0xc8, 0x58, 0x53, 0x9f, 0x30
    };
    unsigned char buf[32] = {};
    gm_sm4_context ctx;
    int rLen, retCode;

    // 解密1
    gm_sm4_init(&ctx, key, 0, 1, NULL);
    rLen = gm_sm4_update(&ctx, plain_one, 16, buf);
    retCode = gm_sm4_done(&ctx, buf + rLen);

    ASSERT_EQ(retCode, -1);
    // 此时解密已经是失败了，这一步的断言其实没啥意义，仅测试明文是不是填充的0
    my_assert_eq(buf, 16, "01234567890000000000000000000000");

    // 解密2
    gm_sm4_init(&ctx, key, 0, 1, NULL);
    rLen = gm_sm4_update(&ctx, plain_two, 16, buf);
    retCode = gm_sm4_done(&ctx, buf + rLen);

    ASSERT_EQ(retCode, -1);
    // 此时解密已经是失败了，这一步的断言其实没啥意义，仅测试明文是不是填充的十进制17，十六进制则是0x11
    my_assert_eq(buf, 16, "01234567891111111111111111111111");
}

// 测试CBC
/**
 * OPENSSL 获取预期结果，校验算法正确性
 * test.in文件中输入内容：12345
 * 执行以下命令
 * openssl enc -e -sm4-cbc -K 0123456789abcdeffedcba9876543210 -iv 0123456789abcdeffedcba9876543210 -in test.in -out test.out
 * 获取十六进制加密输出结果
 * xxd test.out
 */
TEST(SM4Test, cbc) {
    unsigned char key[16] = {
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    unsigned char buf[32] = {
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };
    gm_sm4_context ctx;
    int rLen, retCodeOrRLen;

    // 加密
    gm_sm4_init(&ctx, key, 1, 1, key);
    rLen = gm_sm4_update(&ctx, buf, 5, buf);
    rLen += gm_sm4_done(&ctx, buf + rLen);

    ASSERT_EQ(rLen, 16);
    my_assert_eq(buf, rLen, "53638b349cba7e711dfdd1401fb125fb");

    // 解密
    gm_sm4_init(&ctx, key, 0, 1, key);
    rLen = gm_sm4_update(&ctx, buf, 16, buf);
    rLen += gm_sm4_done(&ctx, buf + rLen);

    ASSERT_EQ(rLen, 5);
    my_assert_eq(buf, rLen, "3132333435");
}