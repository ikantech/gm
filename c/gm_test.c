#include "gm.h"
#include "sm3.h"
#include "sm2.h"
#include "sm4.h"
#include <stdio.h>

#define TEST_BN_ALG(alg_name, a, b, r) \
    do { \
        if(strncmp(argv[1], alg_name, strlen(alg_name)) == 0) { \
            test_bn(a, b, r, alg_name); \
        } \
    }while(0)

#define TEST_EC_ALG(alg_name, a, b, r) \
    do { \
        if(strncmp(argv[1], alg_name, strlen(alg_name)) == 0) { \
            test_ec(a, b, r, alg_name); \
        } \
    }while(0)

/**
 * 大数单元测试
 * @param a 大数a
 * @param b 大数b
 * @param res 预期结果
 * @param ralg 测试的指令add、sub、mul等
 */
void test_bn(const char * a, const char * b, const char * res, const char * ralg) {
    int i, j;
    gm_bn_t bna, bnb, bnr;
    char bnr_hex[65] = {0};
    const uint64_t * m;
    const char * alg = ralg + 4;

    if(gm_bn_from_hex(bna, a) < 0) {
        printf("convert a to bn failed.\n");
    }

    if(gm_bn_from_hex(bnb, b) < 0) {
        printf("convert b to bn failed.\n");
    }

    if(strncmp(ralg, "gmp", 3) == 0) {
        m = GM_BN_P;
    }else {
        m = GM_BN_N;
    }

    if(strcmp(alg, "to_mont") == 0) {
        gm_bn_to_mont(bnr, bna, m);
    }else if(strcmp(alg, "from_mont") == 0) {
        gm_bn_from_mont(bnr, bna, m);
    }else if(strcmp(alg, "mod_t") == 0) {
        uint64_t t = 1;
        for(i = 1; i < 64; i++) {
            t = t * t;
            t = t * (m[0] | m[1] << 32);
        }
        t = 0xFFFFFFFFFFFFFFFF - t + 1;
        gm_bn_copy(bnr, bnb);
        bnr[0] = t & 0x0FFFFFFFFULL;
        bnr[1] = t >> 32;
    }else if(strcmp(alg, "add") == 0) { // 2亿
        gm_bn_copy(bnr, bna);
        for (i = 0; i < 200000000; i++) {
            gm_bn_add(bnr, bnr, bnb, m);
        }
    }else if(strcmp(alg, "sub") == 0) { // 2亿
        gm_bn_copy(bnr, bna);
        for (i = 0; i < 200000000; i++) {
            gm_bn_sub(bnr, bnr, bnb, m);
        }
    }else if(strcmp(alg, "mul") == 0){ // 1千万
        gm_bn_to_mont(bnr, bna, m);
        gm_bn_to_mont(bnb, bnb, m);
        for (i = 0; i < 10000000; i++) {
            gm_bn_mont_mul(bnr, bnr, bnb, m);
        }
        gm_bn_from_mont(bnr, bnr, m);
    }else if(strcmp(alg, "sqr") == 0){ // 1千万
        gm_bn_to_mont(bnr, bna, m);
        for (i = 0; i < 10000000; i++) {
            gm_bn_sqr(bnr, bnr, m);
        }
        gm_bn_from_mont(bnr, bnr, m);
    }else if(strcmp(alg, "exp") == 0){ // 1万
        gm_bn_to_mont(bnr, bna, m);
        for (i = 0; i < 10000; i++) {
            gm_bn_exp(bnr, bnr, bnb, m);
        }
        gm_bn_from_mont(bnr, bnr, m);
    }else if(strcmp(alg, "inv") == 0){ // 1万
        gm_bn_to_mont(bnr, bna, m);
        for (i = 0; i < 10000; i++) {
            gm_bn_inv(bnr, bnr, m);
            gm_bn_from_mont(bnr, bnr, m);
            for(j = 0; j < 8; j++) {
                bnr[j] = bnr[j] ^ bnb[j];
            }
            gm_bn_to_mont(bnr, bnr, m);
        }
        gm_bn_from_mont(bnr, bnr, m);
    }

    gm_bn_to_hex(bnr, bnr_hex);

    printf("r = %s\n", bnr_hex);
    printf("test result: %s\n", (strcmp(res, bnr_hex) == 0 ? "ok" : "fail"));
}

/**
 * 点单元测试
 * @param pa 点a
 * @param pb 点b
 * @param res 预期结果
 * @param alg 测试算法dbl、add、mul等
 */
void test_ec(const char * pa, const char * pb, const char * res, const char * alg) {
    int i, j;
    gm_point_t p1, p2, r;
    char e_r_hex[129] = {0};
    gm_bn_t k;

    gm_point_from_hex(&p1, pa);
    gm_point_from_hex(&p2, pb);
    gm_point_from_hex(&r, pa);

    if(strcmp(alg, "point_dbl") == 0){ // 10万
        int i = 0;
        for (i = 0; i < 100000; i++) {
            gm_point_double(&r, &r);
        }
    }else if(strcmp(alg, "point_add") == 0){ // 10万
        int i = 0;
        for (i = 0; i < 100000; i++) {
            gm_point_add(&r, &r, &p2);
        }
    }else if(strcmp(alg, "point_mul") == 0){ // 1千
        gm_point_get_xy(&p2, k, NULL);
        for (i = 0; i < 1000; i++) {
            gm_point_mul(&r, k, &r);
        }
    }

    gm_point_to_hex(&r, e_r_hex);

    printf("r = %s\n", e_r_hex);
    printf("test result: %s\n", (strcmp(res, e_r_hex) == 0 ? "ok" : "fail"));
}

/**
 * 国密SM2单元测试
 * @param key_hex 私钥十六进制
 * @param pubKey_hex 公钥十六进制
 * @param sig_hex 预期结果十六进制
 * @param dgst_bytes 消息摘要二进制
 * @param algType 算法，0签名及验签，1仅签名，2仅验签
 */
void test_gm_sv(const char * key_hex, const char * pubKey_hex, const char * sig_hex,
        const unsigned char * dgst_bytes,
        int algType) {
    unsigned char sig_res[256] = {0};
    gm_bn_t testK;
    gm_bn_t key;
    gm_bn_t dgst;
    gm_point_t _P, *P = &_P;
    int i, j;

    gm_bn_from_hex(testK, key_hex);
    if(dgst_bytes == NULL) {
        gm_bn_from_hex(dgst, key_hex);
    }else {
        gm_bn_from_bytes(dgst, dgst_bytes);
    }
    gm_bn_from_hex(key, key_hex);
    gm_point_from_hex(P, pubKey_hex);

    if(algType == 0) { // sign and verify
        for (i = 0; i < 1000; i++) {
            if (gm_do_sign_for_test(key, dgst, sig_res + 64, testK) != 1) {
                printf("gm do sign failed.\n");
            }
            if (gm_do_verify(P, dgst, sig_res + 64) != 1) {
                printf("gm do verify failed.\n");
            }
            for (j = 0; j < 32; j++) {
                sig_res[j] = sig_res[64 + j] ^ sig_res[96 + j];
            }
            gm_bn_from_bytes(dgst, sig_res);
        }
    }else if(algType == 1) { // sign only
        for (i = 0; i < 1000; i++) {
            if (gm_do_sign_for_test(key, dgst, sig_res + 64, testK) != 1) {
                printf("gm do sign failed.\n");
            }
            for (j = 0; j < 32; j++) {
                sig_res[j] = sig_res[64 + j] ^ sig_res[96 + j];
            }
            gm_bn_from_bytes(dgst, sig_res);
        }
    }else if(algType == 2) { // verify only
        gm_bn_from_hex(key, sig_hex);
        gm_bn_to_bytes(key, sig_res + 64);
        gm_bn_from_hex(key, sig_hex + 64);
        gm_bn_to_bytes(key, sig_res + 96);

        for (i = 0; i < 1000; i++) {
            if (gm_do_verify(P, dgst, sig_res + 64) != 1) {
                printf("gm do verify failed.\n");
            }
        }
    }

    int k;
    for (k = 0; k < 64; k++) {
        sprintf(sig_res + k * 2, "%02X", (sig_res[64 + k] & 0x0FF));
    }

    sig_res[129] = 0;

    printf("r = %s\n", sig_res);
    printf("test result: %s\n", (strcmp(sig_hex, sig_res) == 0 ? "ok" : "fail"));
}

void test_sm2_sv(const char * key_hex, const char * pubKey_hex, const char * sig_hex,
                 const char * input, unsigned int iLen,
                 int algType) {
    unsigned char buf[32] = {0};
    gm_bn_t key;
    gm_point_t _P, *P = &_P;

    gm_bn_from_hex(key, key_hex);
    // 从私钥中计算公钥
    gm_point_mul(P, key, GM_MONT_G);

    gm_sm2_compute_msg_hash(input, iLen, "1234567812345678", 16, P, buf);

    test_gm_sv(key_hex, pubKey_hex, sig_hex, buf, algType);
}

void test_gm_sm3(const unsigned char * input, unsigned int iLen, const unsigned char * output_hex) {
    gm_sm3_context ctx;
    int i = 0;
    unsigned char buf[32] = {0};
    char res[65] = {0};

    gm_sm3(input, iLen, buf);

    gm_sm3_init(&ctx);
    gm_sm3_update(&ctx, input, iLen);

    for(i = 0; i < 100000; i++) { // 10万次
        gm_sm3(buf, 31, buf);
        gm_sm3_update(&ctx, buf, i % 32);
    }

    gm_sm3_done(&ctx, buf);

    for (i = 0; i < 32; i++) {
        sprintf(res + i * 2, "%02X", (buf[i] & 0x0FF));
    }

    printf("r = %s\n", res);
    printf("test result: %s\n", (strcmp(output_hex, res) == 0 ? "ok" : "fail"));
}

void test_gm_sm4(const unsigned char * key, int forEncryption, 
    const unsigned char * input, 
    const unsigned char * output_hex) {

    int i = 0;
    unsigned char buf[16] = {0};
    char res[33] = {0};

    memcpy(buf, input, 16);

    for(i = 0; i < 100000; i++) {
        gm_sm4_crypt(key, forEncryption, buf, buf);
    }

    for (i = 0; i < 16; i++) {
        sprintf(res + i * 2, "%02X", (buf[i] & 0x0FF));
    }

    printf("r = %s\n", res);
    printf("test result: %s\n", (strcmp(output_hex, res) == 0 ? "ok" : "fail"));
}

void test_gm_point_codec() {
    const char * pubks[20] = {
        "04B33C4A2A3E448FD7C584142B51208AEC25C261CE6A0D152E59DD0E9E6D7F2C391729A17E5A5BD110B77F4048CE24744F019576B93A9FAB133DFD7CEC9BB0C125",
        "046E751153A9BB24BF0B1E82D97BEE2802BA413B9AB74424C67C60E7ECFAE3986DB1CD5D2EA988552A44476E8A81BDFDF349397A3428CB0E7E043ABB0A53C925C6",
        "04F604E51419128B82496A16A73261A8B8FD558114DED38EC2F473B65951D0E9C4551645373491EF4FEBD3E7F8CF928990A18A4AE8E6C647F1FC50935B0E93DE81",
        "045E750E935779D356DBA0ADFCAB464F32E8599677AA443DEE30D15C694EBE8C2FB1A38C268FE08FC3460C320C626BA979BA67F2C33513A708D7300435F2C09FD6",
        "04C7B8D81A0169C841F8A1E7BE93802C65539CF20119865208DE3240FAED50D069EF58DF6F258C3DEF7FC559DA5B1D92D45F8B0DDB137A83DD780B0A4D0D298008",
        "048FAAF363E7A60B7FF805E8DF54F2D127C77AAA47A5E292A701F478590CB10F59D839707BB29FDC532202FFCA4C8DCEB582435559C7CCFE303646C4B6F4B16F16",
        "042B247178EEDA7C3E0C3CC4B4E371550557A9958B67A7C06D915AA4C2994DE7E3D395C2B49BD0805E2174D99C5EB30C876E18AC752B47D8FEA0D233F79615E554",
        "04227477E7314280A563498C72CA9467753E9E1D675B0BA291D5979D33DA90329D1DA8DC7390E298330430102856EEB2DA19769F2AA1DAFBFE72044676CA40BDE8",
        "04C6DE4E3EEA2A8DD31CB7CD2D4F6C604A7A0B1398B317A14294C56F4262DC4B59E9853EC2DC4F2D8C29316D2D024AEC4FF02BB365BBB9275CBBDA04807F4770BD",
        "04A86CE03238B8E6312B17A1FC1EA72ACF5139C0438AF14BD9D81EF81A7793830751E6DD136966389AB4EB74E38B1A8DC08FB59F4E36D2421C27B7E58341506396",
        "049CD65465831CC9A93A9EC06AC7C74E5B3865E9D98FD5F1F74289147BB1AFB603A5A9279150C5AEA27F4863CC5F03FF319DEDAC0EC9E501222821490C39F6C99D",
        "04A15F6088144E410F591931426C4162D97B62867E01EC58518F1CDD8D56EA744C5B996F88D65B0D8377AF4784449DCE62E2FF583F5FF64BE1716DFDE64C4DE954",
        "04AFC8F02E58C7EC2AD9ED8415EEB074550D93C4A739D902F4678AA10DB515EE553B015517EEA5108195CFF7DB6FE472017CF5C7DA22E0DA65BC8B4659E8159B48",
        "041F356F3D3D002D1F133D5E6718A72AD5EFE1B370E14DDEDF7AF8403C8078AD92377BADEF043B6039B9E1EDDFA503A86C083155AE900D8925718DCA4EBA03214F",
        "047EF7A8592B8058FFA37B760455045A027250C7285800D5C202CD58932246FBD2C0FA144F10B7C0C67B688ECD322A7D62A0947BF306EACD6FD4FC7DF7F5A5DBF6",
        "041352C4274C22B79863BBDD5CE18AD67EDC1BD3ED6723C272E6BD23C6EA22BC1CB0938B6F6693830ABEE380BC5FEDA8B508863E836300F92A5D8B383D173EDDF1",
        "04B6B8F2F865585E397A35AC01FC625002ED4EF34AAB3DC4BF014AB88D067B348A6FF093E492A5D474D6231DD16B252EE0B82BDE8DF05EFC4F67892C16FEA2E521",
        "0446BC59D115B46DCB54F96470E42B2879897268BE2FA525959F29558DD0D2D296955BA4C5C1EB0A8F7AF85B0BE82BF8FABC81142FE45511497D6C725D76EBD91E",
        "040F5049F8335EE7401599E6A97D94481252972879DE02CB3461B648C77DC918C0EED9C57C65CDB005B5D3A43BDDB785770CA859F8D8AC61C2D753C8220D9C4695",
        "04EA07958F8AAE0AB03613AE7689E9B17F9608271FF01A85EADA62736E5E56841B718464FF99E3C0E2CC98A84B02B58B5B11097397D128A91A5BC048A3C224908D"
    };

    const char * pubksC[20] = {
        "03B33C4A2A3E448FD7C584142B51208AEC25C261CE6A0D152E59DD0E9E6D7F2C39",
        "026E751153A9BB24BF0B1E82D97BEE2802BA413B9AB74424C67C60E7ECFAE3986D",
        "03F604E51419128B82496A16A73261A8B8FD558114DED38EC2F473B65951D0E9C4",
        "025E750E935779D356DBA0ADFCAB464F32E8599677AA443DEE30D15C694EBE8C2F",
        "02C7B8D81A0169C841F8A1E7BE93802C65539CF20119865208DE3240FAED50D069",
        "028FAAF363E7A60B7FF805E8DF54F2D127C77AAA47A5E292A701F478590CB10F59",
        "022B247178EEDA7C3E0C3CC4B4E371550557A9958B67A7C06D915AA4C2994DE7E3",
        "02227477E7314280A563498C72CA9467753E9E1D675B0BA291D5979D33DA90329D",
        "03C6DE4E3EEA2A8DD31CB7CD2D4F6C604A7A0B1398B317A14294C56F4262DC4B59",
        "02A86CE03238B8E6312B17A1FC1EA72ACF5139C0438AF14BD9D81EF81A77938307",
        "039CD65465831CC9A93A9EC06AC7C74E5B3865E9D98FD5F1F74289147BB1AFB603",
        "02A15F6088144E410F591931426C4162D97B62867E01EC58518F1CDD8D56EA744C",
        "02AFC8F02E58C7EC2AD9ED8415EEB074550D93C4A739D902F4678AA10DB515EE55",
        "031F356F3D3D002D1F133D5E6718A72AD5EFE1B370E14DDEDF7AF8403C8078AD92",
        "027EF7A8592B8058FFA37B760455045A027250C7285800D5C202CD58932246FBD2",
        "031352C4274C22B79863BBDD5CE18AD67EDC1BD3ED6723C272E6BD23C6EA22BC1C",
        "03B6B8F2F865585E397A35AC01FC625002ED4EF34AAB3DC4BF014AB88D067B348A",
        "0246BC59D115B46DCB54F96470E42B2879897268BE2FA525959F29558DD0D2D296",
        "030F5049F8335EE7401599E6A97D94481252972879DE02CB3461B648C77DC918C0",
        "03EA07958F8AAE0AB03613AE7689E9B17F9608271FF01A85EADA62736E5E56841B"
    };
    int i, j;
    unsigned char buf[65] = {0};
    char res[132] = {0};
    gm_point_t p;

    for(i = 0; i < 20; i++) {
        gm_hex2bin(pubks[i], 130, buf);
        gm_point_decode(&p, buf);

        gm_point_encode(&p, buf, 1);
        for (j = 0; j < 33; j++) {
            sprintf(res + j * 2, "%02X", (buf[j] & 0x0FF));
        }
        res[66] = 0;
        if(strcmp(res, pubksC[i]) != 0) {
            break;
        }

        gm_hex2bin(pubksC[i], 66, buf);

        // 这里要还原p，要不测不出来问题
        gm_point_set_infinity(&p);

        gm_point_decode(&p, buf);

        gm_point_encode(&p, buf, 0);
        for (j = 0; j < 65; j++) {
            sprintf(res + j * 2, "%02X", (buf[j] & 0x0FF));
        }
        res[130] = 0;
        if(strcmp(res, pubks[i]) != 0) {
            break;
        }
    }
    if(i != 20) {
        printf("test result: fail\n");
    }else {
        printf("test result: ok\n");
    }
}

void test_sm4_ecb_cbc(int isCBC, int pkcs7, const char * input_hex, int iHexLen, const char * res_hex, int rHexLen) {
    unsigned char expbuf[33000] = {0x0};
    unsigned char buf[33000] = {0x0};
    int i;

    unsigned char key[16] = {
        0x6B, 0x8B, 0x45, 0x67, 0x32, 0x7B, 0x23, 0xC6, 
        0x64, 0x3C, 0x98, 0x69, 0x66, 0x33, 0x48, 0x73
    };

    gm_hex2bin(input_hex, iHexLen, buf);

    int iLen = iHexLen / 2;
    gm_sm4_context ctx;
    for(i = 0; i < 1000; i++) {
        // 这里可以加一个reset函数来代替，避免每次都要计算一次rk
        gm_sm4_init(&ctx, key, 1, pkcs7, isCBC ? key : NULL);

        // 测试内容长度是16的倍数的case
        if(iLen > 32) {
            int tmpLen = iLen - 32;
            iLen = gm_sm4_update(&ctx, buf, 32, buf);
            iLen += gm_sm4_update(&ctx, buf + 32, tmpLen, buf + iLen);
        }else {
            iLen = gm_sm4_update(&ctx, buf, iLen, buf);
        }
        
        int r = gm_sm4_done(&ctx, buf + iLen);
        if(r == -1) {
            printf("test result: fail1\n");
            return;
        }
        iLen += r;
    }

    gm_hex2bin(res_hex, rHexLen, expbuf);
    if(memcmp(buf, expbuf, rHexLen / 2) != 0) {
        printf("test result: fail2\n");
        return;
    }

    for(i = 0; i < 1000; i++) {
        // 这里可以加一个reset函数来代替，避免每次都要计算一次rk
        gm_sm4_init(&ctx, key, 0, pkcs7, isCBC ? key : NULL);

        // 测试内容长度是16的倍数的case
        if(iLen > 32) {
            int tmpLen = iLen - 32;
            iLen = gm_sm4_update(&ctx, buf, 32, buf);
            iLen += gm_sm4_update(&ctx, buf + 32, tmpLen, buf + iLen);
        }else {
            iLen = gm_sm4_update(&ctx, buf, iLen, buf);
        }

        int r = gm_sm4_done(&ctx, buf + iLen);
        if(r == -1) {
            printf("test result: fail3\n");
            return;
        }
        iLen += r;
    }

    gm_hex2bin(input_hex, iHexLen, expbuf);
    if(memcmp(buf, expbuf, iHexLen / 2) != 0) {
        printf("test result: fail4\n");
    }else {
        printf("test result: ok\n");
    }
}

void test_sm2_crypt() {
    gm_sm2_context ctx;
    int i, j;
    gm_bn_t k;

    unsigned char testPrivK[32] = {0};
    unsigned char testPubK[65] = {0};

    unsigned char c3[32] = {0};
    unsigned char buf[6536] = {0};
    unsigned char output[6536] = {0};

    gm_hex2bin("3D325BAA32B2A2437FFB471901FD7C0D218FEF5B9BCF5187431DC4B23330FB16", 64, testPrivK);
    gm_hex2bin("04328B2B5CEB896FB409FAD358F8228F8FD17A9AED7F9C78B1D78AAD45D2514EA1CC615C5184B1CA6C8462DC3ED541E2D7666FEB6C5293FB1B7E60CBE8DF203D2F", 130, testPubK);
    gm_bn_from_bytes(k, testPrivK);

    buf[65] = 0x61;
    buf[66] = 0x62;
    buf[67] = 0x63;
    for(i = 0; i < 100; i++) {
        gm_sm2_crypt_init_for_test(&ctx, testPubK, 65, 1, output, k);
        int rLen = gm_sm2_crypt_update(&ctx, buf + 65, 3 + i * 32, output + 65);
        rLen += gm_sm2_crypt_done(&ctx, output + 65 + rLen, c3);

        memcpy(buf, output, rLen + 65);
        memcpy(buf + rLen + 65, c3, 32);
    }

    gm_hex2bin("04328B2B5CEB896FB409FAD358F8228F8FD17A9AED7F9C78B1D78AAD45D2514EA1CC615C5184B1CA6C8462DC3ED541E2D7666FEB6C5293FB1B7E60CBE8DF203D2F6162634E2DE036AE3AC2C07F99C9108427536B515CBC481E12450658E729992729F88A187A26E9D7CC99F63094948800C7E0A54162B66C0A29A44899A86180BBC41B9DC0924AF86EDD4ADB6B5382CC43FE39F7476609400D554ACD7843EFBC0E8ED25AD6F8AF0266578F9B5D3AA4E47888774BE4ECB0EB989F918A80550AE2AE99DE1FD88897653411DA756F249D11229D7220F2D57CD948CE508F45087A2B78D0D78F9A0A581EBDC5E7F8570E1E90000FCFA5D4DD53448535A46108ACF26D7517F2FE6AF4A85B7F8949CA41DECD7BA6C34AB8B4B3D3C485876C64B5A89AE71BF1732861F41F533A586F4B5043C41E54DFC007F2AF0B33939421E20972753F6893419512FB9D67DC95620BEB2EB5AD86A7493B67ECA5256770112C7FD7A165CD836ED70EDE3B3A8ECDDAFF2C3C65C00FF695E8309CCCCCCE61FDA5A68D29CFCB81A7391C5453F1657F42FEA3B3352A652264CEB8637A807A4D93862AF6FD7D49E33CBBBB96D4165A74F1B5CE28F83EF58A7639DFB2E9748469AE064ABA467091329DB56709873D90B257077EFA990CDFD33354E29280A9D6891027022031C607DD43A495925BC45E6E43422B19F68347EBF904FE318E6378A6A4E9BF1E6A4A0B35C388349975C2C2551F532F8FA78ED7C694768D1B1BAB445C906D9389CD0EF124CFC7D4719301D5D4A1A7B05550D1421AE1499458E5DF55520316B56A872212562CEC9E4CACB542D48C89F82B4702E0264DC0FCEAA1D1C93838AA62AD154F143D09E6A4DF3385AD186FC8AF846EEB40EB5D1CFE555AE726980F42BCAA5059138C48385A137CE3A59B5B8EFEAD18814F2D9820A732A338A85F6A47593628A6C4E55D3878D9AC243BDF016FACEB4275B1050A69B2469103EDD3BDE24B1FF74FE711076BCE4B0585474CD71A42580967306DA0B81E4B5F94B8B82E15029788CFB812D0B1C3F2A216EC18BDCEE1C8B5E6E2C533AABE001BA4AF3251C50D9BD71C8F912B0C0D52710E605B99634C7AFF6B7B27CF889A446F4FC61C0DE3B571AFE44A0BF6B83E7FCF3F077C5EA64A53EAC5525CFEF07BE67DE29E161E4C0B02CE303AEDDC4DAEE64B4CDCC19FB6772BAF2300A2B3B1A986D16EC0D0CC2CD2B19CCF39DA6300A4E99E873D07A7239FA8CC249BE98F5C54EFE607C2DA2B1C1D5E40540D92ABE1DF9A00CAB1BF3E64A63732F2458C3A1254A723F129017C3C0B2E6A4A8F6E9DCF079B3E0740210DE69E5B888FF388C7D9798316B8786169A69F70A61F26C9E8BE5F432245935409EC9E37BEACE9DBE8DD429EB1AF655EC269D70CCDBBCD81C2C8540E46D3DC9FC183A78EE4E875A68FD9DF84351D50F39608E706DA7DB38B14DE6C190C00D0A087AC4DBE0FB01B83A674266DD5EF770F22C06FF480F940877AE086DDD91207598B7DA1523906376F916493868559CC08BA84B5B2DBAE5645410B8AAA28D113FB2ECD4319B396473842C04330E0ECEC087AC8E41FC00F262767BD0C3C966E12D714661D703AECCFDBFAD068EF402FC32CC2956128DFE2CCD883445B0484545F0E53AC4D150F9F3F53AF7B7DFC85E8854C261979637D7C3B55AFEFE94F2ABA94F91EE07BF6AF4396A1E89F35E03B2D305ED36D1FA9ECAD6D4B8F7EBC724466F86B1502137683282EC188981213F93752663A05E6DB04090BF9CCE1B5F0F9D7522A6C4AC71DFFC0E50E73B03FB7C51BF2E536731281AC48FF20B871F930FEDBD5EE225BA345513815F58209F55083C9B6E2AB42D7A1DEC9E43CB121F69CAF28D6DABFFB5DA1A1A3AB4CFD38CF5B7F677E88E174B6AA3A1926BE55DA038A351452C471B496F457B9B6A054D33A513A91283365069128FF45E852654701C65ACD2DF98D2395C82E2818F7D1DD6729703A59E9CBEB8833D0463137B1D6E6A35BBB8D399C0994D13B5B37F3455C9225C8A421EED8005EE71E9FC794E627FE1672212961133354E2D2931A290E0A80DEAD21F15F1BDED014455D4B237AB814A4D138741AE4D59D32FBE88E20F5D21D78A45FBE86DF603D3FEACD7BDA51456E925741DEBC9A7362F0B84C4E00E9BA3B9336F9EB709204AB83400672D489C6F52A68E74ED7CA3BEE77D99210AA4A2A3A71ABA631CCC0E89A0727B84509924E9E8DB47EFB6DCBE2B362D0F1695BBD5C2FFD191098A8A330327040340DC1D72473EB6A0886D046D83FEC99B85AC2740A19E6195683A18E7DADBD97DB8D39F9E00F0B7FD68B26D494AA4090B23F7C7AB0B78117973EC217BA376317BB27A8A36FC52C533A911A24DB0865F42B3E87801FD305FFFDBA937C486B90F9EC9E245B9879E58D42B36EDD8787A21B386E65B0C47695EBCE27A95D70AF2311248E876DD7E36B41C6E6826C4FD22C50ACAF6E8C7E420E934F064D8C792F26212FB58C9AD32705CF859FFD18F5C67EF4DCBA50A37AD7FB01D839423554587CC67BA5955CA8EDBFE3B1242E4F6AA9E46DF41768C3A89BC9AEE371EC2E690A29AA057155B0066CEB08ED725FDA2E24DA37490DA54F36DB66FCB7C77CCB8CF19298C6A5089228B760A805EAE814927FCED1316E7EDB3F761937014B60C95364DF6E19571BD5A34527084FF3338080BD75F6D0E100ED3ADF5524F422CCBEDC5D40DAEE981573EC3B33F8CE76B3F368D02C413DEF85D80C247737FA5BC71835E056AFC87452A6EAB74F5A61D8A6B074304A5C49F4E178B480A43D2B4E7276E48D28FB05B35902399889E7FDFB2B11FBE1F2117A5B5A21CD07D586FFD0D564515C9E1895E75A12778FE493DBBEFACCFE104D97D5C4871D8A3940ECECFDB11427B94DDB05E8550F6E8C424D2FE5AF7C60B3CB2F01F8EA4128185F68FCDB7D744D3C5F2588F02DE5A14BBD5FD82AFA9D16117F5D59E985C4A44D73C53FFDD3B0660EF4BC5105519185D8A8D418426CEA651CFE6F6C7CEAA28940F3878D033DA544D3E9CCED970DDDAA46D4309BBFFB18DF814C9898DD4A38E07768C2D6F2688AB90665AF7F1E9666C04A770341A35421BC456F847B6A0437269CF05296BA014F3B957C4EE8148F63BE231F919BA11A890126BD7C50766EA2F90BE83A174657652A05C1F4D0FEE41CDBD35C2CAD83D922182C9035AA55F07EDA4A02F7782B341B676A310E4543932FF4C0A900FC36EA95D36642052A43AB9104729AFADEECD6C1324FA73F5C45173447706D3DD1654416D15406C81FF3F2880A4C9D1BF4CD81A156366802F6291B03E37B904A20C64FA2B3E1B5003671BA546E5D3FC05581F2A9F8CE76D527B6484F8AF48DD121A715647C1BF92AF77CD2362DDEBD0E597A8EFA425EDDC346B91D455F79802F8EAAFA563398DC8F7E55085C63F9E8F5A454CBFE52D612A9AFE00D4D06A35E72EA9F41D5A37C5C6994DA5F137FE2EE4EDAC77A74F7467CE176F8C901D2B90810CCF1BFFADD4DF04160FC2B2A5CA32E1E075D00B8E5C21F793AC7D244EAE46062DA59E0A291AAC16AD75F54CD15FD229E5FEA2C9FFDEB5C5A010C56E3CF03C2D60ECBA3158DA79BA0B1D46A40704421F772A894AF328A83122B73B7B8E760BB5DD5F148F5ABAC30DA980AB6958E7586CFB42811DDCC7F0A9E7ECE9C81DD1A63F9E433273282A0C2ED8C229F6D0732D5859662098B1F8CD22A5291654AEFC81F81607C99E4F8545C37C880335DFB065272396D408EB78B4A6EB64C5F7F51B79152283F540961E34B3AD0F648EC0CC982373FA9863F4BFD998F0E05770DB2CC411B30C4E498AC9C1CBFE3FE00B60C57E166E3192482BF31BD14192D18342F741DFFDDB60053B4EA0CD4F1AB5177BC6BF0F0F9D1186D7958BFF9A5EF1092F02980BE9D6A04E123633C8BC2BBDA800F38835642E9EEC9B4F1771F25BC6090FA1FF0F25AB58DD491ED7147703DFAC1668646659DE9D577868B269930EDD2A41B07B04F9E16D4C0FECCAFC9CDAB27472E276D975B4345043AB7843CA683DE2DDCECD773114AC75912FEA3D719C08959249A8DF46CA3B497A821A2EC3CA913FC5C777876800956FC1B8BFE27ADFF00673A5269972B4FA721A55548F9E9BDA5382D0F3C6AB0129D977AE86009A1A68C789B042F015C6097B6BE3613317B1BE8491077D24443B24A95B91DDD300564020FFB3D2B7537E82B6748766C87AD92FE7700899FB5909CBF749AE369DFA22F052ABD688AEBD6685F6EDFB4BC2E8F037AEDBCE2D824EEDDF96D1B7A2A3AECC102A3500BF108E00B6121287377482F2AEA4860F42F6B6D8FB3461738ED8860762D7714F9F6F46A18C47A970A40867411180849E37EF758C586E9E5C7373C2742AA9B7BB3CB88A698D2D73C1AC2BEBA9BC7FB51931E8BD0D33925005791C1763F3B81E9FDE3E55D6A0DC54ECDF15334A2BA28958248808F1A294BF1AAA16DDCE2649077D8CE244D6E84ACEDE2DA5B951294B318917568A04D785C827E09E2CCA28C5503C4156E81726C4263E06D932B337F78D65D2CE7DE25EEC60DBFA1B4259807DE14E11C23B3BC2475D20E84EDA715EDD636528404EBF9EFAC9BDCE1094735ED8AD588D886A6111155C3A7364E21649DC7B6", 
        6536, output);
    if(memcmp(buf, output, 3268) != 0) {
        printf("test result: fail1\n");
        return;
    }

    for(i = 0; i < 100; i++) {
        gm_sm2_crypt_init_for_test(&ctx, testPrivK, 32, 0, buf, NULL);
        int rLen = gm_sm2_crypt_update(&ctx, buf + 65, 3268 - 97 - i * 32, output);
        rLen += gm_sm2_crypt_done(&ctx, output + rLen, c3);

        if(memcmp(buf + (3268 - 32 - i *32), c3, 32) != 0) {
            printf("test result: fail2\n");
            return;
        }
        memcpy(buf, testPubK, 65);
        memcpy(buf + 65, output, rLen);
    }

    if(buf[65] != 0x61 || buf[66] != 0x62 || buf[67] != 0x63) {
        printf("test result: fail3\n");
        return;
    }

    for(i = 0; i < 100; i++) {
        gm_sm2_crypt_init(&ctx, testPubK, 65, 1, output);
        int rLen = gm_sm2_crypt_update(&ctx, buf + 65, 3, output + 65);
        rLen += gm_sm2_crypt_done(&ctx, output + 65 + rLen, output + 68);

        gm_sm2_crypt_init(&ctx, testPrivK, 32, 0, output);
        rLen = gm_sm2_crypt_update(&ctx, output + 65, 3, buf + 65);
        rLen += gm_sm2_crypt_done(&ctx, buf + 65 + rLen, buf + 68);

        // check plain bytes
        if(buf[65] != 0x61 || buf[66] != 0x62 || buf[67] != 0x63) {
            printf("test result: fail4\n");
            return;
        }

        // check c3
        if(memcmp(buf + 68, output + 68, 32) != 0) {
            printf("test result: fail5\n");
            return;
        }
    }
    printf("test result: ok\n");
}

void test_sm2_gen_keypair() {
    gm_bn_t k;
    gm_point_t p;
    int i;

    gm_sm2_gen_keypair(k, &p);

    char buf[132] = {0};

    gm_bn_to_hex(k, buf);
    printf("private key: %s\n", buf);

    gm_point_encode(&p, buf, 1);
    for (i = 0; i < 33; i++) {
        sprintf(buf + 33 + i * 2, "%02X", (buf[i] & 0x0FF));
    }
    buf[99] = 0;
    printf("public key compressed: %s\n", buf + 33);

    gm_point_to_hex(&p, buf);
    buf[128] = 0;
    printf("public key: 04%s\n", buf);
}

void test_sm2_key_exch() {
    gm_bn_t da, tmpda;
    gm_bn_t db, tmpdb;
    gm_point_t pa, tmppa;
    gm_point_t pb, tmppb;

    unsigned char userId_a[3] = {0x61, 0x62, 0x63};
    unsigned char userId_b[5] = {0x61, 0x62, 0x63, 0x64, 0x65};

    unsigned char rp_a[128] = {0};
    unsigned char rp_b[128] = {0};

    unsigned char k_s1_sa[256] = {0};
    unsigned char k_sb_s2[256] = {0};

    gm_bn_from_hex(da, "1ED44070B763431D23D35A227A34D91558DC0B1EDD87E91238D4A54D98FAB6A0");
    gm_bn_from_hex(tmpda, "B45B1F0577C6D37C86F252B394B20E55FEEEF2DEE49743A68EC7871CECD89872");

    gm_bn_from_hex(db, "D18FE8EFD4E7C5B2FFDC356E16E397D2443DB6EA4C453EB5DC2852F8E301E846");
    gm_bn_from_hex(tmpdb, "37ED4CE7C7951B76BE93CFD116A9F8AE439664107A59278E0F7095B964A8C7BA");

    gm_point_mul(&pa, da, GM_MONT_G);
    gm_point_mul(&tmppa, tmpda, GM_MONT_G);

    gm_point_mul(&pb, db, GM_MONT_G);
    gm_point_mul(&tmppb, tmpdb, GM_MONT_G);

    gm_point_to_bytes(&pa, rp_a + 64);
    gm_point_to_bytes(&pb, rp_b + 64);

    gm_sm2_exch_context exa, exb;

    unsigned char expbuf[116] = {0};
    gm_hex2bin("3A18CB6BE2DC15C49998BE75DA28C4DEB3ADF33E08E886FCD7B2869CD006A6C4D5852D9E194A091EC9AC01B2D6B5153A09CA39BC3FB4984A09E4CE5B0DEC0E105CA12D712F6C8CBE59BFE54CAD0641B922D3EB0AD10C1D2347BA10985624ACC5A4C21400A3441D8EA5DE97B897B2635E6AEDE9", 
        230, expbuf);

    int i;

    for(i = 0; i < 100; i++) {
        // A为发起方，发起方初始化
        gm_sm2_exch_init_for_test(&exa, da, &pa, tmpda, &tmppa, 1, userId_a, 3, rp_a);

        // B为响应方
        gm_sm2_exch_init_for_test(&exb, db, &pb, tmpdb, &tmppb, 0, userId_b, 5, rp_b);

        // B拿到A的r z w进行密钥计算
        gm_sm2_exch_calculate(&exb, rp_a + 64, rp_a, userId_a, 3, 16 + i, k_sb_s2);

        // A拿到B的r z w进行密钥计算
        gm_sm2_exch_calculate(&exa, rp_b + 64, rp_b, userId_b, 5, 16 + i, k_s1_sa);
        // A校验s1 == sb
        if(memcmp(k_s1_sa + 16, k_sb_s2 + 16, 32) != 0) {
            printf("test result s1 == sb: fail\n");
            return;
        }

        // B校验s2 == sa
        if(memcmp(k_s1_sa + 16 + 32, k_sb_s2 + 16 + 32, 32) != 0) {
            printf("test result s2 == sa: fail\n");
            return;
        }

        // 最后来看看两方计算的密钥值是否一致
        if(memcmp(k_s1_sa, k_sb_s2, 16 + i) != 0) {
            printf("test result ka == kb: fail\n");
            return;
        }

        if(memcmp(k_s1_sa, expbuf, 16 + i) != 0) {
            printf("test result check k: fail\n");
            return;
        }
    }
    printf("test result: ok\n");
}

void test_sm2_ctx_sv() {
    unsigned char input[60] = {0};
    unsigned char buf[64] = {0};
    unsigned char userId[3] = {0x61, 0x62, 0x63};

    gm_bn_t k, dgst;
    gm_point_t p;
    gm_sm2_context ctx;

    unsigned char testPrivK[32] = {0};
    unsigned char testPubK[65] = {0};

    gm_hex2bin("3D325BAA32B2A2437FFB471901FD7C0D218FEF5B9BCF5187431DC4B23330FB16", 64, testPrivK);
    gm_hex2bin("04328B2B5CEB896FB409FAD358F8228F8FD17A9AED7F9C78B1D78AAD45D2514EA1CC615C5184B1CA6C8462DC3ED541E2D7666FEB6C5293FB1B7E60CBE8DF203D2F", 130, testPubK);
    gm_bn_from_bytes(k, testPrivK);
    gm_point_from_bytes(&p, testPubK + 1);

    gm_hex2bin("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C791167A5EE1C13B05D6A1ED99AC24C3C33E7981EDDCA6C05061328990", 
        120, input);

    // 旧方法签名
    gm_sm2_compute_msg_hash(input, 60, userId, 3, &p, buf);
    gm_bn_from_bytes(dgst, buf);
    if(gm_do_sign_for_test(k, dgst, buf, k) != 1) {
        printf("test result sign: fail\n");
        return;
    }

    //新方法验签
    if(gm_sm2_sign_init(&ctx, testPubK, 65, userId, 3, 0) == 0) {
        printf("test result sign init: fail\n");
        return;
    }
    gm_sm2_sign_update(&ctx, input, 60);
    if(gm_sm2_sign_done_for_test(&ctx, buf, k) != 1) {
        printf("test result verify: fail\n");
        return;
    }

    // 新方法签名
    if(gm_sm2_sign_init(&ctx, testPrivK, 32, userId, 3, 1) == 0) {
        printf("test result sign init: fail1\n");
        return;
    }
    gm_sm2_sign_update(&ctx, input, 60);
    if(gm_sm2_sign_done_for_test(&ctx, buf, k) != 1) {
        printf("test result sign: fail1\n");
        return;
    }

    // 旧方法验签
    if(gm_do_verify(&p, dgst, buf) != 1) {
        printf("test result verify: fail1\n");
        return;
    }

    printf("test result: ok\n");
}

void test(const char ** argv) {
    /** base ops **/
    TEST_BN_ALG("gmp_to_mont",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "91167A5EE1C13B05D6A1ED99AC24C3C33E7981EDDCA6C05061328990F418029E");

    TEST_BN_ALG("gmp_from_mont",
                "91167A5EE1C13B05D6A1ED99AC24C3C33E7981EDDCA6C05061328990F418029E",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");

    TEST_BN_ALG("gmn_to_mont",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "5CDA05B37B640FC1A521AA304C8CAFA4A4D8F13B0D66D505CE6907A521AA04BF");

    TEST_BN_ALG("gmn_from_mont",
                "5CDA05B37B640FC1A521AA304C8CAFA4A4D8F13B0D66D505CE6907A521AA04BF",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7");

    TEST_BN_ALG("gmp_mod_t",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000001");

    TEST_BN_ALG("gmn_mod_t",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "000000000000000000000000000000000000000000000000327F9E8872350975");

    /**  bn mod p ops **/

    TEST_BN_ALG("gmp_add",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "6564F159CE84BEC13D3CA303596C95F1E0FC286C6B6EC0B35CD378B33A84A721");

    TEST_BN_ALG("gmp_sub",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "00246AFE6FAE437181F565897B06FD373EC9EF13795D570F85E1125F2C14426D");

    TEST_BN_ALG("gmp_mul",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "64DD9339D3DFA3D15B581B1DD13E3D9202982F62473372E76B5D591A38F193CD");

    TEST_BN_ALG("gmp_sqr",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "D34B72070B8ED7CFA57E42CAAFC947B88AE9C241224110D0E7A4883B3FB787E3");

    TEST_BN_ALG("gmp_exp",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "161F67FA7D66D931B1B743EFA1E66F141324C3A3AF7C5A32D124007AF44BEABA");

    TEST_BN_ALG("gmp_inv",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "BFA4C3D86516875A89E9CD9123288DB4510188032D6EE254EBAF282C905A9A00");

    /**  bn mod n ops **/
    TEST_BN_ALG("gmn_add",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "6564F159CE84BEC13D3CA3035D805623B71F26583B35FD3A6F9D86075603B079");

    TEST_BN_ALG("gmn_sub",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "00246AFE6FAE437181F5658976F33D0568A6F127A9961A887317050B10953915");

    TEST_BN_ALG("gmn_mul",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "6FE789E58A88991A4600A167FAF7F4F49058EF92ED5DDD701F1971356A674484");

    TEST_BN_ALG("gmn_sqr",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "0000000000000000000000000000000000000000000000000000000000000000",
                "64FC21F78304770E66FDF83E8E29C632A1EE34A64B323FA9C9208D9F5D1B25F1");

    TEST_BN_ALG("gmn_exp",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "F0A72A00F0DB40E177BF56EE177EC88D11BD928AE097973060CFDBDFDDB04146");

    TEST_BN_ALG("gmn_inv",
                "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
                "9DDD52AF95B748A553D1B1E106627F901CD453F067A0D50202C672130C90F607",
                "7F1CBEE6FBB9F2C2309A2E889A7FB21DE461013281C15DC939286F04EB9416AC");

    /** ec ops **/
    TEST_EC_ALG("point_dbl",
                "EB04AAE0D53FBA1E3611D5B9ED6EFA3EE5BA57C41AA7A09DDC5816AF09057757CE6FA0678392F4716E45F58E7322C76D5997B1FE44C36D8A5A59B146EE162B93",
                "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "976A325416F812A692E6880A72287604C32FE61839EA4732040451E831E1128F6654AC40E0754A30095AC2FC4C49D4147D1E2395190AEFFB555BD55AC736B2BA");

    TEST_EC_ALG("point_add",
                "EB04AAE0D53FBA1E3611D5B9ED6EFA3EE5BA57C41AA7A09DDC5816AF09057757CE6FA0678392F4716E45F58E7322C76D5997B1FE44C36D8A5A59B146EE162B93",
                "AA307A6575D8348037CEC6F860F6312317B34C81838834EDB008F54A2E590FDC593293D89FE9C933E6CE7E91CD4ABF81EC3C26395622B65754A8C0EE8FB354E9",
                "3B94D813424CC514F0C05A6D0D7A84AD321AFD86DEC60BA7A4CEDEA4F82C67E5A9ABC4ACE4B15ADE7B5175F8E9E0E33C2B2A88107C67BE15596CD83CBBF4E244");

    TEST_EC_ALG("point_mul",
                "EB04AAE0D53FBA1E3611D5B9ED6EFA3EE5BA57C41AA7A09DDC5816AF09057757CE6FA0678392F4716E45F58E7322C76D5997B1FE44C36D8A5A59B146EE162B93",
                "AA307A6575D8348037CEC6F860F6312317B34C81838834EDB008F54A2E590FDC593293D89FE9C933E6CE7E91CD4ABF81EC3C26395622B65754A8C0EE8FB354E9",
                "6CBB13143526BE4C6565BA1061C5835E3C61A5DC10B6CD5824C1F6A93B368F6D86B89F0A0459A745F5A192827E5CDCE9CB035DBFEAC286ADCD8F62C4C028567B");

    if(strcmp(argv[1], "gm_sv") == 0) {
        test_gm_sv("6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC",
                   "0148E6AF89A0E132E4E7CDA26DF2C2AEB53B741FD00AE85C78CF6EBA13E939B12F58B1E8A661EBF3395459F28945D381259BEEDA76B4886FABF5EE0A55ADEEB2",
                   "D6125763F2825F35494E930245D064E408553678A200D018E6217975E19EEFE68E48E00F0BF9632826F64F84122627A36F0F998CDB120327F4BC7ABF84E86FE4",
                   NULL,
                   0);
    }

    if(strcmp(argv[1], "gm_sign") == 0) {
        test_gm_sv("6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC",
                   "0148E6AF89A0E132E4E7CDA26DF2C2AEB53B741FD00AE85C78CF6EBA13E939B12F58B1E8A661EBF3395459F28945D381259BEEDA76B4886FABF5EE0A55ADEEB2",
                   "D6125763F2825F35494E930245D064E408553678A200D018E6217975E19EEFE68E48E00F0BF9632826F64F84122627A36F0F998CDB120327F4BC7ABF84E86FE4",
                   NULL,
                   1);
    }

    if(strcmp(argv[1], "gm_verify") == 0) {
        test_gm_sv("6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC",
                   "0148E6AF89A0E132E4E7CDA26DF2C2AEB53B741FD00AE85C78CF6EBA13E939B12F58B1E8A661EBF3395459F28945D381259BEEDA76B4886FABF5EE0A55ADEEB2",
                   "6CD42C16BC1C04F94924660BD4260B2229EC5070E954455BA3B80304763E929DB86361E8EAF0497DA53DD2DDE83F6CEA3C2C4838E9D3E29BDB269D9C5BF52976",
                   NULL,
                   2);
    }

    if(strcmp(argv[1], "gm_sm3") == 0) {
        test_gm_sm3("abc", 3, "DC7E07FF06247D00B4A8D1837C8F8B2A26C3C67C2EEE81B1E7CF9400B51891CB");
    }

    if(strcmp(argv[1], "sm2_sv") == 0) {
        test_sm2_sv("6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC",
                   "0148E6AF89A0E132E4E7CDA26DF2C2AEB53B741FD00AE85C78CF6EBA13E939B12F58B1E8A661EBF3395459F28945D381259BEEDA76B4886FABF5EE0A55ADEEB2",
                   "E85863FA584DEBE05D573D655DF82B889284189B15D1559E577B0E67500BDF14885066A6176A5D12B5DADC52CB11C84F72AEA157F9E7D0878E988A39BCCBB3B7",
                   "abc", 3,
                   0);
    }

    if(strcmp(argv[1], "sm2_sign") == 0) {
        test_sm2_sv("6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC",
                   "0148E6AF89A0E132E4E7CDA26DF2C2AEB53B741FD00AE85C78CF6EBA13E939B12F58B1E8A661EBF3395459F28945D381259BEEDA76B4886FABF5EE0A55ADEEB2",
                   "E85863FA584DEBE05D573D655DF82B889284189B15D1559E577B0E67500BDF14885066A6176A5D12B5DADC52CB11C84F72AEA157F9E7D0878E988A39BCCBB3B7",
                    "abc", 3,
                   1);
    }

    if(strcmp(argv[1], "sm2_verify") == 0) {
        test_sm2_sv("6B8B4567327B23C6643C98696633487374B0DC5119495CFF2AE8944A625558EC",
                   "0148E6AF89A0E132E4E7CDA26DF2C2AEB53B741FD00AE85C78CF6EBA13E939B12F58B1E8A661EBF3395459F28945D381259BEEDA76B4886FABF5EE0A55ADEEB2",
                   "0EB2C35EB35943C3964116BD3AB589E3AC7EAA526422A3B4F6488B16BF5B2B5F1B803696DB30BBABAEFDEAD134B18AF9F5A14062929412BAE95BE1D90C9A2DA0",
                    "abc", 3,
                   2);
    }

    if(strcmp(argv[1], "gm_sm4_encrypt") == 0) {
        unsigned char key[16] = {
            0x6B, 0x8B, 0x45, 0x67, 0x32, 0x7B, 0x23, 0xC6, 
            0x64, 0x3C, 0x98, 0x69, 0x66, 0x33, 0x48, 0x73
        };
        unsigned char input[16] = {
            0x74, 0xB0, 0xDC, 0x51, 0x19, 0x49, 0x5C, 0xFF, 
            0x2A, 0xE8, 0x94, 0x4A, 0x62, 0x55, 0x58, 0xEC
        };
        test_gm_sm4(key, 1, input,
                    "C941785C2A15751A774DEFCAE01011D4");
    }

    if(strcmp(argv[1], "gm_sm4_decrypt") == 0) {
        unsigned char key[16] = {
            0x6B, 0x8B, 0x45, 0x67, 0x32, 0x7B, 0x23, 0xC6, 
            0x64, 0x3C, 0x98, 0x69, 0x66, 0x33, 0x48, 0x73
        };
        unsigned char input[16] = {
            0xC9, 0x41, 0x78, 0x5C, 0x2A, 0x15, 0x75, 0x1A, 
            0x77, 0x4D, 0xEF, 0xCA, 0xE0, 0x10, 0x11, 0xD4
        };
        test_gm_sm4(key, 0, input,
                    "74B0DC5119495CFF2AE8944A625558EC");
    }

    if(strcmp(argv[1], "gm_point_codec") == 0) {
        test_gm_point_codec();
    }

    if(strcmp(argv[1], "sm4_ecb_pkcs7") == 0) {
        test_sm4_ecb_cbc(0, 1, "74B0DC5119", 10, 
            "78EDF349705ADA24310A9D987962AC6D78024A1723CB9D24544A3A75A68151DFAD28D71945C2AE93D6F0E27AF0460F0A1C155038EA954E3E8C5DBAF67B36BCDFA28C620A9B502CA5962EEE9C03A742472CFCD0D2FF18D572511E23E655C571D12DEB00B251A685C33B8C59D28D205FAE7FDC55B2CA2C9B50A1918350305EAE8C6DE46BB0BB85E6371A2411325C4F136B0A152C14260D07B0BB32D29438C03B409B936C66B2B33B743ED61DF6DD93685B23A9610EAB6C2911DBFF7891AFCD8BB189341338FEE7A8BA27BBB4D2E828B5F66340397BB520DCCAC4E09B89D707B049FE9A62BF5E848FE8A593EAC6FCAA4626683F761959F5C5E2BB9D450D36E44D2345ADC0A435EF24303A8343B0974B8C5D814811E363EC8D1E76D70CDBBF4E4F28B8053ABC42D46D14EED50B9BD2057C54E7586C81E6B6BF06DD0D82E874352E86DC4E84B67D8570005B4F6021B9E4E65D46376F25D804B3278A4AA8A92997F2338B2E152A3059BFA65CB3E54A9ED719ABA06D17B666BD0156D625D45EA7F752A19B477C1E1EB8BDFE99F2410A533639CC8282098446DDED7CB082A85F79E832FF6BAB7162B7F76A9A010619BBA209C6B6DBF2339E32BB54B985F9F7ADE853C7384AA300826A37F703AF45E9D67711FE02D349AAC5D155D2D43909ECE8BF879F44F37C7D893AA6B90D1A2D9A141A66AA18F39CCAF01EA8F647DFD0F1F21FD82FF40E8E265FBCB033C4081909E350BCF3FA8642438A8061E1233460A78F00B9DD8888C80B45DA733E6EC011A707C65AAE663A5A474313A3309FB3FAC52610AAFE890C0DBAC5E1DF40D445DAB35B1CBC49BB169F6A9096BEC2FD1B63583B4E8C497E9C7BFC5BBB3D00A3C2F83A6ABBCBDE72D26F1294AF0A6E06B6BA456E25303F66AB040DA6C801708CAE634B6EA004C1E7C7F0851D49538515FEA2CCE6FC4A1CE769A423900DE0CC3A4C007029A29D4266771FDDB29DF4C5B5678EE72510BE986FFA742341AB57AE72CF0747FEFD0F23643A2DC56C7AD4BF62E17618FF7D1BCFE90FDDF2F36F45D083B79C2CFEB706E2BEC4968322D54962C9C79E36CEA1F2C9EC735E0ACE44D52B0B870487D573DFDEA8060E9D2477A21DA997A84CE6EB97869B5A654D14D9CFD7826AE7060920A4A6D8925691A7FBA3487ACBCBA17FC32D44BE4EFF122CB1DB51226593862AEE842217943C9C1EBA3D64ABAAA687EE176FF078F1C92219DC21B84F914CDB77950643392F0157C21BC9858097537AA523D463F1F060B3CBCA60B3842C3C6906FFD4BC2FC72592DB2E4D46321FDF3E1D9767EF1CB314F6DEADC49ABA05B9422B64CBA5F9D127CC04E15B52B09E127A6DCB49D434158BC18FB093332415146F1E70D7549750E51EAB7A840D797022AC483749116446F41E1DD75DC030588691D62A2A9D127EABD6DCC9B5EFD326FA520DDBEAF9FD30231FDD52AEBE60363EA4AAD3D5C14D5615DEF4C5968D9B02F9A50571D8BD7AE871B3B7C5899CDABCA541D6FCC4CFD31E523DBF51355A52B18EA5D22E7431907165D09BFBE0D7D8BDCCAC6DB65F502BFD60D595453F867A6CA222CD1668D9C8F30A57AF72BEC4EBF1F12D12B171CF0A1389E2D1A3DAE6B1650B6C1D88379D6612AB75BB7BC0A6F19AAC818920E8B40A33BF2312E7EE666FC6D14C680086636AA4B417520515ADC4214BAE0EFA27D70F1748F1B673FF5D9DBE467847E4EE061D301DA2BB0D4B5AC5210F60A6C727F44BE3B6DD2E2249090E330DA0EDFFAC91124BB1402EE9509382C52A60B75272B8FCFB1858FD45B711B116261CC42F773A873EBDB04FACD8256D631D16833FED2898396CB93B4F00DD4FA4AE5E9C3AB0034A911D1B42687CCB4C2B156AC5C1D674B5BF4ADF1659C91ED7D0F2E5BE113CEEA6E671060A5F752200DF681949C79873C4C1C968CF331C1E921D78869EFE6ED60FC784FBE957A35F54301611E98B96BBC4F778003C8724CBF9D42D249DEB4F7B476BC4AC4D95B8E4FE79785FE39D610460A9A9235B44ECD460B07D0249030981565A16CA3EF0CFEDC036CCF48BCC9452AEA76DD23B10A272D7CFC2E1C731E15643F4598FCBAFFE598D05C06E4319E43A44B272E38F1409A9626DF0591ACDA99313C9384EA14ACAE2C3884CA9484AC151FDA1A41B7F4E4E5932A8553849EE6A9DAEAF5D9E3AFE464B187B30E5C13AC33FBEB822FB0B0C9CFC0116313B57B54892644704AEA998EF8E6C392B0B111F67F76E5A7147A071FE18C668D3EB37F7ED9ED9995F862C1DA98F6DACAAC5851884B90A66DB14C6C6CD2F842B4FC7E4AFDEAE11BB2F080906AEA5222E2F59E2C2E8DC63BCFF9B041A6FAD332EC995052DE39147D171E72D55C0E13EE8ABFA4AE7167CD49AD1C1FB7DF45C39F5D5772EAFCDA3D3B6ABE1BE892CE334F65F59E13B5EBF391902E044240320457C05E1CE9DBEBDA623630D196A2E7C4DC1D060E6B8A24CD2BDF61FA317D993909291359312D217CF8AB867DC5D5F2822A3DCFFB23C8365FEFCFBCA334F3ABCC28B41169E403163CD7B153156D36977E2C7FDF00CB9820CD594C378F60CE4BD5D4863A4FFA7FDB3DA628230AE82C0498E0D9D66D17BF9A95B70B5763D2B9B01FB055235B6B4FCACD326B96C5BE7CB53812D6620E2E32DD20934DF38470F0A449EE02D869AF2149E6051667E5B06ED7B3E89954250F0186A21E4FE397FED8A7F5126511AE670947B81742763718702ED9B55715A397F6ABB991A299E29AB1AFEDAE597249655E6B8851B92E0125A27F233D3EE3224618D8CB65EDA65B30A7EC3C8F907A7593A7B3F4933940C5B154C7741A98E4098EDCFEB020AD633721FA8219C9FBEA5A5B9F8D5B9E8B5D96D3BAE80F799C1715D8CDCB069EC27D5F41E6F502EB6E28DA3E0A8EA88D85D54B89976FDFE1B60C33D06C1B2A963158DA74255C3636F03F859D2F131F0044AFC286D80FC2A4438D107F8EFACF0D5777BB618D3B4833B8F8A9444286FD351BFBDE5C10D97A814B393A3E8825E2A24A1594E8873251F21EEE2CD23866CC90B970A39449FE50125F2FAAF5FC7E4D7BB20E621B9502F5A4DA201A3559392ABA77538307699FCA6B93E58D6B684D0F021F95E2D2100AFF0C84F2F45D5A9A818E182C9B63FA1C9CA11842E1229AB3066C6B525F2E7CAD31618F67E6B5DE9D78850434B5794B3534A64AA03DB51E313C6707C847A3D5769E4519B945DDDAECA95A6268F59D9F2DC152472840D27302F4B8D6D04DF2332B0806B144A5F3FD3BF805A2F1B865291A1E0F849BA76F6673B94B840DC471D6A49BDE69C61AE74388A31C42329DEFA650E7D7FF95801829ABE11A6B0014A56B2967B8F8C046FEEBDD7DCBB342BB234C3CC5B9655E43F001E63FAEF0A31D2ACA312CB0E468D816D25663DC6B28C50DB5C0037D21FD28A14BA7095EA0F4EAD8696C4F2953F5F80E42A6460BDA23CCB08AB2D02E8AAB3C6196BC90FE49B4F49DF695230250C1329AA98AB5442FB942ED626C62DD95800354DCB68D49915B1020DA1AD431CF941FAE834D9D37E262BEA48F0E7B3C4BD74190810E4355F38F0903C4C3635109B643FB4E982392EB732A18C239BB90DE3FFA83164140CD49C52EEF1083BA41873D8ED8B742916E5C009744475FE784E542D7B0E746C2D098668A3B08A8CC3D512210458C65430E72E8D814E5575BAE3A72656FF3F73A5FEF322E0F7A2B493A0FC33ED23FD12DB8F1EFB4CD5437A5178586CCE8BAD4FC86CC3CC614E94C33B0E2C197E71521A4FCECA9FCCC55D9CC2D98FA49B784BA6AE5D220A411A0793E418F2DD06BAC3CED4551229C45922EF234974887AAA010C2391E32EA56052FA58462BA0A5C8C5E67F49F2832DD508B8DC5FE0E47C3ACBC3C0BDB62AE198724CB4A62C763ED84D240937D9BED813A952FD8027B7ED72AC4560C26EBC2A30AE461D557A0732C6AB87FE5E5BF2B3D1D4932D37E30BC90BD7E71F5CAE9359DF98B935569CE8D7A585740C75713DACF6E2B64C761DC70B819F6B3308B76EF5063E47138CE3E9B3A972638036D7B20357E524DF9BA818CCB717F079E42530DADD864C3B64587F886E0E78E1561AACED6E9BA25095BF1A80CC4FA7D3392972C14E8CE777EDB0C12DB21CC028CEFC687BF96CC23E6A3BCC3C5A6486B99A365CFBB81143972C7EFEEA6DE1C5CFEE3D8CCCC86440FA657B727CBBAF973C490571D676040C9723026E103A036DEEE6D50B80DD140854530F4B244B7EAE4153E0C7B91C457A8E6C06FF66D60456C7F13B56CCD33BF94DE6CA56AECE355C4075D3DD00213877C350F90EEB9162D22EA0EBD21A5927B4151053DDFF6251A8FE41EAC5D1AD5CC08A4749A5852C3F5B187AABD7CB1742849ABDE33C6FE1D8E65A15B82038A6F590174CBB7A53BF4295E01E56C57BA44166CD7DAC0B65FF23092FEB101B0C3BFD51028F1899B87C2B9977A302EFFD3C93749BA52F9A41C67AD306215051ED5139967E954B1BEEC1B437B9459431B043AFCA68B494A6C4107488B68F1ED7CA99E80CCD8FEB7F938CD58E411416C9B270C154B3935101BC93E5D203F86EEBE264806E1763F115676B1E2C4DA9063838F6EAE4E43B2EFDE7E0366A1D6C12887C38B9E80002552697030DB5243BC027312707B7488A264D0D24296D3DBE0980AE26ACF5660EC7AEE31EC08626D4D96A78DDCA815574E23BF1C7B677B3E30F58040C32963CAAA7F7A2071E4C4DE5367A3AFE8EC012A51C4B7AFBAC27AA95CCAB9FDC54552E718963C4408557D8838225C2B43695022318DF352457618943E31BD66F0F835084B0C59B6A69FFEF791976C3189B09201509B885EC470BEAFD754F70F38AE24A8ADC771629851748FA4830CE4FCACF62E5FBDEE466FE64EAE42E0BD5BB23295A228B904560529AD9D2956956245519CF8E8ED08FF3B2D18F876B2698704DAAF127E11D23FFB4363098C1C9183443EEAF789F012E013933889FBCBDEF081121E54174FBC7765C3968198CB7021250374CC6F45B20DEAAC6943C1959CC4DC9CC5CB3AB935B213F335031AF2164F90803134F262C4A5A7FAE053F3496CC541E3908308B7D7552E91FABB2E36A8289AC3D417BA5A797BFA798808A6EA0D730F75D48A53F7B4896733527744D87834D3E1B0758D6ADF2F82A73475818DA39CA00506C5D602257FDC03CD9E297147063415EA85D6EF06A493B7B023D93055ED6B0D664700B90D9E6ADBABEB664E6E8B0B7CC9818A742CCCED18966FF8AD6176FC4790DDF953EC0F44DDFBE492406B7C8F9A039624B94ACA3B578FB6DEEC9D930AEAF0A73CB8AE305EA73F87CB0562F0E5E14D01C523E1F4A2DE4CC24335D3CAB14443BE82CA94B1CD1E56A90C0006E3931992E6A93B0644657A93C11FE9A49FBF3F0C64682CEF90E287EE691936E1FB756F8E9E519912248DD4EAAC9A9D9E6A025C3AB6AFCFD4FAAEA1C171217F704024CA74143766DBCBBE65456DEBB0E62AF3C7551157A5F5FC118BB2D7CDE5A27ADB6D7185084D7852EA1EADEEF8441B83D3FEEDC907A74142B6305ED9F4D287586414C7A417BEFA57793BB926AE39792ABD462D20708A20CEA88619714206A7339C63206AF341A01B3638415BC433FA052910B936459A458E3BAE1675434714E9B554BCDF2195460020273674A2BB03A8D7AED3140C80EF607D63181FD23F3EBF44083F70074413D15EED77C37D8009ED3B98C7FEFA66EC50AB0404849C27B043A0D3C3D46ABB64E5844BFD0B87895A45E4D797B14932F46E87D7E82A2203B0435CF0381D22B9E05C87DA82F2662C6FBF52A3DDCDED7A69E3E07EC6141F839C911E848D78102BE5B1D5AF5C78CE368ACCA0FE0DC8FCB997FD795F2CAD4004B567C355C0FC7FC903E020BE227C0F3F35786EAFBA72396E91C78ABE22B419A41D2C442E65FA6B788B5FDCB9AAAFC31D46A62FF7C1209CFCCAB1B070288CD7BF469592EF5B289D9BE36867707A61EECF3370E61F3A16D2B944ADCDE724B0A6045F8F20E3E775B51E961AEC42B6410EA6C329592ABADE95AE6BA1805EAAF68C085EC165EE525B7F2B3A38061D9A4CC51E1DA8E9054979BDBFA42C34596C9473DCE36F06F8749C58CD29BBFA7E4B35B97F2DD504BB18CB8DF2A377393C5D066EFBB3A3738AA2243DCB8A53A080F331F849A8DB8CE161A4589287BED97C0B98C1DD63E994471204608C4CE7108951AE32C892E07774CD13A00CBDAD2B3F19B3133FD8DEAF30AD49C83BE3B2061DF2DD5A7B372B320C64600AD6F1DEBCFF05B222FD84244B5AD42E47298A27C9FF71D241E5F1BF9ED57EF50BBBFC6F08C283ACCC8A5E9349C46EBF2F5FF6E1F34384F91734BF03C787D012FA3509C6D86AD62947848DA9D646BABD7B0DFC2218AD6D596EA682D2CD4D0FB4B86BB021C641D42233CAAEDBE1561C0FDA2228846647D9706827E77DC34C1D4F2F97B7F071209F0380E64429C65A50FD2E11684406A206C7DB8D72B500961F875345ED98FC4C19ACE6985F0F5E26A2C45560E89D043CE48FAAD7A2C0A257591C6C9793EC05FCA428BC4042EBED3323552A517610765F6C5E060BD8D5B60171DE6BE3131032CADE4B567C1789DAC5AB16A027F9E7E811D0448C95796A032D3DE0A24E8FCACCD940328E514E825D1A97488C6E3F1EFF45B445D56961B6595E2E9740B251348A98375CEAF3E15F3B2E49970E7A33AAA8381A2F905C6F35B7EDF00B6F0375FEC37B91F191C6ED600DADB7229CD9ADA6FB193EC08A4B991A30ADCCF8099CC7B870DDBAB93B6BA2D3A60934113F386A80E4E959FA753083AC47938796B0718768A9DAFBCE065CA0806EF5A3D35829A58EDEA72FA9696084644830DCF2F4263FF3B7DFD4B0C992930991A104657C06B0E423E478162A5968545FACB417110DE7F04D90887033C54EDD4772764AB0AFBFB41B2A3CF51F8A1B9C229039E225278F1EF62AE8972C14AB48FEA4590811B10AE3160D5710B7E526ABEA3BF4AD34A6A926DA5CB5C7C94979D89130D4E9E0590AABEC3BD7C6B91DAD57C23AE342964503BA572C6107302E3996EF5D155E35440A3F8ED5F3CF1E0DBE1B293321346566BB4D6DA3404A154AB2DFB5659DE18C10CCC1DB9B60013BEFBD5B8825CA4015BAD3C053F763DB770DB026E97E88D966A8E3BDE26CCC83D53473FCFD9C426D0B1CFDC48E6047A978B0FF7C87796B816D0E7708490EC3B2DCC39B992314BEA467BCDD5185EE996D4EF2B29F86E4172E34E7E8E3014085158436EDE87B4BCABF0ABA261A21CB199088DBA147B1FE04A31A2ADFEBA3716439C2592823E262E350F398D297D8F6C5C1884F5853A17C6F403DC59906FDD6E86928F7499A8BE3C5B19B4F855D82DF003BA6CA8EE1D950BCF32820BF5B1C272EDA4DACEC3562424011661BD49A4765BC720B68AEFB02624A0BEEC2B7D0AC4468288270C4875A6A042DA5B57C73E9485C89E65A6ED8FCDCBDDEC04350880AAB0546164333929FC002AEC7E232D4BD1932153B69F921E4768D3E0AB607E592BB77A1BABD6D8228EE3FF5E5DEC6DB1C19B16E2B1DAA4E1FFF260AE92E50CF68B05EF51119ACBA9E930A4DF6515F523531A8BE6BADE766F1CE67AF71DF754457C0FA44E2854B87D3AB1CC78AA7D8A39646EB8CC4D28C45222D4ECAAA5BE46E8DD969E8B7A528FA98E893270C09CF0BA81CA8401E993A916B88776754964096D19C15AEAADE2373084574F2B38C89025D66E672AC82C36AA4699F3F6E7E2FC323534BB9A884B228999DCDE4EBCB94B4324D10834EBED6173D178D9465A0922D6996FD9442087E8BB8E10CCA2E9A8DBA7A8DC3839283B4BA8D432D7E82A894864CFBF71D2C6B0622005F4A3D8EABBAAF7BA9E6FD9810CD0B5C029E1E38587EA93E6348A91FDCC59CDAC1561456043A7363A0404C3A7987A2A7855E6DD81BCC6A5F5E58DBD397CD8AF68E9989462A9BFD3A68EB0DD7C2FA9EDE6EAE1F00870C9E5BA78A43D3EF67F989D808E717BABFBB88823F7DA74B670405E5B74DC0A1BAAEBB621E39A77CCE2AA4162A59813EC0C6141EF1E70E432E7CA06D86C1CF6E0DB800BF2A3BB6AB8182C148387ADBDE1DB9339367A6550D6AA9F74D7BCBACABC956523656AA9074AFDEC909FD1B8DBD33D5CABFBC208FDE7BEC77C0083604A1210230705106DE3397AA2A050F2744D9A00A5662A0CFFBF99DA1BF02D743EAACE4B5542EE87AE9B6901279C494118D0E7FB2FAEE9459D48C636F8865FF7D0DAF6B3A974B93A600660CE43393662A84EF498D29140EC10FDD687C1EB03151FB0D3A1D442F825BF9E799E2D15F526C84FC5F5446C5A6527B071021ADACFD8E9F402F7963F83CC28CF126D3E67CBF8D09DAF3793DD3A9A1D12EAE5F9FAAFB760789D17C7D392DC4FA44A2ABA126CB1411A22F49E1FEFE8BE22809003F9C33322DCB9DD6495D2CB56527F16264F77AB72D88677B3EC2D246AD6BEBDAFE6BBBBAA9CA23BAF55B4CB349B18E0F98D7925BD7B3AA53FCE2F0DD0191D2968334E200779B3C33385AC570595311D6EB52B42877C84680E9B84CB676BBB7EC31D5C5516FE05AA4A4426A4053515EB9C88350E20846446C0A3ACCD0DA5A873124B69A06EE4DD0AFCA9317DDB170E3145412F373776051B398CB132FF7A19CF8C4D163EECA973CC927FF366385F6FA209AA96A8CC6C3DDAFB922F674D9B603528525C311A1072FF37E2F524725003DB8BE0A021CB4951A766C14A52E3FFF0BD9D7135D8AF4B920B54795E17FAAD778296CD8D27DCF21C78079F9AC77B60874FF7E9BF75E5C01E0A56FDF0BACEA23686A0F8759246063383AB3EF6A5CEE37916DC43FD616FF71DBD8F9829CEEF90734923DDA673BDD6A0ABCFD5D7A0E47B78330F6D31BD8596020DE520D75DB5A0A51A3C254BA798358D0A5E916B83CF525F2CF43CB9EF9F807FF0ABA6E0862595197BC594BED5F1EE23485D34987E46E543CA707F4FA691E4561B63570A4F535A2E8923C2A9BEAD1048818C4288A8A5674708D8448796E7EB7B84273F9C652C2F539ECB0D2BEDFB3404F7955B7E5489769685DA2929DB1C5435D78BDD32A62549801EE47FAC0D47429EEADF19BF569ECEBE76A8E377C98FFCC6760145E7EEAB4ACB481EE643203503DFCB9D73FE902261A0AB7AEFF52F65452EB613B47B167F3B0BB965F7F9BF86A9FA87B6F069E5605D7502BC561696687247F5FB3C7C3A0483E4FAEE5E74A1DAFE0EC6FE82D483A52C798BBA73E6622AB3A1E67C5B1C550423227FF52C937D3C1B769A350C72964A5425AAE9CE694A1FCAE0830ADDB9765C0F5A1D8C380F6331920A1210C2995B4426627B661F75F59989171A70ADEBDA3F6A68A990F2B770D487F2A0BF1DDA82F3EC7A000BF3833C914BA35B663DCF2F6AA4FF8A7EE928668FF8E991541D6E537BB6BFCFEF031D511D2ECE2CA6D7EFA415170A7B02587EB3655D0593AEA33BD2CEF3FC529EBE0C69AB402F6EF26CAB7EDDA5AFEC2C0BE889D92C643DA69A491384F61881ECF8756B97247B7C00C398562B4FF7940DA80026AC1C904AA6A42410FDE9FB33E62FE9EE3C5AD8F5B412B20AA5C14919F20842BE8863EFDE2FA99AC1B9F240497D5D9AC60844621972C252DB54CF7BB5E83D18A962A53F5455158E3B80876C3AED12AF1E534B008A498AFC84701CBFAF6C4EB183A0EDC795EF640A70C9FCEEF8F7E01EAF8C1C75BE50D877DB85D88E491287A5867DF483161237812D703CAD858DDFA98F0CCA03CF1093A5A25BEDC9E632BA29F4E6CBE93E01E666D47B07591D8E14684915454E6BDEA1DD0911792C5A086093270820132065C1EA1BEDB316F9A6910266F66570733E05D9B80D4B0EC7F26E9CB6A7B1A09BACB0E3810A17BA469BBF18580CA37A963DBECAC76477CBAF4D40E36BB9E99AC6E00406273EBD9B1EA65205FD69FF1C07A36626EE0BEE8C216947F4C3AA594F95006489ADAD6B556D5596C1590E3E45520B5C02AD18A12E679D8429657BF3637FFA848EB948D7A97F0C0FEC8E17CEF03CDD6D2A8206AC751093BFBFAE223CEE098CE74F32EACBF62BAFC18D9F4024841B145CCAF22EF70BEF835CF9FE47EF997AE20413FD88786022DE3B3E890BAB9801A8B62A05D0E3B35A46FED7E94C9F1E533C631BDA6BAF22D5FD49EAD26E5EF867DD37CE6D439ACA4C0751775DE83250045B7A24B39C13B295C3C67275FFC47CEC3F012D40D930A07B179AC2CB194D3F0B200A530BFD4A6E8D954914E823D42291A351C744DC5F1D2B0233B779EB96BE6148A5A0FDEE7F5800EF3EB89C30496450DBD5AE1874B7657FAB91A346FD6D794411FB6E4E93C1341BCDF6253B1FA1431FCB9EC65A8E693A59429F26617212BA8C167246472EC6D903982ED90312DDF317EDEFB79B71F7EE75D5899D7A7F4525C1138736CCE5C3102D1D366B5EEB16449A0A2FE7CFC74765E9CBD969AA3FBCC165C3645F4031BD858A5D50D0FF619565455EE7FB5F382DC76CD8CD6F4CBE96711C6E219EACD7EFC80DF738522EBC1825DB64D1C0E8A872D17C6A2FA4C5713D544E0AF33E09B7AA15BB4A8A1E3EC9F38FFF29CC174221BF75E432B530F56879656519BFD54732B1CC4FF32CDA6943D5B77DF71E3A797D82D043BE0B32779EF02EFFAFE6182736EAC1F0673AAA14F55164DA4C361BB5B00483B6DDE7AF794E9E3683E3BA202E0D4FC0E2F66B440458921EE0747DBC95ADD5594FA6FDD787FA75B0B2AEA57085720C911417FC0C95E6C6871276264596DF60BD1D48266DFCE638042CD9152041413B6A0C63BFA8CDEE7232F85C899B33CD727AF36D47D4D0FEDACFDE2F6E49BF5AEEBC00CE51538D4CFCF6592DF55EEC276F6F129E91F92A63F2F4960CCE258D0262A3FE56E06DC73223C34D53CDC2EF3770F86DF05C4D36310F56E90CF2DFE1E6F24735A3CCA56356AD52653EA01303C6FBB64D5971C394E11A3B16A2EF2343A33FBA922E71B52491441FF492E1E45115A7028F047F2B665847B172E444A90D5BABC0D80343A2FBE26538ECF916F5C3E729684EFF272D5D46CEFCCF7E5E0DFC6C68FC2E1E2631576FC4BB3103E2A7E6D4F37EA503A8B862331BE5FC1CC794D16FBF4BEE060742509C39C79636F6804AB80A60930621188B798BF08519589AD24A6185BFE0AEB7A75E304726FD3D9612604C7BA513059EA6E603C01B0BDDB7B7980F4792F74B7D978453162816029D47AB77C028F9F0E724D27E72994824527E10D8881738FB29BE65F864FB7F54D35D59AF4ABB20297D42B7C3C4D508F331090D08F61D6A57D8769523A958B84B8A6688A442D1932E546EB250846F5A7B0E790A7A1ECCE15C0FE94BD0F3CB46C2709BB39581246BC4E788CD861F41AE6344D1090B04ADE45E973C05F4E1850D5A8F8FEFA1ABB0E6309383DBB02F7DCCC22C5CED01073A132730324478DBE5E4BC09673439C526F137B163EA28EA886E729E9154F6F120C18B90B6AD8AB78B847D681852061E15BE80FAD18DDDDF4D515FB56FC46A072432400507FF74DDF2B4F04E443639DB50DF77B6A6899DEE96DE3C445F193EBD31CFA72244359C8C37601BDD8DE779595E07EA25BEFEFCE99232FA83D9EDA6B481A108D020AD70469D90115592943B8C086122DFFA98C64AEFB8827F5D65D658FE786DEC340AACD2A1841F6EAEA12AAF76D408FD1753A993DEF24D0ADF21FA180CDC43690D1E713AEDBA7E87902EF7B417046EE58EF550AE7499EAF67E73C78347AF156D019B0BF15D49F89F713C1F29DA2038F043F97401CE25E92BBF499FA2859A8DBDD006823BD48A81B8B77AE11D0B246CC9826F9549DD6F1B026481574279F6DAC6B536A73A2D4FA70ECA61396030005B0F851015AAE8C09D35D05D430B86089D8FAA70954BDB98DCE44E202CE08241EEA3F35F2FA1781C63E83B2A213CE7E6509C61A2A5BC2878B78254CE5719F5BB23B6A3102BA422AC30D7F3DFECAAD25A6E080399053547F994FF17360F31DA9EE4FCF6443DC2BA612CBCF754B5880CDE6FA9913196667934843B980E814F3FE80708FB8B590323A01729CAC8F7CFCCC5B09813FBF37E6D2F18FB0CE3ABEA51A18C7A1B533D074AD42D91AD8BD1BB7DBF358064D21243B5431E1FC51CB0C808639886644A1FD12B1CB00C7703A618ED85CA911F2678348CEB1351BA6DC228B94C2BABADA3927822A1938AB12416542D1E5A15D1877EC272DB78E6E4FF431C84432F08E7F9F2111A98DA16C557B326F39B59FB2284F7D8944F9A19CC206EFD3CACE299E1F1B87B51F7143EC78E0D7AD4DF266576C23D7F0E2243A5E583969D77E65462C51BA864AB08922F2E7E62BE43060FB93038636103AE280E71AF57AF759EEFA280F9892D3E014C0B0A2A3965795804A62122BA1FD3AD6E2C80D76082AE46BD37E06B6B7E0C2738F01B036F5876DFA972E94DDDBB9AB1ACA7E981ACF211D039791DBD454E86231041A151605D29B6047FD5DC4EBE9F9C401DFF278ED7213994BC8FA2CA1117E761EF8AD7BF8937A6A34B618F4B8324D498EA184A56447FB504909B7E78775784C2C10C66166E9187F3CD9F0F332F82CADA80D1A4C4078ED6340116DA283082E6731577601277919867C7D4C86792A398E000412F53D5F35F5E6D9194B4CCCECABCDF7BAF8668691858498CA020708B204B6B05AE27C811C35523F84579646875BDAD67A35030331EDAB025F893C1CAB1796881991F6252585C8660599DC2ED239AF950D0FBDA87E5D153961C74DD3283115F132F8E4209A2A90C26AD74CB3B5BC19B6D3F3195479196411F2E3483D0BA7AC3DFF5C83F45B1DE640A01EBE92CCE8C889C5B7B145D32034F16167E97F61321FD0220A4E8526EDCF048564CA5DDB3026E5A6743458A307FAB58DE567C76D87964DD65571DDA8A30423E9325A9472A9030B5FE988246897D019D837F06F467EE164A7AA16F8D1241A2D24F83B0B4B7D1DE6A685F06E3E07B8ACAEEA11D22699C3605040325E711CE59D60E581BB069DD3ADF95EFA9A254735BE2840F63F2AF4C28FFA04BB267832B473E48F3984C0A250676B43EA49390A499D79010EC7576ADE9F35F9534FBB19BFAFDFB1C409F08876BEEF66ABD4D5F906F6338D497E9BD5BCB4F2DCF68B50D86D98C524CA309FB84B49D52D38D32CAFA1CF472EBF667212969EACF0F545F08FD67F3A4BAFBAAEA2EA20E9EE0D38F1966E80C28979E042AFAB9932C506E3E921E5A37EF077264538F9E06137B83B1E03B095E4E16BF7434294028066AD238E6B718DA27728DE073D72B05F77214032278DC537AF5609BC631D0EF1F8CCEC2A30319A5A1A330F283F54313CBB045B9C5F1E44E61516BD383E0D1F8A03780BE902362AEC99C3190BCB2FB026D641B81A976ECA885300711BE0A1A91DB035FE2A3D501001F8B9539589BE455BCA42499690B0F36C916F2BF33F275BDB0A723F4D298DDE4D87F1E28A4FB74E099CEB13F5CA46165B208EE127713B054FAA259F4B02F94642D6F179B8EDAF6AB977228441949F438536DA3748BDFA283B4FA15FB4ACE2E70F236DF417F2019AB495AE80688C1DC8375C31FBCFFF50802625461DC77D4A2B36D16DE1F7785EEE8E9CF058FBBAE519959357C204DC658D773DFC67378870D862053396E8B96C194D72DE780722CE6991637B923961BD5324DE97F3AA9D41D284F9389F1CABC1DC6FEFFB2358A70A2B9A69EF93C973DA42943F38B0E151A093550F01A53F9513E0B6050FB4E784DEFD737C0247ADBE2FE4F6AD7F87DCBE89299FDEDC808715651263DC4AA249182F9CCF4E905DF1DD741A98801D21FC582493C5078F7FA8BF46C356E2AA824488703115029994BFC02557AA049946ABE18FD0E9A2E8A8BADEEC1650660D12FC9B4857AA90BC1B86E85883B4B87893F0EDD03B1716B69358583BE4CE47621F9D109F9518219F3FA4B8480C59F325322227007CC0B781E7C50C8B88B466E0EF5E20378BC546936043B323F380E638FEFE869170130BBCDCC7F4C1DC5B45462FC4902B1954704C011682CCD0F84BE81006876B8DD7C6AF5FED85DD9A3C3C17CF865C887A3A4892C718A5E7B8BD1F76DA84500E2781FA750682072B45474A09D9F07CDFEF25B0ECDB80439C2A0FBEA943E593E309F3514990B26AA52086840490C54D866D4B8FF0361A8E3D7C5AFA74AA5DC25B86360BE79D37BBD66DC018DB96A5041A555B88FD1005E2AE7AEDC7CFCEBE7CC6D46201A2873C803560378898CD986F43F029F1A9E452454C524A7CBDC52ED1696B5724769157BA11AB38183D24071579EA78C4F1470443998F95A9BB912DA2E13AAF1C4FA82E1BABA908EB9BB5F3431C6A6EB1BB45CB9B9D5F123BAC25EB61BAA739E151D8A1C032700474B93DA0887658F6AF35F163D993A51841D30B6B57F358C5A6531B46E34741AF6C4E2D159B17F9CEAD4062576068F02FD40D2FA2D80CE57C77C92CB7C1E62A32BDF7C37BE316FAB7AEFDBDD36111C31102C655928926D6E1C9B46973E046D6E846CDC872004EF2BB3DD4B0226CF788E9D8FFA2C64709BE27D9BD2E6CBF18FB0871D6119938EE1B90556438AE57BDCC96A058C1CC88A6374AE50E88A9FE93750521468F45B40FAB72FD375280148E3911729AE393F31CFE8C2917EA39240EF0A285CDAF657E202F7EE1C679E268F01856791CD4A325E76DEB894A8A194773D14282EFECABFB8CC9DE072DD0C0E064746F07EAC1F470D5F545A47049D4ACE77AB6CD7B26B8CC8FB5AAA92116FB62FE274B44798C0B79EDFDABA0BE0FC83327C09138B0B57BEF8751DEACE5395E86FFC3E45D57F6338DD6E7D1E780C73CF455CB4647E661111E0F60958FE9DB255F858956812E2EA5DE95D5B5AB3F75F1052D5B39BDFCDF02F15DA6E69063B06446ED361A143FA924096B4BB7FF27B17A6000589329C1FC3DEB4CFAD193C1303BD45434BE9926A8B91B6AA3A46C5BC714432B518E62802B7789AA75519DCCF4D513FDA5CFFADDF4769B7B096CA12C0DC084CB1D1BA79692D73AE5C37AD5CF21A2ED1353263205064E5A728BBBB4D858D1A72EB6C59EA1F445673120C9A62E13C7F890955A8F77760537C4D44C2D4372C5C781B854925E73CBA220665D97D7E02016111E6906BEF0DC0D099C40044806CADE49CCC4C0783C499B9E7ADD2C8C7D8979C3294B225E80127CF536B635BB0E8AFB86D8328C535F884FC7145993DFE00E8356D92077421A4B88FACF567E86B04009644E27402D57580279FF35D9EC968BF3E359CCE2973D91285C15D258082C086D3DB4FD3E7C3B931CB03EC3B2E9223592B70B7072B63DBB590E54F09A6D81167FF65788209B509250C713B3A59420844D9078CDF9775B2505E1C2E01E4172AE574E4C3C38BE68694CF66A757CDBA7981F8189C21FDD9B3DE534F9538554273CD097813CAE090A0E3F01860750ADE03A0D2FA8A995AB94ECF6256288A7FBFA955EFCD1424030205531816F5D2CD25360CF62EAD2EFBCD8CF3203A39FBF5F24CF478A8D56B1F61F27AAC90D179602E84810415A3A3E9C1A58C2A7434D431A83B4456A55649CF8F005CDDA7E7962A4B011871540EF5D9FDB780BC5E4F992EA3CB70C3D47F590E508C8FB4FC7C06B5C25ADFA61479B3DE8A6BEDF6E9740FEF1F2B1B28D2DC25284277DD00C7EDCA0AD91AC1B316E70CCE3F2816084E369F973AD6050D6B464C16FFB522609473F9AA9AFF3FD3F3B1CCA822113EFA419E69622E7925581651B18BFE7933B5C83979FC250C37B5896AA430D1A2A6945BEF8DBA36D57C058C44A58DDA16689952DFF0B7053613A50585B5BCAB9750EDE42B39C7576AA04D8538CDF5BBD854968CCA4E0213C90B807797D2131FC4FFE6988B638ECE3F936EC05145165A5265AD4168C1914F22E8CC02A3BFB5225104292832DE4C026890D02665533F4230CAF5DD27B4E4E4D42557A74196BEA35706E4F4E36AF1F1D77AB45209EF9A520FC8208A991BE84266FC7E5024987B987D4B07D85479F44C2AFA7B70D79F601D2DD20619D60DDE3C2997947FE7BD08C1C0A0119E042792B45B5BCABE5412D014AFD7F40302ED858E4C11026466E123D1BD5FFB30EFCE8502D44C80B050B680F8792A2B9916B94F2AC2C27934F0FC66401B1C9E153AED30C0B489D3A9A0742D9F42B1655984AF73568EA58A007E7A8DEFE8F9EB40132BFDA4FFC41AE7C6BD9F3FCBDD51FE79FE01CFC9803429F9CDB651CE70F84C9F7CFDE34985DE4ED19DCC204757933A05A08EE5F341ABDD5FCF2B54C498825861F3E04BB7804EEC3878C49E341B42455212D810C565849FEB6805F14BC93E93D8FD3F4EFCA8259C1C61F769CB4FD203E91E9D4D23AD4877B1C704091ADFEBF54DE2BC86E6BA5AF19683F296CA186CB88E3E3350D4FBE1B30774A79CB161D4915AC86A13B2E745E48C6226BDA62AF921DAC91CA15FA8823D165C6229E6FEE6781BEC321E71D09E04A72B46BAB16501AAAA835DF88A80CDA893309F5DB4B019831AC4AD4CC92D75C697A35D35EA70C461E400EAFC26545DD6773F93BEC53F2F4B7588C947053B4871EB5733E290CDC75500F47AE2A355C66E21EB6C683358DC9E9F521CAAB1E9CDCCFDAF73CD3082D84A0E79F140131A29A28D18A5CC9504B60692AB41704AC30824F1C6F959E99E0492C51FF1CA6E648F4E03D640BB5656CEEDAB5F87A88A4549E30E54AF6871322D5679513791B2519007DABB3F5D18E092AF1DA2B7AAA6EA4DCBD80966C64CBCA01DBDB1B1FAB23521DF0AB077D65C3DE3C63725F5CBCD94DBCA606A3B07498919C542E393076140FAE67143726C7FBBE33C53C9397BEBFE611803E0574CED573B69566D22A89B5F4878F594A0CF787C1AB86668502A461A39EF304F1E033F8C54FD421F2860575A088642268061E3E45224F3F05040DDBB37BB470AE86FBAAC7798DB7B160E9C82BB45A7ACABACF67267C2625B892B9AE7761F7C376412F782C6A564C3C6D64C12992B7DC4DC62D062E221204B7CB068267CF6C744B7856DE8173937BDB12BDD12098FB197EA8FE72A6EEC015698057B94B8EDF88EDC4F37436A48014E8B06DBE6C4EC6B04A9145E9197BAA0AFE603D18AEB85EE5F643B9C843260EF305152338A3AB517DC442F90ECDB678F22077C243FB8C65751E11C102AC930D192B49930DC3E94BE94BEBAC0C1C1FC64A236BC492BB1C7243F322B8C420258D94C606BCDF4E693C3B7965CBD83BA66254BB6CBFF259EC72D608C99554B54E27143695F3677BF6FC94D739B351772CADCE4406C38CBB7312C5CFB28BCABC4B8FA91226F034A5BA9C17B39C2C7D7FBAFFCFAF08D1A8BC209C59E56218B3073CF04B1FE829FE31D4C41FC05BF78B78B8F20CF76D0F6FE94D048C0588747713A6CC25BA9553BDA90839A74731AB1215DAFBBD29FF21B58EFF47EFC548C83A335E71FCD2E3F5376A9726466A0962410BEAD4687CA705BEE22CFC746147E50534255B94F4A8EAF3B20CDA2F706050AA97EDD1A103432AE711532060901A8324B39DF8C8E86D8C8CE9D0AEC799BEF1CA25F28BEE7CDCC5AFBD7D73F38FD7005E0316B13B656A0AA35266DF2D6E813C2E87FFB0D80B94FC91A4C62F8A2C4C9ECA92B90B5F82A757D05BBB1D3BDD09B53AD0523DF91CDC6820831223FC095E70B008683683A31DE1380D895D53D5471920F1375B9491AA1F80090A922DF12D2BF0649ACC4188C5E88DDF9D33C9C0F43178FFF6557479D64AEED36E43C192114E652BFE5984C26C95C694789B1AF7D858130A4E4A0EF2B044D7994784AA4509BAB9DFB2887816346AE1460E270A7336C2367DDC19A5B62D68B424CB571154A01FC82200F0A8309458EFA2E45FF8646FB73BDB28B174A6A6419A0A7355091A1321A2F3277310BA5C926CD4A59C51FF242C4B6D721983B590A5354E3482F10F03E4AD5372F992A34B20C2A108F54FD40E60639F838B1A4345801CE3DDC85B3FB023046481E3E1BB25B7E93EB8E821116C74FE6B233227D65A0299C3F4179AE3BC881CD24520B567CCCC135C41A13C308021679278AEBA45856B4B3667315B8CE55AC6C0CA6313F6B900DC47C2F5856F96B0E4DFC2F9A2F3B9E3A8F7F575209141773D89DFBE0CA3DCEBB3A6C8FB0A603E1CC8B45116A26D76E842B0EAA6AFEA1B5A5BA5EC4DA43E436AC20F57E2384E2789FEAEEFCFC7056F94D9102ABB03294F1100DEC0AE1E08CD3CA99F8445923462978A918624A16B1BFE45B09158DD73B424A5E2365D1A2761E9A9359477D61477E926FE9893397ECD79E9508058629642D863C28DC5DF180D3087F2AAAC05C3F82706560C0A28ED6EBD6EBAF98352FA36DDC01D9EA67104688B348114EF1233AB1A579D35B7EDA2300164207E3E82A9CF69495E1224DDC9E5B1DB160A6ABC793104470A560698F529B88053417EC6B4B19B8504B0CC1A4A28BA0506C8296D382F10C8998EAFC45B7BA6B35C4EA5C19E31D8C37F2295E9608E6F7DFDE281AD525565DA6604D425977E25CD600A5A361033A60FF7F0F3D159AF95ADD203DDB4B7A347AAA05BD2FF7FD20B18FE96397614FABD602E629CBF59D1210C3A769F37462A9C144DD553580A413DDE65FE4B81CDD3D26BFB28C63FD5529598279D2A7E3C6AA9715AA423D61A94AF467CECE6419C11CFB1B7425AD9EE0A5F522F8A160C48F0E8D2DEDF16EDB5E77865400E48D803A6C831B8E03EA53D805829748BD6404C590C544F929E5213BE0054FA9FE92BBB9BF0FEB8E0440C8091EA31E6C5012D9AEB548DBCE75B68F6160B756E4AEBEA0A90E54D527E5DC590646B31EF766FDDFF2112245AEBA172A63A3C2E8E5D5C8EFC7A36280D6EE3BC3DC7F6137B276FAF1171BBF0E823DEB163A47FCC789B854E570B7ACEC862425630EFE7B0FB3A12A873D5390D953B8705817060CFC1726100268B33EE0C1EC56B620A327C27403ED44DA282BB1201CE6B08C14B7E7F61B6FF78E2F4C58D2AB6A24D2F7A90E769B716F8DF54359EC04967C13C3549C44B766B9303D0BAFB43EE03570DE0335F2B3CC0EDA1485C39FD890FE259B802FD6E5BFDE6389FC0693BBB10A9ABF66A0E5E82EC2A333356EDB4528A50C11FDA6B040FD9F406675D83F5012BE6D3F9265E1147204129AE818C68997F3358247F01D419D5ABC15448BE0E0F324C815F24FFDA241D3858EA455B639391234975D3D864692342E1FB7C58457B68AB1D4A00F8FD53168C57DF8D87279349867B13CC39C52A1665675A9493BA98E95AFDE7B1002FA75976E637A621589DF644DE1117C8D9619B5417CEC36501FE39168480F4060CB9A41966900CB258C9073A94C94A32B326E7A4CF86CEB47ABDDDC60127741CEEBBB760D5481D586BF037482DF6A3BB70BBCE279ED5D016E5EA60A5D0291E3B450828566FBD71235125A23FB49904B6EB1ED151E9E1C3D2777A8DEB8387EBD28BDC5FA0EB32BF60EE1A20C7043E806400C043517A7EF7E5FDE848D064FE487A282B7FDE277EED2EA9A6C81872EF32B57EA8AC7C8B7D9C9A4A0B29A0DF38DE0238783EED63B60DC6C346333A1ADF9D890ED8DDA3E9FF9F91F7C914A3CB3D614CAF5072C4191775A2B0C47AF29556CFF7B2D69081EDEB764A7B470AA21E35F4E48238A0FA70A8190B814331956A9711C5A50D635388D948A2A58377D4478092BA145E4763E47810CF686D4C0F9A12B53D2CE2B3F8C193E24C24B5520EB3089F0AE9E703BE3C1CD1F0FB3C548508A8AAD67312D3D07FD8D41678602CE81DE8A7F379F3BE90032F1280056FF0D296E6EC30EE275FC0FAB663A90A11901BB0DEF2AB7760D1DD0C008073905D8F4FAAB01987830B9683F4B75CF6B4DA5824F133FAF6BFCEA3C8F73238F928D84F4CF9F58F861A6AB8ED0E1DB3AB8FE9059C33531AEEFA7A94FDF56DFA7EF91DC8AE33DE17BD16D396AAF337B59F35D4F3BD661A053012920A89D21AE2A77EAC870810E3ADA6BA4FA02D9A3D9F8B3406DA56F1A6E49F60B0E25CC0B6CFB558577D57B388BA381494D6884AEAD0175BD6D6CDC7980E519FDE6AA9F23B8436FA865351BD6BD9C3F48161765E477B84277B6ACCC6F79D5D854C9407834E99D801E69610105EF7CEFF162C97B20A2B8F04259F33274A1BE2A5C7E9263535A5B1614B1D2693CDD3C0B5C535C31C4C90724C8462C4012290213E477FE2DB856E4D45DEE2985C5D9EC580F248E795D1C816598970631AE91338EA86BDCB3280CB7EF76C470FDA4FA35FC96E253DF8EB4FBBFE33E2DD68F2C51B7D5455D86288878F34BC028D2BC42DB3FAB751AEAC58BE97D0631F03DDD1868E71FEA2D5D18D36520BD8BBC48CFF3C7AF3034D8C38B8651C53E97218A1AFA32657E700C2A527408C795F31E5346CC09305BE40AF144064B0439292493B8C72F2E150C8E2997F0992B4FC7865DFF500BB9C7FAA9CEC9A39FB2570C1D3D118A8E8A869DBC2111660A289246E6B0273E308FCE15E0C7EA71E0E00959A35C452E8D4FEFCB5CD1F8344CB44A2A93D2DE015F2BE3350FB5B1534FABAE8376EC01CB274E9315B8A71E12FE2179966D7A19ADA48315E3AED2673746A59050359C27CD4571A84E6D9977C8E604CEF8EC53F52493FBA8C1057EE0168BB7FE35A5C9111D932F497DBD0C5567D1242C808C4416D81875BB91823DD7673EF0FA35D2450BC2998665E81E3386ECCABA52B86B64A43D6E5AAEC27233DBBF2C76D94310CDD1588026304842EFF67CA02BC0A16B623A9589C00BF3E82D3ECF31CD0C173B252F859141D04BE0F2456646F46B29AD33AF743605A437321E3599FF31ED670C4325B26CA3D1F70D35754D9BE4531C42E950CD539E01BF57959D587A8C393834BE90E2E341DA46384C2A23A7456518C4BA5B9C1A1D00B4231FDC1420D303E047B1B44732FB1D095C8530B2151C84D5728D3FFAF2A5B7B5A6FF6E78D94D90372E669822464D659DE908B2B1D6168D18C9EA554AB3CA8AB5D6C70E3AE376A9B6803D77F05EBF1A2E5D81ECC3998932D65F3E4EA29908D0A78F232D5CF0882FA5B8ACB2B798358B463DECBF2615A4D934956E021A54E81D1F5C724F083C7074BB13720581ECD6ABB17ED5D3453CC0AE2EDEFAC2AF2E95CB185FCD1F6BF3548A90DBF1D7F998E761C40AA581F7E3B5DDB556FBB125E9083F2222AFFE763412E166632D31EDA31FC072330F019A27AF6F82EA8B8256295F401AB8B0B6F73EBCB4253B01B702BDD5998C7E65D9E54FF578D74438489610E3A1B89C7977182F8DDFFD054F9B1D4338B7A6B7A65C16706AAACC3C7AA1A44AB6C06642414691DB5148A12CAC44EC75A612F9B238DB12F0F16B63827FA2739B27EBBE433E7C93EFCF5516D37284A94B1D94D6280D8B966BB910B32F8D52CDB2294DE313F71A8DFABECF98F9E9585EC59FB46F968E29F0A0D4F96BB3D9098EC776BF6592A494161FE9DD51DE4003E207B631F4B04C7FAA818AB542E8CDC8BFD22417BA116EDB8D38231FD24CD6089A4983FE26CA138A6BB379F94013434ABC8D6FCA7D5C0096D309EBA9548207090496D81D54508142E88A203FB56847AFAC1517F05EC6D54B25EF03D497C3512AD6114C4FE3C6096291397CBBFD4BFA0E9B0F0F1DB8D8BB5DD85E859B89C2F2DBD8B2E2728896A14A9203CCA527E518177F7CB11744909C0596966585AD81E073B7C86938C811EF4819B4E11A99C714951FCE7DA8F2E8AD4EEBB1E0A78ABF436F67DD83221E0A29EF200164D342CFB5CD472FFDED79E47F23C530B899DAF0C26FB10321D1167033F7E5C1DF882725ADC1670BD55928D8C94DF6289D535D909FB0241DE2FE0A8BEF1AB50CDF7539915977188BA27F42492E31E099643467386CE0E829F550AD70E1207D2E8953272647EDB014B0EBF9D9CD12459B7675C02867B33A34389415D41A8CA90D547881D424AC14527788A4B44347BC5D3521DF99BF5FDF1B8B3F89A4E5EB540DD798E0F06321513DCC25EC5F0B1465FE391C7BC679B8FB676D127D8BC49667AC7C66AFF49231980C792D58F1B6AA3138CF6EEF6C016A40E90F90967FD284F21D9209BD75095315173F55FEB861138A9C5E2A72BDCB00C11C8C13C4E2F993C414567534669F61C353C20E893B25347664662422361F97954AA129AD5115DF67784D6C8387C8BAC79888B935275C76DEDC0026F7A23413FF466ECE1E517D34D643F6D0CE1978060244945656E686516AA3D432B51F20F20A6FB6A942DA8C9B38CE2C417D21B7B67FC9F0F9974C96733565083E2F0855C1AA4EDE17C82AE678056F2EF1ABF1734B6132967B79D5A303F29F433CD1B7C7ADB066A865F5F91ACB6507B970EFDBBEED3C98626F260514C0952D8000CC4268C49387A41B157B59EA08EC0B2AF085E9DE91772557DB769AAC4CA49261B8BA3AE2DAFDB902E55324FDE7D55728580FDB188830244BE607B31046F79365121717543D60A9EE6FCCC9464D65E059C16F8B359448C12ADAD3A388CE224CBA12281C722F72475F4D8A5374362C196C738E09C3DFFF9CF81132F3E7A490828D4EDD10E7C865CB2D89026103186C786EE31C824EE40A27AE73A0FE47DDA16CED6EBDB1DE5A7A37B2BC96425DBCBFFD337BD48CA1A71185CF21F3102C337393F73F2F207AF7B4BCCD8961FD064BC156FEC4684E7569C07620B1CD2FA071884291DD942757E8CABC22A3DF993CCF20F6483F874A68A6BDE05E93EB22D298691BFC9BE3B043E5C48ABFCC3395144E8B354BC4283F458288CF81FD", 
            32000);
    }

    if(strcmp(argv[1], "sm4_ecb_nopad") == 0) {
        test_sm4_ecb_cbc(0, 0, "74B0DC5119495CFF2AE8944A625558EC", 32, 
            "31A75DA59AFE35A1B82EA9109BE74C71", 32);
    }

    if(strcmp(argv[1], "sm4_cbc_pkcs7") == 0) {
        test_sm4_ecb_cbc(1, 1, "74B0DC5119", 10, 
            "86B0FBA90E2C04512437848A6987C0B14E26E39DBCABA44FD7F2E48627CAA32388E55AFF6740F4D46A7A5A622077AC2A64B7B91210D2DF6AF984A7FDEA29F7D467E9109DF2621972850551425E70A7E1851F8A2D76DC630EB948A9FD0303BEAD36BCE96723AB79E8F3EC32C8A26AAA80C96C93C049F80210C0EA9C25CDF06D6EC1A5F18A70EEE4E0D44F5EDA483033B9F6589E72F3AFDED9C59F0A35841B14B551C0DE15C3A8F3D18DC4E32AB94798001637785ED9356BD2DB9126431E1141C9617CB2F62980C8E5B81FFCB4B316EADDACF44FCB27F5390052331A7D7448DCEE75562C0A46E4BF6ABE61DD64FE57F130D05972447EBB0F55FCD619D17E52D6995B84655F0C5BA60612B090811AA919EA5121649E1DA157C153324D30C4C9D5451A9954B219C0819DE50359825AD61E7BF4814E6753839BCA46A0225151084B5A805C2F27C63CB02095B5AE214998BFC923C8AAE8CD05D6E4E4F61A05D53D82FEDB4480965D83BE20634A3BDD4E78976E942BFFEC4F20E11B1908B238334D72F202B48A67A13AD77F553AF53AEA2021D62E1C9A07CC42388DF79E54089F5DEF690DF2E7F1AE81888A6738E4AFB487F8975E067A0A8275C449F9DCC15FCBDD7365C2EEF2D7B5484BBF7B82FF7F3EF7ED8EAEC7BA4F9A236C2A86EB7E4FEE34637D5F78922650920DC78C91EADDAD8DB8013E79D6763E965380021300F4F4DFC24235EBFA4C8DF5E025CD743D9520624236C8A6F0142DC8AD8C816679483E3659C6E598B50551333F349F32CF406917B74D05EE62C9DECA5D1E2B8A9DAE6C89707A7D746E713A80C768EE2D6EAEF6A3CCA7734A5F954C83689278B7E9B384EE2A4915D10F6842717E0A73BC31AC8CD899CE23BF95B6172FE376B232B6D794C6B5B3FD75C554C68056BC838FA814616493F06FBAE5EF34522FD0D1E8F15625BB7B6A8FB738C232FC7D8D320AE2FDD10A621B50D3B0016C3BC5F4E03AF6CCDC2C44AD31BD9B352DFE6E35B7C4A37D78EB0F4DCB8DBEF88E401812CD354D1838DA09C654ADB27AC189F5C1BAB436E3CB89E7E0FBF100EFD0F8918E283549AD9E2C11D1A51E040B6F0CA6C34F8A18632C76DFB1A4ED21FE242CB5A09FC2AAD64DFE045617D0F40F0CAFDAEA8B4FEA84201124F1F770E3C4AC89A8226395E265C4C3D3ABA700E6CEF9A357F6C8DB579D2A7E2E8462EA2C1F95758A4A59A3E556A277975DF89947D6CB82CD4825B8043F147EE502DDEE6631508F98921B87BA80587C1DE2E2537F1D4C5E06DA02ADC95E5528757A43CD994A5D92BB736F262FCB065567FDC0AD1BF91D2CE1BAA756D41078FABC9DAA12999612A917BD0DBD5922A3D15652C923BF1C2D38F770AFC594399EC5F2908B2CCFCCA4917C4D61F01B8F278FFF73E7F59861A2DB778318B7CD52F45416ED8D99BC4DFA66B1BD96E2F167A4FE4A46BED3DD74740B3A72B7139E51A73CF6F9F8204378B6CF69EFF736F681523C1EA98C5B293CF94E6A327546FF3E89CDCA7D6FE46168F25295FFF04245B398C51C2789EC1445F08408299A939627373A793917F63815013DCF0C2A3C3D1411430629436D123ECEAF79ABD4747FE798739C44EF2F17F13F9CA106EE874C59A0DC70B2CA58DF8C699D5EDC59C9FBB50134CE8B0E748BBFDFCFAF164FFD8EB3162623556E58A6FD63D69BE80D1147A6E8A31FF1AB8B4947959C5A657832A49212FCF8AC737BF2FB50D25C10ACBE968B8A5D4E2EC72CC7900700F3B0CFADD7FDE24AA98DB9295DC1A015B8D113884ECFCF7AB007AE23DB2AF1F361C17F06AD796321452A8EE0325B6B4108C900D7113EB4A66B9BF9549066CEBB839D616ACD1182A5E7DFF553880F6C133B38A06C8B097BE65E3211DAFF6A7CF5B7954C5FBBE58DD00034CB6172B168C62B1081278B1CB6F286814FA019245713037B2CB10C054BE9C884F249A9B32BA29A47118402867842D5A96E47E6B5768AEE49E0F421DF6A6B25623F7BA07C41EE1C07C3FD0179B6E9B211F77A5A5D2B7FC3E085D83728923A8146726866CF571C759A44FB8324F84109D66FE6E5FA6DFD875128F33A5CF4D103B82188F8D3081AFBB014BB5031EAD9255CB64349122253EC61C3E44EE2F5FF7718403F156D4CFB09903008125A1AFDB0DD3F76C80818BD974FEE1192DC618A9AB79689E985E6DD65022069D53176B8F981563BAFE875D6DC887234A4E83229291332055525639CAC6A867CD368CF2669327C4D188C9CA8C65D9CA2438C8FF1D1C31245B468FDF9A833724AE2D0AFA241398AD584F2902505BCC004C669521C19F275D9530537E9EED4D5B7E15877EB5DA6E16AD8E967BF2898190BF77AC9533A9319D6DF803E64575FDB671ADEE2C01F06FFBDB2C92BF90D71338D87067BC5F6E9DF022CAECEB06DC280E5674B733F2259BD957254F628AF8AD97196D1EEE182277F1733A96AA667BF272CF38E5958586D3BFFE60A71E6410193A99216B125538FA0420DB9E4857C07B46ED1F5358ECC3B109F2164278F87DDE08E9C111513F50814354597C3785A232F74236499F11CFE9B181EA66E9E8751F18F6E8DF424693EC7E4C6C821D62F7DA03CA3D58D82E216969DBCFC6A1616F40819215D3ADAFF915B34A3A1FF98FC1C6BB83560718C9D6C7C5B05DA97EFFAB3136DFB16EE95A4E9BF890CDC55CAE51D0670EB64FD0F334EA180486B2869ACD4A950FF1FEE8D0AEA8987961953EFD83505C86F793CF4854E6D7C64862E334345928ECDD14928926D7B4BDEDDF521D0E6C1AC7F3AE213748810B4A69CCB96D4F8D45F2CB1E335128B482C42BCFCE5B34B5FAA241349970E3FB14859921671498AA2D0757C714110D00BBAB318159E66A730FA6C55DC72FC3CE451DAFB9F2222FAC1B465E5EB684951751CEE55F611334A58ECE93FFE577CB1828B1D4EDEEF0D777C1D664A0A8ECA81F4577B00518FCB2AF0E7AF804095F47167D3C74383F7D221CA82E2E9221A02E01262F9F63FDB97D3F43DB4D7C4D01D7D0C402799CE30483A76385FC013882D801EFE64B6609C5D889BCAD48C76D373385487F550ACA23EB2624DD54005D54270F77A20EBCFA5FE35908103CBBA4E9FC035ECBCFC7880DA71663A005FF3C79EF483377E8071CE1C0B30421FBD99D8A1A7D8C1CDA8072407A43F55B8429FC70CEBC0B9E99D329913E480D7E2DD45F23EE51ED28671A0701805DBF1BB10A80F78383DBBD3D40459DE4BC8428454CC1F6316A111800F4ECC94A4EBAF8680A011FAC0080DA71E80AD22135279BD584A3E3DFF4216F06E6AD3621AA037750188AC8C30947FFD285ABAEEFD7F13713016DFB35F50E095EF011770A89EB84D807BE8AAE80076339C7E45DFF12F868C740468FDA9D945AA1E6E6DE73136795C5349C553A9657E3132E70336DAC84E24E6F7408A0ABF6CAB7C9ECA3272BCC7889B03F0D691D15D6D58C0891FBE540F6F19B28FF0C82011DDE09EE96D627B3BA32B9C12A65A8186114F832CD9707041876AF86B331700F7D31878D8997674FF8896ED975FF2CE788AFCCB4BABA04E018075659B41DBBD510BF23B2EFED38C4DCD45BD1AFDA521F9EC1FCF3D131856677D64CB717264915CBD2FDD152C7E2E5554A0AACA88958A6926E0CB2A4857858799F3EE8AEA2E18CF4AD1D3C79A526C6120497A39E00A8F74BC10CF93E3BEDBBE337621A144499E97B16E8095AAF7F938650EF8B1E76DE86F83CDBFAEF13658B9294A7DB9C61611F0850A4985132632F279646486384B56248C5748F4B020143DD330991B9366E6AD2943A3478BDC8EDB677F4658723A6B565365D79F03DC1AC6307ABB464D241C3212355F933BDAE55E2D0373ADF0F79FDAACF2EE9F0A837ACFDE0549172F803CFA88E5F2C4CAAB4EB9F4C874D77F545DA20FFAF3363E8FF949C9808804A91B58486011DDF66847AF08239CB9E31DF0F5A7A6A86ABCE4158F5271897C12CC981E09DE4AA0C83A33FB4342929CF81CC2F6218D930382AB12846AF39378FF3E6ED6304A9223982E7114747F729A6DF9A3B67AA4D608547B9E180D0DAB592A9F48B53ABA980F85843C7E580D118C7E7D39143621C93ADC0D71613C61774FA6062087319360F9B7BBC31B7099B8B4EC5BE7D93FF3D949B0B94720C6BE462F26FF1D2DEF89E2525A254BC0FAFF216514C8FCC75EB6F21CE753A391DD6E38D5E145D842ADC158EB9238F89EB78169639328A7689EB4A639BC7C4F9025209DF43DCF12F176B9E83D129A67740B3CD5A0F7F8A08E354B088DC0D32755E329E81E0D29AD46BE4F0130E49D56AE93A89E57EE7D27CA21907C75F2E1D2D7250A7FFB7CF70FF047F17EFE78620D0C75D2D7141F2F8E5A0F04836A7E9950D38DA3F197646033849B6E27AE7F3EAFE3C93E279B388979C6986D6DBFD2ACC9C6569E039D37B0CB6C753A3F38A93ADB763D8734CAFB6C846A683A92FAB8D76331189B5ADDB48ECBDB8DF0928B9D70CA338EE113030B95D49921B4DFA2777D82CD9F2848173427B4B60EA208805A9424836D3C8E570FBA3DDF95039FC498FCEBD38BE22E056449C8ADC38C1F062A7FC12B5F6DE28F13E3DF7D5E4B4554ED08169031A2BA07A4515B99486CB6107A3DBA9376BB76EFD623A28F0C514575F900A9C70E10F2CD7E9285B5ECE24B835682803F052ACFC14669712A4EFDD92BE29C63D4F138D8517CC8BE647A69B94A8206CD2AD5744E44083A6E655AB51B234051D4D4A5DEA24F2361C6588FF9F1F523B27D6E3E45A2759796563C34617A2BC382F9DCD6A59EFF7DAAEC87186AB5270CB6776954A0A6E3E968AF5BECCFCF3F5EA591A3709385B087711E055C56E0669A8B59E0E13D7EEB87172B357E96E450E5B2DC6E809D02B170B4D932355B0D2D59CDB446D23F167D07499E999951964EF375C77A3A0602106838F8FCFF973DAA3B4E4D33CF4D1D704C9A7937CDAB3234231CD3FAD591DCFC5B849B0ADAE190A321D89CFCE959439D8FE2806484B2DBD7678C03438E668B200A00F8B35FA8C58A4680DD00C76BF9986748095E703FE755D6CBAD53AF00DB8BAF4E8EB5446F2BEEB867DBE85F3423BAA8F72C8E66237466C517E0EF295249C287B4D63F6DA1086FBDD427F35C4F252BBB7A7DA2B7965C4E677249BFB0E922CBD52C2E18B266A38612188901F8A9F08ADE7439C3AE840774F4E97FF05C7B069F9DA8809E6C7546BD4091BF89F6627B575ACF0E4A4F55F2603FDF0DD39F750029EDB884741DF1732A2E18626963ACC0C8766B11C9EEB27363540C0398343F6625F9424E8DD798D22745A18F754E89133F2A6B608F12B2674AD3C51A9E39947B2A61697206332FC1CFF9F3D80D553F34B1F6063092DA2232233FDFB1F7736651FCD73FDD0DF2E717FEBD7D5211B0E79C5E58AEFF8879165EA16CE85EADCB84A1F7705BB2D93CE83BBE3C0847C985D0D1AD1BAE7F8821E1A7DE3AEF556BA8E9B321602A1202981897147E97407EA3E26CB3533AC6C2B514A04A0222BA899A1CCC446A3F34748122D519C3F256B38A4D55761D13C2A70B6513D3E4389303AC29516C1E4ACA9C9AEB32EBB2F546AA1423F05B4789FE15F77F6A4BBE3440B8C0D8156CC6D23619B252A0605F0B84784A087502E98D5B40D7FB273861718649CEE002C80F45FFA7051003EB3EC7BBB6697EB032025689FD7FFD0FF698A80564EE7D8D5D359FC4D6B046BF6EA1DE0AB65A631CA84B92D782A93E1D6E0A45B9EA4BAD98625B9A0C85C89791339A91170E6070A9645CF982CEA79DB2285F08E8657D40CB2B13D4A80A89A74BD8256C3EA2DABC059BD26DAD0D539893B07A22C24CFCB55CDC1AC83F5E31C5864C70974AD52EF2E414498C6AAA9EAD60801C2192B45F91DB3AF61B13484DAD9BE25C0442EE2B67AEEC20F89959F6E4A41C7D8C2600FD74C7AD631D9A60839005F7C774E4ECB8393A15E5821B32CA4C4E073388A1C4A86448FE7D0E1A0D493352E4434D5479085B9D7A5A76BBB00C0096DA854A7A6DBB5BF709521C6DA5627137B9F4556BA9E80A8D61E94CBF953CA3ECD6131A75BE3A9384A17C83B2DD1A91E895227F51314553B439405C1A8ACBF42574A4A098B438B5BEF771B60C9F2C517F7AE2D926795F319F3B6F9969904D1C83142AF0E8B373597DAE551A9A04F5B479CC3C9095389DD62F67362407AAC26D82D2FFFC716564C26B1452357F2BBDAC2454530D32EB908EB122D6464903FD94BC46749CE13A7B50E1BB59A4427C78AC34BB9AB5760B96CC1322EB4B71E719E06432ECD3372E5ABFD15AD3482B8091AD63F018B9FE2AE64367C753929E41DF0226507F01ACA47BF37CDE1FD79E49F29630CCD32ADBB268DBCA8FF19429F407C50A303FEDB80C4A294E99EA210E3C1406B5FD5563AD3AFBC8E2EF93B443073D3F5459AA25FC65E69104517CB5CF2259097D269762FD698E6C94F11C7B4F14385380D6678F5DE5255FBD80F3CEA8E11A4ED2525D9F26F08D3C7A223E2DF8E753A07DDEBBF9CA19ABEC9EE0AC60D50275F01C73B97D27A21DDAC0EF17B5342107EA02287C790DEBD58DA6FD467CA7117708F64F5B6EE48BAEDE29BA26F097128CBAAC4EC389F3C3AC58730951582B80CD2AA050565B865DAB97ABDB64E80DB98E74E3DE98743588D637666C05EFE3131CBBF9C9CBB9D4560DEDF716D6BA01126DAA4FB34AF349B8DC9B8B7BCCF99882EB944BEDA2BE9BAB8F5D9FDD284137119DB91A83F9E86E59EBD9F84024BA2C475AEA0FD4741CD4A4EA54676F9748489D510DF79300F87F77D86930ADDB833E271C89CED3C7200C97D5658BBB3FDD81133E0E50C3E0089844D2530A79A666C85A16123F07F946A0A0F1A28483DB238180C168FEF001683B7DC5C7192F85C9F31BDB87F80AB199987421A2B26C4FA68C465AD04782296014E31D0D78791EE7A9313D249673D0CC8C00DB448AAA5FCA2DD8417310165BC768B6AA1970FC51D741EF6F1AF3F07B60A291CFEF3F2E3E5328C1EC028591BEEC4E7152E62A51E6358734860BFA281CC6F5F0B8AD1E0115C7DFC903B45C604C6F9A6177F3171A343F7AF898613B25C561BB89C39B6339370676B0F0624E63B07C63DC7FD6B601A2527FDE31D52D4367CD1A96B55BD57AC872614B4DF00DF90A0BF8D97A01A341E408B1CA481A49B20A9631F0527F79790BB460BBB31C5624BABDD3773FB32221C3E35A0A3DF5A2D1E2E6B33CA7A1E03C5CD6D53AC065037F7DFD1747F869FF860D69F6C288DCB448D3F3B099D5F10B40BCB9100E7B8BD645451AC8E77AA01023B2968CE2893C1AC7CA45414200F2C1E8743D8703E77C39FFBC91AAF8E67512634DC966392DA2CBF1AC66C9A3FD09570613AC0692551E2D3BCFA29322123DF16CD31643B9D6D23C715DB65E99B52431C1FD748D5C743CF003110FDFE5D79420696BBCBF35C94FEBE5A3F3156C414F28D4D19569BBCEED0E7E88BAA910FFA28932A151715A07478112E9CBDE554195ECD55287B2E9489BF595124A2F9A84D4ACB1738CE37E0D98546E764743B1F0C204E1F8234C8F3ADA16645040403161F1D81436E402AA1D65169BB14E51A77C00EAFDF7E270AB0840F8EFD3C0C47557B5734E62FBE8FC301AD3D6D5466B0EFA85051388D08C943DE9388720A1BA5DAEA23162E0770FA029C3988FA7C3438313F0C8F053C5296579AA40E7951D50BB6FDE64D2A9211DBA0E311E45209C0B6B6DE580DEFC6A2594D8B1C85E5A83818C07DCBA66F93B20200E3F001D5D41B552AFB321915D68DEF5D695446BEE050B49705AE7E6E11B6784D6B35E3541A2CF25C5D8C9F7756B32B043DFC46DAB910EB3ECF43CE47A653A3B82CA8A6447A3572C3D6D7A34E04A4860BBD2AE2D46EEFD48F969E1B31A94D3BFA64AC187F20B27D510DC6578C55037803C32879F4FE8230C49311C574EA9B98DF359DF1CECCC229814FA7BAD84E7A2F2C1CE4BDCE68922742B0622FA16D08B817086F6173FB2F6B91462D6FB286E6907B140139A6535571CBB45189AA4CF25B21EAF9F14CEF07F959A94D62F2829729A6975486A57ED73852D216C3CBBCE58F13D65772328E9FA94581C70572E32205B8FC500961D460EB26C023ED0824FFBFAD80EA3DC160C4D0AC74ACAC0065BD24EC991E6A03B6705C1649F99132BF80E3C2017CD0E8D568DAF7ACF1CCAB4FBC9769248F1F875CA1DD8BC6778457F60DDF70A665CF5E3A155214279B4AACA56B44B83EF29DF895FA9FB19BD387C7F9074B546E0F6E325A6D94055043944BFFC889069D808700B46CD787764E9A3E3681BF4FE6E91F069E078DBB6EA9A61E2CE4382047FFF28228F7B02012B9577C914D17E1C698CC3F63892F0E6BBE95AA3542FB10EAE06C62E056055671ED414304BBFFED1C6AD9530B5F147533268545C36EAA289A58B14B4ABA174CD69D06094F04D15C6E81279F5C051737A2DD81E4B5F9BC73650121D0D6D7F2075A7C42FF180BDBFFD88831010F26C4A3BC3DE014FDDCB6A7B80650DA6D3DE80A97CA1C7ABFB6D55DE609CB3D4E35CF4BB9E389CF7B16939140C41AD2158E9C470458601E4527C75D986D6613A9BC778A148864CEA35BC227C79E3451F407F3C9F34B9BE644E9605063349FA622C93DAD517F6F3F1064569DE67B14D6D90607F8750D5D86ED93DB13DE6ED0347209F0290038DBE73AB2091D22522686A651B95C5CB725DEABEB8CAE4AE7E4342B71CA05E6AEFE4049011E1CE6DD01B95382C24757EB2760B38B5C4255DDAFE1D12D29BE3096CB1342E64E1B1538FC52071A589F65F22644253B46D6379FF2A5EC8EE7381488D0CB2D22D51A4BD91DF238DD5F2E9A3FCB6D7ABB81832F15AA264DC46E3A37C1A7A6AF0D7362CC0E051E94C74E75E2AFC3273AEC4D65F3A2507A3B2A4B0AA2BBF0026CBA224CE777C33B8C44D7F8F44199BCC68165709A022F0E8F9515EC65B4EB87324471199AF206FA6B72FB24F94045B5B1081C0DEAC2FD5203AA5EE991D694A3311A9E1E515109C043F85945B5A065E85E135CC020FE657E0ECA02404F30383653F41BDD32D8CC1F1F206BA60C94FA21A6AFE16351811F051084A7173EDF2802612B3C3832EF17EEEA4491FF74654D778A38F4F04A077A127AE537D4BC3DA63BCCE67BAF251575FB29C0858008D262D06C0587A3BD4A7EDE3B00833A0D26C36D3768828F816F4B58C12482DA6CB1CF23E42B074D3EA87BEFD5E64E28F5B05AA19BFCEA95AB8D6BFE341872585149A97C2212CED23BF2C22936848F8BCAAB84DEB08B3F109CAECFEC7DB1CAD3950F25F0C64C0DCE19A435DE50537D4DBCC68472603D31D09130F816EE05ADA98D782415A76EC0EB50960F0332E0E002B95202E160A646D3F582C1D188A9582FEE6C29793C800F43A21A827A67801E16B7C6A145E568EF5EF88F851577AD6E302A08722B4E4171CE21B325C1CC863957A2D5540B11021F1DD104E437E573CF2CE59E84B92735DDA681D6FE2956E5C5E9C64705D1B32CF7B920CA709CF94B80C017422D4C31EB2C847B4C0B4545D93C5A8EBA8704A061DB98FA6CD43DF061266C89D322B0793244115CC35C59CF93A1091E45495DDD17500B960B776F702C078BF2EC74D62586194197C1EBD8925891927AF6ECF41530D1951CE061A45D1E176C8D43D9ACF9E4E2C36CBE97F35CF0DB7B49BDE4DF5A333D61684845366AB46A2EA48274EF89A576A8675528C1A27A1876032B5C51A8A429E1C683F36AEC7D302C8D8B982066B2847AADCE4997F1A84A4F9403C7DF60F5CC8374CD13C1320D9D44C1507443E149C22424EA7856EA2D70CBE5F07A4F7C13B6CF1B2D5D93A3CA0A3D7874C16F49A4AFB3840605A35F302F4456C5A636B37567922EC80A5860656DCB4847E11A93C38934DD8D2563DE0BD88BBF44C1230905FC8972AEC5DFFCED55D603F27175B16A948F59A3F2D1EED76D7B96621D95375276CA463A99F1E10DD5E83BF6A5DD74314A4727EF42F0554AE01D5CE547C47144FDC1F619B1199FEFBBF1A8C11C1C5606AF8EA9561557599811E88B72C603BC11D920ED37A2774F4FCA8AF49E898EABAD39CA83D6D494AFAFCD512DD23AF636370253EB8A22B3C95427EB1474570CDBC8F4F09ECCE307D78C26E4156493F487567D31DE85600C6DD1E99F382EEFB57DB680C223CB078E6039CBAF629DB7FA6BAF23B23C9D708736BE52D72F3502868A9A90081F30818CED660D046B30191E9990523A6956D894DCAF97C27D4BEEC82A6FC565DE0AB2B0AEEF8DA02102F14400FF262ADB3044A27F82A6BC2D77CDC0A5F5C545FCA1E3D5620CAD57486B7DEF25696CC2BCB392781DD70C7DC6DF4CA314E32D28D8ADE7E259C9158E7F285A258EFEC126CFB804031AF9D6EA6B8EC47C5F9AA249CB289157C66078C6B1B69DB1D4948288EBD4199B3B4EAAA48C04325D36EFE0FC4E0D1FC4AAAD3841997D5BF04CC3B96908442925452E6489C5ABC9E9A5B94AEA3162170E6667707850BD054801EDFFA7146B86D755D01C9540026B6C1FBB8E697D730A9852FCD7C4FEE7501EF031F7E14DBC8A7E2C826C9F7805F807C3EF7DB4CA4DC49160DD88638A9234441C37FE64CCA16FC101365647341627B5D1F00327BD43903D273B5A6126D3526E6541A051DF83368DD7FDC60350F5F73C8BF1F8890B2B16347514042FF760AA86F5A1BBF675391A739B22FA4A810A0C7CB5324E0C59B5DB967823B77742F0DC5787C12661586F364E476B45E38D1251CE10B99F2C8FBDBFE447BF7C95D003F3BAB9AA1E3067D47CC1EE93BD7B351847F19C18750BC036AC88A695B96D70CDC8060E188F9F2A7269925F2ACA6D53552198954F460C89C872B99942EBC605758264C6E75C686B0B0CA1DF01163D09C195650AC8E748A6DA3885CA2FD7BB3B4E10ED961A3EF5CDE55E9FAC04BB2A5CDA002FFE22DC27378E9D6E58372C17DE3604D9A58758336A16F81CBDC7EFDF5F79E104E055923CF7D2BE77D966BD20A90FF5319DAA68D8C61068E8A7E6479F34FE3427F40A5CCDAB601FF85E48D6D6F93A6147BC82734251DD62EC6D6C631CAC91EE776BB678E05A317A2A719643D36376C2C92478D6E19D8AEEE9C78267444E0E32839464A57E5267D7DC422E928090E42260B6C08C6D2A6243E1579D433C13AA8EF9BDD2B2AFB14CB95C38C35E70B5452FD9000C9DD29A230C7CB7BA322C8622C0B5B985532D6171A43BF12C1F234BE44833D5DF6750004E838BC6DD61991DBBFEA8FB0C2814D8C7DF2BC93914B4C0115831A8841082F64F00381AB8D866ADF595BEA999E84B08ADB4097C96074BF16085FD9F5279B40504CC049BE061904687ADE95FABF2D80A90FB63F81960EE60A8778FC70FA5B76CCA6D69ED56EB5DDC06DD42CC459923B029DB9C633D94929D7F2F3D096790F9384D1F451F46197F6FDE08D7705C1B02E558204CCA8DB810BCB37584EE9032B2F467D24BFA620A098BBC6465D521F704BE7E74B62F83CF95BF574465302F2BBE3AC2D4EC2D3BB80190F9209366139ADD570A08F1E22A84705D6573EC400D3968867EF9C2534CC9B9B1BC93E6C4629DD4AFCEBF74379DA796987FCC36FA17B0B0F5A94E9704EA1015F2F17F339A45848628A7E90B9C38F8F1B76067EE1413A6E52CF99D2055BBB297E85D861E4788CCBC0E3CEDBA433350003D3464DBD96FCE67CC72A37D91152E273998C3D05F5D48C5387BECB8F04DA53DCDF1F6E14D4E00828BA5AB6D46B534353439CFDA05ECEB09FD26899728D6946257BF23ACF4185E76434542D710A00D901439E2ABE3219FBF3E9450C2CD191B57C4F9FD6AB616C324B95EDB05BAC0C21F5D8306545A86A7FE7A8B225A2A4ACD02647965A98E3AEB4F59A9ADEAAACBFA9F68CDD58F460C30BC928A489D932792A9E35975FA4490D888F06FA4B3959370798ABF9248C7421E859D09FA3FA9E2C46012A077407BE145B0B7AE601AB5B5F43BA32E786740500595117D8E37990AB59E72ECDFA1A621E140D13439687C2CB5909A5F8E4A2465870C4A64041E744F99AE39D360E103EA81F3347F45B773E41BC58CE63837350B5C7DB257AC00A1F30B2996D38364EC2C2BBEEE1C0E20076240ED060E031D7AA1B80311D187DD591BE6A830AD2567B3499228598B3B3C538A181ED17EC9B57F0C4383AFAAC41999E52238ACE29736678F54429F92F49EF9F166B89C69C8C5005409CF999A522487B641640FC276C691BA47409EE54FE7FDE46844DA842706F58E73B69EF879579AB9A7D0FE2CA81FC62479CE9EEAEDA33D1EBC6A8DF3EA81897A757A0CB04F62FEDC511CD9A0325ED03BA7F2F4A09F52CFC7DFDA61A76442C7AD431579E02D143F2AC4B3CCBC482F2EE4775227CB1058F07895A66C6B41050F36BE0F73A9F6DB23137F8348DE1C75ABB9BA894562713F7D632F6C2B0F2E588095A013074EB2396472D1A8C033E25F431DFF6FF5A4E221B398F1E88EA3257F0AE2BE385D7DD28926F6FDC50168EDE8003CB62818BFC01B7DADE7325F05B287F23BD0833686A75695ABCABC57567C716677DA71CE6B168DB22CDE9B8D93A02EE161B475DCC11463B902052C89F08C69C7BA72A32BACBD3F5978E66331FAD8B5F6702B12FDACBBC4570751DB9AB1FD9C4BEF1915A8CF2F94DB4B54B08589BEB92327EB12E519AB033EEF66221226385A596C6B63A17FECE0BCFBA68022CB2E9126E392470A34D9D3C6008778DDD0F56FCBA8EE58FDA2971D03C33EAB6AC168AFD8C0A30ADC44F54C82D1F896358E4E879A477BAEF607C1CF8D15D31D131FF6D15665CD69406025B9794C523B96A5826511D6B1A17EF6AF68F04F0F602292E557E4130866E05E273FB7B248CEA96770558DB68D311732C6556717E91D3EC8417245D54EADC27F9921143BC50447B322BCF3663A38F63D9172ECBDF753F50755F936C23BE535580BF7449E34D4116905774755C8547CFAE83AC3AACCEABA618947046C05EA454EBA50C28D447CC87E78258AB82A23666A08E2262C39A5DCCC280B3B59E590CE0D7AA076E73A962E1BC0D3CC7AE7DCCAD1336D37CB58B7D7D546DCF7799BB89EDBA0DEC07A9F1678E61D061752CF695E3B7A48EF45FC3C50A9BDB11DEE8433075A47B021ED22353A8448C529D469571C10F3BB64295F9D85620F5F1048F37EF5C86A1C1DC5E1ECF6614880906FF10C1E65F55DDA9B5FA7AA05929385EE654CFF0064C4EDA7ED25420DB9CC4888BAC470BF915FEF6437E133A14266916238502AED733002724F5EE27445D4F4132AE35A8DF251570A695BFD4CB9E2C8AEE363C14DFCC575A3BB724B5AE3689CBCB836A2FAEA4E7D7193CDA0C9E9A7A928D58693A8C64BD0D66EEC3404ACFECCA4B8301A359775434FEB9A1545E7A5C367370019224254322780F380E31D2ABEC0C53DE107D55D02B2999055831EB953C9E5A88FF03AEACC5A619518AB8DFC6B239CA0C4005166F28ADD0355AE82D50BEA961F866EB47F0639D3EE4860EFEFB213D63ABADA42D187FB85F14222B51ABD0DCF40D9A15088E26EE698D69ACFE0F81862AC77713AAC1C07D3D07187B7EE374F85E763484598F75061F5B00578920095953A6516649A2E83E639C88C97B61F52CAEB6C0626B2B963BF0BAF09DC0986B6912A83D635BAA341C51899BF10F0CCB4878C72D771905884BE337DCA73852AC973FABCF098AF64B5D5B614880DB5660C4EDE57A298CF793CA1A8635A886E1B5C593C1E9B73C9D728E6FDC4F2829BB89C18D1D5973DD06E7E58A93A44259AC8079B1E8F9D3224385A3BEFAE35306368B386EBB76DF58792B44683B4DED670EB9A7AA6A394003BA7215C3D3752DCE9EAFD5B73007A5FEDE96F6013A3F35A01A734EE488BB94B1D229E7D98F24C971AAFD5FBE222B327F8740534DB3B898DF0F5028F38AECB77FC99F3477488BEF0BD879C7F83C42F43118678976FDF36E6ADC194438601DFC1D237E91C10AEE9807CB994334515CE28262B8E42DB733C5F8C1E5EE78A3B8514398A16CDEC38A4B84863A3CE8B0754D2DDD6AEFD146ACEEECC9DC7979ABB8BB7BC45157BE418BE9C8F25C979C3D34B8252935B1A8F3B9108DD809353264CEE5C58E091F203ECCE437E6321A92D85507D7F03F45D8DEA713C2B4FF256ADC16137E78243E02ABF58353CEC275A8091E14A85EC5A2A149FDE0BD419F09826EE4918376C4A9D8C1087CC2725034E706310C39318112240680CD32441FC6A59F43D3D89B10C5586F4EB03CAE774FE8739557BCE24849FC488E8F994C4F5ACDEEE6EC358A9C55C3B54D2E6DD6AE6B89EB6C5F5C466261B52FFC4C0D1C50D486BA25732776D05F2004E793D57B97182CB171027DE1A07DE926AB68DB4FDC9E4FDDAC9CB61D5868958E0313058AAF2B4AAE7A5F544A80C8CFEB29E49B54B01B90FF67F000DA24FEFCDB2337D4C405C7DE2D3AFBFD9471C7F828400DA9566CA2479950E3E9B5D08441A657B2CAED02B3AB22B69C9909ACCF410B9ECF9D42585AC12256205F66763580A319C3D57C3A3720FC5D71BCACD85F4B4AC0E20944A8C8F51E5CC1071F396BA94753BBB590204E99797101BB954411CF12036CB90ECCF48E2A8032BA09BD62F676CF24ADBEE52134C73FD072EF81E6D72FE4FFBAC61D64B270E80F4D03EF7C3DE77DAB97BE1A3B6068CCE9858C9F0D656855AB57DCFFC23A61CCD0B5D27111EDE5976BC92814493C70C3B32A418823B272324C9118A4DEE5EF64D2A45947D8D17F1E2437EECF2C2E341C92D124732E27150EDA4B92CAC387BDD44774F3E177DABCAC5C3417E58B1DF9F0E89E689C9C3229230A6179A76BA8BCE00C8CC4121E91C968A1D7F78422D94EA53D6F0003A00011E0D3138A87EF8693D3348C57892C579924FD1ED3BC4B08C43B1C97AF6D8224127047DCF2026E4038B5290A63F6A811C2AF9688B56DA92B42D0069833FE6BB73393CC5599F7D6CBDF87EFCC56A321D7E4C41F029479BB876588239B4F9C5674FDBA079A1BF3249BA4CC3C646C5B5ACC81D8966958D7701D37ED6548A8777F37998812664C519091E166DC61A7C6F850FDC2E81088CE8FCD6E2C30921FD68682393232E3550DF440AC1E241A31E7BB10DD4A7D0A4FF29FE0F38445C3CD8C72A9AA941E872BE9EC64867285DB191FCCBF3BD4FEDB02EF336FB6C25367CD77095AC3EA280ADA05ED8802D31B41B17944FDCB09E1E6B98D5EE44EB0510896A696C535F6EEA9B6EB4D64D37DA121E693CC47F09F34311E9C77FDB06C723B30036356AC92F30DCE630B06F572CCD2E61ED79610A2965539E59A0D8A8DEF5EA73CA0EE0EB786C1E3657E161FBE6AEDA757D935616394B67DA55167168B246A4A5BB76324089584F67F4652B3D138C5A3CBA13FA712C883ED4795ED8460A9927FD560DA95FC68393C9B0D4D81BD127AE17C46B4F95C2727480F34BA3F684D24ADD5F9EEC99342DD3BD3BBEDF3CF56888B9305964E0487729A32A3B4D743B6DFA20F56AF34C0589462750611B90C90EF1E7062A4462AC5E37A67B10EC5A335F38FEDDB04171E213CEE05EEDEBE1A30E38316139262C5392119573E432680EC2B2A4A32A9CAC294D10290AEFDD9E610579B093C458DBEFC44534C6CEF18E5DBDDCF72A9D3D1D7D9FB4F3AEBA37A02C456DEF86B20DC722CE1B9DFBAB16565688DAD4D7474BB5820D4B4E349396AA2832606D331CF9623DC7B97CB54F325C7384508C41DE494A2311F821E41034487067A6A1A4BBA36EB3C82F1ACB9527657853C3A552D2107441F32B140A70A6D54DA091A3307908C24D34A47738B45289B4C62974F28340BBDF82CCC16045ADF526636B50690E4DEE2E28B03398D03224D629FE106EDF69321ABDABF27071631D0F36446C464B961D0B628F3DE5E70EA282FE2CAA15E896FA241EC2F082298BD314EF444BD6404E35F4ED7734A9159F24542E467AC383E944FCDF87AFD9978FC308EB68A3744294A24EAF998E05C94F3F3F3C6400B0A972455451C74A09D4CB2014A8D4DF67BC3FB0B1684211B5206FB0971BB7C787BFEEC8BBE3D3A37B98452000BF3EA53A745548034A4F4EFD7AF3A1D8781573EF5E6AF52A251D90A62C96DCF3B4DAD6B4264F2701B7D2575AFB9DAC44208EC1CBB57B18D74972305B22B3153CCECDCA3CA4E362D1B47931C8C3FB6B9C1FA4A86AE1987516122E8BDB24445C92AC10F5B854C2344C23C52A1080A07919569891AEC7C539E54107135C46F09557E370DD86255640B1A02A96B705B942AFEB182237D607AD1DB70BF22066B8429480DF89CA3C6AC4463329D8A5117055914CDE19A60F1281010D8800AE6B9A438806A516CF5B755D13304DFE2526791218E7DAB7800F2B75DEE3779A01FE124BB32481520E890701C67F7CAAAFB50D4527057FF66569F137D283CEC23EA5831BCF2A41DCB5E93F325E67C58511303F65A995496D257D58075A0012927CB3BF81B82E1992F618817C38F9B7DDA78846737F677FA2FB8AE61D4E66CBF286BC19E504560E6A6B5AD09C770E3060BB99382408BAAB117C0DBC5A6B579D01C2C1051731004997EC28533A28C8EBB90D53DE856824FA18E612C279D65B97B4FD85FCB22E998AE939AA6CA5BAC09147E9F502A671802310497C63DF4DF43C61625B96B03FBDA1969BB2C380F5A48DB79604C49F2525B71010BB857A3E8092E76BFC025CAE63988793C42D7D3406DAF2B9B75A3584EA0D983566549C73FAF6FB94C153158AE2E5B3986364D2CB1E64E1403EDF1E4C9DC6F300505C31EE3991215A4B3B1BC95A64496008C127F678879F592F3E947686E23CC88222B5A0F2BECC49F7A286717353CAD17204CDAB2BD77A57222374CE36E86D79D424ABA8C111085280A6EA5F2C6AD35F8CBBDB685344E2151FED36A4E1680D0BCF17F8E73ABA96D25D3E29B14918A48ECE4525A2717D8FB193285F40C5C11515EDFCD2B4D916CEEB78DC57294E252CAF64BCA591C9748F8E606687B2C3BF42FFA3C478840B79A74F1FB1346D3971E7DC55DF6F0C8D3564F6E8DD264D693FE25E2217CC5C8823E4D3A8AC735932DC6DD2C4F6954D35DBC8F4666DA0B55C3732D78608A8C61D68A3CF134BD099BEE2AF80C1EBF3B874F4DC1B15E793CEBAA534EE01842AC299C2A17625BDE44580F1DF6BC4A7ACA2D54DD2D5E3232017FC3DE26C6FD5F2B70A06209676CF55ABB3D66D9717EB28A2C9A11365C28D9B98CA631855F928A53B9A1DF8AF54BFD559C7EBC330220E7D490A349361984B7DBEE87C873A943718EAB68051DAEC493E7A7EC557831EF482E1C955923963D5F24446E6879D9E113E7C288E65C9EFC953130FD6FAC487964A53F1CE68507E4CFA1F91179B3D0E994EE36FF6C8DA146604A59167D0AFF35EA865BE30BE64262EC9D8CCC1E9DAD4BEAD9DAC7C39424CD0213240B51D4A115120B815111D57D619387BF1F4BD97B825FEB65DC24F9E778548641F8DC48BDCF1AC2F802AC9A696E0B96C41B27CE6BCCC0B73F768C9FF207F323A3B4737B865EB6A6C945DB5C58B8D7225DEEE05E32659BC84BE5FD85AFE1C76F75CFBAC479B29380EC6CE84FD62C7BA62A49B2DC2D317AB8B51DFA2CB02928A13CDB918953C4AC162592668AACF385E32E1382C480E5C91C55F4B2F514E204B8F156AF82F5A65CA778EF0195756DE9689ACAE3C147AAC61E293F59714A09145726EB857AC990153BFBC845559B9BE498727E57E75862D85AD2C093B04224F2ACC7C4BB0F92029A6BC6020887DD8E6141F5BDCABA3D9E0D73D0BB4BF282103D109B454CF24F27E73DCAF369F880A2D511FB3137A3B5AF7287EFCE5962B65EF8C33CDC3DA217390025C850AAE53AFECA7F41C3A4C0B1FBEEB9BA1C72A510384607CF21437386AF4EEC6E3C3FC94E64AC05777AE2256267D337793F20BBDDC29630E5A096CB70752A1D86D5E7659701A0A6BAC828DE37EF747E4CE2FB79156ADD30055094AFA0F8C3A38CE5C92944310B363ECECAE4BDA43A630A731BD2588ED9C5C8928D095D3DBAA649258DE9BB2C8CC8B876052F568A894A3AAF617113DA4D70F52A0B62A19B6B828939970E6B57ACAD2F9304B0A41C680EBCD46DC1E2E11E1B2ECC27500523BAE75F5A92811D86F3190ACB325396A8B30F84CDCBA4BEF679EA62FCE31D08DA332B596AFAB3F3899F875A27C20B4B4D98C40D9CA42DEAB409DC2CF44D76D65FCB517375957E07BA8791678D77F865C6ABD19DB367797756170B5A663D0AE84DC9FB9385E4CB3C2E3F7600248F28B6EAD4E85B54BEA80EF9BDFAEE50185023ED12C9B22220C85636C4F6C7D58FD6F24C511B67247CDA0B9C86335160B50E3C7E70DA800A1837EAAB5E2EB366539D38285DA492883B9E311F7D20DF66F55C78410FE02F1423A8CC0314F1ABF3CE3CF72C0C309DBC3039B9188F1D6339430795E6FDB68DAAB5D6CD70E7DF1E12D17625F3CB2460E295209626B02B2F0D8CBEC2B2CE2662563729892A550253385B3C0FCC64162D09734C66D3CB51180A780DA772127111EBD1549D98B851CE0CFBB70297EF9B263EB2B03DC96BDF629F2AD87770165BBC8441A890BD39B168EEB3A44CAF3A44FAA17B08E439AF7DF6266A859B15A5B7A627C8C123DE847C803F8E089EA42BF95ADBBC08E3E33523D1BC335AF225F0091E323594EF61570EDE97085AFFAAFCB2FB928F673B9503C4FB674FB3A792A6B11439E108257D7F4548706D3B66995E291EA278A64EA7B120C60FB451A0DA68FD4C752AABDAC846F2475810E2EA6523E88CC9EA3C2BF15D1B747C40C5E3C2B0559B5E4502CEBA84730069EC10A5561A2428C5B9C2E7437AFC79E466FC89C9FB781666CDFE78E0B69D58041AED3334EC2B34C4F7F770F44F1713CE292DAD0373356492D85C22D0480F37F36E217D29CE31969F491609A6B0B49BD771B242F09788DB88CF530290EF8A85FE0E7F39BB4B96FF7A9D0504D5D4672161A3E40B047934D984D48DC0356BB3BFAD15E54EC63A4114983DA05F4B91B6A3DF21DF9D82813ED285EFF5717F58218FA83D838EF92C72356AAD97D9F7F59CB7D1FE27A44F92AB866F3CD9E46E96CEC573823730A13A186D644F8ED11F74DAC017573D58D7E072AA0DC2B86082285BF6214ACC6F7137FEA63E4A4DED72741558C0533D39D69DC63AAEBB912E600201D17F37C6092DFA0A20E9DB6CFFAF8077827C951DFDD52CFE2B7A1F2A1E5191BF39E8D91018B4E772289BFB07432C84996C287B0DAE1D8F855AD33FB02C22C85ADB66CCED232393A68CE60B22FCE9EAEA5D0A0EA526EE4E4707BC49AD995E1B4D3A4EB78FC45B6AF0DD228CB7B73A9662F894F7ED7086DB28B6B33DAF5011197B521EC511E4E2B77CC17C433E127320FA5B7DFEB0B1F06751B3ED72609477A4C55F05AE2ABC1DC2574D1B5813DF0AC64C003DC638C06220FAE14653FED285EB8FFAB2DD9CCADD1D9A1952BA95DC057409EAEEE273A4D0EC505A14512BE5399780E928F6DCE86AEACA57EBB4C2FECAA4DDE2F46B30E92BC40EDE89BDD3DA378DBE72EA1D114719E6A37BD714ECA7CA87B1F9F2C24604AF85A9FB7F75B2C3B9E452B89CAE9694E0DCD3C64F4A51F2BF7986D054AE28657CF02D5EB34948B0F22E91F76A7D08D10CB91E57019767DAE08526A03C793EDF09334A2E339D2E37D8F87737C8DD65991C8F96E5CC484511F452D465F7888EBA6B4EBAE7E472164587AED3DB26D7C112181203E9114CAB931CFDD31A6A2622ECFCAC0896A591322036F814FAFA6E768502EFBBA84EB5D5C13FCDD73883C30A0908AFB8965105FE741F586F3F0D15041A59E905F135C63F42997F39985E17798A64357C26CBC2510D92D9F4813635CA66BD0378AB8C9684B2151B17FD7AB75FCFE4ECBD4361D2916564C992CFF6B32FAC4C8483710EB5ECF2DD589EC5CA38F709152A9451B5D33FF04028BED305C9FB5A438DA4681EB05A121D3230AF1E8C8894BD62DE9FEF5BDC8AA74162671AFA4E2C4776599C3A983E4527EC47B06E0BCAFBDAF85334FB9141F3EF9BFE9DFC3A9B66ABA80DBFC5C624611459209832A6C4CB244E50DC30A840CC357312FFF081312596152FC03C1C582C878DD349FF04A4FD1C207F4A66011A3FF88F622AFDE9C8B759B7FA1C6BC79B4016CC3364FC7660F0DE1449323767ACE8A154583C3194873785278E187551BF5392AE181D3EA108D93D89C26606D3743059B8D4A53D3D7F1C01AFDBD622B168D4DE04A8ADDF2E442B14780A803D978615C79F0D53B5F51288F958B8670DB066E0EAD8C19413DB653EA68EFD14312173BF7C6D9B1E025B3E03C2ABA01DB7980B0A779C74332D4A81263662F38D7EA7ABE846342DF973E58EAB2C68AD6A6A54819977021F1ABD15B9A00A0E07A1EF1A65C3696C3E85DDD39E11BD28DE49D7D67AC40DC5144DAB66C81A96023F2DB8AC562076E6FE82AEB42310343E29DC55E2A59C3E150C10467D176A99F37DCC33367DE1B089FC873E6BC6A6D67C483D262A74BCA169BF1E679A531729CAAC7D53CE368FFB90C6488093E1182D99A637BFC9629B060B9B7771C1DDBB945E13F509C79BBBCADD3832D083E21BD6D9FC3106AD9EF34ACBEB9900DFA600728F78849AF1E6A68613B7E1C83C76EB342586D6A43164CE0E75EBE4487EDED6AD62F062F52C02B798D6A7DD5911615605A94CD91FCBAB8D4A6BE4407F5E8D23BE1145001A456351047BB2E48990BCCC5BA6C79B95CFB97EA17A3C7D01A29C7DFD55115176D0D097B19CCB11A42535D1D039D6B0A5728ED282847C4DECCE6A3E3F728D8E3A890CCC6BC7ADE52993130DC9D479DD7DE8C760F120DC2C7F2E29F12E38F11B2A796446C307A4F1F04B2ED9649FB8A7C0D4FD0EE441D4CA515DD253DC7167B9748FCBF341D558B769004706B3610E1F3C36A415D71F9649F19FF396E61E903E21EDC9ED7A7E37E53FAA0DBF0504F1496EDCF4672EA579C5E18A1E3F7EC98AF96D281BCB3EC288AD0250EA04ED8B9C21C7B738E3B6026893B21AB6C61C10B4FDF9DCDEE1F658A7D7B612B691298EA4969F68D86582ABBCD8240651F89BB44F651A93DC6CB192DAEC8BC2AB4B27FDC876D2E8F141B9C03B2B0DECB8CCC13E7569680377C97E7989731A6C1BEC476E357E892258200AD11AEA78AD1C5778C8A045E908FF7EFA753DC3924D525CC2383E57ED12C19DAF1F987502D1F34260743C23A57F6C77ACFBFB2D43DFDC11FBCEDBC57E2091D070EE8BB02B0511A62999631552C645D90D08F0B968AF279954A842E235E6258E8322DE8D485855BDA1F1D0ED612DEB5129C950DB48C30367CB6A3610D621E1EBBB9D9ABCAC10A3EA4FD1906426452231B5623042EA8F5BAB72E632E2AFB50A3CF8DF9880752BA8CD49D3BCF1AAFBABEF7456BC9DCCDAB7486E2CE5C3061AE6E71DF5AC97CF8CDB63B2818FAFCD8C2C3EDBB872CE811D60CF00E6CBEE508EBDDFA1759FE8611BEEAD6B4293E3C2A9B48E6C4EE1F069AFB87329E51E910C5F93E7CE6744F335E665D574C288ADF6F041D4AE983BDD4F18331D653F5BF6222EC454730058AB8E0EB8388C78C28AADE98C40A6536A6CBA9BAA538043BB97C6111BE6CB57CED50E035053A66C2A380299777C89981994B88362B1C3ECEBD932F788E46412D1D7DCD121DDE2ACCAFA129AB7C372668B2A2F74D6E50DABC6D96CFE4AECA45E42634C24E61DCF8310C29A5E58AD427B5F35C2A48F61CB5987551F09BF05E2F3BCAD9313146F7F812AD0DECB8F44879AD6D3D5E9ACDBCC4C13F716F3F982FC6559490888566135D572E571F541ED074ED7FD9F7C4956917F828F9484BE5724D4D432EF28D3C6C6354EE41A86EEC7B8B4171BC9FCE299CFEEEEFEB892DBF8A625F4B48DA2F66A2857D9B6EF994FE8FC412BF9BB741BE63310BC55C34B414167979FDA88E6C5FE2B02A428EC7970D3F7A17BFC2181DD13351B01EA27D9CFE62345D814B5E2150E31F9F7492900290B1BD4973AFF07272426D79E1A02B8D401CD623EE236318FEA5A6C037117CA7FD2BF8F4E2D33B5707D420C526A8A4111CB6689CCDDDFAB452A5C5E33D37E825933E5211BFAE555BE35CB92A55DC32C19147E69EDEC9CA44B07C383E204D983FB1723FC9165AA8C587F1BE969C2FD02919A0CF1DDDCE4B8578314772DC52B2A7115C7697F9E1A74F1E73A9FA925145AC288AD0EDFD73927C3B3165C5E5D81912DFFBB91BE098BF0DBDEE60FBF36C1FEE68A780FB973BBBB9705087080FCD28F5226F2F50B71A1DD3AE6C6E7CE2769EC424F5345D0D5E8C95BCC2DE173D18C4357A20648DA21D9134AC5026AFF78CB0C65528EC84D0D1FC0B99085DA318A176D824C4C821304DBE3FBD777CAAFF483BC0E6E62C20A9782AFE284FC67C7679C40EB06888825FE124B4095CB0FCEC2832F47C65EC5669F33F182163FD4476512DF648158A748B1A58D7F8CD33BE219ACBF50D36003DFDA4055C01260C48F4FE7C1B57262FFF745EC8BDFE885B204B09CB43341785F6DF02EE1F430C73EAC8CFE5421A1A6E2FB705E0A3688EA94115FD0F9890F62751B4EA2C5AC4BD967023233EA0604D98F801A4631278AD15DE98A9B90AAFBFFE9942658E262D312BA9E73CC7B88BF6ED2A197629A76F83FB7E3DA6C31DF0875CFA0B6F63FE76A7022CFC3051CA1069B8E8C94821BE54AD3C4233C5B46E69D93FA26DDE58D775ED58980B258DDB859ED52DEA8D7AC341235521C581CE7F338", 
            32000);
    }

    if(strcmp(argv[1], "sm4_cbc_nopad") == 0) {
        test_sm4_ecb_cbc(1, 0, "74B0DC5119495CFF2AE8944A625558EC", 32, 
            "208247CB3E1E2E76B9AA6CF26F04EAC3", 32);
    }

    if(strcmp(argv[1], "sm2_crypt") == 0) {
        test_sm2_crypt();
    }

    if(strcmp(argv[1], "sm2_gen_keypair") == 0) {
        test_sm2_gen_keypair();
    }

    if(strcmp(argv[1], "sm2_key_exch") == 0) {
        test_sm2_key_exch();
    }

    if(strcmp(argv[1], "sm2_ctx_sv") == 0) {
        test_sm2_ctx_sv();
    }
}

int main(int argc, char ** argv) {
    size_t cmdLen = strlen(argv[1]);
    if (cmdLen < 2) return -1;

    if(strcmp(argv[1], "test_all") == 0) {
        int i;
        char * algs[39] = {
                "gmp_to_mont",
                "gmn_to_mont",
                "gmp_from_mont",
                "gmn_from_mont",
                "gmp_mod_t",
                "gmn_mod_t",
                "gmp_add",
                "gmn_add",
                "gmp_sub",
                "gmn_sub",
                "gmp_mul",
                "gmn_mul",
                "gmp_sqr",
                "gmn_sqr",
                "gmp_exp",
                "gmn_exp",
                "gmp_inv",
                "gmn_inv",
                "point_dbl",
                "point_add",
                "point_mul",
                "gm_sv",
                "gm_sign",
                "gm_verify",
                "gm_sm3",
                "sm2_sv",
                "sm2_sign",
                "sm2_verify",
                "gm_sm4_encrypt",
                "gm_sm4_decrypt",
                "gm_point_codec",
                "sm4_ecb_pkcs7",
                "sm4_ecb_nopad",
                "sm4_cbc_pkcs7",
                "sm4_cbc_nopad",
                "sm2_crypt",
                "sm2_gen_keypair",
                "sm2_key_exch",
                "sm2_ctx_sv"
        };
        for(i = 0; i < 39; i++) {
            argv[1] = algs[i];
            printf("\n%s:\n", argv[1]);
            test(argv);
        }
    }else {
        test(argv);
    }

    return 0;
}