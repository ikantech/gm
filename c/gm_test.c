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

void test_gm_sm4(const unsigned char * key, int mode, 
    const unsigned char * input, 
    const unsigned char * output_hex) {

    int i = 0;
    unsigned char buf[16] = {0};
    char res[33] = {0};

    memcpy(buf, input, 16);

    for(i = 0; i < 100000; i++) {
        gm_sm4_crypt(key, mode, buf, buf);
    }

    for (i = 0; i < 16; i++) {
        sprintf(res + i * 2, "%02X", (buf[i] & 0x0FF));
    }

    printf("r = %s\n", res);
    printf("test result: %s\n", (strcmp(output_hex, res) == 0 ? "ok" : "fail"));
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
        test_gm_sm4(key, 0, input,
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
        test_gm_sm4(key, 1, input,
                    "74B0DC5119495CFF2AE8944A625558EC");
    }
}

int main(int argc, char ** argv) {
    size_t cmdLen = strlen(argv[1]);
    if (cmdLen < 2) return -1;

    if(strcmp(argv[1], "test_all") == 0) {
        int i;
        char * algs[30] = {
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
                "gm_sm4_decrypt"
        };
        for(i = 0; i < 30; i++) {
            argv[1] = algs[i];
            printf("\n%s:\n", argv[1]);
            test(argv);
        }
    }else {
        test(argv);
    }

    return 0;
}