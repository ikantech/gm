package net.yiim.gm;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.agreement.SM2KeyExchange;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;

public class SM2KeyExchangeTest {

    @Test
    public void testExchange() {
        // 获取国密曲线
        X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造Domain参数
        ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
                gmParameters.getG(), gmParameters.getN());

        try {
            // SM2KeyExchangePrivateParameters及SM2KeyExchangePublicParameters中ephemeral开头的为随机公私钥
            // 知道这个区别，用BC的SM2KeyExchange来实现SM2密钥协商就简单了

            // 用户A
            ECPrivateKeyParameters userAPrivK = new ECPrivateKeyParameters(
                    new BigInteger(1, Hex.decodeStrict("a09a8cdea50ce62e172c6aab13d1c74cc7b6b3b1f76b3789bfde4db1c4a95d06")),
                    gmDomainParameters);
            ECPublicKeyParameters userAPubK = new ECPublicKeyParameters(gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("0256fbc5499c97e4b3e0b242c78e97f7792b416cbdec84357a7d1e9f52f133982d")), gmDomainParameters);

            // FIXME 生产应随机生成
            ECPrivateKeyParameters userARandPrivK = new ECPrivateKeyParameters(
                    new BigInteger(1, Hex.decodeStrict("0027ebfb3086a7c993134b3fd7abbc911c561558a0cde7ca5fc230c825025cd3")),
                    gmDomainParameters);
            ECPublicKeyParameters userARandPubK = new ECPublicKeyParameters(gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("03953b219b0bd5b4a7fc7e56b1a4c7c9623a6ef8fce63535aca2a421be541f2bdc")), gmDomainParameters);

            byte[] userAId = Hex.decodeStrict("31323334353637383132333435363738");

            // 用户A为发起方
            SM2KeyExchangePrivateParameters userAPrivParams = new SM2KeyExchangePrivateParameters(true, userAPrivK, userARandPrivK);
            ParametersWithID userAPrivIdParams = new ParametersWithID(userAPrivParams, userAId);

            SM2KeyExchange userAKeyExchange = new SM2KeyExchange();
            userAKeyExchange.init(userAPrivIdParams);

            System.out.println("步骤一：");
            System.out.println("用户A为发起方，生成随机SM2密钥对，初始化密钥协商");
            System.out.println("用户A将公钥发送给用户B：0256fbc5499c97e4b3e0b242c78e97f7792b416cbdec84357a7d1e9f52f133982d");
            System.out.println("用户A将随机公钥发送给用户B：03953b219b0bd5b4a7fc7e56b1a4c7c9623a6ef8fce63535aca2a421be541f2bdc");
            System.out.println("用户A将自身USERID发送给用户B：31323334353637383132333435363738");
            System.out.println();

            // 用户B
            ECPrivateKeyParameters userBPrivK = new ECPrivateKeyParameters(
                    new BigInteger(1, Hex.decodeStrict("1baa9c7d28281970da2502730abf275d0300ec410390c3d7c2611daa3d9b9892")),
                    gmDomainParameters);
            ECPublicKeyParameters userBPubK = new ECPublicKeyParameters(gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("029754599adf0d8f71e8cc6bd7c284f0b1e4750c4cb1409d42fe0e4c5690cff705")), gmDomainParameters);

            // FIXME 生产应随机生成
            ECPrivateKeyParameters userBRandPrivK = new ECPrivateKeyParameters(
                    new BigInteger(1, Hex.decodeStrict("eed5f1af1daf647f31eebbb4cea58d16bf7716d085c5ef79c543c645c8c44654")),
                    gmDomainParameters);
            ECPublicKeyParameters userBRandPubK = new ECPublicKeyParameters(gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("021fdfb35f7fb1de5d65b54bd623f3caea0ff8da5e3bc716b6e4342080d8f540f4")), gmDomainParameters);

            byte[] userBId = Hex.decodeStrict("31323334353637383837363534333231");

            // 用户B为响应方
            SM2KeyExchangePrivateParameters userBPrivParams = new SM2KeyExchangePrivateParameters(false, userBPrivK, userBRandPrivK);
            ParametersWithID userBPrivIdParams = new ParametersWithID(userBPrivParams, userBId);

            SM2KeyExchange userBKeyExchange = new SM2KeyExchange();
            userBKeyExchange.init(userBPrivIdParams);

            System.out.println("步骤二：");
            System.out.println("用户B为响应方，生成随机SM2密钥对，初始化密钥协商");

            System.out.println("用户B使用用户A的公钥、随机公钥、USERID来计算密钥及SB");
            // 用A的公钥、随机公钥、USERID生成参数
            // 我这里直接拿A的变量用了，实际要用传过来的公钥、随机公钥、USERID创建对应的userAPubK,、userARandPubK、userAId
            SM2KeyExchangePublicParameters userAPubParams = new SM2KeyExchangePublicParameters(userAPubK, userARandPubK);
            ParametersWithID userAPubIdParams = new ParametersWithID(userAPubParams, userAId);
            byte[][] userBResults = userBKeyExchange.calculateKeyWithConfirmation(128, null, userAPubIdParams);
            System.out.println("用户B计算的密钥：" + Hex.toHexString(userBResults[0]));
            System.out.println();
            System.out.println("用户B将公钥发送给用户A：029754599adf0d8f71e8cc6bd7c284f0b1e4750c4cb1409d42fe0e4c5690cff705");
            System.out.println("用户B将随机公钥发送给用户A：021fdfb35f7fb1de5d65b54bd623f3caea0ff8da5e3bc716b6e4342080d8f540f4");
            System.out.println("用户B将自身USERID发送给用户A：31323334353637383837363534333231");
            System.out.println("用户B将SB发送给用户A：" + Hex.toHexString(userBResults[1]));
            System.out.println();

            // 用B的公钥、随机公钥、USERID生成参数
            // 我这里直接拿B的变量用了，实际要用传过来的公钥、随机公钥、USERID创建对应的userBPubK,、userBRandPubK、userBId
            SM2KeyExchangePublicParameters userBPubParams = new SM2KeyExchangePublicParameters(userBPubK, userBRandPubK);
            ParametersWithID userBPubIdParams = new ParametersWithID(userBPubParams, userBId);
            byte[][] userAResults = userAKeyExchange.calculateKeyWithConfirmation(128, userBResults[1], userBPubIdParams);

            System.out.println("步骤三：");
            System.out.println("用户A使用用户B的公钥、随机公钥、USERID来计算密钥及SA，并校验S1==SB");
            System.out.println("用户A计算的密钥：" + Hex.toHexString(userAResults[0]));
            System.out.println();
            System.out.println("用户A将SA发送给用户B：" + Hex.toHexString(userAResults[1]));
            System.out.println();

            System.out.println("步骤四：");
            // 用户B校验S2==SA
            Assert.assertArrayEquals(userBResults[2], userAResults[1]);
            System.out.println("用户B校验S2==SA");

            // 比较两者计算的密钥是否相等
            Assert.assertArrayEquals(userAResults[0], userBResults[0]);

            // 与预期密钥结果比较
            Assert.assertArrayEquals(userAResults[0], Hex.decodeStrict("d454c84c592dda5da97ce0d9b506ab7e"));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
