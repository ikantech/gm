package net.yiim.gm;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.security.SecureRandom;

public class SM2KeyTest {

    /**
     * SM2 密钥对的生成
     */
    @Test
    public void testGenKeypair() {
        // 获取国密曲线
        X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造Domain参数
        ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
                gmParameters.getG(), gmParameters.getN());

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(gmDomainParameters, new SecureRandom()));

        // 生成密钥对
        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keyPair.getPublic();

        // 注意这里需要用到BigIntegers.asUnsignedByteArray将私钥转换为二进制数组，并且指定二进制数组的长度为32字节
        // 如果不这样做，遇到大数最高字节超出byte表示范围的（如0xF0），ecpriv.getD().toByteArray()这样转出来的二进
        // 制数组长度会是33字节，下标为0的数据为0x00，即补了一字节的0。而对于大数长度不满32字节的呢，转出来的二进制数组
        // 长度也不是32字节，这不符合一般的应用要求（一般我们认为SM2的私钥就是32字节长度256bit的一个大数）
        System.out.println("私钥：" + Hex.toHexString(BigIntegers.asUnsignedByteArray(32, ecpriv.getD())));

        // 压缩公钥即为：yTile || X
        System.out.println("压缩公钥：" + Hex.toHexString(ecpub.getQ().getEncoded(true)));

        // 未压缩公钥即为：PC || X || Y，其中PC = 0x04，有些文档里公钥写64字节，其实就是省略了PC这一个字节
        System.out.println("公钥：" + Hex.toHexString(ecpub.getQ().getEncoded(false)));
    }

    /**
     * 从十六进制字符串或二进制数组中创建一个SM2私钥参数
     * 无论是后续加解密，还是签名验签，都会用到ECPrivateKeyParameters
     */
    @Test
    public void testCreatePrivK() {
        // 获取国密曲线
        X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造Domain参数
        ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
                gmParameters.getG(), gmParameters.getN());

        try {
            // 创建无符号大数
            BigInteger sm2D = new BigInteger(1,
                    Hex.decode("b8b08eae2876ef4e24bc7b3e95373b39246cdcce58aaf6cdaf42874369ba1ff3"));

            // 创建SM2私钥，ECPrivateKeyParameters实例创建时，会去校验大数是否符合SM2曲线的要求
            ECPrivateKeyParameters ecpriv = new ECPrivateKeyParameters(sm2D, gmDomainParameters);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }

        try {
            // 测试一个非法的私钥
            BigInteger sm2D = new BigInteger(1,
                    Hex.decode("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54124"));

            ECPrivateKeyParameters ecpriv = new ECPrivateKeyParameters(sm2D, gmDomainParameters);
            Assert.fail("大数不在[1, n - 1]范围");
        }catch (Exception ex) {
            Assert.assertEquals("Scalar is not in the interval [1, n - 1]", ex.getMessage());
        }
    }

    /**
     * 从十六进制字符串或二进制数组中创建一个SM2公钥参数
     * 无论是后续加解密，还是签名验签，都会用到ECPublicKeyParameters
     */
    @Test
    public void testCreatePubK() {
        // 获取国密曲线
        X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造Domain参数
        ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
                gmParameters.getG(), gmParameters.getN());

        try {
            // 从压缩公钥中创建点
            ECPoint sm2Q = gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("03aa8644b5ffafe526a6ed5dbeb09a1743b919f078da457536bc3c381d4ada6801"));

            // 跟私钥一样，在创建ECPublicKeyParameters实例的时候，会去校验点是否符合SM2曲线要求
            ECPublicKeyParameters ecpub = new ECPublicKeyParameters(sm2Q, gmDomainParameters);

            // 这里跟未压缩的公钥进行比较
            Assert.assertEquals(Hex.toHexString(ecpub.getQ().getEncoded(false)),
                    "04aa8644b5ffafe526a6ed5dbeb09a1743b919f078da457536bc3c381d4ada6801d57ff1f6acc7547121bfb36e5eda717c2be60bcd2542e1d1857924b6a5f11bfb");
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }

        try {
            // 从未压缩公钥中创建点，decodePoint会校验点是否合法
            ECPoint sm2Q = gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("04aa8644b5ffafe526a6ed5dbeb09a1743b919f078da457536bc3c381d4ada6801d57ff1f6acc7547121bfb36e5eda717c2be60bcd2542e1d1857924b6a5f11bfb"));

            // 跟私钥一样，在创建ECPublicKeyParameters实例的时候，会去校验点是否符合SM2曲线要求
            ECPublicKeyParameters ecpub = new ECPublicKeyParameters(sm2Q, gmDomainParameters);

            // 这里跟压缩的公钥进行比较
            Assert.assertEquals(Hex.toHexString(ecpub.getQ().getEncoded(true)),
                    "03aa8644b5ffafe526a6ed5dbeb09a1743b919f078da457536bc3c381d4ada6801");
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }

        try {
            // 从未压缩公钥中创建点，decodePoint会校验点是否合法
            ECPoint sm2Q = gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("0432C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A2"));

            // 跟私钥一样，在创建ECPublicKeyParameters实例的时候，会去校验点是否符合SM2曲线要求
            ECPublicKeyParameters ecpub = new ECPublicKeyParameters(sm2Q, gmDomainParameters);

            Assert.fail("无效点");
        }catch (Exception ex) {
            Assert.assertEquals("Invalid point coordinates", ex.getMessage());
        }
    }

    /**
     * 从私钥中获取公钥
     */
    @Test
    public void testGetPubKFromPrivK() {
        // 获取国密曲线
        X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造Domain参数
        ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
                gmParameters.getG(), gmParameters.getN());
        try {
            // 创建无符号大数
            BigInteger sm2D = new BigInteger(1,
                    Hex.decode("b8b08eae2876ef4e24bc7b3e95373b39246cdcce58aaf6cdaf42874369ba1ff3"));

            // 创建SM2私钥，ECPrivateKeyParameters实例创建时，会去校验大数是否符合SM2曲线的要求
            ECPrivateKeyParameters ecpriv = new ECPrivateKeyParameters(sm2D, gmDomainParameters);

            // 从私钥中获取公钥
            ECPoint sm2Q = gmDomainParameters.getG().multiply(sm2D);

            // 创建SM2公钥参数，在创建ECPublicKeyParameters实例的时候，会去校验点是否符合SM2曲线要求
            ECPublicKeyParameters ecpub = new ECPublicKeyParameters(sm2Q, gmDomainParameters);

            // 与预期的压缩公钥进行比较
            Assert.assertEquals("02a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed72",
                    Hex.toHexString(ecpub.getQ().getEncoded(true)));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
