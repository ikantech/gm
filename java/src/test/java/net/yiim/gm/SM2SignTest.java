package net.yiim.gm;


import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SM2SignTest {

    /**
     * r||s编解码器，使得签名结果为64字节的二进制数据
     * 因为大部分场景下，都是需要64字节的签名结果
     */
    private class SM2RSEncoding implements DSAEncoding {
        @Override
        public BigInteger[] decode(BigInteger n, byte[] encoding) throws IOException {
            if(encoding == null || encoding.length != 64) {
                throw new IllegalArgumentException("Malformed signature");
            }
            byte[] buf = new byte[32];
            System.arraycopy(encoding, 0, buf, 0, 32);
            BigInteger r = checkValue(n, new BigInteger(1, buf));
            System.arraycopy(encoding, 32, buf, 0, 32);
            BigInteger s = checkValue(n, new BigInteger(1, buf));
            return new BigInteger[]{r, s};
        }

        @Override
        public byte[] encode(BigInteger n, BigInteger r, BigInteger s) throws IOException {
            ByteArrayOutputStream bout = new ByteArrayOutputStream(65);
            bout.write(BigIntegers.asUnsignedByteArray(32, checkValue(n, r)));
            bout.write(BigIntegers.asUnsignedByteArray(32, checkValue(n, s)));
            return bout.toByteArray();
        }

        BigInteger checkValue(BigInteger n, BigInteger x) {
            if (x.signum() < 0 || (null != n && x.compareTo(n) >= 0)) {
                throw new IllegalArgumentException("Value out of range");
            }

            return x;
        }
    }

    /**
     * 单元测试需要，固定每次签名生成的随机K，实际生产可千万不能这么用
     */
    private class FixedRandom extends SecureRandom {
        byte[] fixedK = Hex.decode("b8b08eae2876ef4e24bc7b3e95373b39246cdcce58aaf6cdaf42874369ba1ff3");
        @Override
        public void nextBytes(byte[] bytes) {
            System.arraycopy(fixedK, 0, bytes, 0, 32);
        }
    }


    /**
     * SM2签名算法，采用默认的USERID：1234567812345678
     */
    @Test
    public void testSignWithDefaultUserId() {
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

            // FIXME 生产时，请勿这样使用
            ParametersWithRandom fixedRandomParameters = new ParametersWithRandom(ecpriv, new FixedRandom());

            // 默认的摘要算法即是SM3
            SM2Signer sm2Signer = new SM2Signer(new SM2RSEncoding());
            // 此时默认的userid为1234567812345678
            sm2Signer.init(true, fixedRandomParameters); // FIXME 注意生产时应直接用ecpriv代替fixedRandomParameters
            // 添加待签名的数据
            sm2Signer.update(new byte[]{0x61, 0x62, 0x63}, 0, 3);
            // 生成签名
            byte[] signature = sm2Signer.generateSignature();

            Assert.assertEquals("edc1431d5871f4f0047775101453f5c7de18ddad9eba7c713fadc23f08e23069b625cf28779efaa432baa3f6682b95534fb6a7fa1c031f2f3778339902f95d66",
                    Hex.toHexString(signature));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    /**
     * SM2签名算法，采用自定义的USERID：1234567887654321
     */
    @Test
    public void testSignWithCustomUserId() {
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

            // 生产时，请勿这样使用
            ParametersWithRandom fixedRandomParameters = new ParametersWithRandom(ecpriv, new FixedRandom());

            // 自定义userid
            ParametersWithID customIdParameters = new ParametersWithID(fixedRandomParameters,
                    Hex.decodeStrict("31323334353637383837363534333231")); // 注意生产时应直接用ecpriv代替fixedRandomParameters

            // 默认的摘要算法即是SM3
            SM2Signer sm2Signer = new SM2Signer(new SM2RSEncoding());
            // 此时的userid为1234567887654321
            sm2Signer.init(true, customIdParameters);
            // 添加待签名的数据
            sm2Signer.update(new byte[]{0x61, 0x62, 0x63}, 0, 3);
            // 生成签名
            byte[] signature = sm2Signer.generateSignature();

            Assert.assertEquals("732286b4258a1bb7cfb4c8b4156f39661bf1785b48531d521e38b5cb1237c90517e8df1a8c7530c8d813af0c4da784b0e69c125fdef9128b6ff3e0b9242ac850",
                    Hex.toHexString(signature));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    /**
     * SM2验签算法，采用默认的USERID：1234567812345678
     */
    @Test
    public void testVerifyWithDefaultUserId() {
        // 获取国密曲线
        X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造Domain参数
        ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
                gmParameters.getG(), gmParameters.getN());

        try {
            // 从压缩公钥中创建点
            ECPoint sm2Q = gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("02a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed72"));

            // 跟私钥一样，在创建ECPublicKeyParameters实例的时候，会去校验点是否符合SM2曲线要求
            ECPublicKeyParameters ecpub = new ECPublicKeyParameters(sm2Q, gmDomainParameters);

            // 默认的摘要算法即是SM3
            SM2Signer sm2Signer = new SM2Signer(new SM2RSEncoding());
            // 此时默认的userid为1234567812345678
            sm2Signer.init(false, ecpub);
            // 添加待签名的数据
            sm2Signer.update(new byte[]{0x61, 0x62, 0x63}, 0, 3);
            // 校验签名
            boolean verifyResult = sm2Signer.verifySignature(Hex.decodeStrict("edc1431d5871f4f0047775101453f5c7de18ddad9eba7c713fadc23f08e23069b625cf28779efaa432baa3f6682b95534fb6a7fa1c031f2f3778339902f95d66"));

            Assert.assertTrue(verifyResult);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    /**
     * SM2验签算法，采用自定义的USERID：1234567887654321
     */
    @Test
    public void testVerifyWithCustomUserId() {
        // 获取国密曲线
        X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造Domain参数
        ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
                gmParameters.getG(), gmParameters.getN());

        try {
            // 从压缩公钥中创建点
            ECPoint sm2Q = gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("02a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed72"));

            // 跟私钥一样，在创建ECPublicKeyParameters实例的时候，会去校验点是否符合SM2曲线要求
            ECPublicKeyParameters ecpub = new ECPublicKeyParameters(sm2Q, gmDomainParameters);

            // 自定义userid
            ParametersWithID customIdParameters = new ParametersWithID(ecpub,
                    Hex.decodeStrict("31323334353637383837363534333231"));

            // 默认的摘要算法即是SM3
            SM2Signer sm2Signer = new SM2Signer(new SM2RSEncoding());
            // 此时的userid为1234567887654321
            sm2Signer.init(false, customIdParameters);
            // 添加待签名的数据
            sm2Signer.update(new byte[]{0x61, 0x62, 0x63}, 0, 3);
            // 校验签名
            boolean verifyResult = sm2Signer.verifySignature(Hex.decodeStrict("732286b4258a1bb7cfb4c8b4156f39661bf1785b48531d521e38b5cb1237c90517e8df1a8c7530c8d813af0c4da784b0e69c125fdef9128b6ff3e0b9242ac850"));

            Assert.assertTrue(verifyResult);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
