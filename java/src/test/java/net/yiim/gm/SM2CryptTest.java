package net.yiim.gm;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;

public class SM2CryptTest {

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
     * 测试公钥加密
     */
    @Test
    public void testEncrypt() {
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

            // FIXME 生产时，请勿这样使用
            ParametersWithRandom fixedRandomParameters = new ParametersWithRandom(ecpub, new FixedRandom());

            YiSM2Engine yiSM2Engine = new YiSM2Engine();
            byte[] c1 = yiSM2Engine.initForEncryption(fixedRandomParameters); // FIXME 注意生产时应直接用ecpub代替fixedRandomParameters
            yiSM2Engine.update(new byte[]{0x61, 0x62, 0x63}, 0, 3); // 因为数据只有3字节，不满一轮，所以这里是不会输出结果的
            byte[] c3 = new byte[32];
            byte[] c2 = yiSM2Engine.doFinal(c3, 0);

            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.init(true, fixedRandomParameters);
            byte[] c1c2c3 = sm2Engine.processBlock(new byte[]{0x61, 0x62, 0x63}, 0, 3);

            // 这里处理一下，更方便比较
            ByteArrayOutputStream aout = new ByteArrayOutputStream(100);
            aout.write(c1);
            aout.write(c2);
            aout.write(c3);

            byte[] myC1C2C3 = aout.toByteArray();

            // 与预期结果比较
            Assert.assertArrayEquals(myC1C2C3,
                    Hex.decodeStrict("04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5278134241f03ef890e33026fcdaf822a2dc48959eea26348c9a699a1217825a7417f25f"));

            // 与BC算法比较
            Assert.assertArrayEquals(myC1C2C3, c1c2c3);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    /**
     * 测试私钥解密
     */
    @Test
    public void testDecrypt() {
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

            YiSM2Engine yiSM2Engine = new YiSM2Engine();
            yiSM2Engine.initForDecryption(ecpriv,
                    Hex.decodeStrict("04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f52"));
            yiSM2Engine.update(new byte[]{0x78, 0x13, 0x42}, 0, 3); // 因为数据只有3字节，不满一轮，所以这里是不会输出结果的
            byte[] c3 = new byte[32];
            byte[] c2 = yiSM2Engine.doFinal(c3, 0);

            SM2Engine sm2Engine = new SM2Engine();
            sm2Engine.init(false, ecpriv);
            byte[] plainBytes = sm2Engine.processBlock(
                    Hex.decodeStrict("04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5278134241f03ef890e33026fcdaf822a2dc48959eea26348c9a699a1217825a7417f25f"), 0, 100);

            // 比较解密计算的C3与预期是否一样
            Assert.assertArrayEquals(c3, Hex.decodeStrict("41f03ef890e33026fcdaf822a2dc48959eea26348c9a699a1217825a7417f25f"));

            // 比较解密的C2与预期的明文是否一样
            Assert.assertArrayEquals(c2, new byte[]{0x61, 0x62, 0x63});

            // 与BC计算结果相比较
            Assert.assertArrayEquals(c2, plainBytes);
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    /**
     * 测试算法的正确性，多样本覆盖
     */
    @Test
    public void testAlg() {
        // 获取国密曲线
        X9ECParameters gmParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造Domain参数
        ECDomainParameters gmDomainParameters = new ECDomainParameters(gmParameters.getCurve(),
                gmParameters.getG(), gmParameters.getN());

        byte[] plainBytes = Hex.decodeStrict("3187bc006d750266e579d12acb0a67ea8057a35c4d0357df7034115ba9249d1315210962527f8e66d9d77bc7572fde210f8179201e91caebe7abe4b70965cf2fd0f67b54e1a162cbff2e68026b789569c3e7744996703472586deb3fa7c72a37feeaca");

        try {
            int [][] rounds = new int[][] {
                    // 第一轮数据小于32
                    {3, 0},  // 只加一轮数据
                    {3, 6},  // 两轮数据总和小于32
                    {3, 29}, // 两轮数据正好等于32
                    {3, 32}, // 第二轮数据正好等于32
                    {3, 33}, // 第二轮数据大于32
                    {3, 61}, // 两轮数据正好是32的两倍
                    {3, 64}, // 两轮数据大于32的两倍

                    // 第二轮数据等于32
                    {32, 0},
                    {32, 6},
                    {32, 29},
                    {32, 32},
                    {32, 33},
                    {32, 61},
                    {32, 64},

                    // 第二轮数据大于32
                    {35, 0},
                    {35, 6},
                    {35, 29},
                    {35, 32},
                    {35, 33},
                    {35, 61},
                    {35, 64},
            };

            String[] expects = new String[] {
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d27be058de611ed7196e2a2edada9a401cdb2969fdadce19ed7a945a2bf0dc472",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da49871fe7c904bd823f84856ddebb49bc551979ae3651e6c2f93efa7130b835a2a1",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da3e4eb57cb0bd1c47e99a0f1dcb741f8cc23edddb82d0fef90b254c8505c72ce6",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992937c4728113ccbac3d1eefb2a38095e1a4897a7743bb5ffa45dac288e3afac8b54",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ecfd6ba15dc9b837bba45a7de554a619095bc0163bd5cc30b51819bd805c45e17",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea5574986212f0e6f3c860cc4c2845271b7ea085afc96ee537304a482ed63c0e9e7dd4e",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea557496914da9a6e10c637d24731edc6cbb5bb450a45517604240cb49e3d9d5d68cd2d0b7347",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da3e4eb57cb0bd1c47e99a0f1dcb741f8cc23edddb82d0fef90b254c8505c72ce6",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec999ae24e250fc8d268cb8a0d6e47a14c0e9be626d6849e752c81db607d0b5cbda0b",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3e57824ac49f9526b84b39fa4e6560bc2432fe656a1416249f6750e0c113ce120f",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea5574986212f0e6f3c860cc4c2845271b7ea085afc96ee537304a482ed63c0e9e7dd4e",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea5574969ae31daf7c9f02be0f4942d00eab0b27b4ed5ffd2e27f4fea3163c128bc3bc6cb",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea557496914dab88c6c8f29537f89d2f721f9975e57ac4bd03d9755e11d366352a57d01d6ac3cddb518765eeea674fe42a3f322588d96c4afa67f11cc3e804f32",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea557496914dab88c6c8f29537f89d2f721f9975e57ac4bd03d9755e11d3663522c6d6d7d0a2d622cf3977304331515f3ecd240d1905f9fe7bc0461bcf4b6c224b23d90",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992937c4728113ccbac3d1eefb2a38095e1a4897a7743bb5ffa45dac288e3afac8b54",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebc41849913154cb9778412c21e81ffda7f6a9282b2d711466190a3a867957493f",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea5574986212f0e6f3c860cc4c2845271b7ea085afc96ee537304a482ed63c0e9e7dd4e",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea557496914da9a6e10c637d24731edc6cbb5bb450a45517604240cb49e3d9d5d68cd2d0b7347",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea557496914dab8cc9e93a554c4afe69d713eb5d5257395d438642f6d850140ef6d06930f413ce3",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea557496914dab88c6c8f29537f89d2f721f9975e57ac4bd03d9755e11d3663522c6d6d7d0a2d622cf3977304331515f3ecd240d1905f9fe7bc0461bcf4b6c224b23d90",
                    "04a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed724a1411c7fef1c108a2e71dc421c2d18fd0ef183e97f600ab06e84dfdc6c55f5228f69d1d6a80c3da493e4e14ea01f8861409f30dfb054b92811676abe7fd33da6992938ec9991bd8ebec35c1169e054522afaf2882c7070019bd54fb3ea557496914dab88c6c8f29537f89d2f721f9975e57ac4bd03d9755e11d3663522c6d6d7af11b5a03a2dde8b2e114681ee289955879ef605e1b68f1a0189240dae7ababed2cd3"
            };

            // 设BC的算法是正确的

            // 从压缩公钥中创建点
            ECPoint sm2Q = gmDomainParameters.getCurve().decodePoint(
                    Hex.decode("02a9036e0289d9fa6d566cd0500807e3cba1ce14ba9b58bfbbef00b4b8d502ed72"));

            // 跟私钥一样，在创建ECPublicKeyParameters实例的时候，会去校验点是否符合SM2曲线要求
            ECPublicKeyParameters ecpub = new ECPublicKeyParameters(sm2Q, gmDomainParameters);

            // 生产时，请勿这样使用
            ParametersWithRandom fixedRandomParameters = new ParametersWithRandom(ecpub, new FixedRandom());

            // 创建无符号大数
            BigInteger sm2D = new BigInteger(1,
                    Hex.decode("b8b08eae2876ef4e24bc7b3e95373b39246cdcce58aaf6cdaf42874369ba1ff3"));

            // 创建SM2私钥，ECPrivateKeyParameters实例创建时，会去校验大数是否符合SM2曲线的要求
            ECPrivateKeyParameters ecpriv = new ECPrivateKeyParameters(sm2D, gmDomainParameters);

            for(int i = 0; i < rounds.length; i++) {
                // 加密测试
                ByteArrayOutputStream bout = new ByteArrayOutputStream(rounds[i][0] + rounds[i][1] + 97);

                YiSM2Engine yiSM2Engine = new YiSM2Engine();
                byte[] c1 = yiSM2Engine.initForEncryption(fixedRandomParameters);
                bout.write(c1);

                int off = 0;
                for(int j = 0; j < rounds[i].length; j++) {
                    byte[] c2 = yiSM2Engine.update(plainBytes, off, rounds[i][j]);
                    if (c2 != null) {
                        bout.write(c2);
                    }
                    off += rounds[i][j];
                }

                byte[] c3 = new byte[32];
                byte[] c2 = yiSM2Engine.doFinal(c3, 0);
                if(c2 != null) {
                    bout.write(c2);
                }
                bout.write(c3);

                byte[] myC1C2C3 = bout.toByteArray();

                SM2Engine sm2Engine = new SM2Engine();
                sm2Engine.init(true, fixedRandomParameters);
                byte[] c1c2c3 = sm2Engine.processBlock(plainBytes, 0, rounds[i][0] + rounds[i][1]);

                Assert.assertArrayEquals(myC1C2C3, c1c2c3);

                Assert.assertArrayEquals(myC1C2C3, Hex.decodeStrict(expects[i]));


                // 解密测试
                yiSM2Engine = new YiSM2Engine();
                yiSM2Engine.initForDecryption(ecpriv, Hex.decodeStrict(expects[i], 0, 130));
                bout = new ByteArrayOutputStream(rounds[i][0] + rounds[i][1]);
                off = 130;
                for(int j = 0; j < rounds[i].length; j++) {
                    c2 = yiSM2Engine.update(Hex.decodeStrict(expects[i], off, rounds[i][j] * 2));
                    if(c2 != null) {
                        bout.write(c2);
                    }
                    off += rounds[i][j] * 2;
                }

                c2 = yiSM2Engine.doFinal(c3, 0);
                if(c2 != null) {
                    bout.write(c2);
                }

                // 比较C3是否相同
                Assert.assertArrayEquals(c3, Hex.decodeStrict(expects[i], off, 64));
                // 比较原文是否相同
                byte[] exceptPlainBytes = new byte[(off - 130) / 2];
                System.arraycopy(plainBytes, 0, exceptPlainBytes, 0, exceptPlainBytes.length);
                Assert.assertArrayEquals(bout.toByteArray(), exceptPlainBytes);
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
