package net.yiim.gm;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.Security;

public class SM4Test {

    /**
     * 生成SM4密钥
     * SM4密钥没有特别的要求，只要是128比特的随机数据即可
     */
    @Test
    public void testKeygen() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            KeyGenerator keyGenerator = KeyGenerator.getInstance("SM4", BouncyCastleProvider.PROVIDER_NAME);

            keyGenerator.init(128);

            SecretKey secretKey = keyGenerator.generateKey();

            System.out.println("key: " + Hex.toHexString(secretKey.getEncoded()));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    /**
     * 测试SM4 NoPadding 加解密，CBC注意多传一个IV，IV的大小等于BlockSize
     * 注意每轮数据长度必须等于SM4 BlockSize的倍数，也即16字节的倍数
     * 可以取消System.out.println的注释，关注每一轮的输出，每满一轮就会输出数据，可以用来处理大文件
     */
    @Test
    public void testSM4NoPadding() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            String[] rounds = new String[] {
                    "SM4/ECB/NoPadding",
                    "SM4/CBC/NoPadding"
            };
            String[] roundPlains = new String[] {
                    "4167c4875cf2f7a2297da02b8f4ba8e0",
                    "b8b08eae2876ef4e24bc7b3e95373b39246cdcce58aaf6cdaf42874369ba1ff3"
            };
            String[] roundCiphers = new String[] {
                    "daf80aa49ffd52889f1ce80cd88d2370a1e81e96766eeba7b95cf8d038d4214d19ea48263076a6d3bb04a09e3f947331",
                    "957900f635ddfba3c457367d7c6d7c3a9389c5ca9c0848cc222f5902222399b804f5a7b47d21576cf590043a83f68b20"
            };

            // 密钥大小为16字节
            Key sm4Key = new SecretKeySpec(Hex.decodeStrict("66c7f0f462eeedd9d1f2d46bdc10e4e2"), "SM4");
            // IV大小等于blockSize，也即16字节
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Hex.decodeStrict("a9036e0289d9fa6d566cd0500807e3cb"));

            for (int i = 0; i < rounds.length; i++) {
                String alg = rounds[i];

                // NoPadding 加密
                ByteArrayOutputStream bout = new ByteArrayOutputStream(48);
                Cipher cipher = Cipher.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
                if(alg.contains("CBC")) {
                    cipher.init(Cipher.ENCRYPT_MODE, sm4Key, ivParameterSpec);
                }else {
                    cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
                }

                for (String plain: roundPlains) {
                    byte[] cipherBytes = cipher.update(Hex.decodeStrict(plain));
                    if(cipherBytes != null && cipherBytes.length > 0) {
                        // System.out.println("cipher bytes is not null, length: " + cipherBytes.length);
                        bout.write(cipherBytes);
                    }
                }
                byte[] cipherBytes = cipher.doFinal();
                if(cipherBytes != null && cipherBytes.length > 0) {
                    // System.out.println("cipher bytes is not null 3, length: " + cipherBytes.length);
                    bout.write(cipherBytes);
                }

                cipherBytes = bout.toByteArray();
                Assert.assertArrayEquals(cipherBytes, Hex.decodeStrict(roundCiphers[i]));


                // NoPadding 解密
                bout.reset();

                cipher = Cipher.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
                if(alg.contains("CBC")) {
                    cipher.init(Cipher.DECRYPT_MODE, sm4Key, ivParameterSpec);
                }else {
                    cipher.init(Cipher.DECRYPT_MODE, sm4Key);
                }
                byte[] plainBytes = cipher.update(cipherBytes, 0, 16);
                if(plainBytes != null && plainBytes.length > 0) {
                    bout.write(plainBytes);
                }

                plainBytes = cipher.update(cipherBytes, 16, 32);
                if(plainBytes != null && plainBytes.length > 0) {
                    bout.write(plainBytes);
                }
                plainBytes = cipher.doFinal();
                if(plainBytes != null && plainBytes.length > 0) {
                    bout.write(plainBytes);
                }

                plainBytes = bout.toByteArray();
                Assert.assertArrayEquals(plainBytes, Hex.decodeStrict(roundPlains[0] + roundPlains[1]));
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }

    /**
     * 测试SM4 PKCS7Padding 加解密
     * BC中PKCS5PADDING和PKCS7PADDING处理方式是一样的，数据长度不满blocksize大小时，填充至blocksize大小，正好相等时，再填充一个blocksize的大小
     * 详细的填充算法网上搜索一下，不复杂
     */
    @Test
    public void testSM4PKCS7Padding() {
        try {
            Security.addProvider(new BouncyCastleProvider());

            String[] rounds = new String[] {
                    "SM4/ECB/PKCS7Padding",
                    "SM4/CBC/PKCS7Padding"
            };

            String[] roundCiphers = new String[] {
                    "609155d62e40228f3883f366e25d1ded",
                    "1f011e071fa90af38e2bd150471290ad"
            };

            // 密钥大小为16字节
            Key sm4Key = new SecretKeySpec(Hex.decodeStrict("66c7f0f462eeedd9d1f2d46bdc10e4e2"), "SM4");
            // IV大小等于blockSize，也即16字节
            IvParameterSpec ivParameterSpec = new IvParameterSpec(Hex.decodeStrict("a9036e0289d9fa6d566cd0500807e3cb"));

            for (int i = 0; i < rounds.length; i++) {
                String alg = rounds[i];

                // PKCS7Padding 加密
                ByteArrayOutputStream bout = new ByteArrayOutputStream(48);
                Cipher cipher = Cipher.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
                if(alg.contains("CBC")) {
                    cipher.init(Cipher.ENCRYPT_MODE, sm4Key, ivParameterSpec);
                }else {
                    cipher.init(Cipher.ENCRYPT_MODE, sm4Key);
                }
                byte[] cipherBytes = cipher.update(Hex.decodeStrict("616263"));
                if (cipherBytes != null && cipherBytes.length > 0) {
                    bout.write(cipherBytes);
                }

                cipherBytes = cipher.doFinal();
                if (cipherBytes != null && cipherBytes.length > 0) {
                    bout.write(cipherBytes);
                }

                cipherBytes = bout.toByteArray();
                Assert.assertArrayEquals(cipherBytes, Hex.decodeStrict(roundCiphers[i]));


                // PKCS7Padding 解密
                bout.reset();

                cipher = Cipher.getInstance(alg, BouncyCastleProvider.PROVIDER_NAME);
                if(alg.contains("CBC")) {
                    cipher.init(Cipher.DECRYPT_MODE, sm4Key, ivParameterSpec);
                }else {
                    cipher.init(Cipher.DECRYPT_MODE, sm4Key);
                }
                byte[] plainBytes = cipher.update(cipherBytes, 0, 16);
                if (plainBytes != null && plainBytes.length > 0) {
                    bout.write(plainBytes);
                }

                plainBytes = cipher.doFinal();
                if (plainBytes != null && plainBytes.length > 0) {
                    bout.write(plainBytes);
                }

                plainBytes = bout.toByteArray();
                Assert.assertArrayEquals(plainBytes, Hex.decodeStrict("616263"));
            }
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
