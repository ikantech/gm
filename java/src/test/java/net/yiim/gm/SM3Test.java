package net.yiim.gm;

import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;


public class SM3Test {


    /**
     * 摘要算法测试
     */
    @Test
    public void testSM3() {
        try {
            SM3Digest sm3Digest = new SM3Digest();
            // SM3 512比特为一组(64字节)，满一组计算一次，所以直接调它的update方法，不用担心内存问题
            sm3Digest.update(new byte[]{0x61, 0x62, 0x63}, 0, 3);
            byte[] resultBytes = new byte[32];
            sm3Digest.doFinal(resultBytes, 0);

            Assert.assertArrayEquals(resultBytes, Hex.decodeStrict("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"));
        }catch (Exception ex) {
            Assert.fail(ex.getMessage());
        }
    }
}
