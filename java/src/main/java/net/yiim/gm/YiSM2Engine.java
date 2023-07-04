package net.yiim.gm;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.RandomDSAKCalculator;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECMultiplier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Memoable;
import org.bouncycastle.util.Pack;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

public class YiSM2Engine {
    private final Digest digest;
    private final Digest kdfDigest;

    private ECKeyParameters ecKey;
    private ECDomainParameters ecParams;
    private int curveLength;
    private ECPoint kPB;

    private ByteArrayOutputStream buffer;
    private int currentRound = 1;
    private boolean forEncryption;

    public YiSM2Engine() {
        this(new SM3Digest());
    }

    public YiSM2Engine(Digest digest) {
        this.digest = digest;
        this.buffer = new ByteArrayOutputStream(32);
        if(digest instanceof Memoable && digest.getDigestSize() == 32) {
            this.kdfDigest = (Digest) ((Memoable) digest).copy();
        }else {
            throw new IllegalArgumentException("digest must implements Memoable");
        }
    }


    /**
     * 返回加密后的数据长度
     * @param inputLen 输入数据长度
     * @return 返回加密后数据长度
     */
    public int getOutputSize(int inputLen) {
        return (1 + 2 * curveLength) + inputLen + digest.getDigestSize();
    }

    /**
     * 加密初始
     * @param param 公钥参数
     * @return 返回C1
     */
    public byte[] initForEncryption(CipherParameters param) {
        SecureRandom random;

        if (param instanceof ParametersWithRandom) {
            ParametersWithRandom rParam = (ParametersWithRandom)param;
            random = rParam.getRandom();
            param = rParam.getParameters();
        }else {
            random = CryptoServicesRegistrar.getSecureRandom();
        }

        ecKey = (ECKeyParameters)param;
        ecParams = ecKey.getParameters();

        ECPoint s = ((ECPublicKeyParameters)ecKey).getQ().multiply(ecParams.getH());
        if (s.isInfinity()) {
            throw new IllegalArgumentException("invalid key: [h]Q at infinity");
        }

        curveLength = (ecParams.getCurve().getFieldSize() + 7) / 8;

        ECMultiplier multiplier = createBasePointMultiplier();

        DSAKCalculator kCalculator = new RandomDSAKCalculator();
        kCalculator.init(ecParams.getN(), random);

        BigInteger k = kCalculator.nextK();

        ECPoint c1P = multiplier.multiply(ecParams.getG(), k).normalize();

        byte[] c1 = c1P.getEncoded(false);

        kPB = ((ECPublicKeyParameters)ecKey).getQ().multiply(k).normalize();

        addFieldElement(this.digest, kPB.getAffineXCoord());

        this.forEncryption = true;

        return c1;
    }

    /**
     * 解密初始
     * @param param 私钥参数
     * @param c1 C1
     */
    public void initForDecryption(CipherParameters param, byte[] c1) {
        ecKey = (ECKeyParameters)param;
        ecParams = ecKey.getParameters();
        curveLength = (ecParams.getCurve().getFieldSize() + 7) / 8;

        ECPoint c1P = ecParams.getCurve().decodePoint(c1);

        ECPoint s = c1P.multiply(ecParams.getH());
        if (s.isInfinity()) {
            throw new IllegalArgumentException("[h]C1 at infinity");
        }

        kPB = c1P.multiply(((ECPrivateKeyParameters)ecKey).getD()).normalize();

        addFieldElement(this.digest, kPB.getAffineXCoord());

        this.forEncryption = false;
    }

    private byte[] oneRound(byte[] data, int len) {
        int digestSize = digest.getDigestSize();
        byte[] kdfBuf = new byte[digestSize];

        this.kdfDigest.reset();

        addFieldElement(this.kdfDigest, kPB.getAffineXCoord());
        addFieldElement(this.kdfDigest, kPB.getAffineYCoord());
        Pack.intToBigEndian(this.currentRound++, kdfBuf, 0);
        this.kdfDigest.update(kdfBuf, 0, 4);
        this.kdfDigest.doFinal(kdfBuf, 0);

        if(this.forEncryption) {
            this.digest.update(data, 0, len);
        }

        for(int i = 0; i < len; i++) {
            data[i] ^= kdfBuf[i];
        }

        if(!this.forEncryption) {
            this.digest.update(data, 0, len);
        }

        return data;
    }

    /**
     * 添加待计算数据，每满一轮计算一轮
     * @param input 待计算数据
     * @return 已处理数据，不满一轮时，无输出则返回null
     * @throws IOException 计算异常
     */
    public byte[] update(byte[] input) throws IOException {
        return this.update(input, 0, input.length);
    }

    /**
     * 添加待计算数据，每满一轮计算一轮
     * @param input 待计算数据
     * @param off 数据偏移
     * @param len 数据长度
     * @return 已处理数据，不满一轮时，无输出则返回null
     * @throws IOException 计算异常
     */
    public byte[] update(byte[] input, int off, int len) throws IOException {
        int curLen = buffer.size();
        int wLen = 0;
        ByteArrayOutputStream retBuffer = new ByteArrayOutputStream(curLen + len);

        while (wLen < len) {
            int curWriteLen = 32 - curLen; // 本次预写入的数据长度
            if(curWriteLen > (len - wLen)) {
                // 如果本次预写入长度超过待写入数据的长度
                curWriteLen = len - wLen;
            }
            buffer.write(input, off + wLen, curWriteLen);
            wLen += curWriteLen;
            if (buffer.size() == 32) {
                retBuffer.write(oneRound(buffer.toByteArray(), 32), 0, 32);
                buffer.reset();
            }
            curLen = buffer.size();
        }
        if(retBuffer.size() > 0) return retBuffer.toByteArray();
        return null;
    }

    /**
     * 结束数据处理,解密时要自行用这里输出的C3与密文中的C3进行比较
     * @param c3 用于存储输出C3的缓冲区
     * @param c3Off 缓冲区偏移
     * @return 已处理数据，不满一轮时，无输出则返回null
     */
    public byte[] doFinal(byte[] c3, int c3Off) {
        byte[] ret = null;
        if(buffer.size() > 0) {
            ret = oneRound(buffer.toByteArray(), buffer.size());
        }
        addFieldElement(this.digest, kPB.getAffineYCoord());
        this.digest.doFinal(c3, c3Off);
        return ret;
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }

    private void addFieldElement(Digest digest, ECFieldElement v) {
        byte[] p = BigIntegers.asUnsignedByteArray(curveLength, v.toBigInteger());

        digest.update(p, 0, p.length);
    }
}
