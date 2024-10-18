package applet.kyber;

import javacard.framework.*;
import javacard.security.*;

public class KyberAlgorithm
{
    private static KyberAlgorithm kyber = null;

    protected KyberAlgorithm(byte paramsK)
    {
        this.paramsK = paramsK;
        this.keyPair = KeyPair.getInstance(this.paramsK);
    }

    public static KyberAlgorithm getInstance(byte paramsK)
    {
        if (kyber == null) kyber = new KyberAlgorithm(paramsK);
        return kyber;
    }

    private byte paramsK;
    private Keccak keccak;
    private KeyPair keyPair;
    private short[] uniformR;
    private short uniformI = 0;

    public void generateKeys(short privateKeyBytes)
    {
        try
        {
            this.generateKyberKeys();
            byte[] privateKeyFixedLength = new byte[privateKeyBytes];
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            byte[] encodedHash = new byte[32];
            this.keccak.doFinal(this.keyPair.getPublicKey(), encodedHash);
            byte[] pkh = new byte[encodedHash.length];
            Util.arrayCopyNonAtomic(encodedHash, (short)0, pkh, (short)0, (short)encodedHash.length);
            byte[] rnd = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
            random.nextBytes(rnd, (short)0, (short)32);
            random.close();
            short offsetEnd = (short)keyPair.getPrivateKey().length;
            Util.arrayCopyNonAtomic(this.keyPair.getPrivateKey(), (short)0, privateKeyFixedLength, (short)0, offsetEnd);
            Util.arrayCopyNonAtomic(this.keyPair.getPublicKey(), (short)0, privateKeyFixedLength, offsetEnd, (short)this.keyPair.getPublicKey().length);
            offsetEnd = (short)(offsetEnd + this.keyPair.getPublicKey().length);
            Util.arrayCopyNonAtomic(pkh, (short)0, privateKeyFixedLength, offsetEnd, (short)pkh.length);
            offsetEnd += (short)pkh.length;
            Util.arrayCopyNonAtomic(rnd, (short)0, privateKeyFixedLength, offsetEnd, (short)rnd.length);
            this.keyPair.setPrivateKey(privateKeyFixedLength);
            //priv = priv || pub || pkh (pub hash) || rnd
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void generateKyberKeys() throws Exception
    {
        short[] skpv = Poly.getInstance().generateNewPolyVector(this.paramsK);
        short[] pkpv = Poly.getInstance().generateNewPolyVector(this.paramsK);
        short[] e = Poly.getInstance().generateNewPolyVector(this.paramsK);
        byte[] publicSeed = JCSystem.makeTransientByteArray(KyberParams.paramsSymBytes, JCSystem.CLEAR_ON_DESELECT);
        byte[] noiseSeed = new byte[KyberParams.paramsSymBytes];
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        byte[] fullSeed = new byte[(byte)64];
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
        random.nextBytes(publicSeed, (short)0, (short)32);
        random.close();
        this.keccak.doFinal(publicSeed, fullSeed);
        Util.arrayCopyNonAtomic(fullSeed, (short)0, publicSeed, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(fullSeed, KyberParams.paramsSymBytes, noiseSeed, (short)0, KyberParams.paramsSymBytes);
        short[] a = this.generateMatrix(publicSeed, false);
        byte nonce = (byte)0;
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().getNoisePoly(noiseSeed, nonce, paramsK), (short)0, skpv, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().getNoisePoly(noiseSeed, nonce, paramsK), (short)0, e, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        skpv = Poly.getInstance().polyVectorNTT(skpv, paramsK);
        skpv = Poly.getInstance().polyVectorReduce(skpv, paramsK);
        e = Poly.getInstance().polyVectorNTT(e, paramsK);
        for (byte i = 0; i < paramsK; i++)
        {
            short[] polyArow = new short[(short)(384*paramsK)];
            Poly.getInstance().arrayCopyNonAtomic(a, (short)(i*paramsK*384), polyArow,(short)0,(short)(384*paramsK));
            short[] temp = Poly.getInstance().polyVectorPointWiseAccMont(polyArow, skpv, paramsK);
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().polyToMont(temp), (short)0, pkpv, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
        }
        pkpv = Poly.getInstance().polyVectorAdd(pkpv, e, paramsK);
        pkpv = Poly.getInstance().polyVectorReduce(pkpv, paramsK);
        KeyPair keyPair = KeyPair.getInstance(paramsK);
        keyPair.setPrivateKey(this.packPrivateKey(skpv, paramsK));
        keyPair.setPublicKey(this.packPublicKey(pkpv, publicSeed, paramsK));
    }

    public byte[] packPrivateKey(short[] privateKey, byte paramsK)
    {
        return Poly.getInstance().polyVectorToBytes(privateKey, paramsK);
    }

    public byte[] packPublicKey(short[] publicKey, byte[] seed, byte paramsK)
    {
        byte[] initialArray = Poly.getInstance().polyVectorToBytes(publicKey, paramsK);
        byte[] packedPublicKey;
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK512];
            Util.arrayCopyNonAtomic(initialArray, (short)0, packedPublicKey, (short)0, (short)initialArray.length);
            Util.arrayCopyNonAtomic(seed, (short)0, packedPublicKey, (short)initialArray.length, (short)seed.length);
            return packedPublicKey;
//            case 3:
//                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK768];
//                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
//                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
//                return packedPublicKey;
//            default:
//                packedPublicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
//                System.arraycopy(initialArray, 0, packedPublicKey, 0, initialArray.length);
//                System.arraycopy(seed, 0, packedPublicKey, initialArray.length, seed.length);
//                return packedPublicKey;
        }
    }

    public short[] generateMatrix(byte[] seed, boolean transposed)
    {
        //2*2*384 = 1536
        short[] r = new short[(short)(this.paramsK*this.paramsK*KyberParams.paramsPolyBytes)];
        byte[] buf = new byte[672];
        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_128);
        for (byte i = 0; i < this.paramsK; i++)
        {
            for (byte j = 0; j < this.paramsK; j++)
            {
                byte[] ij = new byte[2];
                if (transposed)
                {
                    ij[0] = i;
                    ij[1] = j;
                }
                else
                {
                    ij[0] = j;
                    ij[1] = i;
                }
                byte[] seedAndij = new byte[(short)(seed.length + ij.length)];
                Util.arrayCopyNonAtomic(seed, (short)0, seedAndij, (short)0, (short)seed.length);
                Util.arrayCopyNonAtomic(ij, (short)0, seedAndij, (short)seed.length, (short)ij.length);
                this.keccak.reset();
                this.keccak.setShakeDigestLength((short)buf.length);
                this.keccak.doFinal(seedAndij, buf);
                byte[] buff = new byte[672];
                Util.arrayCopyNonAtomic(buf,(short)0, buff,(short)0, (short)504);
                this.generateUniform(buff, (short)504, KyberParams.paramsN);
                short ui = this.uniformI;
                Poly.getInstance().arrayCopyNonAtomic(this.uniformR, (short)0, r, (short)(((i*2)+j)*384), (short)384);
                while (ui < KyberParams.paramsN)//Occasionally, this code is not always executed
                {
                    Util.arrayCopyNonAtomic(buf,(short)504, buff,(short)0, (short)168);
                    this.generateUniform(buff, (short)168, (short)(KyberParams.paramsN - ui));
                    short ctrn = this.uniformI;
                    short[] missing = this.uniformR;
                    for (short k = ui; k < KyberParams.paramsN; k++)
                    {
                        r[(short)(((i * 2 + j) * 384) + k)] = missing[(short)(k - ui)];
                    }
                    ui += ctrn;
                }
            }
        }
        return r;
    }

    public void generateUniform(byte[] buf, short bufl, short l)
    {
        short[] uniformR = new short[KyberParams.paramsPolyBytes];
        short d1;
        short d2;
        short uniformI = 0; // Always start at 0
        short j = 0;
        while ((uniformI < l) && ((short)(j + 3) <= bufl))
        {
            d1 = (short)(((buf[j] & 0xFF) | ((buf[(short)(j + 1)] & 0xFF) << 8)) & 0xFFF);
            d2 = (short)((((buf[(short)(j + 1)] & 0xFF) >> 4) | ((buf[(short)(j + 2)] & 0xFF) << 4)) & 0xFFF);

            j+=3;
            if (d1 < KyberParams.paramsQ)
            {
                uniformR[uniformI] = d1;
                uniformI++;
            }
            if (uniformI < l && d2 < KyberParams.paramsQ)
            {
                uniformR[uniformI] = d2;
                uniformI++;
            }
        }
        this.uniformI = uniformI;
        this.uniformR = uniformR;
    }
}