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
    public byte[] cipheredText;
    public byte[] secretKey;
    private short[] publicKeyPolyvec;
    private byte[] seed;

    public void generateKeys(short privateKeyBytes)
    {
        try
        {
            this.generateKyberKeys();
            byte[] privateKeyFixedLength = new byte[privateKeyBytes];
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            byte[] encodedHash = new byte[32];
            this.keccak.doFinal(this.keyPair.publicKey, encodedHash);
            byte[] pkh = new byte[encodedHash.length];
            Util.arrayCopyNonAtomic(encodedHash, (short)0, pkh, (short)0, (short)encodedHash.length);
            byte[] rnd = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
//            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//            random.nextBytes(rnd, (short)0, (short)32);
//            random.close();
            short offsetEnd = (short)keyPair.privateKey.length;
            Util.arrayCopyNonAtomic(this.keyPair.privateKey, (short)0, privateKeyFixedLength, (short)0, offsetEnd);
            Util.arrayCopyNonAtomic(this.keyPair.publicKey, (short)0, privateKeyFixedLength, offsetEnd, (short)this.keyPair.publicKey.length);
            offsetEnd = (short)(offsetEnd + this.keyPair.publicKey.length);
            Util.arrayCopyNonAtomic(pkh, (short)0, privateKeyFixedLength, offsetEnd, (short)pkh.length);
            offsetEnd += (short)pkh.length;
            Util.arrayCopyNonAtomic(rnd, (short)0, privateKeyFixedLength, offsetEnd, (short)rnd.length);
            this.keyPair.privateKey = privateKeyFixedLength;
            //priv = priv || pub || pkh (pub hash) || rnd
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void encapsulate()
    {
        try
        {
            byte[] variant = new byte[32];
            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//            random.nextBytes(variant, (short)0, (short)32);
            random.close();
            byte[] publicKey = KeyPair.getInstance((byte)2).publicKey;
            byte[] sharedSecret = new byte[KyberParams.paramsSymBytes];
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            byte[] buf1 = new byte[32];
            this.keccak.doFinal(variant, buf1);
            byte[] buf2 = new byte[32];
            this.keccak.doFinal(publicKey, buf2);
            byte[] buf3 = new byte[(short)(buf1.length + buf2.length)];
            Util.arrayCopyNonAtomic(buf1, (short)0, buf3, (short)0, (short)buf1.length);
            Util.arrayCopyNonAtomic(buf2, (short)0, buf3, (short)buf1.length, (short)buf2.length);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
            byte[] kr = new byte[64];
            this.keccak.doFinal(buf3, kr);
            byte[] subKr = new byte[(short)(kr.length - KyberParams.paramsSymBytes)];
            Util.arrayCopyNonAtomic(kr, KyberParams.paramsSymBytes, subKr, (short)0, (short)subKr.length);
            byte[] ciphertext = this.encrypt(buf1, publicKey, subKr);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            byte[] krc = new byte[32];
            this.keccak.doFinal(ciphertext, krc);
            byte[] newKr = new byte[(short)(KyberParams.paramsSymBytes + krc.length)];
            Util.arrayCopyNonAtomic(kr, (short)0, newKr, (short)0, KyberParams.paramsSymBytes);
            Util.arrayCopyNonAtomic(krc, (short)0, newKr, KyberParams.paramsSymBytes, (short)krc.length);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
            this.keccak.setShakeDigestLength((short)32);
            this.keccak.doFinal(newKr, sharedSecret);
            this.cipheredText = ciphertext;//dont do this, use it as reference
            this.secretKey = sharedSecret;//dont do this, use it as reference
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public byte[] encrypt(byte[] m, byte[] publicKey, byte[] coins)
    {
        short[] sp = Poly.getInstance().generateNewPolyVector(paramsK);
        short[] ep = Poly.getInstance().generateNewPolyVector(paramsK);
        short[] bp = Poly.getInstance().generateNewPolyVector(paramsK);
        short[] k = Poly.getInstance().polyFromData(m);
        this.unpackPublicKey(publicKey, paramsK);
        byte[] partlySeed = new byte[KyberParams.paramsSymBytes];//Opt this away
        Util.arrayCopyNonAtomic(this.seed, (short)0, partlySeed, (short)0, KyberParams.paramsSymBytes);
        short[] at = this.generateMatrix(partlySeed, true);
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().getNoisePoly(coins, i, paramsK), (short)0, sp,(short)(i*384),(short)384);
            Poly.getInstance().arrayCopyNonAtomic(Poly.getInstance().getNoisePoly(coins, (byte)(i + paramsK), (byte)3), (short)0, ep,(short)(i*384),(short)384);
        }
        short[] epp = Poly.getInstance().getNoisePoly(coins, (byte)(paramsK * 2), (byte)3);
        sp = Poly.getInstance().polyVectorNTT(sp,paramsK);
        sp = Poly.getInstance().polyVectorReduce(sp,paramsK);
        short[] polyArow = new short[(short)(384*paramsK)];
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(at, (short)(i*paramsK*384), polyArow,(short)0,(short)(384*paramsK));
            short[] temp = Poly.getInstance().polyVectorPointWiseAccMont(polyArow, sp, paramsK);
            Poly.getInstance().arrayCopyNonAtomic(temp, (short)0,bp,(short)(i*384),(short)384);
        }
        short[] v = Poly.getInstance().polyVectorPointWiseAccMont(this.publicKeyPolyvec, sp, paramsK);
        bp = Poly.getInstance().polyVectorInvNTTMont(bp, paramsK);
        v = Poly.getInstance().polyInvNTTMont(v);
        bp = Poly.getInstance().polyVectorAdd(bp, ep, paramsK);
        v = Poly.getInstance().polyAdd(Poly.getInstance().polyAdd(v, epp), k);
        bp = Poly.getInstance().polyVectorReduce(bp, paramsK);
        return this.packCiphertext(bp, Poly.getInstance().polyReduce(v), paramsK);
    }

    public byte[] packCiphertext(short[] b, short[] v, byte paramsK)
    {
        byte[] bCompress = Poly.getInstance().compressPolyVector(b, paramsK);
        byte[] vCompress = Poly.getInstance().compressPoly(v, paramsK);
        byte[] returnArray = new byte[(short)(bCompress.length + vCompress.length)];
        Util.arrayCopyNonAtomic(bCompress, (short)0, returnArray, (short)0, (short)bCompress.length);
        Util.arrayCopyNonAtomic(vCompress, (short)0, returnArray, (short)bCompress.length, (short)vCompress.length);
        return returnArray;
    }

    public void unpackPublicKey(byte[] packedPublicKey, byte paramsK)
    {
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            byte[] partlyPublicKey = new byte[KyberParams.paramsPolyvecBytesK512];
            Util.arrayCopyNonAtomic(packedPublicKey, (short)0, partlyPublicKey, (short)0, KyberParams.paramsPolyvecBytesK512);
            this.publicKeyPolyvec = Poly.getInstance().polyVectorFromBytes(partlyPublicKey, paramsK);
            this.seed = new byte[32];//is this always 32?
            Util.arrayCopyNonAtomic(packedPublicKey, KyberParams.paramsPolyvecBytesK512, this.seed, (short)0, (short)32);
            break;
//            case 3:
//                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK768), paramsK));
//                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK768, packedPublicKey.length));
//                break;
//            default:
//                unpackedKey.setPublicKeyPolyvec(Poly.polyVectorFromBytes(Arrays.copyOfRange(packedPublicKey, 0, KyberParams.paramsPolyvecBytesK1024), paramsK));
//                unpackedKey.setSeed(Arrays.copyOfRange(packedPublicKey, KyberParams.paramsPolyvecBytesK1024, packedPublicKey.length));
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
//        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//        random.nextBytes(publicSeed, (short)0, (short)32);
//        random.close();
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
        keyPair.privateKey = this.packPrivateKey(skpv, paramsK);
        keyPair.publicKey = this.packPublicKey(pkpv, publicSeed, paramsK);
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
        byte[] buff = new byte[672];
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