package applet.kyber;

import javacard.framework.*;
import javacard.security.*;

public class KyberAlgorithm
{
    private static KyberAlgorithm kyber = null;

    protected KyberAlgorithm(byte paramsK)
    {
        //Create keccak instance so object is created, reserving EEPROM at startup rather than runtime
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        this.paramsK = paramsK;
        this.keyPair = KeyPair.getInstance(paramsK);
        this.poly = Poly.getInstance();
        switch (paramsK)
        {
            case 2:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK768];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                break;
            case 3:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK768];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
                break;
            default:
                this.vCompress = new byte[KyberParams.paramsPolyCompressedBytesK1024];
                this.bCompress = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
                break;
        }
        this.returnArray = new byte[(short)(this.bCompress.length + this.vCompress.length)];
        EEPROM384S_X_PARAMS_K_1 = new short[(short)(384*paramsK)];
        EEPROM384S_X_PARAMS_K_2 = new short[(short)(384*paramsK)];
        EEPROM384S_X_PARAMS_K_3 = new short[(short)(384*paramsK)];
        EEPROM384S_X_PARAMS_K_4 = new short[(short)(384*paramsK)];
        EEPROM384S_X_PARAMS_K_X_PARAMS_K = new short[(short)(384*paramsK*paramsK)];
        EEPROM384B_X_PARAMS_K = new byte[(short)(384*paramsK)];
        EEPROM384 = new short[384];
        EEPROM384_2 = new short[384];
        EEPROM32B_1 = new byte[32];
        EEPROM32B_2 = new byte[32];
        EEPROM672B_1 = new byte[672];
        EEPROM504B_1 = new byte[504];
        EEPROM768B_1 = new byte[768];
        RAM2B_1 = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        EEPROM34_1 = new byte[34];
        EEPROM64B_1 = new byte[64];
        EEPROM64B_2 = new byte[64];
        EEPROM256S_1 = new short[256];
        this.seed = new byte[32];
        this.publicKeyPolyvec = new short[(short)(384*paramsK)];
    }

    public static KyberAlgorithm getInstance(byte paramsK)
    {
        if (kyber == null) kyber = new KyberAlgorithm(paramsK);
        return kyber;
    }

    private byte paramsK;
    private Keccak keccak;
    private KeyPair keyPair;
    private Poly poly;

    //Conditional arrays based on paramsK
    byte[] vCompress;//packCiphertext
    byte[] bCompress;//packCiphertext
    byte[] returnArray;//packCiphertext
    short[] EEPROM384S_X_PARAMS_K_X_PARAMS_K;
    byte[] EEPROM384B_X_PARAMS_K;
    short[] EEPROM384S_X_PARAMS_K_1;
    short[] EEPROM384S_X_PARAMS_K_2;
    short[] EEPROM384S_X_PARAMS_K_3;
    short[] EEPROM384S_X_PARAMS_K_4;

    byte[] RAM2B_1;
    byte[] EEPROM34_1;
    byte[] EEPROM32B_1;
    byte[] EEPROM32B_2;
    byte[] EEPROM64B_1;
    byte[] EEPROM64B_2;
    short[] EEPROM256S_1;
    byte[] EEPROM672B_1;
    byte[] EEPROM768B_1;
    byte[] EEPROM504B_1;
    short[] EEPROM384;
    short[] EEPROM384_2;

    private short uniformI = 0;
    public byte[] secretKey;
    private short[] publicKeyPolyvec;
    private byte[] seed;
    public byte[] encapsulation;
    public byte[] plain;
    private short[] bp;
    private short[] v;

    public void generateKeys(short privateKeyBytes)
    {
        try
        {
            this.generateKyberKeys();
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            this.keccak.doFinal(this.keyPair.publicKey, EEPROM32B_1);
//            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//            random.nextBytes(this.EEPROM32B_2, (short)0, (short)32);
//            random.close();
            short offsetEnd = (short)(this.paramsK * KyberParams.paramsPolyBytes);
            Util.arrayCopyNonAtomic(this.keyPair.publicKey, (short)0, this.keyPair.privateKey, offsetEnd, (short)this.keyPair.publicKey.length);
            offsetEnd = (short)(offsetEnd + this.keyPair.publicKey.length);
            Util.arrayCopyNonAtomic(this.EEPROM32B_1, (short)0, this.keyPair.privateKey, offsetEnd, (short)this.EEPROM32B_1.length);
            offsetEnd += (short)this.EEPROM32B_1.length;
            Util.arrayCopyNonAtomic(this.EEPROM32B_2, (short)0, this.keyPair.privateKey, offsetEnd, (short)this.EEPROM32B_2.length);
            //priv = priv || pub || pkh (pub hash) || rnd
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void decapsulate(short secretKeyBytes, short publicKeyBytes, short privateKeyBytes)
    {
        try
        {
            byte[] sharedSecretFixedLength = new byte[KyberParams.KyberSSBytes];
            byte[] indcpaPrivateKey = new byte[secretKeyBytes];
            Util.arrayCopyNonAtomic(this.keyPair.privateKey, (short)0, indcpaPrivateKey, (short)0, (short)indcpaPrivateKey.length);
            byte[] publicKey = new byte[publicKeyBytes];
            Util.arrayCopyNonAtomic(this.keyPair.privateKey, secretKeyBytes, publicKey, (short)0, (short)publicKey.length);
            //buf renamed to plain
            byte[] plain = this.decrypt(this.encapsulation, indcpaPrivateKey);
            short ski = (short)(privateKeyBytes - (2 * KyberParams.paramsSymBytes));
            byte[] newBuf = new byte[(short)(plain.length + KyberParams.paramsSymBytes)];
            Util.arrayCopyNonAtomic(plain, (short)0, newBuf, (short)0, (short)plain.length);
            Util.arrayCopyNonAtomic(this.keyPair.privateKey, ski, newBuf, (short)plain.length, KyberParams.paramsSymBytes);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
            byte[] kr = new byte[64];
            this.keccak.doFinal(newBuf, kr);
            byte[] subKr = new byte[(short)(kr.length - KyberParams.paramsSymBytes)];
            Util.arrayCopyNonAtomic(kr, KyberParams.paramsSymBytes, subKr, (short)0, (short)subKr.length);
            this.encrypt(plain, publicKey, subKr);
            byte[] cmp = this.returnArray;//todo need opt
            byte fail = this.constantTimeCompare(this.encapsulation, cmp);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            byte[] krh = new byte[32];
            this.keccak.doFinal(this.encapsulation, krh);
            short index = (short)(privateKeyBytes - KyberParams.paramsSymBytes);
            for (byte i = 0; i < KyberParams.paramsSymBytes; i++)
            {
                byte privateKeyIndex = (byte)(this.keyPair.privateKey[index] & (byte)0xFF);
                byte krIndex = (byte)(kr[i] & (byte)0xFF);
                kr[i] = (byte)(krIndex ^ (byte)(fail & (byte)0xFF & (byte)(privateKeyIndex ^ krIndex)));
                index += 1;
            }
            byte[] tempBuf = new byte[(short)(KyberParams.paramsSymBytes + krh.length)];
            Util.arrayCopyNonAtomic(kr, (short)0, tempBuf, (short)0, KyberParams.paramsSymBytes);
            Util.arrayCopyNonAtomic(krh, (short)0, tempBuf, KyberParams.paramsSymBytes, (short)krh.length);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
            this.keccak.setShakeDigestLength((short)32);
            this.keccak.doFinal(tempBuf, sharedSecretFixedLength);
            this.plain = plain;
            this.secretKey = sharedSecretFixedLength;
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public byte[] decrypt(byte[] packedCipherText, byte[] privateKey)
    {
        this.unpackCiphertext(packedCipherText, this.paramsK);
        short[] unpackedPrivateKey = new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
        this.unpackPrivateKey(privateKey, this.paramsK, unpackedPrivateKey);
        Poly.getInstance().polyVectorNTT(this.bp, this.paramsK);
        Poly.getInstance().polyVectorPointWiseAccMont(unpackedPrivateKey, this.bp, this.paramsK, EEPROM384);//EEPROM384 = mp
        Poly.getInstance().polyInvNTTMont(EEPROM384);
        Poly.getInstance().polySub(this.v, EEPROM384);
        Poly.getInstance().polyReduce(this.v);
        byte[] msg = new byte[KyberParams.paramsSymBytes];
        Poly.getInstance().polyToMsg(this.v, msg);
        return msg;
    }

    public void unpackPrivateKey(byte[] packedPrivateKey, byte paramsK, short[] r)
    {
        Poly.getInstance().polyVectorFromBytes(packedPrivateKey, paramsK, r);
    }

    public void unpackCiphertext(byte[] c, byte paramsK)
    {
        byte[] bpc;
        byte[] vc;
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
            break;
//            case 3:
//                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
//                break;
//            default:
//                bpc = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        }
        Util.arrayCopyNonAtomic(c, (short)0, bpc, (short)0, (short)bpc.length);
        vc = new byte[(short)(c.length - bpc.length)];
        Util.arrayCopyNonAtomic(c, (short)bpc.length, vc, (short)0, (short)vc.length);
        this.bp = Poly.getInstance().decompressPolyVector(bpc, paramsK);
        this.v = Poly.getInstance().decompressPoly(vc, paramsK);
    }

    public byte constantTimeCompare(byte[] x, byte[] y)
    {
        if (x.length != y.length) return (byte)1;
        byte v = 0;
        for (short i = 0; i < x.length; i++)
        {
            v = (byte)((v & 0xFF) | ((x[i] & 0xFF) ^ (y[i] & 0xFF)));
        }
        //Byte.compare(v, (byte)0) - returns always v since implementation of Byte.compare is x-y, where x = v and y = 0; v-0 = v
        return v;
    }

    public void encapsulate()
    {
        try
        {
            //variant = EEPROM32B_1
            //buf = EEPROM32B_2
            //buf2 = EEPROM32B_1 (when variant no more used)
            //subKr = EEPROM32B_1 when buf2 no more used
            //krc = EEPROM32B_1 when subKir is no more used
            //sharedSecret = EEPROM32B_1 (when krc no more used)
            //buf3 = EEPROM64B_1
            //kr = EEPROM64B_2
            //newKr = EEPROM64B_1 when buf3 is no more used

            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
            for (byte i = 0; i < EEPROM32B_1.length; i++)//either this or the other line
            {
                EEPROM32B_1[i] = 0x00;
            }
//        random.nextBytes(EEPROM32B_1, (short)0, (short)32);
            random.close();
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            this.keccak.doFinal(EEPROM32B_1, EEPROM32B_2);
            this.keccak.doFinal(this.keyPair.publicKey, EEPROM32B_1);
            Util.arrayCopyNonAtomic(EEPROM32B_2, (short)0, EEPROM64B_1, (short)0, (short)EEPROM32B_2.length);
            Util.arrayCopyNonAtomic(EEPROM32B_1, (short)0, EEPROM64B_1, (short)EEPROM32B_2.length, (short)EEPROM32B_1.length);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
            this.keccak.doFinal(EEPROM64B_1, EEPROM64B_2);
            Util.arrayCopyNonAtomic(EEPROM64B_2, KyberParams.paramsSymBytes, EEPROM32B_1, (short)0, (short)EEPROM32B_1.length);
            this.encrypt(EEPROM32B_2, this.keyPair.publicKey, EEPROM32B_1);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            this.keccak.doFinal(this.returnArray, EEPROM32B_1);
            Util.arrayCopyNonAtomic(EEPROM64B_2, (short)0, EEPROM64B_1, (short)0, KyberParams.paramsSymBytes);
            Util.arrayCopyNonAtomic(EEPROM32B_1, (short)0, EEPROM64B_1, KyberParams.paramsSymBytes, (short)EEPROM32B_1.length);
            this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
            this.keccak.setShakeDigestLength((short)32);
            this.keccak.doFinal(EEPROM64B_1, EEPROM32B_1);
            this.encapsulation = this.returnArray;
            this.secretKey = EEPROM32B_1;
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void encrypt(byte[] m, byte[] publicKey, byte[] coins)
    {
        //cannot use EEPROM64B_1
        //cannot use EEPROM64B_2
        //cannot use EEPROM384
        //cannot use EEPROM384S_X_PARAMS_K_1

        //m = EEPROM32B_2
        //coins = EEPROM32B_1
        //EEPROM384S_X_PARAMS_K_2 = sp
        //EEPROM384S_X_PARAMS_K_3 = ep
        //EEPROM384S_X_PARAMS_K_4 = bp
        //EEPROM384_2 = epp
        //at = EEPROM384S_X_PARAMS_K_X_PARAMS_K
        //k = EEPROM256S_1

        Poly.getInstance().polyFromData(m, EEPROM256S_1);
        this.unpackPublicKey(publicKey, paramsK);
        this.generateMatrix(this.seed, true, EEPROM384S_X_PARAMS_K_X_PARAMS_K);
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(coins, i, paramsK, EEPROM384_2);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_2, (short)0, EEPROM384S_X_PARAMS_K_2,(short)(i*384),(short)384);
            Poly.getInstance().getNoisePoly(coins, (byte)(i + paramsK), (byte)3,EEPROM384_2);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384_2, (short)0, EEPROM384S_X_PARAMS_K_3,(short)(i*384),(short)384);
        }
        Poly.getInstance().getNoisePoly(coins, (byte)(paramsK * 2), (byte)3, EEPROM384_2);
        Poly.getInstance().polyVectorNTT(EEPROM384S_X_PARAMS_K_2, paramsK);
        Poly.getInstance().polyVectorReduce(EEPROM384S_X_PARAMS_K_2,paramsK);
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384S_X_PARAMS_K_X_PARAMS_K, (short)(i*paramsK*384), this.EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*paramsK));
            Poly.getInstance().polyVectorPointWiseAccMont(this.EEPROM384S_X_PARAMS_K_1, EEPROM384S_X_PARAMS_K_2, paramsK, EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384, (short)0,EEPROM384S_X_PARAMS_K_4,(short)(i*384),(short)384);
        }
        Poly.getInstance().polyVectorPointWiseAccMont(this.publicKeyPolyvec, EEPROM384S_X_PARAMS_K_2, paramsK, EEPROM384);
        Poly.getInstance().polyVectorInvNTTMont(EEPROM384S_X_PARAMS_K_4, paramsK);
        Poly.getInstance().polyInvNTTMont(EEPROM384);
        Poly.getInstance().polyVectorAdd(EEPROM384S_X_PARAMS_K_4, EEPROM384S_X_PARAMS_K_3, paramsK);
        Poly.getInstance().polyAdd(EEPROM384, EEPROM384_2);
        Poly.getInstance().polyAdd(EEPROM384, EEPROM256S_1);
        Poly.getInstance().polyVectorReduce(EEPROM384S_X_PARAMS_K_4, paramsK);
        Poly.getInstance().polyReduce(EEPROM384);
        this.packCiphertext(EEPROM384S_X_PARAMS_K_4, EEPROM384, paramsK);
    }

    public void packCiphertext(short[] b, short[] v, byte paramsK)
    {
        Poly.getInstance().compressPolyVector(b, paramsK, this.bCompress);
        Poly.getInstance().compressPoly(v, paramsK, this.vCompress);
        Util.arrayCopyNonAtomic(this.bCompress, (short)0, this.returnArray, (short)0, (short)this.bCompress.length);
        Util.arrayCopyNonAtomic(this.vCompress, (short)0, this.returnArray, (short)this.bCompress.length, (short)this.vCompress.length);
    }

    public void unpackPublicKey(byte[] packedPublicKey, byte paramsK)
    {
        //r = this.publicKeyPolyvec
        //partlyPublicKey = EEPROM768B_1

        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            Util.arrayCopyNonAtomic(packedPublicKey, (short)0, EEPROM768B_1, (short)0, KyberParams.paramsPolyvecBytesK512);
            Poly.getInstance().polyVectorFromBytes(EEPROM768B_1, paramsK, this.publicKeyPolyvec);
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
        this.keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
//        random.nextBytes(this.EEPROM32B_1, (short)0, (short)32);
        random.close();
        this.keccak.doFinal(this.EEPROM32B_1, this.EEPROM384B_X_PARAMS_K);
        Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K, (short)0, this.EEPROM32B_1, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K, KyberParams.paramsSymBytes, this.EEPROM32B_2, (short)0, KyberParams.paramsSymBytes);
        this.generateMatrix(this.EEPROM32B_1, false, this.EEPROM384S_X_PARAMS_K_X_PARAMS_K);
        byte nonce = (byte)0;
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(this.EEPROM32B_2, nonce, this.paramsK, this.EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384, (short)0, this.EEPROM384S_X_PARAMS_K_2, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().getNoisePoly(this.EEPROM32B_2, nonce, this.paramsK, this.EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384, (short)0, this.EEPROM384S_X_PARAMS_K_4, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        Poly.getInstance().polyVectorNTT(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        Poly.getInstance().polyVectorReduce(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        Poly.getInstance().polyVectorNTT(this.EEPROM384S_X_PARAMS_K_4, this.paramsK);
        for (byte i = 0; i < this.paramsK; i++)
        {
            Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384S_X_PARAMS_K_X_PARAMS_K, (short)(i*this.paramsK*384), this.EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*this.paramsK));
            Poly.getInstance().polyVectorPointWiseAccMont(this.EEPROM384S_X_PARAMS_K_1, this.EEPROM384S_X_PARAMS_K_2, this.paramsK, this.EEPROM384);
            Poly.getInstance().polyToMont(this.EEPROM384);
            Poly.getInstance().arrayCopyNonAtomic(EEPROM384, (short)0, this.EEPROM384S_X_PARAMS_K_3, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
        }
        Poly.getInstance().polyVectorAdd(this.EEPROM384S_X_PARAMS_K_3, this.EEPROM384S_X_PARAMS_K_4, this.paramsK);
        Poly.getInstance().polyVectorReduce(this.EEPROM384S_X_PARAMS_K_3, this.paramsK);
        this.packPrivateKey(this.EEPROM384S_X_PARAMS_K_2, this.paramsK);
        this.packPublicKey(this.EEPROM384S_X_PARAMS_K_3, this.EEPROM32B_1, this.paramsK);
    }

    public void packPrivateKey(short[] privateKey, byte paramsK)
    {
        Poly.getInstance().polyVectorToBytes(privateKey, paramsK, this.keyPair.privateKey);
    }

    public void packPublicKey(short[] publicKey, byte[] seed, byte paramsK)
    {
        Poly.getInstance().polyVectorToBytes(publicKey, paramsK, this.EEPROM384B_X_PARAMS_K);
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            Util.arrayCopyNonAtomic(this.EEPROM384B_X_PARAMS_K, (short)0, this.keyPair.publicKey, (short)0, (short)this.EEPROM384B_X_PARAMS_K.length);
            Util.arrayCopyNonAtomic(seed, (short)0, this.keyPair.publicKey, (short)this.EEPROM384B_X_PARAMS_K.length, (short)seed.length);
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

    public void generateMatrix(byte[] seed, boolean transposed, short[] result)
    {
        //seed = EEPROM32B_1
        //result = EEPROM384S_X_PARAMS_K_X_PARAMS_K, 2*2*384 = 1536
        //EEPROM672B_1 = buf
        //EEPROM504B_1 = bufCopy
        //RAM2B_1 = ij
        //EEPROM34_1 = seedAndij
        //EEPROM384 = uniformR

        this.keccak = Keccak.getInstance(Keccak.ALG_SHAKE_128);
        for (byte i = 0; i < this.paramsK; i++)
        {
            for (byte j = 0; j < this.paramsK; j++)
            {
                if (transposed)
                {
                    this.RAM2B_1[0] = i;
                    this.RAM2B_1[1] = j;
                }
                else
                {
                    this.RAM2B_1[0] = j;
                    this.RAM2B_1[1] = i;
                }
                Util.arrayCopyNonAtomic(seed, (short)0, this.EEPROM34_1, (short)0, (short)seed.length);
                Util.arrayCopyNonAtomic(this.RAM2B_1, (short)0, this.EEPROM34_1, (short)seed.length, (short)this.RAM2B_1.length);
                this.keccak.setShakeDigestLength((short)this.EEPROM672B_1.length);
                this.keccak.doFinal(this.EEPROM34_1, this.EEPROM672B_1);
                Util.arrayCopyNonAtomic(this.EEPROM672B_1,(short)0, this.EEPROM504B_1,(short)0, (short)504);
                this.generateUniform(this.EEPROM504B_1, (short)504, KyberParams.paramsN);
                short ui = this.uniformI;
                Poly.getInstance().arrayCopyNonAtomic(this.EEPROM384, (short)0, result, (short)(((i*2)+j)*384), (short)384);
                while (ui < KyberParams.paramsN)
                {
                    Util.arrayCopyNonAtomic(this.EEPROM672B_1,(short)504, this.EEPROM504B_1,(short)0, (short)168);
                    this.generateUniform(this.EEPROM504B_1, (short)168, (short)(KyberParams.paramsN - ui));
                    short ctrn = this.uniformI;
                    for (short k = ui; k < KyberParams.paramsN; k++)
                    {
                        result[(short)(((i * 2 + j) * 384) + k)] = this.EEPROM384[(short)(k - ui)];
                    }
                    ui += ctrn;
                }
            }
        }
    }

    public void generateUniform(byte[] buf, short bufl, short l)
    {
        short d1;
        short d2;
        this.uniformI = 0; // Always start at 0
        short j = 0;
        while ((this.uniformI < l) && ((short)(j + 3) <= bufl))
        {
            d1 = (short)(((buf[j] & 0xFF) | ((buf[(short)(j + 1)] & 0xFF) << 8)) & 0xFFF);
            d2 = (short)((((buf[(short)(j + 1)] & 0xFF) >> 4) | ((buf[(short)(j + 2)] & 0xFF) << 4)) & 0xFFF);
            j+=3;
            if (d1 < KyberParams.paramsQ)
            {
                this.EEPROM384[this.uniformI] = d1;
                this.uniformI++;
            }
            if (this.uniformI < l && d2 < KyberParams.paramsQ)
            {
                this.EEPROM384[this.uniformI] = d2;
                this.uniformI++;
            }
        }
    }
}