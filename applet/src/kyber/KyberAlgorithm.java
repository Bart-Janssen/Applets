package applet.kyber;

import javacard.framework.*;
import javacard.security.*;

public class KyberAlgorithm
{
    //Random static variable for testing
    public static boolean useRandom = false;

    private static KyberAlgorithm kyber = null;

    protected KyberAlgorithm()
    {
        //Create keccak instance so object is created, reserving EEPROM at startup rather than runtime
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
        poly = Poly.getInstance();
        privateKeyBytes = KyberParams.Kyber1024SKBytes;

        //Array sizes initialized only once and at highest Kyber settings so the "init" function can set the Kyber mode
        //EEPROM required arrays
        privateKey = new byte[(short)3168];
        publicKey = new byte[KyberParams.paramsIndcpaPublicKeyBytesK1024];
        encapsulation = new byte[1568];
        secretKey = new byte[32];

        //RAM arrays
        RAM2B_1 = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        RAM32B_1 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        RAM32B_2 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        RAM32B_3 = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
        RAM34B_1 = JCSystem.makeTransientByteArray((short)34, JCSystem.CLEAR_ON_DESELECT);
        RAM64B_1 = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        RAM64B_2 = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        RAM160B_1 = JCSystem.makeTransientByteArray((short)(1568 - KyberParams.paramsPolyvecCompressedBytesK1024), JCSystem.CLEAR_ON_DESELECT);
        RAM160B_2 = JCSystem.makeTransientByteArray(KyberParams.paramsPolyCompressedBytesK1024, JCSystem.CLEAR_ON_DESELECT);
        RAM384S_1 = JCSystem.makeTransientShortArray((short)384, JCSystem.CLEAR_ON_DESELECT);

        //EEPROM arrays
        EEPROM256S_1 = new short[256];
        EEPROM384S_1 = new short[384];
        EEPROM504B_1 = new byte[504];
        EEPROM672B_1 = new byte[672];
        EEPROM768B_1 = new byte[768];
        EEPROM384B_X_PARAMS_K_1 = new byte[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_1 = new short[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_2 = new short[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_3 = new short[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_4 = new short[(short)(384*4)];
        EEPROM384S_X_PARAMS_K_5 = new short[(short)(384*4)];
        EEPROM1408B_1 = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        EEPROM1536B_1 = new byte[KyberParams.paramsIndcpaSecretKeyBytesK1024];
        EEPROM1536B_2 = new byte[KyberParams.paramsIndcpaSecretKeyBytesK1024];
        EEPROM1568B_1 = new byte[1568];
        EEPROM384S_X_PARAMS_K_X_PARAMS_K_1 = new short[(short)(384*4*4)];
    }

    private KyberAlgorithm init(byte paramsK)
    {
        KyberAlgorithm.paramsK = paramsK;
        switch (paramsK)
        {
            case 2:
                privateKeyLength = 1632;
                publicKeyLength = KyberParams.paramsIndcpaPublicKeyBytesK512;
                vCompressLength = KyberParams.paramsPolyCompressedBytesK768;//yes 768 intended
                bCompressLength = KyberParams.paramsPolyvecCompressedBytesK512;
                indcpaPrivateKeyLength = KyberParams.paramsIndcpaSecretKeyBytesK512;
                privateKeyBytes = KyberParams.Kyber512SKBytes;
                break;
            case 3:
                privateKeyLength = 2400;
                publicKeyLength = KyberParams.paramsIndcpaPublicKeyBytesK768;
                vCompressLength = KyberParams.paramsPolyCompressedBytesK768;
                bCompressLength = KyberParams.paramsPolyvecCompressedBytesK768;
                indcpaPrivateKeyLength = KyberParams.paramsIndcpaSecretKeyBytesK768;
                privateKeyBytes = KyberParams.Kyber768SKBytes;
                break;
            default:
                privateKeyLength = 3168;
                publicKeyLength = KyberParams.paramsIndcpaPublicKeyBytesK1024;
                vCompressLength = KyberParams.paramsPolyCompressedBytesK1024;
                bCompressLength = KyberParams.paramsPolyvecCompressedBytesK1024;
                indcpaPrivateKeyLength = KyberParams.paramsIndcpaSecretKeyBytesK1024;
                privateKeyBytes = KyberParams.Kyber1024SKBytes;
                break;
        }
        encapsulationLength = (short)(bCompressLength + vCompressLength);
        vcLength = (short)(encapsulationLength - bCompressLength);
        return this;
    }

    public static KyberAlgorithm getInstance(byte paramsK)
    {
        if (kyber == null) kyber = new KyberAlgorithm();
        return kyber.init(paramsK);
    }

    private static byte paramsK;
    private static Keccak keccak;
    private static Poly poly;

    //Conditional arrays based on paramsK
    public static byte[] privateKey;
    public static short privateKeyLength;
    public static byte[] publicKey;
    public static short publicKeyLength;
    public static byte[] encapsulation;
    public static short encapsulationLength;

    private static byte[] RAM160B_2;//vCompress
    private static short vCompressLength;
    private static byte[] EEPROM1408B_1;//bCompress
    private static short bCompressLength;
    private static byte[] RAM160B_1;//vc
    private static short vcLength;
    private static byte[] EEPROM1536B_2;//indcpaPrivateKey
    private static short indcpaPrivateKeyLength;
    private static short privateKeyBytes;

    private static short[] EEPROM384S_X_PARAMS_K_X_PARAMS_K_1;
    private static byte[] EEPROM384B_X_PARAMS_K_1;
    private static short[] EEPROM384S_X_PARAMS_K_1;
    private static short[] EEPROM384S_X_PARAMS_K_2;
    private static short[] EEPROM384S_X_PARAMS_K_3;
    private static short[] EEPROM384S_X_PARAMS_K_4;

    private static byte[] RAM2B_1;
    private static byte[] RAM34B_1;
    private static byte[] RAM32B_1;
    private static byte[] RAM32B_2;
    private static byte[] RAM64B_1;
    private static byte[] RAM64B_2;
    private static short[] EEPROM256S_1;
    private static byte[] EEPROM672B_1;
    private static byte[] EEPROM768B_1;
    private static byte[] EEPROM1536B_1;
    private static byte[] EEPROM1568B_1;
    private static byte[] EEPROM504B_1;
    private static short[] RAM384S_1;
    private static short[] EEPROM384S_1;

    private static short uniformI = 0;
    public static byte[] secretKey;
    private static short[] EEPROM384S_X_PARAMS_K_5;
    private static byte[] RAM32B_3;

    public void generateKeys()
    {
        try
        {
            this.generateKyberKeys();
            keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            keccak.doFinal(publicKey, publicKeyLength, RAM32B_1);
            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
            if (useRandom) random.nextBytes(RAM32B_2, (short)0, (short)32);
            else for (byte i = 0; i < RAM32B_2.length; i++){RAM32B_2[i] = (byte)0x00;}
            random.close();
            short offsetEnd = (short)(paramsK * KyberParams.paramsPolyBytes);
            Util.arrayCopyNonAtomic(publicKey, (short)0, privateKey, offsetEnd, publicKeyLength);
            offsetEnd = (short)(offsetEnd + publicKeyLength);
            Util.arrayCopyNonAtomic(RAM32B_1, (short)0, privateKey, offsetEnd, (short)RAM32B_1.length);
            offsetEnd += (short)RAM32B_1.length;
            Util.arrayCopyNonAtomic(RAM32B_2, (short)0, privateKey, offsetEnd, (short)RAM32B_2.length);
            //priv = priv || pub || pkh (pub hash) || rnd
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void decapsulate()
    {
        try
        {
            //newBuf = RAM64B_2
            //kr = RAM64B_1
            //subKr = RAM32B_1
            //krh = RAM32B_1
            //sharedSecretFixedLength = RAM32B_1
            //tempBuf = RAM64B_2
            //return array = EEPROM1568B_1

            Util.arrayCopyNonAtomic(privateKey, (short)0, EEPROM1536B_2, (short)0, indcpaPrivateKeyLength);
            Util.arrayCopyNonAtomic(privateKey, indcpaPrivateKeyLength, publicKey, (short)0, publicKeyLength);
            this.decrypt(encapsulation, EEPROM1536B_2, RAM32B_2);//begin RAM32B_2
            short ski = (short)(privateKeyBytes - (2 * KyberParams.paramsSymBytes));
            Util.arrayCopyNonAtomic(RAM32B_2, (short)0, RAM64B_2, (short)0, (short)32);//begin RAM64B_2
            Util.arrayCopyNonAtomic(privateKey, ski, RAM64B_2, (short)32, KyberParams.paramsSymBytes);
            keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
            keccak.doFinal(RAM64B_2, RAM64B_1);//end RAM64B_2, begin RAM64B_1
            Util.arrayCopyNonAtomic(RAM64B_1, KyberParams.paramsSymBytes, RAM32B_1, (short)0, (short)32);//begin RAM32B_1
            Util.arrayCopyNonAtomic(encapsulation, (short)0, EEPROM1568B_1, (short)0, encapsulationLength);
            this.encrypt(RAM32B_2, publicKey, RAM32B_1);//end RAM32B_1
            byte fail = this.constantTimeCompare(EEPROM1568B_1, encapsulation, encapsulationLength);
            keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            keccak.doFinal(EEPROM1568B_1, encapsulationLength, RAM32B_1);//begin RAM32B_1
            short index = (short)(privateKeyBytes - KyberParams.paramsSymBytes);
            for (byte i = 0; i < KyberParams.paramsSymBytes; i++)
            {
                byte privateKeyIndex = (byte)(privateKey[index] & (byte)0xFF);
                byte krIndex = (byte)(RAM64B_1[i] & (byte)0xFF);
                RAM64B_1[i] = (byte)(krIndex ^ (byte)(fail & (byte)0xFF & (byte)(privateKeyIndex ^ krIndex)));
                index += 1;
            }
            Util.arrayCopyNonAtomic(RAM64B_1, (short)0, RAM64B_2, (short)0, KyberParams.paramsSymBytes);//end RAM64B_1, begin RAM64B_2
            Util.arrayCopyNonAtomic(RAM32B_1, (short)0, RAM64B_2, KyberParams.paramsSymBytes, (short)RAM32B_1.length);//end RAM32B_1
            keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
            keccak.setShakeDigestLength((short)32);
            keccak.doFinal(RAM64B_2, RAM32B_1);//end RAM64B_2, begin RAM32B_1
            Util.arrayCopyNonAtomic(RAM32B_1, (short)0, secretKey, (short)0, (short)32);//end RAM32B_1
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void decrypt(byte[] packedCipherText, byte[] privateKey, byte[] msg)
    {
        //cannot use RAM32B_2

        //unpackedPrivateKey = EEPROM384S_X_PARAMS_K_1
        //mp = RAM384S_1

        this.unpackCiphertext(packedCipherText, paramsK);//begin EEPROM384S_X_PARAMS_K_2, begin EEPROM384S_1
        this.unpackPrivateKey(privateKey, paramsK, EEPROM384S_X_PARAMS_K_1);//begin EEPROM384S_X_PARAMS_K_1
        poly.polyVectorNTT(EEPROM384S_X_PARAMS_K_2, paramsK);
        poly.polyVectorPointWiseAccMont(EEPROM384S_X_PARAMS_K_1, EEPROM384S_X_PARAMS_K_2, paramsK, RAM384S_1);//end EEPROM384S_X_PARAMS_K_1, begin RAM384S_1, end EEPROM384S_X_PARAMS_K_2
        poly.polyInvNTTMont(RAM384S_1);
        poly.polySub(EEPROM384S_1, RAM384S_1);//end RAM384S_1
        poly.polyReduce(EEPROM384S_1);
        poly.polyToMsg(EEPROM384S_1, msg);//end EEPROM384S_1
    }

    public void unpackPrivateKey(byte[] packedPrivateKey, byte paramsK, short[] r)
    {
        poly.polyVectorFromBytes(packedPrivateKey, paramsK, r);
    }

    public void unpackCiphertext(byte[] c, byte paramsK)
    {
        //bp = EEPROM384S_X_PARAMS_K_2
        Util.arrayCopyNonAtomic(c, (short)0, EEPROM1408B_1, (short)0, bCompressLength);
        Util.arrayCopyNonAtomic(c, bCompressLength, RAM160B_1, (short)0, vcLength);
        poly.decompressPolyVector(EEPROM1408B_1, paramsK, EEPROM384S_X_PARAMS_K_2);
        poly.decompressPoly(RAM160B_1, paramsK, EEPROM384S_1);
    }

    public byte constantTimeCompare(byte[] x, byte[] y, short length)
    {
        if (x.length != y.length) return (byte)1;
        byte v = 0;
        for (short i = 0; i < length; i++)
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
            //variant = RAM32B_1
            //buf = RAM32B_2
            //buf2 = RAM32B_1 (when variant no more used)
            //subKr = RAM32B_1 when buf2 no more used
            //krc = RAM32B_1 when subKir is no more used
            //sharedSecret = RAM32B_1 (when krc no more used)
            //buf3 = RAM64B_1
            //kr = RAM64B_2
            //newKr = RAM64B_1 when buf3 is no more used

            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
            if (useRandom) random.nextBytes(RAM32B_1, (short)0, (short)32);
            else for (byte i = 0; i < RAM32B_1.length; i++){RAM32B_1[i] = 0x00;}
            random.close();
            keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            keccak.doFinal(RAM32B_1, RAM32B_2);
            keccak.doFinal(publicKey, publicKeyLength, RAM32B_1);
            Util.arrayCopyNonAtomic(RAM32B_2, (short)0, RAM64B_1, (short)0, (short)RAM32B_2.length);
            Util.arrayCopyNonAtomic(RAM32B_1, (short)0, RAM64B_1, (short)RAM32B_2.length, (short)RAM32B_1.length);
            keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
            keccak.doFinal(RAM64B_1, RAM64B_2);
            Util.arrayCopyNonAtomic(RAM64B_2, KyberParams.paramsSymBytes, RAM32B_1, (short)0, (short)RAM32B_1.length);
            this.encrypt(RAM32B_2, publicKey, RAM32B_1);
            keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            keccak.doFinal(encapsulation, encapsulationLength, RAM32B_1);
            Util.arrayCopyNonAtomic(RAM64B_2, (short)0, RAM64B_1, (short)0, KyberParams.paramsSymBytes);
            Util.arrayCopyNonAtomic(RAM32B_1, (short)0, RAM64B_1, KyberParams.paramsSymBytes, (short)RAM32B_1.length);
            keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
            keccak.setShakeDigestLength((short)32);
            keccak.doFinal(RAM64B_1, RAM32B_1);
            Util.arrayCopyNonAtomic(RAM32B_1, (short)0, secretKey, (short)0, (short)32);
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void encrypt(byte[] m, byte[] publicKey, byte[] coins)
    {
        //cannot use RAM64B_1
        //cannot use RAM64B_2
        //cannot use RAM384S_1
        //cannot use EEPROM384S_X_PARAMS_K_1

        //m = RAM32B_2
        //coins = RAM32B_1
        //EEPROM384S_X_PARAMS_K_2 = sp
        //EEPROM384S_X_PARAMS_K_3 = ep
        //EEPROM384S_X_PARAMS_K_4 = bp
        //EEPROM384S_1 = epp
        //at = EEPROM384S_X_PARAMS_K_X_PARAMS_K_1
        //k = EEPROM256S_1

        poly.polyFromData(m, EEPROM256S_1);
        this.unpackPublicKey(publicKey, paramsK);
        this.generateMatrix(RAM32B_3, true, EEPROM384S_X_PARAMS_K_X_PARAMS_K_1);
        for (byte i = 0; i < paramsK; i++)
        {
            poly.getNoisePoly(coins, i, paramsK, EEPROM384S_1);
            poly.arrayCopyNonAtomic(EEPROM384S_1, (short)0, EEPROM384S_X_PARAMS_K_2,(short)(i*384),(short)384);
            poly.getNoisePoly(coins, (byte)(i + paramsK), (byte)3,EEPROM384S_1);
            poly.arrayCopyNonAtomic(EEPROM384S_1, (short)0, EEPROM384S_X_PARAMS_K_3,(short)(i*384),(short)384);
        }
        poly.getNoisePoly(coins, (byte)(paramsK * 2), (byte)3, EEPROM384S_1);
        poly.polyVectorNTT(EEPROM384S_X_PARAMS_K_2, paramsK);
        poly.polyVectorReduce(EEPROM384S_X_PARAMS_K_2,paramsK);
        for (byte i = 0; i < paramsK; i++)
        {
            poly.arrayCopyNonAtomic(EEPROM384S_X_PARAMS_K_X_PARAMS_K_1, (short)(i*paramsK*384), EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*paramsK));
            poly.polyVectorPointWiseAccMont(EEPROM384S_X_PARAMS_K_1, EEPROM384S_X_PARAMS_K_2, paramsK, RAM384S_1);
            poly.arrayCopyNonAtomic(RAM384S_1, (short)0,EEPROM384S_X_PARAMS_K_4,(short)(i*384),(short)384);
        }
        poly.polyVectorPointWiseAccMont(EEPROM384S_X_PARAMS_K_5, EEPROM384S_X_PARAMS_K_2, paramsK, RAM384S_1);
        poly.polyVectorInvNTTMont(EEPROM384S_X_PARAMS_K_4, paramsK);
        poly.polyInvNTTMont(RAM384S_1);
        poly.polyVectorAdd(EEPROM384S_X_PARAMS_K_4, EEPROM384S_X_PARAMS_K_3, paramsK);
        poly.polyAdd(RAM384S_1, EEPROM384S_1);
        poly.polyAdd(RAM384S_1, EEPROM256S_1);
        poly.polyVectorReduce(EEPROM384S_X_PARAMS_K_4, paramsK);
        poly.polyReduce(RAM384S_1);
        this.packCiphertext(EEPROM384S_X_PARAMS_K_4, RAM384S_1, paramsK);
    }

    public void packCiphertext(short[] b, short[] v, byte paramsK)
    {
        poly.compressPolyVector(b, paramsK, EEPROM1408B_1);
        poly.compressPoly(v, paramsK, RAM160B_2);
        Util.arrayCopyNonAtomic(EEPROM1408B_1, (short)0, encapsulation, (short)0, bCompressLength);
        Util.arrayCopyNonAtomic(RAM160B_2, (short)0, encapsulation, bCompressLength, vCompressLength);
    }

    public void unpackPublicKey(byte[] packedPublicKey, byte paramsK)
    {
        //r = EEPROM384S_X_PARAMS_K_5
        //partlyPublicKey = EEPROM768B_1

        switch (paramsK)
        {
            case 2:
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, EEPROM1536B_1, (short)0, KyberParams.paramsPolyvecBytesK512);
                poly.polyVectorFromBytes(EEPROM1536B_1, paramsK, EEPROM384S_X_PARAMS_K_5);
                Util.arrayCopyNonAtomic(packedPublicKey, KyberParams.paramsPolyvecBytesK512, RAM32B_3, (short)0, (short)32);
                break;
            case 3:
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, EEPROM1536B_1, (short)0, KyberParams.paramsPolyvecBytesK768);
                poly.polyVectorFromBytes(EEPROM1536B_1, paramsK, EEPROM384S_X_PARAMS_K_5);
                Util.arrayCopyNonAtomic(packedPublicKey, KyberParams.paramsPolyvecBytesK768, RAM32B_3, (short)0, (short)32);
                break;
            default:
                Util.arrayCopyNonAtomic(packedPublicKey, (short)0, EEPROM1536B_1, (short)0, KyberParams.paramsPolyvecBytesK1024);
                poly.polyVectorFromBytes(EEPROM1536B_1, paramsK, EEPROM384S_X_PARAMS_K_5);
                Util.arrayCopyNonAtomic(packedPublicKey, KyberParams.paramsPolyvecBytesK1024, RAM32B_3, (short)0, (short)32);
                break;
        }
    }

    public void generateKyberKeys() throws Exception
    {
        keccak = Keccak.getInstance(Keccak.ALG_SHA3_512);
        RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
        if (useRandom) random.nextBytes(RAM32B_1, (short)0, (short)32);
        else for (byte i = 0; i < RAM32B_1.length; i++){RAM32B_1[i] = (byte)0x00;}
        random.close();
        keccak.doFinal(RAM32B_1, EEPROM384B_X_PARAMS_K_1);
        Util.arrayCopyNonAtomic(EEPROM384B_X_PARAMS_K_1, (short)0, RAM32B_1, (short)0, KyberParams.paramsSymBytes);
        Util.arrayCopyNonAtomic(EEPROM384B_X_PARAMS_K_1, KyberParams.paramsSymBytes, RAM32B_2, (short)0, KyberParams.paramsSymBytes);
        this.generateMatrix(RAM32B_1, false, EEPROM384S_X_PARAMS_K_X_PARAMS_K_1);
        byte nonce = (byte)0;
        for (byte i = 0; i < paramsK; i++)
        {
            poly.getNoisePoly(RAM32B_2, nonce, paramsK, RAM384S_1);
            poly.arrayCopyNonAtomic(RAM384S_1, (short)0, EEPROM384S_X_PARAMS_K_2, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        for (byte i = 0; i < paramsK; i++)
        {
            poly.getNoisePoly(RAM32B_2, nonce, paramsK, RAM384S_1);
            poly.arrayCopyNonAtomic(RAM384S_1, (short)0, EEPROM384S_X_PARAMS_K_4, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
            nonce = (byte)(nonce + (byte)1);
        }
        poly.polyVectorNTT(EEPROM384S_X_PARAMS_K_2, paramsK);
        poly.polyVectorReduce(EEPROM384S_X_PARAMS_K_2, paramsK);
        poly.polyVectorNTT(EEPROM384S_X_PARAMS_K_4, paramsK);
        for (byte i = 0; i < paramsK; i++)
        {
            poly.arrayCopyNonAtomic(EEPROM384S_X_PARAMS_K_X_PARAMS_K_1, (short)(i*paramsK*384), EEPROM384S_X_PARAMS_K_1,(short)0,(short)(384*paramsK));
            poly.polyVectorPointWiseAccMont(EEPROM384S_X_PARAMS_K_1, EEPROM384S_X_PARAMS_K_2, paramsK, RAM384S_1);
            poly.polyToMont(RAM384S_1);
            poly.arrayCopyNonAtomic(RAM384S_1, (short)0, EEPROM384S_X_PARAMS_K_3, (short)(i*KyberParams.paramsPolyBytes), KyberParams.paramsPolyBytes);
        }
        poly.polyVectorAdd(EEPROM384S_X_PARAMS_K_3, EEPROM384S_X_PARAMS_K_4, paramsK);
        poly.polyVectorReduce(EEPROM384S_X_PARAMS_K_3, paramsK);
        this.packPrivateKey(EEPROM384S_X_PARAMS_K_2, paramsK);
        this.packPublicKey(EEPROM384S_X_PARAMS_K_3, RAM32B_1, paramsK);
    }

    public void packPrivateKey(short[] privateKey, byte paramsK)
    {
        poly.polyVectorToBytes(privateKey, paramsK, KyberAlgorithm.privateKey);
    }

    public void packPublicKey(short[] publicKey, byte[] RAM32B_3, byte paramsK)
    {
        //initialArray = EEPROM384B_X_PARAMS_K_1
        //packedPublicKey = publicKey

        poly.polyVectorToBytes(publicKey, paramsK, EEPROM384B_X_PARAMS_K_1);
        Util.arrayCopyNonAtomic(EEPROM384B_X_PARAMS_K_1, (short)0, KyberAlgorithm.publicKey, (short)0, (short)(384*paramsK));
        Util.arrayCopyNonAtomic(RAM32B_3, (short)0, KyberAlgorithm.publicKey, (short)(384*paramsK), (short)RAM32B_3.length);
    }

    public void generateMatrix(byte[] RAM32B_3, boolean transposed, short[] result)
    {
        //RAM32B_3 = RAM32B_1
        //result = EEPROM384S_X_PARAMS_K_X_PARAMS_K_1, 2*2*384 = 1536
        //EEPROM672B_1 = buf
        //EEPROM504B_1 = bufCopy
        //RAM2B_1 = ij
        //RAM34B_1 = RAM32B_3Andij
        //RAM384S_1 = uniformR

        keccak = Keccak.getInstance(Keccak.ALG_SHAKE_128);
        for (byte i = 0; i < paramsK; i++)
        {
            for (byte j = 0; j < paramsK; j++)
            {
                if (transposed)
                {
                    RAM2B_1[0] = i;
                    RAM2B_1[1] = j;
                }
                else
                {
                    RAM2B_1[0] = j;
                    RAM2B_1[1] = i;
                }
                Util.arrayCopyNonAtomic(RAM32B_3, (short)0, RAM34B_1, (short)0, (short)RAM32B_3.length);
                Util.arrayCopyNonAtomic(RAM2B_1, (short)0, RAM34B_1, (short)RAM32B_3.length, (short)RAM2B_1.length);
                keccak.setShakeDigestLength((short)EEPROM672B_1.length);
                keccak.doFinal(RAM34B_1, EEPROM672B_1);
                Util.arrayCopyNonAtomic(EEPROM672B_1,(short)0, EEPROM504B_1,(short)0, (short)504);
                this.generateUniform(EEPROM504B_1, (short)504, KyberParams.paramsN);
                short ui = uniformI;
                poly.arrayCopyNonAtomic(RAM384S_1, (short)0, result, (short)(((i*paramsK)+j)*384), (short)384);
                while (ui < KyberParams.paramsN)
                {
                    Util.arrayCopyNonAtomic(EEPROM672B_1,(short)504, EEPROM504B_1,(short)0, (short)168);
                    this.generateUniform(EEPROM504B_1, (short)168, (short)(KyberParams.paramsN - ui));
                    short ctrn = uniformI;
                    for (short k = ui; k < KyberParams.paramsN; k++)
                    {
                        result[(short)(((i * paramsK + j) * 384) + k)] = RAM384S_1[(short)(k - ui)];
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
        uniformI = 0; // Always start at 0
        short j = 0;
        while ((uniformI < l) && ((short)(j + 3) <= bufl))
        {
            d1 = (short)(((buf[j] & 0xFF) | ((buf[(short)(j + 1)] & 0xFF) << 8)) & 0xFFF);
            d2 = (short)((((buf[(short)(j + 1)] & 0xFF) >> 4) | ((buf[(short)(j + 2)] & 0xFF) << 4)) & 0xFFF);
            j+=3;
            if (d1 < KyberParams.paramsQ)
            {
                RAM384S_1[uniformI] = d1;
                uniformI++;
            }
            if (uniformI < l && d2 < KyberParams.paramsQ)
            {
                RAM384S_1[uniformI] = d2;
                uniformI++;
            }
        }
    }
}