package applet.kyber;

import javacard.framework.*;

public class Poly
{
    public static void arrayCopyNonAtomic(short[] src, short srcIndex, short[] dst, short dstIndex, short length)
    {
        for (short i = 0; i < length; i++)
        {
            dst[(short)(dstIndex+i)] = src[(short)(srcIndex+i)];
        }
    }

    public static short[] generateNewPolyVector(byte paramsK)
    {
        return new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
    }

    public static short[] getNoisePoly(byte[] seed, byte nonce, byte paramsK)
    {
        short l;
        byte[] p;
        switch (paramsK)
        {
            //this part is already supported for all three kyber
            case 2:
                l = KyberParams.paramsETAK512 * KyberParams.paramsN / 4;
                break;
            default:
                l = KyberParams.paramsETAK768K1024 * KyberParams.paramsN / 4;
        }
        p = Poly.generatePRFByteArray(l, seed, nonce);
        return Poly.generateCBDPoly(p, paramsK);
    }

    public static byte[] generatePRFByteArray(short l, byte[] key, byte nonce)
    {
        byte[] hash = new byte[l];
        byte[] newKey = new byte[(byte)(key.length + 1)];
        Util.arrayCopyNonAtomic(key, (short)0, newKey, (short)0, (short)key.length);
        newKey[key.length] = nonce;
        Keccak keccak = Keccak.getInstance(Keccak.ALG_SHAKE_256);
        keccak.setShakeDigestLength(l);
        keccak.doFinal(newKey, hash);
        return hash;
    }

    public static byte[] polyToBytes(short[] a)
    {
        short t0, t1;
        byte[] r = new byte[KyberParams.paramsPolyBytes];
        for (short i = 0; i < (short)(KyberParams.paramsN / (byte)2); i++)
        {
            t0 = ((short)(a[(short)((byte)2 * i)] & (short)0xFFFF));
            t1 = (short)((a[(short)((byte)2 * i + (byte)1)]) & (short)0xFFFF);
            r[(short)((byte)3 * i + (byte)0)] = (byte) (t0 >>  (byte)0);
            r[(short)((byte)3 * i + (byte)1)] = (byte) ((t0 >> (byte)8) | (t1 << (byte)4));
            r[(short)((byte)3 * i + (byte)2)] = (byte) (t1 >>  (byte)4);
        }
        return r;
    }

    public static byte[] polyVectorToBytes(short[] polyA, byte paramsK)
    {
        //Optimize r as parameter
        byte[] r = new byte[(short)(paramsK * KyberParams.paramsPolyBytes)];
        short[] row = new short[KyberParams.paramsPolyBytes];
        for (byte i = 0; i < paramsK; i++)
        {
            Poly.arrayCopyNonAtomic(polyA, (short)(i * KyberParams.paramsPolyBytes), row, (short)0, KyberParams.paramsPolyBytes);
            byte[] byteA = polyToBytes(row);
            Util.arrayCopyNonAtomic(byteA, (short)0, r, (short)(i * KyberParams.paramsPolyBytes), (short)byteA.length);
        }
        return r;
    }
}