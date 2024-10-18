package applet.kyber;

import javacard.framework.*;

public class Poly
{
    private static Poly poly;

    private static short[] multiplied;
    private static short[] jc;

    private Poly()
    {
        multiplied = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        jc = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
    }

    public static Poly getInstance()
    {
        if (poly == null) poly = new Poly();
        return poly;
    }

    public final static short[] nttZetas = new short[]
    {
        2285, 2571, 2970, 1812, 1493, 1422, 287, 202, 3158, 622, 1577, 182, 962,
        2127, 1855, 1468, 573, 2004, 264, 383, 2500, 1458, 1727, 3199, 2648, 1017,
        732, 608, 1787, 411, 3124, 1758, 1223, 652, 2777, 1015, 2036, 1491, 3047,
        1785, 516, 3321, 3009, 2663, 1711, 2167, 126, 1469, 2476, 3239, 3058, 830,
        107, 1908, 3082, 2378, 2931, 961, 1821, 2604, 448, 2264, 677, 2054, 2226,
        430, 555, 843, 2078, 871, 1550, 105, 422, 587, 177, 3094, 3038, 2869, 1574,
        1653, 3083, 778, 1159, 3182, 2552, 1483, 2727, 1119, 1739, 644, 2457, 349,
        418, 329, 3173, 3254, 817, 1097, 603, 610, 1322, 2044, 1864, 384, 2114, 3193,
        1218, 1994, 2455, 220, 2142, 1670, 2144, 1799, 2051, 794, 1819, 2475, 2459,
        478, 3221, 3021, 996, 991, 958, 1869, 1522, 1628
    };

    public void arrayCopyNonAtomic(short[] src, short srcIndex, short[] dst, short dstIndex, short length)
    {
        for (short i = 0; i < length; i++)
        {
            dst[(short)(dstIndex+i)] = src[(short)(srcIndex+i)];
        }
    }

    public short[] generateNewPolyVector(byte paramsK)
    {
        return new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
    }

    public short[] polyVectorNTT(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            short[] row = new short[(short)384];
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), row, (short)0, (short)384);
            row = this.polyNTT(row);
            this.arrayCopyNonAtomic(row, (short)0, r, (short)(i * (short)384), (short)384);
        }
        return r;
    }

    public short[] polyVectorReduce(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            short[] row = new short[(short)384];
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), row, (short)0, (short)384);
            row = this.polyReduce(row);
            this.arrayCopyNonAtomic(row, (short)0, r, (short)(i * (short)384), (short)384);
        }
        return r;
    }

    public short[] polyReduce(short[] r)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            r[i] = this.barrettReduce(r[i]);
        }
        return r;
    }

    public short barrettReduce(short a)
    {
        //long shift = (((long) 1) << 26);
        //short v = (short) ((shift + (KyberParams.paramsQ / 2)) / KyberParams.paramsQ);
        short v = (short)20159; //All static values, no calculation needed

        //short t = (short) ((v * a) >> 26);
        Arithmetic.multiplyShorts(v,a,multiplied);
        short t = (short)(multiplied[0]>>10);// >> (26-16) = 10

        t = (short)(t * KyberParams.paramsQ);
        return (short)(a - t);
    }

    public short[] polyNTT(short[] r)
    {
        short j = 0;
        short k = 1;
        for (short l = (short)128; l >= 2; l >>= 1)
        {
            for (short start = 0; start < (short)256; start = (short)(j + l))
            {
                short zeta = nttZetas[k];
                k = (short)(k + (short)1);
                for (j = start; j < (short)(start + l); j++)
                {
                    short t = this.modQMulMont(zeta, r[(short)(j + l)]);
                    r[(short)(j + l)] = (short)(r[j] - t);
                    r[j] = (short)(r[j] + t);
                }
            }
        }
        return r;
    }

    public short modQMulMont(short a, short b)
    {
        //(long) ((long) a * (long) b)
        Arithmetic.multiplyShorts(a,b, jc);
        return this.montgomeryReduce(jc);
    }

    public short[] polyToMont(short[] polyR)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            //polyR[i] = this.montgomeryReduce((int) (polyR[i] * 1353));
            Arithmetic.multiplyShorts(polyR[i],(short)1353, jc);
            polyR[i] = this.montgomeryReduce(jc);
        }
        return polyR;
    }

    public short montgomeryReduce(short[] jc)
    {

        //short u = (short) (a * KyberParams.paramsQinv);
        short u = (short) ((jc[1] * KyberParams.paramsQinv) & (short)0xFFFF);

        //int t = (int) (u * KyberParams.paramsQ);
        Arithmetic.multiplyShorts(KyberParams.paramsQ,u, multiplied);

        //t = (int) (a - t);
        Arithmetic.subtract(jc,multiplied);

        // t >>= 16;
        return jc[0];
    }

    public short[] getNoisePoly(byte[] seed, byte nonce, byte paramsK)
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
        p = this.generatePRFByteArray(l, seed, nonce);
        return this.generateCBDPoly(p, paramsK);
    }

    public short[] generateCBDPoly(byte[] buf, byte paramsK)
    {
        byte[] d = new byte[3];
        byte[] t = new byte[3];
        byte[] tempT = new byte[3];

        short a, b;
        short[] r = new short[KyberParams.paramsPolyBytes];
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2: default:
            for (byte i = 0; i < KyberParams.paramsN / 4; i++)
            {
                //t = Poly.convertByteTo24BitUnsignedInt(Arrays.copyOfRange(buf, (3 * i), buf.length));
                t[0] = buf[(short)(3*i+2)];
                t[1] = buf[(short)(3*i+1)];
                t[2] = buf[(short)(3*i+0)];

                //t & 0x00249249
                d[0] = (byte)(t[0] & 0x24);
                d[1] = (byte)(t[1] & 0x92);
                d[2] = (byte)(t[2] & 0x49);

                //t >> 1
                t[2] = (byte)(((t[2]&0xFF)>>1) | ((t[1]&0xFF)<<7));
                t[1] = (byte)(((t[1]&0xFF)>>1) | ((t[0]&0xFF)<<7));
                t[0] = (byte)(((t[0]&0xFF)>>1));

                //(t >> 1) & 0x00249249
                tempT[0] = (byte)(t[0] & 0x24);
                tempT[1] = (byte)(t[1] & 0x92);
                tempT[2] = (byte)(t[2] & 0x49);

                //d = d + (t >> 1) & 0x00249249
                Arithmetic.sumByteArrays(d,tempT);

                //t >> 1
                t[2] = (byte)(((t[2]&0xFF)>>1) | ((t[1]&0xFF)<<7));
                t[1] = (byte)(((t[1]&0xFF)>>1) | ((t[0]&0xFF)<<7));
                t[0] = (byte)(((t[0]&0xFF)>>1));

                //(t >> 1) & 0x00249249
                tempT[0] = (byte)(t[0] & 0x24);
                tempT[1] = (byte)(t[1] & 0x92);
                tempT[2] = (byte)(t[2] & 0x49);

                //d = d + (t >> 1) & 0x00249249
                Arithmetic.sumByteArrays(d,tempT);

                //for (int j = 0; j < 4; j++) //replaced loop with static 4 assignments
                //See generateCBDPoly.txt
                a = (short)(((d[2]&0xFF)>>0) & 0x7);                          //a = (short)((d >> (6 * j + 0)) & 0x7);
                b = (short)((((d[1]&0xFF)<<5) | ((d[2]&0xFF)>>3)) & 0x7);//3  //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                r[(short)(4 * i + 0)] = (short)(a - b);                                //r[4 * i + j] = (short)(a - b);

                a = (short)((((d[1]&0xFF)<<2) | ((d[2]&0xFF)>>6)) & 0x7);//6  //a = (short)((d >> (6 * j + 0)) & 0x7);
                b = (short)((((d[0]&0xFF)<<7) | ((d[1]&0xFF)>>1)) & 0x7);//9  //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                r[(short)(4 * i + 1)] = (short)(a - b);                                //r[4 * i + j] = (short)(a - b);

                a = (short)((((d[0]&0xFF)<<4) | ((d[1]&0xFF)>>4)) & 0x7);//12 //a = (short)((d >> (6 * j + 0)) & 0x7);
                b = (short)((((d[0]&0xFF)<<1) | ((d[1]&0xFF)>>7)) & 0x7);//15 //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                r[(short)(4 * i + 2)] = (short)(a - b);                                //r[4 * i + j] = (short)(a - b);

                a = (short)(((d[0]&0xFF)>>2) & 0x7);//18                      //a = (short)((d >> (6 * j + 0)) & 0x7);
                b = (short)(((d[0]&0xFF)>>5) & 0x7);//21                      //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                r[(short)(4 * i + 3)] = (short)(a - b);
            }
            break;
        }
        return r;
    }

    public byte[] generatePRFByteArray(short l, byte[] key, byte nonce)
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

    public byte[] polyToBytes(short[] a)
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

    public byte[] polyVectorToBytes(short[] polyA, byte paramsK)
    {
        //Optimize r as parameter
        byte[] r = new byte[(short)(paramsK * KyberParams.paramsPolyBytes)];
        short[] row = new short[KyberParams.paramsPolyBytes];
        for (byte i = 0; i < paramsK; i++)
        {
            this.arrayCopyNonAtomic(polyA, (short)(i * KyberParams.paramsPolyBytes), row, (short)0, KyberParams.paramsPolyBytes);
            byte[] byteA = polyToBytes(row);
            Util.arrayCopyNonAtomic(byteA, (short)0, r, (short)(i * KyberParams.paramsPolyBytes), (short)byteA.length);
        }
        return r;
    }

    public short[] polyVectorPointWiseAccMont(short[] polyA, short[] polyB, byte paramsK)
    {
        short rowSize = 384;
        short[] Brow = new short[rowSize];
        this.arrayCopyNonAtomic(polyB, (short)0, Brow, (short)0, rowSize);
        short[] polyArow = new short[rowSize];
        this.arrayCopyNonAtomic(polyA, (short)0, polyArow, (short)0, rowSize);
        //variable r can be removed since polyBaseMulMont returns polyArow
        short[] r = this.polyBaseMulMont(polyArow, Brow);
        for (byte i = 1; i < paramsK; i++)
        {
            short[] Arow = new short[rowSize];
            this.arrayCopyNonAtomic(polyA, (short)(i*rowSize), Arow, (short)0, rowSize);
            this.arrayCopyNonAtomic(polyB, (short)(i*rowSize), Brow, (short)0, rowSize);
            short[] t = this.polyBaseMulMont(Arow, Brow);
            r = this.polyAdd(r, t);
        }
        return this.polyReduce(r);
    }

    public short[] polyBaseMulMont(short[] polyA, short[] polyB)
    {
        for (byte i = 0; i < (KyberParams.paramsN / 4); i++)
        {
            short[] rx = this.baseMultiplier(
                    polyA[(short)(4 * i + 0)], polyA[(short)(4 * i + 1)],
                    polyB[(short)(4 * i + 0)], polyB[(short)(4 * i + 1)],
                    Poly.nttZetas[64 + i]
            );
            short[] ry = this.baseMultiplier(
                    polyA[(short)(4 * i + 2)], polyA[(short)(4 * i + 3)],
                    polyB[(short)(4 * i + 2)], polyB[(short)(4 * i + 3)],
                    (short)(-1 * Poly.nttZetas[(short)(64 + i)])
            );
            polyA[(short)(4 * i + 0)] = rx[0];
            polyA[(short)(4 * i + 1)] = rx[1];
            polyA[(short)(4 * i + 2)] = ry[0];
            polyA[(short)(4 * i + 3)] = ry[1];
        }
        return polyA;
    }

    public short[] baseMultiplier(short a0, short a1, short b0, short b1, short zeta)
    {
        short[] r = new short[2];
        r[0] = this.modQMulMont(a1, b1);
        r[0] = this.modQMulMont(r[0], zeta);
        r[0] = (short)(r[0] + this.modQMulMont(a0, b0));
        r[1] = this.modQMulMont(a0, b1);
        r[1] = (short)(r[1] + this.modQMulMont(a1, b0));
        return r;
    }

    public short[] polyAdd(short[] polyA, short[] polyB)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            polyA[i] = (short)(polyA[i] + polyB[i]);
        }
        return polyA;
    }

    public short[] polyVectorAdd(short[] polyA, short[] polyB, byte paramsK)
    {
        short rowSize = 384;
        for (byte i = 0; i < paramsK; i++)
        {
            for (short j = 0; j < rowSize; j++)
            {
                polyA[(short)((i * rowSize) + j)] += polyB[(short)((i * rowSize) + j)];
            }
        }
        return polyA;
    }
}