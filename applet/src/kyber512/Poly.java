package applet.kyber;

import javacard.framework.*;

public class Poly
{
    private static Poly poly;

    private static short[] multiplied;
    private static short[] jc;
    private static short[] result;
    private static short[] RAM384;

    private Poly()
    {
        multiplied = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        jc = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        result = JCSystem.makeTransientShortArray((short)2, JCSystem.CLEAR_ON_DESELECT);
        RAM384 = JCSystem.makeTransientShortArray((short)384, JCSystem.CLEAR_ON_DESELECT);
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

    public final static short[] nttZetasInv = new short[]
    {
            1701, 1807, 1460, 2371, 2338, 2333, 308, 108, 2851, 870, 854, 1510, 2535,
            1278, 1530, 1185, 1659, 1187, 3109, 874, 1335, 2111, 136, 1215, 2945, 1465,
            1285, 2007, 2719, 2726, 2232, 2512, 75, 156, 3000, 2911, 2980, 872, 2685,
            1590, 2210, 602, 1846, 777, 147, 2170, 2551, 246, 1676, 1755, 460, 291, 235,
            3152, 2742, 2907, 3224, 1779, 2458, 1251, 2486, 2774, 2899, 1103, 1275, 2652,
            1065, 2881, 725, 1508, 2368, 398, 951, 247, 1421, 3222, 2499, 271, 90, 853,
            1860, 3203, 1162, 1618, 666, 320, 8, 2813, 1544, 282, 1838, 1293, 2314, 552,
            2677, 2106, 1571, 205, 2918, 1542, 2721, 2597, 2312, 681, 130, 1602, 1871,
            829, 2946, 3065, 1325, 2756, 1861, 1474, 1202, 2367, 3147, 1752, 2707, 171,
            3127, 3042, 1907, 1836, 1517, 359, 758, 1441
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

    public short[] polyVectorFromBytes(byte[] polyA, byte paramsK)
    {
        short[] r = new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
        for (byte i = 0; i < paramsK; i++)
        {
            short start = (short)(i * KyberParams.paramsPolyBytes);
            short end = (short)((i + 1) * KyberParams.paramsPolyBytes);
            byte[] temp = new byte[(short)(end-start)];
            Util.arrayCopyNonAtomic(polyA, start, temp, (short)0, (short)(end-start));
            this.arrayCopyNonAtomic(this.polyFromBytes(temp), (short)0, r, (short)(i*384), (short)384);
        }
        return r;
    }

    public short[] polyFromBytes(byte[] a)
    {
        short[] r = new short[KyberParams.paramsPolyBytes];
        for (short i = 0; i < KyberParams.paramsN / 2; i++)
        {
            r[(short)(2 * i)] = (short)((((a[(short)(3 * i + 0)] & 0xFF) >> 0) | ((a[(short)(3 * i + 1)] & 0xFF) << 8)) & 0xFFF);
            r[(short)(2 * i + 1)] = (short)((((a[(short)(3 * i + 1)] & 0xFF) >> 4) | ((a[(short)(3 * i + 2)] & 0xFF) << 4)) & 0xFFF);
        }
        return r;
    }

    public short[] polyFromData(byte[] msg)
    {
        short[] r = new short[KyberParams.paramsN];
        short mask;
        for (byte i = 0; i < KyberParams.paramsN / 8; i++)
        {
            for (byte j = 0; j < 8; j++)
            {
                mask = (short)(-1 * (short)(((msg[i] & 0xFF) >> j) & 1));
                r[(short)(8 * i + j)] = (short) (mask & (short)((KyberParams.paramsQ + 1) / 2));
            }
        }
        return r;
    }

    public short[] polyVectorNTT(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384, (short)0, (short)384);
            RAM384 = this.polyNTT(RAM384);
            this.arrayCopyNonAtomic(RAM384, (short)0, r, (short)(i * (short)384), (short)384);
        }
        return r;
    }

    public short[] polyVectorReduce(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384, (short)0, (short)384);
            RAM384 = this.polyReduce(RAM384);
            this.arrayCopyNonAtomic(RAM384, (short)0, r, (short)(i * (short)384), (short)384);
        }
        return r;
    }

    public short conditionalSubQ(short a)
    {
        a = (short)(a - KyberParams.paramsQ);
        a = (short)(a + ((a >> 15) & KyberParams.paramsQ));
        return a;
    }

    public short[] polyConditionalSubQ(short[] r)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            r[i] = this.conditionalSubQ(r[i]);
        }
        return r;
    }

    public short[] polyVectorCSubQ(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            this.arrayCopyNonAtomic(r,(short)(i*384),RAM384,(short)0,(short)384);
            this.arrayCopyNonAtomic(this.polyConditionalSubQ(RAM384),(short)0,r,(short)(i*384),(short)384);
        }
        return r;
    }

    public byte[] compressPoly(short[] polyA, byte paramsK)
    {
        byte[] t = new byte[8];
        polyA = this.polyConditionalSubQ(polyA);
        short rr = 0;
        byte[] r;
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2:
            case 3: default:
            r = new byte[KyberParams.paramsPolyCompressedBytesK768];
            for (byte i = 0; i < KyberParams.paramsN / 8; i++)
            {
                for (byte j = 0; j < 8; j++)
                {
                    //t[j] = (byte) (((((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 15);

                    //((polyA[8 * i + j]) << 4)
                    short shHigh = (short)(polyA[(short)(8 * i + j)] >> 12);
                    short shLow = (short)(polyA[(short)(8 * i + j)] << 4);

                    //(((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2))
                    Arithmetic.add(shHigh, shLow, (short)0, (short)(KyberParams.paramsQ / 2), result);

                    //((((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ))
                    Arithmetic.divide(result[0], result[1], (short)0, KyberParams.paramsQ, result);

                    //(byte) (((((polyA[8 * i + j]) << 4) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 15)
                    t[j] = (byte)(result[1] & 15);
                }
                r[(short)(rr + 0)] = (byte)(t[0] | (t[1] << 4));
                r[(short)(rr + 1)] = (byte)(t[2] | (t[3] << 4));
                r[(short)(rr + 2)] = (byte)(t[4] | (t[5] << 4));
                r[(short)(rr + 3)] = (byte)(t[6] | (t[7] << 4));
                rr+=4;
            }
            break;
//            default:
//                r = new byte[KyberParams.paramsPolyCompressedBytesK1024];
//                for (int i = 0; i < KyberParams.paramsN / 8; i++) {
//                    for (int j = 0; j < 8; j++) {
//                        t[j] = (byte) (((((polyA[8 * i + j]) << 5) + (KyberParams.paramsQ / 2)) / (KyberParams.paramsQ)) & 31);
//                    }
//                    r[rr + 0] = (byte) ((t[0] >> 0) | (t[1] << 5));
//                    r[rr + 1] = (byte) ((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
//                    r[rr + 2] = (byte) ((t[3] >> 1) | (t[4] << 4));
//                    r[rr + 3] = (byte) ((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
//                    r[rr + 4] = (byte) ((t[6] >> 2) | (t[7] << 3));
//                    rr = rr + 5;
//                }
        }

        return r;
    }

    public byte[] compressPolyVector(short[] a, byte paramsK)
    {
        this.polyVectorCSubQ(a, paramsK);
        short rr = 0;
        byte[] r;
        short[] t;
        switch (paramsK)
        {
            case 2:
                r = new byte[KyberParams.paramsPolyvecCompressedBytesK512];
                break;
            case 3:
                r = new byte[KyberParams.paramsPolyvecCompressedBytesK768];
                break;
            default:
                r = new byte[KyberParams.paramsPolyvecCompressedBytesK1024];
        }

        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2:
            case 3: default:
            t = new short[4];//Kyber 512 only for now, perhaps need to be increased for Kyber 768 and Kyber 1024
            for (byte i = 0; i < paramsK; i++)
            {
                for (short j = 0; j < KyberParams.paramsN / 4; j++)
                {
                    for (byte k = 0; k < 4; k++)
                    {
                        //t[k] = ((long) (((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ)) & 0x3ff);

                        this.arrayCopyNonAtomic(a,(short)(i*384),RAM384,(short)0,(short)384);

                        //((long) (a[i][4 * j + k]) << 10)
                        short shHigh = (short)((RAM384[(short)(4 * j + k)]) >> 6);
                        short shLow = (short)((RAM384[(short)(4 * j + k)]) << 10);

                        //((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2))
                        Arithmetic.add(shHigh, shLow, (short)0, (short)(KyberParams.paramsQ / 2), result);

                        //(((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ))
                        Arithmetic.divide(result[0], result[1], (short)0, KyberParams.paramsQ, result);

                        //((long) (((long) ((long) (a[i][4 * j + k]) << 10) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ)) & 0x3ff)
                        t[k] = (short)(result[1]&0x3FF);
                    }
                    r[(short)(rr + 0)] = (byte)(t[0] >> 0);
                    r[(short)(rr + 1)] = (byte)((t[0] >> 8) | (t[1] << 2));
                    r[(short)(rr + 2)] = (byte)((t[1] >> 6) | (t[2] << 4));
                    r[(short)(rr + 3)] = (byte)((t[2] >> 4) | (t[3] << 6));
                    r[(short)(rr + 4)] = (byte)((t[3] >> 2));
                    rr+=5;
                }
            }
            break;
//            default:
//                t = new long[8];
//                for (byte i = 0; i < paramsK; i++) {
//                    for (int j = 0; j < KyberParams.paramsN / 8; j++) {
//                        for (int k = 0; k < 8; k++) {
//                            t[k] = ((long) (((long) ((long) (a[i][8 * j + k]) << 11) + (long) (KyberParams.paramsQ / 2)) / (long) (KyberParams.paramsQ)) & 0x7ff);
//                        }
//                        r[rr + 0] = (byte) ((t[0] >> 0));
//                        r[rr + 1] = (byte) ((t[0] >> 8) | (t[1] << 3));
//                        r[rr + 2] = (byte) ((t[1] >> 5) | (t[2] << 6));
//                        r[rr + 3] = (byte) ((t[2] >> 2));
//                        r[rr + 4] = (byte) ((t[2] >> 10) | (t[3] << 1));
//                        r[rr + 5] = (byte) ((t[3] >> 7) | (t[4] << 4));
//                        r[rr + 6] = (byte) ((t[4] >> 4) | (t[5] << 7));
//                        r[rr + 7] = (byte) ((t[5] >> 1));
//                        r[rr + 8] = (byte) ((t[5] >> 9) | (t[6] << 2));
//                        r[rr + 9] = (byte) ((t[6] >> 6) | (t[7] << 5));
//                        r[rr + 10] = (byte) ((t[7] >> 3));
//                        rr = rr + 11;
//                    }
//                }
        }
        return r;
    }

    public short[] polyVectorInvNTTMont(short[] r, byte paramsK)
    {
        for (byte i = 0; i < paramsK; i++)
        {
            //i=0, row = 384, 0*384 = 0   -> 384
            //i=1, row = 384, 1*384 = 384 -> 768
            this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384, (short)0, (short)384);
            RAM384 = this.polyInvNTTMont(RAM384);
            this.arrayCopyNonAtomic(RAM384, (short)0, r, (short)(i * (short)384), (short)384);
        }
        return r;
    }

    public short[] polyInvNTTMont(short[] r)
    {
        return this.invNTT(r);
    }

    public short[] invNTT(short[] r)
    {
        short j = 0;
        short k = 0;
        for (short l = 2; l <= 128; l <<= 1)
        {
            for (short start = 0; start < 256; start = (short)(j + l))
            {
                short zeta = nttZetasInv[k];
                k+=1;
                for (j = start; j < (short)(start + l); j++)
                {
                    short t = r[j];
                    r[j] = this.barrettReduce((short)(t + r[(short)(j + l)]));
                    r[(short)(j + l)] = (short)(t - r[(short)(j + l)]);
                    r[(short)(j + l)] = this.modQMulMont(zeta, r[(short)(j + l)]);
                }
            }
        }
        for (j = 0; j < 256; j++)
        {
            r[j] = this.modQMulMont(r[j], nttZetasInv[127]);
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
        byte[] d = new byte[4];
        byte[] t = new byte[4];
        byte[] tempT = new byte[4];

        short a, b;
        short[] r = new short[KyberParams.paramsPolyBytes];
        switch (paramsK)
        {
            case 2:
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
                    r[(short)(4 * i + 0)] = (short)(a - b);                       //r[4 * i + j] = (short)(a - b);

                    a = (short)((((d[1]&0xFF)<<2) | ((d[2]&0xFF)>>6)) & 0x7);//6  //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)((((d[0]&0xFF)<<7) | ((d[1]&0xFF)>>1)) & 0x7);//9  //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    r[(short)(4 * i + 1)] = (short)(a - b);                       //r[4 * i + j] = (short)(a - b);

                    a = (short)((((d[0]&0xFF)<<4) | ((d[1]&0xFF)>>4)) & 0x7);//12 //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)((((d[0]&0xFF)<<1) | ((d[1]&0xFF)>>7)) & 0x7);//15 //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    r[(short)(4 * i + 2)] = (short)(a - b);                       //r[4 * i + j] = (short)(a - b);

                    a = (short)(((d[0]&0xFF)>>2) & 0x7);//18                      //a = (short)((d >> (6 * j + 0)) & 0x7);
                    b = (short)(((d[0]&0xFF)>>5) & 0x7);//21                      //b = (short)((d >> (6 * j + KyberParams.paramsETAK512)) & 0x7);
                    r[(short)(4 * i + 3)] = (short)(a - b);                       //r[4 * i + j] = (short)(a - b);
                }
                break;
            default:
                for (byte i = 0; i < KyberParams.paramsN / 8; i++)
                {
                    //t = this.convertByteTo32BitUnsignedInt(Arrays.copyOfRange(buf, (4 * i), buf.length));
                    t[0] = buf[(short)(4*i+3)];
                    t[1] = buf[(short)(4*i+2)];
                    t[2] = buf[(short)(4*i+1)];
                    t[3] = buf[(short)(4*i+0)];

                    //t & 0x55555555
                    d[0] = (byte)(t[0] & 0x55);
                    d[1] = (byte)(t[1] & 0x55);
                    d[2] = (byte)(t[2] & 0x55);
                    d[3] = (byte)(t[3] & 0x55);

                    //t >> 1
                    t[3] = (byte)(((t[3]&0xFF)>>1) | ((t[2]&0xFF)<<7));
                    t[2] = (byte)(((t[2]&0xFF)>>1) | ((t[1]&0xFF)<<7));
                    t[1] = (byte)(((t[1]&0xFF)>>1) | ((t[0]&0xFF)<<7));
                    t[0] = (byte)(((t[0]&0xFF)>>1));

                    //(t >> 1) & 0x55555555
                    tempT[0] = (byte)(t[0] & 0x55);
                    tempT[1] = (byte)(t[1] & 0x55);
                    tempT[2] = (byte)(t[2] & 0x55);
                    tempT[3] = (byte)(t[3] & 0x55);

                    //d = d + (t >> 1) & 0x55555555
                    Arithmetic.sumByteArrays(d,tempT);

                    //for (int j = 0; j < 8; j++) //replaced loop with static 8 assignments
                    a = (short)(((d[3]&0xFF)>>0) & 0x3);
                    b = (short)((((d[2]&0xFF)<<6) | ((d[3]&0xFF)>>2)) & 0x3); //2
                    r[(short)(8 * i + 0)] = (short)(a - b);

                    a = (short)((((d[2]&0xFF)<<4) | ((d[3]&0xFF)>>4)) & 0x3); //4
                    b = (short)((((d[2]&0xFF)<<2) | ((d[3]&0xFF)>>6)) & 0x3); //6
                    r[(short)(8 * i + 1)] = (short)(a - b);

                    a = (short)((((d[2]&0xFF)<<0) | ((d[3]&0xFF)>>8)) & 0x3); //8
                    b = (short)((((d[1]&0xFF)<<6) | ((d[2]&0xFF)>>2)) & 0x3); //10
                    r[(short)(8 * i + 2)] = (short)(a - b);

                    a = (short)((((d[1]&0xFF)<<4) | ((d[2]&0xFF)>>4)) & 0x3); //12
                    b = (short)((((d[1]&0xFF)<<2) | ((d[2]&0xFF)>>6)) & 0x3); //14
                    r[(short)(8 * i + 3)] = (short)(a - b);

                    a = (short)((((d[1]&0xFF)<<0) | ((d[2]&0xFF)>>8)) & 0x3); //16
                    b = (short)((((d[0]&0xFF)<<6) | ((d[1]&0xFF)>>2)) & 0x3); //18
                    r[(short)(8 * i + 4)] = (short)(a - b);

                    a = (short)((((d[0]&0xFF)<<4) | ((d[1]&0xFF)>>4)) & 0x3); //20
                    b = (short)((((d[0]&0xFF)<<2) | ((d[1]&0xFF)>>6)) & 0x3); //22
                    r[(short)(8 * i + 5)] = (short)(a - b);

                    a = (short)((((d[0]&0xFF)<<0) | ((d[1]&0xFF)>>8)) & 0x3); //24
                    b = (short)(((d[0]&0xFF)>>2) & 0x3); //26
                    r[(short)(8 * i + 6)] = (short)(a - b);

                    a = (short)(((d[0]&0xFF)>>4) & 0x3); //28
                    b = (short)(((d[0]&0xFF)>>6) & 0x3); //30
                    r[(short)(8 * i + 7)] = (short)(a - b);
                }
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

    public byte[] polyToMsg(short[] a)
    {
        byte[] msg = new byte[KyberParams.paramsSymBytes];
        short t;
        a = this.polyConditionalSubQ(a);//opt such that a is no return, but update parameter only
        for (byte i = 0; i < (byte)(KyberParams.paramsN / 8); i++)
        {
            msg[i] = 0;
            for (byte j = 0; j < 8; j++)
            {
                t = (short)(((short)((a[(short)(8 * i + j)] << 1) + (KyberParams.paramsQ / 2)) / KyberParams.paramsQ) & 1);
                msg[i] = (byte)(msg[i] | (t << j));
            }
        }
        return msg;
    }

    public short[] decompressPolyVector(byte[] a, byte paramsK)
    {
        short[] r = new short[(short)(paramsK*KyberParams.paramsPolyBytes)];
        short aa = 0;
        short[] t;
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2:
            case 3: default:
            t = new short[4]; // has to be unsigned..
            for (byte i = 0; i < paramsK; i++)
            {
                for (byte j = 0; j < (KyberParams.paramsN / 4); j++)
                {
                    t[0] = (short)(((a[(short)(aa + 0)] & (short)0xFF) >> 0) | ((a[(short)(aa + 1)] & (short)0xFF) << 8));
                    t[1] = (short)(((a[(short)(aa + 1)] & (short)0xFF) >> 2) | ((a[(short)(aa + 2)] & (short)0xFF) << 6));
                    t[2] = (short)(((a[(short)(aa + 2)] & (short)0xFF) >> 4) | ((a[(short)(aa + 3)] & (short)0xFF) << 4));
                    t[3] = (short)(((a[(short)(aa + 3)] & (short)0xFF) >> 6) | ((a[(short)(aa + 4)] & (short)0xFF) << 2));
                    aa+=5;
                    for (byte k = 0; k < 4; k++)
                    {
                        //(long) (t[k] & 0x3FF) * (long) (KyberParams.paramsQ)
                        Arithmetic.multiplyShorts((short)(t[k] & 0x3FF), KyberParams.paramsQ, multiplied);
                        //((long) (t[k] & 0x3FF) * (long) (KyberParams.paramsQ) + 512)

                        Arithmetic.add(multiplied[0], multiplied[1], (short)0, (short)512, multiplied);

                        //((long) (t[k] & 0x3FF) * (long) (KyberParams.paramsQ) + 512) >> 10
                        short value = (short)((multiplied[0]<<6) | (((multiplied[1]>>8)&(short)0xFF) >> 2));

                        this.arrayCopyNonAtomic(r, (short)(i * (short)384), RAM384, (short)0, (short)384);
                        RAM384[(short)(4 * j + k)] = value;
                        this.arrayCopyNonAtomic(RAM384, (short)0, r, (short)(i * (short)384), (short)384);
                    }
                }
            }
            break;
        }
        return r;
    }

    public short[] decompressPoly(byte[] a, byte paramsK)
    {
        short[] r = new short[KyberParams.paramsPolyBytes];
        short aa = 0;
        switch (paramsK)
        {
            //Only kyber 512 for now
            case 2:
            case 3: default:
            for (short i = 0; i < KyberParams.paramsN / 2; i++)
            {
                //(((int) (a[aa] & 0xFF) & 15) * KyberParams.paramsQ)
                Arithmetic.multiplyShorts((short)((a[aa] & (short)0xFF) & 15), KyberParams.paramsQ, multiplied);
                //((((int) (a[aa] & 0xFF) & 15) * KyberParams.paramsQ) + 8)
                Arithmetic.add(multiplied[0], multiplied[1], (short)0, (short)8, multiplied);
                //r[(short)(2 * i + 0)] = (short) (((((int) (a[aa] & 0xFF) & 15) * KyberParams.paramsQ) + 8) >> 4);
                r[(short)(2 * i + 0)] = (short)(((multiplied[1]>>4)&(short)0xFFF));

                //(((int) (a[aa] & 0xFF) >> 4) * KyberParams.paramsQ)
                Arithmetic.multiplyShorts((short)((a[aa] & 0xFF) >> 4), KyberParams.paramsQ, multiplied);
                //((((int) (a[aa] & 0xFF) >> 4) * KyberParams.paramsQ) + 8)
                Arithmetic.add(multiplied[0], multiplied[1], (short)0, (short)8, multiplied);
                //r[(short)(2 * i + 1)] = (short) (((((int) (a[aa] & 0xFF) >> 4) * KyberParams.paramsQ) + 8) >> 4);
                r[(short)(2 * i + 1)] = (short)(((multiplied[1]>>4)&(short)0xFFF));
                aa+=1;
            }
            break;
        }
        return r;
    }

    public short[] polySub(short[] polyA, short[] polyB)
    {
        for (short i = 0; i < KyberParams.paramsN; i++)
        {
            polyA[i] = (short)(polyA[i] - polyB[i]);
        }
        return polyA;
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
        short[] Brow = new short[rowSize];//can use RAN384 here
        this.arrayCopyNonAtomic(polyB, (short)0, Brow, (short)0, rowSize);
        short[] polyArow = new short[rowSize];//cannot use same RAN384 here
        this.arrayCopyNonAtomic(polyA, (short)0, polyArow, (short)0, rowSize);
        //variable r can be removed since polyBaseMulMont returns polyArow
        short[] r = this.polyBaseMulMont(polyArow, Brow);
        short[] Arow = new short[rowSize];//cannot use same RAN384 here
        for (byte i = 1; i < paramsK; i++)
        {
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