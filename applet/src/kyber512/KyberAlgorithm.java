package applet.kyber;

import javacard.framework.*;
import javacard.security.*;

public class KyberAlgorithm
{
    private static KyberAlgorithm kyber = null;

    protected KyberAlgorithm(){}

    public static KyberAlgorithm getInstance()
    {
        if (kyber == null) kyber = new KyberAlgorithm();
        return kyber;
    }

    public void generateKeys(byte paramsK, short privateKeyBytes)
    {
        try
        {
            Keccak keccak;
            KeyPair keyPair = KeyPair.getInstance(paramsK);
            this.generateKyberKeys(paramsK);
            byte[] privateKeyFixedLength = new byte[privateKeyBytes];
            keccak = Keccak.getInstance(Keccak.ALG_SHA3_256);
            byte[] encodedHash = new byte[(byte)32];
            keccak.doFinal(keyPair.getPublicKey(), encodedHash);
            byte[] pkh = new byte[encodedHash.length];
            Util.arrayCopyNonAtomic(encodedHash, (short)0, pkh, (short)0, (short)encodedHash.length);
            byte[] rnd = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
            RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
            random.nextBytes(rnd, (short)0, (short)32);
            short offsetEnd = (short)keyPair.getPrivateKey().length;
            Util.arrayCopyNonAtomic(keyPair.getPrivateKey(), (short)0, privateKeyFixedLength, (short)0, offsetEnd);
            Util.arrayCopyNonAtomic(keyPair.getPublicKey(), (short)0, privateKeyFixedLength, offsetEnd, (short)keyPair.getPublicKey().length);
            offsetEnd = (short)(offsetEnd + keyPair.getPublicKey().length);
            Util.arrayCopyNonAtomic(pkh, (short)0, privateKeyFixedLength, offsetEnd, (short)pkh.length);
            offsetEnd += (short)pkh.length;
            Util.arrayCopyNonAtomic(rnd, (short)0, privateKeyFixedLength, offsetEnd, (short)rnd.length);
            keyPair.setPrivateKey(privateKeyFixedLength);
            //priv = priv || pub || pkh (pub hash) || rnd
        }
        catch (Exception e)
        {
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
    }

    public void generateKyberKeys(byte paramsK) throws Exception
    {
        KeyPair keyPair = KeyPair.getInstance(paramsK);
    }
}