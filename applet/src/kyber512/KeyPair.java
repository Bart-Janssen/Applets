package applet.kyber;

import javacard.framework.*;

public class KeyPair
{
    private static byte[] privateKey;
    private static byte[] publicKey;

    private static KeyPair keyPair = null;

    private KeyPair(){}

    public static KeyPair getInstance(byte paramsK)
    {
        if (keyPair == null)
        {
            keyPair = new KeyPair();
            //Only kyber 512 for now
            if (paramsK == (short)2)
            {
                privateKey = new byte[(short)1632];
                publicKey = new byte[(short)800];
            }
        }
        return keyPair;
    }

    public KeyPair(byte[] privateKey, byte[] publicKey)
    {
        KeyPair.privateKey = privateKey;
        KeyPair.publicKey = publicKey;
    }

    public void setPrivateKey(byte[] privateKey)
    {
        KeyPair.privateKey = privateKey;
    }

    public void setPublicKey(byte[] publicKey)
    {
        KeyPair.publicKey = publicKey;
    }

    public byte[] getPrivateKey()
    {
        return privateKey;
    }

    public byte[] getPublicKey()
    {
        return publicKey;
    }
}