package applet.kyber;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class Kyber extends Applet
{
	private static short setEncapsulationLength = 0;
	private static short receivedDataLength = 0;
	private static byte receivedDataType = 0;
	private static boolean encapsulationIsSet = false;

	private static KyberAlgorithm kyber;
	private static AESKey sharedSecret;
	private static Cipher aesCBC;

	private Kyber(byte[] parameters, short offset)
	{
		super.register(parameters, (short)(offset + 1), parameters[offset]);
		kyber = KyberAlgorithm.getInstance((byte)2);
		aesCBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		sharedSecret = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
	}

	public static void install(byte[] parameters, short offset, byte length)
	{
		new Kyber(parameters, offset);
	}

	@Override
	public void process(APDU apdu) throws ISOException
	{
		if (super.selectingApplet()) return;
		switch (Util.getShort(apdu.getBuffer(), ISO7816.OFFSET_P1))
		{
			case (short)0x0512: this.generateKyberKeyPair(apdu, (byte)2); break;
			case (short)0x0768: this.generateKyberKeyPair(apdu, (byte)3); break;
			case (short)0x1024: this.generateKyberKeyPair(apdu, (byte)4); break;
			case (short)0x0001: this.encapsulate(apdu); break;
			case (short)0x0002: this.decapsulate(apdu); break;
			case (short)0x0003: this.setEncapsulation(apdu); break;
			case (short)0x0004: this.obtainData(apdu, KyberAlgorithm.publicKey, KyberAlgorithm.publicKeyLength, (byte)2); break;
			case (short)0x0005: this.obtainData(apdu, KyberAlgorithm.encapsulation, KyberAlgorithm.encapsulationLength, (byte)4); break;
			case (short)0x0006: this.aes(apdu, Cipher.MODE_ENCRYPT); break;
			case (short)0x0007: this.aes(apdu, Cipher.MODE_DECRYPT); break;

			//WARNING: Enable these functions *only* for testing purposes!
			//Enabling these functions exposes sensitive data and renders the card critically insecure!
			//Use at your own risk and ensure they are disabled in production!
//			case (short)0x1001: this.obtainData(apdu, KyberAlgorithm.privateKey, KyberAlgorithm.privateKeyLength, (byte)1); break;
//			case (short)0x1002: this.obtainData(apdu, KyberAlgorithm.secretKey, (short)32, (byte)3); break;
//			case (short)0x1003: this.clearSecret(apdu); break;
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
		}
	}

	private void aes(APDU apdu, byte cipherMode)
	{
		short length = apdu.setIncomingAndReceive();
		if (length != 32) ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (!sharedSecret.isInitialized()) ISOException.throwIt((short)0x6996);//Data must be updated again
		byte[] buffer = apdu.getBuffer();
		aesCBC.init(sharedSecret, cipherMode);
		aesCBC.doFinal(buffer, ISO7816.OFFSET_CDATA, length, buffer, ISO7816.OFFSET_CDATA);
		apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, length);
	}

	public void clearSecret(APDU apdu)
	{
		for (byte i = 0; i < 32; i++)
		{
			KyberAlgorithm.secretKey[i] = 0x00;
		}
	}

	public void generateKyberKeyPair(APDU apdu, byte paramsK)
	{
		sharedSecret.clearKey();
		kyber = KyberAlgorithm.getInstance(paramsK);
		kyber.generateKeys();
		encapsulationIsSet = false;
	}

	private void encapsulate(APDU apdu)
	{
		sharedSecret.clearKey();
		kyber.encapsulate();
		sharedSecret.setKey(KyberAlgorithm.secretKey, (byte)0x00);
		encapsulationIsSet = true;
	}

	private void decapsulate(APDU apdu)
	{
		if (!encapsulationIsSet) ISOException.throwIt((short)0x6996);//Data must be updated again
		sharedSecret.clearKey();
		kyber.decapsulate();
		sharedSecret.setKey(KyberAlgorithm.secretKey, (byte)0x00);
	}

	private void obtainData(APDU apdu, byte[] data, short length, byte type)
	{
		//type 1 = private key, 2 = public key, 3 = secret, 4 = encapsulation
		if (type != receivedDataType)
		{
			receivedDataLength=0;
			receivedDataType = type;
		}
		short chunkSize = 255;
		if ((short)(receivedDataLength+255) > length) chunkSize = (short)(length-receivedDataLength);
		Util.arrayCopyNonAtomic(data, receivedDataLength, apdu.getBuffer(), (short)0x0000, chunkSize);
		apdu.setOutgoingAndSend((short)0x0000, chunkSize);
		receivedDataLength+=255;
		if (receivedDataLength < length)ISOException.throwIt((short)0x5000);
		receivedDataLength=0;
	}

	private void setEncapsulation(APDU apdu)
	{
		short dataLength = apdu.setIncomingAndReceive();
		Util.arrayCopyNonAtomic(apdu.getBuffer(), ISO7816.OFFSET_CDATA, KyberAlgorithm.encapsulation, setEncapsulationLength, dataLength);
		setEncapsulationLength += dataLength;
		if (setEncapsulationLength == KyberAlgorithm.encapsulationLength)
		{
			setEncapsulationLength = 0;
			encapsulationIsSet = true;
		}
	}
}