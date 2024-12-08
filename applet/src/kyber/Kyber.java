package applet.kyber;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class Kyber extends Applet
{
	private static short setEncapsulationLength = 0;
	private static short receivedDataLength = 0;
	private static byte receivedDataType = 0;

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
			case (short)0x0004: this.obtainData(apdu, KyberAlgorithm.privateKey, KyberAlgorithm.privateKeyLength, (byte)1); break;
			case (short)0x0005: this.obtainData(apdu, KyberAlgorithm.publicKey, KyberAlgorithm.publicKeyLength, (byte)2); break;
			case (short)0x0006: this.obtainData(apdu, KyberAlgorithm.secretKey, (short)32, (byte)3); break;
			case (short)0x0007: this.obtainData(apdu, KyberAlgorithm.encapsulation, KyberAlgorithm.encapsulationLength, (byte)4); break;
			case (short)0x0009: this.getFreeRAM(apdu); break;
			case (short)0x0010: this.clearSecret(apdu); break;
			case (short)0x0011: this.bigTest(apdu); break;
			case (short)0x0012: this.AES(apdu, Cipher.MODE_ENCRYPT); break;
			case (short)0x0013: this.AES(apdu, Cipher.MODE_DECRYPT); break;
			default: ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED); break;
		}
	}

	private void AES(APDU apdu, byte cipherMode)
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

	public void bigTest(APDU apdu)
	{
		kyber = KyberAlgorithm.getInstance((byte)2);
		this.generateKyberKeyPair(apdu, (byte)2);
		this.encapsulate(apdu);
//		this.decapsulate(apdu);
	}

	public void getFreeRAM(APDU apdu)
	{
		byte[] ramUsageBuffer = new byte[2];
		short availableRAM = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
		ramUsageBuffer[0] = (byte)(availableRAM >> 8);
		ramUsageBuffer[1] = (byte)(availableRAM & 0xFF);
		Util.arrayCopyNonAtomic(ramUsageBuffer, (short)0x0000, apdu.getBuffer(), (short)0x0000, (short)ramUsageBuffer.length);
		apdu.setOutgoingAndSend((short)0x0000, (short)ramUsageBuffer.length);
	}

	public void generateKyberKeyPair(APDU apdu, byte paramsK)
	{
		sharedSecret.clearKey();
		kyber = KyberAlgorithm.getInstance(paramsK);
		kyber.generateKeys();
	}

	private void encapsulate(APDU apdu)
	{
		sharedSecret.clearKey();
		kyber.encapsulate();
		sharedSecret.setKey(KyberAlgorithm.secretKey, (byte)0x00);
	}

	private void decapsulate(APDU apdu)
	{
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
		if (setEncapsulationLength == KyberAlgorithm.encapsulationLength) setEncapsulationLength = 0;
	}
}