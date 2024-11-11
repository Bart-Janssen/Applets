package applet.kyber;

import javacard.framework.*;
import javacard.security.*;

public class Kyber512 extends Applet
{
	private Keccak keccak = null;

	private short receivedPrivateKeyLength = 0;
	private short receivedPublicKeyLength = 0;
	private short receivedSecretKeyLength = 0;
	private short receivedEncapsulationLength = 0;
	private short setEncapsulationLength = 0;

	private KyberAlgorithm kyber = KyberAlgorithm.getInstance((byte)2);

	private Kyber512(byte[] parameters, short offset)
	{
		super.register(parameters, (short)(offset + 1), parameters[offset]);
	}

	public static void install(byte[] parameters, short offset, byte length)
	{
		new Kyber512(parameters, offset);
	}

	@Override
	public void process(APDU apdu) throws ISOException
	{
		byte[] apduBuffer = apdu.getBuffer();

		// ignore the applet select command dispatched to the process
		if (selectingApplet()) return;

		if (apduBuffer[ISO7816.OFFSET_CLA] == (byte)0x00)
		{
			switch (apduBuffer[ISO7816.OFFSET_INS])
			{
				case (byte)0x01: this.generateKyber512KeyPair(apdu); break;
				case (byte)0x02: this.encapsulate(apdu); break;
				case (byte)0x03: this.decapsulate(apdu); break;
				case (byte)0x04: this.obtainPrivateKey(apdu); break;
				case (byte)0x05: this.obtainPublicKey(apdu); break;
				case (byte)0x06: this.obtainSecretKey(apdu); break;
				case (byte)0x07: this.obtainEncapsulation(apdu); break;
				case (byte)0x08: this.setEncapsulation(apdu); break;
				case (byte)0x09: this.getFreeRAM(apdu); break;
				case (byte)0x10: this.clearSecret(apdu); break;
				default:
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
					break;
			}
		}
		else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	}

	public void clearSecret(APDU apdu)
	{
		for (byte i = 0; i < 32; i++)
		{
			KyberAlgorithm.getInstance((byte)2).secretKey[i] = (byte)0x00;
		}
	}

	public void getFreeRAM(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		byte[] ramUsageBuffer = new byte[2];
		short availableRAM = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
		ramUsageBuffer[0] = (byte)(availableRAM >> 8);
		ramUsageBuffer[1] = (byte)(availableRAM & 0xFF);

		Util.arrayCopyNonAtomic(ramUsageBuffer, (short)0x0000, buffer, (short)0x0000, (short)ramUsageBuffer.length);
		apdu.setOutgoingAndSend((short)0x0000, (short)ramUsageBuffer.length);
		return;
	}

	public void generateKyber512KeyPair(APDU apdu)
	{
		kyber.generateKeys(KyberParams.Kyber512SKBytes);
	}

	private void encapsulate(APDU apdu)
	{
		//temporarly disabled random for testing
		kyber.encapsulate();
	}

	private void decapsulate(APDU apdu)
	{
		//temporarly disabled random for testing
		kyber.decapsulate();
	}

	private void obtainSecretKey(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short p = (short)255;
		byte[] secretKey = KyberAlgorithm.getInstance((byte)2).secretKey;
		if ((short)(receivedSecretKeyLength+255) > secretKey.length)
		{
			p = (short)(secretKey.length-receivedSecretKeyLength);
		}
		Util.arrayCopyNonAtomic(secretKey, receivedSecretKeyLength, buffer, (short)0x0000, p);
		apdu.setOutgoingAndSend((short)0x0000, p);

		receivedSecretKeyLength+=(short)255;
		if (receivedSecretKeyLength < secretKey.length)
		{
			ISOException.throwIt((short)0x5000);
		}
		receivedSecretKeyLength=0;
	}

	private void obtainEncapsulation(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short p = (short)255;
		byte[] encapsulation = KyberAlgorithm.getInstance((byte)2).encapsulation;
		if ((short)(receivedEncapsulationLength+255) > encapsulation.length)
		{
			p = (short)(encapsulation.length-receivedEncapsulationLength);
		}
		Util.arrayCopyNonAtomic(encapsulation, receivedEncapsulationLength, buffer, (short)0x0000, p);
		apdu.setOutgoingAndSend((short)0x0000, p);

		receivedEncapsulationLength+=(short)255;
		if (receivedEncapsulationLength < encapsulation.length)
		{
			ISOException.throwIt((short)0x5000);
		}
		receivedEncapsulationLength=0;
	}

	private void setEncapsulation(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short dataLength = apdu.setIncomingAndReceive();
		Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, KyberAlgorithm.getInstance((byte)2).encapsulation, setEncapsulationLength, dataLength);
		setEncapsulationLength += dataLength;
		if (setEncapsulationLength == (short)800)
		{
			setEncapsulationLength = 0;
		}
	}

	private void obtainPrivateKey(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short p = (short)255;
		byte[] privateKey = KeyPair.getInstance((byte)2).privateKey;
		if ((short)(receivedPrivateKeyLength+255) > privateKey.length)
		{
			p = (short)(privateKey.length-receivedPrivateKeyLength);
		}
		Util.arrayCopyNonAtomic(privateKey, receivedPrivateKeyLength, buffer, (short)0x0000, p);
		apdu.setOutgoingAndSend((short)0x0000, p);

		receivedPrivateKeyLength+=(short)255;
		if (receivedPrivateKeyLength < privateKey.length)
		{
			ISOException.throwIt((short)0x5000);
		}
		receivedPrivateKeyLength=0;
	}

	private void obtainPublicKey(APDU apdu)
	{
		byte[] buffer = apdu.getBuffer();
		short p = (short)255;
		byte[] publicKey = KeyPair.getInstance((byte)2).publicKey;
		if ((short)(receivedPublicKeyLength+255) > publicKey.length)
		{
			p = (short)(publicKey.length-receivedPublicKeyLength);
		}
		Util.arrayCopyNonAtomic(publicKey, receivedPublicKeyLength, buffer, (short)0x0000, p);
		apdu.setOutgoingAndSend((short)0x0000, p);

		receivedPublicKeyLength+=(short)255;
		if (receivedPublicKeyLength < publicKey.length)
		{
			ISOException.throwIt((short)0x5000);
		}
		receivedPublicKeyLength=0;
	}
}