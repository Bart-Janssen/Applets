package applet.keystore;

import javacard.framework.*;
import javacard.security.CryptoException;

public class KeyStore extends Applet
{
	private KeyStore(byte[] parameters, short offset)
	{
		super.register(parameters, (short) (offset + 1), parameters[offset]);
	}

	public static void install(byte[] parameters, short offset, byte length)
	{
		new KeyStore(parameters, offset);
	}

	byte[] privateKey;
	private short receivedPrivateKeyLength = 0;

	@Override
	public void process(APDU apdu) throws ISOException
	{
		byte[] buffer = apdu.getBuffer();
		byte CLA = buffer[ISO7816.OFFSET_CLA];
		byte INS = buffer[ISO7816.OFFSET_INS];
		byte P1 = buffer[ISO7816.OFFSET_P1];
		byte P2 = buffer[ISO7816.OFFSET_P2];

		if ((CLA == (byte)0x00) && (INS == (byte)0xA4) && (P1 == (byte)0x04) && (P2 == (byte)0x00)) return; //Select, return 0x9000

		//Force CLA and INS to be 0x00, 0x00
		if (CLA != (byte)0x00 || INS != (byte)0x00 || P1 != (byte)0x00) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

		//Set private key size
		if (P2 == (byte)0x00)
		{
			this.receivedPrivateKeyLength = 0;
			byte[] privateKeySize = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, privateKeySize, (short)0x0000, (short)0x0002);
			short size = (short)(((privateKeySize[0] << 8)) + (privateKeySize[1] & 0xFF));
			this.privateKey = new byte[size];
			return;
		}

		//Store private key
		if (P2 == (byte)0x01)
		{
			short dataLength = (short)apdu.setIncomingAndReceive();
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, privateKey, receivedPrivateKeyLength, dataLength);
			receivedPrivateKeyLength += dataLength;
			if (receivedPrivateKeyLength == (short)this.privateKey.length)
			{
				receivedPrivateKeyLength = 0;
			}
			return;
		}

		//Obtain private key
		if (P2 == (byte)0x02)
		{
			short p = (short)255;
			if ((short)(receivedPrivateKeyLength+255) > this.privateKey.length)
			{
				p = (short)(this.privateKey.length-receivedPrivateKeyLength);
			}
			Util.arrayCopyNonAtomic(this.privateKey, receivedPrivateKeyLength, buffer, (short)0x0000, p);
			apdu.setOutgoingAndSend((short)0x0000, p);

			receivedPrivateKeyLength+=(short)255;
			if (receivedPrivateKeyLength < this.privateKey.length)
			{
				ISOException.throwIt((short)0x5000);
			}
			receivedPrivateKeyLength=0;
			return;
		}

		//Check private key size
		if (P2 == (byte)0x03)
		{
			byte[] privateKeySize = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);
			Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, privateKeySize, (short)0x0000, (short)0x0002);
			short size = (short)(((privateKeySize[0] << 8)) + (privateKeySize[1] & 0xFF));
			if (this.privateKey.length == size) return;
			ISOException.throwIt((short)0x6389);
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	}
}