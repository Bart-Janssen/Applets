package applet.kyber;

import javacard.framework.*;
import javacard.security.*;

public class Kyber512 extends Applet
{
	private Sha3 sha3 = null;
	private byte RAMinput[] = null;

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
			switch ( apduBuffer[ISO7816.OFFSET_INS] )
			{
				case (byte)0x01:
					this.sha3Digest(apdu, Sha3.ALG_SHA3_512); break;
				default:
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
					break;
			}
		}
		else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	}

	public void sha3Digest(APDU apdu, byte algorithm)
	{
		this.sha3 = Sha3.getInstance(algorithm);
		byte[] data = apdu.getBuffer();
		short length = apdu.setIncomingAndReceive();
		RAMinput = JCSystem.makeTransientByteArray((short)0xFF, JCSystem.CLEAR_ON_DESELECT);
		Util.arrayCopyNonAtomic(data, ISO7816.OFFSET_CDATA, RAMinput, (short)0, length);
		short hash = this.sha3.doFinal(RAMinput, (short)0, length, data, (short)0);
		apdu.setOutgoingAndSend((short)0, hash);
	}
}