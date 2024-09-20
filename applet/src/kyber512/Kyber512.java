package applet.kyber;

import javacard.framework.*;
import javacard.security.CryptoException;

public class Kyber512 extends Applet
{
	private Kyber512(byte[] parameters, short offset)
	{
		super.register(parameters, (short) (offset + 1), parameters[offset]);
	}

	public static void install(byte[] parameters, short offset, byte length)
	{
		new Kyber512(parameters, offset);
	}

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

		if (true) return;

		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	}
}