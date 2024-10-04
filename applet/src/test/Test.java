package applet.test;

import javacard.framework.*;
import javacard.security.*;

import java.util.Random;

public class Test extends Applet
{

	private Test(byte[] parameters, short offset)
	{
		super.register(parameters, (short)(offset + 1), parameters[offset]);
	}

	public static void install(byte[] parameters, short offset, byte length)
	{
		new Test(parameters, offset);
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
				case (byte)0x00:
					this.random(apdu); break;
				default:
					ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
					break;
			}
		}
		else ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
	}

	public void random(APDU apdu)
	{
		byte[] data = apdu.getBuffer();
		byte[] rnd = JCSystem.makeTransientByteArray((short)32, JCSystem.CLEAR_ON_DESELECT);
		RandomData.OneShot random = RandomData.OneShot.open(RandomData.ALG_TRNG);
		random.nextBytes(rnd, (short)0, (short)32);
		Util.arrayCopyNonAtomic(rnd, (short)0, data, (short)0, (short)32);
		apdu.setOutgoingAndSend((short)0, (short)32);
	}
}