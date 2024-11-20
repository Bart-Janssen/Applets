package applet.ramtest;

import javacard.framework.*;
import javacard.security.CryptoException;

public class RAMtest extends Applet
{
	private RAMtest(byte[] parameters, short offset)
	{
		super.register(parameters, (short) (offset + 1), parameters[offset]);
	}

	public static void install(byte[] parameters, short offset, byte length)
	{
		new RAMtest(parameters, offset);
	}

	private byte[] ramUsageBuffer = new byte[2];

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
		if (buffer[ISO7816.OFFSET_CLA] != (byte)0x00 || buffer[ISO7816.OFFSET_INS] != (byte)0x00) ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);

		//Get free RAM
		if (P1 == (byte)0x00 && P2 == (byte)0xA0)
		{
			//MEMORY_TYPE_PERSISTENT
			//MEMORY_TYPE_TRANSIENT_DESELECT
			//MEMORY_TYPE_TRANSIENT_RESET
			short availableRAM = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
			ramUsageBuffer[0] = (byte)(availableRAM >> 8);
			ramUsageBuffer[1] = (byte)(availableRAM & 0xFF);

			Util.arrayCopyNonAtomic(ramUsageBuffer, (short)0x0000, buffer, (short)0x0000, (short)ramUsageBuffer.length);
			apdu.setOutgoingAndSend((short)0x0000, (short)ramUsageBuffer.length);
			return;
		}
		//Create RAM array
		if (P1 == (byte)0x00 && P2 == (byte)0xA1)
		{
			//CLEAR_ON_RESET = persistant on select and card removed
			//CLEAR_ON_DESELECT = persistant on select and card removed
			//Array of size 100 removes exacaly 100 bytes from free RAM

			byte[] ramArray = JCSystem.makeTransientByteArray((short)1000, JCSystem.CLEAR_ON_DESELECT);
			return;
		}
		//Create + fill RAM array
		if (P1 == (byte)0x00 && P2 == (byte)0xA2)
		{
			//CLEAR_ON_RESET = persistant on select and card removed
			//CLEAR_ON_DESELECT = persistant on select and card removed
			//Array of size 100 removes exacaly 100 bytes from free RAM
			byte[] ramArray = JCSystem.makeTransientByteArray((short)1000, JCSystem.CLEAR_ON_DESELECT);
			for (short i = 0x00;i < (short)1000;i++)
			{
				ramArray[i] = (byte)0xFF;
			}
			return;
		}

		//Get free EEPROM
		if (P1 == (byte)0x00 && P2 == (byte)0xB0)
		{
			short availableRAM = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT);
			ramUsageBuffer[0] = (byte)(availableRAM >> 8);
			ramUsageBuffer[1] = (byte)(availableRAM & 0xFF);

			Util.arrayCopyNonAtomic(ramUsageBuffer, (short)0x0000, buffer, (short)0x0000, (short)ramUsageBuffer.length);
			apdu.setOutgoingAndSend((short)0x0000, (short)ramUsageBuffer.length);
			return;
		}
		//Create EEPROM array
		if (P1 == (byte)0x00 && P2 == (byte)0xB1)
		{
			//Creating 100 byte array removes 238 bytes from EEPROM
			//Creating 1 byte array removes 34 byte from EEPROM
			//Creating 5000 short array uses 10011 bytes (1 short = 2 bytes + overhead)
			short[] eepromArray = new short[(short)5000];
			return;
		}
		//Create + fill EEPROM array
		if (P1 == (byte)0x00 && P2 == (byte)0xB2)
		{
			short[] eepromArray = new short[(short)5000];//5FFF = OK, 6FFF NO
			for (short i = 0x00;i < (short)5000;i++)
			{
				eepromArray[i] = 0xFF;
			}
			return;
		}
		ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
	}
}