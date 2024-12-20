# Applets for PQC project
This repository is part of the
'Post-Quantum Cryptography on smart cards' by Bart Janssen at the
Open University, faculty of Management, Science and Technology.
Master Software Engineering.

This repository contains applets for using PQC on a smart card. The
applet build process is used on a Windows environment. The 'build.xml'
file contains the building possibilities. The jckit
versions used within this project are hidden. If someone wishes to
use the build process to build the applets, the jckit and targetsdk
must be defined to match the smart card used.

## Applets
The repository contains three important applets for the PQC project.

### Keystore applet
The keystore applet is used to store a PQC key on a smart card.
Its usage is considered as a possibility to use PQC on a smart card
but is less secure since the private key can be extracted.

### Ram applet
The ram applet is used to identify the available smart card RAM and 
EEPROM. Functions for benchmarking can be used to find out how fast
the smart card is.

### Kyber applet
The Kyber applet contains the full Kyber algorithm supporting 
Kyber-512, Kyber-768 and Kyber-1024. Several functions can be used:
- Generate Kyber-512 key pair (APDU: 00 00 05 12)
- Generate Kyber-768 key pair (APDU: 00 00 07 68)
- Generate Kyber-1024 key pair (APDU: 00 00 10 24)
- Encapsulate (APDU: 00 00 00 01)
- Decapsulate (APDU: 00 00 00 02)
- Set encapsulation for decapsulating (APDU: 00 00 00 03 <255 hex bytes of encapsulation>); This command can be incrementally repeated
- Obtain public key (APDU: 00 00 00 04); This command can be called repeatedly. Response code 0x5000 indicates more data is available, 0x9000 indicates done
- Obtain encapsulation (APDU: 00 00 00 05); This command can be called repeatedly. Response code 0x5000 indicates more data is available, 0x9000 indicates done
- Use shared secret for AES CBC encryption (APDU: 00 00 00 06)
- Use shared secret for AES CBC decryption (APDU: 00 00 00 07)

Some functions are default disabled due to security reasons, but 
can be enabled if required. <span style="color: red;">Use the following functions ONLY
for development/testing purposes as enabling these functions 
exposes sensitive data and renders the card critically insecure!
Use these functions at your own risk and ensure they are disabled 
in production!</span>
- Obtain private key (APDU: 00 00 10 01); This command can be called repeatedly. Response code 0x5000 indicates more data is available, 0x9000 indicates done
- Obtain shared secret (APDU: 00 00 10 02)
- Clear secret (APDU: 00 00 10 03)
- Enable randomness (APDU: 00 00 10 04); Randomness is enabled by default
- Disable randomness (APDU: 00 00 10 05); Randomness is enabled by default

# Benchmarks of the Kyber applet
The smart card used for benchmarking is an [Infineon SLC37GDL512](https://www.infineon.com/cms/en/product/security-smart-card-solutions/security-controllers/contactless-and-dual-interface-security-controllers/slc37gdaxxx/).
The usable memory within an applet are:
- 3,793 bytes RAM
- 149,829 bytes EEPROM

The benchmarks are as following:

|                | RAM consumption | EEPROM consumption | Duration Kyber-512 | Duration Kyber-768 | Duration Kyber-1024 |
|----------------|-----------------|--------------------|--------------------|--------------------|---------------------|
| Key generation | 3,654 B         | 60,328 B           | 2.33 min           | 4.06 min           | 6.56 min            |
| Encapsulation  | 3,654 B         | 60,328 B           | 3.16 min           | 5.13 min           | 8.13 min            |
| Decapsulation  | 3,654 B         | 60,328 B           | 3.61 min           | 5.88 min           | 8.75 min            |

If someone wishes to use this code with their own smart card, the memory 
consumption will most likely be different Array initializations within the 
'KyberAlgorithm.java' file should be changed accordingly, example;
- To change from EEPROM to RAM: change `new short[384];` to `JCSystem.makeTransientShortArray((short)384, JCSystem.CLEAR_ON_DESELECT);`.
- To change from RAM to EEPROM: change `JCSystem.makeTransientByteArray((short)384, JCSystem.CLEAR_ON_DESELECT);` to `new byte[384];`.

Changing arrays will have changes on the benchmarks. The smart card used to 
create the benchmark could unfortunately not use RAM for all operations due 
to hardware limitations, resulting in a slower execution speed.

# Further Information
Information about CRYSTALS-Kyber can be found [here](https://pq-crystals.org/kyber/index.shtml).