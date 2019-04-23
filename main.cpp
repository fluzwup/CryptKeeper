#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <vector>
using namespace std;

#include "CryptKeeperAES.h"
#include "CryptKeeperDES.h"

int TestDES()
{
	// Init class with a DES key in the clear (single, double, or triple length, in hex)
	CryptKeeperDES cc("123456789ABCDEF00000000000000000123456789ABCDEF0");

	// buffer to contain data we're reading
	unsigned char temp[256];

	// set up 32k of sequential numbers to write from, this allows random data checks
	//  at any given offset
	unsigned char buffer[32768];
	for(int i = 0; i < 32768; ++i)
		buffer[i] = (unsigned char)(i % 256);

	// start fresh
	unlink("test.dat");

	printf("Generating inital file\n");
	// test writing in non-block length sections
	cc.Open("test.dat", "w+");
	for(int i = 0; i < 16536; i += 13)
	{
		cc.Write((void *)&buffer[i], 13);
	}
	cc.Close();

	printf("Testing reading of file\n");
	// test reading across block boundaries
	cc.Open("test.dat", "r");
	for(int i = 0; i < 16000; i += 1127)
	{
		cc.Seek(i, SEEK_SET);
		cc.Read(temp, 64);
		for(int j = 0; j < 64; ++j)
		{
			if(temp[j] != buffer[j + i]) printf("Read error at %i\n", j + i);
			break;
		}
	}

	printf("Testing writing to file\n");
	// test writing odd lengths at various spots
	cc.Open("test.dat", "r+");
	for(int i = 1; i < 16000; i += 73)
	{
		cc.Seek(i, SEEK_SET);
		cc.Write(&buffer[i], 19);
	}
	cc.Close();

	printf("Testing read\n");
	// test reading across blocks
	cc.Open("test.dat", "r");
	for(int i = 0; i < 16000; i += 1127)
	{
		cc.Seek(i, SEEK_SET);
		cc.Read(temp, 64);
		for(int j = 0; j < 64; ++j)
		{
			if(temp[j] != (j + i) % 256) printf("Read error at %i\n", j + i);
			break;
		}
	}
	cc.Close();

	printf("Appending to file\n");
	// open to append
	cc.Open("test.dat", "a");
	for(int i = cc.Tell(); i < 20000; i += 29)
	{
		cc.Write(&buffer[i], 29);
	}
	cc.Close();
	
	printf("Testing read\n");
	// check reading across the append boundary
	cc.Open("test.dat", "r");
	for(int i = 1600; i < 19000; i += 256)
	{
		cc.Seek(i, SEEK_SET);
		cc.Read(temp, 256);
		for(int j = 0; j < 256; ++j)
		{
			if(temp[j] != (j + i) % 256) printf("Read error at %i\n", j + i);
			break;
		}
	}
	cc.Close();

	return 0;
}

int TestAES()
{
	// Init class with a DES key in the clear (single, double, or triple length, in hex)
	CryptKeeperAES cc("123456789ABCDEF00000000000000000123456789ABCDEF0");

	// buffer to contain data we're reading
	unsigned char temp[256];

	// set up 32k of sequential numbers to write from, this allows random data checks
	//  at any given offset
	unsigned char buffer[32768];
	for(int i = 0; i < 32768; ++i)
		buffer[i] = (unsigned char)(i % 256);

	// start fresh
	unlink("test.dat");

	printf("Generating inital file\n");
	// test writing in non-block length sections
	cc.Open("test.dat", "w+");
	for(int i = 0; i < 16536; i += 13)
	{
		cc.Write((void *)&buffer[i], 13);
	}
	cc.Close();

	printf("Testing reading of file\n");
	// test reading across block boundaries
	cc.Open("test.dat", "r");
	for(int i = 0; i < 16000; i += 1127)
	{
		cc.Seek(i, SEEK_SET);
		cc.Read(temp, 64);
		for(int j = 0; j < 64; ++j)
		{
			if(temp[j] != buffer[j + i]) printf("Read error at %i\n", j + i);
			break;
		}
	}

	printf("Testing writing to file\n");
	// test writing odd lengths at various spots
	cc.Open("test.dat", "r+");
	for(int i = 0; i < 16000; i += 73)
	{
		cc.Seek(i, SEEK_SET);
		cc.Write(&buffer[i], 19);
	}
	cc.Close();

	printf("Testing read\n");
	// test reading across blocks
	cc.Open("test.dat", "r");
	for(int i = 0; i < 16000; i += 1127)
	{
		cc.Seek(i, SEEK_SET);
		cc.Read(temp, 64);
		for(int j = 0; j < 64; ++j)
		{
			if(temp[j] != (j + i) % 256) printf("Read error at %i\n", j + i);
			break;
		}
	}
	cc.Close();

	printf("Appending to file\n");
	// open to append
	cc.Open("test.dat", "a");
	for(int i = cc.Tell(); i < 20000; i += 29)
	{
		cc.Write(&buffer[i], 29);
	}
	cc.Close();
	
	printf("Testing read\n");
	// check reading across the append boundary
	cc.Open("test.dat", "r");
	for(int i = 1600; i < 19000; i += 256)
	{
		cc.Seek(i, SEEK_SET);
		cc.Read(temp, 256);
		for(int j = 0; j < 256; ++j)
		{
			if(temp[j] != (j + i) % 256) printf("Read error at %i\n", j + i);
			break;
		}
	}
	cc.Close();

	return 0;
}

#include "misc.h"

void ValidateAESImplementation()
{
	/*
		Validation of AES algorithm.  This uses test cases from The Advanced Encryption Standard Algorithm Validation Suite (AESAVS) November 15, 2002.

		https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf

		Test data from Table C.3
	*/
	vector<string> keys;
	vector<string> answers;

	keys.push_back("c47b0294dbbbee0fec4757f22ffeee3587ca4730c3d33b691df38bab076bc558");
	answers.push_back("46f2fb342d6f0ab477476fc501242c5f");
	keys.push_back("28d46cffa158533194214a91e712fc2b45b518076675affd910edeca5f41ac64");
	answers.push_back("4bf3b0a69aeb6657794f2901b1440ad4");
	keys.push_back("c1cc358b449909a19436cfbb3f852ef8bcb5ed12ac7058325f56e6099aab1a1c");
	answers.push_back("352065272169abf9856843927d0674fd");
	keys.push_back("984ca75f4ee8d706f46c2d98c0bf4a45f5b00d791c2dfeb191b5ed8e420fd627");
	answers.push_back("4307456a9e67813b452e15fa8fffe398");
	keys.push_back("b43d08a447ac8609baadae4ff12918b9f68fc1653f1269222f123981ded7a92f");
	answers.push_back("4663446607354989477a5c6f0f007ef4");
	keys.push_back("1d85a181b54cde51f0e098095b2962fdc93b51fe9b88602b3f54130bf76a5bd9");
	answers.push_back("531c2c38344578b84d50b3c917bbb6e1");
	keys.push_back("dc0eba1f2232a7879ded34ed8428eeb8769b056bbaf8ad77cb65c3541430b4cf");
	answers.push_back("fc6aec906323480005c58e7e1ab004ad");
	keys.push_back("f8be9ba615c5a952cabbca24f68f8593039624d524c816acda2c9183bd917cb9");
	answers.push_back("a3944b95ca0b52043584ef02151926a8");
	keys.push_back("797f8b3d176dac5b7e34a2d539c4ef367a16f8635f6264737591c5c07bf57a3e");
	answers.push_back("a74289fe73a4c123ca189ea1e1b49ad5");
	keys.push_back("6838d40caf927749c13f0329d331f448e202c73ef52c5f73a37ca635d4c47707");
	answers.push_back("b91d4ea4488644b56cf0812fa7fcf5fc");
	keys.push_back("ccd1bc3c659cd3c59bc437484e3c5c724441da8d6e90ce556cd57d0752663bbc");
	answers.push_back("304f81ab61a80c2e743b94d5002a126b");
	keys.push_back("13428b5e4c005e0636dd338405d173ab135dec2a25c22c5df0722d69dcc43887");
	answers.push_back("649a71545378c783e368c9ade7114f6c");
	keys.push_back("07eb03a08d291d1b07408bf3512ab40c91097ac77461aad4bb859647f74f00ee");
	answers.push_back("47cb030da2ab051dfc6c4bf6910d12bb");
	keys.push_back("90143ae20cd78c5d8ebdd6cb9dc1762427a96c78c639bccc41a61424564eafe1");
	answers.push_back("798c7c005dee432b2c8ea5dfa381ecc3");
	keys.push_back("b7a5794d52737475d53d5a377200849be0260a67a2b22ced8bbef12882270d07");
	answers.push_back("637c31dc2591a07636f646b72daabbe7");
	keys.push_back("fca02f3d5011cfc5c1e23165d413a049d4526a991827424d896fe3435e0bf68e");
	answers.push_back("179a49c712154bbffbe6e7a84a18e220");

	aes256_context AESContext;

	for(int i = 0; i < keys.size(); ++i)
	{
		printf("AES 256 encryption algorithm validation, test case %i\n", i);
		unsigned char block[16];
		unsigned char ref[16];
		unsigned char key[32];
		int len;

		// set up input of all zeros
		memset(block, 0, 16);

		// convert key to binary
		len = 32;
		Hex2Bin(keys[i].c_str(), key, len);

		// convert reference output to binary
		len = 16;
		Hex2Bin(answers[i].c_str(), ref, len);

		// set up key
		aes256_init(&AESContext, key);

		// encrypt zeros
		aes256_encrypt_ecb(&AESContext, block);

		// check answer
		for(int j = 0; j < 16; ++j)
		{
			if(ref[i] != block[i])
				printf("Error at %i byte %i on encryption!\n", i, j);
		}

		// decrypt back to zeros
		aes256_decrypt_ecb(&AESContext, block);

		// check answer
		for(int j = 0; j < 16; ++j)
		{
			if(0x00 != block[i])
				printf("Error at %i byte %i on decryption!\n", i, j);
		}

		aes256_done(&AESContext);
	}
}

int main(int argc, char **argv)
{
	printf("Testing DES version.\n");
	TestDES();

	printf("Testing AES version.\n");
	TestAES();

	return 0;
}
