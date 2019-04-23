#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <assert.h>

#include <vector>
using namespace std;

#include "CryptKeeper1.h"
#include "DES.h"
#include "misc.h"

// accepts the file encryption key in the clear; it's the caller's responsibility to 
//  handle providing the key from secure storage
CryptKeeper1::CryptKeeper1(const char *enckey) : CryptKeeper2(enckey)
{
	// for backwards compatibility with CryptKeeper 1.0 utility (DES, ECB mode, no nonce)
	blockSize = 8;
	headerSize = 64;
	fileVersion = "1.0";
}

CryptKeeper1::~CryptKeeper1()
{
}

void CryptKeeper1::EncryptBlock(vector<unsigned char> &data, int offset, int counter)
{
	assert(offset + blockSize <= data.size());

	// encrypt data
	unsigned char output[blockSize];
	encryptECB(&key[0], key.size(), &data[offset], blockSize, output);
	memcpy(&data[offset], output, blockSize);

	return;
}

void CryptKeeper1::DecryptBlock(vector<unsigned char> &data, int offset, int counter)
{
	assert(offset + blockSize <= data.size());

	// decrypt data
	unsigned char output[blockSize];
	decryptECB(&key[0], key.size(), &data[offset], blockSize, output);
	memcpy(&data[offset], output, blockSize);

	return;
}

string CryptKeeper1::GetKCV()
{
	unsigned char zeros[64] = {0};
	unsigned char output[64] = {0};

	encryptECB(&key[0], key.size(), zeros, blockSize, (unsigned char *)output);

	char kcv[16];
	sprintf(kcv, "%06x", (int)output[0] << 16 | (int)output[1] << 8 | (int)output[2]);

	return string(kcv);
}

