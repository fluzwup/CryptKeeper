#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <assert.h>

#include <vector>
using namespace std;

#include "CryptKeeperAES.h"
#include "misc.h"


// accepts the file encryption key in the clear; it's the caller's responsibility to 
//  handle providing the key from secure storage
CryptKeeperAES::CryptKeeperAES(const char *enckey) : CryptKeeper(enckey)
{
	// set up larger AES block size
	blockSize = 16;
	// extend file header to handle longer nonce
	headerSize = 80;
	// change version
	fileVersion = "1.1";

	aes256_init(&AESContext, &key[0]);
}

CryptKeeperAES::~CryptKeeperAES()
{
	aes256_done(&AESContext);
}

void CryptKeeperAES::EncryptBlock(vector<unsigned char> &data, int offset, int counter)
{
	assert(offset + blockSize <= data.size());

	// add block counter to nonce
	vector<unsigned char> modifiedNonce;
	ModifyNonce(counter, modifiedNonce);

	// XOR data with nonce
	for(int i = 0; i < blockSize; ++i)
	{
		data[offset + i] = data[offset + i] ^ modifiedNonce[i];
	}

	// encrypt data
	aes256_encrypt_ecb(&AESContext, &data[offset]);

	return;
}

void CryptKeeperAES::DecryptBlock(vector<unsigned char> &data, int offset, int counter)
{
	assert(offset + blockSize <= data.size());

	// add block counter to nonce
	vector<unsigned char> modifiedNonce;
	ModifyNonce(counter, modifiedNonce);
	
	// decrypt data
	aes256_decrypt_ecb(&AESContext, &data[offset]);

	// XOR with nonce
	for(int i = 0; i < blockSize; ++i)
	{
		data[offset + i] = data[offset + i] ^ modifiedNonce[i];
	}

	return;
}

string CryptKeeperAES::GetKCV()
{
	unsigned char zeros[64] = {0};

	aes256_encrypt_ecb(&AESContext, zeros);

	char kcv[16];
	sprintf(kcv, "%06x", (int)zeros[0] << 16 | (int)zeros[1] << 8 | (int)zeros[2]);

	return string(kcv);
}

