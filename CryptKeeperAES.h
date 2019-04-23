#ifndef CrytpKeeperAES_h_included
#define CrytpKeeperAES_h_included

#include "CryptKeeper.h"
#include "aes256.h"

using namespace std;

/* Example of a file header:

0000000: 4372 7970 744b 6565 7065 7220 322e 3120  CryptKeeper 1.1 
0000010: 3230 3031 3820 3164 3830 6637 2046 3443  20018 1d80f7 F4C
0000020: 4535 3531 3931 3344 4343 4344 4435 4631  E551913DCCCDD5F1
0000030: 4230 3244 3538 3931 4637 3246 3500 0000  B02D5891F72F5...
0000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................

*/

class CryptKeeperAES : public CryptKeeper
{
protected:
	aes256_context AESContext;

	virtual void DecryptBlock(vector<unsigned char> &data, int offset, int counter);
	virtual void EncryptBlock(vector<unsigned char> &data, int offset, int counter);
	virtual string GetKCV();

public:
	CryptKeeperAES(const char *key);
	~CryptKeeperAES();
};

#endif
