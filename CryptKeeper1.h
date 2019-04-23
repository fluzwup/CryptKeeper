#ifndef CrytpKeeper1_h_included
#define CrytpKeeper1_h_included

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <vector>
#include <string>
using namespace std;

#include <CryptKeeper2.h>

/* Example of a file header:

0000000: 4372 7970 744b 6565 7065 7220 322e 3020  CryptKeeper 2.0 
0000010: 3230 3031 3820 3334 6532 6637 2036 3244  20018 34e2f7 62D
0000020: 3837 3132 3646 3431 3139 4435 4300 0000  87126F4119D5C...
0000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................

*/

class CryptKeeper1 : public CryptKeeper2
{
protected:
	// we want these virtual so that derived classes will call the right encryption function
	virtual void DecryptBlock(vector<unsigned char> &data, int offset, int counter);
	virtual void EncryptBlock(vector<unsigned char> &data, int offset, int counter);
	virtual string GetKCV();

public:
	CryptKeeper1(const char *key);
	~CryptKeeper1();
};

#endif
