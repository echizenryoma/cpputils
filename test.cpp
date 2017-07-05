#include <openssl/crypto.h>
#include "test/des3_test.h"

int main(int argc, char** argv)
{
	DES3_Test();
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
