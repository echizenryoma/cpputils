#include <openssl/crypto.h>
#include "test/des_test.h"

int main(int argc, char** argv)
{
	DES_Test();
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
