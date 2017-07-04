#include <openssl/crypto.h>
#include "test/aes_test.h"

int main(int argc, char** argv)
{
	AES_Test();
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
