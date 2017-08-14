#include <openssl/crypto.h>
#include "rsa_test.h"


int main(int argc, char** argv)
{
	RSA_Test();
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
