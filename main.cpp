#include "test/rsa_test.h"
using namespace std;

int main(int argc, char** argv)
{
	RSA_Test();

	CRYPTO_cleanup_all_ex_data();
	return 0;
}
