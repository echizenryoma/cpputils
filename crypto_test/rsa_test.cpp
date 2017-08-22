include "pch.h"
#include "../crypto/rsa.h"

TEST(RSA, pubkey)
{
	std::ostringstream sout;
	sout << "-----BEGIN PUBLIC KEY-----\n"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCupklvg4M62TpvbbISD8MrEb1h\n" <<
		"a2jW0bo4JshAUguKfWvc5w3B+59QmB4u6DANEemkmPBCVqgNACoM63L8q4Tl3WJo\n" <<
		"E1EQ735qaV2eRjweDroLtgLfVRGSzlZnajLFwhRqKO6/fId3J0kBLCVdZINfQbns\n" <<
		"DsqD6Wjyqf0z7DiWkQIDAQAB\n" <<
		"-----END PUBLIC KEY-----";
	string key_str = sout.str();
	RSA::pubkey(key_str);
}