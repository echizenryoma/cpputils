#include "pch.h"

#include "../crypto/pbkdf2.h"
using crypto::mac::PBEwithHmac;

#include "../crypto/hex.h"
using crypto::encode::Hex;

/**
* \brief PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) 
* Test Vectors
* \sa <A HREF="https://www.ietf.org/rfc/rfc6070.txt"></A>
* for additional details.
*/
TEST(PBEwithHmac, HmacSHA1)
{
	string P;
	string S;
	uint32_t c;
	size_t dkLen;
	vector<byte> DK;

	P = "password";
	S = "salt";
	c = 1;
	dkLen = 20;
	DK = PBEwithHmac::derived(vector<byte>(P.begin(), P.end()), vector<byte>(S.begin(), S.end()), c, PBEwithHmac::HmacScheme::HmacSHA1, dkLen);
	EXPECT_EQ(Hex::encode(DK), "0C60C80F961F0E71F3A9B524AF6012062FE037A6");

	P = "password";
	S = "salt";
	c = 2;
	dkLen = 20;
	DK = PBEwithHmac::derived(vector<byte>(P.begin(), P.end()), vector<byte>(S.begin(), S.end()), c, PBEwithHmac::HmacScheme::HmacSHA1, dkLen);
	EXPECT_EQ(Hex::encode(DK), "EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957");

	P = "password";
	S = "salt";
	c = 4096;
	dkLen = 20;
	DK = PBEwithHmac::derived(vector<byte>(P.begin(), P.end()), vector<byte>(S.begin(), S.end()), c, PBEwithHmac::HmacScheme::HmacSHA1, dkLen);
	EXPECT_EQ(Hex::encode(DK), "4B007901B765489ABEAD49D926F721D065A429C1");

//	P = "password";
//	S = "salt";
//	c = 16777216;
//	dkLen = 20;
//	DK = PBEwithHmac::derived(vector<byte>(P.begin(), P.end()), vector<byte>(S.begin(), S.end()), c, PBEwithHmac::HmacScheme::HmacSHA1, dkLen);
//	EXPECT_EQ(Hex::encode(DK), "EEFE3D61CD4DA4E4E9945B3D6BA2158C2634E984");

	P = "passwordPASSWORDpassword";
	S = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
	c = 4096;
	dkLen = 25;
	DK = PBEwithHmac::derived(vector<byte>(P.begin(), P.end()), vector<byte>(S.begin(), S.end()), c, PBEwithHmac::HmacScheme::HmacSHA1, dkLen);
	EXPECT_EQ(Hex::encode(DK), "3D2EEC4FE41C849B80C8D83662C0E44A8B291A964CF2F07038");


	char P_cstr[] = "pass\0word";
	size_t P_cstr_size = 9;
	char S_cstr[] = "sa\0lt";
	size_t S_cstr_size = 5;
	c = 4096;
	dkLen = 16;
	DK = PBEwithHmac::derived(vector<byte>(&P_cstr[0], &P_cstr[0] + P_cstr_size), vector<byte>(&S_cstr[0], &S_cstr[0] + S_cstr_size), c, PBEwithHmac::HmacScheme::HmacSHA1, dkLen);
	EXPECT_EQ(Hex::encode(DK), "56FA6AA75548099DCC37D7F03425E0C3");
}
