#include "pch.h"

#include "../crypto/rc4.h"
using crypto::RC4;

#include "../crypto/base64.h"
using crypto::encode::Base64;

TEST(RC4, RC4_ECB_NoPadding)
{
	vector<byte> key = Base64::decode("2FI6QTt6bO/Uzs7jwsfNyQ==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = RC4::encrypt(plain, key);
	EXPECT_EQ("b7DKnU85w7p0+2o=", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = RC4::encrypt(plain, key);
	EXPECT_EQ("w3bzLO0w50EKLa3fR0+1Jylbc7Q=", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = RC4::encrypt(plain, key);
	EXPECT_EQ("+PZv2v++fit5hYAsT2ou/GFd7sOo1AazJZhAgyA/zE4=", Base64::encode(encrypt));
}