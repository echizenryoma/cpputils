#include "pch.h"
#include "../crypto/nopadding.h"
#include "../crypto/base64.h"
#include <cryptopp/argnames.h>

TEST(Padding, NoPadding)
{
	vector<byte> message = Base64::decode("wE89");
	NoPadding(16).Pad(message);
	EXPECT_EQ("AAAAAAAAAAAAAAAAAMBPPQ==", Base64::encode(message));

	message = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	NoPadding(16).Pad(message);
	EXPECT_EQ("tQJT13nQjQeKScukjRt11gAAAAAAAAAAAAAAAFT3DjY=", Base64::encode(message));
}