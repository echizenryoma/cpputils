#include "pch.h"

#include "../crypto/aes.h"
using crypto::Aes;

#include "../crypto/base64.h"
using crypto::encode::Base64;

TEST(Aes, AES_128_CBC_PKCS5Padding)
{
	vector<byte> key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("1u9HjUFAEFOQeiP361vzgA==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("PSUzyhLaY18amGtyoIm9qAbmOzTnOApDsqXZa8fyj2E=", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("raQhAYQHP/MQyew2DfEIZa9kOncLtCktq+uFjNnccj7yMcoVlFpPIqcosTAOBPZz", Base64::encode(encrypt));
}

TEST(Aes, AES_128_CFB_PKCS5Padding)
{
	vector<byte> key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("ntzGj2yhERTULzjEogILLw==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("Mhr/Ps6oNe+q+f9lKhx7/HGbtg2CdG8TXk1y5qeWv/w=", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("CZpjyNwmrIXZUdKWIjngJ5AIiVuFUAXhInXitkDzyJVlVDlcvZqNiB7n++UJMDnK", Base64::encode(encrypt));
}

TEST(Aes, AES_128_CTR_NoPadding)
{
	vector<byte> key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
	EXPECT_EQ("ntzGj2yhERTULzg=", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
	EXPECT_EQ("Mhr/Ps6oNe+q+f9lKhx7/A1xYTI=", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
	EXPECT_EQ("CZpjyNwmrIXZUdKWIjngJ0V3/EWJnVTPc7BZNP9T4FU=", Base64::encode(encrypt));
}

TEST(Aes, AES_128_CTS_ZeroPadding)
{
	vector<byte> key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CTS, Aes::PaddingScheme::ZeroPadding);
	EXPECT_EQ("tINbgNUv4Mp9Mo9k2wMjhQ==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CTS, Aes::PaddingScheme::ZeroPadding);
	EXPECT_EQ("PSUzyhLaY18amGtyoIm9qGKeqPEtgtMSDfEqKCqoxFs=", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::CTS, Aes::PaddingScheme::ZeroPadding);
	EXPECT_EQ("raQhAYQHP/MQyew2DfEIZa9kOncLtCktq+uFjNnccj4iqduHOZrVyT9LQ1RfFm5T", Base64::encode(encrypt));
}

TEST(Aes, AES_128_ECB_PKCS5Padding)
{
	vector<byte> key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");

	vector<byte> plain;
	vector<byte> encrypt;

	key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");
	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("1u9HjUFAEFOQeiP361vzgA==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("PSUzyhLaY18amGtyoIm9qOyMITTOhMI4eVe5MHkVPiw=", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("raQhAYQHP/MQyew2DfEIZcAhdH+zzWUWnULUMmEHv7+aAsTBtM1vMpxMy7Dq/yO8", Base64::encode(encrypt));
}

TEST(Aes, AES_128_OFB_PKCS5Padding)
{
	vector<byte> key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");

	vector<byte> plain;
	vector<byte> encrypt;

	key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");
	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("ntzGj2yhERTULzjEogILLw==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("Mhr/Ps6oNe+q+f9lKhx7/GeftRH/lPxBx3PYkCouibg=", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("CZpjyNwmrIXZUdKWIjngJy+ZKGakkO1ZChFbJXxaQVbJtqf5FNNRVoHc1S2R6HXR", Base64::encode(encrypt));
}

TEST(Aes, AES_128_GCM_NoPadding)
{
	vector<byte> key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");

	vector<byte> plain;
	vector<byte> encrypt;

	key = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");
	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
	EXPECT_EQ("JgXewdBzHpu50XzCHCG/7wZYJSSQNognedSk", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
	EXPECT_EQ("isPncHJ6OmDHB7tvA5foXdBUb5J9aD7Kzepx1KbnN0aVoocA", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Aes::encrypt(plain, key, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
	EXPECT_EQ("sUN7hmD0owq0r5acC7JzhphS8uWB4D5eG81IuCvoD0Q+WsePfOb/UL6U54oMHAvV", Base64::encode(encrypt));
}
