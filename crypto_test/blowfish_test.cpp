#include "pch.h"
#include "../crypto/blowfish.h"
#include "../crypto/base64.h"

TEST(Blowfish, CBC_PKCS5Padding)
{
	vector<byte> key = Base64::decode("jFvNvrFxR1NiXdYk1mxB6Q==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CBC, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("SP54OhX8w+okaQbjFHrScg==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CBC, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("Q7ZpVar/hQ4PdO7Z3rylZaSNt2yv2odi", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CBC, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("VMz8e/ZULWAzTjCeWypzbGR66og1TkxQ/2ufT8DZU3hv20uY3ssT9Q==", Base64::encode(encrypt));
}

TEST(Blowfish, CFB_PKCS5Padding)
{
	vector<byte> key = Base64::decode("jFvNvrFxR1NiXdYk1mxB6Q==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CFB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("rn2kjo7FRAtyI8PNhidV4w==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CFB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("ArudPyzMYPChC7DFli07vEbqlNIQHmil", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CFB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("OTsByT5C+ZpE20a+GpjSSl5aB5TqyhKr33yihVi65DT+T8yuVKRfYQ==", Base64::encode(encrypt));
}

TEST(Blowfish, CTR_NoPadding)
{
	vector<byte> key = Base64::decode("jFvNvrFxR1NiXdYk1mxB6Q==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CTR, Blowfish::PaddingScheme::No_Padding);
	EXPECT_EQ("rn2kjo7FRAuQOzc=", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CTR, Blowfish::PaddingScheme::No_Padding);
	EXPECT_EQ("ArudPyzMYPDu7fA8FXpgBTp3ErA=", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CTR, Blowfish::PaddingScheme::No_Padding);
	EXPECT_EQ("OTsByT5C+ZqdRd3PHV/73nJxj8fkYk1vlUmM9MnupWo=", Base64::encode(encrypt));
}

TEST(Blowfish, CTS_ZeroPadding)
{
	vector<byte> key = Base64::decode("jFvNvrFxR1NiXdYk1mxB6Q==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CTS, Blowfish::PaddingScheme::Zero_Padding);
	EXPECT_EQ("SP54OhX8w+oAQeEm3YF26g==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CTS, Blowfish::PaddingScheme::Zero_Padding);
	EXPECT_EQ("Q7ZpVar/hQ4PdO7Z3rylZaEeKA3TRwM+", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::CTS, Blowfish::PaddingScheme::Zero_Padding);
	EXPECT_EQ("VMz8e/ZULWAzTjCeWypzbGR66og1TkxQ/2ufT8DZU3jjjZ+foL0HFg==", Base64::encode(encrypt));
}

TEST(Blowfish, ECB_PKCS5Padding)
{
	vector<byte> key = Base64::decode("jFvNvrFxR1NiXdYk1mxB6Q==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::ECB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("SP54OhX8w+qo0Cgk1nbaKg==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::ECB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("Q7ZpVar/hQ5SPLYusO/flB2zs0BA2Xti", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::ECB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("VMz8e/ZULWCqkvfNvZRX6+wMJUDksvkCe+0l38qeJhSLPMXNit2KRQ==", Base64::encode(encrypt));
}

TEST(Blowfish, OFB_PKCS5Padding)
{
	vector<byte> key = Base64::decode("jFvNvrFxR1NiXdYk1mxB6Q==");

	vector<byte> plain;
	vector<byte> encrypt;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::OFB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("rn2kjo7FRAtPVkIvXs3kxw==", Base64::encode(encrypt));

	plain = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::OFB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("ArudPyzMYPAxgIWO1tOUFNHH/OuB5hY6", Base64::encode(encrypt));

	plain = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	encrypt = Blowfish::encrypt(plain, key, Blowfish::CipherMode::OFB, Blowfish::PaddingScheme::PKCS5_Padding);
	EXPECT_EQ("OTsByT5C+ZpCKKh93vYPz5nBYZzS6g8qLj7P1EKb4DXirPw7xMsVow==", Base64::encode(encrypt));
}
