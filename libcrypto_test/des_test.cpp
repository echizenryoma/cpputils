#include "pch.h"

#include "../libcrypto/des.h"
using crypto::Des;

#include "../libcrypto/base64.h"
using crypto::encode::Base64;

const vector<byte> DESede_KEY = Base64::decode("0PuknauivM2nomFnSpRGQGS8V/LOvOPI");

TEST(Des, DESede_CBC_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CBC, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("2LfrhZDYnoKqT74baBxE1w==", Base64::encode(ctext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CBC, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("cHI+sBzKhLOOLrR1N+Zhl2OyzFjY/QN2", Base64::encode(ctext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CBC, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("xHEEmS5x1AxhUXVHf1zkUZxRoK2WGrXJ6ZrlonffDU/yIusjYaL3lA==", Base64::encode(ctext));
}

TEST(Des, DESede_CFB_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CFB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("6PHcG+TwUmzNxtPCT5ZScw==", Base64::encode(ctext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CFB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("RDflqkb5dpd4yphL5AgQ7MhR6PG8FB/D", Base64::encode(ctext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CFB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("f7d5XFR37/0f1APCFAU3Vi/6ZG8HGhIzmTDLXKiqvZG20BMhmqS/AQ==", Base64::encode(ctext));
}

TEST(Des, DESede_CTR_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CTR, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("6PHcG+TwUmyruQtYo61hBw==", Base64::encode(ctext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CTR, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("RDflqkb5dpfVb8z5K7MR1EB5YnAYNrOO", Base64::encode(ctext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CTR, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("f7d5XFR37/2mx+EKI5aKDwh//wdLOqqeMjyhremupIDW+GsOD7TPsQ==", Base64::encode(ctext));
}

TEST(Des, DESede_CTS_NoPadding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CTS, Des::PaddingScheme::NoPadding);
	EXPECT_EQ("cHI+sBzKhLPNqStFj4HiDI4utHU=", Base64::encode(ctext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::CTS, Des::PaddingScheme::NoPadding);
	EXPECT_EQ("xHEEmS5x1AxhUXVHf1zkUema5aJ33w1PnFGgrZYatck=", Base64::encode(ctext));
}

TEST(Des, DESede_ECB_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::ECB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("2LfrhZDYnoL0e/hdTNmvUg==", Base64::encode(ctext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::ECB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("cHI+sBzKhLPyua8G3fs06n3Utke30QRT", Base64::encode(ctext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::ECB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("xHEEmS5x1Ay9GvyqTPpGi+TJYZZFvck2VPgPYvytmvzJc6+pTVYUgQ==", Base64::encode(ctext));
}

TEST(Des, DESede_OFB_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::OFB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("6PHcG+TwUmzaiWfEzBi3kw==", Base64::encode(ctext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::OFB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("RDflqkb5dpekX6BlRAbHQHFSwgI+w+qQ", Base64::encode(ctext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Des::encrypt(ptext, DESede_KEY, Des::CipherMode::OFB, Des::PaddingScheme::PKCS5Padding);
	EXPECT_EQ("f7d5XFR37/3X942WTCNcmzlUX3Vtz/OA9cYnVPr2fvVgenWBGNUrzg==", Base64::encode(ctext));
}