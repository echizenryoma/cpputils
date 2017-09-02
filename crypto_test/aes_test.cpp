#include "pch.h"

#include "../crypto/aes.h"
using crypto::Aes;

#include "../crypto/base64.h"
using crypto::encode::Base64;

/*
*  Define patterns for testing
*/
#define TEST_KEY_1 "\x06\xa9\x21\x40\x36\xb8\xa1\x5b\x51\x2e\x03\xd5\x34\x12\x00\x06"
#define TEST_IV_1 "\x3d\xaf\xba\x42\x9d\x9e\xb4\x30\xb4\x22\xda\x80\x2c\x9f\xac\x41"
#define TEST_DATA_1 "Single block msg"

#define TEST_KEY_2 "\xc2\x86\x69\x6d\x88\x7c\x9a\xa0\x61\x1b\xbb\x3e\x20\x25\xa4\x5a"
#define TEST_IV_2 "\x56\x2e\x17\x99\x6d\x09\x3d\x28\xdd\xb3\xba\x69\x5a\x2e\x6f\x58"
#define TEST_DATA_2 \
	"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"\
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"

#define TEST_KEY_3 "\x6c\x3e\xa0\x47\x76\x30\xce\x21\xa2\xce\x33\x4a\xa7\x46\xc2\xcd"
#define TEST_IV_3 "\xc7\x82\xdc\x4c\x09\x8c\x66\xcb\xd9\xcd\x27\xd8\x25\x68\x2c\x81"
#define TEST_DATA_3 "This is a 48-byte message (exactly 3 AES blocks)"

#define TEST_KEY_4 "\x56\xe4\x7a\x38\xc5\x59\x89\x74\xbc\x46\x90\x3d\xba\x29\x03\x49"
#define TEST_IV_4 "\x8c\xe8\x2e\xef\xbe\xa0\xda\x3c\x44\x69\x9e\xd7\xdb\x51\xb7\xd9"
#define TEST_DATA_4 \
	"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf" \
	"\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf" \
	"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf" \
	"\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"

struct AesTest
{
	const char* key_array;
	size_t key_array_size;
	const char* iv_array;
	size_t iv_array_size;
	const char* test_array;
	size_t test_array_size;
	string result_array;
};

const vector<byte> AES_128_KEY = Base64::decode("LbpWRuZIvD1a/dA9GVs2LQ==");

TEST(Aes, AES_CBC_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("1u9HjUFAEFOQeiP361vzgA==", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("PSUzyhLaY18amGtyoIm9qAbmOzTnOApDsqXZa8fyj2E=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("raQhAYQHP/MQyew2DfEIZa9kOncLtCktq+uFjNnccj7yMcoVlFpPIqcosTAOBPZz", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_CBC_ISO10126Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ctext = Base64::decode("EY0b1wWDQ6PQwo8i4e/z6w==");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ctext = Base64::decode("PSUzyhLaY18amGtyoIm9qDDHEhfFHLQRglN2F/FnMe8=");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ctext = Base64::decode("raQhAYQHP/MQyew2DfEIZa9kOncLtCktq+uFjNnccj4jMInTxIlCeb3C4YLoKEvz");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CBC, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_CFB_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("ntzGj2yhERTULzjEogILLw==", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("Mhr/Ps6oNe+q+f9lKhx7/HGbtg2CdG8TXk1y5qeWv/w=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("CZpjyNwmrIXZUdKWIjngJ5AIiVuFUAXhInXitkDzyJVlVDlcvZqNiB7n++UJMDnK", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_CFB_ISO10126Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ctext = Base64::decode("ntzGj2yhERTULzg3Lk3SLw==");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ctext = Base64::decode("Mhr/Ps6oNe+q+f9lKhx7/HGbtg37S2lPanrsFJmaZPw=");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ctext = Base64::decode("CZpjyNwmrIXZUdKWIjngJ5AIiVuFUAXhInXitkDzyJXst2wY0myiBUAjogNhlP3K");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CFB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_CTR_NoPadding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("ntzGj2yhERTULzg=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("Mhr/Ps6oNe+q+f9lKhx7/A1xYTI=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("CZpjyNwmrIXZUdKWIjngJ0V3/EWJnVTPc7BZNP9T4FU=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_CTR_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("ntzGj2yhERTULzjEogILLw==", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("Mhr/Ps6oNe+q+f9lKhx7/A1xYTLSmUXXvtLagaknKLs=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("CZpjyNwmrIXZUdKWIjngJ0V3/EWJnVTPc7BZNP9T4FUh92/BxqmKTZ3KH5Zms/kH", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_CTR_ISO10126Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ctext = Base64::decode("ntzGj2yhERTULzjEogILLw==");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ctext = Base64::decode("Mhr/Ps6oNe+q+f9lKhx7/A1xYTLSmUXXvtLagaknKLs=");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ctext = Base64::decode("CZpjyNwmrIXZUdKWIjngJ0V3/EWJnVTPc7BZNP9T4FUh92/BxqmKTZ3KH5Zms/kH");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTR, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_CTS_NoPadding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CTS, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("Yp6o8S2C0xIN8SooKqjEWz0lM8o=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTS, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::CTS, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("r2Q6dwu0KS2r64WM2dxyPq2kIQGEBz/zEMnsNg3xCGU=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::CTS, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_ECB_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("1u9HjUFAEFOQeiP361vzgA==", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("PSUzyhLaY18amGtyoIm9qOyMITTOhMI4eVe5MHkVPiw=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("raQhAYQHP/MQyew2DfEIZcAhdH+zzWUWnULUMmEHv7+aAsTBtM1vMpxMy7Dq/yO8", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_ECB_ISO10126Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ctext = Base64::decode("fLVwdQoyeuSOGCW49dCHcQ==");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ctext = Base64::decode("PSUzyhLaY18amGtyoIm9qLBzGm/tw0FD72WlOczhGUY=");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ctext = Base64::decode("raQhAYQHP/MQyew2DfEIZcAhdH+zzWUWnULUMmEHv7/SzvuLM2AP90/AG7X4hF6W");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::ECB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_OFB_PKCS5Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("ntzGj2yhERTULzjEogILLw==", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("Mhr/Ps6oNe+q+f9lKhx7/GeftRH/lPxBx3PYkCouibg=", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("CZpjyNwmrIXZUdKWIjngJy+ZKGakkO1ZChFbJXxaQVbJtqf5FNNRVoHc1S2R6HXR", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::PKCS5Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_OFB_ISO10126Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ctext = Base64::decode("ntzGj2yhERTULzhmrRxBLw==");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ctext = Base64::decode("Mhr/Ps6oNe+q+f9lKhx7/GeftREFXJRwiXrDvg7lALg=");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ctext = Base64::decode("CZpjyNwmrIXZUdKWIjngJy+ZKGakkO1ZChFbJXxaQVbVUA18ALBUMNQkMPGdhgDR");
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::OFB, Aes::PaddingScheme::ISO10126Padding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}

TEST(Aes, AES_GCM_NoPadding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("JgXewdBzHpu50XzCHCG/7wZYJSSQNognedSk", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("GcRqZtvZqfz0nww=", Base64::encode(ptext));

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("isPncHJ6OmDHB7tvA5foXdBUb5J9aD7Kzepx1KbnN0aVoocA", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("tQJT13nQjQeKScukjRt11lT3DjY=", Base64::encode(ptext));

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Aes::encrypt(ptext, AES_128_KEY, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("sUN7hmD0owq0r5acC7JzhphS8uWB4D5eG81IuCvoD0Q+WsePfOb/UL6U54oMHAvV", Base64::encode(ctext));
	ptext = Aes::decrypt(ctext, AES_128_KEY, Aes::CipherMode::GCM, Aes::PaddingScheme::NoPadding);
EXPECT_EQ("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=", Base64::encode(ptext));
}
