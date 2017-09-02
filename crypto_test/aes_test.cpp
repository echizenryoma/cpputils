#include "pch.h"

#include "../crypto/aes.h"
using crypto::Aes;

#include "../crypto/base64.h"
using crypto::encode::Base64;

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
