#include "pch.h"

#include "../crypto/hmac.h"
using crypto::mac::Hmac;

#include "../crypto/base64.h"
using crypto::encode::Base64;

vector<byte> key = Base64::decode("W34PnJOcS6d/1wQxqZudwk+b9WtwFL/4INsQUctRIcrdx0sM0N2YKSbHacUQqgC6jnNs0zZhFO3DLbKvLCjovg==");

TEST(HMAC, MD5)
{
	string hmac;

	hmac = Hmac::mac("!Q}F$WCk", key, Hmac::HashScheme::MD5, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("DB13358D5337082EE3845DBEB833399D", hmac);

	hmac = Hmac::mac("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", key, Hmac::HashScheme::MD5, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("A265A14691A8A27004BD691130674334", hmac);

	hmac = Hmac::mac("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", key, Hmac::HashScheme::MD5, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("E2A5142F68B9350342921D79A2787CB6", hmac);
}

TEST(HMAC, SHA1)
{
	string hmac;

	hmac = Hmac::mac("!Q}F$WCk", key, Hmac::HashScheme::SHA1, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("B89EDC41911AD9026ECC40EBE3D7BFB7693608E4", hmac);

	hmac = Hmac::mac("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", key, Hmac::HashScheme::SHA1, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("3FD684ADADCA8850B737363B4B5AAB6396AB46E5", hmac);

	hmac = Hmac::mac("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", key, Hmac::HashScheme::SHA1, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("D6868D46D3D21D778BC93B2BAFC9C1C3AACC220C", hmac);
}

TEST(HMAC, SHA224)
{
	string hmac;

	hmac = Hmac::mac("!Q}F$WCk", key, Hmac::HashScheme::SHA224, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("D53118044AB4D9EDC94940463A1AB090200D9EFD9285F09C3F9BF8C9", hmac);

	hmac = Hmac::mac("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", key, Hmac::HashScheme::SHA224, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("B55193238E83BC0426694E553146F247A08DC3CCD572E29B97A9BEB9", hmac);

	hmac = Hmac::mac("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", key, Hmac::HashScheme::SHA224, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("DC81DE069BB752663C62261D2CE106EE11A4E2815CC37E1DC05F1953", hmac);
}

TEST(HMAC, SHA256)
{
	string hmac;

	hmac = Hmac::mac("!Q}F$WCk", key, Hmac::HashScheme::SHA256, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("8E27803C59B9AC314F7A30AA0091EEA8B1C7BD62C5A7FB7783E14D8104F7EE3D", hmac);

	hmac = Hmac::mac("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", key, Hmac::HashScheme::SHA256, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("4DADEED06BFF92D1D9590A62D8A930F6675B75B038B33047D6F5DE1DD4214B95", hmac);

	hmac = Hmac::mac("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", key, Hmac::HashScheme::SHA256, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("B918278B0E56C73B97D2B98C881CC36DC71170F8CBA000CC47C39CDF332C40A6", hmac);
}

TEST(HMAC, SHA384)
{
	string hmac;

	hmac = Hmac::mac("!Q}F$WCk", key, Hmac::HashScheme::SHA256, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("93BEF0A5B4B1021A822D578A1E47834B0F28C089E08A481D19AE8948EA3AC141639B2CE17031B7FED181B6F0473FB443", hmac);

	hmac = Hmac::mac("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", key, Hmac::HashScheme::SHA384, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("4DC28D4C80C28C74A93D2BA4847D23C14A1A95563C8B778DDEAB53ECF15F712AB930CD3606F1A43C5C762281253406CE", hmac);

	hmac = Hmac::mac("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", key, Hmac::HashScheme::SHA384, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("008537D737F4941EEBEAB9003A0357DF58366D67534B2ADF1E4B0534972E107176811443B0F98FBA05E71B79E883B492", hmac);
}

TEST(HMAC, SHA512)
{
	string hmac;

	hmac = Hmac::mac("!Q}F$WCk", key, Hmac::HashScheme::SHA256, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("3DEFA5BA4D2C2DEFEA47819FB0184F4BACCEB75D6155B3EB94A699BDD21E4DAEB9AAA6D2C5E80062BBC630952F2763C7543E639E6DED1C1515AC4B466ECDAD3A", hmac);

	hmac = Hmac::mac("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", key, Hmac::HashScheme::SHA512, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("FBC1CBA7DBF3F4383C22C36721FCD1CDDA80E5FB1C6A12C21B055F94882AFB9E35BEEF489E2E375300A1F84F45E1E15C790A363907F3F50131C39735BB9ADA03", hmac);

	hmac = Hmac::mac("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", key, Hmac::HashScheme::SHA512, Hmac::EncodeScheme::Hex);
	EXPECT_EQ("B014709C590980EB6176ED2D350EB535FD0576BE0FF19D8F33DEB9802F787EBB2A5DD6350958D243F1574CED13E838F23D67E623540F406C5C6F8F67E99EA52E", hmac);
}
