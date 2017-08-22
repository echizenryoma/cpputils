#include "pch.h"
#include "../crypto/base64.h"
using crypto::encode::Base64;

TEST(Base64, encode_Standard)
{
	EXPECT_EQ("IVF9RiRXQ2s=", Base64::encode("!Q}F$WCk"));
	EXPECT_EQ("Tk9zR246THVQI3klXUJkNVt8dGZfKGxnXmlhIm9Kd1U=", Base64::encode("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU"));
	EXPECT_EQ("dWgvTUQ3VnVpRGNsI1NLSWs+K1FMaVo9J3B8X1J1T2pFLGQ8JTI5S2lRNH1oOEEjaHBydmA1WSF5VTdTeTs7MDdOU0dndXshfjVfIWhBNFt0OF1VZE58ZStqT1NBOUgoVEgjUyw5NEQtRF9EKWQ8OWxnYWUjRUM2LXdkOW4s", Base64::encode("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,"));
}

TEST(Base64, decode_Standard)
{
	EXPECT_EQ("!Q}F$WCk", bytes2str(Base64::decode("IVF9RiRXQ2s=")));
	EXPECT_EQ("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", bytes2str(Base64::decode("Tk9zR246THVQI3klXUJkNVt8dGZfKGxnXmlhIm9Kd1U")));
	EXPECT_EQ("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", bytes2str(Base64::decode("dWgvTUQ3VnVpRGNsI1NLSWs+K1FMaVo9J3B8X1J1T2pFLGQ8JTI5S2lRNH1oOEEjaHBydmA1WSF5VTdTeTs7MDdOU0dndXshfjVfIWhBNFt0OF1VZE58ZStqT1NBOUgoVEgjUyw5NEQtRF9EKWQ8OWxnYWUjRUM2LXdkOW4s")));
}
