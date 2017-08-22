#include "pch.h"

#include "../crypto/base64.h"
using crypto::encode::Base64;

TEST(Base64, encode)
{
	EXPECT_EQ(Base64::encode("!Q}F$WCk"), "IVF9RiRXQ2s=");
	EXPECT_EQ(Base64::encode("~D!@e78<2K%O=Ayb1l>S;9MUp`Lv"), "fkQhQGU3ODwySyVPPUF5YjFsPlM7OU1VcGBMdg==");
	EXPECT_EQ(Base64::encode("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,"), "dWgvTUQ3VnVpRGNsI1NLSWs+K1FMaVo9J3B8X1J1T2pFLGQ8JTI5S2lRNH1oOEEjaHBydmA1WSF5VTdTeTs7MDdOU0dndXshfjVfIWhBNFt0OF1VZE58ZStqT1NBOUgoVEgjUyw5NEQtRF9EKWQ8OWxnYWUjRUM2LXdkOW4s", );
}

TEST(Base64, decode)
{
	EXPECT_EQ(bytes2str(Base64::decode("IVF9RiRXQ2s=")), "!Q}F$WCk");
	EXPECT_EQ(bytes2str(Base64::decode("fkQhQGU3ODwySyVPPUF5YjFsPlM7OU1VcGBMdg==")), "~D!@e78<2K%O=Ayb1l>S;9MUp`Lv");
	EXPECT_EQ(bytes2str(Base64::decode("dWgvTUQ3VnVpRGNsI1NLSWs+K1FMaVo9J3B8X1J1T2pFLGQ8JTI5S2lRNH1oOEEjaHBydmA1WSF5VTdTeTs7MDdOU0dndXshfjVfIWhBNFt0OF1VZE58ZStqT1NBOUgoVEgjUyw5NEQtRF9EKWQ8OWxnYWUjRUM2LXdkOW4s")), "uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,");
}
