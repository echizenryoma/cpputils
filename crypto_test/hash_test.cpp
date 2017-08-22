#include "pch.h"

#include "../crypto/hash.h"
using crypto::message::digest::Hash;

TEST(Hash, MD2)
{
	EXPECT_EQ("517EAE3B5E7EC1CE00147119F0117D78", Hash::digest("!Q}F$WCk", Hash::HashScheme::MD2, Hash::EncodeScheme::Hex));
	EXPECT_EQ("AE3DD2166F5962BD719F9C4B45E0437A", Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::MD2, Hash::EncodeScheme::Hex));
	EXPECT_EQ("FBFD337A52CA5910C6B2A88EF5CCCFDB", Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::MD2, Hash::EncodeScheme::Hex));
}

TEST(Hash, MD4)
{
	EXPECT_EQ("C1FF900C3BE8D2066F71C543AE44DC1E", Hash::digest("!Q}F$WCk", Hash::HashScheme::MD4, Hash::EncodeScheme::Hex));
	EXPECT_EQ("78D237930CF6960D75744E421CA9CDBF", Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::MD4, Hash::EncodeScheme::Hex));
	EXPECT_EQ("5B455C7B2BBF40DCB2863396742B7EEC", Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::MD4, Hash::EncodeScheme::Hex));
}

TEST(Hash, MD5)
{
	EXPECT_EQ("6EA2A9C8803CED9AD898FFD09D73CB00", Hash::digest("!Q}F$WCk", Hash::HashScheme::MD5, Hash::EncodeScheme::Hex));
	EXPECT_EQ("21EEF939E014E7DA40AC31CF7B8663D4", Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::MD5, Hash::EncodeScheme::Hex));
	EXPECT_EQ("1484821D36ACBC33F6640573FACDDF23", Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::MD5, Hash::EncodeScheme::Hex));
}

TEST(Hash, SHA1)
{
	EXPECT_EQ("EBF87C07674ED5EA7973B90D038C1070DB9AC3F1", Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA1, Hash::EncodeScheme::Hex));
	EXPECT_EQ("B5A8E8B3032CAE2EDE1EC5788CC6D824EEC4AA16", Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA1, Hash::EncodeScheme::Hex));
	EXPECT_EQ("70F3AFB4751173195217DDBBBFC3FBB17C8EA620", Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA1, Hash::EncodeScheme::Hex));
}

TEST(Hash, SHA224)
{
	EXPECT_EQ("90E383BA4D4DBB5A5BAE249F2F1C2404AEEC2D874D58114D39AF55BB", Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA224, Hash::EncodeScheme::Hex));
	EXPECT_EQ("099A1B59FEDC2E6CB3E224D3D61069AB89C1E4B7E144C5A33FD96575", Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA224, Hash::EncodeScheme::Hex));
	EXPECT_EQ("6D2D0EC664580DE8E6326BFB5D6FBCD653B018AE9EBB03CC328376C7", Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA224, Hash::EncodeScheme::Hex));
}

TEST(Hash, SHA256)
{
	EXPECT_EQ("75199505AACADC17E1BF7E73C40F75FC45DB52B89F5B94BC6099A18EB867953E", Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA256, Hash::EncodeScheme::Hex));
	EXPECT_EQ("45D9BBDC7626B7E9894635E55C69894CA59D5226057C32C6B760BFE53B92ADFC", Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA256, Hash::EncodeScheme::Hex));
	EXPECT_EQ("72493762F6ECEAEB85154C5525C2D3D7890C945E1A7B5917F40CD7B60876A237", Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,",Hash::HashScheme::SHA256, Hash::EncodeScheme::Hex));
}

TEST(Hash, SHA384)
{
	EXPECT_EQ("6CA165956CC56E40AEFC1FC7F1F861FA1FC50AD74B64B6B80B37107AC92E3841956EDB4EA001649CE5B9658FA07FEC36", Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA384, Hash::EncodeScheme::Hex));
	EXPECT_EQ("FF6AB08A039B9542D30B9808C791543A84B87D440185BC045765CDE33BA3CBEC5B1B39C21F7A1EA3C282007B049027DD", Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA384, Hash::EncodeScheme::Hex));
	EXPECT_EQ("B806A66B40048FC3CDC8F918D7B85DEC13BF1DD7C957B4302E51CBB34E65F80D4E9B340CE290923B71019032CEB56996", Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA384, Hash::EncodeScheme::Hex));
}

TEST(Hash, SHA512)
{
	EXPECT_EQ("A54AE328E216C5A8282316679B8B195C61D77E5562FCCD4E4BD6D0E11C7BBFBB47F640FDE0D321A77F6A0B631E8FBFB1E4306BA2E318CC4856A90BAD30B89152", Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA512, Hash::EncodeScheme::Hex));
	EXPECT_EQ("A2AA5873564A567D21482EE8C422E304A449DD2D9452C5A7C7E18AB1C343D8CB1F3A4AF27BB2953D0054E213A8092C25221C336AA653B86E07D9F098028D44D6", Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA512, Hash::EncodeScheme::Hex));
	EXPECT_EQ("2277A75A6E84C248CFA2C10E44C8C7ABF7D563BABC187F2EE257D7D2F055190009FC6E773FD4B3CDEF4FB28A45AD7D1B15656B77902B49C899476F8654B80D90", Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA512, Hash::EncodeScheme::Hex));
}