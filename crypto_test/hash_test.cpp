#include "pch.h"

#include "../crypto/hex.h"
using crypto::encode::Hex;

#include "../crypto/hash.h"
using crypto::message::digest::Hash;

TEST(Hash, MD2)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::MD2);
	EXPECT_EQ(Hex::encode(digest), "517EAE3B5E7EC1CE00147119F0117D78");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::MD2);
	EXPECT_EQ(Hex::encode(digest), "AE3DD2166F5962BD719F9C4B45E0437A");

	digest = Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::MD2);
	EXPECT_EQ(Hex::encode(digest), "FBFD337A52CA5910C6B2A88EF5CCCFDB");
}

TEST(Hash, MD4)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::MD4);
	EXPECT_EQ(Hex::encode(digest), "C1FF900C3BE8D2066F71C543AE44DC1E");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::MD4);
	EXPECT_EQ(Hex::encode(digest), "78D237930CF6960D75744E421CA9CDBF");

	digest = Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::MD4);
	EXPECT_EQ(Hex::encode(digest), "5B455C7B2BBF40DCB2863396742B7EEC");
}

TEST(Hash, MD5)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::MD5);
	EXPECT_EQ(Hex::encode(digest), "6EA2A9C8803CED9AD898FFD09D73CB00");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::MD5);
	EXPECT_EQ(Hex::encode(digest), "21EEF939E014E7DA40AC31CF7B8663D4");

	digest = Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::MD5);
	EXPECT_EQ(Hex::encode(digest), "1484821D36ACBC33F6640573FACDDF23");
}

TEST(Hash, SHA1)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA1);
	EXPECT_EQ(Hex::encode(digest), "EBF87C07674ED5EA7973B90D038C1070DB9AC3F1");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA1);
	EXPECT_EQ(Hex::encode(digest), "B5A8E8B3032CAE2EDE1EC5788CC6D824EEC4AA16");

	digest = Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA1);
	EXPECT_EQ(Hex::encode(digest), "70F3AFB4751173195217DDBBBFC3FBB17C8EA620");
}

TEST(Hash, SHA224)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA224);
	EXPECT_EQ(Hex::encode(digest), "90E383BA4D4DBB5A5BAE249F2F1C2404AEEC2D874D58114D39AF55BB");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA224);
	EXPECT_EQ(Hex::encode(digest), "099A1B59FEDC2E6CB3E224D3D61069AB89C1E4B7E144C5A33FD96575");

	digest = Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA224);
	EXPECT_EQ(Hex::encode(digest), "6D2D0EC664580DE8E6326BFB5D6FBCD653B018AE9EBB03CC328376C7");
}

TEST(Hash, SHA256)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA256);
	EXPECT_EQ(Hex::encode(digest), "75199505AACADC17E1BF7E73C40F75FC45DB52B89F5B94BC6099A18EB867953E");
	
	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA256);
	EXPECT_EQ(Hex::encode(digest), "45D9BBDC7626B7E9894635E55C69894CA59D5226057C32C6B760BFE53B92ADFC");
	
	digest = Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA256);
	EXPECT_EQ(Hex::encode(digest), "72493762F6ECEAEB85154C5525C2D3D7890C945E1A7B5917F40CD7B60876A237");
}

TEST(Hash, SHA384)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA384);
	EXPECT_EQ(Hex::encode(digest), "6CA165956CC56E40AEFC1FC7F1F861FA1FC50AD74B64B6B80B37107AC92E3841956EDB4EA001649CE5B9658FA07FEC36");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA384);
	EXPECT_EQ(Hex::encode(digest), "FF6AB08A039B9542D30B9808C791543A84B87D440185BC045765CDE33BA3CBEC5B1B39C21F7A1EA3C282007B049027DD");

	digest = Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA384);
	EXPECT_EQ(Hex::encode(digest), "B806A66B40048FC3CDC8F918D7B85DEC13BF1DD7C957B4302E51CBB34E65F80D4E9B340CE290923B71019032CEB56996");
}

TEST(Hash, SHA512)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA512);
	EXPECT_EQ(Hex::encode(digest), "A54AE328E216C5A8282316679B8B195C61D77E5562FCCD4E4BD6D0E11C7BBFBB47F640FDE0D321A77F6A0B631E8FBFB1E4306BA2E318CC4856A90BAD30B89152");
	
	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA512);
	EXPECT_EQ(Hex::encode(digest), "A2AA5873564A567D21482EE8C422E304A449DD2D9452C5A7C7E18AB1C343D8CB1F3A4AF27BB2953D0054E213A8092C25221C336AA653B86E07D9F098028D44D6");
	
	digest = Hash::digest("uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,", Hash::HashScheme::SHA512);
	EXPECT_EQ(Hex::encode(digest), "2277A75A6E84C248CFA2C10E44C8C7ABF7D563BABC187F2EE257D7D2F055190009FC6E773FD4B3CDEF4FB28A45AD7D1B15656B77902B49C899476F8654B80D90");
}
