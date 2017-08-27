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

	digest = Hash::digest(
		"uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,",
		Hash::HashScheme::MD2);
EXPECT_EQ(Hex::encode(digest), "FBFD337A52CA5910C6B2A88EF5CCCFDB");
}

TEST(Hash, MD4)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::MD4);
EXPECT_EQ(Hex::encode(digest), "C1FF900C3BE8D2066F71C543AE44DC1E");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::MD4);
EXPECT_EQ(Hex::encode(digest), "78D237930CF6960D75744E421CA9CDBF");

	digest = Hash::digest(
		"uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,",
		Hash::HashScheme::MD4);
EXPECT_EQ(Hex::encode(digest), "5B455C7B2BBF40DCB2863396742B7EEC");
}

TEST(Hash, MD5)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::MD5);
EXPECT_EQ(Hex::encode(digest), "6EA2A9C8803CED9AD898FFD09D73CB00");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::MD5);
EXPECT_EQ(Hex::encode(digest), "21EEF939E014E7DA40AC31CF7B8663D4");

	digest = Hash::digest(
		"uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,",
		Hash::HashScheme::MD5);
EXPECT_EQ(Hex::encode(digest), "1484821D36ACBC33F6640573FACDDF23");
}

TEST(Hash, SHA1)
{
	const size_t TEST_COUNT = 8;
	struct HashTest
	{
		struct
		{
			const string test_array;
			long repeat_count;
			const string result_array;
		} tests[TEST_COUNT];
	} sha1_tests = {
			{
				/* 1 */{
					"abc",
					1,
					"A9993E364706816ABA3E25717850C26C9CD0D89D"
				},
				/* 2 */{
					"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
					1,
					"84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
				},
				/* 3 */{
					"a",
					1000000,
					"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"
				},
				/* 4 */{
					"01234567012345670123456701234567"
					"01234567012345670123456701234567",
					10,
					"DEA356A2CDDD90C7A7ECEDC5EBB563934F460452"
				},
				/* 5 */{
					"",
					1,
					"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
				},
				/* 6 */{
					"\x5e",
					1,
					"5E6F80A34A9798CAFC6A5DB96CC57BA4C4DB59C2"
				},
				/* 7 */{
					"\x9a\x7d\xfd\xf1\xec\xea\xd0\x6e\xd6\x46\xaa\x55\xfe\x75\x71\x46",
					1,
					"82ABFF6605DBE1C17DEF12A394FA22A82B544A35"
				},
				/* 8 */{
					"\xf7\x8f\x92\x14\x1b\xcd\x17\x0a\xe8\x9b\x4f\xba\x15\xa1\xd5\x9f"
					"\x3f\xd8\x4d\x22\x3c\x92\x51\xbd\xac\xbb\xae\x61\xd0\x5e\xd1\x15"
					"\xa0\x6a\x7c\xe1\x17\xb7\xbe\xea\xd2\x44\x21\xde\xd9\xc3\x25\x92"
					"\xbd\x57\xed\xea\xe3\x9c\x39\xfa\x1f\xe8\x94\x6a\x84\xd0\xcf\x1f"
					"\x7b\xee\xad\x17\x13\xe2\xe0\x95\x98\x97\x34\x7f\x67\xc8\x0b\x04"
					"\x00\xc2\x09\x81\x5d\x6b\x10\xa6\x83\x83\x6f\xd5\x56\x2a\x56\xca"
					"\xb1\xa2\x8e\x81\xb6\x57\x66\x54\x63\x1c\xf1\x65\x66\xb8\x6e\x3b"
					"\x33\xa1\x08\xb0\x53\x07\xc0\x0a\xff\x14\xa7\x68\xed\x73\x50\x60"
					"\x6a\x0f\x85\xe6\xa9\x1d\x39\x6f\x5b\x5c\xbe\x57\x7f\x9b\x38\x80"
					"\x7c\x7d\x52\x3d\x6d\x79\x2f\x6e\xbc\x24\xa4\xec\xf2\xb3\xa4\x27"
					"\xcd\xbb\xfb",
					1,
					"CB0082C8F197D260991BA6A460E76E202BAD27B3"
				}
			}
		};

	for (int j = 0; j < TEST_COUNT; ++j)
	{
		string msg;
		for (int i = 0; i < sha1_tests.tests[j].repeat_count; ++i)
		{
			msg += sha1_tests.tests[j].test_array;
		}
	EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::SHA1)), sha1_tests.tests[j].result_array);
	}
}

TEST(Hash, SHA224)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA224);
EXPECT_EQ(Hex::encode(digest), "90E383BA4D4DBB5A5BAE249F2F1C2404AEEC2D874D58114D39AF55BB");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA224);
EXPECT_EQ(Hex::encode(digest), "099A1B59FEDC2E6CB3E224D3D61069AB89C1E4B7E144C5A33FD96575");

	digest = Hash::digest(
		"uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,",
		Hash::HashScheme::SHA224);
EXPECT_EQ(Hex::encode(digest), "6D2D0EC664580DE8E6326BFB5D6FBCD653B018AE9EBB03CC328376C7");
}

TEST(Hash, SHA256)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA256);
EXPECT_EQ(Hex::encode(digest), "75199505AACADC17E1BF7E73C40F75FC45DB52B89F5B94BC6099A18EB867953E");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA256);
EXPECT_EQ(Hex::encode(digest), "45D9BBDC7626B7E9894635E55C69894CA59D5226057C32C6B760BFE53B92ADFC");

	digest = Hash::digest(
		"uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,",
		Hash::HashScheme::SHA256);
EXPECT_EQ(Hex::encode(digest), "72493762F6ECEAEB85154C5525C2D3D7890C945E1A7B5917F40CD7B60876A237");
}

TEST(Hash, SHA384)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA384);
EXPECT_EQ(Hex::encode(digest),
		"6CA165956CC56E40AEFC1FC7F1F861FA1FC50AD74B64B6B80B37107AC92E3841956EDB4EA001649CE5B9658FA07FEC36");

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA384);
EXPECT_EQ(Hex::encode(digest),
		"FF6AB08A039B9542D30B9808C791543A84B87D440185BC045765CDE33BA3CBEC5B1B39C21F7A1EA3C282007B049027DD");

	digest = Hash::digest(
		"uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,",
		Hash::HashScheme::SHA384);
EXPECT_EQ(Hex::encode(digest),
		"B806A66B40048FC3CDC8F918D7B85DEC13BF1DD7C957B4302E51CBB34E65F80D4E9B340CE290923B71019032CEB56996");
}

TEST(Hash, SHA512)
{
	vector<byte> digest;

	digest = Hash::digest("!Q}F$WCk", Hash::HashScheme::SHA512);
EXPECT_EQ(Hex::encode(digest),
		"A54AE328E216C5A8282316679B8B195C61D77E5562FCCD4E4BD6D0E11C7BBFBB47F640FDE0D321A77F6A0B631E8FBFB1E4306BA2E318CC4856A90BAD30B89152"
	);

	digest = Hash::digest("NOsGn:LuP#y%]Bd5[|tf_(lg^ia\"oJwU", Hash::HashScheme::SHA512);
EXPECT_EQ(Hex::encode(digest),
		"A2AA5873564A567D21482EE8C422E304A449DD2D9452C5A7C7E18AB1C343D8CB1F3A4AF27BB2953D0054E213A8092C25221C336AA653B86E07D9F098028D44D6"
	);

	digest = Hash::digest(
		"uh/MD7VuiDcl#SKIk>+QLiZ='p|_RuOjE,d<%29KiQ4}h8A#hprv`5Y!yU7Sy;;07NSGgu{!~5_!hA4[t8]UdN|e+jOSA9H(TH#S,94D-D_D)d<9lgae#EC6-wd9n,",
		Hash::HashScheme::SHA512);
EXPECT_EQ(Hex::encode(digest),
		"2277A75A6E84C248CFA2C10E44C8C7ABF7D563BABC187F2EE257D7D2F055190009FC6E773FD4B3CDEF4FB28A45AD7D1B15656B77902B49C899476F8654B80D90"
	);
}
