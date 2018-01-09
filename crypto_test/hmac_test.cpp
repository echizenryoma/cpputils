#include "pch.h"

#include "../crypto/hmac.h"
using crypto::mac::Hmac;

#include "../crypto/base64.h"
using crypto::encode::Base64;

#include "../crypto/hex.h"
using crypto::encode::Hex;

/**
* \sa <A HREF="https://tools.ietf.org/html/rfc2202#section-2">2. Test Cases for HMAC-MD5</A>
* for additional details.
*/
/*
*  Define patterns for testing
*/
#define TEST_KEY_1 \
	"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b" \
	"\x0b\x0b\x0b\x0b\x0b"
#define TEST_KEY_2 "\x4a\x65\x66\x65" /* "Jefe" */
#define TEST_KEY_3 \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa"
#define TEST_KEY_4 \
	"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" \
	"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19"
#define TEST_KEY_5 \
	"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c" \
	"\x0c\x0c\x0c\x0c\x0c"
#define TEST_KEY_6 \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
	"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
#define TEST_KEY_7 TEST_KEY_6

#define TEST_DATA_1 "\x48\x69\x20\x54\x68\x65\x72\x65" /* "Hi There" */
#define TEST_DATA_2 \
	"\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e\x74" \
	"\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f"
/* "what do ya want for nothing?" */
#define TEST_DATA_3 \
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
	"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
	"\xdd\xdd\xdd\xdd\xdd"
#define TEST_DATA_4 \
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd" \
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd" \
	"\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd" \
	"\xcd\xcd\xcd\xcd\xcd"
#define TEST_DATA_5 "Test With Truncation"
#define TEST_DATA_6 "Test Using Larger Than Block-Size Key - Hash Key First"
#define TEST_DATA_7a \
	"Test Using Larger Than Block-Size Key and " \
	"Larger Than One Block-Size Data"
/* "This is a test using a larger than block-size key and a "
"larger than block-size data.  The key needs to be hashed "
"before being used by the HMAC algorithm." */
#define TEST_DATA_7b \
	"\x54\x68\x69\x73\x20\x69\x73\x20\x61\x20\x74\x65\x73\x74\x20" \
	"\x75\x73\x69\x6e\x67\x20\x61\x20\x6c\x61\x72\x67\x65\x72\x20" \
	"\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73\x69\x7a\x65" \
	"\x20\x6b\x65\x79\x20\x61\x6e\x64\x20\x61\x20\x6c\x61\x72\x67" \
	"\x65\x72\x20\x74\x68\x61\x6e\x20\x62\x6c\x6f\x63\x6b\x2d\x73" \
	"\x69\x7a\x65\x20\x64\x61\x74\x61\x2e\x20\x54\x68\x65\x20\x6b" \
	"\x65\x79\x20\x6e\x65\x65\x64\x73\x20\x74\x6f\x20\x62\x65\x20" \
	"\x68\x61\x73\x68\x65\x64\x20\x62\x65\x66\x6f\x72\x65\x20\x62" \
	"\x65\x69\x6e\x67\x20\x75\x73\x65\x64\x20\x62\x79\x20\x74\x68" \
	"\x65\x20\x48\x4d\x41\x43\x20\x61\x6c\x67\x6f\x72\x69\x74\x68" \
	"\x6d\x2e"

struct HmacTest
{
	const char* key_array;
	size_t key_array_size;
	const char* test_array;
	size_t test_array_size;
	string result_array;
};

TEST(HMAC, MD5)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc2202#section-2">2. Test Cases for HMAC-MD5</A>
	* for additional details.
	*/
	vector<HmacTest> HAMC_TESTS{
		/* 1 */{
			TEST_KEY_1, 16,
			TEST_DATA_1, length(TEST_DATA_1),
			"9294727A3638BB1C13F48EF8158BFC9D"
		},
		/* 2 */{
			TEST_KEY_2, length(TEST_KEY_2),
			TEST_DATA_2, length(TEST_DATA_2),
			"750C783E6AB0B503EAA86E310A5DB738"
		},
		/* 3 */{
			TEST_KEY_3, 16,
			TEST_DATA_3, length(TEST_DATA_3),
			"56BE34521D144C88DBB8C733F0E8B3F6"
		},
		/* 4 */{
			TEST_KEY_4, length(TEST_KEY_4),
			TEST_DATA_4, length(TEST_DATA_4),
			"697EAF0ACA3A3AEA3A75164746FFAA79"
		},
		/* 5 */{
			TEST_KEY_5, 16,
			TEST_DATA_5, length(TEST_DATA_5),
			"56461EF2342EDC00F9BAB995690EFD4C"
		},
		/* 6 */{
			TEST_KEY_6, 80,
			TEST_DATA_6, length(TEST_DATA_6),
			"6B1AB7FE4BD7BF8F0B62E6CE61B9D0CD"
		},
		/* 7 */{
			TEST_KEY_7, 80,
			TEST_DATA_7a, length(TEST_DATA_7a),
			"6F630FAD67CDA0EE1FB1F562DB3AA53E"
		}
	};

	for (HmacTest t : HAMC_TESTS)
	{
		string msg(t.test_array, t.test_array + t.test_array_size);
		string key(t.key_array, t.key_array + t.key_array_size);
	EXPECT_EQ(Hex::encode(Hmac::mac(msg, vector<byte>(key.begin(), key.end()), Hmac::HashScheme::MD5)), t.result_array);
	}
}

TEST(HMAC, SHA1)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc6234#section-8.5">8.5.  The Test Driver</A>
	* for additional details.
	*/
	vector<HmacTest> HAMC_TESTS{
		/* 1 */{
			TEST_KEY_1, length(TEST_KEY_1),
			TEST_DATA_1, length(TEST_DATA_1),
			"B617318655057264E28BC0B6FB378C8EF146BE00"
		},
		/* 2 */{
			TEST_KEY_2, length(TEST_KEY_2),
			TEST_DATA_2, length(TEST_DATA_2),
			"EFFCDF6AE5EB2FA2D27416D5F184DF9C259A7C79"
		},
		/* 3 */{
			TEST_KEY_3, length(TEST_KEY_3),
			TEST_DATA_3, length(TEST_DATA_3),
			"125D7342B9AC11CD91A39AF48AA17B4F63F175D3"
		},
		/* 4 */{
			TEST_KEY_4, length(TEST_KEY_4),
			TEST_DATA_4, length(TEST_DATA_4),
			"4C9007F4026250C6BC8414F9BF50C86C2D7235DA"
		},
		/* 5 */{
			TEST_KEY_5, length(TEST_KEY_5),
			TEST_DATA_5, length(TEST_DATA_5),
			"4C1A03424B55E07FE7F27BE1D58BB9324A9A5A04"
		},
		/* 6 */{
			TEST_KEY_6, 80,
			TEST_DATA_6, length(TEST_DATA_6),
			"AA4AE5E15272D00E95705637CE8A3B55ED402112"
		},
		/* 7 */{
			TEST_KEY_7, 80,
			TEST_DATA_7a, length(TEST_DATA_7a),
			"E8E99D0F45237D786D6BBAA7965C7808BBFF1A91"
		}
	};

	for (HmacTest t : HAMC_TESTS)
	{
		string msg(t.test_array, t.test_array + t.test_array_size);
		string key(t.key_array, t.key_array + t.key_array_size);
	EXPECT_EQ(Hex::encode(Hmac::mac(msg, vector<byte>(key.begin(), key.end()), Hmac::HashScheme::SHA1)), t.result_array);
	}
}

TEST(HMAC, SHA224)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc6234#section-8.5">8.5.  The Test Driver</A>
	* for additional details.
	*/
	vector<HmacTest> HAMC_TESTS{
		/* 1 */{
			TEST_KEY_1, length(TEST_KEY_1),
			TEST_DATA_1, length(TEST_DATA_1),
			"896FB1128ABBDF196832107CD49DF33F47B4B1169912BA4F53684B22"
		},
		/* 2 */{
			TEST_KEY_2, length(TEST_KEY_2),
			TEST_DATA_2, length(TEST_DATA_2),
			"A30E01098BC6DBBF45690F3A7E9E6D0F8BBEA2A39E6148008FD05E44"
		},
		/* 3 */{
			TEST_KEY_3, length(TEST_KEY_3),
			TEST_DATA_3, length(TEST_DATA_3),
			"7FB3CB3588C6C1F6FFA9694D7D6AD2649365B0C1F65D69D1EC8333EA"
		},
		/* 4 */{
			TEST_KEY_4, length(TEST_KEY_4),
			TEST_DATA_4, length(TEST_DATA_4),
			"6C11506874013CAC6A2ABC1BB382627CEC6A90D86EFC012DE7AFEC5A"
		},
		/* 5 */{
			TEST_KEY_5, length(TEST_KEY_5),
			TEST_DATA_5, length(TEST_DATA_5),
			"0E2AEA68A90C8D37C988BCDB9FCA6FA8099CD857C7EC4A1815CAC54C"
		},
		/* 6 */{
			TEST_KEY_6, length(TEST_KEY_6),
			TEST_DATA_6, length(TEST_DATA_6),
			"95E9A0DB962095ADAEBE9B2D6F0DBCE2D499F112F2D2B7273FA6870E"
		},
		/* 7 */{
			TEST_KEY_7, length(TEST_KEY_7),
			TEST_DATA_7b, length(TEST_DATA_7b),
			"3A854166AC5D9F023F54D517D0B39DBD946770DB9C2B95C9F6F565D1"
		}
	};

	for (HmacTest t : HAMC_TESTS)
	{
		string msg(t.test_array, t.test_array + t.test_array_size);
		string key(t.key_array, t.key_array + t.key_array_size);
	EXPECT_EQ(Hex::encode(Hmac::mac(msg, vector<byte>(key.begin(), key.end()), Hmac::HashScheme::SHA224)), t.result_array);
	}
}

TEST(HMAC, SHA256)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc6234#section-8.5">8.5.  The Test Driver</A>
	* for additional details.
	*/
	vector<HmacTest> HAMC_TESTS{
		/* 1 */{
			TEST_KEY_1, length(TEST_KEY_1),
			TEST_DATA_1, length(TEST_DATA_1),
			"B0344C61D8DB38535CA8AFCEAF0BF12B881DC200C9833DA726E9376C2E32"
			"CFF7"
		},
		/* 2 */{
			TEST_KEY_2, length(TEST_KEY_2),
			TEST_DATA_2, length(TEST_DATA_2),
			"5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC"
			"3843"
		},
		/* 3 */{
			TEST_KEY_3, length(TEST_KEY_3),
			TEST_DATA_3, length(TEST_DATA_3),
			"773EA91E36800E46854DB8EBD09181A72959098B3EF8C122D9635514CED5"
			"65FE"
		},
		/* 4 */{
			TEST_KEY_4, length(TEST_KEY_4),
			TEST_DATA_4, length(TEST_DATA_4),
			"82558A389A443C0EA4CC819899F2083A85F0FAA3E578F8077A2E3FF46729"
			"665B"
		},
		/* 5 */{
			TEST_KEY_5, length(TEST_KEY_5),
			TEST_DATA_5, length(TEST_DATA_5),
			"A3B6167473100EE06E0C796C2955552BFA6F7C0A6A8AEF8B93F860AAB0CD"
			"20C5"
		},
		/* 6 */{
			TEST_KEY_6, length(TEST_KEY_6),
			TEST_DATA_6, length(TEST_DATA_6),
			"60E431591EE0B67F0D8A26AACBF5B77F8E0BC6213728C5140546040F0EE3"
			"7F54"
		},
		/* 7 */{
			TEST_KEY_7, length(TEST_KEY_7),
			TEST_DATA_7b, length(TEST_DATA_7b),
			"9B09FFA71B942FCB27635FBCD5B0E944BFDC63644F0713938A7F51535C3A"
			"35E2"
		}
	};

	for (HmacTest t : HAMC_TESTS)
	{
		string msg(t.test_array, t.test_array + t.test_array_size);
		string key(t.key_array, t.key_array + t.key_array_size);
	EXPECT_EQ(Hex::encode(Hmac::mac(msg, vector<byte>(key.begin(), key.end()), Hmac::HashScheme::SHA256)), t.result_array);
	}
}

TEST(HMAC, SHA384)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc6234#section-8.5">8.5.  The Test Driver</A>
	* for additional details.
	*/
	vector<HmacTest> HAMC_TESTS{
		/* 1 */{
			TEST_KEY_1, length(TEST_KEY_1),
			TEST_DATA_1, length(TEST_DATA_1),
			"AFD03944D84895626B0825F4AB46907F15F9DADBE4101EC682AA034C7CEB"
			"C59CFAEA9EA9076EDE7F4AF152E8B2FA9CB6"
		},
		/* 2 */{
			TEST_KEY_2, length(TEST_KEY_2),
			TEST_DATA_2, length(TEST_DATA_2),
			"AF45D2E376484031617F78D2B58A6B1B9C7EF464F5A01B47E42EC3736322"
			"445E8E2240CA5E69E2C78B3239ECFAB21649"
		},
		/* 3 */{
			TEST_KEY_3, length(TEST_KEY_3),
			TEST_DATA_3, length(TEST_DATA_3),
			"88062608D3E6AD8A0AA2ACE014C8A86F0AA635D947AC9FEBE83EF4E55966"
			"144B2A5AB39DC13814B94E3AB6E101A34F27"
		},
		/* 4 */{
			TEST_KEY_4, length(TEST_KEY_4),
			TEST_DATA_4, length(TEST_DATA_4),
			"3E8A69B7783C25851933AB6290AF6CA77A9981480850009CC5577C6E1F57"
			"3B4E6801DD23C4A7D679CCF8A386C674CFFB"
		},
		/* 5 */{
			TEST_KEY_5, length(TEST_KEY_5),
			TEST_DATA_5, length(TEST_DATA_5),
			"3ABF34C3503B2A23A46EFC619BAEF897F4C8E42C934CE55CCBAE9740FCBC"
			"1AF4CA62269E2A37CD88BA926341EFE4AEEA"
		},
		/* 6 */{
			TEST_KEY_6, length(TEST_KEY_6),
			TEST_DATA_6, length(TEST_DATA_6),
			"4ECE084485813E9088D2C63A041BC5B44F9EF1012A2B588F3CD11F05033A"
			"C4C60C2EF6AB4030FE8296248DF163F44952"
		},
		/* 7 */{
			TEST_KEY_7, length(TEST_KEY_7),
			TEST_DATA_7b, length(TEST_DATA_7b),
			"6617178E941F020D351E2F254E8FD32C602420FEB0B8FB9ADCCEBB82461E"
			"99C5A678CC31E799176D3860E6110C46523E"
		}
	};

	for (HmacTest t : HAMC_TESTS)
	{
		string msg(t.test_array, t.test_array + t.test_array_size);
		string key(t.key_array, t.key_array + t.key_array_size);
	EXPECT_EQ(Hex::encode(Hmac::mac(msg, vector<byte>(key.begin(), key.end()), Hmac::HashScheme::SHA384)), t.result_array);
	}
}

TEST(HMAC, SHA512)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc6234#section-8.5">8.5.  The Test Driver</A>
	* for additional details.
	*/
	vector<HmacTest> HAMC_TESTS{
		/* 1 */{
			TEST_KEY_1, length(TEST_KEY_1),
			TEST_DATA_1, length(TEST_DATA_1),
			"87AA7CDEA5EF619D4FF0B4241A1D6CB02379F4E2CE4EC2787AD0B30545E1"
			"7CDEDAA833B7D6B8A702038B274EAEA3F4E4BE9D914EEB61F1702E696C20"
			"3A126854"
		},
		/* 2 */{
			TEST_KEY_2, length(TEST_KEY_2),
			TEST_DATA_2, length(TEST_DATA_2),
			"164B7A7BFCF819E2E395FBE73B56E0A387BD64222E831FD610270CD7EA25"
			"05549758BF75C05A994A6D034F65F8F0E6FDCAEAB1A34D4A6B4B636E070A"
			"38BCE737"
		},
		/* 3 */{
			TEST_KEY_3, length(TEST_KEY_3),
			TEST_DATA_3, length(TEST_DATA_3),
			"FA73B0089D56A284EFB0F0756C890BE9B1B5DBDD8EE81A3655F83E33B227"
			"9D39BF3E848279A722C806B485A47E67C807B946A337BEE8942674278859"
			"E13292FB"
		},
		/* 4 */{
			TEST_KEY_4, length(TEST_KEY_4),
			TEST_DATA_4, length(TEST_DATA_4),
			"B0BA465637458C6990E5A8C5F61D4AF7E576D97FF94B872DE76F8050361E"
			"E3DBA91CA5C11AA25EB4D679275CC5788063A5F19741120C4F2DE2ADEBEB"
			"10A298DD"
		},
		/* 5 */{
			TEST_KEY_5, length(TEST_KEY_5),
			TEST_DATA_5, length(TEST_DATA_5),
			"415FAD6271580A531D4179BC891D87A650188707922A4FBB36663A1EB16D"
			"A008711C5B50DDD0FC235084EB9D3364A1454FB2EF67CD1D29FE6773068E"
			"A266E96B"
		},
		/* 6 */{
			TEST_KEY_6, length(TEST_KEY_6),
			TEST_DATA_6, length(TEST_DATA_6),
			"80B24263C7C1A3EBB71493C1DD7BE8B49B46D1F41B4AEEC1121B013783F8"
			"F3526B56D037E05F2598BD0FD2215D6A1E5295E64F73F63F0AEC8B915A98"
			"5D786598"
		},
		/* 7 */{
			TEST_KEY_7, length(TEST_KEY_7),
			TEST_DATA_7b, length(TEST_DATA_7b),
			"E37B6A775DC87DBAA4DFA9F96E5E3FFDDEBD71F8867289865DF5A32D20CD"
			"C944B6022CAC3C4982B10D5EEB55C3E4DE15134676FB6DE0446065C97440"
			"FA8C6A58"
		}
	};

	for (HmacTest t : HAMC_TESTS)
	{
		string msg(t.test_array, t.test_array + t.test_array_size);
		string key(t.key_array, t.key_array + t.key_array_size);
	EXPECT_EQ(Hex::encode(Hmac::mac(msg, vector<byte>(key.begin(), key.end()), Hmac::HashScheme::SHA512)), t.result_array);
	}
}
