#include "pch.h"

#include "../crypto/hex.h"
using crypto::encode::Hex;

#include "../crypto/hash.h"
using crypto::message::digest::Hash;

/**
* \sa <A HREF="https://tools.ietf.org/html/rfc4634#section-8.4">8.4.  The Test Driver</A>
* for additional details.
*/
/*
*  Define patterns for testing
*/
#define TEST1    "abc"
#define TEST2_1  \
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define TEST2_2a \
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
#define TEST2_2b \
        "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
#define TEST2_2  TEST2_2a TEST2_2b
#define TEST3    "a"                            /* times 1000000 */
#define TEST4a   "01234567012345670123456701234567"
#define TEST4b   "01234567012345670123456701234567"
/* an exact multiple of 512 bits */
#define TEST4   TEST4a TEST4b                   /* times 10 */

#define TEST7_1 \
  "\x49\xb2\xae\xc2\x59\x4b\xbe\x3a\x3b\x11\x75\x42\xd9\x4a\xc8"
#define TEST8_1 \
  "\x9a\x7d\xfd\xf1\xec\xea\xd0\x6e\xd6\x46\xaa\x55\xfe\x75\x71\x46"
#define TEST9_1 \
  "\x65\xf9\x32\x99\x5b\xa4\xce\x2c\xb1\xb4\xa2\xe7\x1a\xe7\x02\x20" \
  "\xaa\xce\xc8\x96\x2d\xd4\x49\x9c\xbd\x7c\x88\x7a\x94\xea\xaa\x10" \
  "\x1e\xa5\xaa\xbc\x52\x9b\x4e\x7e\x43\x66\x5a\x5a\xf2\xcd\x03\xfe" \
  "\x67\x8e\xa6\xa5\x00\x5b\xba\x3b\x08\x22\x04\xc2\x8b\x91\x09\xf4" \
  "\x69\xda\xc9\x2a\xaa\xb3\xaa\x7c\x11\xa1\xb3\x2a"
#define TEST10_1 \
  "\xf7\x8f\x92\x14\x1b\xcd\x17\x0a\xe8\x9b\x4f\xba\x15\xa1\xd5\x9f" \
  "\x3f\xd8\x4d\x22\x3c\x92\x51\xbd\xac\xbb\xae\x61\xd0\x5e\xd1\x15" \
  "\xa0\x6a\x7c\xe1\x17\xb7\xbe\xea\xd2\x44\x21\xde\xd9\xc3\x25\x92" \
  "\xbd\x57\xed\xea\xe3\x9c\x39\xfa\x1f\xe8\x94\x6a\x84\xd0\xcf\x1f" \
  "\x7b\xee\xad\x17\x13\xe2\xe0\x95\x98\x97\x34\x7f\x67\xc8\x0b\x04" \
  "\x00\xc2\x09\x81\x5d\x6b\x10\xa6\x83\x83\x6f\xd5\x56\x2a\x56\xca" \
  "\xb1\xa2\x8e\x81\xb6\x57\x66\x54\x63\x1c\xf1\x65\x66\xb8\x6e\x3b" \
  "\x33\xa1\x08\xb0\x53\x07\xc0\x0a\xff\x14\xa7\x68\xed\x73\x50\x60" \
  "\x6a\x0f\x85\xe6\xa9\x1d\x39\x6f\x5b\x5c\xbe\x57\x7f\x9b\x38\x80" \
  "\x7c\x7d\x52\x3d\x6d\x79\x2f\x6e\xbc\x24\xa4\xec\xf2\xb3\xa4\x27" \
  "\xcd\xbb\xfb"

#define TEST8_224 \
  "\x18\x80\x40\x05\xdd\x4f\xbd\x15\x56\x29\x9d\x6f\x9d\x93\xdf\x62"
#define TEST10_224 \
  "\x55\xb2\x10\x07\x9c\x61\xb5\x3a\xdd\x52\x06\x22\xd1\xac\x97\xd5" \
  "\xcd\xbe\x8c\xb3\x3a\xa0\xae\x34\x45\x17\xbe\xe4\xd7\xba\x09\xab" \
  "\xc8\x53\x3c\x52\x50\x88\x7a\x43\xbe\xbb\xac\x90\x6c\x2e\x18\x37" \
  "\xf2\x6b\x36\xa5\x9a\xe3\xbe\x78\x14\xd5\x06\x89\x6b\x71\x8b\x2a" \
  "\x38\x3e\xcd\xac\x16\xb9\x61\x25\x55\x3f\x41\x6f\xf3\x2c\x66\x74" \
  "\xc7\x45\x99\xa9\x00\x53\x86\xd9\xce\x11\x12\x24\x5f\x48\xee\x47" \
  "\x0d\x39\x6c\x1e\xd6\x3b\x92\x67\x0c\xa5\x6e\xc8\x4d\xee\xa8\x14" \
  "\xb6\x13\x5e\xca\x54\x39\x2b\xde\xdb\x94\x89\xbc\x9b\x87\x5a\x8b" \
  "\xaf\x0d\xc1\xae\x78\x57\x36\x91\x4a\xb7\xda\xa2\x64\xbc\x07\x9d" \
  "\x26\x9f\x2c\x0d\x7e\xdd\xd8\x10\xa4\x26\x14\x5a\x07\x76\xf6\x7c" \
  "\x87\x82\x73"

#define TEST8_256 \
  "\xe3\xd7\x25\x70\xdc\xdd\x78\x7c\xe3\x88\x7a\xb2\xcd\x68\x46\x52"
#define TEST10_256 \
  "\x83\x26\x75\x4e\x22\x77\x37\x2f\x4f\xc1\x2b\x20\x52\x7a\xfe\xf0" \
  "\x4d\x8a\x05\x69\x71\xb1\x1a\xd5\x71\x23\xa7\xc1\x37\x76\x00\x00" \
  "\xd7\xbe\xf6\xf3\xc1\xf7\xa9\x08\x3a\xa3\x9d\x81\x0d\xb3\x10\x77" \
  "\x7d\xab\x8b\x1e\x7f\x02\xb8\x4a\x26\xc7\x73\x32\x5f\x8b\x23\x74" \
  "\xde\x7a\x4b\x5a\x58\xcb\x5c\x5c\xf3\x5b\xce\xe6\xfb\x94\x6e\x5b" \
  "\xd6\x94\xfa\x59\x3a\x8b\xeb\x3f\x9d\x65\x92\xec\xed\xaa\x66\xca" \
  "\x82\xa2\x9d\x0c\x51\xbc\xf9\x33\x62\x30\xe5\xd7\x84\xe4\xc0\xa4" \
  "\x3f\x8d\x79\xa3\x0a\x16\x5c\xba\xbe\x45\x2b\x77\x4b\x9c\x71\x09" \
  "\xa9\x7d\x13\x8f\x12\x92\x28\x96\x6f\x6c\x0a\xdc\x10\x6a\xad\x5a" \
  "\x9f\xdd\x30\x82\x57\x69\xb2\xc6\x71\xaf\x67\x59\xdf\x28\xeb\x39" \
  "\x3d\x54\xd6"

#define TEST8_384 \
  "\xa4\x1c\x49\x77\x79\xc0\x37\x5f\xf1\x0a\x7f\x4e\x08\x59\x17\x39"
#define TEST10_384 \
  "\x39\x96\x69\xe2\x8f\x6b\x9c\x6d\xbc\xbb\x69\x12\xec\x10\xff\xcf" \
  "\x74\x79\x03\x49\xb7\xdc\x8f\xbe\x4a\x8e\x7b\x3b\x56\x21\xdb\x0f" \
  "\x3e\x7d\xc8\x7f\x82\x32\x64\xbb\xe4\x0d\x18\x11\xc9\xea\x20\x61" \
  "\xe1\xc8\x4a\xd1\x0a\x23\xfa\xc1\x72\x7e\x72\x02\xfc\x3f\x50\x42" \
  "\xe6\xbf\x58\xcb\xa8\xa2\x74\x6e\x1f\x64\xf9\xb9\xea\x35\x2c\x71" \
  "\x15\x07\x05\x3c\xf4\xe5\x33\x9d\x52\x86\x5f\x25\xcc\x22\xb5\xe8" \
  "\x77\x84\xa1\x2f\xc9\x61\xd6\x6c\xb6\xe8\x95\x73\x19\x9a\x2c\xe6" \
  "\x56\x5c\xbd\xf1\x3d\xca\x40\x38\x32\xcf\xcb\x0e\x8b\x72\x11\xe8" \
  "\x3a\xf3\x2a\x11\xac\x17\x92\x9f\xf1\xc0\x73\xa5\x1c\xc0\x27\xaa" \
  "\xed\xef\xf8\x5a\xad\x7c\x2b\x7c\x5a\x80\x3e\x24\x04\xd9\x6d\x2a" \
  "\x77\x35\x7b\xda\x1a\x6d\xae\xed\x17\x15\x1c\xb9\xbc\x51\x25\xa4" \
  "\x22\xe9\x41\xde\x0c\xa0\xfc\x50\x11\xc2\x3e\xcf\xfe\xfd\xd0\x96" \
  "\x76\x71\x1c\xf3\xdb\x0a\x34\x40\x72\x0e\x16\x15\xc1\xf2\x2f\xbc" \
  "\x3c\x72\x1d\xe5\x21\xe1\xb9\x9b\xa1\xbd\x55\x77\x40\x86\x42\x14" \
  "\x7e\xd0\x96"

#define TEST8_512 \
  "\x8d\x4e\x3c\x0e\x38\x89\x19\x14\x91\x81\x6e\x9d\x98\xbf\xf0\xa0"
#define TEST10_512 \
  "\xa5\x5f\x20\xc4\x11\xaa\xd1\x32\x80\x7a\x50\x2d\x65\x82\x4e\x31" \
  "\xa2\x30\x54\x32\xaa\x3d\x06\xd3\xe2\x82\xa8\xd8\x4e\x0d\xe1\xde" \
  "\x69\x74\xbf\x49\x54\x69\xfc\x7f\x33\x8f\x80\x54\xd5\x8c\x26\xc4" \
  "\x93\x60\xc3\xe8\x7a\xf5\x65\x23\xac\xf6\xd8\x9d\x03\xe5\x6f\xf2" \
  "\xf8\x68\x00\x2b\xc3\xe4\x31\xed\xc4\x4d\xf2\xf0\x22\x3d\x4b\xb3" \
  "\xb2\x43\x58\x6e\x1a\x7d\x92\x49\x36\x69\x4f\xcb\xba\xf8\x8d\x95" \
  "\x19\xe4\xeb\x50\xa6\x44\xf8\xe4\xf9\x5e\xb0\xea\x95\xbc\x44\x65" \
  "\xc8\x82\x1a\xac\xd2\xfe\x15\xab\x49\x81\x16\x4b\xbb\x6d\xc3\x2f" \
  "\x96\x90\x87\xa1\x45\xb0\xd9\xcc\x9c\x67\xc2\x2b\x76\x32\x99\x41" \
  "\x9c\xc4\x12\x8b\xe9\xa0\x77\xb3\xac\xe6\x34\x06\x4e\x6d\x99\x28" \
  "\x35\x13\xdc\x06\xe7\x51\x5d\x0d\x73\x13\x2e\x9a\x0d\xc6\xd3\xb1" \
  "\xf8\xb2\x46\xf1\xa9\x8a\x3f\xc7\x29\x41\xb1\xe3\xbb\x20\x98\xe8" \
  "\xbf\x16\xf2\x68\xd6\x4f\x0b\x0f\x47\x07\xfe\x1e\xa1\xa1\x79\x1b" \
  "\xa2\xf3\xc0\xc7\x58\xe5\xf5\x51\x86\x3a\x96\xc9\x49\xad\x47\xd7" \
  "\xfb\x40\xd2"

#define length(x) (sizeof(x)-1)

TEST(Hash, MD2)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc1320">A.5 Test suite</A>
	* for additional details.
	*/
	vector<test> HASH_TESTS{
		/* 1 */{
			"", 0, 1,
			"8350E5A3E24C153DF2275C9F80692773"
		},
		/* 2 */{
			"a", 1, 1,
			"32EC01EC4A6DAC72C0AB96FB34C0B5D1"
		},
		/* 3 */{
			"abc", 3, 1,
			"DA853B0D3F88D99B30283A69E6DED6BB"
		},
		/* 4 */{
			"message digest", 14, 1,
			"AB4F496BFB2A530B219FF33031FE06B0"
		},
		/* 5 */{
			"abcdefghijklmnopqrstuvwxyz", 26, 1,
			"4E8DDFF3650292AB5A4108C3AA47940B"
		},
		/* 6 */{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, 1,
			"DA33DEF2A42DF13975352846C30338CD"
		},
		/* 7 */{
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, 1,
			"D5976F79D83D3A0DC9806C3C66F3EFD8"
		},
	};

	for (test t : HASH_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
		EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::MD2)), t.result_array);
	}
}

TEST(Hash, MD4)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc1320">A.5 Test suite</A>
	* for additional details.
	*/
	vector<test> HASH_TESTS{
		/* 1 */{
			"", 0, 1,
			"31D6CFE0D16AE931B73C59D7E0C089C0"
		},
		/* 2 */{
			"a", 1, 1,
			"BDE52CB31DE33E46245E05FBDBD6FB24"
		},
		/* 3 */{
			"abc", 3, 1,
			"A448017AAF21D8525FC10AE87AA6729D"
		},
		/* 4 */{
			"message digest", 14, 1,
			"D9130A8164549FE818874806E1C7014B"
		},
		/* 5 */{
			"abcdefghijklmnopqrstuvwxyz", 26, 1,
			"D79E1C308AA5BBCDEEA8ED63DF412DA9"
		},
		/* 6 */{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, 1,
			"043F8582F241DB351CE627E153E7F0E4"
		},
		/* 7 */{
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, 1,
			"E33B4DDC9C38F2199C3E7B164FCC0536"
		},
	};

	for (test t : HASH_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
		EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::MD4)), t.result_array);
	}
}

TEST(Hash, MD5)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc1321">A.5 Test suite</A>
	* for additional details.
	*/
	vector<test> HASH_TESTS{
		/* 1 */{
			"", 0, 1,
			"D41D8CD98F00B204E9800998ECF8427E"
		},
		/* 2 */{
			"a", 1, 1,
			"0CC175B9C0F1B6A831C399E269772661"
		},
		/* 3 */{
			"abc", 3, 1,
			"900150983CD24FB0D6963F7D28E17F72"
		},
		/* 4 */{
			"message digest", 14, 1,
			"F96B697D7CB7938D525A2F31AAF161D0"
		},
		/* 5 */{
			"abcdefghijklmnopqrstuvwxyz", 26, 1,
			"C3FCD3D76192E4007DFB496CCA67E13B"
		},
		/* 6 */{
			"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", 62, 1,
			"D174AB98D277D9F5A5611C2C9F419D9F"
		},
		/* 7 */{
			"12345678901234567890123456789012345678901234567890123456789012345678901234567890", 80, 1,
			"57EDF4A22BE3C955AC49DA2E2107B67A"
		},
	};

	for (test t : HASH_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
	EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::MD5)), t.result_array);
	}
}

TEST(Hash, SHA1)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc4634#section-8.4">8.4.  The Test Driver</A>
	* for additional details.
	*/
	vector<test> HASH_TESTS{
		/* 1 */{
			TEST1, length(TEST1), 1,
			"A9993E364706816ABA3E25717850C26C9CD0D89D"
		},
		/* 2 */{
			TEST2_1, length(TEST2_1), 1,
			"84983E441C3BD26EBAAE4AA1F95129E5E54670F1"
		},
		/* 3 */{
			TEST3, length(TEST3), 1000000,
			"34AA973CD4C4DAA4F61EEB2BDBAD27316534016F"
		},
		/* 4 */{
			TEST4, length(TEST4), 10,
			"DEA356A2CDDD90C7A7ECEDC5EBB563934F460452"
		},
		/* 5 */{
			"", 0, 0,
			"DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"
		},
		/* 6 */{
			"\x5e", 1, 1,
			"5E6F80A34A9798CAFC6A5DB96CC57BA4C4DB59C2"
		},
		/* 8 */{
			TEST8_1, length(TEST8_1), 1,
			"82ABFF6605DBE1C17DEF12A394FA22A82B544A35"
		},
		/* 10 */{
			TEST10_1, length(TEST10_1), 1,
			"CB0082C8F197D260991BA6A460E76E202BAD27B3"
		}
	};

	for (test t : HASH_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
	EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::SHA1)), t.result_array);
	}
}

TEST(Hash, SHA224)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc4634#section-8.4">8.4.  The Test Driver</A>
	* for additional details.
	*/
	vector<test> HASH_TESTS{
		/* 1 */{
			TEST1, length(TEST1), 1,
			"23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7"
		},
		/* 2 */{
			TEST2_1, length(TEST2_1), 1,
			"75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525"
		},
		/* 3 */{
			TEST3, length(TEST3), 1000000,
			"20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67"
		},
		/* 4 */{
			TEST4, length(TEST4), 10,
			"567F69F168CD7844E65259CE658FE7AADFA25216E68ECA0EB7AB8262"
		},
		/* 5 */{
			"", 0, 0,
			"D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F"
		},
		/* 6 */{
			"\x07", 1, 1,
			"00ECD5F138422B8AD74C9799FD826C531BAD2FCABC7450BEE2AA8C2A"
		},
		/* 8 */{
			TEST8_224, length(TEST8_224), 1,
			"DF90D78AA78821C99B40BA4C966921ACCD8FFB1E98AC388E56191DB1"
		},
		/* 10 */{
			TEST10_224, length(TEST10_224), 1,
			"0B31894EC8937AD9B91BDFBCBA294D9ADEFAA18E09305E9F20D5C3A4"
		}
	};

	for (test t : HASH_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
	EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::SHA224)), t.result_array);
	}
}

TEST(Hash, SHA256)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc4634#section-8.4">8.4.  The Test Driver</A>
	* for additional details.
	*/
	vector<test> HASH_TESTS{
		/* 1 */{
			TEST1, length(TEST1), 1,
			"BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
		},
		/* 2 */{
			TEST2_1, length(TEST2_1), 1,
			"248D6A61D20638B8E5C026930C3E6039A33CE45964FF2167F6ECEDD419DB06C1"
		},
		/* 3 */{
			TEST3, length(TEST3), 1000000,
			"CDC76E5C9914FB9281A1C7E284D73E67F1809A48A497200E046D39CCC7112CD0"
		},
		/* 4 */{
			TEST4, length(TEST4), 10,
			"594847328451BDFA85056225462CC1D867D877FB388DF0CE35F25AB5562BFBB5"
		},
		/* 5 */{
			"", 0, 0,
			"E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
		},
		/* 6 */{
			"\x19", 1, 1,
			"68AA2E2EE5DFF96E3355E6C7EE373E3D6A4E17F75F9518D843709C0C9BC3E3D4"
		},
		/* 8 */{
			TEST8_256, length(TEST8_256), 1,
			"175EE69B02BA9B58E2B0A5FD13819CEA573F3940A94F825128CF4209BEABB4E8"
		},
		/* 10 */{
			TEST10_256, length(TEST10_256), 1,
			"97DBCA7DF46D62C8A422C941DD7E835B8AD3361763F7E9B2D95F4F0DA6E1CCBC"
		},
	};

	for (test t : HASH_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
	EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::SHA256)), t.result_array);
	}
}

TEST(Hash, SHA384)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc4634#section-8.4">8.4.  The Test Driver</A>
	* for additional details.
	*/
	vector<test> HASH_TESTS{
		/* 1 */{
			TEST1, length(TEST1), 1,
			"CB00753F45A35E8BB5A03D699AC65007272C32AB0EDED163"
			"1A8B605A43FF5BED8086072BA1E7CC2358BAECA134C825A7"
		},
		/* 2 */{
			TEST2_2, length(TEST2_2), 1,
			"09330C33F71147E83D192FC782CD1B4753111B173B3B05D2"
			"2FA08086E3B0F712FCC7C71A557E2DB966C3E9FA91746039"
		},
		/* 3 */{
			TEST3, length(TEST3), 1000000,
			"9D0E1809716474CB086E834E310A4A1CED149E9C00F24852"
			"7972CEC5704C2A5B07B8B3DC38ECC4EBAE97DDD87F3D8985"
		},
		/* 4 */{
			TEST4, length(TEST4), 10,
			"2FC64A4F500DDB6828F6A3430B8DD72A368EB7F3A8322A70"
			"BC84275B9C0B3AB00D27A5CC3C2D224AA6B61A0D79FB4596"
		},
		/* 5 */{
			"", 0, 0,
			"38B060A751AC96384CD9327EB1B1E36A21FDB71114BE0743"
			"4C0CC7BF63F6E1DA274EDEBFE76F65FBD51AD2F14898B95B"
		},
		/* 6 */{
			"\xb9", 1, 1,
			"BC8089A19007C0B14195F4ECC74094FEC64F01F90929282C"
			"2FB392881578208AD466828B1C6C283D2722CF0AD1AB6938"
		},
		/* 8 */{
			TEST8_384, length(TEST8_384), 1,
			"C9A68443A005812256B8EC76B00516F0DBB74FAB26D66591"
			"3F194B6FFB0E91EA9967566B58109CBC675CC208E4C823F7"
		},
		/* 10 */{
			TEST10_384, length(TEST10_384), 1,
			"4F440DB1E6EDD2899FA335F09515AA025EE177A79F4B4AAF"
			"38E42B5C4DE660F5DE8FB2A5B2FBD2A3CBFFD20CFF1288C0"
		}
	};

	for (test t : HASH_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
	EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::SHA384)), t.result_array);
	}
}

TEST(Hash, SHA512)
{
	/**
	* \sa <A HREF="https://tools.ietf.org/html/rfc4634#section-8.4">8.4.  The Test Driver</A>
	* for additional details.
	*/
	vector<test> HASH_TESTS{
		/* 1 */{
			TEST1, length(TEST1), 1,
			"DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA2"
			"0A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD"
			"454D4423643CE80E2A9AC94FA54CA49F"
		},
		/* 2 */{
			TEST2_2, length(TEST2_2), 1,
			"8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA1"
			"7299AEADB6889018501D289E4900F7E4331B99DEC4B5433A"
			"C7D329EEB6DD26545E96E55B874BE909"
		},
		/* 3 */{
			TEST3, length(TEST3), 1000000,
			"E718483D0CE769644E2E42C7BC15B4638E1F98B13B204428"
			"5632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31B"
			"EB009C5C2C49AA2E4EADB217AD8CC09B"
		},
		/* 4 */{
			TEST4, length(TEST4), 10,
			"89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024"
			"DB872D1ABD2BA8141A0F85072A9BE1E2AA04CF33C765CB51"
			"0813A39CD5A84C4ACAA64D3F3FB7BAE9"
		},
		/* 5 */{
			"", 0, 0,
			"CF83E1357EEFB8BDF1542850D66D8007D620E4050B5715DC"
			"83F4A921D36CE9CE47D0D13C5D85F2B0FF8318D2877EEC2F"
			"63B931BD47417A81A538327AF927DA3E"
		},
		/* 6 */{
			"\xD0", 1, 1,
			"9992202938E882E73E20F6B69E68A0A7149090423D93C81B"
			"AB3F21678D4ACEEEE50E4E8CAFADA4C85A54EA8306826C4A"
			"D6E74CECE9631BFA8A549B4AB3FBBA15"
		},
		/* 8 */{
			TEST8_512, length(TEST8_512), 1,
			"CB0B67A4B8712CD73C9AABC0B199E9269B20844AFB75ACBD"
			"D1C153C9828924C3DDEDAAFE669C5FDD0BC66F630F677398"
			"8213EB1B16F517AD0DE4B2F0C95C90F8"
		},
		/* 10 */{
			TEST10_512, length(TEST10_512), 1,
			"C665BEFB36DA189D78822D10528CBF3B12B3EEF726039909"
			"C1A16A270D48719377966B957A878E720584779A62825C18"
			"DA26415E49A7176A894E7510FD1451F5"
		}
	};

	for (test t : HASH_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
	EXPECT_EQ(Hex::encode(Hash::digest(msg, Hash::HashScheme::SHA512)), t.result_array);
	}
}
