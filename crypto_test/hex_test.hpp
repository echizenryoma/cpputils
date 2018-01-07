#pragma once

#include "pch.h"

#include "../crypto/hex.h"
using crypto::encode::Hex;

/**
* \sa <A HREF="https://tools.ietf.org/html/rfc4648#section-10">10. Test Vectors</A>
* for additional details.
*/
vector<test_case> HEX_TESTS{
	/* 1 */{
		"", 0,
		1,
		""
	},
	/* 2 */{
		"f", 1,
		1,
		"66"
	},
	/* 3 */{
		"fo", 2,
		1,
		"666F"
	},
	/* 4 */{
		"foo", 3,
		1,
		"666F6F"
	},
	/* 5 */{
		"foob", 4,
		1,
		"666F6F62"
	},
	/* 6 */{
		"fooba", 5,
		1,
		"666F6F6261"
	},
	/* 7 */{
		"foobar", 6,
		1,
		"666F6F626172"
	},
	/* 8 */{
		"Send reinforcements", 19,
		1,
		"53656E64207265696E666F7263656D656E7473"
	},
	/* 9 */{
		"Now is the time for all good coders\nto learn Ruby", 49,
		1,
		"4E6F77206973207468652074696D6520666F7220616C6C20676F6F6420636F646572730A746F206C6561726E2052756279"
	},
	/* 10 */{
		"This is line one\nThis is line two\nThis is line three\nAnd so on...\n", 66,
		1,
		"54686973206973206C696E65206F6E650A54686973206973206C696E652074776F0A54686973206973206C696E652074687265650A416E6420736F206F6E2E2E2E0A"
	},
	/* 11 */{
		"\0", 1,
		1,
		"00"
	},
	/* 12 */{
		"\0\0", 2,
		1,
		"0000"
	},
	/* 13 */{
		"\0\0\0", 3,
		1,
		"000000"
	},
	/* 13 */{
		"\377", 1,
		1,
		"FF"
	},
	/* 14 */{
		"\377\377", 2,
		1,
		"FFFF"
	},
	/* 15 */{
		"\377\377\377", 3,
		1,
		"FFFFFF"
	},
	/* 16 */{
		"\xff\xef", 2,
		1,
		"FFEF"
	},
};

TEST(Hex, encode)
{
	for (test_case t : HEX_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
	EXPECT_EQ(Hex::encode(msg), t.result_array);
	}
}

TEST(Hex, decode)
{
	for (test_case t : HEX_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
	EXPECT_EQ(bytes2str(Hex::decode(t.result_array)), msg);
	}
}
