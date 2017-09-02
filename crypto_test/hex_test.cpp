#include "pch.h"

#include "../crypto/hex.h"
using crypto::encode::Hex;

/**
* \sa <A HREF="https://tools.ietf.org/html/rfc4648#section-10">10. Test Vectors</A>
* for additional details.
*/
vector<test> HEX_TESTS{
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
};

TEST(Hex, encode)
{
	for (test t : HEX_TESTS)
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
	for (test t : HEX_TESTS)
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
