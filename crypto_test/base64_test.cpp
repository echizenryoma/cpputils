#include "pch.h"
#include "../crypto/base64.h"
using crypto::encode::Base64;

/**
* \sa <A HREF="https://tools.ietf.org/html/rfc4648#section-10">10. Test Vectors</A>
* for additional details.
*/
vector<test> BASE64_TESTS{
	{
		"", 0,
		1,
		""
	},
	{
		"f", 1,
		1,
		"Zg=="
	},
	{
		"fo", 2,
		1,
		"Zm8="
	},
	{
		"foo", 3,
		1,
		"Zm9v"
	},
	{
		"foob", 4,
		1,
		"Zm9vYg=="
	},
	{
		"fooba", 5,
		1,
		"Zm9vYmE="
	},
	{
		"foobar", 6,
		1,
		"Zm9vYmFy"
	},
};

TEST(Base64, encode)
{
	for (test t : BASE64_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
		EXPECT_EQ(Base64::encode(msg), t.result_array);
	}
}

TEST(Base64, decode)
{
	for (test t : BASE64_TESTS)
	{
		string msg;
		const string test_str(t.test_array, t.test_array + t.test_array_size);
		for (int i = 0; i < t.repeat_count; ++i)
		{
			msg += test_str;
		}
		EXPECT_EQ(bytes2str(Base64::decode(t.result_array)), msg);
	}
}
