#include "pch.h"
#include "../libcrypto/base64.h"
using crypto::encode::Base64;

/**
* \sa <A HREF="https://tools.ietf.org/html/rfc4648#section-10">10. Test Vectors</A>
* for additional details.
*/
vector<test> BASE64_TESTS{
	/* 1 */{
		"", 0,
		1,
		""
	},
	/* 2 */{
		"f", 1,
		1,
		"Zg=="
	},
	/* 3 */{
		"fo", 2,
		1,
		"Zm8="
	},
	/* 4 */{
		"foo", 3,
		1,
		"Zm9v"
	},
	/* 5 */{
		"foob", 4,
		1,
		"Zm9vYg=="
	},
	/* 6 */{
		"fooba", 5,
		1,
		"Zm9vYmE="
	},
	/* 7 */{
		"foobar", 6,
		1,
		"Zm9vYmFy"
	},
	/* 8 */{
		"Send reinforcements", 19,
		1,
		"U2VuZCByZWluZm9yY2VtZW50cw=="
	},
	/* 9 */{
		"Now is the time for all good coders\nto learn Ruby", 49,
		1,
		"Tm93IGlzIHRoZSB0aW1lIGZvciBhbGwgZ29vZCBjb2RlcnMKdG8gbGVhcm4gUnVieQ=="
	},
	/* 10 */{
		"This is line one\nThis is line two\nThis is line three\nAnd so on...\n", 66,
		1,
		"VGhpcyBpcyBsaW5lIG9uZQpUaGlzIGlzIGxpbmUgdHdvClRoaXMgaXMgbGluZSB0aHJlZQpBbmQgc28gb24uLi4K"
	},
	/* 11 */{
		"\0", 1,
		1,
		"AA=="
	},
	/* 12 */{
		"\0\0", 2,
		1,
		"AAA="
	},
	/* 13 */{
		"\0\0\0", 3,
		1,
		"AAAA"
	},
	/* 13 */{
		"\377", 1,
		1,
		"/w=="
	},
	/* 14 */{
		"\377\377", 2,
		1,
		"//8="
	},
	/* 15 */{
		"\377\377\377", 3,
		1,
		"////"
	},
	/* 16 */{
		"\xff\xef", 2,
		1,
		"/+8="
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
