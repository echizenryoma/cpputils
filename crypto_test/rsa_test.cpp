#include "pch.h"

#include "../crypto/rsa.h"
using crypto::Rsa;

#include "../crypto/pkcs1padding.h"
using crypto::padding::PKCS1v15Padding;

#include "../crypto/oaepping.h"
using crypto::padding::OAEPwithHashandMGF1Padding;

#include "../crypto/base64.h"
using crypto::encode::Base64;


TEST(RSA, key)
{
	string privkey = "-----BEGIN RSA PRIVATE KEY-----\n"
		"MIICWwIBAAKBgQCupklvg4M62TpvbbISD8MrEb1ha2jW0bo4JshAUguKfWvc5w3B\n"
		"+59QmB4u6DANEemkmPBCVqgNACoM63L8q4Tl3WJoE1EQ735qaV2eRjweDroLtgLf\n"
		"VRGSzlZnajLFwhRqKO6/fId3J0kBLCVdZINfQbnsDsqD6Wjyqf0z7DiWkQIDAQAB\n"
		"AoGAIdore8jzA9IdSIHrtSKHAu8iVSK7pH/sZ3vk7sq4X/SllqDWgtYh8D48A32P\n"
		"6sihD/1w/HrNgg+ZFv4AQMeCL7X60wyC9+gPUkpWLXjemDgy6jlLr66TstbKMHeR\n"
		"0QGoZN+VrxjerPVHls6jDuTLg0o1YYUcKB60XhWdUUEjqpECQQDVwGFF5vxf0AWp\n"
		"oz8BNSMTheCXNsrRUii+JA4tU18prvCOR6DGy4YoKgPjFEUxixKxMu8EizdvVOyo\n"
		"0El1sdb9AkEA0StjDgYNzz0B3c59CMTwKdWfnnJCicQFWaxEce3WsgCevvoYWcL/\n"
		"kWDjFRNSHvhgw2EWLkRFlmIJ9HNz+dfUJQJBAMePfsGGb+T8D+1azb3Q4Fifyxki\n"
		"PKTEsekjPGEwz03ZWBld4kr3RN9Gqq5dBGTG1MK/LMvvNegpP3I0VAEf8fkCQDwN\n"
		"uOLN2ikl2uNT5ZIe+NUKAEn9hB0Jqn+UdhI/tuRkSS+LnnInCjkzF/91DJ7XsPBn\n"
		"b3bZIyGKBFGq1CFnVgECP0IpF8c6V1PBslZBM6rut/XbfGYzWd6/aKZmHGXUir/v\n"
		"LhnHN6B7gOM/zQNCfZQiMhxHFE7SfB8dF1qAsl9/sA==\n"
		"-----END RSA PRIVATE KEY-----";
	ASSERT_NO_THROW(Rsa::privkey(privkey));

	string pubkey = "-----BEGIN PUBLIC KEY-----\n"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCupklvg4M62TpvbbISD8MrEb1h\n"
		"a2jW0bo4JshAUguKfWvc5w3B+59QmB4u6DANEemkmPBCVqgNACoM63L8q4Tl3WJo\n"
		"E1EQ735qaV2eRjweDroLtgLfVRGSzlZnajLFwhRqKO6/fId3J0kBLCVdZINfQbns\n"
		"DsqD6Wjyqf0z7DiWkQIDAQAB\n"
		"-----END PUBLIC KEY-----";
	ASSERT_NO_THROW(Rsa::pubkey(pubkey));
}

TEST(RSA, OAEPwithSHA1andMGF1Padding)
{
	OAEPwithHashandMGF1Padding oaep(1024 / 8, OAEPwithHashandMGF1Padding::HashScheme::SHA1);
	vector<byte> plain;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	oaep.Pad(plain);
	oaep.Unpad(plain);
	EXPECT_EQ(Base64::encode(plain), "GcRqZtvZqfz0nww=");
}

TEST(RSA, PKCS1v15Padding)
{
	PKCS1v15Padding padding(1024 / 8);
	vector<byte> plain;

	plain = Base64::decode("GcRqZtvZqfz0nww=");
	padding.Pad(plain);
	padding.Unpad(plain);
	EXPECT_EQ(Base64::encode(plain), "GcRqZtvZqfz0nww=");
}
