#include "pch.h"

#include "../crypto/rsa.h"
using crypto::Rsa;

#include "../crypto/pkcs1padding.h"
using crypto::padding::PKCS1v15Padding;

#include "../crypto/oaepping.h"
using crypto::padding::OAEPwithHashandMGF1Padding;

#include "../crypto/base64.h"
using crypto::encode::Base64;

const string PUBLIC_KEY_STR = "-----BEGIN PUBLIC KEY-----\n"
	"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCupklvg4M62TpvbbISD8MrEb1h\n"
	"a2jW0bo4JshAUguKfWvc5w3B+59QmB4u6DANEemkmPBCVqgNACoM63L8q4Tl3WJo\n"
	"E1EQ735qaV2eRjweDroLtgLfVRGSzlZnajLFwhRqKO6/fId3J0kBLCVdZINfQbns\n"
	"DsqD6Wjyqf0z7DiWkQIDAQAB\n"
	"-----END PUBLIC KEY-----";
RSA_ptr RSA_PUBLIC_KEY = Rsa::pubkey(PUBLIC_KEY_STR);

const string PRIVATE_KEY_STR = "-----BEGIN RSA PRIVATE KEY-----\n"
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
RSA_ptr RSA_PRIVATE_KEY = Rsa::privkey(PRIVATE_KEY_STR);


TEST(RSA, NoPadding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ptext = Base64::decode("GcRqZtvZqfz0nww=");
	ctext = Rsa::encrypt(ptext, RSA_PUBLIC_KEY, Rsa::KeyType::PublicKey, Rsa::PaddingScheme::NoPadding);
	EXPECT_EQ(Base64::encode(ctext), "pzBDwFqxfJOu9qtlnK/XVEJ9wE4iH8/DiVv+fvQ91eUcJgBeTtameNT3SBXxbnOlM5Q1Jbo2bJ45G3/qPMJ37kCF+xprUqQqvokfIVgbTt0YZzgeiW8fMoI1j5Wc/Rb/AJL2DvW3QYJx7CmO+0xz4RKE1JuaESQKVhHd3cNFVm0=");

	ptext = Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY=");
	ctext = Rsa::encrypt(ptext, RSA_PUBLIC_KEY, Rsa::KeyType::PublicKey, Rsa::PaddingScheme::NoPadding);
	EXPECT_EQ(Base64::encode(ctext), "InqdAC5hM6SCuvEzqdVnxbXtM2uXtJ37PC/+GqlrggbExYorlSZtDtrZ1qrKIF5k+Qtc5skUSWXeVWDpnTI0AnqNF2NfLRLyhhJdR2kpZ87slkikBXJe3U1vKTFhFzVoxUzMcNkGXFl/Orrl/Md9ujdxsFSSD0jBU/FyUlG7KE4=");

	ptext = Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
	ctext = Rsa::encrypt(ptext, RSA_PUBLIC_KEY, Rsa::KeyType::PublicKey, Rsa::PaddingScheme::NoPadding);
	EXPECT_EQ(Base64::encode(ctext), "hAF1NdBHfEBQaef3CdoaemuCDRYui8GzekaVNOeIUhqgOaeSJbzTJITS61ei07EStSNPXTWMjN+E/Vh24+T8J/olrBUmKyxJgo0DaRhE2/jRumdMfunt1S4dYvJ+TS8PRVCciXrZkSGF/NtxJxw2jJ8gWaqSo9K4rHC6B+bMvdg=");
}


TEST(RSA, OAEPwithSHA1andMGF1Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ctext = Base64::decode("TuWMFF3P7kadwf+AhqFN0xBfGbvVsrNJwB6lstnaMgVbKu7LiC1cgNpKHdmgttDWJfBl3qWgakTayqHNuYNwhYoyGdxqdbBxDne5L3SN7PAIaKhO4J9Ef4a2up8iAKqRemvEdRGKLTeFxZwSWdrpC3luUFDlKSx9XV+LwCw6ASA=");
	ptext = Rsa::decrypt(ctext, RSA_PRIVATE_KEY, Rsa::KeyType::PrivateKey, Rsa::PaddingScheme::OAEPwithSHA1andMGF1Padding);
	EXPECT_EQ(Base64::encode(ptext), "GcRqZtvZqfz0nww=");

	ctext = Base64::decode("IR7BaC/UOnM4UQQypIl/yZDxOvy2dBywXVXlLcDXyZ7jZ7N58PW8ds6JLArxni8be5DE6XZMmd7EUfPu/yKo32CeabeJkFU27H+oV02ZoZMKxQi44LLpVW+pCdYORurDlyParKUdf66Q4T7w4LpCmknpetSFDJOLXIwSu5JhWpc=");
	ptext = Rsa::decrypt(ctext, RSA_PRIVATE_KEY, Rsa::KeyType::PrivateKey, Rsa::PaddingScheme::OAEPwithSHA1andMGF1Padding);
	EXPECT_EQ(Base64::encode(ptext), "tQJT13nQjQeKScukjRt11lT3DjY=");

	ctext = Base64::decode("cc2r58bW8Yne0iY3Caa0NBgsi4RuYcNzOxmdW/nDf97fvk6+YteWfKRqddB9vhHvgbubShMFhtgk9bfstQGwlxTgKGqxOPOlIt2Q1M+aiLMsk5SRQo+57Vx6uvjbvBMDazH+NaNE+ZIYgoTYSdQubTwv6pIpZdQKrHRWtfm9mr8=");
	ptext = Rsa::decrypt(ctext, RSA_PRIVATE_KEY, Rsa::KeyType::PrivateKey, Rsa::PaddingScheme::OAEPwithSHA1andMGF1Padding);
	EXPECT_EQ(Base64::encode(ptext), "joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
}

TEST(RSA, PKCS1v15Padding)
{
	vector<byte> ptext;
	vector<byte> ctext;

	ctext = Base64::decode("eKOGJNkfFhBx76F6Ga+9AomnGn1kWa5kKqKH21XjZFOpqd43+jWGoW/cXM4Qq6Lt/oP9lVZh42xNcPL0n2/7oJaWmoKgzVlAC8G3ZVw01UplFsHBCs3oTKayxEdQvaFNvIbwGWOpNqah2M93IZrEnisv9lK0d6t/1IZVaeSVCIE=");
	ptext = Rsa::decrypt(ctext, RSA_PRIVATE_KEY, Rsa::KeyType::PrivateKey, Rsa::PaddingScheme::PKCS1Padding);
	EXPECT_EQ(Base64::encode(ptext), "GcRqZtvZqfz0nww=");

	ctext = Base64::decode("jw6JaQi6zIBozAC0JMW8eXf6Zg7BoRBwDJJi3UXlEZNXhp17k2IOSrumKUFZ4dC4tabBPH8uHINpap8O53IdQuSabgq9qo8qH1624XsUh7ZhhcvlvWUbbwti4ZCj2oIIDCm6fV/iHrHmppK5JC0fb+NM6kDAL+3cHDnZ58o/VV8=");
	ptext = Rsa::decrypt(ctext, RSA_PRIVATE_KEY, Rsa::KeyType::PrivateKey, Rsa::PaddingScheme::PKCS1Padding);
	EXPECT_EQ(Base64::encode(ptext), "tQJT13nQjQeKScukjRt11lT3DjY=");

	ctext = Base64::decode("IBytQHv60nNYDLHTwvR23y/EgWRj9ue6bsoLfCpVWiZCAQxr0YUFWYUZZMALIxjAKzoYWYGF90DDgIwK3+TNCBVlryQHUSHv8a9QkiFCu4QBwTuKUiLBctcla9CgOX9pBooLRebcphZU6AuX3nTzciEoDaSRDLqWXglbF6hNSH8=");
	ptext = Rsa::decrypt(ctext, RSA_PRIVATE_KEY, Rsa::KeyType::PrivateKey, Rsa::PaddingScheme::PKCS1Padding);
	EXPECT_EQ(Base64::encode(ptext), "joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI=");
}
