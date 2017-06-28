#pragma once

#include <ostream>
#include <sstream>
#include <random>
#include <iostream>
#include "../rsa.h"
using namespace std;

inline RSA* RSA_ReadPublicKey_Test()
{
	ostringstream sout;
	sout << "-----BEGIN PUBLIC KEY-----\n"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCupklvg4M62TpvbbISD8MrEb1h\n" <<
		"a2jW0bo4JshAUguKfWvc5w3B+59QmB4u6DANEemkmPBCVqgNACoM63L8q4Tl3WJo\n" <<
		"E1EQ735qaV2eRjweDroLtgLfVRGSzlZnajLFwhRqKO6/fId3J0kBLCVdZINfQbns\n" <<
		"DsqD6Wjyqf0z7DiWkQIDAQAB\n" <<
		"-----END PUBLIC KEY-----";
	string key_str = sout.str();
	return key(key_str, Crypto::Rsa::KEY_TYPE::PUBLIC_KEY);
}

inline RSA* RSA_ReadPrivateKey_Test()
{
	ostringstream sout;
	sout << "-----BEGIN RSA PRIVATE KEY-----\n" <<
		"MIICWwIBAAKBgQCupklvg4M62TpvbbISD8MrEb1ha2jW0bo4JshAUguKfWvc5w3B\n" <<
		"+59QmB4u6DANEemkmPBCVqgNACoM63L8q4Tl3WJoE1EQ735qaV2eRjweDroLtgLf\n" <<
		"VRGSzlZnajLFwhRqKO6/fId3J0kBLCVdZINfQbnsDsqD6Wjyqf0z7DiWkQIDAQAB\n" <<
		"AoGAIdore8jzA9IdSIHrtSKHAu8iVSK7pH/sZ3vk7sq4X/SllqDWgtYh8D48A32P\n" <<
		"6sihD/1w/HrNgg+ZFv4AQMeCL7X60wyC9+gPUkpWLXjemDgy6jlLr66TstbKMHeR\n" <<
		"0QGoZN+VrxjerPVHls6jDuTLg0o1YYUcKB60XhWdUUEjqpECQQDVwGFF5vxf0AWp\n" <<
		"oz8BNSMTheCXNsrRUii+JA4tU18prvCOR6DGy4YoKgPjFEUxixKxMu8EizdvVOyo\n" <<
		"0El1sdb9AkEA0StjDgYNzz0B3c59CMTwKdWfnnJCicQFWaxEce3WsgCevvoYWcL/\n" <<
		"kWDjFRNSHvhgw2EWLkRFlmIJ9HNz+dfUJQJBAMePfsGGb+T8D+1azb3Q4Fifyxki\n" <<
		"PKTEsekjPGEwz03ZWBld4kr3RN9Gqq5dBGTG1MK/LMvvNegpP3I0VAEf8fkCQDwN\n" <<
		"uOLN2ikl2uNT5ZIe+NUKAEn9hB0Jqn+UdhI/tuRkSS+LnnInCjkzF/91DJ7XsPBn\n" <<
		"b3bZIyGKBFGq1CFnVgECP0IpF8c6V1PBslZBM6rut/XbfGYzWd6/aKZmHGXUir/v\n" <<
		"LhnHN6B7gOM/zQNCfZQiMhxHFE7SfB8dF1qAsl9/sA==\n" <<
		"-----END RSA PRIVATE KEY-----" << endl;
	string key_str = sout.str();
	return key(key_str, Crypto::Rsa::KEY_TYPE::PRIVATE_KEY);
}

inline size_t RSA_PKEncode_SKDecode_Test(RSA* PK, RSA* SK, const Crypto::Rsa::RSA_PADDING& padding)
{
	size_t rsa_key_size = RSA_size(PK);

	random_device rd;
	default_random_engine random_engine(rd());
	uniform_int_distribution<unsigned> uniform_int(0, 0xff);

	size_t max_data_size = 0;
	switch (padding)
	{
	case Crypto::Rsa::RSA_PADDING::RSA_NoPadding:
		max_data_size = rsa_key_size - 1;
		break;
	case Crypto::Rsa::RSA_PADDING::RSA_PKCS1Padding:
		max_data_size = rsa_key_size - RSA_PKCS1_PADDING_SIZE - 1;
		break;
	case Crypto::Rsa::RSA_PADDING::RSA_OAEPPadding:
		max_data_size = rsa_key_size - 2 * SHA_DIGEST_LENGTH - 2;
		break;
	case Crypto::Rsa::RSA_PADDING::RSA_OAEPwithSHA224andMGF1Padding:
		max_data_size = rsa_key_size - 2 * SHA224_DIGEST_LENGTH - 2;
		break;
	case Crypto::Rsa::RSA_PADDING::RSA_OAEPwithSHA256andMGF1Padding:
		max_data_size = rsa_key_size - 2 * SHA256_DIGEST_LENGTH - 2;
		break;
	case Crypto::Rsa::RSA_PADDING::RSA_OAEPwithSHA384andMGF1Padding:
		max_data_size = rsa_key_size - 2 * SHA384_DIGEST_LENGTH - 2;
		break;
	case Crypto::Rsa::RSA_PADDING::RSA_OAEPwithSHA512andMGF1Padding:
		max_data_size = rsa_key_size - 2 * SHA512_DIGEST_LENGTH - 2;
		break;
	default: ;
	}
	size_t success = 0;
	vector<byte> rand_buffer(max_data_size);
	for (size_t i = 1; i <= max_data_size; ++i)
	{
		rand_buffer.resize(i);
		for (size_t j = 0; j < i; ++j)
		{
			rand_buffer[j] = uniform_int(random_engine);
		}
		if(padding == Crypto::Rsa::RSA_PADDING::RSA_NoPadding)
		{
			while (rand_buffer[0] == 0)
			{
				rand_buffer[0] = uniform_int(random_engine);
			}
		}

		try
		{
			vector<byte> encrypt_buffer = encode(rand_buffer, PK, padding);
			vector<byte> decrypt_buffer = decode(encrypt_buffer, SK, padding);
			if (rand_buffer == decrypt_buffer)
			{
				success++;
			}
		}
		catch (exception e)
		{
		}
	}
	return success;
}

inline int RSA_Test()
{
	cout << "RSA Public Key Read Test: ";
	RSA* rsa_public_key = RSA_ReadPublicKey_Test();
	if (rsa_public_key == nullptr)
	{
		cerr << "[Fail]" << endl;
		return -1;
	}
	cout << "[Success]" << endl;

	cout << "RSA Private Key Read Test: ";
	RSA* rsa_private_key = RSA_ReadPrivateKey_Test();
	if (rsa_private_key == nullptr)
	{
		RSA_free(rsa_public_key);
		cerr << "[Fail]" << endl;
		return -1;
	}
	cout << "[Success]" << endl;

	size_t success = 0;

	cout << "RSA PKEncode_SKDecode with NoPadding Test: ";
	success = RSA_PKEncode_SKDecode_Test(rsa_public_key, rsa_private_key, Crypto::Rsa::RSA_PADDING::RSA_NoPadding);
	cout << "[" << success << "]" << endl;

	cout << "RSA PKEncode_SKDecode with PKCS1Padding Test: ";
	success = RSA_PKEncode_SKDecode_Test(rsa_public_key, rsa_private_key, Crypto::Rsa::RSA_PADDING::RSA_PKCS1Padding);
	cout << "[" << success << "]" << endl;

	cout << "RSA PKEncode_SKDecode with OAEPPadding Test: ";
	success = RSA_PKEncode_SKDecode_Test(rsa_public_key, rsa_private_key, Crypto::Rsa::RSA_PADDING::RSA_OAEPPadding);
	cout << "[" << success << "]" << endl;

	cout << "RSA PKEncode_SKDecode with OAEPwithSHA1andMGF1Padding Test: ";
	success = RSA_PKEncode_SKDecode_Test(rsa_public_key, rsa_private_key, Crypto::Rsa::RSA_PADDING::RSA_OAEPwithSHA1andMGF1Padding);
	cout << "[" << success << "]" << endl;

	cout << "RSA PKEncode_SKDecode with OAEPwithSHA224andMGF1Padding Test: ";
	success = RSA_PKEncode_SKDecode_Test(rsa_public_key, rsa_private_key, Crypto::Rsa::RSA_PADDING::RSA_OAEPwithSHA224andMGF1Padding);
	cout << "[" << success << "]" << endl;

	cout << "RSA PKEncode_SKDecode with OAEPwithSHA256andMGF1Padding Test: ";
	success = RSA_PKEncode_SKDecode_Test(rsa_public_key, rsa_private_key, Crypto::Rsa::RSA_PADDING::RSA_OAEPwithSHA256andMGF1Padding);
	cout << "[" << success << "]" << endl;

	cout << "RSA PKEncode_SKDecode with OAEPwithSHA384andMGF1Padding Test: ";
	success = RSA_PKEncode_SKDecode_Test(rsa_public_key, rsa_private_key, Crypto::Rsa::RSA_PADDING::RSA_OAEPwithSHA384andMGF1Padding);
	cout << "[" << success << "]" << endl;

	RSA_free(rsa_public_key);
	RSA_free(rsa_private_key);
	return 0;
}
