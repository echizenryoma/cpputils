#include <iostream>
#include <string>
#include <sstream>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "base64.h"
#include "hex.h"
#include "convert.h"
#include "rsa.h"
using namespace std;

RSA* RSALoadPublicKey(const string& public_key_string)
{
	BIO* public_key_content = BIO_new_mem_buf(public_key_string.c_str(), public_key_string.length());
	if (public_key_content == nullptr)
	{
		return nullptr;
	}
	RSA* rsa_public_key = PEM_read_bio_RSA_PUBKEY(public_key_content, nullptr, nullptr, nullptr);
	ERR_print_errors_fp(stderr);
	if (rsa_public_key == nullptr)
	{
		throw exception("PEM_read_bio_RSA_PUBKEY");
	}
	BIO_free(public_key_content);
	return rsa_public_key;
}

string RSAEncrypt_PublicKey(RSA* public_key, string data)
{
	unsigned int rsa_key_size = RSA_size(public_key);
	unsigned char* plain_text = new unsigned char[rsa_key_size] {0};
	for (unsigned int i = 0; i < data.length(); ++i)
	{
		plain_text[rsa_key_size - data.length() + i] = static_cast<unsigned char>(data[i]);
	}
	//RSA_set_default_method(RSA_null_method());
	unsigned char* encrypt_data = new unsigned char[rsa_key_size]{0};
	int encrypt_data_length = RSA_public_encrypt(rsa_key_size, reinterpret_cast<const unsigned char*>(plain_text), encrypt_data, public_key, RSA_NO_PADDING);
	ERR_print_errors_fp(stderr);
	if (encrypt_data_length == -1)
	{
		throw exception("RSA_public_encrypt");
	}
	string base64 = Base64::encode(encrypt_data, encrypt_data_length);

	delete []plain_text;
	plain_text = nullptr;
	delete []encrypt_data;
	encrypt_data = nullptr;

	return base64;
}


int main(int argc, char** argv)
{
//	string str = "面面面面面面様様様様様様";
//	wstring wstr = string2wstring(str, Convert::String::CharacterSetType::GB2312);
//
//
//	string data = "0123456789ABCDEF";
//	string hex_string = Hex::encode(reinterpret_cast<const byte*>(data.c_str()), data.length());
//	cout << hex_string << endl;
//	vector<byte> byte_array = Hex::decode(hex_string);


	ostringstream sout;
	sout << "-----BEGIN PUBLIC KEY-----\n" <<
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgkB5vTONXv15SukpyFKKbkO3m\n" <<
		"MbZ8z4u8HwtV14qEoOJaOhh6pu75o6bojX3RFnWm3wHxFjmdJu1+JurChFiY2fxD\n" <<
		"Q+SZWXKzNvfK/fvi3JNMfgVfp0HcuCzKDWE+vPeactLeTNnjFRYlnaUygiwm0KNE\n" <<
		"hDDHw2/41xjcPLmPpQIDAQAB\n" <<
		"-----END PUBLIC KEY-----\n";
	//	sout << "-----BEGIN PUBLIC KEY-----\n"
	//		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCupklvg4M62TpvbbISD8MrEb1h\n" <<
	//		"a2jW0bo4JshAUguKfWvc5w3B+59QmB4u6DANEemkmPBCVqgNACoM63L8q4Tl3WJo\n" <<
	//		"E1EQ735qaV2eRjweDroLtgLfVRGSzlZnajLFwhRqKO6/fId3J0kBLCVdZINfQbns\n" <<
	//		"DsqD6Wjyqf0z7DiWkQIDAQAB\n" <<
	//		"-----END PUBLIC KEY-----";
	string public_key_string = sout.str();
	cout << public_key_string << endl;

	sout.clear();
	sout.seekp(0);

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
	string priave_key_string = sout.str();

	cout << priave_key_string << endl;
	RSA* public_key = Crypto::Rsa::key(public_key_string, Crypto::Rsa::KEY_TYPE::PUBLIC_KEY);
	RSA* private_key = Crypto::Rsa::key(priave_key_string, Crypto::Rsa::KEY_TYPE::PRIVATE_KEY);
	cout << RSAEncrypt_PublicKey(public_key, "0123456789ABCDEF") << endl;
	RSA_free(public_key);

	vector<byte> results = Crypto::Rsa::decode(Base64::decode("NTFJbV3UWkeglVIkgGxdII583QuvA8ZNxRgXVpOSp8Stx3Dzfk1ttNofDH82nYo95k+oY5VyjvE1qxAtEM1kbdgqpYYpazcCbBbbVsSJl6kxj0O52il+4FGfwXj4naAxixOG7VuiSkwI6oPZ393d0k87KtT0CiYDU1VXdeIZ9es="), private_key);

	RSA_free(private_key);

	CRYPTO_cleanup_all_ex_data();
	return 0;
}
