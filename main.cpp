#include <iostream>
#include <string>
#include <sstream>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include "base64.h"
#include "hex.h"
#include "convert.h"
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
	string str = "面面面面面面様様様様様様";
	wstring wstr = string2wstring(str, Convert::String::CharacterSetType::GB2312);


	string data = "weoncvm";
	string hex_string = Hex::encode(reinterpret_cast<const byte*>(data.c_str()), data.length());
	cout << hex_string << endl;
	vector<byte> byte_array = Hex::decode(hex_string);


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
	RSA* public_key = RSALoadPublicKey(public_key_string);
	cout << RSAEncrypt_PublicKey(public_key, "0123456789ABCDEF") << endl;
	RSA_free(public_key);
	CRYPTO_cleanup_all_ex_data();

	public_key = RSALoadPublicKey(public_key_string);
	cout << RSAEncrypt_PublicKey(public_key, "0123456d789ABCDEF") << endl;
	RSA_free(public_key);
	CRYPTO_cleanup_all_ex_data();
	return 0;
}
