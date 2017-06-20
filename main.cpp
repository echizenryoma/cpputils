#include <iostream>
#include <string>
#include <sstream>
#include "base64.h"
#include "hash.h"
#include "hex.h"
#include "rsa.h"
#include "hmac.h"
using namespace std;

int main(int argc, char** argv)
{
	ostringstream sout;
	sout << "-----BEGIN PUBLIC KEY-----\n"
		"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCupklvg4M62TpvbbISD8MrEb1h\n" <<
		"a2jW0bo4JshAUguKfWvc5w3B+59QmB4u6DANEemkmPBCVqgNACoM63L8q4Tl3WJo\n" <<
		"E1EQ735qaV2eRjweDroLtgLfVRGSzlZnajLFwhRqKO6/fId3J0kBLCVdZINfQbns\n" <<
		"DsqD6Wjyqf0z7DiWkQIDAQAB\n" <<
		"-----END PUBLIC KEY-----";
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
	RSA* public_key = key(public_key_string, Crypto::Rsa::KEY_TYPE::PUBLIC_KEY);
	RSA* private_key = key(priave_key_string, Crypto::Rsa::KEY_TYPE::PRIVATE_KEY);
	string str = "0123456789ABCDEF";
	vector<byte> param(str.length());
	cout << Base64::encode(Crypto::Rsa::encode(vector<byte>(str.begin(), str.end()), public_key, Crypto::Rsa::RSA_PADDING::RSA_OAEPPadding)) << endl;
	RSA_free(public_key);

	vector<byte> results = Crypto::Rsa::decode(Base64::decode("V/Et5H/pJ1ePQF3nFPKEzooyn95NZaVFf9SFTK8pjJ5KCnYv4OmlIJs5ioSYHKWvLQGsEyxZIp7RGnHXumIf9mDYCxZBKqNyzvw8Omy1DstFBcp7Q1N/Ih2hCJ7+lyDI659RDuP176Jb02XW8SLRAunDdjsI3RLY5ACaENdBFcE="), private_key);
	cout << Hex::encode(results) << endl;
	RSA_free(private_key);

	cout << Hash::md4(vector<byte>(str.begin(), str.end())) << endl;
	cout << Hash::md5(vector<byte>(str.begin(), str.end())) << endl;
	cout << Hash::sha1(vector<byte>(str.begin(), str.end())) << endl;
	cout << Hash::sha256(vector<byte>(str.begin(), str.end())) << endl;
	cout << Hash::sha512(vector<byte>(str.begin(), str.end())) << endl;

	string key = "key";
	cout << Hmac::hamc_md5(vector<byte>(key.begin(), key.end()), vector<byte>(str.begin(), str.end())) << endl;
	cout << Hmac::hamc_sha1(vector<byte>(key.begin(), key.end()), vector<byte>(str.begin(), str.end())) << endl;
	cout << Hmac::hamc_sha256(vector<byte>(key.begin(), key.end()), vector<byte>(str.begin(), str.end())) << endl;
	cout << Hmac::hamc_sha512(vector<byte>(key.begin(), key.end()), vector<byte>(str.begin(), str.end())) << endl;

	CRYPTO_cleanup_all_ex_data();
	return 0;
}
