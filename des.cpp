#include <vector>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include "type.h"
#include "des.h"
using std::vector;
using std::string;
using std::exception;

const EVP_CIPHER* Crypto::Des::GetMode(const DES_MODE& mode)
{
	const EVP_CIPHER* cipher_mode = nullptr;
	switch (mode)
	{
	case CBC:
		cipher_mode = EVP_des_cbc();
		break;
	case CFB:
		cipher_mode = EVP_des_cfb();
		break;
	case ECB:
		cipher_mode = EVP_des_ecb();
		break;
	case OFB:
		cipher_mode = EVP_des_ofb();
		break;
	default:
		throw exception("Mode is unsupported.");
	}
	return cipher_mode;
}

vector<byte> Crypto::Des::encode(const vector<byte>& data, vector<byte> key, const DES_MODE& mode, const DES_PADDING& padding)
{
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	EVP_CIPHER_CTX_init(ctx);
	EVP_CIPHER_CTX_set_padding(ctx, padding);
	const EVP_CIPHER* cipher_type = GetMode(mode);

	vector<byte> iv(8);
	int ret = EVP_EncryptInit_ex(ctx, cipher_type, nullptr, &key[0], &iv[0]);
	if (ret != 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}

	int cipher_text_buffer_length;
	byte* cipher_text_buffer = nullptr;
	ret = EVP_EncryptUpdate(ctx, cipher_text_buffer, &cipher_text_buffer_length, &data[0], data.size());
	if (ret != 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}

	ret = EVP_EncryptFinal_ex(ctx, cipher_text_buffer + cipher_text_buffer_length, &cipher_text_buffer_length);
	if (ret != 0)
	{
		throw exception(ERR_error_string(ERR_get_error(), nullptr));
	}
	vector<byte> cipher_text(cipher_text_buffer, cipher_text_buffer + cipher_text_buffer_length);
	EVP_CIPHER_CTX_cleanup(ctx);
	OPENSSL_free(cipher_text_buffer);
	return cipher_text;
}

vector<byte> Crypto::Des::decode(const vector<byte>& data, vector<byte> key, const DES_MODE& mode, const DES_PADDING& padding)
{
	return {};
}
