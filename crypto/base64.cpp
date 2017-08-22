/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "base64.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

string crypto::encode::Base64::encode(const byte* msg, size_t msg_size)
{
	BIO* bio_mem = BIO_new(BIO_s_mem());
	if (bio_mem == nullptr)
	{
		std::bad_alloc();
	}

	BIO* bio_base64 = BIO_new(BIO_f_base64());
	if (bio_base64 == nullptr)
	{
		std::bad_alloc();
	}

	bio_mem = BIO_push(bio_base64, bio_mem);
	BIO_set_flags(bio_mem, BIO_FLAGS_BASE64_NO_NL);

	int read_size = BIO_write(bio_mem, msg, msg_size);
	if (read_size < 0)
	{
		throw std::runtime_error("[runtime_error] <base64.cpp> encode::Base64::encode(const byte*, size_t): " + string(ERR_error_string(ERR_get_error(), nullptr)));
	}

	BIO_flush(bio_mem);
	BUF_MEM* buf_mem;
	BIO_get_mem_ptr(bio_mem, &buf_mem);
	BIO_set_close(bio_mem, BIO_NOCLOSE);
	string out = string(buf_mem->data, buf_mem->length);

	BUF_MEM_free(buf_mem);
	BIO_free_all(bio_mem);
	return out;
}

string crypto::encode::Base64::encode(const vector<byte>& msg)
{
	return encode(msg.data(), msg.size());
}

string crypto::encode::Base64::encode(const string& msg)
{
	return encode(reinterpret_cast<const byte*>(msg.data()), msg.size());
}

vector<byte> crypto::encode::Base64::decode(const string& encoded)
{
	BIO* bio_mem = BIO_new_mem_buf(encoded.c_str(), encoded.length());
	BIO* bio_base64 = BIO_new(BIO_f_base64());
	bio_mem = BIO_push(bio_base64, bio_mem);
	BIO_set_flags(bio_mem, BIO_FLAGS_BASE64_NO_NL);

	vector<byte> out(encoded.length() * 3 / 4);
	int out_size = BIO_read(bio_mem, out.data(), encoded.length());
	BIO_free_all(bio_mem);

	if (out_size < 0)
	{
		throw std::runtime_error("[runtime_error] <base64.cpp> encode::Base64::decode(const string&): " + string(ERR_error_string(ERR_get_error(), nullptr)));
	}
	out.resize(out_size);
	return out;
}
