/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "base64.h"

string crypto::encode::Base64::encode(const string& msg)
{
	BIO* bio_mem = BIO_new(BIO_s_mem());
	if (bio_mem == nullptr)
	{
		throw bad_alloc();
	}

	BIO* bio_base64 = BIO_new(BIO_f_base64());
	if (bio_base64 == nullptr)
	{
		throw bad_alloc();
	}

	bio_mem = BIO_push(bio_base64, bio_mem);
	BIO_set_flags(bio_mem, BIO_FLAGS_BASE64_NO_NL);

	if (BIO_write(bio_mem, msg.data(), static_cast<int64_t>(msg.size())) < 0 || BIO_flush(bio_mem) < 0)
	{
		BIO_free_all(bio_mem);
		throw runtime_error("[runtime_error] <base64.cpp> crypto::encode::Base64::encode(const string&): " + string(ERR_error_string(ERR_get_error(), nullptr)));
	}

	BUF_MEM* buf_mem;
	BIO_get_mem_ptr(bio_mem, &buf_mem);
	BIO_set_close(bio_mem, BIO_NOCLOSE);
	string base64_str = string(buf_mem->data, buf_mem->length);

	BUF_MEM_free(buf_mem);
	BIO_free_all(bio_mem);
	return base64_str;
}

string crypto::encode::Base64::encode(const vector<byte>& msg)
{
	return encode(string(msg.begin(), msg.end()));
}

vector<byte> crypto::encode::Base64::decode(const string& base64_str)
{
	BIO* bio_mem = BIO_new_mem_buf(base64_str.c_str(), base64_str.size());
	BIO* bio_base64 = BIO_new(BIO_f_base64());
	bio_mem = BIO_push(bio_base64, bio_mem);
	BIO_set_flags(bio_mem, BIO_FLAGS_BASE64_NO_NL);

	vector<byte> msg(base64_str.length() * 3 / 4, 0);
	const int msg_length = BIO_read(bio_mem, msg.data(), msg.size());	
	if (BIO_read(bio_mem, msg.data(), msg.size()) < 0)
	{
		BIO_free_all(bio_mem);
		throw runtime_error("[runtime_error] <base64.cpp> crypto::encode::Base64::decode(const string&): " + string(ERR_error_string(ERR_get_error(), nullptr)));
	}
	BIO_free_all(bio_mem);
	msg.resize(msg_length);
	return msg;
}
