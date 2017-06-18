#pragma once

#ifndef __BASE64_H__
#define __BASE64_H__

#include <vector>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include "type.h"
using namespace std;

namespace Base64
{
	string encode(const byte* val, const size_t& length);
	string encode(const vector<byte>& val);
	vector<byte> decode(const string& str_base64);

	inline string encode(const byte* val, const size_t& length)
	{
		BIO* bio_mem = BIO_new(BIO_s_mem());
		if (bio_mem == nullptr)
		{
			ERR_print_errors_fp(stderr);
			throw exception("BIO_new");
		}
		BIO* bio_base64 = BIO_new(BIO_f_base64());
		if (bio_base64 == nullptr)
		{
			ERR_print_errors_fp(stderr);
			throw exception("BIO_new");
		}
		bio_mem = BIO_push(bio_base64, bio_mem);

		BIO_set_flags(bio_mem, BIO_FLAGS_BASE64_NO_NL); //No New Line

		int res = BIO_write(bio_mem, val, length);
		if (res < 0)
		{
			ERR_print_errors_fp(stderr);
			throw exception("BIO_write");
		}

		BIO_flush(bio_mem);
		BUF_MEM* buf_mem;
		BIO_get_mem_ptr(bio_mem, &buf_mem);
		BIO_set_close(bio_mem, BIO_NOCLOSE);
		string str_base64 = string((*buf_mem).data, (*buf_mem).length);

		BUF_MEM_free(buf_mem);
		BIO_free_all(bio_base64);
		BIO_free_all(bio_mem);
		return str_base64;
	}

	inline string encode(const vector<byte>& val)
	{
		return encode(&val[0], val.size());
	}

	inline vector<byte> decode(const string& str_base64)
	{
		BIO* bio_mem = BIO_new_mem_buf(str_base64.c_str(), str_base64.length());
		BIO* bio_base64 = BIO_new(BIO_f_base64());
		bio_mem = BIO_push(bio_base64, bio_mem);
		BIO_set_flags(bio_mem, BIO_FLAGS_BASE64_NO_NL); //No New Line

		byte* buffer = new byte[str_base64.length() * 3 / 4]{0};
		size_t length = BIO_read(bio_mem, buffer, str_base64.length());

		vector<byte> val(buffer, buffer + length);

		delete[]buffer;
		BIO_free_all(bio_base64);
		BIO_free_all(bio_mem);
		return val;
	}
}

#endif __BASE64_H__
