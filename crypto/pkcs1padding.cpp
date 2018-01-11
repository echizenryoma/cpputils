/*
* Copyright (c) 2012, 2017, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#include "pch.h"
#include "pkcs1padding.h"

crypto::padding::PKCS1v15Padding::PKCS1v15Padding(size_t block_size, uint8_t type_version): block_size_(block_size), type_version_(type_version)
{
}

void crypto::padding::PKCS1v15Padding::Pad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte> out(block_size_);

	int rc;
	switch (type_version_)
	{
	case PUBLIC_KEY_OPERATION:
		rc = RSA_padding_add_PKCS1_type_1(
			out.data(), out.size(),
			in.data(), in.size()
		);
		if (rc != 1)
		{
			throw std::runtime_error("[runtime_error] <pkcs1padding.cpp> crypto::padding::PKCS1v15Padding::Pad(vector<byte>&) const: {RSA_padding_add_PKCS1_type_1} fail.");
		}
		break;
	case PRIVATE_KEY_OPERATION:
		rc = RSA_padding_add_PKCS1_type_2(
			out.data(), out.size(),
			in.data(), in.size()
		);
		if (rc != 1)
		{
			throw std::runtime_error("[runtime_error] <pkcs1padding.cpp> crypto::padding::PKCS1v15Padding::Pad(vector<byte>&) const: {RSA_padding_add_PKCS1_type_2} fail.");
		}
		break;
	default: 
		throw std::invalid_argument("[invalid_argument] <pkcs1padding.cpp> crypto::padding::PKCS1v15Padding::Pad(vector<byte>&) const: {type_version_} is not support.");
	}
	in_out = out;	
}

size_t crypto::padding::PKCS1v15Padding::Unpad(vector<byte>& in_out) const
{
	vector<byte>& in = in_out;
	vector<byte> out(block_size_);

	int out_size;
	switch (type_version_)
	{
	case PRIVATE_KEY_OPERATION:
		out_size = RSA_padding_check_PKCS1_type_1(
			out.data(), out.size(),
			in.data(), in.size(),			
			block_size_
		);
		if (out_size == -1)
		{
			throw std::runtime_error("[runtime_error] <pkcs1padding.cpp> crypto::padding::PKCS1v15Padding::Pad(vector<byte>&) const: {RSA_padding_add_PKCS1_type_1} fail.");
		}
		break;
	case PUBLIC_KEY_OPERATION:
		out_size = RSA_padding_check_PKCS1_type_2(
			out.data(), out.size(),
			in.data(), in.size(),
			block_size_
		);
		if (out_size == -1)
		{
			throw std::runtime_error("[runtime_error] <pkcs1padding.cpp> crypto::padding::PKCS1v15Padding::Pad(vector<byte>&) const: {RSA_padding_add_PKCS1_type_2} fail.");
		}
		break;
	default:
		throw std::invalid_argument("[invalid_argument] <pkcs1padding.cpp> crypto::padding::PKCS1v15Padding::Pad(vector<byte>&) const: {type_version_} is not support.");
	}
	out.resize(out_size);
	in_out = out;
	return out_size;
}

size_t crypto::padding::PKCS1v15Padding::GetPadLength(size_t len) const
{
	return block_size_ - 11 - len;
}


