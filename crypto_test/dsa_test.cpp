#include "pch.h"

#include "../crypto/dsa.h"
using crypto::signature::Dsa;

#include "../crypto/base64.h"
using crypto::encode::Base64;

#include "../crypto/hash.h"
using crypto::message::digest::Hash;

const string PUBLIC_KEY_STR = "-----BEGIN PUBLIC KEY-----\n"
	"MIIBtzCCASsGByqGSM44BAEwggEeAoGBAO5OQrMKDxH3OVUCHk3M1rk2OzVms7bJ\n"
	"UHm2FFB2EXq7H+MLB2feKEDya210C58ApJCsSpGkJ3mq8YtkteRuRlWeolUl+Yvv\n"
	"4syJfxRUeQ3EDeEh2AC/DwkTzJsKskdobStQroFef2/sgDHOnFv4n35Z5bvKGk+f\n"
	"5VMsxJdZ9txrAhUAuqO9Aa9zo1JeD+W9wSVLCub5fa0CgYBn4F0PD7odiMfkmeAT\n"
	"cr6swBk/+ZkABiJRxWraGCE/qAcUo9KDYVik/lySmVM2YLJ3M/20aTUhT9hgGl4P\n"
	"qjaLBtf1XuANQu77E7VrM6XBBeIIFGuDUw6wzMxVqqF4rIxIzjYrIo2wX1Dnwlos\n"
	"vrTL9huv4UB4YwlMBYhPBqGPZAOBhQACgYEAuiNjdO4fw/he1lYsZAf9oFCx3j5q\n"
	"fN0kf+Ph+l/e/dLwR+tkp/HVvnIrgpeqE+fNLph1CwcPYGFqpKob/9PiaDsEq9jg\n"
	"SGISb7MS2cWFNx4mQW8KCyGcwbN9oTgh9g9ZC9WgNtpXw8CB4vQACXadnkPmtShb\n"
	"DPMBQrc4knfXkbc=\n"
	"-----END PUBLIC KEY-----";
DSA_ptr DSA_PUBLIC_KEY = Dsa::pubkey(PUBLIC_KEY_STR);

const string PRIVATE_KEY_STR = "-----BEGIN DSA PRIVATE KEY-----\n"
	"MIIBvAIBAAKBgQDuTkKzCg8R9zlVAh5NzNa5Njs1ZrO2yVB5thRQdhF6ux/jCwdn\n"
	"3ihA8mttdAufAKSQrEqRpCd5qvGLZLXkbkZVnqJVJfmL7+LMiX8UVHkNxA3hIdgA\n"
	"vw8JE8ybCrJHaG0rUK6BXn9v7IAxzpxb+J9+WeW7yhpPn+VTLMSXWfbcawIVALqj\n"
	"vQGvc6NSXg/lvcElSwrm+X2tAoGAZ+BdDw+6HYjH5JngE3K+rMAZP/mZAAYiUcVq\n"
	"2hghP6gHFKPSg2FYpP5ckplTNmCydzP9tGk1IU/YYBpeD6o2iwbX9V7gDULu+xO1\n"
	"azOlwQXiCBRrg1MOsMzMVaqheKyMSM42KyKNsF9Q58JaLL60y/Ybr+FAeGMJTAWI\n"
	"Twahj2QCgYEAuiNjdO4fw/he1lYsZAf9oFCx3j5qfN0kf+Ph+l/e/dLwR+tkp/HV\n"
	"vnIrgpeqE+fNLph1CwcPYGFqpKob/9PiaDsEq9jgSGISb7MS2cWFNx4mQW8KCyGc\n"
	"wbN9oTgh9g9ZC9WgNtpXw8CB4vQACXadnkPmtShbDPMBQrc4knfXkbcCFQCF5o9O\n"
	"CxLOGvChxRhFhGs9Uofv5A==\n"
	"-----END DSA PRIVATE KEY-----";
DSA_ptr DSA_PRIVATE_KEY = Dsa::privkey(PRIVATE_KEY_STR);

TEST(DSA, SHA512)
{
	vector<byte> ptext;
	vector<byte> stext;

	ptext = Hash::digest(Base64::decode("GcRqZtvZqfz0nww="), Hash::HashScheme::SHA512);
	stext = Dsa::sign(DSA_PRIVATE_KEY, ptext);
EXPECT_EQ(Dsa::verify(DSA_PUBLIC_KEY, stext, ptext), true);

	ptext = Hash::digest(Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY="), Hash::HashScheme::SHA512);
	stext = Dsa::sign(DSA_PRIVATE_KEY, ptext);
EXPECT_EQ(Dsa::verify(DSA_PUBLIC_KEY, stext, ptext), true);

	ptext = Hash::digest(Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI="), Hash::HashScheme::SHA512);
	stext = Dsa::sign(DSA_PRIVATE_KEY, ptext);
EXPECT_EQ(Dsa::verify(DSA_PUBLIC_KEY, stext, ptext), true);
}
