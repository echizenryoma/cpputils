#include "pch.h"

#include "../crypto/ecdsa.h"
using crypto::signature::EcDsa;

#include "../crypto/base64.h"
using crypto::encode::Base64;

#include "../crypto/hash.h"
using crypto::message::digest::Hash;

const string PUBLIC_KEY_STR = "-----BEGIN PUBLIC KEY-----\n"
	"MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE71+KZ2RvEFo68DfP7MGNQGcgl+LNy5WR\n"
	"H3uoetgJMxd3jtUoraVXFMSMX2mcYZmvOwuZdSjacEHeRqYpKrMHJw==\n"
	"-----END PUBLIC KEY-----";
EC_KEY_ptr ECDSA_PUBLIC_KEY = EcDsa::pubkey(PUBLIC_KEY_STR);

const string PRIVATE_KEY_STR = "-----BEGIN EC PRIVATE KEY-----\n"
	"MHQCAQEEIFXaSjW+ami1YzjOMl77B0Fy1OsRAGbh8yajcCB1eaWkoAcGBSuBBAAK\n"
	"oUQDQgAE71+KZ2RvEFo68DfP7MGNQGcgl+LNy5WRH3uoetgJMxd3jtUoraVXFMSM\n"
	"X2mcYZmvOwuZdSjacEHeRqYpKrMHJw==\n"
	"-----END EC PRIVATE KEY-----";
EVP_KEY_ptr ECDSA_PRIVATE_KEY = EcDsa::privkey(PRIVATE_KEY_STR);

TEST(ECDSA, SHA512)
{
	vector<byte> ptext;
	vector<byte> stext;

	ptext = Hash::digest(Base64::decode("GcRqZtvZqfz0nww="), Hash::HashScheme::SHA512);
	stext = EcDsa::sign(ECDSA_PRIVATE_KEY, ptext);
EXPECT_TRUE(EcDsa::verify(ECDSA_PUBLIC_KEY, stext, ptext));

	ptext = Hash::digest(Base64::decode("tQJT13nQjQeKScukjRt11lT3DjY="), Hash::HashScheme::SHA512);
	stext = EcDsa::sign(ECDSA_PRIVATE_KEY, ptext);
EXPECT_TRUE(EcDsa::verify(ECDSA_PUBLIC_KEY, stext, ptext));

	ptext = Hash::digest(Base64::decode("joLPIWteFG354eZXhT7uDRzxk0FXCB0UwW6PuVp4xOI="), Hash::HashScheme::SHA512);
	stext = EcDsa::sign(ECDSA_PRIVATE_KEY, ptext);
EXPECT_TRUE(EcDsa::verify(ECDSA_PUBLIC_KEY, stext, ptext));
}
