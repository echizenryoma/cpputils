//
// pch.h
// Header for standard system include files.
//

#pragma once

#define _SILENCE_CXX17_UNCAUGHT_EXCEPTION_DEPRECATION_WARNING
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include <algorithm>
#include <memory>
#include <random>

#include <cryptopp/aes.h>
#include <cryptopp/arc4.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/md2.h>
#include <cryptopp/md4.h>
#include <cryptopp/md5.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/rsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "type.h"
