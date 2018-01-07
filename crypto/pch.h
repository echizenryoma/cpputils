//
// pch.h
// Header for standard system include files.
//

#pragma once

#include <cstddef>
#include <functional>
#include <iomanip>
#include <memory>
#include <sstream>
#include <string>
#include <vector>
using namespace std;

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

#ifndef OPENSSL_NO_MD2
#include <openssl/md2.h>
#endif

#ifndef OPENSSL_NO_MD4
#include <openssl/md4.h>
#endif

#ifndef OPENSSL_NO_MD5
#include <openssl/md5.h>
#endif

# if !(defined(OPENSSL_NO_SHA) || (defined(OPENSSL_NO_SHA0) && defined(OPENSSL_NO_SHA1)))
#include <openssl/sha.h>
#endif
