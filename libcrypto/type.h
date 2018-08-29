/*
* Copyright (c) 2012, Echizen Ryoma. All rights reserved.
* DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
*/

#pragma once

#include <string>
using std::string;

#include <vector>
using std::vector;

#if _HAS_STD_BYTE == 0
#include <cstdint>
typedef uint8_t byte;
#endif
