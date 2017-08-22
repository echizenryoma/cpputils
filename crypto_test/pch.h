//
// pch.h
// Header for standard system include files.
//

#pragma once

#include <gtest/gtest.h>
#include <cryptopp/config.h>
#include <string>
using std::string;
using std::vector;

string bytes2str(const vector<byte>& bytes);