#pragma once

#ifndef __CONVERT_H__
#define __CONVERT_H__

#include <codecvt>
#include <map>
using namespace std;

namespace Convert
{
	namespace String
	{
		enum CharacterSetType;
		string wstring2string(const wstring& wstr, const CharacterSetType& wstr_type);
		wstring string2wstring(const string& str, const CharacterSetType& wstr_type);

		enum CharacterSetType
		{
			Default = 0,
			GBK = 936,
			GB2312 = 936,
			GB18030 = 54936,
			UTF_8 = 65001,
#ifdef _WIN32
			UTF_16 = 1200,
			UTF_16LE = 1200,
			UTF_16BE = 1201,
			UTF_32 = 12000,
			UTF_32LE = 12000,
			UTF_32BE = 12001,
#endif
		};

		pair<CharacterSetType, string> CharacterSetTypePairs[] = {
#ifdef _WIN32
			pair<CharacterSetType, string>(GBK, ".936"),
			pair<CharacterSetType, string>(GB2312, ".936"),
			pair<CharacterSetType, string>(GB18030, ".54936"),
#elif __linux__
			pair<CharacterSetType, string>(GBK, "GBK"),
			pair<CharacterSetType, string>(GB2312, "GB2312"),
			pair<CharacterSetType, string>(GB18030, "GB18030"),
#endif
		};

		map<CharacterSetType, string> CharacterSetTypeMap(CharacterSetTypePairs, CharacterSetTypePairs + sizeof CharacterSetTypePairs / sizeof CharacterSetTypePairs[0]);

		inline string wstring2string(const wstring& wstr, const CharacterSetType& str_type = Default)
		{
			wstring_convert<codecvt_utf8<wchar_t>> utf8_converter;
			wstring_convert<codecvt<wchar_t, char, mbstate_t>> default_converter;
			wstring_convert<codecvt_byname<wchar_t, char, mbstate_t>> converter(new codecvt_byname<wchar_t, char, mbstate_t>(CharacterSetTypeMap[str_type]));

			string str;
			switch (str_type)
			{
			case Default:
				str = default_converter.to_bytes(wstr);
				break;
			case UTF_8:
				str = utf8_converter.to_bytes(wstr);
				break;
			default:
				str = converter.to_bytes(wstr);
			}
			return str;
		}

		inline wstring string2wstring(const string& str, const CharacterSetType& str_type = Default)
		{
			wstring_convert<codecvt_utf8<wchar_t>> utf8_converter;
			wstring_convert<codecvt<wchar_t, char, mbstate_t>> default_converter;
			wstring_convert<codecvt_byname<wchar_t, char, mbstate_t>> converter(new codecvt_byname<wchar_t, char, mbstate_t>(CharacterSetTypeMap[str_type]));

			wstring wstr;
			switch (str_type)
			{
			case Default:
				wstr = default_converter.from_bytes(str);
				break;
			case UTF_8:
				wstr = utf8_converter.from_bytes(str);
				break;
			default:
				wstr = converter.from_bytes(str);
			}
			return wstr;
		}
	}
}

#endif __CONVERT_H__
