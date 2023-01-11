#include <iostream>

#include <Windows.h>

int CharToWchar_t(const char* from, UINT characterSet, std::wstring& out) {
	int WideCharLen = MultiByteToWideChar(
		characterSet, 0,
		from, -1,
		NULL, 0);
	wchar_t* WideChar = new wchar_t[WideCharLen] { 0 };
	WideCharLen = MultiByteToWideChar(
		characterSet, 0,
		from, -1,
		WideChar, WideCharLen);

	out = WideChar;

	if (WideChar) delete[] WideChar;

	return WideCharLen;
}

int Wchar_tToChar(const wchar_t* from, UINT characterSet, std::string& out) {
	int MultiByteLen = WideCharToMultiByte(
		characterSet, 0,
		from, -1,
		NULL, NULL,
		NULL, NULL);
	char* MultiByte = new char[MultiByteLen] { 0 };
	MultiByteLen = WideCharToMultiByte(
		characterSet, 0,
		from, -1,
		MultiByte, MultiByteLen,
		NULL, NULL);

	out = MultiByte;

	if (MultiByte) delete[] MultiByte;

	return MultiByteLen;
}

int CharacterSetEncodeing(const char* from, UINT fromCharacterSet, UINT toCharacterSet, std::string& out) {
	int len;
	std::wstring w;
	len = CharToWchar_t(from, fromCharacterSet, w);
	if (len > 0) {
		len = Wchar_tToChar(w.c_str(), toCharacterSet, out);
	}
	return len;
}

int U2G(const char* from, std::string& out) {
	return CharacterSetEncodeing(from, CP_UTF8, CP_ACP, out);
}

int G2U(const char* from, std::string& out) {
	return CharacterSetEncodeing(from, CP_ACP, CP_UTF8, out);
}

std::ostream& print_errmsg(std::ostream& out, DWORD err_code) {
    CHAR err_msg[64];
    DWORD result = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM, NULL, err_code, LANG_USER_DEFAULT, err_msg, sizeof(err_msg), NULL);
    if (result != 0) {
        std::cout << err_msg;
    } else {
        std::cout << err_code << " and " << GetLastError();
    }
	return out;
}

std::string replaceAll(std::string src, std::string subStr, std::string newStr) {
    size_t index = src.find(subStr);
    while (index != std::string::npos) {
        src = src.replace(index, subStr.length(), newStr);
        index = src.find(subStr);
    }
    return src;
}
