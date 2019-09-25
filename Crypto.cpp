// Crypto.cpp : CCrypto의 구현입니다.

#include "stdafx.h"
#include "Crypto.h"




// CCrypto

HRESULT CCrypto::Activate()
{
	HRESULT hr = GetObjectContext(&m_spObjectContext);
	if (SUCCEEDED(hr))
		return S_OK;
	return hr;
} 

BOOL CCrypto::CanBePooled()
{
	return FALSE;
} 

void CCrypto::Deactivate()
{
	m_spObjectContext.Release();
} 


STDMETHODIMP CCrypto::Encrypt(BSTR name, BSTR key, BSTR iv, BSTR text, VARIANT * pResult)
{
	using namespace std;

	VariantInit(pResult);
	std::string EncodedText;
	std::string Name((LPCSTR)(_bstr_t)name);

	try {
		ExecMapType exec;
		InitEncrypt<CryptoPP::Base64Encoder>(exec);

		Name = boost::algorithm::to_lower_copy(Name);
		EncodedText = exec[Name]((LPCSTR)(_bstr_t)key, (LPCSTR)(_bstr_t)iv, (LPCSTR)(_bstr_t)text);
		
		*pResult = _variant_t(EncodedText.c_str()).Detach();
	}
	catch (...) {
		*pResult = _variant_t("").Detach();
	}

	if (m_spObjectContext) m_spObjectContext->SetComplete();

	return S_OK;
}

STDMETHODIMP CCrypto::Decrypt(BSTR name, BSTR key, BSTR iv, BSTR text, VARIANT * pResult)
{
	using namespace std;

	VariantInit(pResult);
	std::string RecoveredText;
	std::string Name((LPCSTR)(_bstr_t)name);

	try {
		ExecMapType exec;
		InitDecrypt<CryptoPP::Base64Decoder>(exec);

		Name = boost::algorithm::to_lower_copy(Name);
		RecoveredText = exec[Name]((LPCSTR)(_bstr_t)key, (LPCSTR)(_bstr_t)iv, (LPCSTR)(_bstr_t)text);

		*pResult = _variant_t(RecoveredText.c_str()).Detach();
	}
	catch (...) {
		*pResult = _variant_t("").Detach();
	}

	if (m_spObjectContext) m_spObjectContext->SetComplete();

	return S_OK;
}


STDMETHODIMP CCrypto::Encrypt_HexEnc(BSTR name, BSTR key, BSTR iv, BSTR text, VARIANT * pResult)
{
	using namespace std;

	VariantInit(pResult);
	std::string EncodedText;
	std::string Name((LPCSTR)(_bstr_t)name);

	try {
		ExecMapType exec;
		InitEncrypt<CryptoPP::HexEncoder>(exec);

		Name = boost::algorithm::to_lower_copy(Name);
		EncodedText = exec[Name]((LPCSTR)(_bstr_t)key, (LPCSTR)(_bstr_t)iv, (LPCSTR)(_bstr_t)text);
		
		*pResult = _variant_t(EncodedText.c_str()).Detach();
	}
	catch (...) {
		*pResult = _variant_t("").Detach();
	}

	if (m_spObjectContext) m_spObjectContext->SetComplete();

	return S_OK;
}

STDMETHODIMP CCrypto::Decrypt_HexDec(BSTR name, BSTR key, BSTR iv, BSTR text, VARIANT * pResult)
{
	using namespace std;

	VariantInit(pResult);
	std::string RecoveredText;
	std::string Name((LPCSTR)(_bstr_t)name);

	try {
		ExecMapType exec;
		InitDecrypt<CryptoPP::HexDecoder>(exec);

		Name = boost::algorithm::to_lower_copy(Name);
		RecoveredText = exec[Name]((LPCSTR)(_bstr_t)key, (LPCSTR)(_bstr_t)iv, (LPCSTR)(_bstr_t)text);

		*pResult = _variant_t(RecoveredText.c_str()).Detach();
	}
	catch (...) {
		*pResult = _variant_t("").Detach();
	}

	if (m_spObjectContext) m_spObjectContext->SetComplete();

	return S_OK;
}



char CCrypto::HexToChar(const std::string &str)
{
	int n = 0;

	std::istringstream ss(str);
	ss >> std::hex >> n;

	return char(n);
}

void CCrypto::KeyConvert(const std::string &str, byte KEY[], const int nKeySize)
{
	typedef std::vector<std::string> ResultType;
	const std::string sPrefix = "hex:";

	std::string sKey;

	if (sPrefix == str.substr(0, sPrefix.length())) {
		std::string sHex = str.substr(sPrefix.length());

		ResultType r;
		boost::algorithm::split(r, sHex, boost::algorithm::is_any_of(","));
		
		ResultType::iterator it = r.begin();
		for (; it != r.end(); ++it) {
			sKey += HexToChar(*it);
		}
	}
	else {
		sKey = str;
	}

	if (nKeySize != sKey.size()) {
		throw -1;
	}

	std::copy(sKey.begin(), sKey.end(), KEY);
}