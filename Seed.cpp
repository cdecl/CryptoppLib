// Seed.cpp : CSeed의 구현입니다.

#include "stdafx.h"
#include "Seed.h"


#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

// Crypto++ Includes
#include "cryptopp560/cryptlib.h"
#include "cryptopp560/osrng.h" 
#include "cryptopp560/hex.h"
#include "cryptopp560/Base32.h"
#include "cryptopp560/Base64.h"
#include "cryptopp560/seed.h"
#include "cryptopp560/modes.h"      // CBC_Mode< >
#include "cryptopp560/filters.h"    // StringSource and
                        // StreamTransformation

#pragma comment(lib, "cryptlib")

#include <comdef.h>
#include <string>
#include <algorithm>


// CSeed

HRESULT CSeed::Activate()
{
	HRESULT hr = GetObjectContext(&m_spObjectContext);
	if (SUCCEEDED(hr))
		return S_OK;
	return hr;
} 

BOOL CSeed::CanBePooled()
{
	return FALSE;
} 

void CSeed::Deactivate()
{
	m_spObjectContext.Release();
} 


HRESULT CSeed::Encrypt(BSTR key, BSTR text, VARIANT* pResult)
{
	using namespace std;

	VariantInit(pResult);
	std::string EncodedText;

	try {
		byte KEY[ CryptoPP::SEED::DEFAULT_KEYLENGTH ] = {0, }; 

		{
			std::string sKey((LPCSTR)_bstr_t(key));
			if (sKey.length() > CryptoPP::SEED::DEFAULT_KEYLENGTH) {
				sKey = sKey.substr(0, CryptoPP::SEED::DEFAULT_KEYLENGTH);
			}
			std::copy(sKey.begin(), sKey.end(), KEY);
		}

		std::string PlainText((LPCSTR)_bstr_t(text));

		//
		CryptoPP::ECB_Mode<CryptoPP::SEED>::Encryption Encryptor(KEY, CryptoPP::SEED::DEFAULT_KEYLENGTH);

		// Encryption
		CryptoPP::StringSource( PlainText, true,
			new CryptoPP::StreamTransformationFilter(Encryptor, 
				new CryptoPP::Base64Encoder(
					new CryptoPP::StringSink( EncodedText ), false
				), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING
			)
		); 

		*pResult = _variant_t(EncodedText.c_str()).Detach();
	}
	catch (...) {
		*pResult = _variant_t("").Detach();
	}

	if (m_spObjectContext) m_spObjectContext->SetComplete();

	return S_OK;
}

HRESULT CSeed::Decrypt(BSTR key, BSTR text, VARIANT* pResult)
{
	using namespace std;

	VariantInit(pResult);
	std::string RecoveredText;

	try {
		byte KEY[ CryptoPP::SEED::DEFAULT_KEYLENGTH ] = {0, }; 

		{
			std::string sKey((LPCSTR)_bstr_t(key));
			if (sKey.length() > CryptoPP::SEED::DEFAULT_KEYLENGTH) {
				sKey = sKey.substr(0, CryptoPP::SEED::DEFAULT_KEYLENGTH);
			}
			std::copy(sKey.begin(), sKey.end(), KEY);
		}

		std::string EncodedText((LPCSTR)_bstr_t(text));

		//
		CryptoPP::ECB_Mode<CryptoPP::SEED>::Decryption Decryptor(KEY, CryptoPP::SEED::DEFAULT_KEYLENGTH);

		CryptoPP::StringSource( EncodedText, true,
			new CryptoPP::Base64Decoder(
				new CryptoPP::StreamTransformationFilter( Decryptor,
					new CryptoPP::StringSink( RecoveredText ), CryptoPP::BlockPaddingSchemeDef::ZEROS_PADDING
				) 
			) 
		); 
		
		*pResult = _variant_t(RecoveredText.c_str()).Detach();
	}
	catch (...) {
		*pResult = _variant_t("").Detach();
	}

	if (m_spObjectContext) m_spObjectContext->SetComplete();

	return S_OK;
}
