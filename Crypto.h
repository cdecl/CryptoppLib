// Crypto.h : CCrypto의 선언입니다.

#pragma once
#include "CryptoppLib_i.h"
#include "resource.h"       // 주 기호입니다.
#include <comsvcs.h>


#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

// Crypto++ Includes
#include "cryptopp560/cryptlib.h"
#include "cryptopp560/osrng.h" 
#include "cryptopp560/hex.h"
#include "cryptopp560/Base32.h"
#include "cryptopp560/Base64.h"
#include "cryptopp560/seed.h"
#include "cryptopp560/aes.h"
#include "cryptopp560/des.h"
#include "cryptopp560/modes.h"      // CBC_Mode< >
#include "cryptopp560/filters.h"    // StringSource and
                        // StreamTransformation

#pragma comment(lib, "cryptlib")

#include <comdef.h>
#include <string>
#include <sstream>
#include <algorithm>
#include <map>

#include <boost/algorithm/string.hpp>
#include <boost/function.hpp>


typedef boost::function<const std::string (const std::string &, const std::string &, const std::string &)> ExecType;
typedef std::map<std::string, ExecType> ExecMapType;




void Dump(byte *p, int size) 
{
	std::ostringstream ss;
	ss << "Key : ";

	for (int i = 0; i < size; ++i) {
		ss << std::hex << (int)p[i] << ","; 
	}

	OutputDebugStringA(ss.str().c_str());
}


// CCrypto

class ATL_NO_VTABLE CCrypto :
	public CComObjectRootEx<CComMultiThreadModel>,
	public IObjectControl,
	public CComCoClass<CCrypto, &CLSID_Crypto>,
	public IDispatchImpl<ICrypto, &IID_ICrypto, &LIBID_CryptoppLibLib, /*wMajor =*/ 1, /*wMinor =*/ 0>
{
public:
	CCrypto()
	{
	}

	DECLARE_PROTECT_FINAL_CONSTRUCT()

	HRESULT FinalConstruct()
	{
		return S_OK;
	}

	void FinalRelease()
	{
	}

DECLARE_REGISTRY_RESOURCEID(IDR_CRYPTO)

BEGIN_COM_MAP(CCrypto)
	COM_INTERFACE_ENTRY(ICrypto)
	COM_INTERFACE_ENTRY(IObjectControl)
	COM_INTERFACE_ENTRY(IDispatch)
END_COM_MAP()



// IObjectControl
public:
	STDMETHOD(Activate)();
	STDMETHOD_(BOOL, CanBePooled)();
	STDMETHOD_(void, Deactivate)();

	CComPtr<IObjectContext> m_spObjectContext;


// ICrypto
public:
	STDMETHOD(Encrypt)(BSTR name, BSTR key, BSTR iv, BSTR text, VARIANT * pResult);
	STDMETHOD(Decrypt)(BSTR name, BSTR key, BSTR iv, BSTR text, VARIANT * pResult);
	STDMETHOD(Encrypt_HexEnc)(BSTR name, BSTR key, BSTR iv, BSTR text, VARIANT * pResult);
	STDMETHOD(Decrypt_HexDec)(BSTR name, BSTR key, BSTR iv, BSTR text, VARIANT * pResult);

private:
	static char HexToChar(const std::string &str);
	static void KeyConvert(const std::string &str, byte KEY[], const int nKeySize);

public:
	template <class TyE> static void InitEncrypt(ExecMapType &m);
	template <class TyD> static void InitDecrypt(ExecMapType &m);

	template <class Ty, class TyEncoder> static std::string CBC_Encrypt_(const std::string &key, const std::string &iv, const std::string &text);
	template <class Ty, class TyDecoder> static std::string CBC_Decrypt_(const std::string &key, const std::string &iv, const std::string &text);
	template <class Ty, class TyEncoder> static std::string ECB_Encrypt_(const std::string &key, const std::string &iv, const std::string &text);
	template <class Ty, class TyDecoder> static std::string ECB_Decrypt_(const std::string &key, const std::string &iv, const std::string &text);


};

OBJECT_ENTRY_AUTO(__uuidof(Crypto), CCrypto)



template <class TyE>
void CCrypto::InitEncrypt(ExecMapType &m) 
{
	using boost::algorithm::to_lower_copy;

	m.insert(ExecMapType::value_type(to_lower_copy(std::string("AES/CBC")), CBC_Encrypt_<CryptoPP::AES, TyE>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("DES/CBC")), CBC_Encrypt_<CryptoPP::DES, TyE>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("3DES/CBC")), CBC_Encrypt_<CryptoPP::DES_EDE3, TyE>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("DESede/CBC")), CBC_Encrypt_<CryptoPP::DES_EDE3, TyE>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("SEED/CBC")), CBC_Encrypt_<CryptoPP::SEED, TyE>));

	m.insert(ExecMapType::value_type(to_lower_copy(std::string("AES/ECB")), ECB_Encrypt_<CryptoPP::AES, TyE>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("DES/ECB")), ECB_Encrypt_<CryptoPP::DES, TyE>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("3DES/ECB")), ECB_Encrypt_<CryptoPP::DES_EDE3, TyE>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("DESede/ECB")), ECB_Encrypt_<CryptoPP::DES_EDE3, TyE>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("SEED/ECB")), ECB_Encrypt_<CryptoPP::SEED, TyE>));

}

template <class TyD>
void CCrypto::InitDecrypt(ExecMapType &m) 
{
	using boost::algorithm::to_lower_copy;

	m.insert(ExecMapType::value_type(to_lower_copy(std::string("AES/CBC")), CBC_Decrypt_<CryptoPP::AES, TyD>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("DES/CBC")), CBC_Decrypt_<CryptoPP::DES, TyD>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("3DES/CBC")), CBC_Decrypt_<CryptoPP::DES_EDE3, TyD>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("DESede/CBC")), CBC_Decrypt_<CryptoPP::DES_EDE3, TyD>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("SEED/CBC")), CBC_Decrypt_<CryptoPP::SEED, TyD>));

	m.insert(ExecMapType::value_type(to_lower_copy(std::string("AES/ECB")), ECB_Decrypt_<CryptoPP::AES, TyD>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("DES/ECB")), ECB_Decrypt_<CryptoPP::DES, TyD>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("3DES/ECB")), ECB_Decrypt_<CryptoPP::DES_EDE3, TyD>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("DESede/ECB")), ECB_Decrypt_<CryptoPP::DES_EDE3, TyD>));
	m.insert(ExecMapType::value_type(to_lower_copy(std::string("SEED/ECB")), ECB_Decrypt_<CryptoPP::SEED, TyD>));
}


template <class Ty, class TyEncoder>
std::string CCrypto::CBC_Encrypt_(const std::string &key, const std::string &iv, const std::string &text) 
{
	std::string EncodedText;
	byte KEY[ typename Ty::DEFAULT_KEYLENGTH ] = {0, }; 
	byte IV[ typename Ty::BLOCKSIZE ] = {0, }; 

	KeyConvert(key, KEY, typename Ty::DEFAULT_KEYLENGTH);
	KeyConvert(iv, IV, typename Ty::BLOCKSIZE);

	std::string PlainText(text);

	//
	typename CryptoPP::CBC_Mode<Ty>::Encryption Encryptor(KEY, typename Ty::DEFAULT_KEYLENGTH, IV);

	// Encryption
	CryptoPP::StringSource( PlainText, true,
		new CryptoPP::StreamTransformationFilter(Encryptor, 
			new TyEncoder (
				new CryptoPP::StringSink( EncodedText ), false
			), CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING
		)
	); 

	return EncodedText;
}


template <class Ty, class TyDecoder>
std::string CCrypto::CBC_Decrypt_(const std::string &key, const std::string &iv, const std::string &text) 
{
	std::string RecoveredText;
	byte KEY[ typename Ty::DEFAULT_KEYLENGTH ] = {0, }; 
	byte IV[ typename Ty::BLOCKSIZE ] = {0, }; 

	KeyConvert(key, KEY, typename Ty::DEFAULT_KEYLENGTH);
	KeyConvert(iv, IV, typename Ty::BLOCKSIZE);


	std::string EncodedText(text);

	//
	typename CryptoPP::CBC_Mode<Ty>::Decryption Decryptor(KEY, typename Ty::DEFAULT_KEYLENGTH, IV);

	CryptoPP::StringSource( EncodedText, true,
		new TyDecoder (
			new CryptoPP::StreamTransformationFilter( Decryptor,
				new CryptoPP::StringSink( RecoveredText ), CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING
			) 
		) 
	); 

	return RecoveredText;
}



template <class Ty, class TyEncoder>
std::string CCrypto::ECB_Encrypt_(const std::string &key, const std::string &iv, const std::string &text) 
{
	std::string EncodedText;
	byte KEY[ typename Ty::DEFAULT_KEYLENGTH ] = {0, }; 

	KeyConvert(key, KEY, typename Ty::DEFAULT_KEYLENGTH);

	std::string PlainText(text);

	//
	typename CryptoPP::ECB_Mode<Ty>::Encryption Encryptor(KEY, typename Ty::DEFAULT_KEYLENGTH);

	// Encryption
	CryptoPP::StringSource( PlainText, true,
		new CryptoPP::StreamTransformationFilter(Encryptor, 
			new TyEncoder (
				new CryptoPP::StringSink( EncodedText ), false
			), CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING
		)
	); 

	return EncodedText;
}


template <class Ty, class TyDecoder>
std::string CCrypto::ECB_Decrypt_(const std::string &key, const std::string &iv, const std::string &text) 
{
	std::string RecoveredText;
	byte KEY[ typename Ty::DEFAULT_KEYLENGTH ] = {0, }; 

	KeyConvert(key, KEY, typename Ty::DEFAULT_KEYLENGTH);

	std::string EncodedText(text);

	//
	typename CryptoPP::ECB_Mode<Ty>::Decryption Decryptor(KEY, typename Ty::DEFAULT_KEYLENGTH);

	CryptoPP::StringSource( EncodedText, true,
		new TyDecoder (
			new CryptoPP::StreamTransformationFilter( Decryptor,
				new CryptoPP::StringSink( RecoveredText ), CryptoPP::BlockPaddingSchemeDef::DEFAULT_PADDING
			) 
		) 
	); 

	return RecoveredText;
}
