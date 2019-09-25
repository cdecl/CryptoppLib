// Seed.h : CSeed의 선언입니다.

#pragma once
#include "CryptoppLib_i.h"
#include "resource.h"       // 주 기호입니다.
#include <comsvcs.h>



// CSeed

class ATL_NO_VTABLE CSeed :
	public CComObjectRootEx<CComMultiThreadModel>,
	public IObjectControl,
	public CComCoClass<CSeed, &CLSID_Seed>,
	public IDispatchImpl<ISeed, &IID_ISeed, &LIBID_CryptoppLibLib, /*wMajor =*/ 1, /*wMinor =*/ 0>
{
public:
	CSeed()
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

DECLARE_REGISTRY_RESOURCEID(IDR_SEED)

BEGIN_COM_MAP(CSeed)
	COM_INTERFACE_ENTRY(ISeed)
	COM_INTERFACE_ENTRY(IObjectControl)
	COM_INTERFACE_ENTRY(IDispatch)
END_COM_MAP()



// IObjectControl
public:
	STDMETHOD(Activate)();
	STDMETHOD_(BOOL, CanBePooled)();
	STDMETHOD_(void, Deactivate)();

	CComPtr<IObjectContext> m_spObjectContext;


// ISeed
public:
	STDMETHOD(Encrypt)(BSTR key, BSTR text, VARIANT* pResult);
	STDMETHOD(Decrypt)(BSTR key, BSTR text, VARIANT* pResult);
};

OBJECT_ENTRY_AUTO(__uuidof(Seed), CSeed)
