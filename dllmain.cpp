// dllmain.cpp : DllMain�� ������ ���Դϴ�.

#include "stdafx.h"
#include "resource.h"
#include "CryptoppLib_i.h"
#include "dllmain.h"

CCryptoppLibModule _AtlModule;

// DLL �������Դϴ�.
extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	hInstance;
	return _AtlModule.DllMain(dwReason, lpReserved); 
}
