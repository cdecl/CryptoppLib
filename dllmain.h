// dllmain.h : 모듈 클래스의 선언입니다.

class CCryptoppLibModule : public CAtlDllModuleT< CCryptoppLibModule >
{
public :
	DECLARE_LIBID(LIBID_CryptoppLibLib)
	DECLARE_REGISTRY_APPID_RESOURCEID(IDR_CRYPTOPPLIB, "{A9C28515-57C1-45B8-A3EC-044F8C82D9C8}")
};

extern class CCryptoppLibModule _AtlModule;
