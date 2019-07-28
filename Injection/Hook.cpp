// Core.cpp : DLL アプリケーション用にエクスポートされる関数を定義します。
//

#include "Hook.h"

HINSTANCE g_hDLL;

// This segment must be defined as SHARED in the .DEF
#pragma data_seg (".HookShared")		
// Shared instance for all processes.
HHOOK g_hHook = NULL;
#pragma data_seg()

#pragma comment(linker, "/Section:.HookShared,rws")


LRESULT CALLBACK HookProc(int nCode, WPARAM wParam, LPARAM lParam) 
{
    return ::CallNextHookEx( g_hHook, nCode, wParam, lParam); 
}

INJECTION_API void InstallHook()
{
	g_hHook = ::SetWindowsHookEx( WH_CBT, HookProc, g_hDLL, 0 ); 
}

INJECTION_API void RemoveHook()
{
    ::UnhookWindowsHookEx( g_hHook );
	g_hHook = NULL;
}


