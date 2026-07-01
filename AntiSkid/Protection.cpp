#include "pch.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <winreg.h>

#include <vector>
#include <string>
#include <cstring>
#include <cwchar>
#include <intrin.h>

bool IsDebugger()
{
    if (IsDebuggerPresent())
        return true;

    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);

    return remote;
}

bool CheckPEB()
{
#ifdef _M_X64
    PBYTE peb = (PBYTE)__readgsqword(0x60);
#else
    PBYTE peb = (PBYTE)__readfsdword(0x30);
#endif

    return (peb[2] != 0);
}

bool CheckProcesses()
{
    std::vector<std::wstring> bad = {
        L"ollydbg.exe", L"x64dbg.exe", L"ida.exe",
        L"ida64.exe", L"dnspy.exe", L"processhacker.exe"
    };

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snap, &pe))
    {
        do
        {
            for (const auto& b : bad)
            {
                if (_wcsicmp(pe.szExeFile, b.c_str()) == 0)
                {
                    CloseHandle(snap);
                    return true;
                }
            }

        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return false;
}

bool CheckVM_Vendor()
{
    int cpuInfo[4] = { 0 };
    char vendor[13] = { 0 };

    __cpuid(cpuInfo, 0x40000000);

    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[2], 4);
    memcpy(vendor + 8, &cpuInfo[3], 4);

    std::string v(vendor);

    if (v.find("VMware") != std::string::npos)
        return true;

    if (v.find("VBox") != std::string::npos)
        return true;

    if (v.find("KVM") != std::string::npos)
        return true;

   
    return false;
}

bool CheckVM_Registry()
{
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS",
        0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        WCHAR buffer[256];
        DWORD size = sizeof(buffer);

        if (RegQueryValueExW(hKey, L"SystemManufacturer", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS)
        {
            std::wstring val(buffer);

            if (val.find(L"VMware") != std::wstring::npos ||
                val.find(L"VirtualBox") != std::wstring::npos)
            {
                RegCloseKey(hKey);
                return true;
            }
        }

        size = sizeof(buffer);
        if (RegQueryValueExW(hKey, L"SystemProductName", NULL, NULL, (LPBYTE)buffer, &size) == ERROR_SUCCESS)
        {
            std::wstring val(buffer);

            if (val.find(L"VMware") != std::wstring::npos ||
                val.find(L"VirtualBox") != std::wstring::npos ||
                val.find(L"KVM") != std::wstring::npos)
            {
                RegCloseKey(hKey);
                return true;
            }
        }

        RegCloseKey(hKey);
    }

    return false;
}

bool CheckVM_Files()
{
    if (GetFileAttributesA("C:\\Windows\\System32\\drivers\\vmmouse.sys") != INVALID_FILE_ATTRIBUTES)
        return true;

    if (GetFileAttributesA("C:\\Windows\\System32\\drivers\\VBoxMouse.sys") != INVALID_FILE_ATTRIBUTES)
        return true;

    return false;
}


void TriggerResponse()
{
    ExitProcess(0);
}



extern "C"
{
    __declspec(dllexport) void __cdecl RunProtection()
    {
        int debugScore = 0;
        int vmScore = 0;

        
        if (IsDebugger()) debugScore += 3;
        if (CheckPEB()) debugScore += 2;
        if (CheckProcesses()) debugScore += 3;

        
        if (CheckVM_Vendor()) vmScore++;
        if (CheckVM_Registry()) vmScore++;
        if (CheckVM_Files()) vmScore++;

        
        if (debugScore >= 3 || vmScore >= 2)
        {
            TriggerResponse();
        }
    }
}