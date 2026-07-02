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
#include <memory>

namespace AntiDebug {
    // Debugger detection methods
    class DebuggerDetector {
    public:
        static bool IsDebuggerPresent() {
            if (::IsDebuggerPresent())
                return true;

            BOOL remote = FALSE;
            CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
            return remote != FALSE;
        }

        static bool CheckPEB() {
#ifdef _M_X64
            PBYTE peb = (PBYTE)__readgsqword(0x60);
#else
            PBYTE peb = (PBYTE)__readfsdword(0x30);
#endif
            return (peb[2] != 0);
        }

        static bool CheckDebuggerProcesses() {
            const std::vector<std::wstring> debuggerProcesses = {
                L"ollydbg.exe", L"x64dbg.exe", L"ida.exe",
                L"ida64.exe", L"dnspy.exe", L"processhacker.exe",
                L"cheatengine.exe", L"windbg.exe", L"x32dbg.exe"
            };

            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (snap == INVALID_HANDLE_VALUE)
                return false;

            std::unique_ptr<void, decltype(&CloseHandle)> snapGuard(snap, CloseHandle);
            
            PROCESSENTRY32W pe{};
            pe.dwSize = sizeof(PROCESSENTRY32W);

            if (!Process32FirstW(snap, &pe))
                return false;

            do {
                for (const auto& process : debuggerProcesses) {
                    if (_wcsicmp(pe.szExeFile, process.c_str()) == 0) {
                        return true;
                    }
                }
            } while (Process32NextW(snap, &pe));

            return false;
        }

        static int GetDebugScore() {
            int score = 0;
            if (IsDebuggerPresent()) score += 3;
            if (CheckPEB()) score += 2;
            if (CheckDebuggerProcesses()) score += 3;
            return score;
        }
    };

    // Virtual Machine detection methods
    class VMDetector {
    private:
        static std::string GetCPUVendor() {
            int cpuInfo[4] = { 0 };
            char vendor[13] = { 0 };

            __cpuid(cpuInfo, 0x40000000);

            memcpy(vendor, &cpuInfo[1], 4);
            memcpy(vendor + 4, &cpuInfo[2], 4);
            memcpy(vendor + 8, &cpuInfo[3], 4);

            return std::string(vendor);
        }

        static bool CheckRegistryValue(HKEY hKey, const std::wstring& subKey, 
                                       const std::wstring& valueName, 
                                       const std::vector<std::wstring>& keywords) {
            HKEY hSubKey;
            if (RegOpenKeyExW(hKey, subKey.c_str(), 0, KEY_READ, &hSubKey) != ERROR_SUCCESS)
                return false;

            std::unique_ptr<void, decltype(&RegCloseKey)> keyGuard(hSubKey, RegCloseKey);

            WCHAR buffer[512] = { 0 };
            DWORD size = sizeof(buffer);
            
            if (RegQueryValueExW(hSubKey, valueName.c_str(), NULL, NULL, 
                                (LPBYTE)buffer, &size) != ERROR_SUCCESS)
                return false;

            std::wstring value(buffer);
            for (const auto& keyword : keywords) {
                if (value.find(keyword) != std::wstring::npos)
                    return true;
            }

            return false;
        }

    public:
        static bool CheckVendor() {
            std::string vendor = GetCPUVendor();
            const std::vector<std::string> vmKeywords = {
                "VMware", "VBox", "KVM", "Microsoft Virtual PC", "Xen"
            };

            for (const auto& keyword : vmKeywords) {
                if (vendor.find(keyword) != std::string::npos)
                    return true;
            }
            return false;
        }

        static bool CheckRegistry() {
            const std::vector<std::wstring> vmKeywords = {
                L"VMware", L"VirtualBox", L"KVM", L"Xen", L"QEMU"
            };

            // Check BIOS manufacturer
            if (CheckRegistryValue(HKEY_LOCAL_MACHINE, 
                                  L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                                  L"SystemManufacturer", vmKeywords))
                return true;

            // Check BIOS product name
            if (CheckRegistryValue(HKEY_LOCAL_MACHINE,
                                  L"HARDWARE\\DESCRIPTION\\System\\BIOS",
                                  L"SystemProductName", vmKeywords))
                return true;

            // Additional registry checks
            if (CheckRegistryValue(HKEY_LOCAL_MACHINE,
                                  L"SYSTEM\\CurrentControlSet\\Control\\SystemInformation",
                                  L"SystemManufacturer", vmKeywords))
                return true;

            return false;
        }

        static bool CheckFiles() {
            const std::vector<std::string> vmFiles = {
                "C:\\Windows\\System32\\drivers\\vmmouse.sys",
                "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
                "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
                "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
                "C:\\Windows\\System32\\drivers\\vm3dmp.sys"
            };

            for (const auto& file : vmFiles) {
                if (GetFileAttributesA(file.c_str()) != INVALID_FILE_ATTRIBUTES)
                    return true;
            }
            return false;
        }

        static int GetVMScore() {
            int score = 0;
            if (CheckVendor()) score++;
            if (CheckRegistry()) score++;
            if (CheckFiles()) score++;
            return score;
        }
    };

    // Protection response handler
    class ProtectionResponse {
    public:
        static void Trigger() {
            // Clean exit to prevent debugging
            ExitProcess(0);
        }
    };

    // Main protection orchestrator
    class ProtectionOrchestrator {
    private:
        static constexpr int DEBUG_THRESHOLD = 3;
        static constexpr int VM_THRESHOLD = 2;

    public:
        static void Execute() {
            int debugScore = DebuggerDetector::GetDebugScore();
            int vmScore = VMDetector::GetVMScore();

            if (debugScore >= DEBUG_THRESHOLD || vmScore >= VM_THRESHOLD) {
                ProtectionResponse::Trigger();
            }
        }
    };
}

// Exported function for external use
extern "C" {
    __declspec(dllexport) void __cdecl RunProtection() {
        AntiDebug::ProtectionOrchestrator::Execute();
    }
}
