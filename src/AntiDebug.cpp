#include "AntiDebug.h"
#include "Util.h"
#include <spdlog/spdlog.h>
#include <PolyHook/PolyHook.h>
#include <Windows.h>
#include <winternl.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_PORT_NOT_SET ((NTSTATUS)0xC0000353L)

namespace AntiDebug
{
    PLH::Detour detNtSIT;
    PLH::Detour detNtQIP;

    NTSTATUS NTAPI hkNtSetInformationThread(
        __in HANDLE ThreadHandle,
        __in THREAD_INFORMATION_CLASS ThreadInformationClass,
        __in PVOID ThreadInformation,
        __in ULONG ThreadInformationLength)
    {
        // TODO: Check handle is valid and is for a valid thread in this process
        // TODO: Maybe need to hook NtQueryInformationThread in case the process actually checks that ThreadHideFromDebugger is set

        if (ThreadInformationClass == 17 && ThreadInformation == nullptr && ThreadInformationLength == 0) // ThreadHideFromDebugger
        {
            spdlog::get("logger")->info("NtSetInformationThread called with ThreadHideFromDebugger (Thread ID = %d)\n", GetCurrentThreadId());
            return STATUS_SUCCESS;
        }

        return detNtSIT.GetOriginal<decltype(&hkNtSetInformationThread)>()(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength);
    }

    NTSTATUS WINAPI hkNtQueryInformationProcess(
        __in HANDLE ProcessHandle,
        __in PROCESSINFOCLASS ProcessInformationClass,
        __out PVOID ProcessInformation,
        __in ULONG ProcessInformationLength,
        __out_opt PULONG ReturnLength)
    {
        NTSTATUS result = detNtQIP.GetOriginal<decltype(&hkNtQueryInformationProcess)>()(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength);

        if (!NT_SUCCESS(result) || ProcessInformation == nullptr || ProcessInformationLength == 0)
        {
            return result;
        }

        if (ProcessInformationClass == 30) // ProcessDebugObjectHandle
        {
            *((HANDLE*)ProcessInformation) = 0;
            return STATUS_PORT_NOT_SET;
        }
        else if (ProcessInformationClass == 31) // ProcessDebugFlags
        {
            *((ULONG*)ProcessInformation) = 1;
        }
        else if (ProcessInformationClass == ProcessDebugPort)
        {
            *((HANDLE*)ProcessInformation) = 0;
        }

        return result;
    }

    void DisableAntiDebug()
    {
        Util::HookRuntimeFunction(detNtSIT, "ntdll.dll", "NtSetInformationThread", &hkNtSetInformationThread);
        Util::HookRuntimeFunction(detNtQIP, "ntdll.dll", "NtQueryInformationProcess", &hkNtQueryInformationProcess);

        spdlog::get("logger")->info("Anti-debug APIs hooked successfully");
    }
}
