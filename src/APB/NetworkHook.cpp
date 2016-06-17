#include "APB.h"
#include <spdlog/spdlog.h>
#include <PolyHook/PolyHook.h>
#include "../Util.h"
#include <WinSock2.h>
#include "../ModuleScan.h"

namespace NetworkHook
{
    PLH::Detour detSend;
    PLH::Detour detSendWrapper;
    PLH::Detour detRecv;
    PLH::Detour detPacketHandler;

    std::shared_ptr<spdlog::logger> logger;

    int WINAPI hkSend(SOCKET s, const char* buf, int len, int flags)
    {
        logger->info("send:");
        logger->info("    socket = {}", (void*)s);
        logger->info("    len = {}", len);
        logger->info("    buf = {}", Util::DataToHex(buf, len));
        return detSend.GetOriginal<decltype(&hkSend)>()(s, buf, len, flags);
    }

    typedef bool(__thiscall* tSendWrapper)(void* thisPtr, const char* buf);
    bool __fastcall hkSendWrapper(void* thisPtr, void* edx, const char* buf)
    {
        int size = *(int*)buf;
        logger->info("SendWrapper:");
        logger->info("    size = {}", size);
        logger->info("    buf = {}", Util::DataToHex(buf, size));

        return detSendWrapper.GetOriginal<tSendWrapper>()(thisPtr, buf);
    }

    int WINAPI hkRecv(SOCKET s, char* buf, int len, int flags)
    {
        int result = detRecv.GetOriginal<decltype(&hkRecv)>()(s, buf, len, flags);
        if (result <= 0)
        {
            return result;
        }

        logger->info("recv:");
        logger->info("    socket = {}", (void*)s);
        logger->info("    len = {}", result);
        logger->info("    buf = {}", Util::DataToHex(buf, result));

        return result;
    }

    typedef int(__thiscall* tPacketHandler)(void* thisPtr, const char* buf);
    int __fastcall hkPacketHandler(void* thisPtr, void* edx, const char* buf)
    {
        int size = *(int*)buf;
        logger->info("PacketHandler:");
        logger->info("    size = {}", size);
        logger->info("    buf = {}", Util::DataToHex(buf, size));

        return detPacketHandler.GetOriginal<tPacketHandler>()(thisPtr, buf);
    }

    void Initialise()
    {
        logger = spdlog::get("logger");
        logger->info("Hooking Network functions");

        ModuleScan APBScan("APB.exe");

        Util::HookLibraryFunction(detSend, "wsock32.dll", "send", &hkSend);
        Util::HookSignatureFunction(detSendWrapper, APBScan, "\x55\x8B\xEC\x56\x8B\xF1\x83\x7E\x04\x03", "xxxxxxxxxx", &hkSendWrapper);
        Util::HookLibraryFunction(detRecv, "wsock32.dll", "recv", &hkRecv);
        Util::HookSignatureFunction(detPacketHandler, APBScan, "\x55\x8B\xEC\x56\x8B\x75\x08\x8B\x46\x04\x05", "xxxxxxxxxxx", &hkPacketHandler);

        logger->info("Network functions hooked");
    }

    void Shutdown()
    {
        logger->info("Unhooking Network functions");

        detSend.UnHook();
        detSendWrapper.UnHook();
        detRecv.UnHook();
        detPacketHandler.UnHook();

        logger->info("Network functions unhooked");
    }
}
