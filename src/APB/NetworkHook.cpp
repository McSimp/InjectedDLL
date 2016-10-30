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
    PLH::Detour detLobbyPacketHandler;
    PLH::Detour detWorldPacketHandler;
    PLH::Detour detSendTo;
    PLH::Detour detRecvFrom;
    PLH::Detour detReceivedRawPacket;
    PLH::Detour detLowLevelSend;

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
    int __fastcall hkLobbyPacketHandler(void* thisPtr, void* edx, const char* buf)
    {
        int size = *(int*)buf;
        logger->info("LobbyPacketHandler:");
        logger->info("    size = {}", size);
        logger->info("    buf = {}", Util::DataToHex(buf, size));

        return detLobbyPacketHandler.GetOriginal<tPacketHandler>()(thisPtr, buf);
    }

    int __fastcall hkWorldPacketHandler(void* thisPtr, void* edx, const char* buf)
    {
        int size = *(int*)buf;
        logger->info("WorldPacketHandler:");
        logger->info("    size = {}", size);
        logger->info("    buf = {}", Util::DataToHex(buf, size));

        return detWorldPacketHandler.GetOriginal<tPacketHandler>()(thisPtr, buf);
    }

    int WINAPI hkSendTo(SOCKET s, const char* buf, int len, int flags, const struct sockaddr_in* to, int tolen)
    {
        logger->info("sendto:");
        logger->info("    socket = {}", (void*)s);
        logger->info("    len = {}", len);
        logger->info("    buf = {}", Util::DataToHex(buf, len));
        logger->info("    to = {}", to->sin_addr.s_addr);
        return detSendTo.GetOriginal<decltype(&hkSendTo)>()(s, buf, len, flags, to, tolen);
    }

    int WINAPI hkRecvFrom(SOCKET s, char* buf, int len, int flags, struct sockaddr* from, int* fromLen)
    {
        int result = detRecvFrom.GetOriginal<decltype(&hkRecvFrom)>()(s, buf, len, flags, from, fromLen);
        if (result <= 0)
        {
            return result;
        }

        logger->info("recvfrom:");
        logger->info("    socket = {}", (void*)s);
        logger->info("    len = {}", result);
        logger->info("    buf = {}", Util::DataToHex(buf, result));

        return result;
    }

    typedef int(__thiscall* tReceivedRawPacket)(void* thisPtr, const char* InData, int Count);
    int __fastcall hkReceivedRawPacket(void* thisPtr, void* edx, const char* InData, int Count)
    {
        logger->info("ReceivedRawPacket:");
        logger->info("    Count = {}", Count);
        logger->info("    InData = {}", Util::DataToHex(InData, Count));

        return detReceivedRawPacket.GetOriginal<tReceivedRawPacket>()(thisPtr, InData, Count);
    }

    typedef int(__thiscall* tLowLevelSend)(void* thisPtr, const char* Data, int Count);
    int __fastcall hkLowLevelSend(void* thisPtr, void* edx, const char* Data, int Count)
    {
        logger->info("LowLevelSend:");
        logger->info("    Count = {}", Count);
        logger->info("    InData = {}", Util::DataToHex(Data, Count));

        return detLowLevelSend.GetOriginal<tLowLevelSend>()(thisPtr, Data, Count);
    }

    void Initialise()
    {
        logger = spdlog::get("logger");
        logger->info("Hooking Network functions");

        ModuleScan APBScan("APB.exe");

        Util::HookLibraryFunction(detSend, "wsock32.dll", "send", &hkSend);
        Util::HookSignatureFunction(detSendWrapper, APBScan, "\x55\x8B\xEC\x56\x8B\xF1\x83\x7E\x04\x03", "xxxxxxxxxx", &hkSendWrapper);
        Util::HookLibraryFunction(detRecv, "wsock32.dll", "recv", &hkRecv);
        Util::HookSignatureFunction(detLobbyPacketHandler, APBScan, "\x55\x8B\xEC\x56\x8B\x75\x08\x8B\x46\x04\x05", "xxxxxxxxxxx", &hkLobbyPacketHandler);
        Util::HookSignatureFunction(detWorldPacketHandler, APBScan, "\x55\x8B\xEC\x8B\x45\x08\x56\x8B\x50\x04\x8D\xB2", "xxxxxxxxxxxx", &hkWorldPacketHandler);
        Util::HookLibraryFunction(detSendTo, "wsock32.dll", "sendto", &hkSendTo);
        Util::HookLibraryFunction(detRecvFrom, "wsock32.dll", "recvfrom", &hkRecvFrom);
        Util::HookSignatureFunction(detReceivedRawPacket, APBScan, "\x55\x8B\xEC\x83\xEC\x38\x56\x8B\x75\x0C", "xxxxxxxxxx", &hkReceivedRawPacket);
        Util::HookSignatureFunction(detLowLevelSend, APBScan, "\x55\x8B\xEC\x83\xEC\x1C\x56\x8B\xF1\x8B\x8E\x00\x00\x00\x00\x85\xC9\x0F\x84\x00\x00\x00\x00\x8B\x01\xFF\x50\x04", "xxxxxxxxxxx????xxxx????xxxxx", &hkLowLevelSend);

        logger->info("Network functions hooked");
    }

    void Shutdown()
    {
        logger->info("Unhooking Network functions");

        detSend.UnHook();
        detSendWrapper.UnHook();
        detRecv.UnHook();
        detLobbyPacketHandler.UnHook();
        detWorldPacketHandler.UnHook();
        detSendTo.UnHook();
        detReceivedRawPacket.UnHook();

        logger->info("Network functions unhooked");
    }
}
