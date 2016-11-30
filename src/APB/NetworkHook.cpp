#include "APB.h"
#include <spdlog/spdlog.h>
#include <PolyHook/PolyHook.h>
#include "../Util.h"
#include <WinSock2.h>
#include "../ModuleScan.h"
#include <codecvt>

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
    PLH::Detour detSendAck;
    PLH::Detour detFlushNet;
    PLH::Detour detReceivedNak;
    PLH::Detour detTcpTickDispatch;
    PLH::Detour detTickFlush;
    PLH::Detour detSendBunch;

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

    typedef int(__thiscall* tSendAck)(void* thisPtr, int AckPacketId, int FirstTime);
    int __fastcall hkSendAck(void* thisPtr, void* edx, int AckPacketId, int FirstTime)
    {
        logger->info("SendAck:");
        logger->info("    AckPacketId = {}", AckPacketId);
        logger->info("    FirstTime = {}", FirstTime);

        return detSendAck.GetOriginal<tSendAck>()(thisPtr, AckPacketId, FirstTime);
    }

    typedef int(__thiscall* tFlushNet)(void* thisPtr, int IgnoreSimulation);
    int __fastcall hkFlushNet(void* thisPtr, void* edx, int IgnoreSimulation)
    {
        logger->info("FlushNet:");
        logger->info("    IgnoreSimulation = {}", IgnoreSimulation);

        return detFlushNet.GetOriginal<tFlushNet>()(thisPtr, IgnoreSimulation);
    }

    typedef int(__thiscall* tReceivedNak)(void* thisPtr, int NakPacketId);
    int __fastcall hkReceivedNak(void* thisPtr, void* edx, int NakPacketId)
    {
        logger->info("ReceivedNak:");
        logger->info("    NakPacketId = {}", NakPacketId);

        return detReceivedNak.GetOriginal<tReceivedNak>()(thisPtr, NakPacketId);
    }

    typedef int(__thiscall* tTcpTickDispatch)(void* thisPtr, float DeltaTime);
    int __fastcall hkTcpTickDispatch(void* thisPtr, void* edx, float DeltaTime)
    {
        logger->info("Start UTcpNetDriver::TickDispatch:");
        logger->info("    DeltaTime = {}", DeltaTime);

        int retVal = detTcpTickDispatch.GetOriginal<tTcpTickDispatch>()(thisPtr, DeltaTime);

        logger->info("Finish UTcpNetDriver::TickDispatch");

        return retVal;
    }

    typedef int(__thiscall* tTickFlush)(void* thisPtr);
    int __fastcall hkTickFlush(void* thisPtr, void* edx)
    {
        logger->info("Start UNetDriver::TickFlush:");

        int retVal = detTickFlush.GetOriginal<tTickFlush>()(thisPtr);

        logger->info("Finish UNetDriver::TickFlush");

        return retVal;
    }
    
    
    template <typename T> class TArray
    {
    public:
        T* AllocatorInstance;
        INT	  ArrayNum;
        INT	  ArrayMax;
    };

    class FBitWriter
    {
    public:
        unsigned char _data[0x24];
        TArray<unsigned char> Buffer;
        INT Num;
        INT Max;
    };

    class FOutBunch : public FBitWriter
    {
    public:
        void* Next;
        void* Channel;
        double Time;
        unsigned int ReceivedAck;
        int ChIndex;
        int ChType;
        int ChSequence;
        int PacketId;
        unsigned char bOpen;
        unsigned char bClose;
        unsigned char bReliable;
    };

    class UChannel
    {
    public:
        void** vtable;
    };

    class FString : public TArray<TCHAR>
    {
        
    };

    typedef int(__thiscall* tSendBunch)(UChannel* thisPtr, FOutBunch* Bunch, int Merge);
    typedef FString(__thiscall* tDescribe)(UChannel* thisPtr);

    int __fastcall hkSendBunch(UChannel* thisPtr, void* edx, FOutBunch* Bunch, int Merge)
    {
        logger->info("UChannel::SendBunch");


        logger->info("    ChIndex = {}, ChType = {}, bOpen = {}, bClose = {}, bReliable = {}", Bunch->ChIndex, Bunch->ChType, Bunch->bOpen, Bunch->bClose, Bunch->bReliable);
        logger->info("    NumBits = {}", Bunch->Num);
        logger->info("    Data = {}", Util::DataToHex((const char*)Bunch->Buffer.AllocatorInstance, (Bunch->Num + 8 - 1) / 8));

        return detSendBunch.GetOriginal<tSendBunch>()(thisPtr, Bunch, Merge);
    }

    void Initialise()
    {
        // Ensure FOutBunch matches the structure in the game
        static_assert(offsetof(FBitWriter, Num) == 0x30, "FBitWriter.Num offset is invalid");
        static_assert(offsetof(FOutBunch, Next) == 0x38, "FOutBunch.Next offset is invalid");
        static_assert(offsetof(FOutBunch, Channel) == 0x3C, "FOutBunch.Channel offset is invalid");
        static_assert(offsetof(FOutBunch, Time) == 0x40, "FOutBunch.Time offset is invalid");
        static_assert(offsetof(FOutBunch, ChIndex) == 0x4C, "FOutBunch.ChIndex offset is invalid");
        static_assert(offsetof(FOutBunch, bReliable) == 0x5E, "FOutBunch.bReliable offset is invalid");

        logger = spdlog::get("logger");
        logger->info("Hooking Network functions");

        ModuleScan APBScan("APB.exe");

        Util::HookLibraryFunction(detSend, "wsock32.dll", "send", &hkSend); logger->info("Hooked send");
        Util::HookSignatureFunction(detSendWrapper, APBScan, "\x55\x8B\xEC\x56\x8B\xF1\x83\x7E\x04\x03", "xxxxxxxxxx", &hkSendWrapper); logger->info("Hooked SendWrapper");
        Util::HookLibraryFunction(detRecv, "wsock32.dll", "recv", &hkRecv); logger->info("Hooked recv");
        Util::HookSignatureFunction(detLobbyPacketHandler, APBScan, "\x55\x8B\xEC\x56\x8B\x75\x08\x8B\x46\x04\x05", "xxxxxxxxxxx", &hkLobbyPacketHandler); logger->info("Hooked LobbyPacketHandler");
        Util::HookSignatureFunction(detWorldPacketHandler, APBScan, "\x55\x8B\xEC\x8B\x45\x08\x56\x8B\x50\x04\x8D\xB2", "xxxxxxxxxxxx", &hkWorldPacketHandler); logger->info("Hooked WorldPacketHandler");
        Util::HookLibraryFunction(detSendTo, "wsock32.dll", "sendto", &hkSendTo); logger->info("Hooked sendto");
        Util::HookLibraryFunction(detRecvFrom, "wsock32.dll", "recvfrom", &hkRecvFrom); logger->info("Hooked recvfrom");
        Util::HookSignatureFunction(detReceivedRawPacket, APBScan, "\x55\x8B\xEC\x83\xEC\x38\x56\x8B\x75\x0C", "xxxxxxxxxx", &hkReceivedRawPacket); logger->info("Hooked ReceivedRawPacket");
        Util::HookSignatureFunction(detLowLevelSend, APBScan, "\x55\x8B\xEC\x83\xEC\x1C\x56\x8B\xF1\x8B\x8E\x00\x00\x00\x00\x85\xC9\x0F\x84\x00\x00\x00\x00\x8B\x01\xFF\x50\x04", "xxxxxxxxxxx????xxxx????xxxxx", &hkLowLevelSend); logger->info("Hooked LowLevelSend");
        Util::HookSignatureFunction(detSendAck, APBScan, "\x55\x8B\xEC\x83\xEC\x14\x57\x6A\x01\x8B\xF9", "xxxxxxxxxxx", &hkSendAck); logger->info("Hooked SendAck");
        Util::HookSignatureFunction(detFlushNet, APBScan, "\x55\x8B\xEC\x83\xEC\x10\x8B\x45\xF0", "xxxxxxxxx", &hkFlushNet); logger->info("Hooked FlushNet");
        Util::HookSignatureFunction(detReceivedNak, APBScan, "\x55\x8B\xEC\x51\x8B\xC1\x56\x8B\xB0\x00\x00\x00\x00\x4E\x89\x45\xFC\x78\x35", "xxxxxxxxx????xxxxxx", &hkReceivedNak); logger->info("Hooked ReceivedNak");
        Util::HookSignatureFunction(detTcpTickDispatch, APBScan, "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\x53\x56\x8B\xD9\x57\x89\x5D\xE4\xE8\x00\x00\x00\x00\xF3\x0F\x10\x83", "xxxxx????xxxxxxxxx????xxxx", &hkTcpTickDispatch); logger->info("Hooked TcpTickDispatch");
        Util::HookSignatureFunction(detTickFlush, APBScan, "\x56\x8B\xF1\x57\xF3\x0F\x10\x86\x00\x00\x00\x00\xF2\x0F\x10\x4E", "xxxxxxxx????xxxx", &hkTickFlush); logger->info("Hooked TickFlush");
        Util::HookSignatureFunction(detSendBunch, APBScan, "\x55\x8B\xEC\x53\x8B\x5D\x08\x56\x57\x8B\xF9\x83\x7F\x50\xFF", "xxxxxxxxxxxxxxx", &hkSendBunch); logger->info("Hooked SendBunch");

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
        detLowLevelSend.UnHook();
        detSendAck.UnHook();
        detFlushNet.UnHook();
        detReceivedNak.UnHook();
        detTcpTickDispatch.UnHook();
        detTickFlush.UnHook();
        detSendBunch.UnHook();

        logger->info("Network functions unhooked");
    }
}
