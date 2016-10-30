#include "APB.h"
#include <spdlog/spdlog.h>
#include <PolyHook/PolyHook.h>
#include "../Util.h"
#include <WinSock2.h>
#include "../ModuleScan.h"

namespace CompressionHook
{
    PLH::Detour detUncompressMemory;
    PLH::Detour detCompressMemory;

    std::shared_ptr<spdlog::logger> logger;

    int __cdecl hkUncompressMemory(int Flags, void* UncompressedBuffer, int UncompressedSize, const void* CompressedBuffer, int CompressedSize)
    {
        if (Flags != 0x01)
        {
            return detUncompressMemory.GetOriginal<decltype(&hkUncompressMemory)>()(Flags, UncompressedBuffer, UncompressedSize, CompressedBuffer, CompressedSize);
        }

        logger->info("appUncompressMemory:");
        logger->info("    Flags = 0x{:X}", Flags);
        logger->info("    UncompressedSize = {}", UncompressedSize);
        logger->info("    CompressedBuffer = {}", Util::DataToHex((const char*)CompressedBuffer, CompressedSize));
        logger->info("    CompressedSize = {}", CompressedSize);

        int result = detUncompressMemory.GetOriginal<decltype(&hkUncompressMemory)>()(Flags, UncompressedBuffer, UncompressedSize, CompressedBuffer, CompressedSize);

        if (result)
        {
            logger->info("    UncompressedBuffer = {}", Util::DataToHex((const char*)UncompressedBuffer, UncompressedSize));
        }
        else
        {
            logger->info("    Failed to uncompress data");
        }

        return result;
    }

    int __cdecl hkCompressMemory(int Flags, void* CompressedBuffer, int* CompressedSize, const void* UncompressedBuffer, int UncompressedSize)
    {
        if (Flags != 0x01)
        {
            return detCompressMemory.GetOriginal<decltype(&hkCompressMemory)>()(Flags, CompressedBuffer, CompressedSize, UncompressedBuffer, UncompressedSize);
        }

        logger->info("appCompressMemory:");
        logger->info("    Flags = 0x{:X}", Flags);
        logger->info("    UncompressedSize = {}", UncompressedSize);
        logger->info("    UncompressedBuffer = {}", Util::DataToHex((const char*)UncompressedBuffer, UncompressedSize));

        int result = detCompressMemory.GetOriginal<decltype(&hkCompressMemory)>()(Flags, CompressedBuffer, CompressedSize, UncompressedBuffer, UncompressedSize);

        if (result)
        {
            logger->info("    CompressedSize = {}", *CompressedSize);
            logger->info("    CompressedBuffer = {}", Util::DataToHex((const char*)CompressedBuffer, *CompressedSize));
        }
        else
        {
            logger->info("    Failed to compress data");
        }

        return result;
    }

    void Initialise()
    {
        logger = spdlog::get("logger");
        logger->info("Hooking compression functions");

        ModuleScan APBScan("APB.exe");

        Util::HookSignatureFunction(detUncompressMemory, APBScan, "\x55\x8B\xEC\x8B\x45\x08\x83\xE0\x0F", "xxxxxxxxx", &hkUncompressMemory);
        Util::HookSignatureFunction(detCompressMemory, APBScan, "\x55\x8B\xEC\x83\xEC\x10\xE8\x00\x00\x00\x00\x89\x45\xF8", "xxxxxxx????xxx", &hkCompressMemory);

        logger->info("Compression functions hooked");
    }

    void Shutdown()
    {
        logger->info("Unhooking compression functions");

        detUncompressMemory.UnHook();
        detCompressMemory.UnHook();

        logger->info("Compression functions unhooked");
    }
}
