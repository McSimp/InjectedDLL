#include <Windows.h>
#include <spdlog/spdlog.h>
#include <PolyHook/PolyHook.h>
#include "AntiDebug.h"
#include "APB/APB.h"

void Initialise()
{
    AntiDebug::DisableAntiDebug();
    SRPHook::Initialise();
    CryptHook::Initialise();
    NetworkHook::Initialise();
}

void Shutdown()
{
    AntiDebug::Cleanup();
    SRPHook::Shutdown();
    CryptHook::Shutdown();
    NetworkHook::Shutdown();
}

void PreInitialise()
{
    // Create console window and redirect stdout
    AllocConsole();
    FILE* stream;
    freopen_s(&stream, "CONOUT$", "w", stdout);

    // Create sinks to file and console
    std::vector<spdlog::sink_ptr> sinks;
    sinks.push_back(std::make_shared<spdlog::sinks::stdout_sink_mt>());

    // The file sink could fail so capture the error if so
    std::unique_ptr<std::string> fileError;
    try
    {
        sinks.push_back(std::make_shared<spdlog::sinks::simple_file_sink_mt>("DebugLog.log", true));
    }
    catch (spdlog::spdlog_ex& ex)
    {
        fileError = std::make_unique<std::string>(ex.what());
    }

    // Create logger from sink
    auto logger = std::make_shared<spdlog::logger>("logger", begin(sinks), end(sinks));
    logger->set_pattern("[%T] [%l] [thread %t] %v");
    spdlog::register_logger(logger);

    if (fileError)
    {
        logger->warn("Failed to initialise file sink, log file will be unavailable ({})", *fileError);
    }
}

DWORD WINAPI OnAttach(LPVOID lpThreadParameter)
{
    PreInitialise();

    auto logger = spdlog::get("logger");

    try
    {
        Initialise();
        logger->info("Initialisation complete");
    }
    catch (std::exception& ex)
    {
        logger->error("Failed to initialise DLL ({})", ex.what());
    }

    // Wait for key press to unload DLL
    while (true)
    {
        if (GetAsyncKeyState(VK_F9))
        {
            logger->info("Unloading DLL");
            break;
        }
        Sleep(100);
    }

    Shutdown();
    FreeLibraryAndExitThread((HMODULE)lpThreadParameter, 0);

    return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, OnAttach, hModule, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
