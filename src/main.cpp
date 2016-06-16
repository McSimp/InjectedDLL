#include <Windows.h>
#include <spdlog/spdlog.h>
#include <PolyHook/PolyHook.h>
#include "AntiDebug.h"

void Initialise()
{
    auto logger = spdlog::get("logger");

    // Specific init goes here
    AntiDebug::DisableAntiDebug();
}

DWORD WINAPI OnAttach(LPVOID lpThreadParameter)
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

    try
    {
        Initialise();
        logger->info("Initialisation complete");
    }
    catch (std::exception& ex)
    {
        logger->error("Failed to initialise DLL ({})", ex.what());
    }

    return 0;
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    switch (dwReason)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, 0, OnAttach, NULL, 0, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}
