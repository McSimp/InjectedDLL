#include "APB.h"
#include <spdlog/spdlog.h>
#include <PolyHook/PolyHook.h>
#include "../Util.h"

namespace SRPHook
{
    PLH::Detour detSetUsername;
    PLH::Detour detSetParams;
    PLH::Detour detSetAuthPassword;
    PLH::Detour detGenPub;
    PLH::Detour detComputeKey;
    PLH::Detour detRespond;
    
    std::shared_ptr<spdlog::logger> logger;

    typedef struct cstr_st {
        char* data;
        int length;
        int cap;
        int ref;
        void* allocator;
    } cstr;

    typedef int SRP_RESULT;
    typedef void SRP;

    SRP_RESULT hkSRPSetUsername(SRP* srp, const char* username)
    {
        logger->info("SRP_set_username: username = {}", username);
        return detSetUsername.GetOriginal<decltype(&hkSRPSetUsername)>()(srp, username);
    }

    SRP_RESULT hkSRPSetParams(SRP* srp,
        const unsigned char* modulus, int modlen,
        const unsigned char* generator, int genlen,
        const unsigned char* salt, int saltlen)
    {
        logger->info("SRP_set_params:");
        logger->info("    modulus = {}", Util::DataToHex((const char*)modulus, modlen));
        logger->info("    generator = {}", Util::DataToHex((const char*)generator, genlen));
        logger->info("    salt = {}", Util::DataToHex((const char*)salt, saltlen));
        
        return detSetParams.GetOriginal<decltype(&hkSRPSetParams)>()(srp, modulus, modlen, generator, genlen, salt, saltlen);
    }

    SRP_RESULT hkSetAuthPassword(SRP* srp, const char* password)
    {
        logger->info("SRP_set_auth_password: password = {}", password);
        return detSetAuthPassword.GetOriginal<decltype(&hkSetAuthPassword)>()(srp, password);
    }

    SRP_RESULT hkGenPub(SRP* srp, cstr** result)
    {
        SRP_RESULT retVal = detGenPub.GetOriginal<decltype(&hkGenPub)>()(srp, result);
        logger->info("SRP_gen_pub: result = {}", Util::DataToHex((*result)->data, (*result)->length));
        return retVal;
    }

    SRP_RESULT hkComputeKey(SRP* srp, cstr** result, const unsigned char* pubkey, int pubkeylen)
    {
        SRP_RESULT retVal = detComputeKey.GetOriginal<decltype(&hkComputeKey)>()(srp, result, pubkey, pubkeylen);
        logger->info("SRP_compute_key:");
        logger->info("    result = {}", Util::DataToHex((*result)->data, (*result)->length));
        logger->info("    pubkey = {}", Util::DataToHex((const char*)pubkey, pubkeylen));
        return retVal;
    }

    SRP_RESULT hkRespond(SRP* srp, cstr** proof)
    {
        SRP_RESULT retVal = detRespond.GetOriginal<decltype(&hkRespond)>()(srp, proof);
        logger->info("SRP_respond: proof = {}", Util::DataToHex((*proof)->data, (*proof)->length));
        return retVal;
    }

    void Initialise()
    {
        logger = spdlog::get("logger");
        logger->info("Hooking SRP functions");

        Util::HookLibraryFunction(detSetUsername, "srp32.dll", "SRP_set_username", &hkSRPSetUsername);
        Util::HookLibraryFunction(detSetParams, "srp32.dll", "SRP_set_params", &hkSRPSetParams);
        Util::HookLibraryFunction(detSetAuthPassword, "srp32.dll", "SRP_set_auth_password", &hkSetAuthPassword);
        Util::HookLibraryFunction(detGenPub, "srp32.dll", "SRP_gen_pub", &hkGenPub);
        Util::HookLibraryFunction(detComputeKey, "srp32.dll", "SRP_compute_key", &hkComputeKey);
        Util::HookLibraryFunction(detRespond, "srp32.dll", "SRP_respond", &hkRespond);

        logger->info("SRP functions hooked");
    }

    void Shutdown()
    {
        logger->info("Unhooking SRP functions");

        detSetUsername.UnHook();
        detSetParams.UnHook();
        detSetAuthPassword.UnHook();
        detGenPub.UnHook();
        detComputeKey.UnHook();
        detRespond.UnHook();

        logger->info("SRP functions unhooked");
    }
}
