#include "APB.h"
#include <spdlog/spdlog.h>
#include <PolyHook/PolyHook.h>
#include "../Util.h"
#include <Wincrypt.h>
#include <vector>

namespace CryptHook
{
    PLH::Detour detCryptGenKey;
    PLH::Detour detCryptImportKey;
    PLH::Detour detCryptEncrypt;
    PLH::Detour detRC4SetKey;
    PLH::Detour detSHA1Update;

    std::shared_ptr<spdlog::logger> logger;
    std::vector<unsigned char> lastSHA1Data;

    BOOL WINAPI hkCryptGenKey(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY* phKey)
    {
        // Ensure we can export the private key
        dwFlags |= CRYPT_ARCHIVABLE | CRYPT_EXPORTABLE;
        BOOL result = detCryptGenKey.GetOriginal<decltype(&hkCryptGenKey)>()(hProv, Algid, dwFlags, phKey);
        if (Algid != AT_KEYEXCHANGE || !result)
        {
            return result;
        }

        logger->info("CryptGenKey:");
        logger->info("    handle = 0x{:X}", *phKey);

        // Export private key
        BYTE keyData[2048];
        DWORD keyLength = 2048;
        if (!CryptExportKey(*phKey, 0, PRIVATEKEYBLOB, 0, keyData, &keyLength))
        {
            logger->error("    CryptExportKey for PRIVATEKEYBLOB failed (Error = {})", GetLastError());
        }
        else
        {
            logger->info("    privKeyLength = {}", keyLength);
            logger->info("    privKey = {}", Util::DataToHex((const char*)keyData, keyLength));
        }

        // Export public key
        keyLength = 2048;
        if (!CryptExportKey(*phKey, 0, PUBLICKEYBLOB, 0, keyData, &keyLength))
        {
            logger->error("    CryptExportKey for PUBLICKEYBLOB failed (Error = {})", GetLastError());
        }
        else
        {
            logger->info("    pubKeyLength = {}", keyLength);
            logger->info("    pubKey = {}", Util::DataToHex((const char*)keyData, keyLength));
        }
        
        return result;
    }

    BOOL WINAPI hkCryptImportKey(HCRYPTPROV hProv, BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey)
    {
        logger->info("CryptImportKey:");
        logger->info("    flags = 0x{:X}", dwFlags);
        logger->info("    keyLength = {}", dwDataLen);
        logger->info("    key = {}", Util::DataToHex((const char*)pbData, dwDataLen));

        BOOL result = detCryptImportKey.GetOriginal<decltype(&hkCryptImportKey)>()(hProv, pbData, dwDataLen, hPubKey, dwFlags, phKey);
        logger->info("    handle = 0x{:X}", *phKey);
        return result;
    }

    BOOL WINAPI hkCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen)
    {
        if (pbData == nullptr)
        {
            return detCryptEncrypt.GetOriginal<decltype(&hkCryptEncrypt)>()(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
        }

        logger->info("CryptEncrypt:");
        logger->info("    hKey = 0x{:X}", hKey);
        logger->info("    hHash = 0x{:X}", hHash);
        logger->info("    Final = {}", Final);
        logger->info("    dwFlags = 0x{:X}", dwFlags);
        logger->info("    plainDataLen = {}", *pdwDataLen);
        logger->info("    plainData = {}", Util::DataToHex((const char*)pbData, *pdwDataLen));

        BOOL result = detCryptEncrypt.GetOriginal<decltype(&hkCryptEncrypt)>()(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);

        if (result)
        {
            logger->info("    encryptedDataLen = {}", *pdwDataLen);
            logger->info("    encryptedData = {}", Util::DataToHex((const char*)pbData, *pdwDataLen));
        }
        else 
        {
            logger->info("    Failed to encrypt data (Error = {})", GetLastError());
        }
        
        return result;
    }

    void hkRC4SetKey(void* key, int len, const unsigned char* data)
    {
        logger->info("RC4_set_key:");
        logger->info("    keyPtr = {}", key);
        logger->info("    hashedKeyData = {}", Util::DataToHex((const char*)data, len));
        logger->info("    rawKeyData = {}", Util::DataToHex((const char*)lastSHA1Data.data(), lastSHA1Data.size()));

        return detRC4SetKey.GetOriginal<decltype(&hkRC4SetKey)>()(key, len, data);
    }

    int hkSHA1Update(void* c, const unsigned char* data, unsigned long len)
    {
        // SHA1_Update is always called before the SetEncryptionKeys function
        // so we store the data that it hashed.
        lastSHA1Data.clear();
        lastSHA1Data.insert(lastSHA1Data.begin(), data, data + len);
        return detSHA1Update.GetOriginal<decltype(&hkSHA1Update)>()(c, data, len);
    }

    void Initialise()
    {
        logger = spdlog::get("logger");
        logger->info("Hooking Crypt functions");

        Util::HookLibraryFunction(detCryptGenKey, "Advapi32.dll", "CryptGenKey", &hkCryptGenKey);
        Util::HookLibraryFunction(detCryptImportKey, "Advapi32.dll", "CryptImportKey", &hkCryptImportKey);
        Util::HookLibraryFunction(detCryptEncrypt, "Advapi32.dll", "CryptEncrypt", &hkCryptEncrypt);
        Util::HookLibraryFunction(detRC4SetKey, "LIBEAY32.dll", "RC4_set_key", &hkRC4SetKey);
        Util::HookLibraryFunction(detSHA1Update, "LIBEAY32.dll", "SHA1_Update", &hkSHA1Update);

        logger->info("Crypt functions hooked");
    }

    void Shutdown()
    {
        logger->info("Unhooking Crypt functions");

        detCryptGenKey.UnHook();
        detCryptImportKey.UnHook();
        detCryptEncrypt.UnHook();
        detRC4SetKey.UnHook();
        detSHA1Update.UnHook();

        logger->info("Crypt functions unhooked");
    }
}
