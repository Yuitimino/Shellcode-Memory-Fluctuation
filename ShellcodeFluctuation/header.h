#pragma once

#include <windows.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <memory>

// Function pointer types
typedef void (WINAPI* FnSleep)(DWORD dwMilliseconds);
typedef DWORD(NTAPI* FnNtFlushInstructionCache)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    ULONG NumberOfBytesToFlush
    );

// Smart pointer for HANDLE
typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype(&::CloseHandle)> HandlePtr;

// Memory protection constant for shellcode
constexpr DWORD SHELLCODE_MEMORY_PROTECTION = PAGE_EXECUTE_READ;

/**
 * @enum TypeOfFluctuation
 * @brief Defines memory fluctuation modes
 */
enum TypeOfFluctuation
{
    NoFluctuation = 0,      ///< No memory fluctuation
    FluctuateToRW = 1,      ///< Fluctuate between RX and RW
    FluctuateToNA = 2       ///< Fluctuate to PAGE_NOACCESS (ORCA666's technique)
};

/**
 * @struct FluctuationMetadata
 * @brief Stores shellcode memory fluctuation metadata
 */
struct FluctuationMetadata
{
    LPVOID shellcodeAddr;       ///< Base address of shellcode allocation
    SIZE_T shellcodeSize;       ///< Size of shellcode allocation
    bool currentlyEncrypted;    ///< Whether shellcode is currently encrypted
    DWORD encodeKey;            ///< XOR32 encryption key
    DWORD protect;              ///< Original memory protection
};

/**
 * @struct HookedSleep
 * @brief Stores Sleep hook information
 */
struct HookedSleep
{
    FnSleep originalSleep;      ///< Original Sleep function pointer
    BYTE sleepStub[16];         ///< Original bytes from Sleep function
};

/**
 * @struct HookTrampolineBuffers
 * @brief Buffers for hook trampoline installation/removal
 */
struct HookTrampolineBuffers
{
    BYTE* originalBytes;        ///< Buffer containing original bytes
    DWORD originalBytesSize;    ///< Size of original bytes buffer
    BYTE* previousBytes;        ///< Buffer to receive previous bytes
    DWORD previousBytesSize;    ///< Size of previous bytes buffer
};

// Global variables
extern HookedSleep g_hookedSleep;
extern FluctuationMetadata g_fluctuationData;
extern TypeOfFluctuation g_fluctuate;

/**
 * @brief Template logging function with variadic arguments
 */
template<class... Args>
void Log(Args... args)
{
    std::stringstream oss;
    (oss << ... << args);
    std::cout << oss.str() << std::endl;
}

// Function declarations
bool HookSleepFunction();
bool InjectShellcode(std::vector<uint8_t>& shellcode, HandlePtr& thread);
bool ReadShellcodeFromFile(const char* path, std::vector<uint8_t>& shellcode);
std::vector<MEMORY_BASIC_INFORMATION> CollectMemoryMap(
    HANDLE hProcess,
    DWORD type = MEM_PRIVATE | MEM_MAPPED
);
void InitializeShellcodeFluctuation(const LPVOID caller);
bool FastTrampoline(
    bool installHook,
    BYTE* addressToHook,
    LPVOID jumpAddress,
    HookTrampolineBuffers* buffers = nullptr
);
void XOR32Encode(uint8_t* buffer, size_t bufferSize, uint32_t xorKey);
bool IsShellcodeThread(LPVOID address);
void ShellcodeEncryptDecrypt(LPVOID callerAddress);
LONG NTAPI VectoredExceptionHandler(PEXCEPTION_POINTERS exceptionInfo);

void WINAPI HookedSleepHandler(DWORD dwMilliseconds);