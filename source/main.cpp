#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>

static_assert(sizeof(void*) == 4, "exitTime.asi must be built for Win32.");

namespace {

constexpr DWORD kGtaLoadStateAddress = 0x00C8D4C0;
constexpr char kConfigSection[] = "Settings";
constexpr char kConfigKey[] = "Time in milliseconds";
constexpr int kDefaultTimeMs = 1000;

enum class SampVersion {
    R1,
    R3_1,
    R5_2,
    DL_R1_2,
};

struct SampVersionInfo {
    DWORD entryPointRva;
    SampVersion version;
    const char* name;
    std::uint32_t timeOperandOffset;
    std::uint32_t getTickCountCallOffset;
};

struct Config {
    int timeMs = kDefaultTimeMs;
    std::string path;
};

constexpr std::array<SampVersionInfo, 4> kSupportedVersions{{
    { 0x31DF13, SampVersion::R1, "R1", 0x0009ED79, 0x000B28DE },
    { 0x0CC4D0, SampVersion::R3_1, "R3-1", 0x000A3379, 0x000C472B },
    { 0x0CBC90, SampVersion::R5_2, "R5-2", 0x000A3AA9, 0x000C3EAA },
    { 0x0FDB60, SampVersion::DL_R1_2, "DL-R1-2", 0x000A3809, 0x000C557B },
}};

#pragma pack(push, 1)
struct RelativeCallPatch {
    std::uint8_t opcode;
    std::int32_t relative;
};

struct IndirectCallPatch {
    std::uint8_t opcode0;
    std::uint8_t opcode1;
    std::uint32_t targetPointerAddress;
};
#pragma pack(pop)

HMODULE g_module = nullptr;
Config g_config;
std::uint32_t g_hookTargetAddress = 0;

std::string BuildConfigPath() {
    char modulePath[MAX_PATH] = {};
    if (GetModuleFileNameA(g_module, modulePath, MAX_PATH) == 0) {
        return "exitTime.ini";
    }

    std::string path(modulePath);
    const std::size_t slash = path.find_last_of("\\/");
    if (slash != std::string::npos) {
        path.erase(slash + 1);
    } else {
        path.clear();
    }

    path += "exitTime.ini";
    return path;
}

Config LoadConfig() {
    Config config;
    config.path = BuildConfigPath();

    char rawValue[64] = {};
    const DWORD length = GetPrivateProfileStringA(
        kConfigSection,
        kConfigKey,
        "",
        rawValue,
        static_cast<DWORD>(sizeof(rawValue)),
        config.path.c_str());

    if (length == 0) {
        std::strcpy(rawValue, "1000");
    }

    char* end = nullptr;
    const long parsed = std::strtol(rawValue, &end, 10);
    if (end == rawValue || *end != '\0' || parsed < std::numeric_limits<int>::min()
        || parsed > std::numeric_limits<int>::max()) {
        config.timeMs = kDefaultTimeMs;
    } else {
        config.timeMs = static_cast<int>(parsed);
    }

    char normalizedValue[32] = {};
    _snprintf_s(
        normalizedValue,
        _TRUNCATE,
        "%d",
        config.timeMs);
    WritePrivateProfileStringA(kConfigSection, kConfigKey, normalizedValue, config.path.c_str());

    return config;
}

bool WriteBytes(void* address, const void* data, std::size_t size) {
    DWORD oldProtect = 0;
    if (!VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }

    std::memcpy(address, data, size);
    FlushInstructionCache(GetCurrentProcess(), address, size);

    DWORD restoreProtect = 0;
    VirtualProtect(address, size, oldProtect, &restoreProtect);
    return true;
}

template <typename T>
bool WriteValue(std::uintptr_t address, const T& value) {
    return WriteBytes(reinterpret_cast<void*>(address), &value, sizeof(value));
}

const SampVersionInfo* DetectSampVersion(HMODULE sampModule) {
    if (sampModule == nullptr) {
        return nullptr;
    }

    const auto* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(sampModule);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return nullptr;
    }

    const auto* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS32*>(
        reinterpret_cast<const std::uint8_t*>(sampModule) + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        return nullptr;
    }

    const DWORD entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    for (const auto& version : kSupportedVersions) {
        if (version.entryPointRva == entryPoint) {
            return &version;
        }
    }

    return nullptr;
}

DWORD WINAPI HookGetTickCount() {
    if (g_config.timeMs == -1) {
        ExitProcess(0);
    }

    if (g_config.timeMs == -2) {
        TerminateProcess(GetCurrentProcess(), 0);
    }

    return ::GetTickCount();
}

bool InstallGetTickCountHook(std::uintptr_t callAddress) {
    std::uint8_t opcodeBytes[2] = {};
    std::memcpy(opcodeBytes, reinterpret_cast<const void*>(callAddress), sizeof(opcodeBytes));

    if (opcodeBytes[0] == 0xE8) {
        const auto hookAddress = reinterpret_cast<std::uintptr_t>(&HookGetTickCount);
        const long long relative = static_cast<long long>(hookAddress)
            - static_cast<long long>(callAddress + sizeof(RelativeCallPatch));

        if (relative < std::numeric_limits<std::int32_t>::min()
            || relative > std::numeric_limits<std::int32_t>::max()) {
            return false;
        }

        const RelativeCallPatch patch{
            0xE8,
            static_cast<std::int32_t>(relative),
        };
        return WriteBytes(reinterpret_cast<void*>(callAddress), &patch, sizeof(patch));
    }

    if (opcodeBytes[0] == 0xFF && opcodeBytes[1] == 0x15) {
        const IndirectCallPatch patch{
            0xFF,
            0x15,
            reinterpret_cast<std::uint32_t>(&g_hookTargetAddress),
        };
        return WriteBytes(reinterpret_cast<void*>(callAddress), &patch, sizeof(patch));
    }

    return false;
}

bool ApplyPatches(HMODULE sampModule, const SampVersionInfo& version) {
    const std::uintptr_t sampBase = reinterpret_cast<std::uintptr_t>(sampModule);
    const std::uint32_t delay = g_config.timeMs >= 0 ? static_cast<std::uint32_t>(g_config.timeMs) : 0u;

    if (!WriteValue(sampBase + version.timeOperandOffset, delay)) {
        return false;
    }

    return InstallGetTickCountHook(sampBase + version.getTickCountCallOffset);
}

DWORD WINAPI InitializePlugin(void*) {
    const auto* gtaLoadState = reinterpret_cast<volatile DWORD*>(kGtaLoadStateAddress);
    while (*gtaLoadState < 9) {
        Sleep(10);
    }

    g_config = LoadConfig();
    g_hookTargetAddress = reinterpret_cast<std::uint32_t>(&HookGetTickCount);

    for (;;) {
        HMODULE sampModule = GetModuleHandleA("samp.dll");
        if (sampModule != nullptr) {
            const auto* version = DetectSampVersion(sampModule);
            if (version != nullptr) {
                ApplyPatches(sampModule, *version);
            }
            return 0;
        }

        Sleep(100);
    }
}

}  // namespace

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_module = module;
        DisableThreadLibraryCalls(module);

        HANDLE thread = CreateThread(nullptr, 0, &InitializePlugin, nullptr, 0, nullptr);
        if (thread != nullptr) {
            CloseHandle(thread);
        }
    }

    return TRUE;
}
