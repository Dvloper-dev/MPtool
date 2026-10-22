
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const uint8_t kPrologue2650[12] = {
    0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x28, 0x4C, 0x89, 0xCB
};
static const uint8_t kPrologue2644[12] = {
    0x41, 0x56, 0x56, 0x57, 0x53, 0x48, 0x83, 0xEC, 0x38, 0x4C, 0x89, 0xCB
};

static const int kPattern2650[] = {
    0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xEC,0x28,0x4C,0x89,0xCB,0x4D,0x89,0xC6,
    0x48,0x89,0xD7,0x48,0x89,0xCE,0x48,0x8B,0x02,0x48,0x8B,0x80,0xB8,0x03,0x00,
    0x00,0x48,0x89,0xD1,0xFF,0x15,-1,-1,-1,-1,0x84,0xC0,0x0F,0x84,-1,-1,-1,-1
};
static const int kPattern2644[] = {
    0x41,0x56,0x56,0x57,0x53,0x48,0x83,0xEC,0x38,0x4C,0x89,0xCB,0x4D,0x89,0xC6,
    0x48,0x89,0xD7,0x48,0x89,0xCE,0x48,0x8B,0x02,0x48,0x8B,0x80,0xC0,0x03,0x00,
    0x00,0x48,0x89,0xD1,0xFF,0x15,-1,-1,-1,-1,0x84,0xC0,0x0F,0x84,-1,-1,-1,-1
};
static const size_t kStealSize = 15;
static const uintptr_t kFallbackRva2650 = 0x41E7AD0;
static const uintptr_t kFallbackRva2644 = 0x4225320;

static const char kOwned[] = "store.owned";
static const char kIncompatible[] = "store.incompatible";

static const int kGatePattern[] = {
    0x48,0x8B,0x89,0x88,0x00,0x00,0x00,0x48,0x81,0xC2,0x68,0x01,0x00,0x00,0x48,
    0x8B,0x01,0x48,0x8B,0x40,0x10,0x4C,0x8D,0x85,-1,-1,-1,-1,0xFF,0x15,-1,-1,
    -1,-1,0x84,0xC0,0x74,0x48
};
static const size_t kGatePatternLen = sizeof(kGatePattern) / sizeof(kGatePattern[0]);
static const size_t kGateJzOffset = 36;

static bool IsReadable(void* p, size_t n) {
    MEMORY_BASIC_INFORMATION mi;
    if (!VirtualQuery(p, &mi, sizeof(mi))) return false;
    if (mi.State != MEM_COMMIT) return false;
    if (mi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) return false;
    uintptr_t base = (uintptr_t)mi.BaseAddress, end = base + mi.RegionSize;
    return (uintptr_t)p >= base && (uintptr_t)p + n <= end;
}

static void Log(const char* msg) {
    char path[MAX_PATH];
    if (!GetTempPathA(MAX_PATH, path)) return;
    strcat_s(path, "ApollonMarketplaceUnlock.log");
    FILE* f = NULL;
    fopen_s(&f, path, "a");
    if (f) { fputs(msg, f); fputc('\n', f); fclose(f); }
}

static uint8_t* ScanModule(HMODULE mod, const int* pat, size_t len) {
    auto* dos = (IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, ".text", 5) != 0) continue;
        uint8_t* base = (uint8_t*)mod + sec->VirtualAddress;
        size_t size = sec->Misc.VirtualSize;
        if (len == 0 || size < len) continue;
        for (size_t o = 0; o + len <= size; o++) {
            bool ok = true;
            for (size_t j = 0; j < len; j++) {
                if (pat[j] >= 0 && base[o + j] != (uint8_t)pat[j]) { ok = false; break; }
            }
            if (ok) return base + o;
        }
    }
    return NULL;
}

typedef char* (__fastcall* OwnedStatusFn)(char* out, void* item, void* a3, void* a4);
static OwnedStatusFn g_orig = NULL;

static void WriteAbsJump64(uint8_t* at, void* dst) {
    DWORD old = 0;
    VirtualProtect(at, 14, PAGE_EXECUTE_READWRITE, &old);
    at[0] = 0xFF; at[1] = 0x25;
    *(uint32_t*)(at + 2) = 0;
    *(uint64_t*)(at + 6) = (uint64_t)dst;
    VirtualProtect(at, 14, old, &old);
    FlushInstructionCache(GetCurrentProcess(), at, 14);
}

static void ForceOwned(char* s) {
    size_t sz = *(size_t*)(s + 16);
    char* data = (sz < 16) ? s : *(char**)s;
    if (!data) return;
    if (strcmp(data, kIncompatible) == 0) return;
    memcpy(data, kOwned, sizeof(kOwned));
    *(size_t*)(s + 16) = sizeof(kOwned) - 1;
}

static unsigned char __fastcall EntAlwaysTrue(void*) { return 1; }
static volatile LONG g_entPatched = 0;

static bool IsCodePtr(HMODULE mod, const void* p) {
    if (!p) return false;
    auto* dos = (IMAGE_DOS_HEADER*)mod;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = (IMAGE_NT_HEADERS64*)((uint8_t*)mod + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (!(sec->Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
        uint8_t* base = (uint8_t*)mod + sec->VirtualAddress;
        uint8_t* end = base + sec->Misc.VirtualSize;
        if ((const uint8_t*)p >= base && (const uint8_t*)p < end) return true;
    }
    return false;
}

static void TryPatchEntitlement(void* ent) {
    if (!ent || g_entPatched) return;
    if (!IsReadable(ent, sizeof(void*))) return;
    void** vt = *(void***)ent;
    if (!IsReadable(vt, 5 * sizeof(void*))) return;

    HMODULE game = GetModuleHandleA(NULL);
    char buf[320];
    sprintf_s(buf, " entitlement %p vtable %p slots 0-4: %p %p %p %p %p",
              ent, vt, vt[0], vt[1], vt[2], vt[3], vt[4]);
    Log(buf);

    if (!IsCodePtr(game, vt[3]) || vt[3] == (void*)EntAlwaysTrue) {
        Log(" entitlement: slot3 is not game code (skip)");
        InterlockedExchange(&g_entPatched, 1);
        return;
    }
    const uint8_t* g2 = (const uint8_t*)vt[2];
    if (!IsCodePtr(game, g2) || !IsReadable((void*)g2, 12)) {
        Log(" entitlement: slot2 not readable (skip)");
        InterlockedExchange(&g_entPatched, 1);
        return;
    }
    bool tinyGetter =
        (g2[0] == 0x8B && (g2[1] == 0x81 || g2[1] == 0x41)) ||
        (g2[0] == 0x8A && (g2[1] == 0x81 || g2[1] == 0x41)) ||
        (g2[0] == 0x0F && (g2[1] == 0xB6 || g2[1] == 0xB7) &&
         (g2[2] == 0x81 || g2[2] == 0x41)) ||
        (g2[0] == 0x48 && g2[1] == 0x8B && (g2[2] == 0x81 || g2[2] == 0x41));
    if (!tinyGetter) {
        sprintf_s(buf, " entitlement: slot2 %p not a getter (%02X %02X %02X %02X), skip",
                  g2, g2[0], g2[1], g2[2], g2[3]);
        Log(buf);
        InterlockedExchange(&g_entPatched, 1);
        return;
    }

    void* orig = vt[3];
    DWORD old = 0;
    if (!VirtualProtect(&vt[3], sizeof(void*), PAGE_READWRITE, &old)) {
        Log(" entitlement: VirtualProtect failed");
        return;
    }
    InterlockedExchangePointer((PVOID volatile*)&vt[3], (PVOID)EntAlwaysTrue);
    VirtualProtect(&vt[3], sizeof(void*), old, &old);
    FlushInstructionCache(GetCurrentProcess(), vt, 5 * sizeof(void*));
    InterlockedExchange(&g_entPatched, 1);
    sprintf_s(buf, "OK: Entitlement::isOwned patched (vtable slot3 %p -> true)", orig);
    Log(buf);
}

static char* __fastcall OwnedStatusHook(char* out, void* item, void* a3, void* a4) {
    char* ret = g_orig(out, item, a3, a4);
    TryPatchEntitlement(a4);
    ForceOwned(out);
    return ret;
}

static bool InstallHook(uint8_t* target, const uint8_t* prologue) {
    if (memcmp(target, prologue, 12) != 0) return false;
    uint8_t* tram = (uint8_t*)VirtualAlloc(NULL, 64, MEM_COMMIT | MEM_RESERVE,
                                           PAGE_EXECUTE_READWRITE);
    if (!tram) return false;
    memcpy(tram, target, kStealSize);
    WriteAbsJump64(tram + kStealSize, target + kStealSize);
    g_orig = (OwnedStatusFn)tram;
    WriteAbsJump64(target, (void*)OwnedStatusHook);
    return true;
}

static void PatchOwnershipGate(HMODULE game) {
    uint8_t* site = ScanModule(game, kGatePattern, kGatePatternLen);
    if (!site) { Log(" gate: sig not found (skip)"); return; }
    if (!IsReadable(site + kGateJzOffset, 1)) { Log(" gate: unreadable"); return; }
    DWORD old = 0;
    if (!VirtualProtect(site + kGateJzOffset, 1, PAGE_EXECUTE_READWRITE, &old)) {
        Log(" gate: VirtualProtect failed"); return;
    }
    site[kGateJzOffset] = 0xEB;
    VirtualProtect(site + kGateJzOffset, 1, old, &old);
    FlushInstructionCache(GetCurrentProcess(), site + kGateJzOffset, 1);
    Log("OK: ownership gate patched (jz->jmp)");
}

struct Target {
    const int* pat;
    size_t pat_len;
    const uint8_t* prologue;
    uintptr_t fallback_rva;
    const char* name;
};

static const Target kTargets[] = {
    { kPattern2650, sizeof(kPattern2650) / sizeof(kPattern2650[0]), kPrologue2650,
      kFallbackRva2650, "26.50" },
    { kPattern2644, sizeof(kPattern2644) / sizeof(kPattern2644[0]), kPrologue2644,
      kFallbackRva2644, "26.44" },
};

static DWORD WINAPI InitThread(LPVOID) {
    HMODULE game = GetModuleHandleA(NULL);
    if (!game) { Log("FAIL: no host module"); return 1; }

    const Target* hit = NULL;
    uint8_t* target = NULL;
    for (size_t i = 0; i < sizeof(kTargets) / sizeof(kTargets[0]); i++) {
        target = ScanModule(game, kTargets[i].pat, kTargets[i].pat_len);
        if (target) { hit = &kTargets[i]; break; }
    }

    if (target) {
        char buf[160];
        sprintf_s(buf, " [%s] sig found at %p", hit->name, target);
        Log(buf);
    } else {

        for (size_t i = 0; i < sizeof(kTargets) / sizeof(kTargets[0]); i++) {
            uint8_t* cand = (uint8_t*)game + kTargets[i].fallback_rva;
            if (IsReadable(cand, 12) && memcmp(cand, kTargets[i].prologue, 12) == 0) {
                target = cand;
                hit = &kTargets[i];
                break;
            }
        }
        Log(target ? " fallback RVA matched" : "FAIL: target not found");
    }
    if (!target) return 1;

    PatchOwnershipGate(game);
    if (InstallHook(target, hit->prologue))
        Log("OK: marketplace unlock active (store.owned forced)");
    else
        Log("FAIL: hook install failed");
    return 0;
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        HANDLE t = CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
        if (t) CloseHandle(t);
    }
    return TRUE;
}
