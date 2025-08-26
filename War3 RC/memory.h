#pragma once
#include <stdint.h>
#include <Windows.h>
#include <detours/detours.h>

// 只是为了方便理解
template<class t = uint32_t>
inline t ReadMemory(uint32_t addr) {
    return *(t*)addr;
}
template<class t = uint32_t>
inline void WriteMemory(uint32_t addr, t value) {
    *(t*)addr = value;
}
template<class t = uint32_t>
void WriteMemoryEx(uint32_t addr, t value) {
    DWORD old;
    VirtualProtect((void*)addr, sizeof(t), PAGE_EXECUTE_READWRITE, &old); // 不检查成功与否 因为失败了游戏可能就会异步 不如直接崩游戏
    WriteMemory(addr, value);
    VirtualProtect((void*)addr, sizeof(t), old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, sizeof(t)); // 安全起见还是加上好了
}
inline void memsetEx(uint32_t addr, uint8_t value, uint32_t size) {
    DWORD old;
    VirtualProtect((void*)addr, size, PAGE_EXECUTE_READWRITE, &old); // 不检查成功与否 因为失败了游戏可能就会异步 不如直接崩游戏
    memset((void*)addr, value, size);
    VirtualProtect((void*)addr, size, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)addr, size); // 安全起见还是加上好了
}
inline void memcpyEx(uint32_t dest, const void* src, uint32_t size) {
    DWORD old;
    VirtualProtect((void*)dest, size, PAGE_EXECUTE_READWRITE, &old); // 不检查成功与否 因为失败了游戏可能就会异步 不如直接崩游戏
    memcpy((void*)dest, src, size);
    VirtualProtect((void*)dest, size, old, &old);
    FlushInstructionCache(GetCurrentProcess(), (void*)dest, size); // 安全起见还是加上好了
}
template<class t>
inline void PatchCallRelative(uint32_t addr, t func) {
    WriteMemoryEx(addr + 1, (uint32_t)func - addr - 5);
}
template<class t>
inline void SetCallRelative(uint32_t addr, t func, uint32_t padding) {
    WriteMemoryEx<uint8_t>(addr, 0xE8);
    WriteMemoryEx(addr + 1, (uint32_t)func - addr - 5);
    if (padding)
        memsetEx(addr + 5, 0x90, padding);
}
inline void hook_func(uint32_t* real, uint32_t fake) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach((PVOID*)real, (PVOID)fake);
    DetourTransactionCommit();
}
template<class A, class B>
inline void hook_func_s(A real, B fake) {
    hook_func((uint32_t*)real, (uint32_t)fake);
}
inline void unhook_func(uint32_t* real, uint32_t fake) {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach((PVOID*)real, (PVOID)fake);
    DetourTransactionCommit();
}
template<class A, class B>
inline void unhook_func_s(A real, B fake) {
    unhook_func((uint32_t*)real, (uint32_t)fake);
}
static bool can_read(void* ptr, size_t byteCount) {
    // https://stackoverflow.com/questions/18394647/can-i-check-if-memory-block-is-readable-without-raising-exception-with-c
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    switch (mbi.Protect) {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
        break;
    default:
        return false;
    }

    // This checks that the start of memory block is in the same "region" as the
    // end. If it isn't you "simplify" the problem into checking that the rest of 
    // the memory is readable.
    size_t blockOffset = (size_t)ptr - (size_t)mbi.BaseAddress;
    size_t blockBytesPostPtr = mbi.RegionSize - blockOffset;

    if (blockBytesPostPtr < byteCount)
        return can_read((void*)((size_t)ptr + blockBytesPostPtr),
            byteCount - blockBytesPostPtr);

    return true;
}
static bool can_read_write(void* ptr, size_t byteCount) {
    // https://stackoverflow.com/questions/18394647/can-i-check-if-memory-block-is-readable-without-raising-exception-with-c
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    switch (mbi.Protect) {
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        break;
    default:
        return false;
    }

    // This checks that the start of memory block is in the same "region" as the
    // end. If it isn't you "simplify" the problem into checking that the rest of 
    // the memory is readable.
    size_t blockOffset = (size_t)ptr - (size_t)mbi.BaseAddress;
    size_t blockBytesPostPtr = mbi.RegionSize - blockOffset;

    if (blockBytesPostPtr < byteCount)
        return can_read_write((void*)((size_t)ptr + blockBytesPostPtr),
            byteCount - blockBytesPostPtr);

    return true;
}
static bool can_execute(void* ptr, size_t byteCount) {
    // https://stackoverflow.com/questions/18394647/can-i-check-if-memory-block-is-readable-without-raising-exception-with-c
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(ptr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
        return false;

    if (mbi.State != MEM_COMMIT)
        return false;

    switch (mbi.Protect) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        break;
    default:
        return false;
    }

    // This checks that the start of memory block is in the same "region" as the
    // end. If it isn't you "simplify" the problem into checking that the rest of 
    // the memory is readable.
    size_t blockOffset = (size_t)ptr - (size_t)mbi.BaseAddress;
    size_t blockBytesPostPtr = mbi.RegionSize - blockOffset;

    if (blockBytesPostPtr < byteCount)
        return can_execute((void*)((size_t)ptr + blockBytesPostPtr),
            byteCount - blockBytesPostPtr);

    return true;
}
static bool is_valid_class(void* ptr) {
    if (!can_read(ptr, 4)) // test read vfn
        return false;

    uint32_t vfn = ReadMemory((uint32_t)ptr);

    if (!can_read((void*)(vfn - 4), 8) || !can_execute(ReadMemory<void*>(vfn), 4))  // test read RTTI Complete Object Locator & first vfn executable
        return false;

    return true;
}