#include <Windows.h>
#pragma comment(lib, "WS2_32.lib")

void init_game();
void init_game_new();
void init_server();

HMODULE hModule;

BOOL APIENTRY DllMain(HMODULE hM , DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        hModule = hM;
        if (GetModuleHandleA("Game.dll"))
            init_game();
        else if (GetModuleHandleA("Warcraft III.exe") == GetModuleHandleA(NULL))
            init_game_new();
        else
            init_server();
    }
    else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
        TerminateProcess(GetCurrentProcess(), 0);
    }
    return TRUE;
}