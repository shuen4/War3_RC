#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <string>
#include <detours/detours.h>
#include <vector>
#include "fp_call.h"
#include "memory.h"
#include "base64.h"
#include "util.h"

// 1.29+ default calling conversion is __cdecl
// if we do it at same file as old version
// then code is very ugly
extern HMODULE hModule;
namespace client_new {
#pragma region war3
    uint32_t base;
    enum class VERSION {
        V1_29_2_9231,
    };
    VERSION version;
    enum PROPERTY {
        PROP_NET = 0xE,
    };
    class Node {
    public:
        Node* prev;
        uint32_t* next;

        __inline static bool LIST_IS_TERM(uint32_t* ptr) {
            return (int32_t)ptr <= 0;
        }
        __inline Node* NextLink(uint32_t link_offset) {
            if (!LIST_IS_TERM(next))
                return (Node*)((uint32_t)this + (uint32_t)next - (uint32_t)prev->next);
            else
                return (Node*)(~(uint32_t)next);
        }
        __inline uint32_t* Next() {
            if (LIST_IS_TERM(next))
                return NULL;
            return next;
        }
        __inline void Unlink() {
            if ((int32_t)prev > 0) {
                NextLink(-1)->prev = prev;
                prev->next = next;
                prev = NULL;
                next = NULL;
            }
        }
    };
    class __list {
    public:
        uint32_t link_offset;
        Node terminator;

        __inline Node* Head() {
            return (Node*)terminator.Next();
        }
    };
    struct GAMEDATA {
        char name[32];
        char password[16];
        char desc[320];
        uint32_t max_players;
        uint32_t category_id;
    }; static_assert(sizeof(GAMEDATA) == 376);
    uint32_t(__cdecl* PropGet)(PROPERTY);
    uint32_t(__thiscall* CNetData_OnIdle)(uint32_t _this, uint32_t);
    void(__cdecl* Net_NetClient_FlushUnsentTurns)(uint32_t _this);
    BOOL(__cdecl* Net_CheckAllowCommand)(uint32_t, uint32_t, uint32_t, uint32_t*);
    void(__cdecl* Net_NetClient_SendTurn)(uint32_t _this, Node*);
    void(__thiscall* TInstanceRecycler_Net_ClientTurn_Put)(uint32_t _this, Node*);
    void(__cdecl* CGlueMgr_SetGlueScreen)(uint32_t a1, uint32_t a2);
    void(__cdecl* NetInitializeProvider)(uint32_t id, uint32_t a2);
    uint32_t(__thiscall* Net_NetProvider_RemoteAdAdd)(uint32_t _this, sockaddr_in*, sockaddr_in*, uint32_t gameID, uint32_t game_secret, uint32_t programID, uint32_t version, GAMEDATA* game_data, uint32_t player, uint32_t max_player, uint32_t creation_time, uint32_t a13, uint32_t a14);
    void(__cdecl* NetGlueGameJoin)(uint32_t game_list_ID, uint32_t, const char* password, const char* player_name, uint32_t, uint32_t playerID);
    void(__thiscall* Net_NetProvider_RemoteAdFind)(uint32_t _this, uint32_t game_list_ID, const char* game_name, uint32_t* gameID, uint32_t* game_secret, sockaddr_in* addr, GAMEDATA* game_data);
    void(__thiscall* Net_NetProvider_JoinGame)(uint32_t _this, uint32_t game_list_ID, const char* game_password, uint32_t a4);
    uint32_t(__thiscall* CGameWar3_GetPlayer)(uint32_t _this, uint32_t player_id);
    void(__thiscall* CSelectionWar3_Realize)(uint32_t _this, uint32_t additive);
    void(__cdecl* RefreshUI)(BOOL);
    void(__thiscall* CSelectionWar3_ClearSelectionLocal)(uint32_t _this, uint32_t player_id, uint32_t);
    void(__thiscall* CSelectionWar3_AddLocal)(uint32_t _this, uint32_t unit, uint32_t player_id, uint32_t, uint32_t, uint32_t);
    uint32_t* CGameWar3;
    uint32_t CNetData_offset_viewSpeedMultiplier;
    uint32_t NetClient_offset_turnRecycler;
    uint32_t NetProvider_offset_maxGames;
    uint32_t NetClient_offset_turnUnsent;
    uint32_t NetClient_offset_router;
    uint32_t NetClient_offset_timer;
    uint32_t NetClient_flush_factor1;
    uint32_t NetClient_flush_factor2;
#pragma endregion

#pragma region game util
#define SERVER_IP_MASK 0x8000007F // 127.0.0.128
#define SERVER_IP(pid) (SERVER_IP_MASK | ((pid << 8) & 0x7FFFFF00))

    void(__cdecl* real_Net_NetClient_FlushUnsentTurns)(uint32_t _this);
    void __cdecl fake_Net_NetClient_FlushUnsentTurns(uint32_t _this) {
        if (ReadMemory(ReadMemory(_this + NetClient_offset_router) + 0x3C)) {
            while (auto node = (Node*)ReadMemory(_this + NetClient_offset_turnUnsent)) {
                uint32_t ondata = 2;
                uint32_t tmp = 1000 * ReadMemory((uint32_t)node + 0xC) / NetClient_flush_factor1;
                if (!Net_CheckAllowCommand(_this + NetClient_offset_timer, min(tmp, NetClient_flush_factor2), 0, &ondata))
                    return;
                Net_NetClient_SendTurn((int)_this, node);
                WriteMemory(_this + NetClient_offset_turnUnsent, node->Next());
                node->Unlink();
                TInstanceRecycler_Net_ClientTurn_Put(_this + NetClient_offset_turnRecycler, node);
            }
        }
    }
#pragma endregion

    static int(WSAAPI* real_connect)(SOCKET s, const sockaddr* name, int namelen) = connect;
#pragma region connect
    GAMEDATA g_GameData;
    bool do_redirect = false;
    uint32_t(__thiscall* real_Net_NetProvider_JoinGame)(uint32_t _this, uint32_t game_list_ID, const char* game_password, uint32_t a4);
    uint32_t __fastcall fake_Net_NetProvider_JoinGame(uint32_t _this, uint32_t, uint32_t game_list_ID, const char* game_password, uint32_t a4) {
        sockaddr_in addr;
        uint32_t gameID;
        uint32_t game_secret;

        // save game data and send it to server later
        Net_NetProvider_RemoteAdFind(_this, game_list_ID, NULL, &gameID, &game_secret, &addr, &g_GameData);

        do_redirect = true;
        auto ret = real_Net_NetProvider_JoinGame(_this, game_list_ID, game_password, a4);
        do_redirect = false;

        return ret;
    }
    int WSAAPI fake_connect(SOCKET s, const sockaddr* name, int namelen) {
        if (!do_redirect)
            return real_connect(s, name, namelen);

        do_redirect = false;
#define BUFFER_SIZE 4096
        // construct command line
        std::string commandline = "\"rundll32.exe\" \"";
        commandline.resize(BUFFER_SIZE + commandline.size());
        uint32_t filepath_size = GetModuleFileNameA(hModule, &commandline[commandline.size() - BUFFER_SIZE], BUFFER_SIZE);
        commandline.resize(commandline.size() - BUFFER_SIZE + filepath_size);
        commandline += "\",#1";
        commandline += '\0';

        // start local server
        STARTUPINFOA si{};
        si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessA(NULL, &commandline[0], NULL, NULL, FALSE, HIGH_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
            MessageBoxA(NULL, "create local server process failed", "Error", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
            return real_connect(s, name, namelen);
        }

        // redirect to connect local server
        sockaddr_in sin = {};
        sin.sin_family = AF_INET;
        sin.sin_addr.S_un.S_addr = SERVER_IP(pi.dwProcessId);
        sin.sin_port = htons(44444);

        // set tcp no delay
        int OptVal = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&OptVal, sizeof(int));

        // set socket blocking
        int iMode = 0;
        ioctlsocket(s, FIONBIO, (u_long FAR*) & iMode);

        // fill infomation required
        uint8_t buffer[sizeof(sockaddr_in) + sizeof(uint64_t)]{};
        // #1: target server addressz
        memcpy(buffer, name, sizeof(sockaddr_in));
        auto game_desc = DecodeGameDesc(g_GameData.desc);
        // #2: game type
        buffer[sizeof(sockaddr_in) + 0] = game_desc[0];
        buffer[sizeof(sockaddr_in) + 1] = game_desc[1];
        buffer[sizeof(sockaddr_in) + 2] = game_desc[2];
        buffer[sizeof(sockaddr_in) + 3] = game_desc[3];
        buffer[sizeof(sockaddr_in) + 4] = game_desc[4];
        // pad to uint64_t so we can just read uint64_t later
        buffer[sizeof(sockaddr_in) + 5] = 0;
        buffer[sizeof(sockaddr_in) + 6] = 0;
        buffer[sizeof(sockaddr_in) + 7] = 0;

        // connect to local server
        auto ret = real_connect(s, (sockaddr*)&sin, sizeof(sin));
        // send required infomation to server
        send(s, (char*)buffer, sizeof(buffer), 0);
        uint32_t len = strlen(GetCommandLineA());
        send(s, (char*)&len, sizeof(len), 0);
        send(s, GetCommandLineA(), len, 0);

        // set socket non - blocking
        iMode = 1;
        ioctlsocket(s, FIONBIO, (u_long FAR*) & iMode);

        // clean up
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        return ret;
    }
#pragma endregion

#pragma region reconnect
#define FF_SPEED 65535
    uint32_t rc_PID;
    HANDLE rc_event;
    uint64_t rc_game_type;
    std::string rc_player_name;
    int WSAAPI fake_connect_RC(SOCKET s, const sockaddr* name, int namelen) {
        // set tcp no delay
        int OptVal = 1;
        setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (const char*)&OptVal, sizeof(int));

        return real_connect(s, name, namelen);
    }
    uint32_t(__thiscall* real_CNetData_OnIdle)(uint32_t _this, uint32_t);
    uint32_t __fastcall fake_CNetData_OnIdle(uint32_t _this, uint32_t, uint32_t a2) {
        // if we are reconnecting
        if (rc_event) {
            auto ret = WaitForSingleObject(rc_event, 0);
            if (ret == WAIT_OBJECT_0) {
                // reconnect completed
                // restore all modified game code
                WriteMemory(_this + CNetData_offset_viewSpeedMultiplier, 1); // view speed multiplier
                switch (version) {
                case VERSION::V1_29_2_9231:
                    WriteMemoryEx<uint8_t>(base + 0x1AF197, 0x0F); //
                    WriteMemoryEx<uint8_t>(base + 0x1AF198, 0x42); // process up to 4000ms
                    WriteMemoryEx<uint8_t>(base + 0x1AF3FC, 0x76); // fast forward up to 200ms
                    break;
                default:
                    __debugbreak();
                }
                CloseHandle(rc_event);
                rc_event = NULL;
                // sync selection
                if (auto player = CGameWar3_GetPlayer(*CGameWar3, ReadMemory<uint16_t>(*CGameWar3 + 0x28)))
                    if (auto selection = ReadMemory(player + 0x34)) {
                        uint32_t player_id = ReadMemory(selection + 0x1AC);

                        // reset current selection
                        CSelectionWar3_ClearSelectionLocal(selection, player_id, NULL);
                        auto ptr = ((__list*)(selection + 0x4))->Head();
                        while (ptr) {
                            if (auto unit = ReadMemory((uint32_t)ptr + 0x8)) {
                                this_call_vf<void>(unit, 404, 1, 0, 1, 0, player_id);
                                CSelectionWar3_AddLocal(selection, unit, player_id, 0, 0, 1);
                            }
                            ptr = (Node*)ptr->Next();
                        }

                        // reset subgroup
                        for (uint32_t i = 0; i < 10; i++) {
                            auto sync_set = selection + 0x14 + i * 0x14;
                            auto local_set = selection + 0xDC + i * 0x14;
                            auto sync_set_list = (__list*)((uint32_t)sync_set + 0x4);

                            this_call_vf<void>(local_set, 0xC);
                            ptr = sync_set_list->Head();
                            while (ptr) {
                                if (auto unit = ReadMemory((uint32_t)ptr + 0x8)) {
                                    this_call_vf<void>(local_set, 0x4, unit, 0, 1);
                                }
                                ptr = (Node*)ptr->Next();
                            }
                        }

                        CSelectionWar3_Realize(selection, true);
                        RefreshUI(false);
                    }
            }
            else if (ret == WAIT_TIMEOUT) {
                // set view speed
                WriteMemory(_this + CNetData_offset_viewSpeedMultiplier, FF_SPEED); // view speed multiplier
            }
            else {
                // this should not happen at all
                MessageBoxA(NULL, "internal error while reconnecting", "Error", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                exit(1);
            }
        }
        return real_CNetData_OnIdle(_this, a2);
    }

    void(__cdecl* real_CGlueMgr_SetGlueScreen)(uint32_t a1, uint32_t a2);
    void __cdecl fake_CGlueMgr_SetGlueScreen(uint32_t a1, uint32_t a2) {
        // main menu
        if (a1 == 2) {
            // initialize NetProvider
            NetInitializeProvider('TCPN', 0);

            // set to LAN menu
            real_CGlueMgr_SetGlueScreen(8, 1);

            // construct local server address
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_addr.S_un.S_addr = SERVER_IP(rc_PID);
            addr.sin_port = htons(44444);

            // construct raw game data;
            std::vector<uint8_t> raw_game_data;

            // game type
            raw_game_data.push_back((rc_game_type >> 0) & 0xFF);
            raw_game_data.push_back((rc_game_type >> 8) & 0xFF);
            raw_game_data.push_back((rc_game_type >> 16) & 0xFF);
            raw_game_data.push_back((rc_game_type >> 24) & 0xFF);
            raw_game_data.push_back((rc_game_type >> 32) & 0xFF);

            // map width
            raw_game_data.push_back(0x00);
            raw_game_data.push_back(0x00);

            // map height
            raw_game_data.push_back(0x00);
            raw_game_data.push_back(0x00);

            // CRC (disable CRC check)
            raw_game_data.push_back(0xFF);
            raw_game_data.push_back(0xFF);
            raw_game_data.push_back(0xFF);
            raw_game_data.push_back(0xFF);

            // file path
            raw_game_data.insert(raw_game_data.end(), (uint8_t*)"Reconnect", (uint8_t*)"Reconnect" + sizeof("Reconnect"));

            // host name
            raw_game_data.insert(raw_game_data.end(), (uint8_t*)"Reconnect", (uint8_t*)"Reconnect" + sizeof("Reconnect"));

            // ???
            raw_game_data.push_back(0);

            // encode
            std::vector<uint8_t> game_desc = EncodeGameDesc(raw_game_data);

            // construct game data
            GAMEDATA game_data{};
            // game name
            strcpy_s(game_data.name, "Reconnect");
            // encoded game data
            strncpy_s(game_data.desc, (char*)&game_desc[0], game_desc.size());
            // max player (not important)
            game_data.max_players = 24;
            // ???
            game_data.category_id = 0;

            // get net provider
            uint32_t net = PropGet(PROP_NET);

            // set max game (default 0)
            WriteMemory(net + NetProvider_offset_maxGames, 1);

            // add game and send join request
            NetGlueGameJoin(Net_NetProvider_RemoteAdAdd(net, &addr, &addr, 1, 0, ReadMemory(net + 0x24), ReadMemory(net + 0x28), &game_data, 1, 12, 0, NULL, 1), 0, "", rc_player_name.c_str(), 0, 0);
            return;
        }
        return real_CGlueMgr_SetGlueScreen(a1, a2);
    }
#pragma endregion
}
void init_game_new() {
    using namespace client_new;
    // get base address
    base = (uint32_t)GetModuleHandleA(NULL);

    // get timestamp (for version check)
    IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)base;
    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)((uint32_t)dos_header + dos_header->e_lfanew);
    uint32_t timestap = nt_header->FileHeader.TimeDateStamp;

    if (timestap == 0x5AE8F617) {
        version = VERSION::V1_29_2_9231;
        WriteMemory((uint32_t)&PropGet                                  , base + 0x05DF90);
        WriteMemory((uint32_t)&CNetData_OnIdle                          , base + 0x1AEFD0);
        WriteMemory((uint32_t)&Net_NetClient_FlushUnsentTurns           , base + 0x542440);
        WriteMemory((uint32_t)&Net_CheckAllowCommand                    , base + 0x52E010);
        WriteMemory((uint32_t)&Net_NetClient_SendTurn                   , base + 0x549430);
        WriteMemory((uint32_t)&TInstanceRecycler_Net_ClientTurn_Put     , base + 0x5486F0);
        WriteMemory((uint32_t)&CGlueMgr_SetGlueScreen                   , base + 0x186100);
        WriteMemory((uint32_t)&NetInitializeProvider                    , base + 0x1AD390);
        WriteMemory((uint32_t)&Net_NetProvider_RemoteAdAdd              , base + 0x5390A0);
        WriteMemory((uint32_t)&NetGlueGameJoin                          , base + 0x11EFA0);
        WriteMemory((uint32_t)&Net_NetProvider_RemoteAdFind             , base + 0x539470);
        WriteMemory((uint32_t)&Net_NetProvider_JoinGame                 , base + 0x537E60);
        WriteMemory((uint32_t)&CGameWar3                                , base + 0xD3B6F4);
        WriteMemory((uint32_t)&CGameWar3_GetPlayer                      , base + 0x0777D0);
        WriteMemory((uint32_t)&CSelectionWar3_Realize                   , base + 0x0F3070);
        WriteMemory((uint32_t)&RefreshUI                                , base + 0x1F6E50);
        WriteMemory((uint32_t)&CSelectionWar3_ClearSelectionLocal       , base + 0x0F1760);
        WriteMemory((uint32_t)&CSelectionWar3_AddLocal                  , base + 0x0EFC40);
        CNetData_offset_viewSpeedMultiplier                             = 0x2680;
        NetClient_offset_turnRecycler                                   = 0x2A8;
        NetProvider_offset_maxGames                                     = 0x514;
        NetClient_offset_turnUnsent                                     = 0x2D0;
        NetClient_offset_router                                         = 0x208;
        NetClient_offset_timer                                          = 0x2C0;
        NetClient_flush_factor1                                         = 0xFA0;
        NetClient_flush_factor2                                         = 0x3E;
        WriteMemoryEx<uint16_t>(base + 0x548349                         , 0xE990);              // validate packet will be done at local server side
    }
    else {
        MessageBoxA(NULL, "version not supported", "Error", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    // if not reconnecting
    if (std::string(GetCommandLineA()).find("-reconnect") == std::string::npos) {
        // modify game code
        DetourAttach(&(PVOID&)real_connect, fake_connect);
        WriteMemory((uint32_t)&real_Net_NetClient_FlushUnsentTurns, Net_NetClient_FlushUnsentTurns);
        DetourAttach(&(PVOID&)real_Net_NetClient_FlushUnsentTurns, fake_Net_NetClient_FlushUnsentTurns);
        WriteMemory((uint32_t)&real_Net_NetProvider_JoinGame, Net_NetProvider_JoinGame);
        DetourAttach(&(PVOID&)real_Net_NetProvider_JoinGame, fake_Net_NetProvider_JoinGame);
    }
    else {
        // get reconnection parameter
        int argc;
        auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
        wchar_t* pid = NULL;
        wchar_t* game_type = NULL;
        wchar_t* player_name = NULL;
        for (int i = 0; i < argc - 3; i++) {
            if (wcscmp(argv[i], L"-reconnect") == 0) {
                pid = argv[i + 1];
                game_type = argv[i + 2];
                player_name = argv[i + 3];
            }
        }

        // technically we only need to check 1 of them
        if (!pid || !game_type || !player_name) {
            MessageBoxA(NULL, "invalid command line", "Error", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
            exit(1);
        }

        // convert reconnection parameter
        rc_PID = _wtoi(pid);
        rc_game_type = wcstoull(game_type, NULL, 10);
        rc_player_name = base64_decode(player_name);

        // cleanup
        LocalFree(argv);

        // open reconnection event (created by local server)
        rc_event = OpenEventA(SYNCHRONIZE, false, ("War3 RC " + std::to_string(rc_PID)).c_str());
        if (!rc_event) {
            MessageBoxA(NULL, "initialize reconnect failed", "Error", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
            exit(1);
        }

        // modify game code
        DetourAttach(&(PVOID&)real_connect, fake_connect_RC);
        WriteMemory((uint32_t)&real_Net_NetClient_FlushUnsentTurns, Net_NetClient_FlushUnsentTurns);
        DetourAttach(&(PVOID&)real_Net_NetClient_FlushUnsentTurns, fake_Net_NetClient_FlushUnsentTurns);
        WriteMemory((uint32_t)&real_CNetData_OnIdle, CNetData_OnIdle);
        DetourAttach(&(PVOID&)real_CNetData_OnIdle, fake_CNetData_OnIdle);
        WriteMemory((uint32_t)&real_CGlueMgr_SetGlueScreen, CGlueMgr_SetGlueScreen);
        DetourAttach(&(PVOID&)real_CGlueMgr_SetGlueScreen, fake_CGlueMgr_SetGlueScreen);
        switch (version) {
        case VERSION::V1_29_2_9231:
            WriteMemoryEx<uint8_t>(base + 0x1AF197, 0x90); //
            WriteMemoryEx<uint8_t>(base + 0x1AF198, 0x8B); // process up to 4000ms
            WriteMemoryEx<uint8_t>(base + 0x1AF3FC, 0xEB); // fast forward up to 200ms
            break;
        default:
            __debugbreak();
        }
    }
    DetourTransactionCommit();
}