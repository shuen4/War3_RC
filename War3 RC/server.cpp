#include <vector>
#ifndef FD_SETSIZE
#define FD_SETSIZE 2 // only max of 2 is used
#endif
#include <winsock2.h>
#include <Windows.h>
#include <queue>
#include <list>
#include <string>
#include "memory.h"
#include "base64.h"

#define SERVER_IP_MASK 0x8000007F // 127.0.0.128
#define SERVER_IP(pid) (SERVER_IP_MASK | ((pid << 8) & 0x7FFFFF00))

#define Q_STR(s) s, sizeof(s) - 1

#define W3GS_HEADER_CONSTANT    0xF7

#define W3GS_PING_FROM_HOST		0x01
#define W3GS_SLOTINFOJOIN		0x04
#define W3GS_REJECTJOIN			0x05
#define W3GS_PLAYERINFO			0x06
#define W3GS_PLAYERLEAVE_OTHERS	0x07
#define W3GS_GAMELOADED_OTHERS	0x08
#define W3GS_SLOTINFO			0x09
#define W3GS_COUNTDOWN_START	0x0A
#define W3GS_COUNTDOWN_END		0x0B
#define W3GS_INCOMING_ACTION	0x0C
#define W3GS_CHAT_FROM_HOST		0x0F
#define W3GS_START_LAG			0x10
#define W3GS_STOP_LAG			0x11
#define W3GS_HOST_KICK_PLAYER	0x1C
#define W3GS_REQJOIN			0x1E
#define W3GS_LEAVEGAME			0x21
#define W3GS_GAMELOADED_SELF	0x23
#define W3GS_OUTGOING_ACTION	0x26
#define W3GS_OUTGOING_KEEPALIVE	0x27
#define W3GS_CHAT_TO_HOST		0x28
#define W3GS_DROPREQ			0x29
#define W3GS_SEARCHGAME			0x2F
#define W3GS_GAMEINFO			0x30
#define W3GS_CREATEGAME			0x31
#define W3GS_REFRESHGAME		0x32
#define W3GS_DECREATEGAME		0x33
#define W3GS_CHAT_OTHERS		0x34
#define W3GS_PING_FROM_OTHERS	0x35
#define W3GS_PONG_TO_OTHERS		0x36
#define W3GS_MAPCHECK			0x3D
#define W3GS_STARTDOWNLOAD		0x3F
#define W3GS_MAPSIZE			0x42
#define W3GS_MAPPART			0x43
#define W3GS_MAPPARTOK			0x44
#define W3GS_MAPPARTNOTOK		0x45
#define W3GS_PONG_TO_HOST		0x46
#define W3GS_INCOMING_ACTION2	0x48

#define GPS_HEADER_CONSTANT     0xF8

int recv(SOCKET s, uint8_t* buf, int len, int flags) {
    return recv(s, (char*)buf, len, flags);
}

int send(SOCKET s, uint8_t* buf, int len, int flags) {
    return send(s, (char*)buf, len, flags);
}

int send(SOCKET s, std::vector<uint8_t>& packet) {
    return send(s, &packet[0], packet.size(), 0);
}

void set_length(std::vector<uint8_t>& packet) {
    packet[2] = (uint8_t)(packet.size() >> 0);
    packet[3] = (uint8_t)(packet.size() >> 8);
}

std::vector<uint8_t> send_chat_to_host_buffer;
int send_w3_chat_to_host(SOCKET s, const char* str, uint8_t local_player_pid, bool include_self = false) {
    auto& packet = send_chat_to_host_buffer;
    packet.clear();
    packet.push_back(W3GS_HEADER_CONSTANT);
    packet.push_back(W3GS_CHAT_TO_HOST);
    packet.push_back(0x00);
    packet.push_back(0x00);
    
    // neither war3 nor GHost++ verify receiver ID
    // so its fine to include all ID
    uint32_t count = 0;
#define MAX_PLAYERS 12
    for (uint32_t i = 1; i <= MAX_PLAYERS; i++) {
        if (i != local_player_pid || include_self) {
            count++;
            packet.push_back(i);
        }
    }
    packet.insert(packet.end() - count, count);

    packet.push_back(local_player_pid); // from PID
    packet.push_back(0x20); // flag (in game chat message)

    packet.push_back(0x02); // Obs/Ref
    packet.push_back(0x00);
    packet.push_back(0x00);
    packet.push_back(0x00);

    packet.insert(packet.end(), str, str + strlen(str));
    packet.push_back(0x00);
    
    set_length(packet);

    return send(s, packet);
}
void init_server() {
    // initialize winsock
    WSADATA wsadata;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (ret) {
        MessageBoxA(NULL, "WSAStartup failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }
    if (LOBYTE(wsadata.wVersion) != 2 || HIBYTE(wsadata.wVersion) != 2) {
        MessageBoxA(NULL, "WSAVersion check failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    // setup local server socket
    SOCKET localhost = socket(AF_INET, SOCK_STREAM, 0);
    if (localhost == INVALID_SOCKET) {
        MessageBoxA(NULL, "create local server socket failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }
    sockaddr_in sin{};
    sin.sin_family = AF_INET;
    sin.sin_addr.S_un.S_addr = SERVER_IP(GetCurrentProcessId());
    sin.sin_port = htons(44444);
    if (bind(localhost, (sockaddr*)&sin, sizeof(sin)) == SOCKET_ERROR) {
        MessageBoxA(NULL, "local server bind failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }
    if (listen(localhost, SOMAXCONN) == SOCKET_ERROR) {
        MessageBoxA(NULL, "local server listen failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    // initialize fd_set
    fd_set fd;
    FD_ZERO(&fd);
    FD_SET(localhost, &fd);

    timeval tv = { 30, 0 };
    ret = select(0, &fd, NULL, NULL, &tv);
    if (ret == 0) {
        MessageBoxA(NULL, "waiting for client connect timeout", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }
    else if (ret == SOCKET_ERROR) {
        MessageBoxA(NULL, "waiting for client connect error", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    // accept connection
    SOCKET client = accept(localhost, NULL, NULL);
    if (client == INVALID_SOCKET) {
        MessageBoxA(NULL, "local server accept connection failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    // set tcp no delay
    int OptVal = 1;
    setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char*)&OptVal, sizeof(int));

    uint8_t buffer[sizeof(sockaddr_in) + sizeof(uint64_t)];
    if (recv(client, (char*)buffer, sizeof(buffer), MSG_WAITALL) != sizeof(buffer)) {
        MessageBoxA(NULL, "get target addr failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    uint32_t len;
    if (recv(client, (char*)&len, sizeof(len), MSG_WAITALL) != sizeof(len)) {
        MessageBoxA(NULL, "get process command line length failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    std::string commandline(len, 0);
    if (recv(client, (char*)&commandline[0], len, MSG_WAITALL) != len) {
        MessageBoxA(NULL, "get process command line failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    SOCKET server = socket(AF_INET, SOCK_STREAM, 0);
    if (server == INVALID_SOCKET) {
        MessageBoxA(NULL, "create socket failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    if (connect(server, (sockaddr*)buffer, sizeof(sockaddr_in)) == SOCKET_ERROR) {
        MessageBoxA(NULL, "connect server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
        exit(1);
    }

    // set tcp no delay
    OptVal = 1;
    setsockopt(server, IPPROTO_TCP, TCP_NODELAY, (const char*)&OptVal, sizeof(int));

    // data
    uint64_t game_type = ReadMemory<uint64_t>((uint32_t)&buffer[sizeof(sockaddr_in)]);
    std::string player_name;
    uint8_t local_player_id;
    std::queue<std::vector<uint8_t>> local_actions;
    std::vector<uint32_t> checksums;
    bool game_loaded = false;
    std::list<std::vector<uint8_t>> packet_pre_load;
    std::list<std::vector<uint8_t>> packet_post_load;
    bool notice_on_server_disconnect = false;
    bool commandline_inited = false;

    // buffer
    uint8_t client_buffer[0xFFFF];
    uint32_t client_buffer_pos = 0;
    uint8_t server_buffer[0xFFFF];
    uint32_t server_buffer_pos = 0;

    // main loop
    while (true) {
        // re-init fd (select will alter them)
        FD_ZERO(&fd);
        FD_SET(client, &fd);
        FD_SET(server, &fd);

        if (select(0, &fd, NULL, NULL, NULL) == SOCKET_ERROR) {
            MessageBoxA(NULL, "waiting for new data failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
            exit(1);
        }
        if (FD_ISSET(client, &fd)) {
            // perform receive on client socket
            int len = recv(client, &client_buffer[client_buffer_pos], sizeof(client_buffer) - client_buffer_pos, 0);
            // if an error occur
            if (len <= 0) {
                // close client socket
                closesocket(client);

                // we shall not try to reconnect if:
                // - game not started
                // - there is no checksum stored
                if (!game_loaded || checksums.size() == 0)
                    exit(0);

                // tell everyone game disconnected
                if (send_w3_chat_to_host(server, "Game disconnected (maybe crashed).", local_player_id) == SOCKET_ERROR) {
                    MessageBoxA(NULL, "send chat to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }

                // ask the user to try reconnect or not
                if (MessageBoxA(NULL, "Game disconnected.\nDo you want to try reconnect ?", "Local server", MB_YESNO | MB_ICONQUESTION | MB_DEFBUTTON1 | MB_SETFOREGROUND) == IDNO) {
                    // tell everyone we not going to reconnect
                    // socket error are not checked because we are going to close it anyways
                    send_w3_chat_to_host(server, "User decided to not reconnect.", local_player_id);

                    // followed by leaving the game (W3GS_LEAVEGAME)
                    // we dont last 1 byte here because NULL terminator appended at end of string
                    static_assert(sizeof("\xF7\x21\x08\x00\x07\x00\x00") == 8); // just in case compiler decided to not insert NULL
                    send(server, "\xF7\x21\x08\x00\x07\x00\x00", 8, 0);
                    
                    // if we can shut down socket gracefully
                    if (shutdown(server, SD_SEND) != SOCKET_ERROR) {
                        if (WSAEVENT shutdown_event = WSACreateEvent()) {
                            if (WSAEventSelect(server, shutdown_event, FD_CLOSE) != SOCKET_ERROR) {
                                if (WSAWaitForMultipleEvents(1, &shutdown_event, TRUE, INFINITE, FALSE) == WSA_WAIT_EVENT_0) {
                                    closesocket(server);
                                    exit(0);
                                }
                            }
                        }
                    }

                    // else block thread for 5 seconds and force exit
                    Sleep(5000);
                    closesocket(server);
                    exit(0);
                }

                if (send_w3_chat_to_host(server, "User is reconnecting", local_player_id) == SOCKET_ERROR) {
                    MessageBoxA(NULL, "send chat to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }

                // create event for signal reconnect completed
                HANDLE rc_event = CreateEventA(NULL, true, false, ("War3 RC " + std::to_string(GetCurrentProcessId())).c_str());
                if (!rc_event) {
                    MessageBoxA(NULL, "initialize reconnect failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }

                // restart war3
                STARTUPINFOA si{};
                si.cb = sizeof(si);
                PROCESS_INFORMATION pi{};

                if (!commandline_inited) {
                    commandline_inited = true;
                    commandline += ' ';
                    commandline += "-reconnect"; // tell game we are performing reconnection and parameter are stored afterward
                    commandline += ' ';
                    commandline += std::to_string(GetCurrentProcessId()); // local server PID (to reconnect server)
                    commandline += ' ';
                    commandline += std::to_string(game_type); // map speed, visiblity, observer, etc (these are required to not cause desync)
                    commandline += ' ';
                    commandline += base64_encode(player_name); // and player name too (base64 encode to avoid UTF-8 char and space)
                }
                if (!CreateProcessA(NULL, (char*)commandline.c_str(), NULL, NULL, FALSE, HIGH_PRIORITY_CLASS, NULL, NULL, &si, &pi)) {
                    MessageBoxA(NULL, "restart game failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }

                // discard client buffer
                client_buffer_pos = 0;

                fd_set fd1;
                FD_ZERO(&fd1);
                FD_SET(localhost, &fd1);

                timeval tv = { 60, 0 };
                ret = select(0, &fd1, NULL, NULL, &tv);
                if (ret == 0) {
                    TerminateProcess(pi.hProcess, 1);
                    MessageBoxA(NULL, "waiting for client reconnect timeout", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }
                else if (ret == SOCKET_ERROR) {
                    TerminateProcess(pi.hProcess, 1);
                    MessageBoxA(NULL, "waiting for client reconnect error", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }
                if (send_w3_chat_to_host(server, "Reconnecting", local_player_id) == SOCKET_ERROR) {
                    TerminateProcess(pi.hProcess, 1);
                    MessageBoxA(NULL, "send chat to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }

                // accept reconnection
                // we dont update fd_set fd since it will re-init before performing select
                client = accept(localhost, NULL, NULL);
                if (client == INVALID_SOCKET) {
                    TerminateProcess(pi.hProcess, 1);
                    MessageBoxA(NULL, "accept reconnection failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }

                int OptVal = 1;
                setsockopt(client, IPPROTO_TCP, TCP_NODELAY, (const char*)&OptVal, sizeof(int));

                // allocate buffer on heap (not stack because this function already take too much stack size)
                uint8_t* buffer = new uint8_t[65535];

                // resend packet
                for (auto i = packet_pre_load.begin()++; i != packet_pre_load.end(); i++) {
                    // if current packet is start game
                    if (i->operator[](1) == W3GS_COUNTDOWN_END) {
                        // wait until we receive map verify response from game
                        // because before verify done and game start sent, war3 will automatic left the game
                        while (true) {
                            ret = recv(client, buffer, 4, MSG_WAITALL);
                            if (ret != 4) {
                                TerminateProcess(pi.hProcess, 1);
                                MessageBoxA(NULL, "wait for client join failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                                exit(1);
                            }
                            if (buffer[0] != W3GS_HEADER_CONSTANT) {
                                TerminateProcess(pi.hProcess, 1);
                                MessageBoxA(NULL, "wait for client join failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                                exit(1);
                            }
                            uint16_t packet_size = ReadMemory<uint16_t>((uint32_t)&buffer[2]);
                            if (packet_size != 4) {
                                packet_size -= 4;
                                ret = recv(client, buffer + 4, packet_size, MSG_WAITALL);
                                if (ret != packet_size) {
                                    TerminateProcess(pi.hProcess, 1);
                                    MessageBoxA(NULL, "wait for client join failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                                    exit(1);
                                }
                            }

                            if (buffer[1] == W3GS_MAPSIZE)
                                break;
                        }
                    }
                    if (send(client, *i) == SOCKET_ERROR) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "resend lobby packet failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                }

                // wait until game loaded
                while (true) {
                    ret = recv(client, buffer, 4, MSG_WAITALL);
                    if (ret != 4) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "wait for client load failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    if (buffer[0] != W3GS_HEADER_CONSTANT) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "wait for client load failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    uint16_t packet_size = ReadMemory<uint16_t>((uint32_t)&buffer[2]);
                    if (packet_size != 4) {
                        packet_size -= 4;
                        ret = recv(client, buffer + 4, packet_size, MSG_WAITALL);
                        if (ret != packet_size) {
                            TerminateProcess(pi.hProcess, 1);
                            MessageBoxA(NULL, "wait for client load failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                            exit(1);
                        }
                    }

                    if (buffer[1] == W3GS_GAMELOADED_SELF)
                        break;
                }

                // send a message to all player that said
                // we had started to fast forward the game
                if (send_w3_chat_to_host(server, ("Reconnecting 0% (0 / " + std::to_string(checksums.size()) + ")").c_str(), local_player_id) == SOCKET_ERROR) {
                    MessageBoxA(NULL, "send chat to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }

                for (auto i = packet_post_load.begin(); i != packet_post_load.end(); i++) {
                    if (send(client, *i) == SOCKET_ERROR) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "resend game packet failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                }

                #pragma warning(push)
                // GetTickCount
                // we are just using it for subtraction to get time passed
                // game should never take more than 49 days to reconnect at all
                #pragma warning(disable: 28159)
                uint32_t start = GetTickCount();
                uint32_t checksum_count = 0;
                uint32_t last_update = GetTickCount();
                while (checksum_count < checksums.size()) {
                    // update the message every 5 seconds
                    if (GetTickCount() - last_update >= 5000) {
                        last_update = GetTickCount();
                        if (send_w3_chat_to_host(server, ("Reconnecting " + std::to_string((float)checksum_count / (float)checksums.size() * 100.f) + "% (" + std::to_string(checksum_count) + " / " + std::to_string(checksums.size()) + ")").c_str(), local_player_id) == SOCKET_ERROR) {
                            MessageBoxA(NULL, "send chat to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                            exit(1);
                        }
                    }
                    ret = recv(client, buffer, 4, MSG_WAITALL);
                    if (ret != 4) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "wait for client fast forward failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    if (buffer[0] != W3GS_HEADER_CONSTANT) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "wait for client fast forward failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    uint16_t packet_size = ReadMemory<uint16_t>((uint32_t)&buffer[2]);
                    if (packet_size != 4) {
                        packet_size -= 4;
                        ret = recv(client, buffer + 4, packet_size, MSG_WAITALL);
                        if (ret != packet_size) {
                            TerminateProcess(pi.hProcess, 1);
                            MessageBoxA(NULL, "wait for client fast forward failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                            exit(1);
                        }
                    }

                    switch(buffer[1]){
                    case W3GS_OUTGOING_KEEPALIVE:
                        // verify checksum 
                        if (ReadMemory<uint32_t>((uint32_t)&buffer[5]) != checksums[checksum_count]) {
                            // if it does not match
                            // then game is out of sync(for w/e reason) 
                            // even we reconnected, we will get kicked/dropped by server
                            // so reconnecting is not possible at all
                            if (send_w3_chat_to_host(server, "Game desynced, reconnect is halted", local_player_id) == SOCKET_ERROR) {
                                MessageBoxA(NULL, "send chat to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                                exit(1);
                            }
                            TerminateProcess(pi.hProcess, 1);
                            MessageBoxA(NULL, "Game desynced, reconnect is halted", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                            exit(1);
                        }
                        checksum_count++;
                        break;
                    case W3GS_CHAT_TO_HOST:
                        // allow chat to send to server while reconnecting
                        // although receiving chat is not implemented yet
                        if (send(server, buffer, packet_size, 0) == SOCKET_ERROR) {
                            TerminateProcess(pi.hProcess, 1);
                            MessageBoxA(NULL, "send chat to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                            exit(1);
                        }
                        break;
                    }
                }

                // drop all packet from client util there no packet left
                // or a checksum received
                do {
                    FD_ZERO(&fd1);
                    FD_SET(client, &fd1);

                    // do a 0s select to check if there is any packet queued
                    tv.tv_sec = 0;
                    ret = select(0, &fd1, NULL, NULL, &tv);
                    if (ret == 0)
                        break;
                    else if (ret == SOCKET_ERROR) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "droping client packet failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    ret = recv(client, buffer, 4, MSG_PEEK);
                    if (ret != 4) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "drop packet failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    if (buffer[0] != W3GS_HEADER_CONSTANT) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "drop packet failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    // if we got checksum then its probably game fast forwarded after the time when it crashed
                    // break out the loop and continue as usual
                    if (buffer[1] == W3GS_OUTGOING_KEEPALIVE) {
                        break;
                    }
                    uint16_t packet_size = ReadMemory<uint16_t>((uint32_t)&buffer[2]);
                    ret = recv(client, buffer, packet_size, MSG_WAITALL);
                    if (ret != packet_size) {
                        TerminateProcess(pi.hProcess, 1);
                        MessageBoxA(NULL, "drop packet failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                } while (true);

                // tell everyone(include ourself) we are reconnected
                // and time taken for this operation
                uint32_t end = GetTickCount() - start;
                if (send_w3_chat_to_host(server, (std::string("Reconnected (") + std::to_string(end) + "ms)").c_str(), local_player_id, true) == SOCKET_ERROR) {
                    MessageBoxA(NULL, "send chat to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }
                delete[] buffer;
                #pragma warning(pop)

                // notify war3 we had done the reconnection
                SetEvent(rc_event);
                CloseHandle(rc_event);

                // cleanup
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                continue;
            }
            // adjust buffer pos
            client_buffer_pos += len;
            // packet is always at least 4 bytes
            while (client_buffer_pos > 3) {
                uint16_t packet_size = ReadMemory<uint16_t>((uint32_t)&client_buffer[2]);
                // if received full packet then process it
                if (packet_size <= client_buffer_pos) {
                    if (client_buffer[0] != W3GS_HEADER_CONSTANT) {
                        MessageBoxA(NULL, "receive invalid packet from client", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    switch (client_buffer[1]) {
                    case W3GS_OUTGOING_ACTION:
                        // save action we sent for verify later
                        local_actions.push(std::vector<uint8_t>(&client_buffer[8], &client_buffer[8] + packet_size - 8));
                        break;
                    case W3GS_GAMELOADED_SELF:
                        // mark game loaded and save packet afterward to another variable
                        game_loaded = true;
                        break;
                    case W3GS_OUTGOING_KEEPALIVE:
                        // record checksum
                        checksums.push_back(ReadMemory<uint32_t>((uint32_t)&client_buffer[5]));
                        break;
                    case W3GS_REQJOIN:
                        // record player name for reconnection
                        player_name = (char*)&client_buffer[19];
                        break;
                    case W3GS_LEAVEGAME:
                        // server are expected to close connection afterward
                        notice_on_server_disconnect = false;
                        break;
                    default:
                        break;
                    }
                    if (send(server, client_buffer, packet_size, 0) == SOCKET_ERROR) {
                        MessageBoxA(NULL, "send data to server failed", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    // adjust buffer
                    client_buffer_pos -= packet_size;
                    memmove(client_buffer, &client_buffer[packet_size], client_buffer_pos);
                }
                else
                    // packet is incomplete
                    break;
            }
        }
        if (FD_ISSET(server, &fd)) {
            // perform receive on server socket
            int len = recv(server, &server_buffer[server_buffer_pos], sizeof(server_buffer) - server_buffer_pos, 0);
            // if an error occur
            if (len <= 0) {
                if (notice_on_server_disconnect) {
                    MessageBoxA(NULL, "server disconnected", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                    exit(1);
                }
                exit(0);
            }
            // adjust buffer pos
            server_buffer_pos += len;
            // packet is always at least 4 bytes
            while (server_buffer_pos > 3) {
                uint16_t packet_size = ReadMemory<uint16_t>((uint32_t)&server_buffer[2]);
                // if received full packet then process it
                if (packet_size <= server_buffer_pos) {
                    if (server_buffer[0] != W3GS_HEADER_CONSTANT) {
                        MessageBoxA(NULL, "receive invalid packet from server", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                        exit(1);
                    }
                    switch (server_buffer[1]) {
                    case W3GS_SLOTINFOJOIN:
                        // get our player id
                        local_player_id = server_buffer[packet_size - 17];
                        // server disconnect should notice user
                        notice_on_server_disconnect = true;
                        goto record_packet;
                    case W3GS_INCOMING_ACTION:
                    case W3GS_INCOMING_ACTION2:
                        // verify actions are from ourself and not modified by server
                        // war3 has verify but we killed it and done it on local server side
                        for (uint32_t i = 8; i < packet_size;) {
                            if (server_buffer[i] == local_player_id) {
                                i++;
                                if (
                                    !local_actions.size() ||
                                    ReadMemory<uint16_t>((uint32_t)&server_buffer[i]) != local_actions.front().size() ||
                                    memcmp(&server_buffer[i+2], &local_actions.front()[0], local_actions.front().size())
                                ) {
                                    // send a message and disconnect from server
                                    send_w3_chat_to_host(client, "server sent packet that marked from us, but we didnt do it!", local_player_id);
                                    MessageBoxA(NULL, "received unpected packet", "Local server", MB_OK | MB_ICONERROR | MB_SETFOREGROUND);
                                    exit(1);
                                }
                                local_actions.pop();
                            }
                            else
                                i++;
                            i += ReadMemory<uint16_t>((uint32_t)&server_buffer[i]);
                            i += 2;
                        }
                        goto record_packet;
                    case W3GS_COUNTDOWN_END:
                    case W3GS_PLAYERINFO:
                    case W3GS_PLAYERLEAVE_OTHERS:
                    case W3GS_GAMELOADED_OTHERS:
                    case W3GS_SLOTINFO:
                    case W3GS_MAPCHECK:
                    case W3GS_START_LAG:
                    case W3GS_STOP_LAG:
                        // useless packet that are not important for reconnection are not saved
                        record_packet:
                        if (game_loaded)
                            packet_post_load.push_back(std::vector<uint8_t>(&server_buffer[0], &server_buffer[packet_size]));
                        else
                            packet_pre_load.push_back(std::vector<uint8_t>(&server_buffer[0], &server_buffer[packet_size]));
                        break;
                    default:
                        break;
                    }
                    if (send(client, server_buffer, packet_size, 0) == SOCKET_ERROR) {
                        // break out the server loop and see if we need to do client reconnection
                        break;
                    }
                    // adjust buffer
                    server_buffer_pos -= packet_size;
                    memmove(server_buffer, &server_buffer[packet_size], server_buffer_pos);
                }
                else
                    // packet is incomplete
                    break;
            }
        }
    }
    exit(0);
}