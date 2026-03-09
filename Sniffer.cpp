// Usage:
//
// NOTE: Run as Administrator.

#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <conio.h>
#include <stdio.h>
#include <string>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")

#include "windivert.h"

// ======= HARD-CODE HERE =======
static const int HOST_PORT = 8888;
static const char* HOST_LAN_IP = "10.122.255.76";      // IP Windows LAN/Wi-Fi
static const char* VM_IP = "192.168.23.194";   // IP Ubuntu VM (NAT/VMnet8)// port
// ==============================

static std::string ipToStr(UINT32 ip_net_order) {
    in_addr a{};
    a.S_un.S_addr = ip_net_order;
    char buf[64]{};
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

int main(int argc, char** argv) {


    int mode = 2; // default 1: allow, if 2:block
    bool block = (mode == 2);

    if (mode != 1 && mode != 2) {
        std::cerr << "Invalid mode. Use 1 (allow) or 2 (block).\n";
        return 1;
    }

    WSADATA wsadata{};
    int wsa_rc = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (wsa_rc != 0) {
        std::cerr << "WSAStartup failed: " << wsa_rc << "\n";
        return 1;
    }

    char filter[512];
    snprintf(filter, sizeof(filter),
        "("
        "  (inbound  and ip and tcp and ip.DstAddr == %s and tcp.DstPort == %d)"  // client -> host:8888
        "  or "
        "  (outbound and ip and tcp and ip.DstAddr == %s and tcp.DstPort == %d)"  // host -> vm:8888 (forward)
        "  or "
        "  (inbound  and ip and tcp and ip.SrcAddr == %s and tcp.SrcPort == %d)"  // vm -> host (reply from 8888)
        "  or "
        "  (outbound and ip and tcp and ip.SrcAddr == %s and tcp.SrcPort == %d)"  // host -> client (reply from 8888)
        ")",
        HOST_LAN_IP, HOST_PORT,
        VM_IP, HOST_PORT,
        VM_IP, HOST_PORT,
        HOST_LAN_IP, HOST_PORT
    );

    HANDLE handle = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cerr << "WinDivertOpen failed.\n"
            << "Check: Run as Administrator + WinDivert driver installed.\n";
        WSACleanup();
        return 2;
    }

    std::cout << "Sniffer started.\n";
    std::cout << "Local IP: " << HOST_LAN_IP << "\n";
    std::cout << "Port    : " << HOST_PORT << "\n";
    std::cout << "Filter  : " << filter << "\n";
    std::cout << (block ? "Mode: BLOCK (drop)\n" : "Mode: ALLOW (pass)\n");
    std::cout << "Press any key to stop...\n\n";

    UINT8 packet[0xFFFF];
    UINT packetLen = 0;
    WINDIVERT_ADDRESS addr{};

    while (!_kbhit()) {
        if (!WinDivertRecv(handle, packet, sizeof(packet), &packetLen, &addr)) {
            continue;
        }

        PWINDIVERT_IPHDR ip = nullptr;
        PWINDIVERT_IPV6HDR ipv6 = nullptr;
        UINT8 protocol = 0;
        PWINDIVERT_ICMPHDR icmp = nullptr;
        PWINDIVERT_ICMPV6HDR icmpv6 = nullptr;
        PWINDIVERT_TCPHDR tcp = nullptr;
        PWINDIVERT_UDPHDR udp = nullptr;
        PVOID payload = nullptr;
        UINT payloadLen = 0;
        PVOID next = nullptr;
        UINT nextLen = 0;

        WinDivertHelperParsePacket(
            packet, packetLen,
            &ip, &ipv6, &protocol,
            &icmp, &icmpv6,
            &tcp, &udp,
            &payload, &payloadLen,
            &next, &nextLen
        );

        if (ip && tcp) {
            auto src = ipToStr(ip->SrcAddr);
            auto dst = ipToStr(ip->DstAddr);
            UINT16 sport = ntohs(tcp->SrcPort);
            UINT16 dport = ntohs(tcp->DstPort);

            std::cout << "[TCP] " << src << ":" << sport
                << " -> " << dst << ":" << dport
                << " size=" << packetLen
                << " ttl=" << (int)ip->TTL
                << " payload=" << payloadLen
                << (block ? "  [DROPPED]" : "  [PASSED]")
                << "\n";
        }

        if (!block) {
            WinDivertSend(handle, packet, packetLen, nullptr, &addr);
        }
        // else: drop
    }

    WinDivertClose(handle);
    WSACleanup();
    return 0;
}