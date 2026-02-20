#ifndef COMMON_HPP
#define COMMON_HPP

#include <sys/socket.h>
#include "fcntl.h"
#include <unistd.h>
#include <arpa/inet.h>
#include <iostream>
#include <cmath>
#include "wait.h"
#include "semaphore.h"
#include "check.hpp"
#include "signal.h"
#include "sys/prctl.h"
#include <netinet/in.h>
#include <stdexcept>

constexpr unsigned short SERVER_PORT = 60003;

inline std::ostream &operator<<(std::ostream &s, const sockaddr_in &addr)
{
    union
    {
        in_addr_t x;
        char c[sizeof(in_addr)];
    } t{};
    t.x = addr.sin_addr.s_addr;
    return s << std::to_string(int(t.c[0]))
             << "." << std::to_string(int(t.c[1]))
             << "." << std::to_string(int(t.c[2]))
             << "." << std::to_string(int(t.c[3]))
             << ":" << std::to_string(ntohs(addr.sin_port));
}

// Convert sockaddr_in to string in format "ip:port"
std::string str_addr(const sockaddr_in &addr)
{
    char ip[INET_ADDRSTRLEN] = {0};

    if (!inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip))) {
        return "?.?.?.?:" + std::to_string(ntohs(addr.sin_port));
    }

    return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port));
}

inline int make_socket(int type)
{
    switch (type)
    {
    case SOCK_STREAM:
        return socket(AF_INET, SOCK_STREAM, 0);
    case SOCK_DGRAM:
        return socket(AF_INET, SOCK_DGRAM, 0);
    case SOCK_SEQPACKET:
        return socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP); // analogue to SOCK_SEQPACKET
    default:
        errno = EINVAL;
        return -1;
    }
}

inline sockaddr_in local_addr(unsigned short port)
{
    sockaddr_in addr{};
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    return addr;
}

inline sockaddr_in any_addr(unsigned short port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;   // 0.0.0.0

    return addr;
}


inline sockaddr_in remote_addr(const char* ip, unsigned short port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        throw std::runtime_error("Invalid IP address");
    }

    return addr;
}

enum Status
{
    None,
    Less,
    Equal,
    Large,
    Guess,
    Start,
    Number,
    SetMin,
    SetMax,
    Restart,
    InvalidStatus,
    InvalidData,
};

#pragma pack(push, 1)
struct Message
{
    int data;
    Status status;

    Message(int data = 0, Status status = None): data(data), status(status) {}

    void to_host_order()
    {
        data = ntohl(data);
        status = (Status)ntohl(status);
    }

    void to_net_order()
    {
        data = htonl(data);
        status = (Status)htonl(status);
    }
};
#pragma pack(pop)

inline std::ostream &operator<<(std::ostream &s, const Message &m)
{
    std::string status = "";
    if (m.status == None)
        status = "None";
    else if (m.status == Large)
        status = "Large";
    else if (m.status == Less)
        status = "Less";
    else if (m.status == Equal)
        status = "Equal";
    else if (m.status == Guess)
        status = "Guess";
    else if (m.status == Start)
        status = "Start";
    else if (m.status == SetMin)
        status = "SetMin";
    else if (m.status == SetMax)
        status = "SetMax";
    else if (m.status == Number)
        status = "Number";
    else if (m.status == Restart)
        status = "Restart";
    else if (m.status == InvalidStatus)
        status = "InvalidStatus";
    else if (m.status == InvalidData)
        status = "InvalidData";
    return s << "Message { x: " << m.data << ", status: " << status << " }";
}

std::string str_message(const Message &m)
{
    std::string status = "";
    if (m.status == None)
        status = "None";
    else if (m.status == Large)
        status = "Large";
    else if (m.status == Less)
        status = "Less";
    else if (m.status == Equal)
        status = "Equal";
    else if (m.status == Guess)
        status = "Guess";
    else if (m.status == Start)
        status = "Start";
    else if (m.status == SetMin)
        status = "SetMin";
    else if (m.status == SetMax)
        status = "SetMax";
    else if (m.status == Number)
        status = "Number";
    else if (m.status == Restart)
        status = "Restart";
    else if (m.status == InvalidStatus)
        status = "InvalidStatus";
    else if (m.status == InvalidData)
        status = "InvalidData";
    return "Message { x: " + std::to_string(m.data) + ", status: " + status + " }";
}

class SemGuard
{
private:
    sem_t* _sem;
public:
    SemGuard(sem_t* sem): _sem(sem)
    {
        sem_wait(_sem);
    }
    ~SemGuard()
    {
        sem_post(_sem);
    }
};

#endif // COMMON_HPP

