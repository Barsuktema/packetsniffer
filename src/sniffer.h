#pragma once
#include <string>
#include <pcap/pcap.h>
#include <vector>
#include "reswrite.h"
#include <queue>

static const size_t dns_payload_len = 512;

struct dns_header
{
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t a_count;
    uint16_t auth_count;
    uint16_t add_count;
};

struct ret
{
    std::string domain;
    size_t len;
};

struct session
{
    uint32_t user_ip;
    bool ind = false;
    std::vector<uint32_t> server_ip;
    static std::string domain_name;
    uint32_t seq;
    uint16_t tcp_len;
    std::array<uint8_t, 3000> tmp_buf;
};

class Sniffer
{
    public:
        std::unordered_map<uint32_t, std::array<uint8_t, 3000>> tcp;
        std::unordered_map<uint32_t, size_t> tcp_len;

    Sniffer() = default;

    static void udp_packet_process(const uint8_t* bytes, class Log& check);
    static void tcp_packet_process(const uint8_t* bytes, std::unordered_map<uint32_t, std::array<uint8_t, 3000>>& tcp,std::unordered_map<uint32_t, size_t>& tcp_len, class Log& check);

    ~Sniffer() = default;
};