#include "sniffer.h"
#include <iostream>
#include<linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>
#include <arpa/inet.h>

constexpr int dns_port = 53;

std::string return_ip(uint32_t ip)
{
    struct sockaddr_in sa;
    char str[INET_ADDRSTRLEN];
    ip = htonl(ip);
    inet_ntop(AF_INET, &(ip), str, INET_ADDRSTRLEN);
    return str;
}

template <typename T>
T calc_data(const uint8_t* ptr) 
{
    T value;
    memcpy(&value, ptr, sizeof(T));
    return value;
}

struct ret dns_parse(const uint8_t* buffer, const uint8_t* dns_ptr, size_t data_size)
{
    struct ret dom;
    dom.len = 0;

        while (dns_ptr < buffer + data_size && *dns_ptr != 0)
        {
            size_t label_len = *dns_ptr;
            dom.len += label_len + 1;
            if (!dom.domain.empty())
            {
                dom.domain += ".";
            }
            dom.domain += std::string((char*)dns_ptr + 1, label_len);
            dns_ptr += label_len + 1;
        }

    return dom;
}

static bool check_deny_domain(std::vector<std::string>& list, std::string value)
{
    bool ind = false;
    for (auto element : list)
    {

        if (value.find(element) != std::string::npos)
        {
            ind = true;
        };
    };

    return ind;
}

static void process_dns_packet(const uint8_t* payload, size_t _data_size, class Log& check, uint32_t user_ip)
{
    const struct dns_header* dns_hdr = reinterpret_cast<const struct dns_header *>(payload);

    struct ret name;

    if (ntohs(dns_hdr->flags) == 0x8180)
    {
        size_t offset = 0;
        size_t data_size =  _data_size - sizeof(dns_hdr);

        const uint8_t * ptr = payload + sizeof(dns_hdr) + 4;

        for (uint16_t queries_cnt = 0; queries_cnt < ntohs(dns_hdr->q_count); queries_cnt++)
        {
            name = dns_parse(payload, ptr + offset, data_size);
            offset += name.len + 5;
        }

        for (uint16_t answers_cnt = 0; answers_cnt < ntohs(dns_hdr->a_count); answers_cnt++)
        {
            size_t type = htons(calc_data<size_t>(ptr + offset + 2));

            switch (type)
            {
                case 1:
                {
                    if (htons(calc_data<size_t>(ptr + offset + 10)) == 4) 
                    {
                        uint32_t ipaddr = calc_data<uint32_t>(ptr + offset + 12);
                        offset += 16;
                        std::string tmp = "DNS: user ip-" + return_ip(user_ip)+ " ,server ip-" + return_ip(htonl(ipaddr)) +", domain name-" + name.domain+ ";";
                        if (check_deny_domain(check.deny_domain, name.domain))
                        {
                            check.app_logger_->error(tmp);
                        }
                        else
                        {
                            check.app_logger_->info(tmp);
                        }
                    }
                    break;
                }
                case 5:
                {
                    size_t answer_len = htons(calc_data<size_t>(ptr + offset + 10));
                    offset += answer_len + 12;
                    break;
                }
                default:
                    break;
            }
        }
    } else 
    {
        return;
    }
}

void Sniffer::udp_packet_process(const uint8_t* bytes, class Log& check)
{

    struct iphdr* ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));

    uint32_t abonent_ip = htonl(ip_header->saddr);
    uint32_t server_ip = htonl(ip_header->daddr);

    if (ip_header->protocol == IPPROTO_UDP)
    {

        const struct udphdr* udp_header = reinterpret_cast<const struct udphdr*>(bytes + sizeof(ethhdr) + ip_header->ihl * 4);

        uint16_t abonent_port = htons(udp_header->source);
        uint16_t server_port = htons(udp_header->dest);
        size_t data_size = htons(udp_header->uh_ulen) - sizeof(udp_header);
        const uint8_t* payload = bytes + sizeof(ethhdr) + ip_header->ihl * 4 + sizeof(udphdr);

        if (server_port == dns_port || abonent_port == dns_port)
        {
            process_dns_packet(payload, data_size, check, server_ip);
        }
    }
}


std::string tls_read_sni(const uint8_t* payload, std::unordered_map<uint32_t, std::array<uint8_t, 3000>>& ses, uint32_t key, std::unordered_map<uint32_t, size_t>& ses_tcp)
{
    const uint16_t payload_length = ntohs(*reinterpret_cast<const uint16_t*>(payload + 3)) + 3;

    size_t offset = 43; 
    bool search_ind = false;
    uint16_t ext_type;
    size_t ext_len;

    offset += *(payload + offset) + 1;
    offset += ntohs(calc_data<size_t>(payload + offset)) + 3;
    offset += *(payload + offset) + 1;

    const size_t ext_total_len = ntohs(calc_data<size_t>(payload + offset)); 

    offset += 2;
  
    while (offset + 4 <= payload_length)
    {
        const uint16_t cur_extension_type =
            ntohs(*reinterpret_cast<const uint16_t*>(&payload[offset]));
        const uint16_t cur_extension_length =
            ntohs(*reinterpret_cast<const uint16_t*>(&payload[offset + 2]));
        offset += 4;
    

        if (cur_extension_type == 0x0000)
        {
            return std::string{
            reinterpret_cast<const char*>(&payload[offset + 5]),
            ntohs(*reinterpret_cast<const uint16_t*>(&payload[offset + 3]))};
            ses.erase(key);
            ses_tcp.erase(key);
        }
        else
        {
            offset += cur_extension_length;
        } 

    }

    return "";
}

void Sniffer::tcp_packet_process(const uint8_t* bytes, std::unordered_map<uint32_t, std::array<uint8_t, 3000>>& ses, std::unordered_map<uint32_t, size_t>& ses_tcp_len,class Log& check)
{
    struct iphdr* ip_header = (struct iphdr*)(bytes + sizeof(struct ethhdr));

    uint32_t abonent_ip = htonl(ip_header->saddr);
    uint32_t server_ip = htonl(ip_header->daddr);

    if (ip_header->protocol == IPPROTO_TCP)
    {
        const struct tcphdr* tcp_head = reinterpret_cast<const struct tcphdr*>(bytes + sizeof(ethhdr) + (ip_header->ihl * 4));

        uint16_t abonent_port = htons(tcp_head->source);
        uint16_t server_port = htons(tcp_head->dest);

        const uint8_t* payload = bytes + sizeof(ethhdr) + (ip_header->ihl * 4) + (tcp_head->doff * 4);
        const uint16_t tcp_len = htons(ip_header->tot_len) - (ip_header->ihl * 4) - (tcp_head->doff * 4);
        uint32_t tcp_seq = ntohl(tcp_head->seq);
        if (*payload == 0x16 &&*(payload + 5) == 0x01) 
        {
            memcpy(&ses[tcp_seq + tcp_len][0], payload, tcp_len);
            ses_tcp_len[tcp_seq + tcp_len] = tcp_len;
        };

        if (auto search = ses.find(tcp_seq) ; search != ses.end())
        {
            memcpy(&ses[tcp_seq][0] + ses_tcp_len[tcp_seq], payload, tcp_len);
            if (tcp_len > 100) // Retransmission avoid
            {
                auto name = tls_read_sni(&ses[tcp_seq][0], ses, tcp_head->seq, ses_tcp_len);

                std::string tmp = "TLS: user_ip-" + return_ip(abonent_ip) + " ,server_ip-" + return_ip(server_ip) + ", domain_name-" + name + ";";

                if (check_deny_domain(check.deny_domain, name))
                {
                    check.app_logger_->error(tmp);
                }
                else
                {
                    check.app_logger_->info(tmp);
                }
                
            }
        }
    }
}

