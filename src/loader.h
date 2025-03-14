#pragma once
#include <string>
#include <pcap/pcap.h>
#include "spdlog/spdlog.h"
#include "reswrite.h"

class Interfaceloader {
    public:
        std::string dev;
        pcap_t * pcap;
        char errbuf[PCAP_ERRBUF_SIZE];

    Interfaceloader() =default;
    
    void command(std::string& cmd, Log check);
    void interface(std::string& interface, Log& check);

    ~Interfaceloader() {
        if (pcap != nullptr)
        {
            pcap_close(pcap);
        }
    };
};



