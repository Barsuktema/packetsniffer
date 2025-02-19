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
    
    void command(std::string cmd, class Log check);
    void interface(std::string interface, class Log check);

    ~Interfaceloader() {
        if (pcap != NULL)
        {
            pcap_close(pcap);
        }
    };
};



