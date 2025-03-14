#include "pcap.h"
#include "loader.h"
#include "sniffer.h"
#include <iostream>
#include "reswrite.h"

std::string log_value1 = "sniffer";
std::string log_value2 = "system";

Log sni_log(std::ref(log_value1), std::ref(log_value2));

Sniffer ses;

static void handlepacket(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes)
{
    try
    {
        ses.tcp_packet_process(bytes,std::ref(ses.tcp),std::ref(ses.tcp_len),std::ref(sni_log));
        ses.udp_packet_process(bytes,std::ref(sni_log));
        sni_log.app_logger_->flush();       
    }
    catch(const std::exception& except)
    {
        std::string error(except.what());
        sni_log.system_logger_->error("Packet parser problem:" + error);
    }
}

int main() 
{ 
    int res;
    Interfaceloader test;
    std::string command = "ip route";
    test.command(std::ref(command), std::ref(sni_log));
    test.interface(std::ref(test.dev), std::ref(sni_log));
    std::string file = "/etc/sniffer/sniffer.cfg";
    sni_log.CfgReader(std::ref(file));

    if (test.pcap != NULL)
    {
        res = pcap_loop(std::ref(test.pcap), -1, handlepacket, NULL);
    } 
    else
    {
        std::cout << "Interface not found" << "\n"; 
    }
}