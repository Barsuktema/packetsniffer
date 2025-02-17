#include "pcap.h"
#include "loader.h"
#include "sniffer.h"
#include <iostream>
#include "reswrite.h"

Log sni_log("sniffer", "system");
Sniffer ses;


static void handlepacket(uint8_t* user, const struct pcap_pkthdr *hdr, const uint8_t* bytes)
{
    try
    {
        ses.tcp_packet_process(bytes,ses.tcp,ses.tcp_len,sni_log);
        ses.udp_packet_process(bytes,sni_log);
        sni_log.app_logger_->flush();       
    }
    catch(std::string message)
    {
        sni_log.system_logger_->error("Packet parser problem:" + message);
    }
}

int main() 
{ 

    int res;
    Interfaceloader test;

    test.command("ip route", sni_log);
    test.interface(test.dev, sni_log);
    std::string file = "/etc/sniffer/sniffer.cfg";
    sni_log.CfgReader(file);
    if (test.pcap != NULL)
    {
        res = pcap_loop(test.pcap, -1, handlepacket, NULL);
    } 
    else
    {
        std::cout << "Interface not found" << "\n"; 
    }
}