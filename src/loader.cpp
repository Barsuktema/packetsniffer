#include "loader.h"
#include <iostream>
#include <stdexcept>
#include "reswrite.h"
#include "spdlog/spdlog.h"

void Interfaceloader::command(std::string cmd, class Log check)
{
    try
    {
        std::string data;
        FILE * stream;
        const int max_buffer = 256;
        char buffer[max_buffer];
        cmd.append(" 2>&1");
        stream = popen(cmd.c_str(), "r");
        if (stream)
        {
            while (!feof(stream))
            {
                if (fgets(buffer, max_buffer, stream) != NULL)
                {
                    if (static_cast<std::string>(buffer).find("default"))
                    {
                        data = buffer;
                        int loc = data.find("dev");
                        data = data.substr(loc+4,sizeof(buffer));
                        loc = data.find(" ");
                        data = data.substr(0,loc);
                        std::cout << "Found internet interface: " + data << "\n";
                        dev = data;
                    };
                };
            } 
            pclose(stream);
        }
    }
    catch(const std::string message)
    {
        check.system_logger_->error("Can`t finde default route. Please check internet:" + message);

    }


};

void Interfaceloader::interface(std::string interface, class Log check)
{
    const char * inter = interface.c_str();
    pcap = pcap_open_live(inter, 262144, 1, 100, errbuf);
    std::cout << "Started packet capture: " + interface << "\n";    
    if (pcap == NULL)
    {
        check.system_logger_->error("Interface can`t load:" + (std::string)errbuf);
    }
}