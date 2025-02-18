#include "spdlog/sinks/daily_file_sink.h"
#include "spdlog/sinks/rotating_file_sink.h"
#include "reswrite.h"
#include <fstream>


static const int file_size= 1024*1024*10;
static const int file_count= 10;

Log::Log(std::string name_app, std::string name_sys)
{
    system_logger_ = spdlog::rotating_logger_mt(name_sys, "/var/log/sniffer/system.log", file_size, file_count);
    app_logger_ = spdlog::daily_logger_mt(name_app, "/var/log/sniffer/app.log", 0, 00);
    system_logger_->set_level(spdlog::level::err);
    app_logger_->set_level(spdlog::level::info);
};

void Log::CfgReader(std::string& filepath)
{
    try
    {
        std::ifstream file(filepath);
        std::string line;
        while (std::getline(file, line))
        {

            if (line[0] != *"#" && line[0] != *" ")
            {
                deny_domain.push_back(line); 
            }
        }        
    }
    catch(const std::string message)
    {
        system_logger_->error("Can`t load sniffer configuration file" + message);
    }
    

};