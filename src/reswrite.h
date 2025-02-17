#pragma once

#include "spdlog/spdlog.h"

#include <iostream>
#include <vector>
#include "reswrite.h"


class Log
{
  public:
    std::shared_ptr<spdlog::logger> system_logger_;
    std::shared_ptr<spdlog::logger> app_logger_;
    std::vector<std::string> deny_domain;

    Log() = default;

    Log(std::string name_app, std::string name_sys);
    void CfgReader(std::string &filepath);

    ~Log() = default;

};
