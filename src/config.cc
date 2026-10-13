#include "pch.h"
#include "config.h"

namespace wxhelper {
Config::Config(/* args */) {}

Config::~Config() {}

void Config::Initialize() {
  port_ = GetPrivateProfileIntW(L"config", L"Port", 19088, L"./config.ini");
}
int Config::GetPort() { return port_; }

}  // namespace wxhelper
