#include "pch.h"
#include "log.h"


#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO
namespace wxhelper {
Log::Log() {}

Log::~Log() {}

void Log::Initialize() {
  auto logger =
      spdlog::daily_logger_mt("daily_logger", "logs/daily.txt", 23, 59);
  // Use synchronous flushing; no periodic worker may join under loader lock
  // during CRT teardown of this process-lifetime DLL.
  logger->flush_on(spdlog::level::info);
  spdlog::set_default_logger(logger);
  spdlog::set_level(spdlog::level::debug);
  spdlog::set_pattern("%Y-%m-%d %H:%M:%S [%l] [%t] - <%s>|<%#>|<%!>,%v");
}

}  // namespace wxhelper
