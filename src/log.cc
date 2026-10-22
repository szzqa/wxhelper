#include "pch.h"
#include "log.h"


#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_INFO
namespace wxhelper {
Log::Log() {}

Log::~Log() {}

void Log::Initialize(const std::filesystem::path& path) {
  auto logger =
      spdlog::rotating_logger_mt("wxhelper_logger", path.native(), 5 * 1024 * 1024, 3);
  // Use synchronous flushing; no periodic worker may join under loader lock
  // during CRT teardown of this process-lifetime DLL.
  logger->flush_on(spdlog::level::info);
  spdlog::set_default_logger(logger);
  spdlog::set_level(spdlog::level::debug);
  spdlog::set_pattern("%Y-%m-%d %H:%M:%S [%l] [%t] - <%s>|<%#>|<%!>,%v");
}

}  // namespace wxhelper
