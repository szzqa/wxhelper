#ifndef WXHELPER_CONFIG_H_
#define WXHELPER_CONFIG_H_
#include <filesystem>

namespace wxhelper {

class Config {
 public:
  Config();
  ~Config();
  void Initialize(const std::filesystem::path& directory = {});
  int GetPort() const;
  const std::filesystem::path& GetConfigPath() const { return config_path_; }
  const std::filesystem::path& GetLogPath() const { return log_path_; }

 private:
  int port_ = 19088;
  std::filesystem::path config_path_;
  std::filesystem::path log_path_;
};
}  // namespace wxhelper
#endif
