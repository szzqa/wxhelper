#ifndef WXHELPER_LOG_H_
#define WXHELPER_LOG_H_
#include <filesystem>
namespace wxhelper {
class Log {
 private:

 public:
  Log();
  ~Log();
  void Initialize(const std::filesystem::path& path);
};

}  // namespace wxhelper

#endif
