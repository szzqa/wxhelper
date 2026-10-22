#ifndef WXHELPER_THREAD_POOL_H_
#define WXHELPER_THREAD_POOL_H_
#include "Windows.h"
#include "singleton.h"
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
namespace wxhelper {

class ThreadPool :public Singleton<ThreadPool>{
 public:
  static ThreadPool& GetInstance();
  ~ThreadPool();

  bool Create(unsigned long min = 1, unsigned long max = 4);

  bool AddWork(PTP_WORK_CALLBACK callback,PVOID opt);

  // Reject new work, then drain every accepted callback. Ownership transfers
  // only when AddWork returns true; callbacks release their context and must
  // not close the pool-owned PTP_WORK. False from this pool's own callback.
  // Never call from DllMain. Repeated external Stop calls are safe.
  bool Stop();

 private:
  struct Task { PTP_WORK_CALLBACK callback; PVOID context; };
  enum class State { Stopped, Running, Stopping };
  static void CALLBACK RunWork(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK);
  std::mutex mutex_;
  std::condition_variable stopped_;
  std::deque<Task> tasks_;
  State state_ = State::Stopped;
  std::uint64_t completed_stops_ = 0;
  PTP_POOL pool_ = nullptr;
  PTP_WORK work_ = nullptr;
  TP_CALLBACK_ENVIRON env_{};
};

}  // namespace wxhelper

#endif
