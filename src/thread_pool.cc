#include "thread_pool.h"

namespace wxhelper {
namespace { thread_local ThreadPool* current_callback_pool = nullptr; }

ThreadPool& ThreadPool::GetInstance() {
  // A pinned helper must not join callbacks in CRT teardown under loader lock.
  static ThreadPool* instance = new ThreadPool();
  return *instance;
}

ThreadPool::~ThreadPool() { Stop(); }

bool ThreadPool::Create(unsigned long min, unsigned long max) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (!max || min > max || state_ == State::Stopping) return false;
  if (state_ == State::Running) return true;
  InitializeThreadpoolEnvironment(&env_);
  pool_ = CreateThreadpool(nullptr);
  if (!pool_) {
    DestroyThreadpoolEnvironment(&env_);
    return false;
  }
  SetThreadpoolThreadMaximum(pool_, max);
  if (!SetThreadpoolThreadMinimum(pool_, min)) {
    CloseThreadpool(pool_);
    pool_ = nullptr;
    DestroyThreadpoolEnvironment(&env_);
    return false;
  }
  SetThreadpoolCallbackPool(&env_, pool_);
  // One reusable work object avoids retaining a Windows work object per message.
  work_ = CreateThreadpoolWork(RunWork, this, &env_);
  if (!work_) {
    CloseThreadpool(pool_);
    pool_ = nullptr;
    DestroyThreadpoolEnvironment(&env_);
    return false;
  }
  state_ = State::Running;
  return true;
}

bool ThreadPool::AddWork(PTP_WORK_CALLBACK callback, PVOID context) {
  if (!callback) return false;
  std::lock_guard<std::mutex> lock(mutex_);
  if (state_ != State::Running) return false;
  try {
    tasks_.push_back({callback, context});
  } catch (...) {
    return false;
  }
  SubmitThreadpoolWork(work_);
  return true;
}

void CALLBACK ThreadPool::RunWork(PTP_CALLBACK_INSTANCE instance, PVOID context,
                                  PTP_WORK work) {
  auto* self = static_cast<ThreadPool*>(context);
  Task task{};
  {
    std::lock_guard<std::mutex> lock(self->mutex_);
    // Exactly one SubmitThreadpoolWork is issued for each accepted task.
    if (self->tasks_.empty()) return;
    task = self->tasks_.front();
    self->tasks_.pop_front();
  }
  auto* previous = current_callback_pool;
  current_callback_pool = self;
  try {
    task.callback(instance, task.context, work);
  } catch (...) {
    OutputDebugStringA("wxhelper: a thread-pool callback threw an exception.");
  }
  current_callback_pool = previous;
}

bool ThreadPool::Stop() {
  if (current_callback_pool == this) return false;
  std::unique_lock<std::mutex> lock(mutex_);
  if (state_ == State::Stopping) {
    const auto completed = completed_stops_;
    stopped_.wait(lock, [this, completed] { return completed_stops_ != completed; });
    // This call joined the stop already in progress. A later Create belongs
    // to a different generation and must not be stopped by this old waiter.
    return true;
  }
  if (state_ == State::Stopped) return true;
  state_ = State::Stopping;
  const auto work = work_;
  lock.unlock();
  // FALSE is intentional: cancellation would strand caller-owned contexts.
  WaitForThreadpoolWorkCallbacks(work, FALSE);
  CloseThreadpoolWork(work);
  lock.lock();
  work_ = nullptr;
  CloseThreadpool(pool_);
  pool_ = nullptr;
  DestroyThreadpoolEnvironment(&env_);
  state_ = State::Stopped;
  ++completed_stops_;
  lock.unlock();
  stopped_.notify_all();
  return true;
}
}  // namespace wxhelper
