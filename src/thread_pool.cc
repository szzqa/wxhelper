
#include "pch.h"
#include "thread_pool.h"

#include "Windows.h"

namespace wxhelper {
ThreadPool& ThreadPool::GetInstance() {
  // The helper is pinned. Windows reclaims this pool when the process exits;
  // a static destructor must not wait for callbacks under the loader lock.
  static ThreadPool* instance = new ThreadPool();
  return *instance;
}

ThreadPool::~ThreadPool() {
  if(cleanup_group_){
    CloseThreadpoolCleanupGroupMembers(cleanup_group_, true, NULL);
    CloseThreadpoolCleanupGroup(cleanup_group_);
  }
  DestroyThreadpoolEnvironment(&env_);
  if (pool_){
    CloseThreadpool(pool_);
  }
}

bool ThreadPool::Create(unsigned long min, unsigned long max) {
  InitializeThreadpoolEnvironment(&env_);
  pool_ = CreateThreadpool(NULL);
  if (NULL == pool_) {
    DestroyThreadpoolEnvironment(&env_);
    return false;
  }
  SetThreadpoolThreadMaximum(pool_, max);
  BOOL ret = SetThreadpoolThreadMinimum(pool_, min);
  if (FALSE == ret) {
    CloseThreadpool(pool_);
    pool_ = nullptr;
    DestroyThreadpoolEnvironment(&env_);
    return false;
  }
  cleanup_group_ = CreateThreadpoolCleanupGroup();
  if (NULL == cleanup_group_) {
    CloseThreadpool(pool_);
    pool_ = nullptr;
    DestroyThreadpoolEnvironment(&env_);
    return false;
  }
  SetThreadpoolCallbackPool(&env_, pool_);
  SetThreadpoolCallbackCleanupGroup(&env_, cleanup_group_, NULL);
  return true;
}

bool ThreadPool::AddWork(PTP_WORK_CALLBACK callback,PVOID opt) {
  PTP_WORK work = CreateThreadpoolWork(callback, opt, &env_);
  if (NULL == work) {
    return false;
  }
  SubmitThreadpoolWork(work);
  return true;
}

}  // namespace wxhelper
