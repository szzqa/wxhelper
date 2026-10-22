#include "thread_pool.h"
#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <thread>

namespace {
void Check(bool value, const char* reason) { if (!value) throw std::runtime_error(reason); }
struct Counts { std::atomic<int> ran{0}; std::atomic<int> destroyed{0}; };
struct Item {
  Counts& counts;
  HANDLE entered = nullptr;
  HANDLE release = nullptr;
  bool throws = false;
  ~Item() { ++counts.destroyed; }
};
void CALLBACK Run(PTP_CALLBACK_INSTANCE, PVOID context, PTP_WORK) {
  std::unique_ptr<Item> item(static_cast<Item*>(context));
  if (item->entered) SetEvent(item->entered);
  if (item->release && WaitForSingleObject(item->release, 5000) != WAIT_OBJECT_0)
    throw std::runtime_error("fixture callback timed out");
  ++item->counts.ran;
  if (item->throws) throw std::runtime_error("intentional fixture exception");
}
std::atomic<int> self_result{-1};
void CALLBACK SelfStop(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK) {
  self_result = wxhelper::ThreadPool::GetInstance().Stop() ? 1 : 0;
}
}  // namespace
int main() {
  auto& pool = wxhelper::ThreadPool::GetInstance();
  HANDLE entered = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  HANDLE release = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  try {
    Check(entered && release, "fixture events");
    Check(pool.Stop(), "initial idempotent stop");
    Counts counts;
    auto rejected = std::unique_ptr<Item>(new Item{counts});
    Check(!pool.AddWork(Run, rejected.get()), "reject before create");
    rejected.reset();
    Check(!pool.Create(2, 1) && !pool.Create(0, 0), "invalid limits");
    Check(pool.Create(1, 1), "create");
    Check(pool.Create(1, 1), "create idempotence");
    int accepted = 0;
    auto submit = [&](HANDLE in = nullptr, HANDLE out = nullptr, bool throws = false) {
      auto item = std::unique_ptr<Item>(new Item{counts, in, out, throws});
      const bool ok = pool.AddWork(Run, item.get());
      if (ok) { item.release(); ++accepted; }
      return ok;
    };
    Check(submit(entered, release), "accept blocking work");
    Check(WaitForSingleObject(entered, 2000) == WAIT_OBJECT_0, "first callback entered");
    for (int i = 0; i != 8; ++i) Check(submit(), "accept queued work");
    std::atomic<bool> stopped{false};
    bool stop_ok = false;
    std::thread stopper([&] { stop_ok = pool.Stop(); stopped = true; });
    bool rejected_during_stop = false;
    const auto reject_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (std::chrono::steady_clock::now() < reject_deadline) {
      if (!submit()) { rejected_during_stop = true; break; }
      // Give the stopping thread a scheduling turn, rather than repeatedly
      // winning the pool lock in a tight submission loop.
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    const bool waited = !stopped.load();
    bool joined_stop_ok = false;
    std::thread second_stopper([&] { joined_stop_ok = pool.Stop(); });
    SetEvent(release);
    stopper.join();
    second_stopper.join();
    Check(rejected_during_stop && waited && stop_ok && joined_stop_ok,
          "concurrent Stop rejects new work and waits active work");
    Check(counts.ran == accepted, "Stop drains every queued context without cancellation");
    // The initial caller-owned reject and the in-stop rejected submission are also deleted.
    Check(counts.destroyed == accepted + 2, "all accepted and rejected contexts released");
    Check(!submit(), "reject after stop");
    Check(pool.Stop(), "repeat stop");
    Check(pool.Create(1, 2), "explicit restart");
    Check(pool.AddWork(SelfStop, nullptr), "self-stop fixture submitted");
    Check(submit(nullptr, nullptr, true), "throwing callback submitted");
    Check(submit(), "callback after exception submitted");
    Check(pool.Stop() && self_result == 0, "self-stop rejected and exception does not prevent drain");
    Check(counts.ran == accepted, "all restarted tasks drained");
    CloseHandle(entered); CloseHandle(release);
    std::cout << "PASS: thread pool ownership, rejection, drain, restart and self-stop guard\n";
    return 0;
  } catch (const std::exception& error) {
    SetEvent(release);
    pool.Stop();
    if (entered) CloseHandle(entered);
    if (release) CloseHandle(release);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
