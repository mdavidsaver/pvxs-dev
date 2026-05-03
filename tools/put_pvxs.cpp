/*
EPICS Server:
 softIocPVA st.cmd
 ./put_ca
=== EPICS CA Put Benchmark: 1000 PVs ===

[PHASE 1] Creating channels and connecting...
  Connect time:          100.654 ms
  Connected: 1000/1000 PVs

[PHASE 2] Issuing put requests...
  Put issue time:        0.211 ms
  Puts issued: 1000

[PHASE 3] Waiting for put completions...
  Wait time:             3.206 ms
  Completed: 1000/1000 puts

=== SUMMARY ===
  Connect phase:         100.654 ms (96.7%)
  Put issue phase:       0.211 ms (0.2%)
  Wait phase:            3.206 ms (3.1%)
  ---------------------------------
  TOTAL TIME:            104.124 ms
  Throughput:            9603.9 puts/sec
➜  build git:(pvxs) ✗ ./put_pvxs
=== EPICS PVXS Put Benchmark: 1000 PVs ===

[PHASE 1] Creating PVXS client...
  Client creation time:  1.04058 ms

[PHASE 2] Issuing put requests...
  Put issue time:        5.44334 ms
  Puts issued: 1000

[PHASE 3] Waiting for put completions...
  Wait time:             2002.77 ms
  Completed: 1000/1000 puts

=== SUMMARY ===
  Client creation:       1.04058 ms (0.0517875%)
  Put issue phase:       5.44334 ms (0.270903%)
  Wait phase:            2002.77 ms (99.6733%)
  ---------------------------------
  TOTAL TIME:            2009.33 ms
  Throughput:            497.678 puts/sec

***************************************************+
EPICS Server:
softIocPVX st.cmd

./put_ca
=== EPICS CA Put Benchmark: 1000 PVs ===

[PHASE 1] Creating channels and connecting...
  Connect time:          100.629 ms
  Connected: 1000/1000 PVs

[PHASE 2] Issuing put requests...
  Put issue time:        0.195 ms
  Puts issued: 1000

[PHASE 3] Waiting for put completions...
  Wait time:             4.252 ms
  Completed: 1000/1000 puts

=== SUMMARY ===
  Connect phase:         100.629 ms (95.7%)
  Put issue phase:       0.195 ms (0.2%)
  Wait phase:            4.252 ms (4.0%)
  ---------------------------------
  TOTAL TIME:            105.130 ms
  Throughput:            9512.0 puts/sec
➜  build git:(pvxs) ✗ ./put_pvxs
=== EPICS PVXS Put Benchmark: 1000 PVs ===

[PHASE 1] Creating PVXS client...
  Client creation time:  1.02404 ms

[PHASE 2] Issuing put requests...
  Put issue time:        4.97025 ms
  Puts issued: 1000

[PHASE 3] Waiting for put completions...
  Wait time:             1010.81 ms
  Completed: 1000/1000 puts

=== SUMMARY ===
  Client creation:       1.02404 ms (0.100708%)
  Put issue phase:       4.97025 ms (0.488793%)
  Wait phase:            1010.81 ms (99.4072%)
  ---------------------------------
  TOTAL TIME:            1016.84 ms
  Throughput:            983.437 puts/sec


 */
#include <pvxs/client.h>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <atomic>
#include <thread>
#include <iomanip>
#include <sstream>
#include <random>

const std::string PV_PREFIX = "SIM:PV:DOUBLE:";
constexpr int    PV_DIGITS = 4;      // zero-padded width  → "0000"
                                     //
using namespace pvxs;
using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;

double elapsedMs(TimePoint start, TimePoint end) {
  return std::chrono::duration<double, std::milli>(end - start).count();
}

//int main(int argc, char* argv[]) {
int main() {
  const int NUM_PVS = 1000;

  std::vector<std::string> pv_names(NUM_PVS);
  std::vector<double> pv_values(NUM_PVS);

  // Helper: build a zero-padded PV name, e.g. "SIM:PV:DOUBLE:0042"
  auto makePVName = [&](int idx) -> std::string {
    std::ostringstream oss;
    oss << PV_PREFIX
      << std::setw(PV_DIGITS) << std::setfill('0') << idx;
    return oss.str();
  };

  // Random number generator
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_real_distribution<double> dist(0.0, 100.0);

  for (int i = 0; i < NUM_PVS; i++) {
    pv_names[i] =  makePVName(i); //"TEST:PV:" + std::to_string(i);
    pv_values[i] = dist(gen); // static_cast<double>(i);
  }

  std::cout << "=== EPICS PVXS Put Benchmark: " << NUM_PVS << " PVs ===\n\n";

  // Phase 1: Create client
  std::cout << "[PHASE 1] Creating PVXS client...\n";
  TimePoint client_start = Clock::now();

  client::Context ctx = client::Context::fromEnv();

  TimePoint client_end = Clock::now();
  std::cout << "  Client creation time:  " << elapsedMs(client_start, client_end) << " ms\n\n";

  // Phase 2: Issue puts
  std::cout << "[PHASE 2] Issuing put requests...\n";
  TimePoint put_start = Clock::now();

  std::vector<std::shared_ptr<client::Operation>> operations;
  operations.reserve(NUM_PVS);

  std::atomic<int> completed{0};
  std::atomic<int> failed{0};

  for (int i = 0; i < NUM_PVS; i++) {
    auto name = pv_names[i];
    auto op = ctx.put(pv_names[i])
      .set("value", pv_values[i])
      .result([&completed, &failed, name](client::Result&& result) {
          try {
          result();
          completed++;
          } catch (const std::exception& e) {
          failed++;
          std::cerr << "Put failed for " << name << ": " << e.what() << "\n";
          }
          })
    .exec();

    operations.push_back(op);
  }
  ctx.hurryUp();
  TimePoint put_end = Clock::now();
  std::cout << "  Put issue time:        " << elapsedMs(put_start, put_end) << " ms\n";
  std::cout << "  Puts issued: " << NUM_PVS << "\n\n";

  // ========== PHASE 3: WAIT FOR COMPLETION ==========
  std::cout << "[PHASE 3] Waiting for put completions...\n";
  TimePoint wait_start = Clock::now();

  const double TIMEOUT_SEC = 1000.0;
  const auto timeout = std::chrono::milliseconds(static_cast<int>(TIMEOUT_SEC * 1000));
  const auto poll_interval = std::chrono::milliseconds(1);
  auto deadline = Clock::now() + timeout;

  while (Clock::now() < deadline) {
    if (completed + failed >= NUM_PVS) break;
    std::this_thread::sleep_for(poll_interval);
  }

  TimePoint wait_end = Clock::now();

  std::cout << "  Wait time:             " << elapsedMs(wait_start, wait_end) << " ms\n";
  std::cout << "  Completed: " << completed.load() << "/" << NUM_PVS << " puts\n";
  if (failed > 0) {
    std::cout << "  Failed: " << failed.load() << " puts\n";
  }
  std::cout << "\n";

  // ========== SUMMARY ==========
  double total_time = elapsedMs(client_start, wait_end);
  double client_time = elapsedMs(client_start, client_end);
  double put_time = elapsedMs(put_start, put_end);
  double wait_time = elapsedMs(wait_start, wait_end);

  std::cout << "=== SUMMARY ===\n";
  std::cout << "  Client creation:       " << client_time << " ms (" 
    << (100.0 * client_time / total_time) << "%)\n";
  std::cout << "  Put issue phase:       " << put_time << " ms ("
    << (100.0 * put_time / total_time) << "%)\n";
  std::cout << "  Wait phase:            " << wait_time << " ms ("
    << (100.0 * wait_time / total_time) << "%)\n";
  std::cout << "  ---------------------------------\n";
  std::cout << "  TOTAL TIME:            " << total_time << " ms\n";
  std::cout << "  Throughput:            " 
    << ((completed > 0) ? (completed * 1000.0 / total_time) : 0.0) 
    << " puts/sec\n";

  // Cleanup: operations are cancelled when they go out of scope
  operations.clear();

  return 0;
}
