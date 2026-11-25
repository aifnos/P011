#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <gnu/libc-version.h>
#include <future>
#include <iostream>
#include <optional>
#include <string>
#include <thread>

int main(int argc, char **argv)
{
    const std::optional<int> expected = 685;
    const auto started = std::chrono::steady_clock::now();
    std::promise<int> promise;
    auto future = promise.get_future();
    std::thread worker([&promise] { promise.set_value(685); });
    worker.join();
    const int future_value = future.get();
    auto async_future = std::async(std::launch::async, [] { return 685; });
    const int async_value = async_future.get();
    const bool thread_ok = future_value == 685 && async_value == 685;
    char encoded[16] = {};
    const auto result = std::to_chars(encoded, encoded + sizeof(encoded) - 1, *expected);
    int decoded = 0;
    const auto parsed = std::from_chars(encoded, result.ptr, decoded);
    const bool ok = result.ec == std::errc() && parsed.ec == std::errc()
                    && decoded == *expected && sizeof(void *) == 4 && thread_ok;
    // This non-SSO string and iostream output require the dynamic C++ runtime;
    // optional and integer charconv alone may be entirely inlined.
    std::string runtime_text(128 + argc, 'p');
    runtime_text.append(std::to_string(decoded));
    runtime_text.append(argc > 1 ? argv[1] : "fixed");
    std::printf("{\"event\":\"browser685.abi_probe\",\"pointer_bytes\":%u,"
                "\"glibc\":\"%s\",\"cpp17_optional_charconv\":%s,"
                "\"value\":%d,\"qt_built\":false,\"device_browser_tested\":false}\n",
                unsigned(sizeof(void *)), gnu_get_libc_version(), ok ? "true" : "false", decoded);
    std::fflush(stdout);
    std::cout << "{\"event\":\"browser685.libstdcxx_runtime\",\"allocated_string_bytes\":"
              << runtime_text.size() << ",\"iostream\":true}" << std::endl;
    std::cout << "{\"event\":\"browser685.cpp_threads\",\"thread_join\":true,\"future_value\":"
              << future_value << ",\"async_value\":" << async_value << ",\"steady_clock_elapsed_us\":"
              << std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - started).count()
              << "}" << std::endl;
    return ok ? 0 : 2;
}
