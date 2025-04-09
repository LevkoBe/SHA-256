#pragma once
#include "SHA256.h"
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <cassert>
#include <atomic>
#include <thread>
#include <mutex>
#include <random>
#include <chrono>

inline bool hasLeadingZeroBytes(const std::vector<uint8_t>& hash, int zeroBytes) {
    for (int i = 0; i < zeroBytes; ++i)
        if (hash[i] != 0)
            return false;
    return true;
}

inline void incrementPrefix(std::vector<uint8_t>& prefix) {
    for (int i = prefix.size() - 1; i >= 0; --i) {
        if (++prefix[i] != 0) break;
    }
}

inline void findPrefixWithLeadingZeroHash(const std::string& message, int zeroBytes, uint64_t seed = 0) {
    const int prefixLen = 20;
    const int threadCount = std::thread::hardware_concurrency();

    if (seed == 0) seed = std::chrono::steady_clock::now().time_since_epoch().count();
    std::cout << "Using seed: " << seed << std::endl;

    std::atomic<bool> found(false);
    std::mutex outputMutex;
    std::vector<std::thread> threads;

    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back([&, t]() {
            std::mt19937_64 rng(seed + t);
            std::uniform_int_distribution<uint8_t> dist(0, 255);

            SHA256 sha256;
            std::vector<uint8_t> prefix(prefixLen);

            for (int i = 0; i < prefixLen; ++i) {
                prefix[i] = dist(rng);
            }

            size_t localAttempts = 0;
            while (!found.load()) {
                std::string fullInput(reinterpret_cast<char*>(prefix.data()), prefixLen);
                fullInput += message;

                std::vector<uint8_t> hash = sha256.hashRaw(fullInput);

                if (hasLeadingZeroBytes(hash, zeroBytes)) {
                    found.store(true);
                    std::lock_guard<std::mutex> lock(outputMutex);

                    std::cout << "\n[Thread " << t << "] Found after " << localAttempts << " attempts!\n";
                    std::cout << "Prefix: ";
                    for (uint8_t b : prefix)
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                    std::cout << "\nHash: ";
                    for (uint8_t b : hash)
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                    std::cout << std::dec << std::endl;
                    break;
                }

                incrementPrefix(prefix);

                if (++localAttempts % 100000 == 0) {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[Thread " << t << "] Processed " << localAttempts << " prefixes\n";
                }
            }
            });
    }

    for (auto& th : threads)
        th.join();
}