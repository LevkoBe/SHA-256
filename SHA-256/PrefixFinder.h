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

inline void findPrefixWithLeadingZeroHash_MultiThreaded(const std::string& message, int zeroBits, int threadCount = std::thread::hardware_concurrency()) {
    assert(zeroBits % 8 == 0 && zeroBits <= 256);
    const int zeroBytes = zeroBits / 8;
    const int prefixLen = 20;

    std::atomic<bool> found(false);
    std::mutex outputMutex;
    std::vector<std::thread> threads;

    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back([&, t]() {
            SHA256 sha256;
            std::vector<uint8_t> prefix(prefixLen, 0);
            prefix[0] = static_cast<uint8_t>(t);

            size_t localAttempts = 0;
            while (!found.load(std::memory_order_relaxed)) {
                std::string fullInput(reinterpret_cast<char*>(prefix.data()), prefixLen);
                fullInput += message;

                std::vector<uint8_t> hash = sha256.hashRaw(fullInput);

                if (hasLeadingZeroBytes(hash, zeroBytes)) {
                    found.store(true);
                    std::lock_guard<std::mutex> lock(outputMutex);

                    std::cout << "\n[Thread " << t << "] Found valid prefix after " << localAttempts << " attempts!\n";
                    std::cout << "Prefix (hex): ";
                    for (uint8_t b : prefix)
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                    std::cout << "\nHash (hex): ";
                    for (uint8_t b : hash)
                        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
                    std::cout << std::endl;
                    break;
                }

                incrementPrefix(prefix);
				if (++localAttempts % 100000 == 0) {
					std::lock_guard<std::mutex> lock(outputMutex);
					std::cout << "[Thread " << t << "] Processed " << localAttempts << " prefixes...\n";
				}
            }
            });
    }

    for (auto& th : threads)
        th.join();
}
