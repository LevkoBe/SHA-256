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

inline int countLeadingZeroBits(const std::vector<uint8_t>& hash) {
    int count = 0;

    for (size_t i = 0; i < hash.size(); i++) {
        if (hash[i] == 0) {
            count += 8;
            continue;
        }

        uint8_t byte = hash[i];
        for (int bit = 7; bit >= 0; bit--) {
            if ((byte & (1 << bit)) == 0) {
                count++;
            }
            else return count;
        }
        return count;
    }

    return count;
}

inline bool hasLeadingZeroBits(const std::vector<uint8_t>& hash, int zeroBits) {
    return countLeadingZeroBits(hash) >= zeroBits;
}

inline void printHex(const std::vector<uint8_t>& data) {
    for (uint8_t b : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
}

inline void printBinary(const std::vector<uint8_t>& hash, int maxBytes = 4) {
    std::cout << "Binary (first " << maxBytes << " bytes): ";
    for (size_t i = 0; i < std::min(hash.size(), static_cast<size_t>(maxBytes)); i++) {
        for (int bit = 7; bit >= 0; bit--) {
            std::cout << ((hash[i] & (1 << bit)) ? '1' : '0');
        }
        std::cout << ' ';
    }
    std::cout << std::endl;
}

inline std::string generateRandomString(std::mt19937_64& rng, int length) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::uniform_int_distribution<size_t> dist(0, charset.size() - 1);

    std::string result(length, ' ');
    for (int i = 0; i < length; ++i) {
        result[i] = charset[dist(rng)];
    }
    return result;
}

inline void incrementString(std::string& str) {
    const std::string charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = str.size() - 1; i >= 0; --i) {
        size_t pos = charset.find(str[i]);
        if (pos != std::string::npos) {
            if (pos < charset.size() - 1) {
                str[i] = charset[pos + 1];
                return;
            }
            else str[i] = charset[0];
        }
        else {
            if (str[i] < 127) {
                str[i]++;
                return;
            }
            else str[i] = 32;
        }
    }
}

inline void findPrefixWithLeadingZeroBits(const std::string& message, int zeroBits, uint64_t seed = 0) {
    const int prefixLen = 20;
    const int threadCount = std::thread::hardware_concurrency();

    if (seed == 0) seed = std::chrono::steady_clock::now().time_since_epoch().count();
    std::cout << "Using seed: " << seed << std::endl;
    std::cout << "Searching for a prefix that produces a hash with " << zeroBits << " leading zero bits" << std::endl;

    std::atomic<bool> found(false);
    std::atomic<int> maxBitsFound(0);
    std::mutex outputMutex;
    std::vector<std::thread> threads;

    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back([&, t]() {
            std::mt19937_64 rng(seed + t);

            SHA256 sha256;
            std::string prefix = generateRandomString(rng, prefixLen);
            std::string bestPrefix = prefix;
            std::vector<uint8_t> bestHash;
            int localMaxBits = 0;

            size_t localAttempts = 0;
            while (!found.load()) {
                std::string fullInput = prefix + message;
                std::vector<uint8_t> hash = sha256.hashRaw(fullInput);
                int currentBits = countLeadingZeroBits(hash);

                if (currentBits > localMaxBits) {
                    localMaxBits = currentBits;
                    bestPrefix = prefix;
                    bestHash = hash;

                    int currentMax = maxBitsFound.load();
                    while (currentBits > currentMax) {
                        if (maxBitsFound.compare_exchange_strong(currentMax, currentBits)) {
                            std::lock_guard<std::mutex> lock(outputMutex);
                            std::cout << "\n[Thread " << t << "] New max zero bits: " << currentBits << "\n";
                            std::cout << "Prefix: " << prefix << "\n";
                            std::cout << "Hash: ";
                            printHex(hash);
                            std::cout << std::dec << std::endl;
                            printBinary(hash);
                            break;
                        }
                        currentMax = maxBitsFound.load();
                    }
                }

                if (hasLeadingZeroBits(hash, zeroBits)) {
                    found.store(true);
                    std::lock_guard<std::mutex> lock(outputMutex);

                    std::cout << "\n[Thread " << t << "] Found target " << zeroBits << " zero bits after " << localAttempts << " attempts!\n";
                    std::cout << "Prefix: " << prefix << "\n";
                    std::cout << "Hash: ";
                    printHex(hash);
                    std::cout << std::dec << std::endl;
                    printBinary(hash);
                    break;
                }

                incrementString(prefix);

                if (++localAttempts % 100000 == 0) {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[Thread " << t << "] Processed " << localAttempts << " prefixes. Best: " << localMaxBits << " zero bits\n";
                }
            }
            });
    }

    for (auto& th : threads)
        th.join();
}