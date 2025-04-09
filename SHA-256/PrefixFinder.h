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

inline int countLeadingZeroBytes(const std::vector<uint8_t>& hash) {
    int count = 0;
    while (count < hash.size() && hash[count] == 0) {
        count++;
    }
    return count;
}

inline bool hasLeadingZeroBytes(const std::vector<uint8_t>& hash, int zeroBytes) {
    return countLeadingZeroBytes(hash) >= zeroBytes;
}

inline void printHex(const std::vector<uint8_t>& data) {
    for (uint8_t b : data)
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
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

inline void findPrefixWithLeadingZeroHash(const std::string& message, int zeroBytes, uint64_t seed = 0) {
    const int prefixLen = 20;
    const int threadCount = std::thread::hardware_concurrency();

    if (seed == 0) seed = std::chrono::steady_clock::now().time_since_epoch().count();
    std::cout << "Using seed: " << seed << std::endl;

    std::atomic<bool> found(false);
    std::atomic<int> maxZeroesFound(0);
    std::mutex outputMutex;
    std::vector<std::thread> threads;

    for (int t = 0; t < threadCount; ++t) {
        threads.emplace_back([&, t]() {
            std::mt19937_64 rng(seed + t);

            SHA256 sha256;
            std::string prefix = generateRandomString(rng, prefixLen);
            std::string bestPrefix = prefix;
            std::vector<uint8_t> bestHash;
            int localMaxZeroes = 0;

            size_t localAttempts = 0;
            while (!found.load()) {
                std::string fullInput = prefix + message;
                std::vector<uint8_t> hash = sha256.hashRaw(fullInput);
                int currentZeroes = countLeadingZeroBytes(hash);

                if (currentZeroes > localMaxZeroes) {
                    localMaxZeroes = currentZeroes;
                    bestPrefix = prefix;
                    bestHash = hash;

                    int currentMax = maxZeroesFound.load();
                    while (currentZeroes > currentMax) {
                        if (maxZeroesFound.compare_exchange_strong(currentMax, currentZeroes)) {
                            std::lock_guard<std::mutex> lock(outputMutex);
                            std::cout << "\n[Thread " << t << "] New max zeroes: " << currentZeroes << "\n";
                            std::cout << "Prefix: " << prefix << "\n";
                            std::cout << "Hash: ";
                            printHex(hash);
                            std::cout << std::dec << std::endl;
                            break;
                        }
                        currentMax = maxZeroesFound.load();
                    }
                }

                if (hasLeadingZeroBytes(hash, zeroBytes)) {
                    found.store(true);
                    std::lock_guard<std::mutex> lock(outputMutex);

                    std::cout << "\n[Thread " << t << "] Found target " << zeroBytes << " zeroes after " << localAttempts << " attempts!\n";
                    std::cout << "Prefix: " << prefix << "\n";
                    std::cout << "Hash: ";
                    printHex(hash);
                    std::cout << std::dec << std::endl;
                    break;
                }

                incrementString(prefix);

                if (++localAttempts % 100000 == 0) {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[Thread " << t << "] Processed " << localAttempts << " prefixes. Best: " << localMaxZeroes << " zero bytes\n";
                }
            }
            });
    }

    for (auto& th : threads)
        th.join();
}