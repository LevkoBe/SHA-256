#pragma once
#include "SHA256.h"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <cassert>

inline void testOutput(const std::string& expectedHash, const std::string& result, int testNum) {
    std::cout << "  Test " << testNum << ".\n";
    std::cout << ((result == expectedHash) ? "[PASSED]" : "[FAILED]") << std::endl;
    std::cout << "  Expected: " << expectedHash << std::endl;
    std::cout << "  Got:      " << result << std::endl;
}

inline void runTests(const std::string& input, const std::string& expectedHash, int testNum) {
    SHA256 sha256;
    std::string result = sha256.hash(input);
    testOutput(expectedHash, result, testNum);
    assert(result == expectedHash);
}

inline void testVeryLongString(const std::string& pattern, size_t repeatCount, const std::string& expectedHash, int testNum) {
    std::cout << "\nRunning very long string test (16 777 216 blocks)..." << std::endl;
    SHA256 sha256;

    const size_t patternSize = pattern.size();
    const uint64_t totalSize = patternSize * repeatCount;
    std::cout << "  Total calculated size: " << totalSize << " bytes" << std::endl;

    size_t fullBlocks = totalSize / 64;
    size_t patternPos = 0;
    for (size_t i = 0; i < fullBlocks; ++i) {
        std::vector<uint8_t> block(64);
        for (size_t j = 0; j < 64; ++j) {
            block[j] = pattern[patternPos];
            patternPos = (patternPos + 1) % patternSize;
        }

        sha256.hash512bBlock(block.data());
        if (i % 1000000 == 0 && i > 0)
            std::cout << "  Processed " << i << " blocks..." << std::endl;
    }

    size_t remaining = totalSize % 64;
    size_t paddingLength = (remaining < 56) ? 64 : 128;
    std::vector<uint8_t> finalBlock = SHA256::createStandardPadding(paddingLength, totalSize * 8);

    for (size_t i = 0; i < remaining; ++i) {
        finalBlock[i] = pattern[patternPos];
        patternPos = (patternPos + 1) % patternSize;
    }

    sha256.hash512bBlock(finalBlock.data());
    if (paddingLength == 128)
        sha256.hash512bBlock(finalBlock.data() + 64);

    std::stringstream ss;
    for (int i = 0; i < 8; i++)
        ss << std::hex << std::setw(8) << std::setfill('0') << sha256.H[i];
    std::string result = ss.str();

    testOutput(expectedHash, result, testNum);
    assert(result == expectedHash);
}

inline void runAllTests() {
    using TestCase = std::pair<std::string, std::string>;
    std::vector<TestCase> test_cases = {
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
         "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
        {std::string(1000000, 'a'), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
    };

    std::cout << "Running basic tests..." << std::endl;
    int i = 1;
    for (const auto& [input, expected] : test_cases)
        runTests(input, expected, i++);

    testVeryLongString("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno", 16777216,
        "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e", i++);

    std::cout << "\nAll tests passed!" << std::endl;
}
