#include "SHA256.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <cstring>

SHA256::SHA256() {
    reset();
}

void SHA256::reset() {
    H[0] = 0x6a09e667;
    H[1] = 0xbb67ae85;
    H[2] = 0x3c6ef372;
    H[3] = 0xa54ff53a;
    H[4] = 0x510e527f;
    H[5] = 0x9b05688c;
    H[6] = 0x1f83d9ab;
    H[7] = 0x5be0cd19;
}

inline uint32_t SHA256::rotr(uint32_t x, int n) const {
    return (x >> n) | (x << (32 - n));
}

inline uint32_t SHA256::ch(uint32_t x, uint32_t y, uint32_t z) const {
    return (x & y) ^ (~x & z);
}

inline uint32_t SHA256::maj(uint32_t x, uint32_t y, uint32_t z) const {
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t SHA256::sigma0(uint32_t x) const {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

inline uint32_t SHA256::sigma1(uint32_t x) const {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

inline uint32_t SHA256::gamma0(uint32_t x) const {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

inline uint32_t SHA256::gamma1(uint32_t x) const {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

void SHA256::hash512bBlock(const uint8_t* block) {
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;

    for (int j = 0; j < 16; j++) {
        w[j] = (block[j * 4] << 24) | (block[j * 4 + 1] << 16) |
            (block[j * 4 + 2] << 8) | (block[j * 4 + 3]);
    }

    for (int j = 16; j < 64; j++) {
        w[j] = gamma1(w[j - 2]) + w[j - 7] + gamma0(w[j - 15]) + w[j - 16];
    }

    for (int j = 0; j < 8; j++) {
        wv[j] = H[j];
    }

    for (int j = 0; j < 64; j++) {
        t1 = wv[7] + sigma1(wv[4]) + ch(wv[4], wv[5], wv[6]) + K[j] + w[j];
        t2 = sigma0(wv[0]) + maj(wv[0], wv[1], wv[2]);

        wv[7] = wv[6];
        wv[6] = wv[5];
        wv[5] = wv[4];
        wv[4] = wv[3] + t1;
        wv[3] = wv[2];
        wv[2] = wv[1];
        wv[1] = wv[0];
        wv[0] = t1 + t2;
    }

    for (int j = 0; j < 8; j++) {
        H[j] += wv[j];
    }
}

std::vector<uint8_t> SHA256::createStandardPadding(size_t paddingLength, size_t inputLengthBits) {
    std::vector<uint8_t> padding(paddingLength, 0);

    padding[0] = 0x80;
    
    for (int i = 0; i < 8; i++)
        padding[paddingLength - 1 - i] = static_cast<uint8_t>((inputLengthBits >> (8 * i)) & 0xFF);

    return padding;
}

std::vector<std::vector<uint8_t>> SHA256::splitIn512bBlocks(const std::string& message) {
    std::vector<std::vector<uint8_t>> blocks;

    size_t originalLenBytes = message.length();
    size_t originalLenBits = originalLenBytes * 8;

    size_t totalLen = originalLenBytes + 1 + 8;
    size_t paddingLen = ((totalLen % BLOCKSize) == 0) ? 0 : (BLOCKSize - totalLen % BLOCKSize);
    size_t totalPaddedLen = originalLenBytes + 1 + paddingLen + 8;

    std::vector<uint8_t> fullMessage;
    fullMessage.insert(fullMessage.end(), message.begin(), message.end());
    std::vector<uint8_t> padding = createStandardPadding(totalPaddedLen - originalLenBytes, originalLenBits);
    fullMessage.insert(fullMessage.end(), padding.begin(), padding.end());

    size_t blockCount = fullMessage.size() / BLOCKSize;
    for (size_t i = 0; i < blockCount; i++) {
        blocks.emplace_back(fullMessage.begin() + i * BLOCKSize, fullMessage.begin() + (i + 1) * BLOCKSize);
    }

    return blocks;
}

std::string SHA256::hash(const std::string& input) {
    reset();

    std::vector<std::vector<uint8_t>> blocks = splitIn512bBlocks(input);
    for (const auto& block : blocks) hash512bBlock(block.data());

    std::stringstream ss;
    for (int i = 0; i < 8; i++) ss << std::hex << std::setw(8) << std::setfill('0') << H[i];

    return ss.str();
}

void SHA256::update(const std::string& data) {
    std::vector<std::vector<uint8_t>> blocks = splitIn512bBlocks(data);
    for (const auto& block : blocks) {
        hash512bBlock(block.data());
    }
}
