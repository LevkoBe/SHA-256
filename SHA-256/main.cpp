#include <fstream>
#include "SHA256.h"
#include "TestSuite.h"
#include "PrefixFinder.h"

std::string base64_decode(const std::string& in) {
    std::string out;

    std::vector T(256, -1);
    for (int i = 0; i < 64; i++) T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;

    int val = 0, valB = -8;
    for (const unsigned char c : in) {
        if (c == '\n' || c == '\r') continue;
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valB += 6;
        if (valB >= 0) {
            out.push_back(static_cast<char>((val >> valB) & 0xFF));
            valB -= 8;
        }
    }
    return out;
}

int main() {
    /* Execute tests */
    // ------------- //
    //runAllTests();

    /* Find prefix for given message */
    // ----------------------------- //
    //PrefixFinder prefixFinder;
    //prefixFinder.find("give my friend 2 bitcoins for a pizza", 256); // ~~256~~ => 32

    /* Raw hash in file */
    // ---------------- //
    // SHA256 sha256;
    // const std::string message = "give my friend 2 bitcoins for a pizza";
    // const std::string hash = sha256.hash(message);
    // const std::string rawHash = hexToString(hash);
    //
    // std::ofstream ofs("../message.sha256", std::ios::binary);
    // if (!ofs) {
    //     std::cerr << "Error opening file for reading." << std::endl;
    //     return 1;
    // }
    // ofs.write(rawHash.c_str(), rawHash.size());
    // ofs.close();
    // std::cout << "Hash: " << hash << std::endl;

    /* Certificate analysis */
    // -------------------- //
    //SHA256 sha256;
    // std::ifstream ifs("../kse.ua.crt", std::ios::binary);
    // if (!ifs) {
    //     std::cerr << "Error opening file for reading." << std::endl;
    //     return 1;
    // }
    // std::string certificate((std::istreambuf_iterator(ifs)),
    //                         std::istreambuf_iterator<char>());
    // ifs.close();
    //
    // std::string token = "-----BEGIN CERTIFICATE-----";
    // size_t pos = 0;
    // while ((pos = certificate.find(token)) != std::string::npos) {
    //     certificate.erase(pos, token.length());
    // }
    // token = "-----END CERTIFICATE-----";
    // while ((pos = certificate.find(token)) != std::string::npos) {
    //     certificate.erase(pos, token.length());
    // }
    //
    // const std::string decoded = base64_decode(certificate);
    // const std::string hash = sha256.hash(decoded);
    // std::cout << "Hash: " << hash << std::endl;
    return 0;
}
