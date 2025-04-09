#include "SHA256.h"
#include "TestSuite.h"
#include "PrefixFinder.h"

int main() {
    //runAllTests();
    findPrefixWithLeadingZeroHash_MultiThreaded("give my friend 2 bitcoins for a pizza", 32);
    return 0;
}
