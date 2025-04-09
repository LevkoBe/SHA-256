#include "SHA256.h"
#include "TestSuite.h"
#include "PrefixFinder.h"

int main() {
    //runAllTests();
    findPrefixWithLeadingZeroHash("give my friend 2 bitcoins for a pizza", 32);
    return 0;
}
