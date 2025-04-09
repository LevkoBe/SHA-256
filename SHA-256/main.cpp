#include "SHA256.h"
#include "TestSuite.h"
#include "PrefixFinder.h"

int main() {
    //runAllTests();
    findPrefixWithLeadingZeroHash("give my friend 2 bitcoins for a pizza", 11); // we need only 4 bytes actually
    return 0;
}
