#include "SHA256.h"
#include "TestSuite.h"
#include "PrefixFinder.h"

int main() {
    runAllTests();
    findPrefixWithLeadingZeroHash("give my friend 2 bitcoins for a pizza", 4);
    return 0;
}
