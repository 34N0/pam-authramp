#include "tests/tests.h"
#include <stdio.h>

int main() {
    // run integration tests
    test_valid_auth();
    test_invalid_auth();
    test_bounce_auth();

    printf("------ \n");
    return 0;
}