// Copyright 2023 34n0
// 
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

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