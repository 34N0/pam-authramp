#include <stdio.h>
#include "../include/tests.h"

int main() {
    if (create_pam_service_file() == 0) {
        printf("PAM service file created successfully.\n");
    }

    if (remove_pam_service_file() == 0) {
        printf("PAM service file removed successfully.\n");
    }

    if (clear_tally_dir() == 0) {
        printf("Tally directory cleared successfully.\n");
    }

    return 0;
}