#include "utils.h"
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

char SRV_DIR[] = "/etc/pam.d/";
char PAM_SRV[] = "test-authramp";

const char TALLY_DIR[] = "/var/run/authramp";

struct pam_conv conv = {misc_conv, NULL};

int writeToFile(const char *filePath, const char *content) {
  FILE *file = fopen(filePath, "w");

  if (file == NULL) {
    perror("Error opening file");
    return 1;
  }

  if (fprintf(file, "%s", content) < 0) {
    perror("Error writing to file");
    fclose(file);
    return 1;
  }

  if (fclose(file) != 0) {
    perror("Error closing file");
    return 1;
  }

  return 0;
}

int create_pam_service_file(const char *srv_content) {
  char filePath[FILE_PATH_MAX];
  snprintf(filePath, sizeof(filePath), "%s%s", SRV_DIR, PAM_SRV);
  return writeToFile(filePath, srv_content);
}

int removeFile(const char *filePath) {
  if (remove(filePath) != 0) {
    perror("Error removing file");
    return 1;
  }
  return 0;
}

int remove_pam_service_file() {
  char filePath[FILE_PATH_MAX];
  snprintf(filePath, sizeof(filePath), "%s%s", SRV_DIR, PAM_SRV);
  return removeFile(filePath);
}

int clear_tally_dir() {
  if (rmdir(TALLY_DIR) != 0) {
    perror("Error clearing tally directory");
    return 1;
  }
  return 0;
}

void print_error(const char *message) {
  printf(RED_TEXT "Error: %s" RESET_TEXT "\n", message);
}

void print_success(const char *message) {
  printf(GREEN_TEXT "Success: %s" RESET_TEXT "\n", message);
}