#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "utils.h"

const char SRV_DIR[] = "/etc/pam.d/";
const char PAM_SRV[] = "test-authramp";
const char TALLY_DIR[] = "/var/run/authramp";
const char srv_content[] =
    "auth        required                                     libpam_authramp.so preauth \n\
                  auth        sufficient                                   pam_unix.so nullok \n\
                  auth        [default=die]                                libpam_authramp.so authfail \n\
                  account     required                                     libpam_authramp.so";

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

int create_pam_service_file() {
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