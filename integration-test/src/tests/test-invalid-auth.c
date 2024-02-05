#include "../utils/utils.h"
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <unistd.h>

int test_invalid_auth() {
  printf("------ \n");
  printf("test_valid_auth: \n\n");

  char srv[] =
      "auth        required                                     libpam_authramp.so preauth \n\
      auth        [default=die]                                libpam_authramp.so authfail \n\
      account     required                                     libpam_authramp.so";

  create_pam_service_file(srv);

  pam_handle_t *pamh = NULL;
  int retval;

  char user_name[] = "user";

  retval = pam_start(PAM_SRV, user_name, &conv, &pamh);

  // Are the credentials correct?
  if (retval == PAM_SUCCESS) {
    printf("PAM module initialized\n");
    retval = pam_authenticate(pamh, 0);
  }

  // Can the accound be used at this time?
  if (retval == PAM_SUCCESS) {
    printf("Credentials accepted.\n");
    retval = pam_acct_mgmt(pamh, 0);
  }

  // Did everything work?
  if (retval == PAM_SUCCESS) {
    print_error("Account is valid.\n");
    print_error("Authenticated\n");
  } else {
    char e[256];
    printf("Not Authenticated:  %d\n", retval);
  }

  // close PAM (end session)
  if (pam_end(pamh, retval) != PAM_SUCCESS) {
    pamh = NULL;
    printf("Check_user: failed to release authenticator\n");
  }

  remove_pam_service_file();

  if (retval != PAM_SUCCESS) {

  char tallyFilePath[FILE_PATH_MAX];
  snprintf(tallyFilePath, sizeof(tallyFilePath), "%s%s", TALLY_DIR, user_name);
    
    if (access(tallyFilePath, F_OK) != -1) {
      print_success("test_valid_auth");
    } else {
      print_error("tally file not created");
    }
    clear_tally_dir();
  }
  return retval;
}