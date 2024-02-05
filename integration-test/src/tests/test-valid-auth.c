#include "../utils/utils.h"
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <unistd.h>

int test_valid_auth() {
  printf("------ \n");
  printf("test_valid_auth: \n\n");

  char srv[] =
      "auth        required                                     libpam_authramp.so preauth \n\
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
    printf("Account is valid.\n");
    printf("Authenticated\n");
  } else {
    char e[256];
    sprintf(e, "Not Authenticated:  %d\n", retval);
    print_error(e);
  }

  // close PAM (end session)
  if (pam_end(pamh, retval) != PAM_SUCCESS) {
    pamh = NULL;
    printf("Check_user: failed to release authenticator\n");
  }

  remove_pam_service_file();

  if (retval == PAM_SUCCESS) {
    print_success("test_valid_auth");
  }
  return retval;
}