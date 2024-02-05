// utils.h
#ifndef UTILS_H
#define UTILS_H

#define FILE_PATH_MAX 128
#define RED_TEXT "\x1b[31m"
#define GREEN_TEXT "\x1b[32m"
#define RESET_TEXT "\x1b[0m"

extern char SRV_DIR[];
extern char PAM_SRV[];
extern struct pam_conv conv;

int create_pam_service_file(const char *srv_content);
int remove_pam_service_file();
int clear_tally_dir();
void print_error(const char *message);
void print_success(const char *message);

#endif // UTILS_H