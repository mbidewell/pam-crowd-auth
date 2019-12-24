#ifndef UTILS_H
#define UTILS_H

#define CFG_CROWD_BASE "crowd_base_url"
#define CFG_CROWD_APP "crowd_app"
#define CFG_CROWD_PWD "crowd_pwd"
#define CFG_CLIENT_CERT "client_cert_file"
#define CFG_CLIENT_KEY "client_key_file"
#define CFG_CLIENT_PWD "client_key_pwd"
#define CFG_CLIENT_TYPE "client_key_type"
#define CFG_FILE "/etc/pam_crowd_auth.conf"

struct crowd_config
{
    char base_url[100];
    char application[30];
    char password[30];
    char client_cert[100];
    char client_cert_key[100];
    char client_cert_pwd[30];
    char client_cert_type[5];
};

char* strtrimcpy(char *src, char *dest);
void read_configuration(struct crowd_config *cfg);

#endif