#ifndef UTILS_H
#define UTILS_H

#define CFG_CROWD_BASE "crowd_base_url"
#define CFG_CROWD_APP "crowd_app"
#define CFG_CROWD_PWD "crowd_pwd"

#define CFG_FILE "/etc/pam_crowd_auth.conf"

char* strtrimcpy(char *src, char *dest);
void read_configuration(char *base_url, char *app, char *pwd);

#endif