#ifndef PAM_CROWD_AUTH
#define PAM_CROWD_AUTH

#define CROWD_AUTH_URL "http://<crowd_base_url>/crowd/rest/usermanagement/1/authentication?username=%s"
#define CROWD_AUTH_BODY "{\"value\": \"%s\"}"

#endif