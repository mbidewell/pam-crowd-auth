#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

char* strtrimcpy(char *src, char *dest)
{
    size_t size;
    char *end;
    char * s = src;
    int strip_len;

    size = strlen(src);

    if (size > 0)
    {
        int i = 0;
        end = s + size - 1;
        while (end >= s && isspace(*end))
            end--;

        while (*s && isspace(*s))
            s++;

        strip_len = (int)(end - s);    

        if(strip_len > 0)
        {
            strncpy(dest, s, strip_len+1);
            dest[strip_len+1] = '\0';

            return dest;
        }
    }

    return NULL;
}

void read_configuration(struct crowd_config *cfg) 
{
    char buffer[1024];
    FILE* fp = fopen(CFG_FILE, "r");

    cfg->client_cert[0] = '\0';
    cfg->client_cert_key[0] = '\0';
    cfg->client_cert_pwd[0] = '\0';

    strcpy(cfg->client_cert_type, "PEM");

    while(fgets(buffer, 1024, fp) != NULL) 
    {
        char *tokptr;
        char key[30];
        char *value;

        if(strtrimcpy(strtok_r(buffer, "=", &tokptr), key) != NULL)
        {
            value = strtok_r(NULL, "=", &tokptr);
            
            if(strcmp(key, CFG_CROWD_BASE) == 0) 
            {
                int end = -1;

                strtrimcpy(value, cfg->base_url);
		
		end = strlen(cfg->base_url)-1;
                if(cfg->base_url[end] = '/') 
                {
                    cfg->base_url[end] = '\0';
                }

            }
            else if(strcmp(key, CFG_CROWD_APP) == 0) 
            {
                strtrimcpy(value, cfg->application);
            }
            else if(strcmp(key, CFG_CROWD_PWD) == 0) 
            {
                strtrimcpy(value, cfg->password);
            }
            else if(strcmp(key, CFG_CLIENT_CERT) == 0) 
            {
                strtrimcpy(value, cfg->client_cert);
            }
            else if(strcmp(key, CFG_CLIENT_KEY) == 0) 
            {
                strtrimcpy(value, cfg->client_cert_key);
            }
            else if(strcmp(key, CFG_CLIENT_PWD) == 0) 
            {
                strtrimcpy(value, cfg->client_cert_pwd);
            }                        
            else if(strcmp(key, CFG_CLIENT_TYPE) == 0) 
            {
                strtrimcpy(value, cfg->client_cert_type);
            } 
        }
    }
}
