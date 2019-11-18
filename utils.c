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

void read_configuration(char *base_url, char *app, char *pwd) 
{
    char buffer[1024];
    FILE* fp = fopen(CFG_FILE, "r");

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
                strtrimcpy(value, base_url);
            }
            else if(strcmp(key, CFG_CROWD_APP) == 0) 
            {
                strtrimcpy(value, app);
            }
            else if(strcmp(key, CFG_CROWD_PWD) == 0) 
            {
                strtrimcpy(value, pwd);
            }
        }
    }
}