/*
 * Copyright Alexander O. Yuriev, 1996.  All rights reserved.
 * NIS+ support by Thorsten Kukuk <kukuk@weber.uni-paderborn.de>
 * Copyright Jan Rękorajski, 1999.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>

/* indicate the following groups are defined */

#define PAM_SM_AUTH

#define _PAM_EXTERN_FUNCTIONS
#include <security/_pam_macros.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <curl/curl.h>

#include "pam_crowd_auth.h"
#include "utils.h"

/*
 * PAM framework looks for these entry-points to pass control to the
 * authentication module.
 */

/* Fun starts here :)

 * pam_sm_authenticate() performs UNIX/shadow authentication
 *
 *      First, if shadow support is available, attempt to perform
 *      authentication using shadow passwords. If shadow is not
 *      available, or user does not have a shadow password, fallback
 *      onto a normal UNIX authentication
 */

static size_t _curl_payload_handler(void *buffer, size_t size, size_t nmemb, void *userp)
{
   return size * nmemb;
}

static int _crowd_auth(const char *user, const char *pwd, pam_handle_t *pamh)
{
	char msg_buf[255];

	CURL *curl;
	CURLcode res;

	int pam_response = PAM_USER_UNKNOWN;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if (curl)
	{
		char crowd_base_url[100];
		char crowd_application[30];
		char crowd_password[30];
		struct curl_slist *hs = NULL;
		char *auth_url = NULL;
		char *pwd_payload = NULL;

		auth_url = malloc(strlen(crowd_base_url) + strlen(CROWD_AUTH_URL) + strlen(user) + 1);
		pwd_payload = malloc(strlen(CROWD_AUTH_BODY) + strlen(pwd) + 1);
		
		hs = curl_slist_append(hs, "Content-Type: application/json");

		sprintf(auth_url, CROWD_AUTH_URL, crowd_base_url, user);
		sprintf(pwd_payload, CROWD_AUTH_BODY, pwd);

		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hs);
		curl_easy_setopt(curl, CURLOPT_USERNAME, crowd_application);
		curl_easy_setopt(curl, CURLOPT_PASSWORD, crowd_password);
		curl_easy_setopt(curl, CURLOPT_URL, auth_url);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, pwd_payload);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_payload_handler);

		pam_syslog(pamh, LOG_INFO, auth_url);
		
		res = curl_easy_perform(curl);
		sprintf(msg_buf, "Error Code: %d", res);
		pam_syslog(pamh, LOG_INFO, msg_buf);
		if (res == CURLE_OK)
		{
			long http_code;
			curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
			sprintf(msg_buf, "HTTP Status: %d for %s", http_code, user);
			pam_syslog(pamh, LOG_INFO, msg_buf);

			if (http_code == 200)
			{
				pam_response = PAM_SUCCESS;
			}
		}
		curl_easy_cleanup(curl);

		free(auth_url);
		free(pwd_payload);
	}
	curl_global_cleanup();

	sprintf(msg_buf, "Finished Crowd Auth for %s,  pam_response=%d", user, pam_response);
	pam_syslog(pamh, LOG_INFO, msg_buf);
	return pam_response;
}

PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
	int retval, *ret_data = NULL;
	const char *name;
	const char *p;

	D(("called."));

	/* get the user'name' */

	retval = pam_get_user(pamh, &name, NULL);
	if (retval == PAM_SUCCESS)
	{
		/*
		 * Various libraries at various times have had bugs related to
		 * '+' or '-' as the first character of a user name. Don't
		 * allow this characters here.
		 */
		if (name == NULL || name[0] == '-' || name[0] == '+')
		{
			pam_syslog(pamh, LOG_ERR, "bad username [%s]", name);
			return PAM_USER_UNKNOWN;
		}
	}
	else
	{
		if (retval == PAM_CONV_AGAIN)
		{
			D(("pam_get_user/conv() function is not ready yet"));
			/* it is safe to resume this function so we translate this
			 * retval to the value that indicates we're happy to resume.
			 */
			retval = PAM_INCOMPLETE;
		}

		return retval;
	}

	/* get this user's authentication token */

	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &p, NULL);
	if (retval != PAM_SUCCESS)
	{
		if (retval != PAM_CONV_AGAIN)
		{
			pam_syslog(pamh, LOG_CRIT,
					   "auth could not identify password for [%s]", name);
		}
		else
		{
			D(("conversation function is not ready yet"));
			/*
			 * it is safe to resume this function so we translate this
			 * retval to the value that indicates we're happy to resume.
			 */
			retval = PAM_INCOMPLETE;
		}
		name = NULL;
		return retval;
	}

	D(("user=%s, password=[%s]", name, p));

	/* verify the password of this user */
	retval = _crowd_auth(name, p, pamh);
	
	name = p = NULL;

	return retval;
}

/*
 * The only thing _pam_set_credentials_unix() does is initialization of
 * UNIX group IDs.
 *
 * Well, everybody but me on linux-pam is convinced that it should not
 * initialize group IDs, so I am not doing it but don't say that I haven't
 * warned you. -- AOY
 */

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh, int flags,
				   int argc, const char **argv)
{
	return PAM_CRED_ERR;
}
