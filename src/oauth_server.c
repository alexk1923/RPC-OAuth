/*
 * This is sample code generated by rpcgen.
 * These are only templates and you can use them
 * as a guideline for developing your own functions.
 */

#include "oauth.h"

char **authorization_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;

	/*
	 * insert server code here
	 */

	return &result;
}

acces_token_struct *access_1_svc(access_token_req *argp,
								 struct svc_req *rqstp) {
	static acces_token_struct result;

	/*
	 * insert server code here
	 */

	return &result;
}

char **validate_action_1_svc(action_req *argp, struct svc_req *rqstp) {
	static char *result;

	/*
	 * insert server code here
	 */

	return &result;
}

auth_token_struct *approve_req_token_1_svc(auth_token_struct *argp,
										   struct svc_req *rqstp) {
	static auth_token_struct result;

	/*
	 * insert server code here
	 */

	return &result;
}
