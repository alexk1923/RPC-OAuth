#include "oauth.h"
#include "serverdb.h"
#include "token.h"
#include "utils/utils.h"
#include <iostream>
#include <stdio.h>

char **auth_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;
	// Check the existance of the user in db
	char *userId = *argp;
	cout << "My user:" << userId << endl;

	bool found = false;
	for (auto element : dbUsers) {
		if (element == userId) {
			cout << "Am gasit user-ul in database si generez token-ul" << endl;
			// Generate Access Token
			result = generate_access_token(userId);
			cout << "Result:" << result << endl;
			found = true;
		}
	}
	if (!found) {
		result = res_code_to_str[USER_NOT_FOUND];
	}
	cout << endl;

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
	// Add resource permissions to the token

	return &result;
}