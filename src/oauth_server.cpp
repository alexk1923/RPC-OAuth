#include "oauth.h"
#include <stdio.h>

#include "oauth.h"
#include "serverdb.h"
#include <iostream>

char **auth_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;
	// Check the existance of the user in db
	for (auto element : dbUsers) {
		cout << element << " ";
	}

	cout << "ResourceS:" << endl;
	for (auto element : dbResources) {
		cout << element << " ";
	}
	printf("\n");

	cout << "Permissions:" << endl;
	for (auto perm : dbResourceMap) {
		cout << perm.first << ":" << perm.second << " ";
	}
	printf("\n");

	cout << token_lifetime;
	printf("\n");

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