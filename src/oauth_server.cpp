#include "oauth.h"
#include "serverdb.h"
#include "token.h"
#include "utils/utils.h"
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>

char **auth_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;
	// Check the existance of the user in db
	char *userId = *argp;

	cout << "BEGIN " << userId << " AUTHZ" << endl;
	bool found = false;
	for (auto element : dbUsers) {
		if (element == userId) {
			// Generate Access Token
			result = generate_access_token(userId);
			cout << "  RequestToken = " << result << endl;
			found = true;
		}
	}

	if (!found) {
		result = res_code_to_str[USER_NOT_FOUND];
	}
	return &result;
}

acces_token_struct *access_1_svc(access_token_req *argp,
								 struct svc_req *rqstp) {
	static acces_token_struct result;
	// cout << "Se incearca acces de la userul" << argp->user_id
	// 	 << " cu token:" << argp->auth_token << endl;
	char *auth_token = argp->auth_token;

	// for (auto m : dbTokenApprovals) {
	// 	cout << m.first << ":" << m.second << endl;
	// }

	// Check if token is valid
	if (dbTokenApprovals.count(auth_token) > 0 &&
		dbTokenApprovals.at(auth_token) == SIGNED) {
		result.access_token = generate_access_token(auth_token);
		// Check if user has auto_refresh enabled
		if (argp->auto_refresh) {
			result.refresh_token = generate_access_token(result.access_token);
		} else {
			result.refresh_token = "";
		}
		result.valability = tokenLifetime;

		// Add the perms for the new authentication token
		if (dbTokenPerms.count(auth_token)) {
			dbTokenPerms.insert(
				make_pair(result.access_token, dbTokenPerms[auth_token]));
		}

		// Set or update the user access token in the server db
		if (dbUsersAccessTokens.count(argp->user_id)) {
			dbUsersAccessTokens[argp->user_id] = result;
		} else {
			dbUsersAccessTokens.insert(make_pair(argp->user_id, result));
		}
	} else {
		result.access_token = res_code_to_str[REQUEST_DENIED];
		result.access_token = res_code_to_str[REQUEST_DENIED];
		result.valability = -1;
	}

	// print_all_perms();

	// If it is NOT a REQUEST DENIED error code
	if (strcmp(result.access_token, res_code_to_str[REQUEST_DENIED])) {
		cout << "  AccessToken = " << result.access_token << endl;
	}
	return &result;
}

char **validate_action_1_svc(action_req *argp, struct svc_req *rqstp) {
	static char *result;

	/*
	 * insert server code here
	 */
	for (auto userAccessToken : dbUsersAccessTokens) {
		cout << "user:" << userAccessToken.first
			 << " cu token:" << userAccessToken.second.access_token << endl;
		if (userAccessToken.second.access_token ==
			argp->access_token.access_token) {
			cout << "Bai frate, am gasit tokenul asta in baza de date, esti "
					"prosti?"
				 << argp->access_token.access_token << endl;
		}
	}

	cout << endl;

	return &result;
}

char **approve_req_token_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;
	// Add resource permissions to the token
	char *auth_token = *argp;
	// Add permissions
	if (!dbResPermsVector.empty()) {
		// Get the perms for current request and add (auth_token, perms) into
		// the database
		unordered_map<string, string> resourcesPerms = dbResPermsVector.back();
		dbResPermsVector.pop_back();
		result = auth_token;

		if (resourcesPerms["*"] == "-") {
			// cout << "Nu a aprobat permisiunile" << endl;
			return &result;
		}

		dbTokenPerms.insert(make_pair(auth_token, resourcesPerms));

		// The user does not approve permissions

		strcat(result, ".SIGNED");
		dbTokenApprovals.insert(make_pair(auth_token, SIGNED));

	} else {
		cout << "Resource file is empty" << endl;
	}
	return &result;
}