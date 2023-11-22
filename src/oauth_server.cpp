#include "oauth.h"
#include "serverdb.h"
#include "token.h"
#include "utils/utils.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>

bool check_permission(string list_of_permissions,
					  e_operation_type operation_type) {
	return list_of_permissions.find(operation_to_char[operation_type]) <
		   list_of_permissions.length();
}

void print_token_perms() {
	for (auto tknPerm : dbTokenPermissions) {
		cout << "Token: ";
		cout << tknPerm.first << " " << endl;
		for (auto perm : tknPerm.second) {
			cout << perm.first << ":" << perm.second << endl;
		}
		cout << "++++++++++++++" << endl;
	}
}

void print_all_access_user_access_tokens() {
	for (auto userAccessToken : dbUsersAccessTokens) {
		cout << "user:" << userAccessToken.first
			 << " cu token:" << userAccessToken.second.access_token << endl;
	}
}

void print_status(char *status, char *operation, char *resource,
				  char *access_token, int valability) {
	cout << status << " (" << operation << "," << resource << ","
		 << access_token << "," << valability << ")" << endl;
}

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

		const char delimeter[] = ".";
		char *original_auth_token = strtok(auth_token, delimeter);
		// Add the perms for the new access token
		if (dbTokenPermissions.count(original_auth_token)) {
			dbTokenPermissions.insert(make_pair(
				result.access_token, dbTokenPermissions[original_auth_token]));
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

	// cout << "Trying to validate action " << operation_to_str[argp->operation]
	// 	 << "for token: " << argp->access_token << endl;

	// cout << "Existing tokens:" << endl;

	// Check if the access token is in the database
	string found_user;
	for (auto userAccessToken : dbUsersAccessTokens) {
		if (strcmp(userAccessToken.second.access_token, argp->access_token) ==
			0) {
			found_user = userAccessToken.first;
			break;
		}
	}

	print_all_access_user_access_tokens();

	if (found_user == "") {
		print_status("DENY", operation_to_str[argp->operation], argp->resource,
					 argp->access_token, 0);
		result = res_code_to_str[PERMISSION_DENIED];
		return &result;
	}

	// Check if token is expired
	if (dbUsersAccessTokens[found_user].valability <= 0) {

		if (dbUsersAccessTokens[found_user].refresh_token == "") {
			print_status("DENY", operation_to_str[argp->operation],
						 argp->resource, "",
						 dbUsersAccessTokens[found_user].valability);

			result = res_code_to_str[TOKEN_EXPIRED];
			return &result;
		} else {
			cout << "BEGIN " << found_user << " AUTHZ REFRESH " << endl;
			char *new_access_token = generate_access_token(
				dbUsersAccessTokens[found_user].refresh_token);
			dbUsersAccessTokens[found_user].access_token = new_access_token;
			dbUsersAccessTokens[found_user].refresh_token =
				generate_access_token(new_access_token);
			dbUsersAccessTokens[found_user].valability = tokenLifetime;
			argp->access_token = new_access_token;
			cout << "  Access Token = " << new_access_token << endl;
			cout << " Refresh Token = "
				 << dbUsersAccessTokens[found_user].refresh_token << endl;
		}
	}

	dbUsersAccessTokens[found_user].valability--;

	// Search for the resource
	// Add the perms for the new access token
	// Search for the token and the specific resource
	// print_token_perms();
	string resource_string(argp->resource);

	std::vector<string>::iterator it =
		find(dbResources.begin(), dbResources.end(), resource_string);

	if (it == dbResources.end()) {
		print_status("DENY", operation_to_str[argp->operation], argp->resource,
					 argp->access_token,
					 dbUsersAccessTokens[found_user].valability);
		result = res_code_to_str[RESOURCE_NOT_FOUND];
		return &result;
	}

	if (dbTokenPermissions.count(argp->access_token) == 0 ||
		dbTokenPermissions.at(argp->access_token).count(argp->resource) == 0 ||
		!check_permission(
			dbTokenPermissions.at(argp->access_token).at(argp->resource),
			argp->operation)) {
		print_status("DENY", operation_to_str[argp->operation], argp->resource,
					 argp->access_token,
					 dbUsersAccessTokens[found_user].valability);
		result = res_code_to_str[OPERATION_NOT_PERMITTED];
		return &result;
	}

	// if (dbTokenPermissions.count(argp->access_token) == 0 ||
	// 	dbTokenPermissions.at(argp->access_token).count(argp->resource) == 0 ||
	// 	!check_permission(
	// 		dbTokenPermissions.at(argp->access_token).at(argp->resource),
	// 		argp->operation)) {
	// 	cout << "Operatia nu e permisa" << endl << endl;
	// 	;
	// 	result = res_code_to_str[OPERATION_NOT_PERMITTED];
	// 	return &result;
	// }

	print_status("PERMIT", operation_to_str[argp->operation], argp->resource,
				 argp->access_token,
				 dbUsersAccessTokens[found_user].valability);

	result = res_code_to_str[PERMISSION_GRANTED];

	return &result;
}

char **approve_req_token_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;
	// Add resource permissions to the token
	char *auth_token = *argp;
	// Add permissions
	if (!dbAllPermissionsList.empty()) {
		// Get the perms for current request and add (auth_token, perms) into
		// the database
		unordered_map<string, string> resourcesPerms =
			dbAllPermissionsList.back();
		dbAllPermissionsList.pop_back();
		result = auth_token;

		if (resourcesPerms.count("*") > 0 && resourcesPerms.at("*") == "-") {
			// cout << "Nu a aprobat permisiunile" << endl;
			return &result;
		}

		dbTokenPermissions.insert(make_pair(auth_token, resourcesPerms));

		// The user does not approve permissions

		strcat(result, ".SIGNED");
		dbTokenApprovals.insert(make_pair(auth_token, SIGNED));

	} else {
		cout << "Resource file is empty" << endl;
	}
	return &result;
}