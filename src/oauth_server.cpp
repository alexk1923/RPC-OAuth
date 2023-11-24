#include "oauth.h"
#include "serverdb.h"
#include "token.h"
#include "utils/constants/constants.h"
#include "utils/utils.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string.h>

/**
 * Client request for authentication token
 *
 * @param list_of_permissions List of permissions in abbv form
 * @param operation_type Desired operation
 * @return true if the operation is allowed on the resource, false otherwise
 */
bool check_permission(string list_of_permissions,
					  e_operation_type operation_type) {

	if (operation_type == INVALID) {
		return false;
	}
	return list_of_permissions.find(operation_to_char[operation_type]) <
		   list_of_permissions.length();
}

/**
 * Client request for authentication token
 *
 * @param status Status of the action
 * @param operation Opereation
 * @param resource Accessed Resource
 * @param access_token Access Token
 * @param remaining_requests Token Reamining Usage
 */
void print_status(string status, char *operation, char *resource,
				  char *access_token, int remaining_requests) {
	cout << status << " (" << operation << "," << resource << ","
		 << access_token << "," << remaining_requests << ")" << endl;
}

/**
 * Client request for authentication token
 *
 * @param argp Address of the user id
 * @param rqstp Server request information
 * @return a new authentication (request) token or USER_NOT_FOUND
 */
char **auth_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;
	// Check the existance of the user in db
	char *user_id = *argp;
	cout << "BEGIN " << user_id << " AUTHZ" << endl;
	bool found = false;
	for (auto element : dbUsers) {
		// Generate token if user is in the database
		if (element == user_id) {
			// Generate RequestToken
			result = generate_access_token(user_id);
			cout << "  RequestToken = " << result << endl;
			found = true;
			break;
		}
	}

	// User has not been found in the database, return an error message
	if (!found) {
		result = const_cast<char *>(res_code_to_str[USER_NOT_FOUND]);
	}
	return &result;
}

/**
 * Client request for access token
 *
 * @param argp Access Token Request structure containing user id, auth token and
 * auto-refresh option value
 * @param rqstp Server request information
 * @return Access Token structure / REQUEST_DENIED /
 */
access_token_struct *access_1_svc(access_token_req *argp,
								  struct svc_req *rqstp) {
	static access_token_struct result;
	char *auth_token = argp->auth_token;

	// Check if token is valid (it does exist in the db and has been signed
	// after user confirming permissions)
	if (dbAuthTokenApprovals.count(auth_token) > 0 &&
		dbAuthTokenApprovals.at(auth_token) == SIGNED) {
		result.access_token = generate_access_token(auth_token);

		// Generate a refresh token if auto refresh option is enabled
		if (argp->auto_refresh) {
			result.refresh_token = generate_access_token(result.access_token);
		} else {
			result.refresh_token = const_cast<char *>(EMPTY_STR);
		}
		result.valability = tokenLifetime;

		// Get the original token, without the signature
		const char delimeter[] = ".";
		char *original_auth_token = strtok(auth_token, delimeter);

		// Copy the perms from auth token to the new access token
		dbTokenPermissions[result.access_token] =
			dbTokenPermissions[original_auth_token];

		// Set or update the user access token in the server db
		dbUsersAccessTokens[argp->user_id] = result;

	} else {
		// Auth Token not found or permissions not approved by the user
		result.access_token =
			const_cast<char *>(res_code_to_str[REQUEST_DENIED]);
		result.access_token =
			const_cast<char *>(res_code_to_str[REQUEST_DENIED]);
		result.valability = -1;
	}

	// Log the new access token and refresh token, if the case
	if (strcmp(result.access_token, res_code_to_str[REQUEST_DENIED])) {
		cout << "  AccessToken = " << result.access_token << endl;
		if (argp->auto_refresh == 1) {
			cout << "  RefreshToken = " << result.refresh_token << endl;
		}
	}
	return &result;
}

/**
 * Client request to validate an action
 *
 * @param argp Request data: operation to be performed, resource to access,
 * access token
 * @param rqstp Server request information
 *  @return Returns one of the following status codes:
 *   - PERMISSION_GRANTED: The action was validated successfully.
 *   - RESOURCE_NOT_FOUND: The requested resource was not found.
 *   - OPERATION_NOT_PERMITTED: The requested operation is not permitted.
 *   - TOKEN_EXPIRED: The authentication token has expired.
 *   - PERMISSION_DENIED: The request was denied.
 */
char **validate_action_1_svc(action_req *argp, struct svc_req *rqstp) {
	static char *result;

	// Check if there is a user having the corresponding token in the database
	string found_user;
	for (auto userAccessToken : dbUsersAccessTokens) {
		if (strcmp(userAccessToken.second.access_token, argp->access_token) ==
			0) {
			found_user = userAccessToken.first;
			break;
		}
	}

	// There is no user having the provided access token
	if (found_user == "") {
		print_status(DENY_MESSAGE, argp->operation, argp->resource,
					 argp->access_token, 0);
		result = const_cast<char *>(res_code_to_str[PERMISSION_DENIED]);
		return &result;
	}

	// Check if token is expired
	if (dbUsersAccessTokens[found_user].valability <= 0) {
		if (strcmp(dbUsersAccessTokens[found_user].refresh_token, EMPTY_STR) ==
			0) {
			print_status(DENY_MESSAGE, argp->operation, argp->resource,
						 const_cast<char *>(EMPTY_STR),
						 dbUsersAccessTokens[found_user].valability);

			result = const_cast<char *>(res_code_to_str[TOKEN_EXPIRED]);
			return &result;
		}
	}

	// Decrease remaining requests associated with the token
	dbUsersAccessTokens[found_user].valability--;

	// Check if the resource is valid
	if (find(dbResources.begin(), dbResources.end(), argp->resource) ==
		dbResources.end()) {
		print_status(DENY_MESSAGE, argp->operation, argp->resource,
					 argp->access_token,
					 dbUsersAccessTokens[found_user].valability);
		result = const_cast<char *>(res_code_to_str[RESOURCE_NOT_FOUND]);
		return &result;
	}

	// Check if the requested operation is permitted by the user owning the
	// access token
	if (dbTokenPermissions.count(argp->access_token) == 0 ||
		dbTokenPermissions.at(argp->access_token).count(argp->resource) == 0 ||
		!check_permission(
			dbTokenPermissions.at(argp->access_token).at(argp->resource),
			string_to_operation_type(argp->operation))) {
		print_status(DENY_MESSAGE, argp->operation, argp->resource,
					 argp->access_token,
					 dbUsersAccessTokens[found_user].valability);
		result = const_cast<char *>(res_code_to_str[OPERATION_NOT_PERMITTED]);
		return &result;
	}

	// All conditions have been fulfilled, the action is valid
	print_status(PERMIT_MESSAGE, argp->operation, argp->resource,
				 argp->access_token,
				 dbUsersAccessTokens[found_user].valability);

	result = const_cast<char *>(res_code_to_str[PERMISSION_GRANTED]);
	return &result;
}

/**
 * Sign the auth token and associate the user permissions
 *
 * @param argp Authentication token passed as a string
 * @param rqstp Server request information
 * @return Returns [AUTH_TOKEN].SIGNED if the user accepts the permissions,
 * unmodified AUTH_TOKEN otherwise
 */
char **approve_req_token_1_svc(char **argp, struct svc_req *rqstp) {
	static char *result;
	char *auth_token = *argp;
	result = auth_token;
	// Add permissions
	if (!dbAllPermissionsList.empty()) {
		// Get the perms for current request
		unordered_map<string, string> resourcesPerms =
			dbAllPermissionsList.back();
		dbAllPermissionsList.pop_back();

		// The user does not approve permissions
		if (resourcesPerms.count("*") > 0 && resourcesPerms.at("*") == "-") {
			return &result;
		}

		// Add permissions to the database
		dbTokenPermissions.insert(make_pair(auth_token, resourcesPerms));

		// Mark the auth token as signed
		strcat(result, ".SIGNED");
		dbAuthTokenApprovals.insert(make_pair(auth_token, SIGNED));

	} else {
		cout << "Resource file is empty" << endl;
	}
	return &result;
}

/**
 * Refresh Access Token
 *
 * @param argp Current Access Token structure
 * @param rqstp Server request information
 * @return Returns a new structure after the refresh
 */
access_token_struct *refresh_access_1_svc(access_token_struct *argp,
										  struct svc_req *rqstp) {
	// Generate new tokens
	static access_token_struct result;

	// Check if the user is valid
	string found_user;
	for (auto userAccessToken : dbUsersAccessTokens) {
		if (strcmp(userAccessToken.second.access_token, argp->access_token) ==
			0) {
			found_user = userAccessToken.first;
			break;
		}
	}

	cout << "BEGIN " << found_user << " AUTHZ REFRESH" << endl;
	char *new_access_token = generate_access_token(argp->refresh_token);
	char *new_refresh_token = generate_access_token(new_access_token);

	result.access_token = new_access_token;
	result.refresh_token = new_refresh_token;
	result.valability = tokenLifetime;
	cout << "  AccessToken = " << result.access_token << endl;
	cout << "  RefreshToken = " << result.refresh_token << endl;

	// Update user:token in the database
	dbUsersAccessTokens[found_user] = result;

	// Update permissions for the new access token
	dbTokenPermissions[result.access_token] =
		dbTokenPermissions[argp->access_token];

	return &result;
}