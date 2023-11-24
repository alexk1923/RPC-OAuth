#ifndef SERVER_DB_H
#define SERVER_DB_H

#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

/* All users IDs got from the input */
extern vector<string> dbUsers;

/* Valid resources names */
extern vector<string> dbResources;

/* List of permissions, in order, for each request
 * key: resource name
 * value: permissions (abbreviation form)
 */
extern vector<unordered_map<string, string>> dbAllPermissionsList;

/* Time before a token expires (meassured in no. of requests) */
extern int tokenLifetime;

/* Status of approval/denial from the user for all authentication tokens
 * key: token
 * value: 0 for NOT_SIGNED, 1 for SIGNED
 */
extern unordered_map<string, e_approval_status> dbAuthTokenApprovals;

/* Pairing of tokens and their corresponding permissions
 * key: auth/access token
 * value: map of permissions
 */
extern unordered_map<string, unordered_map<string, string>> dbTokenPermissions;
extern unordered_map<string, access_token_struct> dbUsersAccessTokens;
void print_all_perms();
void print_users_access_tokens();

#endif