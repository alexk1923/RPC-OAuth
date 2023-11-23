#ifndef SERVER_DB_H
#define SERVER_DB_H

#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

extern vector<string> dbUsers;
extern vector<string> dbResources;
extern vector<unordered_map<string, string>> dbAllPermissionsList;
extern int tokenLifetime;
extern unordered_map<string, e_approval_status> dbAuthTokenApprovals;
extern unordered_map<string, unordered_map<string, string>> dbTokenPermissions;
extern unordered_map<string, access_token_struct> dbUsersAccessTokens;
void print_all_perms();
void print_users_access_tokens();

#endif