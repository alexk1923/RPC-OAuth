#include "oauth.h"
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
using namespace std;

vector<string> dbUsers;
vector<string> dbResources;
vector<unordered_map<string, string>> dbAllPermissionsList;
int tokenLifetime;
unordered_map<string, unordered_map<string, string>> dbTokenPermissions;
unordered_map<string, e_approval_status> dbTokenApprovals;
unordered_map<string, acces_token_struct> dbUsersAccessTokens;

void print_all_perms() {
	cout << "Avem urmatoarele asocieri de permisiuni:" << endl;

	for (auto pair : dbTokenPermissions) {
		cout << "Pentru tokenul:" << pair.first << ":" << endl;
		for (auto perm : pair.second) {
			cout << perm.first << ":" << perm.second << endl;
		}
		cout << endl;
	}
}

void print_users_access_tokens() {
	cout << "Avem urmatoarele asocieri de tokenuri:" << endl;
	for (auto pair : dbUsersAccessTokens) {
		cout << pair.first << " are tokenul: " << pair.second.access_token
			 << endl;
	}
}