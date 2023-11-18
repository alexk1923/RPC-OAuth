#ifndef SERVER_DB_H
#define SERVER_DB_H

#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

extern vector<string> dbUsers;
extern vector<string> dbResources;
extern unordered_map<string, string> dbResourceMap;
extern int token_lifetime;
#endif