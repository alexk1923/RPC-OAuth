#ifndef CLIENT_DB_H
#define CLIENT_DB_H

#include "oauth.h"
#include <unordered_map>
using namespace std;

extern unordered_map<string, access_token_struct> clientsTokens;

#endif