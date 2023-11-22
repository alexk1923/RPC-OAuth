#include "oauth.h"
#include <unordered_map>
using namespace std;

unordered_map<string, access_token_struct *> clientsTokens;