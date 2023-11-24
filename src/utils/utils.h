#pragma once
#include "../oauth.h"
#include <string>
using namespace std;

typedef struct {
	char *user_id;
	char *operation_type;
	char *resource;
	int automatic_refresh;
} operation;

void printClientOperation(operation *op);
e_operation_type string_to_operation_type(string str);
extern char *const res_code_to_str[];
extern char *const operation_to_str[];
extern char *const operation_to_char[];