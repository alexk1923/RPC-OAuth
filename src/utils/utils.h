#pragma once
#include "../oauth.h"
#include <string>
using namespace std;

typedef struct {
	char *user_id;
	e_operation_type operation_type;
	char *resource;
	int automatic_refresh;
} operation;

void printClientOperation(operation *op);
e_operation_type string_to_operation_type(string str);