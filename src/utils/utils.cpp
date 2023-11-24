#include "utils.h"
#include <iostream>
using namespace std;

char *const operation_to_str[] = {
	[REQUEST] = "REQUEST", [READ] = "READ",		[INSERT] = "INSERT",
	[MODIFY] = "MODIFY",   [DELETE] = "DELETE", [EXECUTE] = "EXECUTE"};

char *const operation_to_char[] = {
	[REQUEST] = "", [READ] = "R",	[INSERT] = "I",
	[MODIFY] = "M", [DELETE] = "D", [EXECUTE] = "X"};

void printClientOperation(operation *op) {
	cout << "--------------------------------" << endl;
	cout << "UserId:" << op->user_id << endl;
	cout << "Operatie incercata:" << op->operation_type << endl;
	cout << "Auto refresh enabled:" << op->automatic_refresh << endl;

	if (!op->resource) {
		cout << "Nu se incearca accesarea niciunei resurse" << endl;
	} else {
		cout << "Se incearca sa se acceseze resursa:" << op->resource << endl;
	}

	cout << endl;
}

e_operation_type string_to_operation_type(string str) {
	e_operation_type op_type;
	if (str == "REQUEST") {
		op_type = REQUEST;
	} else if (str == "READ") {
		op_type = READ;
	} else if (str == "INSERT") {
		op_type = INSERT;
	} else if (str == "MODIFY") {
		op_type = MODIFY;
	} else if (str == "DELETE") {
		op_type = DELETE;
	} else if (str == "EXECUTE") {
		op_type = EXECUTE;
	} else {
		op_type = INVALID;
	}
	return op_type;
}

typedef enum e_res_code e_res_code;

char *const res_code_to_str[] = {
	[USER_NOT_FOUND] = "USER_NOT_FOUND",
	[REQUEST_DENIED] = "REQUEST_DENIED",
	[PERMISSION_DENIED] = "PERMISSION_DENIED",
	[TOKEN_EXPIRED] = "TOKEN_EXPIRED",
	[RESOURCE_NOT_FOUND] = "RESOURCE_NOT_FOUND",
	[OPERATION_NOT_PERMITTED] = "OPERATION_NOT_PERMITTED",
	[PERMISSION_GRANTED] = "PERMISSION_GRANTED",
};

char *const approval_status_to_str[] = {
	[SIGNED] = "SIGNED",
	[NOT_SIGNED] = "NOT_SIGNED",
};
