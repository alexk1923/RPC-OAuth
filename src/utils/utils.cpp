#include "utils.h"
#include "constants/constants.h"
#include <iostream>
using namespace std;

const char *const operation_to_str[] = {
	[REQUEST] = REQUEST_STR, [READ] = READ_STR,		[INSERT] = INSERT_STR,
	[MODIFY] = MODIFY_STR,	 [DELETE] = DELETE_STR, [EXECUTE] = EXECUTE_STR};

const char *const operation_to_char[] = {
	[REQUEST] = EMPTY_STR,	[READ] = READ_ABBV,		[INSERT] = INSERT_ABBV,
	[MODIFY] = MODIFY_ABBV, [DELETE] = DELETE_ABBV, [EXECUTE] = EXECUTE_ABBV};

e_operation_type string_to_operation_type(string str) {
	e_operation_type op_type;
	if (str == REQUEST_STR) {
		op_type = REQUEST;
	} else if (str == READ_STR) {
		op_type = READ;
	} else if (str == INSERT_STR) {
		op_type = INSERT;
	} else if (str == MODIFY_STR) {
		op_type = MODIFY;
	} else if (str == DELETE_STR) {
		op_type = DELETE;
	} else if (str == EXECUTE_STR) {
		op_type = EXECUTE;
	} else {
		op_type = INVALID;
	}
	return op_type;
}

typedef enum e_res_code e_res_code;

const char *const res_code_to_str[] = {
	[USER_NOT_FOUND] = USER_NOT_FOUND_STATUS,
	[REQUEST_DENIED] = REQUEST_DENIED_STATUS,
	[PERMISSION_DENIED] = PERMISSION_DENIED_STATUS,
	[TOKEN_EXPIRED] = TOKEN_EXPIRED_STATUS,
	[RESOURCE_NOT_FOUND] = RESOURCE_NOT_FOUND_STATUS,
	[OPERATION_NOT_PERMITTED] = OPERATION_NOT_PERMITTED_STATUS,
	[PERMISSION_GRANTED] = PERMISSION_GRANTED_STATUS,
};
