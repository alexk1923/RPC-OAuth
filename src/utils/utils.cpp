#include "utils.h"
#include <iostream>
using namespace std;

void printClientOperation(operation *op) {
	cout << "Operation structure:" << endl;
	cout << op->user_id << endl;
	cout << op->operation_type << endl;
	cout << op->automatic_refresh << endl;
	if (!op->resource) {
		cout << "No resource" << endl;
	} else {
		cout << op->resource << endl;
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
		cout << "Invalid type of operation!";
	}
	return op_type;
}