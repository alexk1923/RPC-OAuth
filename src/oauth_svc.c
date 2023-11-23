/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "oauth.h"
#include "serverdb.h"
#include <bits/stdc++.h>
#include <fstream>
#include <iostream>
#include <memory.h>
#include <netinet/in.h>
#include <rpc/pmap_clnt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
using namespace std;

#ifndef SIG_PF
#define SIG_PF void (*)(int)
#endif

static void authorization_1(struct svc_req *rqstp, register SVCXPRT *transp) {
	union {
		char *auth_1_arg;
		access_token_req access_1_arg;
		action_req validate_action_1_arg;
		char *approve_req_token_1_arg;
		access_token_struct refresh_access_1_arg;
	} argument;
	char *result;
	xdrproc_t _xdr_argument, _xdr_result;
	char *(*local)(char *, struct svc_req *);

	switch (rqstp->rq_proc) {
	case NULLPROC:
		(void)svc_sendreply(transp, (xdrproc_t)xdr_void, (char *)NULL);
		return;

	case auth:
		_xdr_argument = (xdrproc_t)xdr_wrapstring;
		_xdr_result = (xdrproc_t)xdr_wrapstring;
		local = (char *(*)(char *, struct svc_req *))auth_1_svc;
		break;

	case access:
		_xdr_argument = (xdrproc_t)xdr_access_token_req;
		_xdr_result = (xdrproc_t)xdr_access_token_struct;
		local = (char *(*)(char *, struct svc_req *))access_1_svc;
		break;

	case validate_action:
		_xdr_argument = (xdrproc_t)xdr_action_req;
		_xdr_result = (xdrproc_t)xdr_wrapstring;
		local = (char *(*)(char *, struct svc_req *))validate_action_1_svc;
		break;

	case approve_req_token:
		_xdr_argument = (xdrproc_t)xdr_wrapstring;
		_xdr_result = (xdrproc_t)xdr_wrapstring;
		local = (char *(*)(char *, struct svc_req *))approve_req_token_1_svc;
		break;

	case refresh_access:
		_xdr_argument = (xdrproc_t)xdr_access_token_struct;
		_xdr_result = (xdrproc_t)xdr_access_token_struct;
		local = (char *(*)(char *, struct svc_req *))refresh_access_1_svc;
		break;

	default:
		svcerr_noproc(transp);
		return;
	}
	memset((char *)&argument, 0, sizeof(argument));
	if (!svc_getargs(transp, (xdrproc_t)_xdr_argument, (caddr_t)&argument)) {
		svcerr_decode(transp);
		return;
	}
	result = (*local)((char *)&argument, rqstp);
	if (result != NULL &&
		!svc_sendreply(transp, (xdrproc_t)_xdr_result, result)) {
		svcerr_systemerr(transp);
	}
	if (!svc_freeargs(transp, (xdrproc_t)_xdr_argument, (caddr_t)&argument)) {
		fprintf(stderr, "%s", "unable to free arguments");
		exit(1);
	}
	return;
}

void read_users(ifstream &input_file) {
	string line;
	input_file >> line;
	int n = stoi(line);
	int i = 0;
	while (i < n) {
		input_file >> line;
		dbUsers.push_back(line);
		i++;
	}
}

void read_resources(ifstream &input_file) {
	string line;
	input_file >> line;
	int n = stoi(line);
	int i = 0;
	while (i < n) {
		input_file >> line;
		dbResources.push_back(line);
		i++;
	}
}

void process_line(string line, unordered_map<string, string> &newMap) {
	stringstream ss(line);
	int idx = 0;

	while (ss.good()) {
		string resource;
		string permissions;
		getline(ss, resource, ',');
		getline(ss, permissions, ',');

		// cout << "RESOURCE:" << resource << endl;
		// cout << "PERMISSIONS:" << permissions << endl;

		// File

		newMap.insert(make_pair(resource, permissions));

		idx++;
	}
}

void read_approvals(ifstream &input_file) {
	string line;
	int i = 0;
	while (input_file >> line) {
		unordered_map<string, string> newMap;
		process_line(line, newMap);

		dbAllPermissionsList.insert(dbAllPermissionsList.begin(), newMap);

		i++;
	}

	// Read permissions
	// for (auto currentMap : dbAllPermissionsList) {
	// 	for (auto perm : currentMap) {
	// 		cout << perm.first << ":" << perm.second << endl;
	// 	}
	// 	cout << "============\n\n\n\n\n\n\n";
	// }
}

int main(int argc, char **argv) {
	register SVCXPRT *transp;
	if (argc < 5) {
		printf("usage: %s <users_file> <resources_file> <approvals_file> "
			   "<token_lifetime>\n",
			   argv[0]);
		exit(1);
	}

	ifstream users_file(argv[1]);
	ifstream resources_file(argv[2]);
	ifstream approvals_file(argv[3]);
	tokenLifetime = stoi(argv[4]);

	read_users(users_file);
	read_resources(resources_file);
	read_approvals(approvals_file);

	pmap_unset(AUTHORIZATION, OAUTH);

	transp = svcudp_create(RPC_ANYSOCK);
	if (transp == NULL) {
		fprintf(stderr, "%s", "cannot create udp service.");
		exit(1);
	}
	if (!svc_register(transp, AUTHORIZATION, OAUTH, authorization_1,
					  IPPROTO_UDP)) {
		fprintf(stderr, "%s",
				"unable to register (AUTHORIZATION, OAUTH, udp).");
		exit(1);
	}

	transp = svctcp_create(RPC_ANYSOCK, 0, 0);
	if (transp == NULL) {
		fprintf(stderr, "%s", "cannot create tcp service.");
		exit(1);
	}
	if (!svc_register(transp, AUTHORIZATION, OAUTH, authorization_1,
					  IPPROTO_TCP)) {
		fprintf(stderr, "%s",
				"unable to register (AUTHORIZATION, OAUTH, tcp).");
		exit(1);
	}

	svc_run();
	fprintf(stderr, "%s", "svc_run returned");
	exit(1);
	/* NOTREACHED */
}
