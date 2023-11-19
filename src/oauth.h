/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#ifndef _OAUTH_H_RPCGEN
#define _OAUTH_H_RPCGEN

#include <rpc/rpc.h>


#ifdef __cplusplus
extern "C" {
#endif


enum e_operation_type {
	REQUEST = 0,
	READ = 1,
	INSERT = 2,
	MODIFY = 3,
	DELETE = 4,
	EXECUTE = 5,
};
typedef enum e_operation_type e_operation_type;

enum e_res_code {
	USER_NOT_FOUND = 0,
	REQUEST_DENIED = 1,
	PERMISSION_DENIED = 2,
	TOKEN_EXPIRED = 3,
	RESOURCE_NOT_FOUND = 4,
	OPERATION_NOT_PERMITTED = 5,
	PERMISSION_GRANTED = 6,
};
typedef enum e_res_code e_res_code;

enum e_approval_status {
	SIGNED = 0,
	NOT_SIGNED = 1,
};
typedef enum e_approval_status e_approval_status;

struct resource_perm_struct {
	char *resource;
	char *permission;
};
typedef struct resource_perm_struct resource_perm_struct;

struct acces_token_struct {
	char *access_token;
	char *refresh_token;
	int valability;
};
typedef struct acces_token_struct acces_token_struct;

struct access_token_req {
	char *user_id;
	char *auth_token;
};
typedef struct access_token_req access_token_req;

struct approve_req {
	char *auth_token;
};
typedef struct approve_req approve_req;

struct action_req {
	e_operation_type operation;
	char *resource;
	struct {
		u_int access_token_len;
		acces_token_struct *access_token_val;
	} access_token;
};
typedef struct action_req action_req;

#define AUTHORIZATION 0x31234567
#define OAUTH 1

#if defined(__STDC__) || defined(__cplusplus)
#define auth 1
extern  char ** auth_1(char **, CLIENT *);
extern  char ** auth_1_svc(char **, struct svc_req *);
#define access 2
extern  acces_token_struct * access_1(access_token_req *, CLIENT *);
extern  acces_token_struct * access_1_svc(access_token_req *, struct svc_req *);
#define validate_action 3
extern  char ** validate_action_1(action_req *, CLIENT *);
extern  char ** validate_action_1_svc(action_req *, struct svc_req *);
#define approve_req_token 4
extern  char ** approve_req_token_1(char **, CLIENT *);
extern  char ** approve_req_token_1_svc(char **, struct svc_req *);
extern int authorization_1_freeresult (SVCXPRT *, xdrproc_t, caddr_t);

#else /* K&R C */
#define auth 1
extern  char ** auth_1();
extern  char ** auth_1_svc();
#define access 2
extern  acces_token_struct * access_1();
extern  acces_token_struct * access_1_svc();
#define validate_action 3
extern  char ** validate_action_1();
extern  char ** validate_action_1_svc();
#define approve_req_token 4
extern  char ** approve_req_token_1();
extern  char ** approve_req_token_1_svc();
extern int authorization_1_freeresult ();
#endif /* K&R C */

/* the xdr functions */

#if defined(__STDC__) || defined(__cplusplus)
extern  bool_t xdr_e_operation_type (XDR *, e_operation_type*);
extern  bool_t xdr_e_res_code (XDR *, e_res_code*);
extern  bool_t xdr_e_approval_status (XDR *, e_approval_status*);
extern  bool_t xdr_resource_perm_struct (XDR *, resource_perm_struct*);
extern  bool_t xdr_acces_token_struct (XDR *, acces_token_struct*);
extern  bool_t xdr_access_token_req (XDR *, access_token_req*);
extern  bool_t xdr_approve_req (XDR *, approve_req*);
extern  bool_t xdr_action_req (XDR *, action_req*);

#else /* K&R C */
extern bool_t xdr_e_operation_type ();
extern bool_t xdr_e_res_code ();
extern bool_t xdr_e_approval_status ();
extern bool_t xdr_resource_perm_struct ();
extern bool_t xdr_acces_token_struct ();
extern bool_t xdr_access_token_req ();
extern bool_t xdr_approve_req ();
extern bool_t xdr_action_req ();

#endif /* K&R C */

#ifdef __cplusplus
}
#endif

#endif /* !_OAUTH_H_RPCGEN */
