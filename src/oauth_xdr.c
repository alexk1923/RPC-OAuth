/*
 * Please do not edit this file.
 * It was generated using rpcgen.
 */

#include "oauth.h"

bool_t
xdr_e_operation_type (XDR *xdrs, e_operation_type *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_e_res_code (XDR *xdrs, e_res_code *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_e_approval_status (XDR *xdrs, e_approval_status *objp)
{
	register int32_t *buf;

	 if (!xdr_enum (xdrs, (enum_t *) objp))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_resource_perm_struct (XDR *xdrs, resource_perm_struct *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->resource, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->permission, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_acces_token_struct (XDR *xdrs, acces_token_struct *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->access_token, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->refresh_token, ~0))
		 return FALSE;
	 if (!xdr_int (xdrs, &objp->valability))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_access_token_req (XDR *xdrs, access_token_req *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->user_id, ~0))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->auth_token, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_approve_req (XDR *xdrs, approve_req *objp)
{
	register int32_t *buf;

	 if (!xdr_string (xdrs, &objp->auth_token, ~0))
		 return FALSE;
	return TRUE;
}

bool_t
xdr_action_req (XDR *xdrs, action_req *objp)
{
	register int32_t *buf;

	 if (!xdr_e_operation_type (xdrs, &objp->operation))
		 return FALSE;
	 if (!xdr_string (xdrs, &objp->resource, ~0))
		 return FALSE;
	 if (!xdr_array (xdrs, (char **)&objp->access_token.access_token_val, (u_int *) &objp->access_token.access_token_len, ~0,
		sizeof (acces_token_struct), (xdrproc_t) xdr_acces_token_struct))
		 return FALSE;
	return TRUE;
}
