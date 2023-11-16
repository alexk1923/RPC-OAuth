enum e_operation_type {
    REQUEST,
    READ,
    INSERT,
    MODIFY,
    DELETE,
    EXECUTE
};

enum e_signed_status {
    NOT_SIGNED,
    SIGNED
};

enum e_res_code {
    USER_NOT_FOUND,
    REQUEST_DENIED,
    PERMISSION_DENIED,
    TOKEN_EXPIRED,
    RESOURCE_NOT_FOUND,
    OPERATION_NOT_PERMITTED,
    PERMISSION_GRANTED
};


struct resource_perm_struct {
    string resource<>;
    string permission<>;
};

struct auth_token_struct {
    e_signed_status signed_status;
    resource_perm_struct resource_permissions<>;
};

struct acces_token_struct {
    string access_token<>;
    string refresh_token<>;
    int valability;
};

struct access_token_req {
    string user_id<>;
    string auth_token<>;
};

struct approve_req {
    string auth_token<>;
};

struct action_req {
    e_operation_type operation;
    string resource<>;
    acces_token_struct access_token<>;
};


program AUTHORIZATION{
    version OAUTH {
        string auth(string) = 1;
        acces_token_struct access(access_token_req) = 2;
        string validate_action(action_req) = 3;
        auth_token_struct approve_req_token(auth_token_struct) = 4;
    } = 1;
} = 0x31234567;