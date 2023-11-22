enum e_operation_type {
    REQUEST,
    READ,
    INSERT,
    MODIFY,
    DELETE,
    EXECUTE
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


enum e_approval_status {
    SIGNED,
    NOT_SIGNED
};

struct resource_perm_struct {
    string resource<>;
    string permission<>;
};


struct acces_token_struct {
    string access_token<>;
    string refresh_token<>;
    int valability;
};

struct access_token_req {
    string user_id<>;
    string auth_token<>;
    int auto_refresh;
};

struct approve_req {
    string auth_token<>;
};

struct action_req {
    e_operation_type operation;
    string resource<>;
    string access_token<>;
};



program AUTHORIZATION{
    version OAUTH {
        string auth(string) = 1;
        acces_token_struct access(access_token_req) = 2;
        string validate_action(action_req) = 3;
        string approve_req_token(string) = 4;
    } = 1;
} = 0x31234567;