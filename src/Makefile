CC=g++
CFLAGS= -g -lnsl -Wall
LIBS =
CLIENT = client
CLIENT_SRC = oauth_clnt.c oauth_client.cpp oauth_xdr.c
SERVER = server
SERVER_SRC = oauth_svc.c oauth_server.cpp oauth_xdr.c
RPCGEN = oauth.h oauth_xdr.c oauth_svc.c oauth_clnt.c
UTILS = utils/utils.cpp

all: $(CLIENT) $(SERVER)

client:	$(CLIENT_SRC) $(RPCGEN)
		$(CC) $(CFLAGS) $(LIBS) -o $(CLIENT) $(CLIENT_SRC) $(UTILS)

server: $(SERVER_SRC) $(RPCGEN)
		$(CC) $(CFLAGS) $(LIBS) -o $(SERVER) $(SERVER_SRC) $(UTILS)
 
clean:
	rm -rf $(CLIENT) $(SERVER)
