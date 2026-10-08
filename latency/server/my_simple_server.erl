-module(my_simple_server).
-export([start/0]).

start() ->
    application:start(crypto),
    application:start(asn1),
    application:start(public_key),
    application:start(ssl),
    application:start(inets),

    {ok, Cwd} = file:get_cwd(),
    DocRoot = filename:join(Cwd, "www"),

    % Start HTTPS server on port 443 (with SSL)
    inets:start(),
    {ok, Pid} = inets:start(httpd, [
        {port, 443},
        {server_name,"localhost"},
        {server_root, Cwd},
        {document_root, DocRoot},
        {bind_address, any},
        {socket_type, {ssl, [{certfile, "/cert/server.crt"}, 
                    {keyfile, "/cert/server.key"},
                    {raw, 6, 23, <<5:32/native>>}]}},
        {mimetypes, [{"html", "text/html"}]}
    ]),
    Pid.
