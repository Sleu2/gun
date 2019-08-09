-module(gun_socks5_event_h).
-description("ssl-like gun transport that performs socks5 connection through a proxy first").
-behavior(gun_event).

-define(VERSION, 5).
-define(CONNECT, 1).
-define(NMETHODS, 1).
-define(NO_AUTH, 0).
-define(USERPASS, 2).
-define(UNACCEPTABLE, 16#FF).
-define(RESERVED, 0).
-define(ATYP_IPV4, 1).
-define(ATYP_DOMAINNAME, 3).
-define(ATYP_IPV6, 4).
-define(SUCCEEDED, 0).

-export([init/2]).
-export([domain_lookup_start/2]).
-export([domain_lookup_end/2]).
-export([connect_start/2]).
-export([connect_end/2]).
-export([tls_handshake_start/2]).
-export([tls_handshake_end/2]).
-export([request_start/2]).
-export([request_headers/2]).
-export([request_end/2]).
-export([push_promise_start/2]).
-export([push_promise_end/2]).
-export([response_start/2]).
-export([response_inform/2]).
-export([response_headers/2]).
-export([response_trailers/2]).
-export([response_end/2]).
-export([ws_upgrade/2]).
-export([ws_recv_frame_start/2]).
-export([ws_recv_frame_header/2]).
-export([ws_recv_frame_end/2]).
-export([ws_send_frame_start/2]).
-export([ws_send_frame_end/2]).
-export([protocol_changed/2]).
-export([transport_changed/2]).
-export([origin_changed/2]).
-export([cancel/2]).
-export([disconnect/2]).
-export([terminate/2]).

-export([connect_to_target/3, handshake/2]).

init(_EventData, State) ->
    State.

domain_lookup_start(_EventData, State) ->
    State.

domain_lookup_end(_EventData, State) ->
    State.


connect_start(_EventData, State) ->
    State.
connect_end(#{socket := Socket}, #{host := Host, port := Port} = State) ->
    ok = handshake(Socket, []),
    ok = connect_to_target(Host, Port, Socket),
    State.

tls_handshake_start(_EventData, State) ->
    State.

tls_handshake_end(_EventData, State) ->
    State.

request_start(_EventData, State) ->
    State.

request_headers(_EventData, State) ->
    State.

request_end(_EventData, State) ->
    State.

push_promise_start(_EventData, State) ->
    State.

push_promise_end(_EventData, State) ->
    State.

response_start(_EventData, State) ->
    State.

response_inform(_EventData, State) ->
    State.

response_headers(_EventData, State) ->
    State.

response_trailers(_EventData, State) ->
    State.

response_end(_EventData, State) ->
    State.

ws_upgrade(_EventData, State) ->
    State.

ws_recv_frame_start(_EventData, State) ->
    State.

ws_recv_frame_header(_EventData, State) ->
    State.

ws_recv_frame_end(_EventData, State) ->
    State.

ws_send_frame_start(_EventData, State) ->
    State.

ws_send_frame_end(_EventData, State) ->
    State.

protocol_changed(_EventData, State) ->
    State.

transport_changed(_EventData, State) ->
    State.

origin_changed(_EventData, State) ->
    State.

cancel(_EventData, State) ->
    State.

disconnect(_EventData, State) ->
    State.

terminate(_EventData, State) ->
    State.


handshake(Socket, Options) when is_port(Socket) ->
    User = proplists:get_value(socks5_user, Options, <<>>),
    Password = proplists:get_value(socks5_password, Options, <<>>),
    ok = gen_tcp:send(Socket, case User of
                                  <<>> -> <<?VERSION, ?NMETHODS, ?NO_AUTH>>;
                                  User -> <<?VERSION, ?NMETHODS, ?USERPASS>>
                              end),
    case gen_tcp:recv(Socket, 2) of
        {error, Reason} -> {error, Reason};
        {ok, <<?VERSION, ?UNACCEPTABLE>>} -> {error, unacceptable};
        {ok, <<?VERSION, ?NO_AUTH>>} -> ok;
        {ok, <<?VERSION, ?USERPASS>>} ->
            Auth = list_to_binary([1, iolist_size(User), User, iolist_size(Password), Password]),
            ok = gen_tcp:send(Socket, Auth),
            case gen_tcp:recv(Socket, 2) of
                {ok, <<1, ?SUCCEEDED>>} -> ok;
                _ -> {error, auth_unacceptable}
            end
    end.

connect_to_target(Host, Port, Socket) when is_list(Host) ->
    connect_to_target(list_to_binary(Host), Port, Socket);
connect_to_target(Host, Port, Socket) when is_binary(Host), is_integer(Port), is_port(Socket) ->
    {AddressType, Address} =
        case inet:parse_address(binary_to_list(Host)) of
            {ok, {IP1, IP2, IP3, IP4}} ->
                {?ATYP_IPV4, <<IP1,IP2,IP3,IP4>>};
            {ok, {IP1, IP2, IP3, IP4, IP5, IP6, IP7, IP8}} ->
                {?ATYP_IPV6, <<IP1,IP2,IP3,IP4,IP5,IP6,IP7,IP8>>};
            _ ->
                HostLength = byte_size(Host),
                {?ATYP_DOMAINNAME, <<HostLength,Host/binary>>}
        end,
    ok = gen_tcp:send(Socket, <<?VERSION, ?CONNECT, ?RESERVED, AddressType, Address/binary, (Port):16>>),
    case gen_tcp:recv(Socket, 10) of
        {ok, <<?VERSION, ?SUCCEEDED, ?RESERVED, _/binary>>} -> ok;
        {ok, <<?VERSION, Response, ?RESERVED, _/binary>>} -> {error, response(Response)};
        {error, Reason} -> {error, Reason}
    end.

response(0) -> succeeded;
response(1) -> general_socks_server_failure;
response(2) -> connection_not_allowed_by_ruleset;
response(3) -> network_unreachable;
response(4) -> host_unreachable;
response(5) -> connection_refused;
response(6) -> ttl_expired;
response(7) -> command_not_supported;
response(8) -> address_type_not_supported;
response(9) -> unassigned.
