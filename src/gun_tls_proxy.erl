%% Copyright (c) 2019, Loïc Hoguin <essen@ninenines.eu>
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% Intermediary process for proxying TLS connections. This process
%% is started when the ssl application calls gun_tls_proxy_cb:connect/4
%% and stays alive until the ssl connection exits.
%%
%% Data comes in through the Gun transport interface, and out through
%% the ssl transport callback in gun_tls_proxy_cb. The process then
%% takes care of forwarding the in/out data to the appropriate process
%% (the Gun process, another proxy process or the socket connected to
%% the remote endpoint.
%%
%% Normal scenario:
%%   Gun process -> TLS socket
%%
%% One proxy socket scenario:
%%   Gun process -> gun_tls_proxy (proxied socket) -> TLS socket
%%
%% Many proxy socket scenarios:
%%   Gun process -> gun_tls_proxy -> ... -> gun_tls_proxy -> TLS socket
%%
%% The difficult part is the connection. Because ssl:connect/4 does
%% not return until the connection is setup, and we need to send and
%% receive data for the TLS handshake, we need a temporary process
%% to call this function, and communicate with it. Once the connection
%% is setup the process is gone and things go back to normal.

-module(gun_tls_proxy).

-behaviour(gen_server).

%% Gun-specific interface.
-export([start_link/6]).

%% gun_tls_proxy_cb interface.
-export([cb_controlling_process/2]).
-export([cb_send/2]).
-export([cb_setopts/2]).

%% Gun transport.
-export([name/0]).
-export([messages/0]).
-export([connect/3]).
-export([connect/4]).
-export([send/2]).
-export([setopts/2]).
-export([sockname/1]).
-export([close/1]).

%% gen_server.
-export([init/1]).
-export([connect_proc/5]).
-export([handle_call/3]).
-export([handle_cast/2]).
-export([handle_info/2]).

-record(state, {
	%% The pid of the owner process. This is where we send active messages.
	owner_pid :: pid(),
	owner_active = false :: false | once | true | pos_integer(),
	owner_buffer = <<>> :: binary(),

	%% The host/port the fake ssl socket thinks it's connected to.
	host :: inet:ip_address() | inet:hostname(),
	port :: inet:port_number(),

	%% The fake ssl socket we are using in the proxy.
	proxy_socket :: any(),
	proxy_pid :: pid(),
	proxy_active = false :: false | once | true | pos_integer(),
	proxy_buffer = <<>> :: binary(),

	%% The socket or proxy process we are sending to.
	out_socket :: any(),
	out_transport :: module(),
	out_messages :: {atom(), atom(), atom()} %% @todo Missing passive.
}).

%% Gun-specific interface.

%% @todo We may need to forward data from the OutSocket/OutTransport
%% if the server sends data right after the connection is established.
start_link(Host, Port, Opts, Timeout, OutSocket, OutTransport) ->
	gen_server:start_link(?MODULE,
		{self(), Host, Port, Opts, Timeout, OutSocket, OutTransport},
		[]).

%% gun_tls_proxy_cb interface.

cb_controlling_process(Pid, ControllingPid) ->
	gen_server:cast(Pid, {?FUNCTION_NAME, ControllingPid}).

cb_send(Pid, Data) ->
	gen_server:call(Pid, {?FUNCTION_NAME, Data}).

cb_setopts(Pid, Opts) ->
	gen_server:call(Pid, {?FUNCTION_NAME, Opts}).

%% Transport.

name() -> tls_proxy.

messages() -> {tls_proxy, tls_proxy_closed, tls_proxy_error}.

-spec connect(_, _, _) -> no_return().
connect(_, _, _) ->
	error(not_implemented).

-spec connect(_, _, _, _) -> no_return().
connect(_, _, _, _) ->
	error(not_implemented).

-spec send(pid(), iodata()) -> ok | {error, atom()}.
send(Pid, Data) ->
	gen_server:call(Pid, {?FUNCTION_NAME, Data}).

-spec setopts(pid(), list()) -> ok.
setopts(Pid, Opts) ->
	gen_server:cast(Pid, {?FUNCTION_NAME, Opts}).

-spec sockname(pid())
	-> {ok, {inet:ip_address(), inet:port_number()}} | {error, atom()}.
sockname(Pid) ->
	gen_server:call(Pid, ?FUNCTION_NAME).

-spec close(pid()) -> ok.
close(Pid) ->
	gen_server:call(Pid, ?FUNCTION_NAME).

%% gen_server.

init({OwnerPid, Host, Port, Opts, Timeout, OutSocket, OutTransport}) ->
	Messages = case OutTransport of
		gen_tcp -> {tcp, tcp_closed, tcp_error};
		ssl -> {ssl, ssl_closed, ssl_error};
		_ -> OutTransport:messages()
	end,
	ProxyPid = spawn_link(?MODULE, connect_proc, [self(), Host, Port, Opts, Timeout]),
	{ok, #state{owner_pid=OwnerPid, host=Host, port=Port, proxy_pid=ProxyPid,
		out_socket=OutSocket, out_transport=OutTransport, out_messages=Messages}}.

connect_proc(ProxyPid, Host, Port, Opts, Timeout) ->
	_ = case ssl:connect(Host, Port, [
		{active, false}, binary,
		{cb_info, {gun_tls_proxy_cb, tls_proxy, tls_proxy_closed, tls_proxy_error}},
		{?MODULE, ProxyPid}
	|Opts], Timeout) of
		{ok, Socket} ->
			ssl:controlling_process(Socket, ProxyPid),
			gen_server:cast(ProxyPid, {?FUNCTION_NAME, {ok, Socket}});
		Error ->
			gen_server:cast(ProxyPid, {?FUNCTION_NAME, Error})
	end,
	ok.

%% @todo send must not be a blocking call otherwise cb_send is blocked.
handle_call({cb_send, Data}, _, State=#state{
		out_socket=OutSocket, out_transport=OutTransport}) ->
	{reply, OutTransport:send(OutSocket, Data), State};
handle_call({cb_setopts, Opts}, _, State=#state{
		out_socket=OutSocket, out_transport=OutTransport0}) ->
	%% @todo ssl doesn't support {active, N} yet! When it does, send Opts directly.
	OutTransport = case OutTransport0 of
		gen_tcp -> inet;
		_ -> OutTransport0
	end,
	{reply, OutTransport:setopts(OutSocket, [{active, true}]), proxy_setopts(Opts, State)};
%% @todo If Socket is undefined here we need to buffer input
%% and send it when we receive the {connect_proc, {ok, Socket}} message.
handle_call({send, Data}, From, State=#state{proxy_socket=Socket}) ->
	Self = self(),
	%% @todo Error handling of this send process must be improved.
	spawn(fun() -> gen_server:cast(Self, {send_result, From, ssl:send(Socket, Data)}) end),
	{noreply, State};

	%% @todo This must not run on this process. Use spawn? Check what ssl itself is doing I think it has this problem as well.
%	{reply, ssl:send(Socket, Data), State};
handle_call(sockname, _, State=#state{
		out_socket=OutSocket, out_transport=OutTransport}) ->
	{reply, OutTransport:sockname(OutSocket), State};
handle_call(close, _, State) ->
	{stop, {shutdown, close}, State};
handle_call(_, _, State) ->
	{reply, {error, bad_call}, State}.

handle_cast({connect_proc, {ok, Socket}}, State) ->
	ok = ssl:setopts(Socket, [{active, true}]),
	{noreply, State#state{proxy_socket=Socket}};
handle_cast({connect_proc, Error}, State) ->
	{stop, Error, State};
handle_cast({cb_controlling_process, ProxyPid}, State) ->
	{noreply, State#state{proxy_pid=ProxyPid}};
handle_cast({setopts, Opts}, State) ->
	{noreply, owner_setopts(Opts, State)};
handle_cast({send_result, From, Result}, State) ->
	gen_server:reply(From, Result),
	{noreply, State};
handle_cast(_, State) ->
	{noreply, State}.

handle_info({OK, Socket, Data}, State=#state{proxy_pid=ProxyPid,
		out_socket=Socket, out_messages={OK, _, _}}) ->
	ProxyPid ! {tls_proxy, self(), Data},
	%% @todo Reduce {active,N}.
	{noreply, State};
handle_info({Closed, Socket}, State=#state{proxy_pid=ProxyPid,
		out_socket=Socket, out_messages={_, Closed, _}}) ->
	ProxyPid ! {tls_proxy_closed, self()},
	{stop, {shutdown, closed_remotely}, State};
handle_info({Error, Socket, Reason}, State=#state{proxy_pid=ProxyPid,
		out_socket=Socket, out_messages={_, _, Error}}) ->
	ProxyPid ! {tls_proxy_error, self(), Reason},
	{stop, {shutdown, {Error, Socket, Reason}}, State};
handle_info(_, State) ->
	{noreply, State}.








%handle_cast({proxy_received, Data}, State=#state{buffer=Buffer}) ->
%	{noreply, active(State#state{buffer= <<Buffer/binary, Data/binary>>})};


owner_setopts(Opts, State0) ->
	case [A || {active, A} <- Opts] of
		[] -> State0;
		[false] -> State0#state{owner_active=false};
%		[0] -> OwnerPid ! {tls_proxy_passive, self()}, State0#state{owner_active=false};
		[Active] -> owner_active(State0#state{owner_active=Active})
	end.

owner_active(State=#state{owner_buffer= <<>>}) ->
	State;
owner_active(State=#state{owner_active=false}) ->
	State;
owner_active(State=#state{owner_pid=OwnerPid, owner_active=Active0, owner_buffer=Buffer}) ->
	OwnerPid ! {tls_proxy, self(), Buffer},
	Active = case Active0 of
		true -> true;
		once -> false%;
%		1 -> OwnerPid ! {tls_proxy_passive, self()}, false;
%		N -> N - 1
	end,
	State#state{owner_active=Active, owner_buffer= <<>>}.

proxy_setopts(Opts, State0=#state{proxy_socket=ProxySocket, proxy_pid=ProxyPid}) ->
	case [A || {active, A} <- Opts] of
		[] -> State0;
		[false] -> State0#state{proxy_active=false};
		[0] -> ProxyPid ! {tls_proxy_passive, ProxySocket}, State0#state{proxy_active=false};
		[Active] -> proxy_active(State0#state{proxy_active=Active})
	end.

proxy_active(State=#state{proxy_buffer= <<>>}) ->
	State;
proxy_active(State=#state{proxy_active=false}) ->
	State;
proxy_active(State=#state{proxy_pid=ProxyPid, proxy_active=Active0, proxy_buffer=Buffer}) ->
	ProxyPid ! {tls_proxy, self(), Buffer},
	Active = case Active0 of
		true -> true;
		once -> false;
		%% Note that tcp_passive is currently hardcoded in ssl.
		1 -> ProxyPid ! {tcp_passive, self()}, false;
		N -> N - 1
	end,
	State#state{proxy_active=Active, proxy_buffer= <<>>}.

-ifdef(TEST).
%tcp_test() ->
%	ssl:start(),
%	dbg:tracer(),
%	dbg:tpl(?MODULE, []),
%	dbg:tpl(gun_tls_proxy_cb, []),
%	dbg:tpl(ssl, []),
%	dbg:tpl(gen_tcp, []),
%	dbg:p(all, c),
%	{ok, Socket} = gen_tcp:connect("google.com", 443, [binary, {active, false}]),
%	{ok, ProxyPid1} = start_link("google.com", 443, [], 5000, Socket, gen_tcp),
%	gen_tcp:controlling_process(Socket, ProxyPid1),
%	timer:sleep(5000),
%%	{ok, ProxyPid2} = start_link("google.com", 443, [], 5000, ProxyPid1, ?MODULE),
%%	timer:sleep(5000),
%%	send(ProxyPid2, <<"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n">>),
%	timer:sleep(5000),
%	io:format(user, "~p~n", [erlang:process_info(self(), messages)]),
%	io:format(user, "~p~n", [erlang:process_info(ProxyPid1, messages)]),
%%	io:format(user, "~p~n", [erlang:process_info(ProxyPid2, messages)]),
%	ok.

ssl_test() ->
	ssl:start(),
	dbg:tracer(),
	dbg:tpl(?MODULE, []),
	dbg:tpl(gun_tls_proxy_cb, []),
	dbg:tpl(ssl, []),
	dbg:p(all, c),
	{ok, _, Port} = do_proxy_start(),
	{ok, Socket} = ssl:connect("localhost", Port, [binary, {active, false}]),
	timer:sleep(1000),
	{ok, ProxyPid1} = start_link("google.com", 443, [], 5000, Socket, ssl),
	ssl:controlling_process(Socket, ProxyPid1),
	timer:sleep(5000),
%	{ok, ProxyPid2} = start_link("google.com", 443, [], 5000, ProxyPid1, ?MODULE),
%	timer:sleep(5000),
	send(ProxyPid1, <<"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n">>),
	timer:sleep(5000),
	io:format(user, "~p~n", [erlang:process_info(self(), messages)]),
	io:format(user, "~p~n", [erlang:process_info(ProxyPid1, messages)]),
%	io:format(user, "~p~n", [erlang:process_info(ProxyPid2, messages)]),
	ok.

do_proxy_start() ->
	Self = self(),
	Pid = spawn_link(fun() -> do_proxy_init(Self) end),
	Port = receive_from(Pid),
	{ok, Pid, Port}.

do_proxy_init(Parent) ->
	ct_helper:make_certs_in_ets(),
	Opts = ct_helper:get_certs_from_ets(),
	{ok, ListenSocket} = ssl:listen(0, [binary, {active, false}|Opts]),
	{ok, {_, Port}} = ssl:sockname(ListenSocket),
	Parent ! {self(), Port},
	{ok, ClientSocket} = ssl:transport_accept(ListenSocket, 1000),
	{ok, _} = ssl:handshake(ClientSocket, 1000),
	{ok, OriginSocket} = gen_tcp:connect(
		"google.com", 443,
		[binary, {active, false}]),
	ssl:setopts(ClientSocket, [{active, true}]),
	inet:setopts(OriginSocket, [{active, true}]),
	do_proxy_loop(ClientSocket, OriginSocket).

do_proxy_loop(ClientSocket, OriginSocket) ->
	receive
		{ssl, ClientSocket, Data} ->
			ok = gen_tcp:send(OriginSocket, Data),
			do_proxy_loop(ClientSocket, OriginSocket);
		{tcp, OriginSocket, Data} ->
			ok = ssl:send(ClientSocket, Data),
			do_proxy_loop(ClientSocket, OriginSocket);
		{tcp_closed, _} ->
			ok;
		Msg ->
			error(Msg)
	end.

receive_from(Pid) ->
	receive_from(Pid, 5000).

receive_from(Pid, Timeout) ->
	receive
		{Pid, Msg} ->
			Msg
	after Timeout ->
		error(timeout)
	end.
-endif.
