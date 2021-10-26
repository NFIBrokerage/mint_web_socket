defmodule Mint.WebSocket do
  @moduledoc """
  (Unofficial) WebSocket support for the Mint functional HTTP client

  Like Mint, `Mint.WebSocket` provides a functional, process-less interface
  for operating a WebSocket connection. `Mint.WebSocket` is an extension
  to Mint: the sending and receiving of messages is done with Mint functions.
  Prospective Mint.WebSocket users should first familiarize themselves with
  `Mint.HTTP`.

  Mint.WebSocket is not fully spec-conformant on its own. Runtime behaviors
  such as responding to pings with pongs must be implemented by the user of
  Mint.WebSocket.

  ## Usage

  A connection formed with `Mint.HTTP.connect/4` can be upgraded to a WebSocket
  connection with `upgrade/4`.

  ```elixir
  {:ok, conn} = Mint.HTTP.connect(:http, "localhost", 9_000)
  {:ok, conn, ref} = Mint.WebSocket.upgrade(conn, "/", [])
  ```

  `upgrade/4` sends an upgrade request to the remote server. The WebSocket
  connection is then built by awaiting the HTTP response from the server.

  ```elixir
  http_reply_message = receive(do: (message -> message))
  {:ok, conn, [{:status, ^ref, status}, {:headers, ^ref, resp_headers}, {:done, ^ref}]} =
    Mint.HTTP.stream(conn, http_reply_message)

  {:ok, conn, websocket} =
    Mint.WebSocket.new(conn, ref, status, resp_headers)
  ```

  Now that the WebSocket connection has been formed, we use the `websocket`
  data structure to encode and decode frames, and the
  `Mint.HTTP.stream_request_body/3` and `Mint.HTTP.stream/2` functions from
  Mint to perform sending and receiving of encoded frames.

  For example, we'll send a "hello world" text frame across our connection.

  ```elixir
  {:ok, websocket, data} = Mint.WebSocket.encode(websocket, {:text, "hello world"})
  {:ok, conn} = Mint.HTTP.stream_request_body(conn, ref, data)
  ```

  And let's say that the server is echoing our messages; let's receive our
  echoed "hello world" text frame.

  ```elixir
  echo_message = receive(do: (message -> message))
  {:ok, conn, [{:data, ^ref, data}]} = Mint.HTTP.stream(conn, echo_message)
  {:ok, websocket, [{:text, "hello world"}]} = Mint.WebSocket.decode(websocket, data)
  ```

  ## HTTP/2 Support

  Mint.WebSocket supports WebSockets over HTTP/2 as defined in rfc8441.
  rfc8441 is an extension to the HTTP/2 specification. At the time of
  writing, very few HTTP/2 server libraries support or enable HTTP/2
  WebSockets by default.

  `upgrade/4` works on both HTTP/1 and HTTP/2 connections. In order to select
  HTTP/2, the `:http2` protocol should be explicitly selected in
  `Mint.HTTP.connect/4`.

  ```elixir
  {:ok, conn} =
    Mint.HTTP.connect(:http, "websocket.example", 80, protocols: [:http2])
  :http2 = Mint.HTTP.protocol(conn)
  {:ok, conn, ref} = Mint.WebSocket.upgrade(conn, "/", [])
  ```

  If the server does not support the extended CONNECT method needed to bootstrap
  WebSocket connections over HTTP/2, `upgrade/4` will return an error tuple
  with the `:extended_connect_disabled` error reason.

  ```elixir
  {:error, conn, %Mint.WebSocketError{reason: :extended_connect_disabled}}
  ```

  Why use HTTP/2 for WebSocket connections in the first place? HTTP/2
  can multiplex many requests over the same connection, which can
  reduce the latency incurred by forming new connections for each request.
  A WebSocket connection only occupies one stream of a HTTP/2 connection, so
  even if an HTTP/2 connection has an open WebSocket communication, it can be
  used to transport more requests.

  ## WebSocket Secure

  Encryption of connections is handled by Mint functions. To start a WSS
  connection, select `:https` as the scheme in `Mint.HTTP.connect/4`:

  ```elixir
  {:ok, conn} = Mint.HTTP.connect(:https, "websocket.example", 443)
  ```

  And use `upgrade/4` to upgrade the connection to WebSocket. See the
  Mint documentation on SSL for more information.

  ## Extensions

  The WebSocket protocol allows for _extensions_. Extensions act as a
  middleware for encoding and decoding frames. For example "permessage-deflate"
  compresses and decompresses the body of data frames, which minifies the amount
  of bytes which must be sent over the network.

  See `Mint.WebSocket.Extension` for more information about extensions and
  `Mint.WebSocket.PerMessageDeflate` for information about the
  "permessage-deflate" extension.
  """

  alias __MODULE__.{Utils, Extension, Frame}
  alias Mint.WebSocketError
  alias Mint.{HTTP1, HTTP2}
  import Mint.HTTP, only: [get_private: 2, put_private: 3, protocol: 1]

  @typedoc """
  An immutable data structure representing a WebSocket connection
  """
  @opaque t :: %__MODULE__{
            extensions: [Extension.t()],
            fragment: tuple(),
            private: map(),
            buffer: binary()
          }
  defstruct extensions: [],
            fragment: nil,
            private: %{},
            buffer: <<>>

  @type error :: Mint.Types.error() | WebSocketError.t()

  @typedoc """
  Shorthand notations for control frames

  * `:ping` - shorthand for `{:ping, ""}`
  * `:pong` - shorthand for `{:pong, ""}`
  * `:close` - shorthand for `{:close, nil, nil}`

  These may be passed to `encode/2`.

  <!--
  Note that the shorthand notations may be passed to `encode/2`
  but frames returned from `decode/2` will never be in
  shorthand format.
  -->
  """
  @type shorthand_frame :: :ping | :pong | :close

  @typedoc """
  A WebSocket frame

  * `{:binary, binary}` - a frame containing binary data. Binary frames
    can be used to send arbitrary binary data such as a PDF.
  * `{:text, text}` - a frame containing string data. Text frames must be
    valid utf8. Elixir has wonderful support for utf8: `String.valid?/1`
    can detect valid and invalid utf8.
  * `{:ping, binary}` - a control frame which the server should respond to
    with a pong. The binary data must be echoed in the pong response.
  * `{:pong, binary}` - a control frame which forms a reply to a ping frame.
    Pings and pongs may be used to check the a connection is alive or to
    estimate latency.
  * `{:close, code, reason}` - a control frame used to request that a connection
    be closed or to acknowledgee a close frame send by the server.

  These may be passed to `encode/2` or returned from `decode/2`.

  ## Close frames

  In order to close a WebSocket connection gracefully, either the client or
  server sends a close frame. Then the other endpoint responds with a
  close with code `1_000` and then closes the TCP connection. This can be
  accomplished in Mint.WebSocket like so:

  ```elixir
  {:ok, websocket, data} = Mint.WebSocket.encode(websocket, :close)
  {:ok, conn} = Mint.HTTP.stream_request_body(conn, ref, data)

  close_response = receive(do: (message -> message))
  {:ok, conn, [{:data, ^ref, data}]} = Mint.HTTP.stream(conn, close_response)
  {:ok, websocket, [{:close, 1_000, ""}]} = Mint.WebSocket.decode(websocket, data)

  Mint.HTTP.close(conn)
  ```

  [rfc6455
  section 7.4.1](https://datatracker.ietf.org/doc/html/rfc6455#section-7.4.1)
  documents codes which may be used in the `code` element.
  """
  @type frame ::
          {:text, String.t()}
          | {:binary, binary()}
          | {:ping, binary()}
          | {:pong, binary()}
          | {:close, code :: non_neg_integer() | nil, reason :: binary() | nil}

  @doc """
  Requests that a connection be upgraded to the WebSocket protocol

  This function wraps `Mint.HTTP.request/5` to provide a single interface
  for bootstrapping an upgrade for HTTP/1 and HTTP/2 connections.

  For HTTP/1 connections, this function performs a GET request with
  WebSocket-specific headers. For HTTP/2 connections, this function performs
  an extended CONNECT request which opens a stream to be used for the WebSocket
  connection.

  ## Options

  * `:extensions` - a list of extensions to negotiate. See the extensions
    section below.

  ## Extensions

  Extensions should be declared by passing the `:extensions` option in the
  `opts` keyword list. Note that in the WebSocket protocol, extensions are
  negotiated: the client proposes a list of extensions and the server may
  accept any (or none) of them. See `Mint.WebSocket.Extension` for more
  information about extension negotiation.

  Extensions may be passed as a list of `Mint.WebSocket.Extension` structs
  or with the following shorthand notations:

  * `module` - shorthand for `{module, []}`
  * `{module, params}` - shorthand for `{module, params, []}`
  * `{module, params, opts}` - a shorthand which is expanded to a
    `Mint.WebSocket.Extension` struct

  ## Examples

  ```elixir
  {:ok, conn} = Mint.HTTP.connect(:http, "localhost", 9_000)
  {:ok, conn, ref} =
    Mint.WebSocket.upgrade(conn, "/", [], extensions: [Mint.WebSocket.PerMessageDeflate])
  # or provide params:
  {:ok, conn, ref} =
    Mint.WebSocket.upgrade(
      conn,
      "/",
      [],
      extensions: [{Mint.WebSocket.PerMessageDeflate, [:client_max_window_bits]]}]
    )
  ```
  """
  @spec upgrade(
          scheme :: :ws | :wss,
          conn :: Mint.HTTP.t(),
          path :: String.t(),
          headers :: Mint.Types.headers(),
          opts :: Keyword.t()
        ) :: {:ok, Mint.HTTP.t(), Mint.Types.request_ref()} | {:error, Mint.HTTP.t(), error()}
  def upgrade(scheme, conn, path, headers, opts \\ []) when scheme in ~w[ws wss]a do
    conn = put_private(conn, :scheme, scheme)

    do_upgrade(scheme, Mint.HTTP.protocol(conn), conn, path, headers, opts)
  end

  defp do_upgrade(_scheme, :http1, conn, path, headers, opts) do
    nonce = Utils.random_nonce()
    extensions = get_extensions(opts)

    conn =
      conn
      |> put_private(:sec_websocket_key, nonce)
      |> put_private(:extensions, extensions)

    headers = Utils.headers({:http1, nonce}, extensions) ++ headers

    Mint.HTTP.request(conn, "GET", path, headers, nil)
  end

  defp do_upgrade(scheme, :http2, conn, path, headers, opts) do
    if HTTP2.get_server_setting(conn, :enable_connect_protocol) == true do
      extensions = get_extensions(opts)
      conn = put_private(conn, :extensions, extensions)

      headers =
        [
          {":scheme", if(scheme == :ws, do: "http", else: "https")},
          {":path", path},
          {":protocol", "websocket"}
          | headers
        ] ++ Utils.headers(:http2, extensions)

      Mint.HTTP.request(conn, "CONNECT", path, headers, :stream)
    else
      {:error, conn, %WebSocketError{reason: :extended_connect_disabled}}
    end
  end

  @doc """
  Creates a new WebSocket data structure given the server's reply to the
  upgrade request

  This function will setup any extensions accepted by the server using
  the `c:Mint.WebSocket.Extension.init/2` callback.

  ## Examples

  ```elixir
  http_reply = receive(do: (message -> message))
  {:ok, conn, [{:status, ^ref, status}, {:headers, ^ref, headers}, {:done, ^ref}]} =
    Mint.HTTP.stream(conn, http_reply)

  {:ok, conn, websocket} =
    Mint.WebSocket.new(:ws, conn, ref, status, resp_headers)
  ```
  """
  @spec new(
          Mint.HTTP.t(),
          reference(),
          Mint.Types.status(),
          Mint.Types.headers()
        ) ::
          {:ok, Mint.HTTP.t(), t()} | {:error, Mint.HTTP.t(), error()}
  def new(conn, request_ref, status, response_headers, opts \\ []) do
    websockets = [request_ref | get_private(conn, :websockets) || []]

    conn =
      conn
      |> put_private(:websockets, websockets)
      |> put_private(:mode, Keyword.get(opts, :mode, :active))

    do_new(protocol(conn), conn, request_ref, status, response_headers)
  end

  defp do_new(:http1, conn, _request_ref, status, _response_headers) when status != 101 do
    {:error, conn, %WebSocketError{reason: :connection_not_upgraded}}
  end

  defp do_new(:http1, conn, request_ref, _status, response_headers) do
    with :ok <- Utils.check_accept_nonce(get_private(conn, :sec_websocket_key), response_headers),
         {:ok, extensions} <-
           Extension.accept_extensions(get_private(conn, :extensions), response_headers) do
      conn = re_open_request(conn, request_ref)

      {:ok, conn, %__MODULE__{extensions: extensions}}
    else
      {:error, reason} -> {:error, conn, reason}
    end
  end

  defp do_new(:http2, conn, _request_ref, status, response_headers)
       when status in 200..299 do
    with {:ok, extensions} <-
           Extension.accept_extensions(get_private(conn, :extensions), response_headers) do
      {:ok, conn, %__MODULE__{extensions: extensions}}
    end
  end

  defp do_new(:http2, conn, _request_ref, _status, _response_headers) do
    {:error, conn, %WebSocketError{reason: :connection_not_upgraded}}
  end

  @doc """
  A wrapper around `Mint.HTTP.stream/2` for streaming HTTP and WebSocket
  messages

  This function does not decode WebSocket frames. Instead, once a WebSocket
  connection has been established, decode any
  `{:data, websocket_request_ref, data}` frames with `decode/2`.

  This function is a drop-in replacement for `Mint.HTTP.stream/2` which
  enables streaming WebSocket data after the bootstrapping HTTP/1 connection
  has concluded. It decodes both WebSocket and regular HTTP messages.
  """
  def stream(conn, message) do
    case protocol(conn) do
      :http1 -> stream_http1(conn, message)
      _ -> Mint.HTTP.stream(conn, message)
    end
  end

  # we take manual control of the :gen_tcp and :ssl messages in HTTP/1 because
  # we have taken over the transport
  defp stream_http1(conn, message) do
    socket = HTTP1.get_socket(conn)
    scheme = get_private(conn, :scheme)
    # HTTP/1 only allows one WebSocket per connection
    with [request_ref] <- get_private(conn, :websockets),
         tag = if(scheme == :ws, do: :tcp, else: :ssl),
         {^tag, ^socket, data} <- message do
      reset_mode(conn, tag, [{:data, request_ref, data}])
    else
      _ ->
        HTTP1.stream(conn, message)
    end
  end

  defp reset_mode(conn, tag, responses) do
    module = if tag == :tcp, do: :inet, else: :ssl

    with :active <- get_private(conn, :mode),
         {:error, reason} <- module.setopts(HTTP1.get_socket(conn), active: :once) do
      {:error, conn, %Mint.TransportError{reason: reason}, responses}
    else
      _ -> {:ok, conn, responses}
    end
  end

  @doc """
  Encodes a frame into a binary

  The resulting binary may be sent with `Mint.HTTP.stream_request_body/3`.

  This function will invoke the `c:Mint.WebSocket.Extension.encode/2` callback
  for any accepted extensions.

  ## Examples

  ```elixir
  {:ok, websocket, data} = Mint.WebSocket.encode(websocket, {:text, "hello world"})
  {:ok, conn} = Mint.HTTP.stream_request_body(conn, ref, data)
  ```
  """
  @spec encode(t(), shorthand_frame() | frame()) :: {:ok, t(), binary()} | {:error, t(), any()}
  defdelegate encode(websocket, frame), to: Frame

  @doc """
  Decodes a binary into a list of frames

  The binary may received from the connection with `Mint.HTTP.stream/2`.

  This function will invoke the `c:Mint.WebSocket.Extension.decode/2` callback
  for any accepted extensions.

  ## Examples

  ```elixir
  message = receive(do: (message -> message))
  {:ok, conn, [{:data, ^ref, data}]} = Mint.HTTP.stream(conn, message)
  {:ok, websocket, frames} = Mint.WebSocket.decode(websocket, data)
  ```
  """
  @spec decode(t(), data :: binary()) ::
          {:ok, t(), [frame() | {:error, term()}]} | {:error, t(), any()}
  defdelegate decode(websocket, data), to: Frame

  # we re-open the request in the conn for HTTP1 connections because a :done
  # will complete the request
  defp re_open_request(%Mint.HTTP1{} = conn, request_ref) do
    request = new_request(request_ref, nil, :stream, :identity)
    %{conn | streaming_request: request}
  end

  defp new_request(ref, method, body, encoding) do
    state =
      if body == :stream do
        {:stream_request, encoding}
      else
        :status
      end

    %{
      ref: ref,
      state: state,
      method: method,
      version: nil,
      status: nil,
      headers_buffer: [],
      data_buffer: [],
      content_length: nil,
      connection: [],
      transfer_encoding: [],
      body: nil
    }
  end

  defp get_extensions(opts) do
    opts
    |> Keyword.get(:extensions, [])
    |> Enum.map(fn
      module when is_atom(module) ->
        %Extension{module: module, name: module.name()}

      {module, params} ->
        %Extension{module: module, name: module.name(), params: normalize_params(params)}

      {module, params, opts} ->
        %Extension{
          module: module,
          name: module.name(),
          params: normalize_params(params),
          opts: opts
        }

      %Extension{} = extension ->
        update_in(extension.params, &normalize_params/1)
    end)
  end

  defp normalize_params(params) do
    params
    |> Enum.map(fn
      {_key, false} -> nil
      {key, value} -> {to_string(key), to_string(value)}
      key -> {to_string(key), "true"}
    end)
    |> Enum.reject(&is_nil/1)
  end
end
