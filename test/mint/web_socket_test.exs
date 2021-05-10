defmodule Mint.WebSocketTest do
  use ExUnit.Case, async: true

  describe "given a 'hello world' text frame" do
    setup do
      [frame: {:text, "hello world"}]
    end

    test "we can send it and receive an echo reply", c do
      # bootstrap
      {:ok, conn} = Mint.HTTP.connect(:http, "echo", 8080)
      req_headers = Mint.WebSocket.build_request_headers()
      {:ok, conn, ref} = Mint.HTTP.request(conn, "GET", "/", req_headers, nil)
      assert_receive http_get_message

      {:ok, conn, [{:status, ^ref, status}, {:headers, ^ref, resp_headers}, {:done, ^ref}]} =
        Mint.HTTP.stream(conn, http_get_message)

      {:ok, conn, websocket} =
        Mint.WebSocket.new(conn, ref, status, req_headers, resp_headers)

      {:ok, websocket, messages} =
        Mint.WebSocket.decode(websocket, conn.buffer)

      {conn, websocket} =
        case messages do
          [] ->
            # receive one message about the request being served
            assert_receive request_served_by_message, 1_000
            {:ok, conn, [{:data, ^ref, data}]} = Mint.HTTP.stream(conn, request_served_by_message)

            assert {:ok, websocket, [{:text, "Request served by " <> _}]} =
                     Mint.WebSocket.decode(websocket, data)

            {conn, websocket}

          [{:text, "Request served by " <> _}] ->
            {put_in(conn.buffer, <<>>), websocket}
        end

      # send the hello world frame
      {:ok, websocket, data} = Mint.WebSocket.encode(websocket, c.frame)
      {:ok, conn} = Mint.HTTP.stream_request_body(conn, ref, data)

      # receive another message which is the echo reply to our hello world
      assert_receive hello_world_echo_message
      {:ok, _conn, [{:data, ^ref, data}]} = Mint.HTTP.stream(conn, hello_world_echo_message)
      assert {:ok, _websocket, [{:text, "hello world"}]} = Mint.WebSocket.decode(websocket, data)
    end
  end
end
