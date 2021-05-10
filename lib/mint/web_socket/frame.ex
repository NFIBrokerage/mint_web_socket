defmodule Mint.WebSocket.Frame do
  @moduledoc false

  # Functions and data structures for describing websocket frames.
  # https://tools.ietf.org/html/rfc6455#section-5.2

  shared = [{:reserved, <<0::size(3)>>}, :mask, :data]

  import Record

  defrecord :continuation, shared ++ [:fin?]
  defrecord :text, shared ++ [:fin?]
  defrecord :binary, shared ++ [:fin?]
  # > All control frames MUST have a payload length of 125 bytes or less
  # > and MUST NOT be fragmented.
  defrecord :close, shared ++ [:code, :reason]
  defrecord :ping, shared
  defrecord :pong, shared

  defguard is_control(frame) when elem(frame, 0) in [:close, :ping, :pong]

  defguard is_fin(frame)
           when (elem(frame, 0) in [:continuation, :text, :binary] and elem(frame, 4) == true) or
                  is_control(frame)

  @opcodes %{
    # non-control opcodes:
    continuation: <<0x0::size(4)>>,
    text: <<0x1::size(4)>>,
    binary: <<0x2::size(4)>>,
    # 0x3-7 reserved for future non-control frames
    # control opcodes:
    close: <<0x8::size(4)>>,
    ping: <<0x9::size(4)>>,
    pong: <<0xA::size(4)>>
    # 0xB-F reserved for future control frames
  }
  @reverse_opcodes Map.new(@opcodes, fn {k, v} -> {v, k} end)
  @non_control_opcodes [:continuation, :text, :binary]

  def new_mask, do: :crypto.strong_rand_bytes(4)

  @spec encode(tuple()) :: {:ok, binary()} | {:error, :payload_too_large}
  def encode(frame) do
    payload = payload(frame)
    mask = mask(frame)
    masked? = if mask == nil, do: 0, else: 1

    with {:ok, encoded_payload_length} <-
           encode_payload_length(elem(frame, 0), byte_size(payload)) do
      {:ok,
       <<
         encode_fin(frame)::bitstring,
         reserved(frame)::bitstring,
         encode_opcode(frame)::bitstring,
         masked?::size(1),
         encoded_payload_length::bitstring,
         mask || <<>>::binary,
         apply_mask(payload, mask)::bitstring
       >>}
    end
  end

  for type <- Map.keys(@opcodes) do
    defp payload(unquote(type)(data: data)), do: data
    defp mask(unquote(type)(mask: mask)), do: mask
    defp reserved(unquote(type)(reserved: reserved)), do: reserved
  end

  defp encode_fin(text(fin?: false)), do: <<0b0::size(1)>>
  defp encode_fin(binary(fin?: false)), do: <<0b0::size(1)>>
  defp encode_fin(continuation(fin?: false)), do: <<0b0::size(1)>>
  defp encode_fin(_), do: <<0b1::size(1)>>

  defp encode_opcode(frame), do: @opcodes[elem(frame, 0)]

  def encode_payload_length(_opcode, length) when length in 0..125 do
    {:ok, <<length::integer-size(7)>>}
  end

  def encode_payload_length(opcode, length)
      when length in 126..65_535 and opcode in @non_control_opcodes do
    {:ok, <<126::integer-size(7), length::unsigned-integer-size(8)-unit(2)>>}
  end

  def encode_payload_length(opcode, length)
      when length in 65_535..9_223_372_036_854_775_807 and opcode in @non_control_opcodes do
    {:ok, <<127::integer-size(7), length::unsigned-integer-size(8)-unit(8)>>}
  end

  def encode_payload_length(_opcode, _length) do
    {:error, :payload_too_large}
  end

  # Mask the payload by bytewise XOR-ing the payload bytes against the mask
  # bytes (where the mask bytes repeat).
  # This is an "involution" function: applying the mask will mask
  # the data and applying the mask again will unmask it.
  def apply_mask(payload, nil), do: payload

  def apply_mask(payload, _mask = <<a, b, c, d>>) do
    [a, b, c, d]
    |> Stream.cycle()
    |> Enum.reduce_while({payload, _acc = <<>>}, fn
      _mask_key, {<<>>, acc} ->
        {:halt, acc}

      mask_key, {<<part_key::integer, payload_rest::binary>>, acc} ->
        {:cont, {payload_rest, <<acc::binary, Bitwise.bxor(mask_key, part_key)::integer>>}}
    end)
  end

  @spec decode(binary()) :: {:ok, [tuple()]} | {:error, atom()} | :buffer
  def decode(data) do
    decode_raw(data, [])
  catch
    :throw, {:mint, reason} -> {:error, reason}
  end

  defp decode_raw(
         <<fin::size(1), reserved::bitstring-size(3), opcode::bitstring-size(4), masked::size(1),
           payload_and_mask::bitstring>> = data,
         acc
       ) do
    case decode_payload_and_mask(payload_and_mask, masked == 0b1) do
      {:ok, payload, mask, rest} ->
        decode_raw(rest, [
          decode(
            decode_opcode(opcode),
            fin == 0b1,
            reserved,
            mask,
            apply_mask(payload, mask)
          )
          | acc
        ])

      :buffer ->
        {:buffer, data, :lists.reverse(acc)}
    end
  end

  defp decode_raw(<<>>, acc), do: {:ok, :lists.reverse(acc)}

  defp decode_raw(partial, acc) when is_binary(partial) do
   {:buffer, partial, :lists.reverse(acc)}
  end

  defp decode_opcode(opcode) do
    case Map.fetch(@reverse_opcodes, opcode) do
      {:ok, opcode_atom} ->
        opcode_atom

      :error ->
        throw({:mint, {:unsupported_opcode, opcode}})
    end
  end

  defp decode_payload_and_mask(payload, masked?) do
    {payload_length, rest} = decode_payload_length(payload)
    {mask, rest} = decode_mask(rest, masked?)

    case rest do
      <<payload::binary-size(payload_length), more::bitstring>> ->
        {:ok, payload, mask, more}

      partial when is_binary(partial) ->
        :buffer
    end
  end

  defp decode_payload_length(
         <<127::integer-size(7), payload_length::unsigned-integer-size(8)-unit(8),
           rest::bitstring>>
       ),
       do: {payload_length, rest}

  defp decode_payload_length(
         <<126::integer-size(7), payload_length::unsigned-integer-size(8)-unit(2),
           rest::bitstring>>
       ),
       do: {payload_length, rest}

  defp decode_payload_length(<<payload_length::integer-size(7), rest::bitstring>>)
       when payload_length in 0..125,
       do: {payload_length, rest}

  defp decode_payload_length(malformed) do
    throw({:mint, {:malformed_payload_length, malformed}})
  end

  defp decode_mask(<<mask::binary-size(8)-unit(4), rest::bitstring>>, _masked? = true) do
    {mask, rest}
  end

  defp decode_mask(payload, _masked? = false) do
    {nil, payload}
  end

  defp decode_mask(payload, _masked?) do
    throw({:mint, {:missing_mask, payload}})
  end

  for data_type <- [:continuation, :text, :binary] do
    def decode(unquote(data_type), fin?, reserved, mask, payload) do
      unquote(data_type)(
        fin?: fin?,
        reserved: reserved,
        mask: mask,
        data: payload
      )
    end
  end

  def decode(
        :close,
        _fin?,
        reserved,
        mask,
        <<code::unsigned-integer-size(8)-unit(2), reason::binary>>
      ) do
    close(reserved: reserved, mask: mask, code: code, reason: reason)
  end

  def decode(
        :close,
        _fin?,
        reserved,
        mask,
        _payload
      ) do
    close(reserved: reserved, mask: mask)
  end

  def decode(:ping, _fin?, reserved, mask, payload) do
    ping(reserved: reserved, mask: mask, data: payload)
  end

  def decode(:pong, _fin?, reserved, mask, payload) do
    pong(reserved: reserved, mask: mask, data: payload)
  end

  # translate from user-friendly tuple into record defined in this module
  # (and the reverse)
  @spec translate(Mint.WebSocket.frame()) :: tuple()
  @spec translate(tuple) :: Mint.WebSocket.frame()
  def translate({:text, text}) do
    text(fin?: true, mask: new_mask(), data: text)
  end

  def translate(text(fin?: true, data: data)), do: {:text, data}

  def translate({:binary, binary}) do
    binary(fin?: true, mask: new_mask(), data: binary)
  end

  def translate(binary(fin?: true, data: data)), do: {:binary, data}

  def translate(:ping), do: translate({:ping, <<>>})

  def translate({:ping, body}) do
    ping(mask: new_mask(), data: body)
  end

  def translate(ping(data: <<>>)), do: :ping

  def translate(ping(data: data)), do: {:ping, data}

  def translate(:pong), do: translate({:pong, <<>>})

  def translate({:pong, body}) do
    pong(mask: new_mask(), data: body)
  end

  def translate(pong(data: <<>>)), do: :pong

  def translate(pong(data: data)), do: {:pong, data}

  def translate(:close) do
    close(mask: new_mask(), data: <<>>)
  end

  def translate({:close, code, reason})
      when is_integer(code) and is_binary(reason) do
    close(mask: new_mask(), data: encode_close(code, reason))
  end

  def translate(close(code: nil, reason: nil)), do: :close

  def translate(close(code: code, reason: reason)) do
    {:close, code, reason}
  end

  defp encode_close(code, reason) do
    <<code::unsigned-integer-size(8)-unit(2), reason::binary>>
  end

  for type <- Map.keys(@opcodes) do
    def combine(unquote(type)(data: frame_data), continuation(data: continuation_data)) do
      unquote(type)(data: frame_data <> continuation_data)
    end
  end
end
