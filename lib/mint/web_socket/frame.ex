defmodule Mint.WebSocket.Frame do
  @moduledoc false

  # Functions and data structures for describing websocket frames.
  # https://tools.ietf.org/html/rfc6455#section-5.2

  shared = [{:reserved, <<0::size(3)>>}, :mask, :data]

  import Record
  alias Mint.WebSocket.{Utils, Extension}
  alias Mint.WebSocketError

  defrecord :continuation, shared ++ [:fin?]
  defrecord :text, shared ++ [:fin?]
  defrecord :binary, shared ++ [:fin?]
  # > All control frames MUST have a payload length of 125 bytes or less
  # > and MUST NOT be fragmented.
  defrecord :close, shared ++ [:code, :reason]
  defrecord :ping, shared
  defrecord :pong, shared

  defguard is_control(frame)
           when is_tuple(frame) and
                  (elem(frame, 0) == :close or elem(frame, 0) == :ping or elem(frame, 0) == :pong)

  defguard is_fin(frame)
           when (elem(frame, 0) in [:continuation, :text, :binary] and elem(frame, 4) == true) or
                  is_control(frame)

  # guards frames dealt with in the user-space (not records)
  defguardp is_friendly_frame(frame)
            when frame in [:ping, :pong, :close] or
                   (is_tuple(frame) and elem(frame, 0) in [:text, :binary, :ping, :pong] and
                      is_binary(elem(frame, 1))) or
                   (is_tuple(frame) and elem(frame, 0) == :close and is_integer(elem(frame, 1)) and
                      is_binary(elem(frame, 2)))

  # https://tools.ietf.org/html/rfc6455#section-7.4.1
  @invalid_status_codes [1_004, 1_005, 1_006, 1_016, 1_100, 2_000, 2_999]
  # https://tools.ietf.org/html/rfc6455#section-7.4.2
  defguardp is_valid_close_code(code)
            when code in 1_000..4_999 and code not in @invalid_status_codes

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

  def opcodes, do: Map.keys(@opcodes)

  def new_mask, do: :crypto.strong_rand_bytes(4)

  def encode(websocket, frame) when is_friendly_frame(frame) do
    {frame, extensions} =
      frame
      |> translate()
      |> Extension.encode(websocket.extensions)

    websocket = put_in(websocket.extensions, extensions)
    frame = encode_to_binary(frame)

    {:ok, websocket, frame}
  catch
    :throw, {:mint, reason} -> {:error, websocket, reason}
  end

  @spec encode_to_binary(tuple()) :: binary()
  defp encode_to_binary(frame) do
    payload = payload(frame)
    mask = mask(frame)
    masked? = if mask == nil, do: 0, else: 1
    encoded_payload_length = encode_payload_length(elem(frame, 0), byte_size(payload))

    <<
      encode_fin(frame)::bitstring,
      reserved(frame)::bitstring,
      encode_opcode(frame)::bitstring,
      masked?::size(1),
      encoded_payload_length::bitstring,
      mask || <<>>::binary,
      encode_data(frame, payload, mask)::bitstring
    >>
  end

  defp encode_data(close(code: code, reason: reason), _payload, mask) do
    encode_close(code, reason)
    |> apply_mask(mask)
  end

  defp encode_data(_frame, payload, mask) do
    apply_mask(payload, mask)
  end

  defp encode_close(code, reason) do
    code = code || 1_000
    reason = reason || ""
    <<code::unsigned-integer-size(8)-unit(2), reason::binary>>
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
    <<length::integer-size(7)>>
  end

  def encode_payload_length(opcode, length)
      when length in 126..65_535 and opcode in @non_control_opcodes do
    <<126::integer-size(7), length::unsigned-integer-size(8)-unit(2)>>
  end

  def encode_payload_length(opcode, length)
      when length in 65_535..9_223_372_036_854_775_807 and opcode in @non_control_opcodes do
    <<127::integer-size(7), length::unsigned-integer-size(8)-unit(8)>>
  end

  def encode_payload_length(_opcode, _length) do
    throw({:mint, %WebSocketError{reason: :payload_too_large}})
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

  @spec decode(Mint.WebSocket.t(), binary()) ::
          {:ok, Mint.WebSocket.t(), [Mint.WebSocket.frame()]}
          | {:error, Mint.WebSocket.t(), any()}
  def decode(websocket, data) do
    {websocket, frames} = _decode(websocket, data)

    {websocket, frames} =
      Enum.reduce(frames, {websocket, []}, fn frame, {websocket, acc} ->
        {frame, extensions} = Extension.decode(frame, websocket.extensions)

        {put_in(websocket.extensions, extensions), [frame | acc]}
      end)

    {:ok, websocket, frames |> :lists.reverse() |> Enum.map(&translate/1)}
  catch
    :throw, {:mint, reason} -> {:error, websocket, reason}
  end

  defp _decode(websocket, data) do
    case websocket.buffer |> Utils.maybe_concat(data) |> decode_raw(websocket, []) do
      {:ok, frames} ->
        {websocket, frames} = resolve_fragments(websocket, frames)
        {put_in(websocket.buffer, <<>>), frames}

      {:buffer, partial, frames} ->
        {websocket, frames} = resolve_fragments(websocket, frames)
        {put_in(websocket.buffer, partial), frames}
    end
  end

  defp decode_raw(
         <<fin::size(1), reserved::bitstring-size(3), opcode::bitstring-size(4), masked::size(1),
           payload_and_mask::bitstring>> = data,
         websocket,
         acc
       ) do
    case decode_payload_and_mask(payload_and_mask, masked == 0b1) do
      {:ok, payload, mask, rest} ->
        decode_raw(rest, websocket, [
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

  defp decode_raw(<<>>, _websocket, acc), do: {:ok, :lists.reverse(acc)}

  defp decode_raw(partial, _websocket, acc) when is_binary(partial) do
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
    with {payload_length, rest} <- decode_payload_length(payload),
         {mask, rest} <- decode_mask(rest, masked?),
         <<payload::binary-size(payload_length), more::bitstring>> <- rest do
      {:ok, payload, mask, more}
    else
      partial when is_binary(partial) -> :buffer
      :buffer -> :buffer
    end
  end

  defp decode_payload_length(
         <<127::integer-size(7), payload_length::unsigned-integer-size(8)-unit(8),
           rest::bitstring>>
       ),
       do: {payload_length, rest}

  defp decode_payload_length(<<127::integer-size(7)>>), do: :buffer

  defp decode_payload_length(
         <<126::integer-size(7), payload_length::unsigned-integer-size(8)-unit(2),
           rest::bitstring>>
       ),
       do: {payload_length, rest}

  defp decode_payload_length(<<126::integer-size(7)>>), do: :buffer

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
        <<code::unsigned-integer-size(8)-unit(2), reason::binary>> = payload
      )
      when byte_size(reason) in 0..123 and is_valid_close_code(code) do
    if String.valid?(reason) do
      close(reserved: reserved, mask: mask, code: code, reason: reason)
    else
      throw({:mint, {:invalid_close_payload, payload}})
    end
  end

  def decode(
        :close,
        _fin?,
        reserved,
        mask,
        <<>>
      ) do
    close(reserved: reserved, mask: mask, code: 1_000, reason: "")
  end

  def decode(
        :close,
        _fin?,
        _reserved,
        _mask,
        payload
      ) do
    throw({:mint, {:invalid_close_payload, payload}})
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
  for opcode <- Map.keys(@opcodes) do
    def translate(unquote(opcode)(reserved: <<reserved::bitstring>>))
        when reserved != <<0::size(3)>> do
      throw({:mint, :malformed_reserved})
    end
  end

  def translate({:text, text}) do
    text(fin?: true, mask: new_mask(), data: text)
  end

  def translate(text(fin?: true, data: data)) do
    if String.valid?(data) do
      {:text, data}
    else
      throw({:mint, {:invalid_utf8, data}})
    end
  end

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
    close(mask: new_mask(), code: code, reason: reason, data: <<>>)
  end

  def translate(close(code: nil, reason: nil)), do: :close

  def translate(close(code: 1_000, reason: "")), do: :close

  def translate(close(code: code, reason: reason)) do
    {:close, code, reason}
  end

  for type <- [:continuation, :text, :binary] do
    def combine(
          unquote(type)(data: frame_data) = frame,
          continuation(data: continuation_data, fin?: fin?)
        ) do
      unquote(type)(frame, data: frame_data <> continuation_data, fin?: fin?)
    end
  end

  @doc """
  Emits frames for any finalized fragments and stores any unfinalized fragments
  in the `:fragments` key in the websocket
  """
  def resolve_fragments(websocket, frames, acc \\ [])

  def resolve_fragments(websocket, [], acc) do
    {websocket, :lists.reverse(acc)}
  end

  def resolve_fragments(websocket, [frame | rest], acc) when is_control(frame) do
    resolve_fragments(websocket, rest, [frame | acc])
  end

  def resolve_fragments(websocket, [frame | rest], acc) when is_fin(frame) do
    frame = combine_frames([frame | websocket.fragments])

    put_in(websocket.fragments, [])
    |> resolve_fragments(rest, [frame | acc])
  end

  def resolve_fragments(websocket, [frame | rest], acc) do
    update_in(websocket.fragments, &[frame | &1])
    |> resolve_fragments(rest, acc)
  end

  defp combine_frames([continuation()]) do
    throw({:mint, :uninitiated_continuation})
  end

  defp combine_frames([full_frame]) do
    full_frame
  end

  defp combine_frames([continuation() = continuation, prior_fragment | rest]) do
    combine_frames([combine(prior_fragment, continuation) | rest])
  end

  defp combine_frames(_out_of_order_fragments) do
    throw({:mint, :out_of_order_fragments})
  end
end
