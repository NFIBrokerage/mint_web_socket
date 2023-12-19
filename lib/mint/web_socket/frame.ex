defmodule Mint.WebSocket.Frame do
  @moduledoc false

  # Functions and data structures for describing websocket frames.
  # https://tools.ietf.org/html/rfc6455#section-5.2

  import Record
  alias Mint.WebSocket.{Utils, Extension}
  alias Mint.WebSocketError

  @compile {:inline, apply_mask: 2, apply_mask: 3}

  shared = [{:reserved, <<0::size(3)>>}, :mask, :data, :fin?]

  defrecord :continuation, shared
  defrecord :text, shared
  defrecord :binary, shared
  # > All control frames MUST have a payload length of 125 bytes or less
  # > and MUST NOT be fragmented.
  defrecord :close, shared ++ [:code, :reason]
  defrecord :ping, shared
  defrecord :pong, shared

  @typep continuation_frame() ::
           record(:continuation,
             reserved: <<_::3>>,
             mask: binary(),
             data: binary(),
             fin?: boolean()
           )
  @type text_frame() ::
          record(:text, reserved: <<_::3>>, mask: binary(), data: binary(), fin?: boolean())
  @type binary_frame() ::
          record(:binary, reserved: <<_::3>>, mask: binary(), data: binary(), fin?: boolean())
  @type close_frame() ::
          record(:close,
            reserved: <<_::3>>,
            mask: binary(),
            data: binary(),
            fin?: boolean(),
            code: binary(),
            reason: binary()
          )
  @type ping_frame() ::
          record(:ping, reserved: <<_::3>>, mask: binary(), data: binary(), fin?: boolean())
  @type pong_frame() ::
          record(:pong, reserved: <<_::3>>, mask: binary(), data: binary(), fin?: boolean())

  @type frame_record() ::
          continuation_frame()
          | text_frame()
          | binary_frame()
          | close_frame()
          | ping_frame()
          | pong_frame()

  defguard is_control(frame)
           when is_tuple(frame) and
                  (elem(frame, 0) == :close or elem(frame, 0) == :ping or elem(frame, 0) == :pong)

  defguard is_fin(frame) when elem(frame, 4) == true

  # we can't valiate iodata with a guard but we can sanity check that
  # it's either a binary or a list
  defguardp is_iodata(data) when is_binary(data) or is_list(data)

  # guards frames dealt with in the user-space (not records)
  defguardp is_friendly_frame(frame)
            when frame in [:ping, :pong, :close] or
                   (is_tuple(frame) and elem(frame, 0) in [:text, :ping, :pong] and
                      is_binary(elem(frame, 1))) or
                   (is_tuple(frame) and elem(frame, 0) == :binary and is_iodata(elem(frame, 1))) or
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

  @spec encode(Mint.WebSocket.t(), Mint.WebSocket.shorthand_frame() | Mint.WebSocket.frame()) ::
          {:ok, Mint.WebSocket.t(), iodata()}
          | {:error, Mint.WebSocket.t(), WebSocketError.t()}
  def encode(websocket, frame) when is_friendly_frame(frame) do
    {frame, extensions} =
      frame
      |> translate()
      |> Extension.encode(websocket.extensions)

    websocket = put_in(websocket.extensions, extensions)
    frame = encode_to_iodata(frame)

    {:ok, websocket, frame}
  catch
    :throw, {:mint, reason} -> {:error, websocket, reason}
  end

  @spec encode_to_iodata(frame_record()) :: iodata()
  defp encode_to_iodata(frame) do
    payload = payload(frame)
    mask = mask(frame)
    masked? = if mask == nil, do: 0, else: 1
    encoded_payload_length = encode_payload_length(elem(frame, 0), byte_size(payload))

    [
      # Note this is always a binary despite the small sized bitstrings
      # used to construct the frame. The payload length is either 7, 23 or 71
      # bits so this binary always has bits divisible by 8.
      # (This is important because bitstrings are not valid iodata.)
      <<
        encode_fin(frame)::bitstring,
        reserved(frame)::bitstring,
        encode_opcode(frame)::bitstring,
        masked?::size(1),
        encoded_payload_length::bitstring
      >>,
      mask || <<>>,
      apply_mask(payload, mask)
    ]
  end

  defp payload(close(code: nil, reason: nil)) do
    <<>>
  end

  defp payload(close(code: code, reason: reason)) do
    code = code || 1_000
    reason = reason || ""
    <<code::unsigned-integer-size(8)-unit(2), reason::binary>>
  end

  for type <- Map.keys(@opcodes) -- [:close] do
    defp payload(unquote(type)(data: data)), do: data
  end

  for type <- Map.keys(@opcodes) do
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
  @spec apply_mask(iodata(), binary() | nil) :: iodata()
  def apply_mask(payload, nil), do: payload

  def apply_mask(payload, mask) when is_binary(payload) do
    apply_mask_binary(payload, mask, [])
  end

  def apply_mask(payload, mask) when is_list(payload) do
    apply_mask_iodata(payload, mask, [])
  end

  @spec apply_mask_binary(binary(), binary(), iodata()) :: iodata()
  def apply_mask_binary(payload, mask)

  # n=4 is the happy path
  # n=3..1 catches cases where the remaining byte_size/1 of the payload is shorter
  # than the mask
  for n <- 4..1 do
    def apply_mask_binary(
          <<part_key::integer-size(8)-unit(unquote(n)), payload_rest::binary>>,
          <<mask_key::integer-size(8)-unit(unquote(n)), _::binary>> = mask,
          acc
        ) do
      apply_mask_binary(
        payload_rest,
        mask,
        [<<:erlang.bxor(mask_key, part_key)::integer-size(8)-unit(unquote(n))>> | acc]
      )
    end
  end

  def apply_mask_binary(<<>>, _mask, acc), do: :lists.reverse(acc)

  @spec apply_mask_iodata(iodata(), binary(), iodata()) :: iodata()
  def apply_mask_iodata(_iodata, _mask, _acc) do
    # TODO: encode the payload by applying the mask like with binaries
    # above, but don't switch the payload to a binary to do it.
    :todo
  end

  @spec decode(Mint.WebSocket.t(), binary()) ::
          {:ok, Mint.WebSocket.t(), [Mint.WebSocket.frame() | {:error, term()}]}
          | {:error, Mint.WebSocket.t(), any()}
  def decode(websocket, data) do
    {websocket, frames} = binary_to_frames(websocket, data)

    {websocket, frames} =
      Enum.reduce(frames, {websocket, []}, fn
        {:error, reason}, {websocket, acc} ->
          {websocket, [{:error, reason} | acc]}

        frame, {websocket, acc} ->
          {frame, extensions} = Extension.decode(frame, websocket.extensions)

          {put_in(websocket.extensions, extensions), [translate(frame) | acc]}
      end)

    {:ok, websocket, :lists.reverse(frames)}
  catch
    {:mint, reason} -> {:error, websocket, reason}
  end

  defp binary_to_frames(websocket, data) do
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
        frame = decode_full_frame_binary(opcode, fin, reserved, mask, payload)

        decode_raw(rest, websocket, [frame | acc])

      {:error, reason} ->
        {:ok, :lists.reverse([{:error, reason} | acc])}

      :buffer ->
        {:buffer, data, :lists.reverse(acc)}
    end
  end

  defp decode_raw(<<>>, _websocket, acc), do: {:ok, :lists.reverse(acc)}

  defp decode_raw(partial, _websocket, acc) when is_binary(partial) do
    {:buffer, partial, :lists.reverse(acc)}
  end

  defp decode_payload_and_mask(payload, masked?) do
    with {:ok, payload_length, rest} <- decode_payload_length(payload),
         {:ok, mask, rest} <- decode_mask(rest, masked?),
         <<payload::binary-size(payload_length), more::bitstring>> <- rest do
      {:ok, payload, mask, more}
    else
      partial when is_binary(partial) -> :buffer
      :buffer -> :buffer
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_full_frame_binary(opcode, fin, reserved, mask, payload) do
    with {:ok, opcode} <- decode_opcode(opcode) do
      into_frame(
        opcode,
        _fin? = fin == 0b1,
        reserved,
        mask,
        apply_mask(payload, mask)
      )
    end
  end

  defp decode_opcode(opcode) do
    with :error <- Map.fetch(@reverse_opcodes, opcode) do
      {:error, {:unsupported_opcode, opcode}}
    end
  end

  defp decode_payload_length(
         <<127::integer-size(7), payload_length::unsigned-integer-size(8)-unit(8),
           rest::bitstring>>
       ),
       do: {:ok, payload_length, rest}

  defp decode_payload_length(<<127::integer-size(7), _rest::bitstring>>), do: :buffer

  defp decode_payload_length(
         <<126::integer-size(7), payload_length::unsigned-integer-size(8)-unit(2),
           rest::bitstring>>
       ),
       do: {:ok, payload_length, rest}

  defp decode_payload_length(<<126::integer-size(7), _rest::bitstring>>), do: :buffer

  defp decode_payload_length(<<payload_length::integer-size(7), rest::bitstring>>)
       when payload_length in 0..125,
       do: {:ok, payload_length, rest}

  defp decode_payload_length(malformed) do
    {:error, {:malformed_payload_length, malformed}}
  end

  defp decode_mask(payload, masked?)

  defp decode_mask(<<mask::binary-size(8)-unit(4), rest::bitstring>>, true) do
    {:ok, mask, rest}
  end

  defp decode_mask(payload, false) do
    {:ok, nil, payload}
  end

  defp decode_mask(payload, _masked?) do
    {:error, {:missing_mask, payload}}
  end

  for data_type <- [:continuation, :text, :binary, :ping, :pong] do
    def into_frame(unquote(data_type), fin?, reserved, mask, payload) do
      unquote(data_type)(
        fin?: fin?,
        reserved: reserved,
        mask: mask,
        data: payload
      )
    end
  end

  def into_frame(
        :close,
        fin?,
        reserved,
        mask,
        <<code::unsigned-integer-size(8)-unit(2), reason::binary>> = payload
      )
      when byte_size(reason) in 0..123 and is_valid_close_code(code) do
    if String.valid?(reason) do
      close(reserved: reserved, mask: mask, code: code, reason: reason, fin?: fin?)
    else
      {:error, {:invalid_close_payload, payload}}
    end
  end

  def into_frame(
        :close,
        fin?,
        reserved,
        mask,
        <<>>
      ) do
    close(reserved: reserved, mask: mask, code: 1_000, reason: "", fin?: fin?)
  end

  def into_frame(
        :close,
        _fin?,
        _reserved,
        _mask,
        payload
      ) do
    {:error, {:invalid_close_payload, payload}}
  end

  # translate from user-friendly tuple into record defined in this module
  # (and the reverse)
  @spec translate(Mint.WebSocket.frame() | Mint.WebSocket.shorthand_frame()) :: tuple()
  for opcode <- Map.keys(@opcodes) do
    def translate(unquote(opcode)(reserved: <<reserved::bitstring>>))
        when reserved != <<0::size(3)>> do
      {:error, {:malformed_reserved, reserved}}
    end
  end

  def translate({:error, reason}), do: {:error, reason}

  def translate({:text, text}) do
    text(fin?: true, mask: new_mask(), data: text)
  end

  def translate(text(fin?: true, data: data)) do
    if String.valid?(data) do
      {:text, data}
    else
      {:error, {:invalid_utf8, data}}
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

  def translate(ping(data: data)), do: {:ping, data}

  def translate(:pong), do: translate({:pong, <<>>})

  def translate({:pong, body}) do
    pong(mask: new_mask(), data: body)
  end

  def translate(pong(data: data)), do: {:pong, data}

  def translate(:close) do
    translate({:close, nil, nil})
  end

  def translate({:close, code, reason}) do
    close(mask: new_mask(), code: code, reason: reason, data: <<>>)
  end

  def translate(close(code: code, reason: reason)) do
    {:close, code, reason}
  end

  def translate(continuation()) do
    {:error, :unexpected_continuation}
  end

  @doc """
  Emits frames for any finalized fragments and stores any unfinalized fragments
  in the `:fragment` key in the websocket data structure
  """
  def resolve_fragments(websocket, frames, acc \\ [])

  def resolve_fragments(websocket, [], acc) do
    {websocket, :lists.reverse(acc)}
  end

  def resolve_fragments(websocket, [{:error, reason} | rest], acc) do
    resolve_fragments(websocket, rest, [{:error, reason} | acc])
  end

  def resolve_fragments(websocket, [frame | rest], acc)
      when is_control(frame) and is_fin(frame) do
    resolve_fragments(websocket, rest, [frame | acc])
  end

  def resolve_fragments(websocket, [frame | rest], acc) when is_fin(frame) do
    frame = combine(websocket.fragment, frame)

    put_in(websocket.fragment, nil)
    |> resolve_fragments(rest, [frame | acc])
  end

  def resolve_fragments(websocket, [frame | rest], acc) do
    case combine(websocket.fragment, frame) do
      {:error, reason} ->
        put_in(websocket.fragment, nil)
        |> resolve_fragments(rest, [{:error, reason} | acc])

      frame ->
        put_in(websocket.fragment, frame)
        |> resolve_fragments(rest, acc)
    end
  end

  defp combine(nil, continuation(fin?: true)), do: {:error, :insular_continuation}

  defp combine(nil, frame), do: frame

  for type <- [:continuation, :text, :binary] do
    defp combine(
           unquote(type)(data: frame_data) = frame,
           continuation(data: continuation_data, fin?: fin?)
         ) do
      unquote(type)(frame, data: Utils.maybe_concat(frame_data, continuation_data), fin?: fin?)
    end
  end

  defp combine(a, b), do: {:error, {:cannot_combine_frames, a, b}}
end
