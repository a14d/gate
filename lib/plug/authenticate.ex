defmodule Gate.Plug.Authenticate do
  
  import Plug.Conn

  def init(options), do: options

  def call(conn, _) do
    token = get_session(conn, :gate_token)
    case Gate.verify(token) do
      nil ->
        conn
      {:ok, fields} ->
        conn
          # |> Gate.load_resource(fields["iss"])
          |> put_private(:gate_claims, fields)
      {:error, _} ->
          conn
    end
  end

end