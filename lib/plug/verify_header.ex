defmodule Gate.Plug.VerifyHeader do

  import Plug.Conn

  def init(options), do: options

  def call(conn, _) do
    conn
    |> get_req_header("Authorization")
    |> check_token(conn)
  end

  defp check_token(_, conn), do: conn
  defp check_token(["Bearer " <> jwt], conn) do
    case Gate.verify(jwt) do
      {:ok, fields} ->
        conn
        # |> Bigdeals.Plugs.Gate.load_resource(fields["iss"])
        |> put_private(:gate_claims, fields)
      {:error, _} ->
        conn
        |> put_resp_content_type("application/json")
        |> send_resp(401, Poison.encode!(%{error: "not authorized"}))
    end
  end

end