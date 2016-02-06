defmodule Gate do

  # alias Bigdeals.Repo
  # alias Bigdeals.User

  import Plug.Conn

  def api_sign(conn, user, claims \\ %{}) do
    jwt = generate_token(user, %{})
    conn
      |> put_private(:gate_token, jwt)
      |> put_private(:gate_user, user)
  end

  def sign(conn, user, claims \\ %{}) do
    conn
      |> put_session(:gate_token, generate_token(user, claims))
  end

  defp generate_token(user, claims) do
    # JSON Web Token (JWT)
    jwt = %{
      "iss" => "User:#{user.id}",
      "exp" => token_expire_at(),
      #"http://example.com/is_root" => true
    }

    claims = Map.merge(jwt, claims)

    {_, token} = JOSE.JWT.sign(get_jwk, get_jws, claims) |> JOSE.JWS.compact

    Base.encode64(token)
  end

  @doc """
    JSON Web Key (JWK)
  """
  defp get_jwk do
    %{
      "kty" => "oct",
      "k"   => :base64url.encode(token_secret_key())
    }
  end
  
  @doc """
    JSON Web Signature (JWS)
  """
  defp get_jws do
    %{ "alg" => "HS256" }
  end

  @doc false 
  defp token_secret_key() do
    Application.get_env(:gate, :secret_key, "secret")
  end

  def token_expire_at() do
    #:os.system_time() + 100_000_000
    now_secs() + 1000000
  end


  def verify(nil), do: nil

  def verify(jwt_token) do
    case Base.decode64(jwt_token) do
      {:ok, token_decoded} -> 
        case JOSE.JWT.verify(get_jwk, token_decoded) do
          {true, jose_jwt, _} ->
            if (jose_jwt.fields["exp"] > now_secs()) do
              {:ok, jose_jwt.fields}
            else
              {:error, :token_expired}
            end
          {false, _} ->
            {:error}
        end
      :error ->
        {:error, :invalid_token}
    end
  end

  @doc false 
  def load_resource(conn, "User:" <> resource) do
    conn
    |> put_private(:gate_user, Repo.get!(User, resource))
  end

  def sign_out(conn) do
    conn
    |> delete_session(:gate_token)
    |> put_private(:gate_user, nil)
    |> put_private(:gate_claims, nil)
  end




  def claims(conn, key) when is_atom(key) do
    conn.private[:gate_claims][to_string(key)]
  end

  def claims(conn, key) do
    conn.private[:gate_claims][key]
  end

  defp now_secs, do: :os.timestamp() |> time_to_sec()
  defp time_to_sec({mega, sec, micro}) do
    trunc(mega * 1000000 + sec)
  end

end
