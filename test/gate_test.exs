defmodule GateTest do
  use ExUnit.Case, async: true
  doctest Gate

  setup do
    claims = %{
      "aud" => "User:1",
      "typ" => "token",
      "exp" => Gate.token_expire_at(),
    }

    config = Application.get_env(:gate, Gate)
    algo   = hd(Keyword.get(config, :algo, "HS256"))
    secret = Keyword.get(config, :secret, "secret")

    jose_jws = %{"alg" => algo}
    jose_jwk = %{"kty" => "oct", "k" => :base64url.encode(secret)}

    { _, jwt } = JOSE.JWT.sign(jose_jwk, jose_jws, claims) |> JOSE.JWS.compact

    { :ok, %{
      claims: claims,
      jwt: jwt,
      jose_jws: jose_jws,
      jose_jwk: jose_jwk
    }
  end

end
