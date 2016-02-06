defmodule Gate.Plug.VerifyHeaderTest do
  use ExUnit.Case, async: true

  alias Gate.Plug.VerifyHeader

  setup do
    config = Application.get_env(:guardian, Guardian)
    algo   = hd(Keyword.get(config, :allowed_algos))
    secret = Keyword.get(config, :secret_key)

    jose_jws   = %{"alg" => algo}
    jose_jwk   = %{"kty" => "oct", "k" => :base64url.encode(secret)}
    claims     = Claims.app_claims(%{ "sub" => "user", "aud" => "aud" })
    { _, jwt } = JOSE.JWT.sign(jose_jwk, jose_jws, claims) |> JOSE.JWS.compact

    { :ok, conn: conn(:get, "/"), jwt: jwt, claims: claims, jose_jws: jose_jws, jose_jwk: jose_jwk, secret: secret }
  end

  test "with not JWT in the session", context do
    conn = VerifyHeader.call(context.conn, %{})
  end
end