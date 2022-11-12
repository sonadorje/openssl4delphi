unit openssl3.crypto.provider.provider_seeding;

interface
uses OpenSSL.Api;

function ossl_prov_seeding_from_dispatch(fns : POSSL_DISPATCH):integer;
function ossl_prov_get_nonce(prov_ctx : PPROV_CTX; pout : PPByte; min_len, max_len : size_t;const salt : Pointer; salt_len : size_t):size_t;
function ossl_prov_get_entropy( prov_ctx : PPROV_CTX;out pout : PByte; entropy : integer; min_len, max_len : size_t):size_t;
procedure ossl_prov_cleanup_entropy( prov_ctx : PPROV_CTX; buf : PByte; len : size_t);
procedure ossl_prov_cleanup_nonce( prov_ctx : PPROV_CTX; buf : PByte; len : size_t);

var
  c_get_entropy: TOSSL_FUNC_get_entropy_fn  = nil;
  c_cleanup_entropy: TOSSL_FUNC_cleanup_entropy_fn  = nil;
  c_get_nonce: TOSSL_FUNC_get_nonce_fn = Nil;
  c_cleanup_nonce: TOSSL_FUNC_cleanup_nonce_fn  = nil;

implementation
uses OpenSSL3.openssl.core_dispatch, OpenSSL3.providers.common.provider_ctx;


procedure ossl_prov_cleanup_nonce( prov_ctx : PPROV_CTX; buf : PByte; len : size_t);
begin
    if Assigned(c_cleanup_nonce) then
       c_cleanup_nonce(ossl_prov_ctx_get0_handle(prov_ctx), buf, len);
end;

procedure ossl_prov_cleanup_entropy( prov_ctx : PPROV_CTX; buf : PByte; len : size_t);
begin
    if Assigned(c_cleanup_entropy) then
       c_cleanup_entropy(ossl_prov_ctx_get0_handle(prov_ctx), buf, len);
end;




function ossl_prov_get_entropy( prov_ctx : PPROV_CTX;out pout : PByte; entropy : integer; min_len, max_len : size_t):size_t;
begin
    if not Assigned(c_get_entropy) then Exit(0);
    Exit(c_get_entropy(ossl_prov_ctx_get0_handle(prov_ctx),
                         pout, entropy, min_len, max_len));
end;




function ossl_prov_get_nonce(prov_ctx : PPROV_CTX; pout : PPByte; min_len, max_len : size_t;const salt : Pointer; salt_len : size_t):size_t;
begin
    if not Assigned(c_get_nonce) then Exit(0);
    Exit(c_get_nonce(ossl_prov_ctx_get0_handle(prov_ctx), pout,
                       min_len, max_len, salt, salt_len));
end;

function ossl_prov_seeding_from_dispatch(fns : POSSL_DISPATCH):integer;
begin
    while fns.function_id <> 0 do
    begin
        {
         * We do not support the scenario of an application linked against
         * multiple versions of libcrypto (e.g. one static and one dynamic), but
         * sharing a single fips.so. We do a simple sanity check here.
         }
        case fns.function_id of
            OSSL_FUNC_GET_ENTROPY:
            begin
                if not Assigned(c_get_entropy) then
                   c_get_entropy := _OSSL_FUNC_get_entropy(fns)
                else
                if @c_get_entropy <> @_OSSL_FUNC_get_entropy(fns) then
                   Exit(0);
            end;
            OSSL_FUNC_CLEANUP_ENTROPY:
            begin
                if not Assigned(c_cleanup_entropy) then
                   c_cleanup_entropy := _OSSL_FUNC_cleanup_entropy(fns)
                else
                if @c_cleanup_entropy <> @_OSSL_FUNC_cleanup_entropy(fns) then
                   Exit(0);
            end;
            OSSL_FUNC_GET_NONCE:
            begin
                if not Assigned(c_get_nonce) then
                   c_get_nonce := _OSSL_FUNC_get_nonce(fns)
                else
                if @c_get_nonce<> @_OSSL_FUNC_get_nonce(fns) then
                  Exit(0);
            end;
            OSSL_FUNC_CLEANUP_NONCE:
            begin
                if not Assigned(c_cleanup_nonce) then
                   c_cleanup_nonce := _OSSL_FUNC_cleanup_nonce(fns)
                else
                if @c_cleanup_nonce <> @_OSSL_FUNC_cleanup_nonce(fns) then
                   Exit(0);
            end;
        end;
        Inc(fns);
    end;
    Result := 1;
end;



end.
