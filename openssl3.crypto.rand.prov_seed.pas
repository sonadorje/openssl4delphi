unit openssl3.crypto.rand.prov_seed;

interface
uses OpenSSL.Api, openssl3.crypto.mem;

function ossl_rand_get_entropy( handle : POSSL_CORE_HANDLE; pout : PPByte; entropy : integer; min_len, max_len : size_t):size_t;
  procedure ossl_rand_cleanup_entropy( handle : POSSL_CORE_HANDLE; buf : PByte; len : size_t);
  function ossl_rand_get_nonce(handle : POSSL_CORE_HANDLE; pout : PPByte; min_len, max_len : size_t;const salt : Pointer; salt_len : size_t):size_t;
  procedure ossl_rand_cleanup_nonce( handle : POSSL_CORE_HANDLE; buf : PByte; len : size_t);

implementation
uses openssl3.crypto.rand.rand_pool, OpenSSL3.Err,
     OpenSSL3.providers.implementations.rands.seeding.rand_win,   openssl3.include.openssl.crypto ;

function ossl_rand_get_entropy( handle : POSSL_CORE_HANDLE; pout : PPByte; entropy : integer; min_len, max_len : size_t):size_t;
var
  ret,
  entropy_available : size_t;
  pool              : PRAND_POOL;
begin
    ret := 0;
    pool := ossl_rand_pool_new(entropy, 1, min_len, max_len);
    if pool = nil then begin
        ERR_raise(ERR_LIB_RAND, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    { Get entropy by polling system entropy sources. }
    entropy_available := ossl_pool_acquire_entropy(pool);
    if entropy_available > 0 then
    begin
        ret := ossl_rand_pool_length(pool);
        pout^ := ossl_rand_pool_detach(pool);
    end;
    ossl_rand_pool_free(pool);
    Result := ret;
end;


procedure ossl_rand_cleanup_entropy( handle : POSSL_CORE_HANDLE; buf : PByte; len : size_t);
begin
    OPENSSL_secure_clear_free(buf, len);
end;


function ossl_rand_get_nonce(handle : POSSL_CORE_HANDLE; pout : PPByte; min_len, max_len : size_t;const salt : Pointer; salt_len : size_t):size_t;
var
  ret : size_t;
  pool : PRAND_POOL;
  label _err;
begin
    ret := 0;
    pool := ossl_rand_pool_new(0, 0, min_len, max_len);
    if pool = nil then begin
        ERR_raise(ERR_LIB_RAND, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if 0>=ossl_pool_add_nonce_data(pool) then
        goto _err;
    if (salt <> nil)  and  (0>=ossl_rand_pool_add(pool, salt, salt_len, 0)) then
        goto _err;
    ret := ossl_rand_pool_length(pool);
    pout^ := ossl_rand_pool_detach(pool);
 _err:
    ossl_rand_pool_free(pool);
    Result := ret;
end;


procedure ossl_rand_cleanup_nonce( handle : POSSL_CORE_HANDLE; buf : PByte; len : size_t);
begin
    OPENSSL_clear_free(Pointer(buf), len);
end;



end.
