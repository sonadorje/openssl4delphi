unit openssl3.crypto.rand.rand_meth;

interface
uses OpenSSL.Api;

function drbg_bytes( _out : PByte; count : integer):integer;
function drbg_seed(const buf : Pointer; num : integer):integer;
function drbg_add(const buf : Pointer; num : integer; randomness : Double):integer;
function drbg_status:integer;
function RAND_OpenSSL:PRAND_METHOD;

const
  ossl_rand_meth: TRAND_METHOD = (
    seed: drbg_seed;
    bytes:drbg_bytes;
    cleanup: nil;
    add: drbg_add;
    pseudorand: drbg_bytes;
    status: drbg_status
);



implementation
uses openssl3.crypto.rand.rand_lib, openssl3.crypto.evp.evp_rand;

function RAND_OpenSSL:PRAND_METHOD;
begin
    Result := @ossl_rand_meth;
end;

function drbg_status:integer;
var
  drbg : PEVP_RAND_CTX;
begin
    drbg := RAND_get0_primary(nil);
    if drbg = nil then Exit(0);
    Result := get_result(EVP_RAND_get_state(drbg) = EVP_RAND_STATE_READY , 1 , 0);
end;

function drbg_add(const buf : Pointer; num : integer; randomness : Double):integer;
var
  drbg : PEVP_RAND_CTX;
begin
    drbg := RAND_get0_primary(nil);
    if (drbg = nil)  or  (num <= 0) then Exit(0);
    Result := EVP_RAND_reseed(drbg, 0, nil, 0, buf, num);
end;

function drbg_bytes( _out : PByte; count : integer):integer;
var
  drbg : PEVP_RAND_CTX;
begin
    drbg := RAND_get0_public(nil);
    if drbg = nil then Exit(0);
    Result := EVP_RAND_generate(drbg, _out, count, 0, 0, nil, 0);
end;

function drbg_seed(const buf : Pointer; num : integer):integer;
begin
    Result := drbg_add(buf, num, num);
end;

end.
