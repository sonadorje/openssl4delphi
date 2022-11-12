unit OpenSSL3.providers.implementations.kdf_legacy_kmgmt;

interface
uses  OpenSSL.Api;

function kdf_newdata( provctx : Pointer):Pointer;
procedure kdf_freedata( kdfdata : Pointer);
function kdf_has(const keydata : Pointer; selection : integer):integer;

const ossl_kdf_keymgmt_functions: array[0..3] of TOSSL_DISPATCH  = (
    (function_id: OSSL_FUNC_KEYMGMT_NEW; method:(code:@kdf_newdata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_FREE; method:(code:@kdf_freedata ;data:nil)),
    (function_id: OSSL_FUNC_KEYMGMT_HAS; method:(code:@kdf_has ;data:nil)),
    (function_id: 0; method:(code:nil ;data:nil))
);


procedure ossl_kdf_data_free( kdfdata : PKDF_DATA);
function ossl_kdf_data_new( provctx : Pointer):PKDF_DATA;
function ossl_kdf_data_up_ref( kdfdata : PKDF_DATA):integer;

implementation

uses openssl3.include.internal.refcount, openssl3.crypto.mem,
     OpenSSL3.threads_none,              openssl3.providers.common.provider_ctx,
     openssl3.providers.fips.self_test;





function ossl_kdf_data_up_ref( kdfdata : PKDF_DATA):integer;
var
  ref : integer;
begin
    ref := 0;
    { This is effectively doing a new operation on the KDF_DATA and should be
     * adequately guarded again modules' error states.  However, both current
     * calls here are guarded properly in exchange/kdf_exch.c.  Thus, it
     * could be removed here.  The concern is that something in the future
     * might call this function without adequate guards.  It's a cheap call,
     * it seems best to leave it even though it is currently redundant.
     }
    if not ossl_prov_is_running then
       Exit(0);
    CRYPTO_UP_REF(kdfdata.refcnt, ref, kdfdata.lock);
    Result := 1;
end;


function ossl_kdf_data_new( provctx : Pointer):PKDF_DATA;
var
  kdfdata : PKDF_DATA;
begin
    if  not ossl_prov_is_running() then
        Exit(nil);
    kdfdata := OPENSSL_zalloc(sizeof( kdfdata^));
    if kdfdata = nil then Exit(nil);
    kdfdata.lock := CRYPTO_THREAD_lock_new();
    if kdfdata.lock = nil then
    begin
        OPENSSL_free(Pointer(kdfdata));
        Exit(nil);
    end;
    kdfdata.libctx := PROV_LIBCTX_OF(provctx);
    kdfdata.refcnt := 1;
    Result := kdfdata;
end;

procedure ossl_kdf_data_free( kdfdata : PKDF_DATA);
var
  ref : integer;
begin
    ref := 0;
    if kdfdata = nil then exit;
    CRYPTO_DOWN_REF(kdfdata.refcnt, ref, kdfdata.lock);
    if ref > 0 then exit;
    CRYPTO_THREAD_lock_free(kdfdata.lock);
    OPENSSL_free(Pointer(kdfdata));
end;


function kdf_has(const keydata : Pointer; selection : integer):integer;
begin
    result := 1; { nothing is missing }
end;



procedure kdf_freedata( kdfdata : Pointer);
begin
    ossl_kdf_data_free(kdfdata);
end;


function kdf_newdata( provctx : Pointer):Pointer;
begin
    Result := ossl_kdf_data_new(provctx);
end;


end.
