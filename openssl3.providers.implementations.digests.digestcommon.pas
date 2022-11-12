unit openssl3.providers.implementations.digests.digestcommon;

interface
uses OpenSSL.Api;// openssl3.crypto.sha.sha_local;

const
  PROV_DIGEST_FLAG_XOF             = $0001;
  PROV_DIGEST_FLAG_ALGID_ABSENT    = $0002;

function ossl_digest_default_get_params( params : POSSL_PARAM; blksz, paramsz : size_t; flags : Cardinal):integer;
function ossl_digest_default_gettable_params( provctx : Pointer):POSSL_PARAM;

implementation
uses openssl3.crypto.params, OpenSSL3.Err, OpenSSL3.openssl.params;

var
   digest_default_known_gettable_params: array of TOSSL_PARAM;



function ossl_digest_default_gettable_params( provctx : Pointer):POSSL_PARAM;
begin
    Result := @digest_default_known_gettable_params[0];
end;

function ossl_digest_default_get_params( params : POSSL_PARAM; blksz, paramsz : size_t; flags : Cardinal):integer;
var
  p : POSSL_PARAM;
begin
    p := nil;
    p := OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_BLOCK_SIZE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, blksz)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_SIZE);
    if (p <> nil)  and  (0>= OSSL_PARAM_set_size_t(p, paramsz)) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_XOF);
    if (p <> nil)
         and  (0>= OSSL_PARAM_set_int(p, int( (flags and PROV_DIGEST_FLAG_XOF) <> 0))) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    p := OSSL_PARAM_locate(params, OSSL_DIGEST_PARAM_ALGID_ABSENT);
    if (p <> nil)   and
       (0>= OSSL_PARAM_set_int(p, Int( (flags and PROV_DIGEST_FLAG_ALGID_ABSENT<> 0))))  then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_SET_PARAMETER);
        Exit(0);
    end;
    Result := 1;
end;

initialization
  digest_default_known_gettable_params := [
    _OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_BLOCK_SIZE, nil),
    _OSSL_PARAM_size_t(OSSL_DIGEST_PARAM_SIZE, nil),
    _OSSL_PARAM_int(OSSL_DIGEST_PARAM_XOF, nil),
    _OSSL_PARAM_int(OSSL_DIGEST_PARAM_ALGID_ABSENT, nil),
    OSSL_PARAM_END
];

end.
