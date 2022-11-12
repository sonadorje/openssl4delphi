unit openssl3.crypto.evp.p_legacy;

interface
uses OpenSSL.Api;

 function EVP_PKEY_set1_RSA( pkey : PEVP_PKEY; const key : Pointer):integer;
 function EVP_PKEY_get0_RSA(const pkey : PEVP_PKEY):PRSA;
 function evp_pkey_get0_RSA_int(const pkey : PEVP_PKEY):PRSA;
 function EVP_PKEY_get0_EC_KEY(const pkey : PEVP_PKEY):PEC_KEY;
 function evp_pkey_get0_EC_KEY_int(const pkey : PEVP_PKEY):PEC_KEY;
 function EVP_PKEY_get1_EC_KEY( pkey : PEVP_PKEY):PEC_KEY;

function EVP_PKEY_get1_RSA( pkey : PEVP_PKEY):PRSA;

implementation


uses openssl3.crypto.evp.p_lib, openssl3.crypto.rsa.rsa_lib, OpenSSL3.Err,
     openssl3.crypto.ec.ec_key;



function EVP_PKEY_get1_RSA( pkey : PEVP_PKEY):PRSA;
var
  ret : PRSA;
begin
    ret := evp_pkey_get0_RSA_int(pkey);
    if ret <> nil then RSA_up_ref(ret);
    Result := ret;
end;

function EVP_PKEY_get1_EC_KEY( pkey : PEVP_PKEY):PEC_KEY;
var
  ret : PEC_KEY;
begin
    ret := evp_pkey_get0_EC_KEY_int(pkey);
    if (ret <> nil)  and  (0>=EC_KEY_up_ref(ret) ) then
        ret := nil;
    Result := ret;
end;




function evp_pkey_get0_EC_KEY_int(const pkey : PEVP_PKEY):PEC_KEY;
begin
    if EVP_PKEY_get_base_id(pkey) <> EVP_PKEY_EC  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_A_EC_KEY);
        Exit(nil);
    end;
    Result := evp_pkey_get_legacy(PEVP_PKEY(pkey));
end;



function EVP_PKEY_get0_EC_KEY(const pkey : PEVP_PKEY):PEC_KEY;
begin
    Result := evp_pkey_get0_EC_KEY_int(pkey);
end;

function evp_pkey_get0_RSA_int(const pkey : PEVP_PKEY):PRSA;
begin
    if (pkey.&type <> EVP_PKEY_RSA)  and  (pkey.&type <> EVP_PKEY_RSA_PSS) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_AN_RSA_KEY);
        Exit(nil);
    end;
    Result := evp_pkey_get_legacy(pkey);
end;




function EVP_PKEY_get0_RSA(const pkey : PEVP_PKEY):PRSA;
begin
    Result := evp_pkey_get0_RSA_int(pkey);
end;

function  EVP_PKEY_assign_RSA( pkey : PEVP_PKEY; rsa: Pointer):integer;
begin
   Result := EVP_PKEY_assign((pkey),EVP_PKEY_RSA, (rsa))
end;

function EVP_PKEY_set1_RSA( pkey : PEVP_PKEY; const key : Pointer):integer;
var
  ret : integer;
begin
    ret := EVP_PKEY_assign_RSA(pkey, key);
    if ret >0 then
       RSA_up_ref(PRSA(key));
    Result := ret;
end;

end.
