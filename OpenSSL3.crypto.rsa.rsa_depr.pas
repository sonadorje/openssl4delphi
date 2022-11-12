unit OpenSSL3.crypto.rsa.rsa_depr;

interface
uses openssl.api, openssl3.crypto.bn.bn_lib;

function RSA_generate_key( bits : integer; e_value : Cardinal; callback: Tcallback_func1; cb_arg : Pointer):PRSA;

implementation
uses openssl3.crypto.rsa.rsa_lib,         OpenSSL3.crypto.rsa.rsa_gen;

function RSA_generate_key( bits : integer; e_value : Cardinal;
                           callback: Tcallback_func1; cb_arg : Pointer):PRSA;
var
  i, len : integer;
  cb : PBN_GENCB;
  rsa : PRSA;
  e : PBIGNUM;
  label _err;
begin
    cb := BN_GENCB_new;
    rsa := RSA_new;
    e := BN_new;
    if (cb = nil)  or  (rsa = nil)  or  (e = nil) then
       goto _err;
    {
     * The problem is when building with 8, 16, or 32 BN_ULONG, ulong
     * can be larger
     }
    len := int(sizeof(ulong) * 8);
    for i := 0 to len-1 do
    begin
        if e_value and (ulong(1) shl i) > 0 then
            if BN_set_bit(e, i) = 0 then
                goto _err;
    end;
    BN_GENCB_set_old(cb, callback, cb_arg);
    if RSA_generate_key_ex(rsa, bits, e, cb ) > 0 then
    begin
        BN_free(e);
        BN_GENCB_free(cb);
        Exit(rsa);
    end;

 _err:
    BN_free(e);
    RSA_free(rsa);
    BN_GENCB_free(cb);
    Result := nil;
end;


end.
