unit openssl3.crypto.asn1.a_digest;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ossl_asn1_item_digest_ex(const it : PASN1_ITEM; md : PEVP_MD; asn : Pointer; data : PByte; len : Puint32; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;

implementation
uses openssl3.crypto.asn1.tasn_enc, openssl3.crypto.evp.evp_lib,
     openssl3.crypto.evp.digest, openssl3.crypto.mem,
     openssl3.crypto.engine.tb_digest, openssl3.crypto.engine.eng_init;

function ossl_asn1_item_digest_ex(const it : PASN1_ITEM; md : PEVP_MD; asn : Pointer; data : PByte; len : Puint32; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  i,
  ret        : integer;
  str        : PByte;
  fetched_md : PEVP_MD;
  tmpeng:  PENGINE;
  label _err ;
begin
    ret := 0;
    str := nil;
    fetched_md := PEVP_MD (md);
    i := ASN1_item_i2d(asn, @str, it);
    if (i < 0)  or  (str = nil) then Exit(0);
    if EVP_MD_get0_provider(md) = nil  then
    begin
{$IF not defined(OPENSSL_NO_ENGINE)}
        tmpeng := ENGINE_get_digest_engine(EVP_MD_get_type(md));
        if tmpeng <> nil then
           ENGINE_finish(tmpeng)
        else
{$ENDIF}
            fetched_md := EVP_MD_fetch(libctx, EVP_MD_get0_name(md), propq);
    end;
    if fetched_md = nil then goto _err;
    ret := EVP_Digest(str, i, data, len, fetched_md, nil);
_err:
    OPENSSL_free(str);
    if fetched_md <> md then EVP_MD_free(fetched_md);
    Result := ret;
end;

end.
