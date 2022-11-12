unit openssl3.crypto.asn1.asn_pack;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

 function ASN1_item_pack(obj : Pointer;const it : PASN1_ITEM; oct : PPASN1_STRING):PASN1_STRING;
  function ASN1_item_unpack(const oct : PASN1_STRING; it : PASN1_ITEM):Pointer;

implementation
uses openssl3.crypto.evp.evp_lib, OpenSSL3.Err, openssl3.crypto.rand.rand_lib,
     openssl3.crypto.mem, openssl3.crypto.asn1.x_algor,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_dec;






function ASN1_item_pack(obj : Pointer;const it : PASN1_ITEM;oct : PPASN1_STRING):PASN1_STRING;
var
  octmp : PASN1_STRING;
  label _err;
begin
     if (oct = nil)  or  (oct^ = nil) then
     begin
        octmp := ASN1_STRING_new();
        if (octmp) = nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end
    else
    begin
        octmp := oct^;
    end;
    OPENSSL_free(Pointer(octmp.data));
    octmp.data := nil;
    octmp.length := ASN1_item_i2d(obj, @octmp.data, it);
    if octmp.length =  0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ENCODE_ERROR);
        goto _err ;
    end;
    if octmp.data = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    if (oct <> nil)  and  (oct^ = nil) then
       oct^ := octmp;
    Exit(octmp);
 _err:
    if (oct = nil)  or  (oct^ = nil) then
        ASN1_STRING_free(octmp);
    Result := nil;
end;


function ASN1_item_unpack(const oct : PASN1_STRING; it : PASN1_ITEM):Pointer;
var
  p : PByte;

  ret : Pointer;
begin
    p := oct.data;
    ret := ASN1_item_d2i(nil, @p, oct.length, it);
    if ret = nil then
        ERR_raise(ERR_LIB_ASN1, ASN1_R_DECODE_ERROR);
    Result := ret;
end;






end.
