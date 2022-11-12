unit openssl3.crypto.asn1.a_dup;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

 function ASN1_dup(i2d : Ti2d_of_void; d2i : Td2i_of_void;const x : Pointer):Pointer;
 function ASN1_item_dup(const it : PASN1_ITEM; x : Pointer):Pointer;

implementation
uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_dec ;

function ASN1_dup(i2d : Ti2d_of_void; d2i : Td2i_of_void;const x : Pointer):Pointer;
var
  b, p, p2 : PByte;
  i : integer;
  ret : PUTF8Char;
begin
    if x = nil then
       Exit(nil);

    i := i2d(x, @p);
    if i <= 0 then
       Exit(nil);
    b := OPENSSL_malloc(i + 10);
    if b = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    p := b;
    i := i2d(x, @p);
    p2 := b;
    ret := d2i(nil, @p2, i);
    OPENSSL_free(b);
    Result := ret;
end;


function ASN1_item_dup(const it : PASN1_ITEM; x : Pointer):Pointer;
var
  asn1_cb : TASN1_aux_cb;
  b, p : PByte;
  i : long;
  ret : PASN1_VALUE;
  libctx : POSSL_LIB_CTX;
  propq : PUTF8Char;
  aux : PASN1_AUX;
  label _auxerr;
begin
    asn1_cb := nil;
    b := nil;
    libctx := nil;
     propq := nil;
    if x = nil then Exit(nil);
    if (it.itype = ASN1_ITYPE_SEQUENCE)  or  (it.itype = ASN1_ITYPE_CHOICE)
         or  (it.itype = ASN1_ITYPE_NDEF_SEQUENCE) then
    begin
        aux := it.funcs;
        if aux <> nil then
           asn1_cb :=  aux.asn1_cb
        else
           asn1_cb :=  nil;
    end;
    if Assigned(asn1_cb) then
    begin
        if (0>= asn1_cb(ASN1_OP_DUP_PRE, PPASN1_VALUE(@x), it, nil))
                 or  (0>= asn1_cb(ASN1_OP_GET0_LIBCTX, PPASN1_VALUE(@x), it, @libctx))
                 or  (0>= asn1_cb(ASN1_OP_GET0_PROPQ,  PPASN1_VALUE(@x), it, @propq)) then
            goto _auxerr ;
    end;
    i := ASN1_item_i2d(x, @b, it);
    if b = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    p := b;
    ret := ASN1_item_d2i_ex(nil, @p, i, it, libctx, propq);
    OPENSSL_free(Pointer(b));
    if ( Assigned(asn1_cb))
         and  (0>= asn1_cb(ASN1_OP_DUP_POST, @ret, it, Pointer( x)) ) then
        goto _auxerr ;
    Exit(ret);
 _auxerr:
    ERR_raise_data(ERR_LIB_ASN1, ASN1_R_AUX_ERROR, Format('Type=%s', [it.sname]));
    Result := nil;
end;

end.
