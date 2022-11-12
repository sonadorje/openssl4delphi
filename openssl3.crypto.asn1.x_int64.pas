unit openssl3.crypto.asn1.x_int64;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function INT32_it:PASN1_ITEM;
function uint64_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
  procedure uint64_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
  procedure uint64_clear(pval : PPASN1_VALUE;const it : PASN1_ITEM);
  function uint64_i2c(const pval : PPASN1_VALUE; cont : PByte; putype : PInteger;const it : PASN1_ITEM):integer;
  function uint64_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
  function uint64_print(&out : PBIO;const pval : PPASN1_VALUE; it : PASN1_ITEM; indent : integer;const pctx : PASN1_PCTX):integer;
  function uint32_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
  procedure uint32_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
  procedure uint32_clear(pval : PPASN1_VALUE;const it : PASN1_ITEM);
  function uint32_i2c(const pval : PPASN1_VALUE; cont : PByte; putype : PInteger;const it : PASN1_ITEM):integer;
  function uint32_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
  function uint32_print(&out : PBIO;const pval : PPASN1_VALUE;const it : PASN1_ITEM; indent : integer;const pctx : PASN1_PCTX):integer;
  function ZINT32_it:PASN1_ITEM;

const
  ABS_INT32_MIN = (uint32( INT32_MAX) + 1);
  INTxx_FLAG_ZERO_DEFAULT = (1 shl 0);
  INTxx_FLAG_SIGNED       = (1 shl 1);

var
    uint32_pf: TASN1_PRIMITIVE_FUNCS = (
    app_data: nil;
    flags: 0;
    prim_new: uint32_new;
    prim_free: uint32_free;
    prim_clear: uint32_clear;
    prim_c2i: uint32_c2i;
    prim_i2c: uint32_i2c;
    prim_print: uint32_print
);

implementation
uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.asn1.a_int,
    openssl3.crypto.bio.bio_print ;





function ZINT32_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($0, 2, Pointer(0) , 0, @uint32_pf,
                            (1 shl 0) or (1 shl 1), 'ZINT32');
  Result := @local_it;
end;

function INT32_it:PASN1_ITEM;
 const  local_it: TASN1_ITEM = (
    itype: $0;
    utype:  2;
    templates:  Pointer(0) ;
    tcount:  0;
    funcs:  @uint32_pf;
    size: (1 shl 1);
    sname:  'INT32'
 );
begin
   result := @local_it;
end;






function uint64_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
begin
    pval^ := PASN1_VALUE( OPENSSL_zalloc(sizeof(uint64)));
    if pval^ = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    Result := 1;
end;


procedure uint64_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
begin
    OPENSSL_free( pval^);
    pval^ := nil;
end;


procedure uint64_clear(pval : PPASN1_VALUE;const it : PASN1_ITEM);
begin
    PPuint64(pval)^^ := 0;
end;


function uint64_i2c(const pval : PPASN1_VALUE; cont : PByte; putype : PInteger;const it : PASN1_ITEM):integer;
var
  utmp : uint64;

  neg : integer;

  cp : PUTF8Char;
begin
    neg := 0;
    { this exists to bypass broken gcc optimization }
    cp := PUTF8Char(  pval^);
    { use memcpy, because we may not be uint64_t aligned }
    memcpy(@utmp, cp, sizeof(utmp));
    if ( (it.size and INTxx_FLAG_ZERO_DEFAULT) = INTxx_FLAG_ZERO_DEFAULT )
         and  (utmp = 0) then
        Exit(-1);
    if ( (it.size and INTxx_FLAG_SIGNED) = INTxx_FLAG_SIGNED)
         and  (int64( utmp) < 0)  then
    begin
        { ossl_i2c_uint64_int() assumes positive values }
        utmp := 0 - utmp;
        neg := 1;
    end;
    Result := ossl_i2c_uint64_int(cont, utmp, neg);
end;


function uint64_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
var
  utmp : uint64;
  cp : PUTF8Char;
  neg : integer;
  label _long_compat;
begin
    utmp := 0;
    neg := 0;
    if (pval^ = nil)  and  (0>= uint64_new(pval, it))  then
        Exit(0);
    cp := PUTF8Char(pval^);
    {
     * Strictly speaking, zero length is malformed.  However, long_c2i
     * (x_long.c) encodes 0 as a zero length INTEGER (wrongly, of course),
     * so for the sake of backward compatibility, we still decode zero
     * length INTEGERs as the number zero.
     }
    if len = 0 then
       goto _long_compat ;
    if 0>= ossl_c2i_uint64_int(@utmp, @neg, @cont, len) then
        Exit(0);
    if ( (it.size and INTxx_FLAG_SIGNED) = 0)  and  (neg>0) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_NEGATIVE_VALUE);
        Exit(0);
    end;
    if ( (it.size and INTxx_FLAG_SIGNED) = INTxx_FLAG_SIGNED)
             and  (0>= neg)  and  (utmp > INT64_MAX) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LARGE);
        Exit(0);
    end;
    if neg > 0 then { ossl_c2i_uint64_int() returns positive values }
        utmp := 0 - utmp;
 _long_compat:
    memcpy(cp, @utmp, sizeof(utmp));
    Result := 1;
end;


function uint64_print(&out : PBIO;const pval : PPASN1_VALUE; it : PASN1_ITEM; indent : integer;const pctx : PASN1_PCTX):integer;
begin
    if (it.size and INTxx_FLAG_SIGNED) = INTxx_FLAG_SIGNED then
        Exit(BIO_printf(out, '%jd'#10, [PPint64(pval)^^]));
    Result := BIO_printf(out, '%ju'#10, [PPint64(pval)^^]);
end;


function uint32_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
begin
    pval^ := PASN1_VALUE( OPENSSL_zalloc(sizeof(uint32)));
    if pval^ = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    Result := 1;
end;


procedure uint32_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
begin
    OPENSSL_free(pval^);
    pval^ := nil;
end;


procedure uint32_clear(pval : PPASN1_VALUE;const it : PASN1_ITEM);
begin
    PPuint32( pval)^^ := 0;
end;


function uint32_i2c(const pval : PPASN1_VALUE; cont : PByte; putype : PInteger;const it : PASN1_ITEM):integer;
var
  utmp : uint32;

  neg : integer;

  cp : PUTF8Char;
begin
    neg := 0;
    { this exists to bypass broken gcc optimization }
    cp := PUTF8Char(  pval^);
    { use memcpy, because we may not be uint32_t aligned }
    memcpy(@utmp, cp, sizeof(utmp));
    if ( (it.size and INTxx_FLAG_ZERO_DEFAULT) = INTxx_FLAG_ZERO_DEFAULT)
         and  (utmp = 0) then
        Exit(-1);
    if ( (it.size and INTxx_FLAG_SIGNED) = INTxx_FLAG_SIGNED)
         and  (int32( utmp) < 0)  then
    begin
        { ossl_i2c_uint64_int() assumes positive values }
        utmp := 0 - utmp;
        neg := 1;
    end;
    Result := ossl_i2c_uint64_int(cont, uint64( utmp), neg);
end;


function uint32_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
var
  utmp : uint64;
  utmp2 : uint32;
  cp : PUTF8Char;
  neg : integer;
  label _long_compat;
begin
    utmp := 0;
    utmp2 := 0;
    neg := 0;
    if (pval^ = nil)  and  (0>= uint64_new(pval, it)) then
        Exit(0);
    cp := PUTF8Char(pval^);
    {
     * Strictly speaking, zero length is malformed.  However, long_c2i
     * (x_long.c) encodes 0 as a zero length INTEGER (wrongly, of course),
     * so for the sake of backward compatibility, we still decode zero
     * length INTEGERs as the number zero.
     }
    if len = 0 then goto _long_compat ;
    if 0>= ossl_c2i_uint64_int(@utmp, @neg, @cont, len) then
        Exit(0);
    if ( (it.size and INTxx_FLAG_SIGNED) = 0)  and  (neg>0) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_NEGATIVE_VALUE);
        Exit(0);
    end;
    if neg>0 then
    begin
        if utmp > ABS_INT32_MIN then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL);
            Exit(0);
        end;
        utmp := 0 - utmp;
    end
    else
    begin
        if ( ((it.size and INTxx_FLAG_SIGNED) <> 0)  and  (utmp > INT32_MAX) )   or
           ( ((it.size and INTxx_FLAG_SIGNED) = 0 )  and  (utmp > UINT32_MAX))  then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LARGE);
            Exit(0);
        end;
    end;
 _long_compat:
    utmp2 := uint32( utmp);
    memcpy(cp, @utmp2, sizeof(utmp2));
    Result := 1;
end;


function uint32_print(&out : PBIO;const pval : PPASN1_VALUE;const it : PASN1_ITEM; indent : integer;const pctx : PASN1_PCTX):integer;
begin
    if (it.size and INTxx_FLAG_SIGNED ) = INTxx_FLAG_SIGNED then
        Exit(BIO_printf(out, '%d'#10, [PPint32( pval)^^]));
    Result := BIO_printf(out, '%u'#10, [PPuint32( pval)^^]);
end;

end.
