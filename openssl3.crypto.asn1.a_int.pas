unit openssl3.crypto.asn1.a_int;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;

function ossl_i2c_ASN1_INTEGER( a : PASN1_INTEGER; pp : PPByte):integer;
 function i2c_ibuf(const b : PByte; blen : size_t; neg : integer; pp : PPByte):size_t;
 procedure twos_complement(dst : PByte; src : PByte; len : size_t; pad : Byte);
 function ossl_c2i_ASN1_INTEGER(a : PPASN1_INTEGER;const pp : PPByte; len : long):PASN1_INTEGER;
 function c2i_ibuf(b : PByte; pneg : PInteger; p : PByte; plen : size_t):size_t;
 function ASN1_INTEGER_get(const a : PASN1_INTEGER):long;
 function ASN1_INTEGER_get_int64( pr : Pint64;const a : PASN1_INTEGER):integer;
  function asn1_string_get_int64(pr : Pint64;const a : PASN1_STRING; itype : integer):integer;
 function asn1_get_int64(pr : Pint64;const b : PByte; blen : size_t; neg : integer):integer;
 function asn1_get_uint64(pr : Puint64;const b : PByte; blen : size_t):integer;
 function BN_to_ASN1_INTEGER(const bn : PBIGNUM; ai : PASN1_INTEGER):PASN1_INTEGER;
 function bn_to_asn1_string(const bn : PBIGNUM; ai : PASN1_STRING; atype : integer):PASN1_STRING;
 function ASN1_INTEGER_set( a : PASN1_INTEGER; v : long):integer;

  function ASN1_INTEGER_set_int64( a : PASN1_INTEGER; r : int64):integer;
  function ASN1_INTEGER_get_uint64(pr : Puint64;const a : PASN1_INTEGER):integer;
  function ASN1_INTEGER_set_uint64( a : PASN1_INTEGER; r : uint64):integer;
  function asn1_string_set_int64( a : PASN1_STRING; r : int64; itype : integer):integer;
  function asn1_put_uint64( b : PByte; r : uint64):size_t;
  function asn1_string_get_uint64(pr : Puint64;const a : PASN1_STRING; itype : integer):integer;
  function asn1_string_set_uint64( a : PASN1_STRING; r : uint64; itype : integer):integer;
  function ossl_i2c_uint64_int( p : PByte; r : uint64; neg : integer):integer;
  function ossl_c2i_uint64_int(ret : Puint64; neg : PInteger;const pp : PPByte; len : long):integer;
  function ASN1_INTEGER_cmp(const x, y : PASN1_INTEGER):integer;
  function ASN1_INTEGER_to_BN(const ai : PASN1_INTEGER; bn : PBIGNUM):PBIGNUM;
  function asn1_string_to_bn(const ai : PASN1_INTEGER; bn : PBIGNUM; itype : integer):PBIGNUM;
  function ASN1_INTEGER_dup(const x : PASN1_INTEGER):PASN1_INTEGER;
  function ASN1_ENUMERATED_get(const a : PASN1_ENUMERATED):long;
  function ASN1_ENUMERATED_get_int64(pr : Pint64;const a : PASN1_ENUMERATED):integer;
  function ASN1_ENUMERATED_to_BN(const ai : PASN1_ENUMERATED; bn : PBIGNUM):PBIGNUM;



implementation

uses
  openssl3.crypto.stack, OpenSSL3.Err, openssl3.crypto.asn1.asn1_lib,
  openssl3.crypto.asn1.tasn_typ, openssl3.crypto.bn.bn_lib;


function ASN1_ENUMERATED_to_BN(const ai : PASN1_ENUMERATED; bn : PBIGNUM):PBIGNUM;
begin
    Result := asn1_string_to_bn(ai, bn, V_ASN1_ENUMERATED);
end;



function ASN1_ENUMERATED_get_int64(pr : Pint64;const a : PASN1_ENUMERATED):integer;
begin
    Result := asn1_string_get_int64(pr, PASN1_STRING(a), V_ASN1_ENUMERATED);
end;



function ASN1_ENUMERATED_get(const a : PASN1_ENUMERATED):long;
var
  i : integer;

  r : int64;
begin
    if a = nil then Exit(0);
    if (a.&type and not V_ASN1_NEG) <> V_ASN1_ENUMERATED then
        Exit(-1);
    if a.length > int(sizeof(long)) then
        Exit($ffffffff);
    i := ASN1_ENUMERATED_get_int64(@r, a);
    if i = 0 then Exit(-1);
    if (r > LONG_MAX)  or  (r < LONG_MIN) then
       Exit(-1);
    Result := long(r);
end;

function ASN1_INTEGER_dup(const x : PASN1_INTEGER):PASN1_INTEGER;
begin
    Result := PASN1_INTEGER(ASN1_STRING_dup(PASN1_STRING(x)));
end;




function asn1_string_to_bn(const ai : PASN1_INTEGER; bn : PBIGNUM; itype : integer):PBIGNUM;
var
  ret : PBIGNUM;
begin
    if (ai.&type and not V_ASN1_NEG ) <> itype then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_WRONG_INTEGER_TYPE);
        Exit(nil);
    end;
    ret := BN_bin2bn(ai.data, ai.length, bn);
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_BN_LIB);
        Exit(nil);
    end;
    if (ai.&type and V_ASN1_NEG) > 0 then
       BN_set_negative(ret, 1);
    Result := ret;
end;




function ASN1_INTEGER_to_BN(const ai : PASN1_INTEGER; bn : PBIGNUM):PBIGNUM;
begin
    Result := asn1_string_to_bn(ai, bn, V_ASN1_INTEGER);
end;




function ASN1_INTEGER_cmp(const x, y : PASN1_INTEGER):integer;
var
  neg, ret : integer;
begin
    { Compare signs }
    neg := x.&type and V_ASN1_NEG;
    if neg <> (y.&type and V_ASN1_NEG) then
    begin
        if neg > 0 then
            Exit(-1)
        else
            Exit(1);
    end;
    ret := ASN1_STRING_cmp(PASN1_STRING(x), PASN1_STRING(y));
    if neg > 0 then
       Exit(-ret)
    else
       Result := ret;
end;



function ossl_c2i_uint64_int(ret : Puint64; neg : PInteger;const pp : PPByte; len : long):integer;
var
  buf : array[0..sizeof(uint64)-1] of Byte;

  buflen : size_t;
begin
    buflen := c2i_ibuf(nil, nil, pp^, len);
    if buflen = 0 then Exit(0);
    if buflen > sizeof(uint64)  then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LARGE);
        Exit(0);
    end;
    c2i_ibuf(@buf, neg, pp^, len);
    Result := asn1_get_uint64(ret, @buf, buflen);
end;




function ossl_i2c_uint64_int( p : PByte; r : uint64; neg : integer):integer;
var
  buf : array[0..sizeof(uint64)-1] of Byte;
  off : size_t;
begin
    off := asn1_put_uint64(@buf, r);
    Result := i2c_ibuf(PByte(@buf) + off, sizeof(buf) - off, neg, @p);
end;

function asn1_string_set_uint64( a : PASN1_STRING; r : uint64; itype : integer):integer;
var
  tbuf : array[0..(sizeof(r))-1] of Byte;

  off : size_t;
begin
    a.&type := itype;
    off := asn1_put_uint64(@tbuf, r);
    Result := ASN1_STRING_set(a, PByte(@tbuf) + off, sizeof(tbuf) - off);
end;



function asn1_string_get_uint64(pr : Puint64;const a : PASN1_STRING; itype : integer):integer;
begin
    if a = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (a.&type and not V_ASN1_NEG ) <> itype then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_WRONG_INTEGER_TYPE);
        Exit(0);
    end;
    if (a.&type and V_ASN1_NEG)>0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_NEGATIVE_VALUE);
        Exit(0);
    end;
    Result := asn1_get_uint64(pr, a.data, a.length);
end;

function asn1_put_uint64( b : PByte; r : uint64):size_t;
var
  off : size_t;
begin
{$POINTERMATH ON}
    off := sizeof(uint64) ;
    while true do
    begin
        b[PreDec(off)] := Byte( r);
        r := (r  shr 8);
        if r > 0 then
           Continue
    end;

    Result := off;
{$POINTERMATH OFF}
end;



function asn1_string_set_int64( a : PASN1_STRING; r : int64; itype : integer):integer;
var
  tbuf : array[0..(sizeof(r))-1] of Byte;

  off : size_t;
begin
    a.&type := itype;
    if r < 0 then
    begin
        { Most obvious '-r' triggers undefined behaviour for most
         * common INT64_MIN. Even though below '0 - uint64( r' can
         * appear two's-complement centric, it does produce correct/
         * expected result even on one's-complement. This is because
         * cast to unsigned has to change bit pattern... }
        off := asn1_put_uint64(@tbuf, 0 - uint64( r));
        a.&type  := a.&type  or V_ASN1_NEG;
    end
    else
    begin
        off := asn1_put_uint64(@tbuf, r);
        a.&type := a.&type and (not V_ASN1_NEG);
    end;
    Result := ASN1_STRING_set(a, PByte(@tbuf) + off, sizeof(tbuf) - off);
end;

function ASN1_INTEGER_set_int64( a : PASN1_INTEGER; r : int64):integer;
begin
    Result := asn1_string_set_int64(PASN1_STRING(a), r, 2);
end;


function ASN1_INTEGER_get_uint64(pr : Puint64;const a : PASN1_INTEGER):integer;
begin
    Result := asn1_string_get_uint64(pr, PASN1_STRING(a), 2);
end;


function ASN1_INTEGER_set_uint64( a : PASN1_INTEGER; r : uint64):integer;
begin
    Result := asn1_string_set_uint64(PASN1_STRING(a), r, 2);
end;


function ASN1_INTEGER_set( a : PASN1_INTEGER; v : long):integer;
begin
    Result := ASN1_INTEGER_set_int64(a, v);
end;




function bn_to_asn1_string(const bn : PBIGNUM; ai : PASN1_STRING; atype : integer):PASN1_STRING;
var
  ret : PASN1_INTEGER;

  len : integer;
  label _err;
begin
    if ai = nil then
    begin
        ret := PASN1_INTEGER(ASN1_STRING_type_new(atype));
    end
    else
    begin
        ret := PASN1_INTEGER(ai);
        ret.&type := atype;
    end;
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
        goto _err ;
    end;
    if (BN_is_negative(bn)>0)  and  (not BN_is_zero(bn))  then
        ret.&type  := ret.&type  or V_ASN1_NEG_INTEGER;
    len := BN_num_bytes(bn);
    if len = 0 then len := 1;
    if ASN1_STRING_set(PASN1_STRING(ret), nil, len) = 0  then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    { Correct zero case }
    if BN_is_zero(bn ) then
        ret.data[0] := 0
    else
        len := BN_bn2bin(bn, ret.data);
    ret.length := len;
    Exit(PASN1_STRING(ret));
 _err:
    if PASN1_STRING(ret) <> ai then
       ASN1_INTEGER_free(ret);
    Result := nil;
end;

function BN_to_ASN1_INTEGER(const bn : PBIGNUM; ai : PASN1_INTEGER):PASN1_INTEGER;
begin
    Result := PASN1_INTEGER(bn_to_asn1_string(bn, PASN1_STRING(ai), V_ASN1_INTEGER));
end;



function asn1_get_uint64(pr : Puint64;const b : PByte; blen : size_t):integer;
var
  i : size_t;
  r : uint64;
begin
    if blen > sizeof(pr^)  then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LARGE);
        Exit(0);
    end;
    if b = nil then Exit(0);
    r := 0;
    for i := 0 to blen-1 do
    begin
        r  := r shl 8;
        r  := r  or (b[i]);
    end;
    pr^ := r;
    Result := 1;
end;


const ABS_INT64_MIN = (uint64(INT64_MAX) + (-(INT64_MIN + INT64_MAX)));

function asn1_get_int64(pr : Pint64;const b : PByte; blen : size_t; neg : integer):integer;
var
  r : uint64;
begin
    if asn1_get_uint64(@r, b, blen) = 0  then
        Exit(0);
    if neg > 0 then
    begin
        if r <= INT64_MAX then
        begin
            { Most significant bit is guaranteed to be clear, negation
             * is guaranteed to be meaningful in platform-neutral sense. }
            pr^ := -int64( r);
        end
        else
        if (r = ABS_INT64_MIN) then
        begin
            { This never happens if INT64_MAX = ABS_INT64_MIN, e.g.
             * on ones'-complement system. }
            pr^ := int64(0 - r);
        end
        else
        begin
                  ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL);
                  Exit(0);
        end;
    end
    else
    begin
        if r <= INT64_MAX then
        begin
            pr^ := int64( r);
        end
        else
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LARGE);
            Exit(0);
        end;
    end;
    Result := 1;
end;



function asn1_string_get_int64(pr : Pint64;const a : PASN1_STRING; itype : integer):integer;
begin
    if a = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if (a.&type and (not V_ASN1_NEG)) <> itype then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_WRONG_INTEGER_TYPE);
        Exit(0);
    end;
    Result := asn1_get_int64(pr, a.data, a.length, a.&type and V_ASN1_NEG);
end;

function ASN1_INTEGER_get_int64( pr : Pint64;const a : PASN1_INTEGER):integer;
begin
    Result := asn1_string_get_int64(pr, PASN1_STRING(a), V_ASN1_INTEGER);
end;



function ASN1_INTEGER_get(const a : PASN1_INTEGER):long;
var
  i : integer;

  r : int64;
begin
    if a = nil then Exit(0);
    i := ASN1_INTEGER_get_int64(@r, a);
    if i = 0 then Exit(-1);
    if (r > LONG_MAX)  or  (r < LONG_MIN) then
       Exit(-1);
    Result := long(r);
end;




function c2i_ibuf(b : PByte; pneg : PInteger;p : PByte; plen : size_t):size_t;
var
  neg, pad : integer;

  i : size_t;
begin
    { Zero content length is illegal }
    if plen = 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_ZERO_CONTENT);
        Exit(0);
    end;
    neg := p[0] and $80;
    if pneg <> nil then pneg^ := neg;
    { Handle common case where length is 1 octet separately }
    if plen = 1 then
    begin
        if b <> nil then
        begin
            if neg>0 then
                b[0] := (p[0]  xor  $FF) + 1
            else
                b[0] := p[0];
        end;
        Exit(1);
    end;
    pad := 0;
    if p[0] = 0 then
    begin
        pad := 1;
    end
    else if (p[0] = $FF) then
    begin
        {
         * Special case [of 'one less minimal negative' for given length]:
         * if any other bytes non zero it was padded, otherwise not.
         }
         pad := 0;
        for  i := 1 to plen-1 do
            pad  := pad  or (p[i]);
        pad := get_result( pad <> 0 , 1 , 0);
    end;
    { reject illegal padding: first two octets MSB can't match }
    neg := (p[1] and $80);
    if (pad>0)  and  (neg >0) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_PADDING);
        Exit(0);
    end;
    { skip over pad }
    p  := p + pad;
    plen  := plen - pad;
    if b <> nil then
       twos_complement(b, p, plen, get_result(neg>0 , UINT32( $ff) , 0));
    Result := plen;
end;



function ossl_c2i_ASN1_INTEGER(a : PPASN1_INTEGER;const pp : PPByte; len : long):PASN1_INTEGER;
var
  ret : PASN1_INTEGER;

  r : size_t;

  neg : integer;
  label _err;
begin
    ret := nil;
    r := c2i_ibuf(nil, nil, pp^, len);
    if r = 0 then Exit(nil);
    if (a = nil)  or  (a^ = nil) then
    begin
        ret := ASN1_INTEGER_new();
        if ret = nil then Exit(nil);
        ret.&type := V_ASN1_INTEGER;
    end
    else
        ret := a^;
    if ASN1_STRING_set(PASN1_STRING(ret), nil, r ) = 0 then
        goto _err ;
    c2i_ibuf(ret.data, @neg, pp^, len);
    if neg <> 0 then
       ret.&type  := ret.&type  or V_ASN1_NEG
    else
        ret.&type := ret.&type and (not V_ASN1_NEG);
    pp^  := pp^ + len;
    if a <> nil then a^ := ret;
    Exit(ret);
 _err:
    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
    if (a = nil)  or  (a^ <> ret) then
       ASN1_INTEGER_free(ret);
    Result := nil;
end;


procedure twos_complement(dst : PByte; src : PByte; len : size_t; pad : Byte);
var
  carry : uint32;
begin
    carry := pad and 1;
    { Begin at the end of the encoding }
    if len <> 0 then
    begin
        {
         * if len = 0 then src/dst could be nil, and this would be undefined
         * behaviour.
         }
        dst  := dst + len;
        src  := src + len;
    end;
    { two's complement value: ~value + 1 }
    while PostDec(len) <> 0 do
    begin
        carry := carry + PreDec(src)^ xor pad;
        PreDec(dst)^ := carry;
        carry := carry shr  8;
    end;
end;



function i2c_ibuf(const b : PByte; blen : size_t; neg : integer; pp : PPByte):size_t;
var
  pad : uint32;

  ret, i : size_t;
  pb :Byte;
  p : PByte;
begin
    pad := 0;
    pb := 0;
    if (b <> nil)  and  (blen>0) then
    begin
        ret := blen;
        i := b[0];
        if (0>= neg)  and  (i > 127)  then
        begin
            pad := 1;
            pb := 0;
        end
        else
        if (neg>0) then
        begin
            pb := $FF;
            if i > 128 then
            begin
                pad := 1;
            end
            else
            if (i = 128) then
            begin
                {
                 * Special case [of minimal negative for given length]:
                 * if any other bytes non zero we pad, otherwise we don't.
                 }
                pad := 0;
                for  i := 1 to blen-1 do
                    pad  := pad  or (b[i]);
                pb := get_result(pad <> 0 , $ff , 0);
                pad := pb and 1;
            end;
        end;
        ret  := ret + pad;
    end
    else
    begin
        ret := 1;
        blen := 0;   { reduce '(b = nil  or  blen = 0)' to '(blen = 0)' }
    end;
    p := pp^;
    if (pp = nil)  or  (p = nil) then
        Exit(ret);
    {
     * This magically handles all corner cases, such as '(b = nil  or
     * blen = 0)', non-negative value, 'negative' zero, $80 followed
     * by any number of zeros...
     }
    p^ := pb;
    p  := p + pad;
                      { yes, p[0] can be written twice, but it's little
                      price to pay for eliminated branches }
    twos_complement(p, b, blen, pb);
    pp^  := pp^ + ret;
    Result := ret;
end;



function ossl_i2c_ASN1_INTEGER( a : PASN1_INTEGER; pp : PPByte):integer;
begin
    Result := i2c_ibuf(a.data, a.length, a.&type and V_ASN1_NEG, pp);
end;




end.
