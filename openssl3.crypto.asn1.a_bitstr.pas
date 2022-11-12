unit openssl3.crypto.asn1.a_bitstr;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;

function ossl_i2c_ASN1_BIT_STRING( a : PASN1_BIT_STRING; pp : PPByte):integer;
function ossl_c2i_ASN1_BIT_STRING(a : PPASN1_BIT_STRING;const pp : PPByte; len : long):PASN1_BIT_STRING;
function ASN1_BIT_STRING_set( x : PASN1_BIT_STRING; d : PByte; len : integer):integer;
function ASN1_BIT_STRING_set_bit( a : PASN1_BIT_STRING; n, value : integer):integer;
function ASN1_BIT_STRING_get_bit(const a : PASN1_BIT_STRING; n : integer):integer;



implementation

uses
  openssl3.crypto.stack, openssl3.crypto.mem, OpenSSL3.Err,
  openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.asn1_lib;




function ASN1_BIT_STRING_get_bit(const a : PASN1_BIT_STRING; n : integer):integer;
var
  w, v : integer;
begin
    w := n div 8;
    v := 1  shl  (7 - (n and $07));
    if (a = nil)  or  (a.length < (w + 1))  or  (a.data = nil) then
        Exit(0);
    Result := int((a.data[w] and v) <> 0);
end;



function ASN1_BIT_STRING_set_bit( a : PASN1_BIT_STRING; n, value : integer):integer;
var
  w, v, iv : integer;

  c : PByte;
begin
    w := n div 8;
    v := 1  shl  (7 - (n and $07));
    iv := not v;
    if 0>= value then
       v := 0;
    if a = nil then Exit(0);
    a.flags := a.flags and not (ASN1_STRING_FLAG_BITS_LEFT or $07); { clear, set on write }
    if (a.length < (w + 1) )  or  (a.data = nil) then
    begin
        if 0>= value then Exit(1);         { Don't need to set }
        c := OPENSSL_clear_realloc(Pointer(a.data), a.length, w + 1);
        if c = nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        if w + 1 - a.length > 0 then memset(c + a.length, 0, w + 1 - a.length);
        a.data := c;
        a.length := w + 1;
    end;
    a.data[w] := ((a.data[w]) and iv) or v;
    while (a.length > 0)  and  (a.data[a.length - 1] = 0) do
        Dec(a.length);
    Result := 1;
end;

function ASN1_BIT_STRING_set( x : PASN1_BIT_STRING; d : PByte; len : integer):integer;
begin
    Result := ASN1_STRING_set(PASN1_STRING(x), d, len);
end;



function ossl_c2i_ASN1_BIT_STRING(a : PPASN1_BIT_STRING;const pp : PPByte; len : long):PASN1_BIT_STRING;
var
  ret : PASN1_BIT_STRING;
  p, s : PByte;
  i : integer;
  label _err;
begin
    ret := nil;
    if len < 1 then
    begin
        i := ASN1_R_STRING_TOO_SHORT;
        goto _err ;
    end;
    if len > INT_MAX then
    begin
        i := ASN1_R_STRING_TOO_LONG;
        goto _err ;
    end;
    if (a = nil)  or  ( a^ = nil) then
    begin
        ret := ASN1_BIT_STRING_new();
        if (ret) = nil then
            Exit(nil);
    end
    else
        ret := ( a^);
    p := pp^;
    i := PostInc(p)^;
    if i > 7 then
    begin
        i := ASN1_R_INVALID_BIT_STRING_BITS_LEFT;
        goto _err ;
    end;
    {
     * We do this to preserve the settings.  If we modify the settings, via
     * the _set_bit function, we will recalculate on output
     }
    ret.flags := ret.flags and (not (ASN1_STRING_FLAG_BITS_LEFT or $07)); { clear }
    ret.flags  := ret.flags  or ((ASN1_STRING_FLAG_BITS_LEFT or i));
    if PostDec(len )> 1 then
    begin             { using one because of the bits left byte }
        s := OPENSSL_malloc(int (len));
        if s = nil then
        begin
            i := ERR_R_MALLOC_FAILURE;
            goto _err ;
        end;
        memcpy(s, p, int (len));
        s[len - 1] := s[len - 1] and  ($ff  shl  i);
        p  := p + len;
    end
    else
        s := nil;

    ret.length := int(len);
    OPENSSL_free(ret.data);
    ret.data := s;
    ret.&type := V_ASN1_BIT_STRING;
    if a <> nil then a^ := ret;
    pp^ := p;
    Exit(ret);

 _err:
    ERR_raise(ERR_LIB_ASN1, i);
    if (a = nil) or  (a^ <> ret) then
        ASN1_BIT_STRING_free(ret);
    Result := nil;
end;




function ossl_i2c_ASN1_BIT_STRING( a : PASN1_BIT_STRING; pp : PPByte):integer;
var
  ret, j, bits, len : integer;

  p, d : PByte;
begin
    if a = nil then Exit(0);
    len := a.length;
    if len > 0 then
    begin
        if (a.flags and ASN1_STRING_FLAG_BITS_LEFT)>0 then
        begin
            bits := int( a.flags and $07);
        end
        else
        begin
            while len > 0 do
            begin
                if a.data[len - 1]>0 then
                   break;
                 Dec(len);
            end;
            j := a.data[len - 1];
            if (j and $01)>0 then bits := 0
            else if (j and $02) >0 then
                bits := 1
            else if (j and $04) >0 then
                bits := 2
            else if (j and $08)>0 then
                bits := 3
            else if (j and $10) >0 then
                bits := 4
            else if (j and $20) >0 then
                bits := 5
            else if (j and $40) >0 then
                bits := 6
            else if (j and $80) >0 then
                bits := 7
            else
                bits := 0;       { should not happen }
        end;
    end
    else
        bits := 0;
    ret := 1 + len;
    if pp = nil then Exit(ret);
    p := pp^;
    PostInc(p)^ := Byte( bits);
    d := a.data;
    if len > 0 then
    begin
        memcpy(p, d, len);
        p  := p + len;
        p[-1] := p[-1] and ($ff  shl  bits);
    end;
    pp^ := p;
    Result := ret;
end;




end.
