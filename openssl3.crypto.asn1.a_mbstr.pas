unit openssl3.crypto.asn1.a_mbstr;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

type
  Trfunc = function( value : Cardinal; _in : Pointer):integer;

  function ASN1_mbstring_copy(_out : PPASN1_STRING;const _in : PByte; len, inform : integer; mask : Cardinal):integer;
  function ASN1_mbstring_ncopy(_out : PPASN1_STRING;const _in : PByte; len, inform : integer; mask : Cardinal; minsize, maxsize : long):integer;
  function traverse_string(p : PByte; len, inform : integer; rfunc : Trfunc; arg : Pointer):integer;
  function in_utf8( value : Cardinal; arg : Pointer):integer;
  function out_utf8( value : Cardinal; arg : Pointer):integer;
  function type_str( value : Cardinal; arg : Pointer):integer;
  function cpy_asc( value : Cardinal; arg : Pointer):integer;
  function cpy_bmp( value : Cardinal; arg : Pointer):integer;
  function cpy_univ( value : Cardinal; arg : Pointer):integer;
  function cpy_utf8( value : Cardinal; arg : Pointer):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.a_utf8, openssl3.crypto.ctype;

function ASN1_mbstring_copy(_out : PPASN1_STRING;const _in : PByte; len, inform : integer; mask : Cardinal):integer;
begin
    Result := ASN1_mbstring_ncopy(_out, _in, len, inform, mask, 0, 0);
end;


function ASN1_mbstring_ncopy(_out : PPASN1_STRING;const _in : PByte; len, inform : integer; mask : Cardinal; minsize, maxsize : long):integer;
type
   Tcpyfunc = function( p1 : Cardinal; p2 : Pointer):integer;
var
  str_type,
  ret      : integer;
  free_out : byte;
  outform,
  outlen   : integer;
  dest     : PASN1_STRING;
  p        : PByte;
  nchar    : integer;
  cpyfunc : Tcpyfunc ;
begin
    outlen := 0;
    cpyfunc := nil;
    if len = -1 then
       len := Length(PUTF8Char(  _in));
    if 0>= mask then
       mask := DIRSTRING_TYPE;
    if len < 0 then Exit(-1);
    { First do a string check and work out the number of UTF8Characters }
    case inform of
    MBSTRING_BMP:
    begin
        if (len and 1) > 0 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_BMPSTRING_LENGTH);
            Exit(-1);
        end;
        nchar := len  shr  1;
    end;
    MBSTRING_UNIV:
    begin
        if (len and 3) > 0 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_UNIVERSALSTRING_LENGTH);
            Exit(-1);
        end;
        nchar := len  shr  2;
    end;
    MBSTRING_UTF8:
    begin
        nchar := 0;
        { This counts the characters and does utf8 syntax checking }
        ret := traverse_string(_in, len, MBSTRING_UTF8, in_utf8, @nchar);
        if ret < 0 then begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_UTF8STRING);
            Exit(-1);
        end;
    end;
    MBSTRING_ASC:
        nchar := len;
        //break;
    else
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_FORMAT);
        Exit(-1);
    end;
    end;
    if (minsize > 0 )  and  (nchar < minsize) then
    begin
        ERR_raise_data(ERR_LIB_ASN1, ASN1_R_STRING_TOO_SHORT,
                      Format( 'minsize=%ld', [minsize]));
        Exit(-1);
    end;
    if (maxsize > 0)  and  (nchar > maxsize) then
    begin
        ERR_raise_data(ERR_LIB_ASN1, ASN1_R_STRING_TOO_LONG,
                       Format( 'maxsize=%ld', [maxsize]));
        Exit(-1);
    end;
    { Now work out minimal type (if any) }
    if traverse_string(_in, len, inform, type_str, @mask ) < 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_CHARACTERS);
        Exit(-1);
    end;
    { Now work out output format and string type }
    outform := MBSTRING_ASC;
    if (mask and B_ASN1_NUMERICSTRING) > 0 then
       str_type := V_ASN1_NUMERICSTRING
    else if (mask and B_ASN1_PRINTABLESTRING) > 0 then
        str_type := V_ASN1_PRINTABLESTRING
    else if (mask and B_ASN1_IA5STRING) > 0 then
        str_type := V_ASN1_IA5STRING
    else if (mask and B_ASN1_T61STRING) > 0 then
        str_type := V_ASN1_T61STRING
    else if (mask and B_ASN1_BMPSTRING) > 0 then
    begin
        str_type := V_ASN1_BMPSTRING;
        outform := MBSTRING_BMP;
    end
    else
    if (mask and B_ASN1_UNIVERSALSTRING) > 0 then
    begin
        str_type := V_ASN1_UNIVERSALSTRING;
        outform := MBSTRING_UNIV;
    end
    else
    begin
        str_type := V_ASN1_UTF8STRING;
        outform := MBSTRING_UTF8;
    end;
    if nil = _out then
       Exit(str_type);
    if _out^ <> nil then
    begin
        free_out := 0;
        dest := _out^;
        OPENSSL_free(Pointer(dest.data));
        dest.data := nil;
        dest.length := 0;
        dest.&type := str_type;
    end
    else
    begin
        free_out := 1;
        dest := ASN1_STRING_type_new(str_type);
        if dest = nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(-1);
        end;
        _out^ := dest;
    end;
    { If both the same type just copy across }
    if inform = outform then
    begin
        if 0>= ASN1_STRING_set(dest, _in, len) then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(-1);
        end;
        Exit(str_type);
    end;
    { Work out how much space the destination will need }
    case outform of
        MBSTRING_ASC:
        begin
            outlen := nchar;
            cpyfunc := cpy_asc;
        end;
        MBSTRING_BMP:
        begin
            outlen := nchar  shl  1;
            cpyfunc := cpy_bmp;
        end;
        MBSTRING_UNIV:
        begin
            outlen := nchar  shl  2;
            cpyfunc := cpy_univ;
        end;
        MBSTRING_UTF8:
        begin
            outlen := 0;
            traverse_string(_in, len, inform, out_utf8, @outlen);
            cpyfunc := cpy_utf8;
        end;
    end;
    p := OPENSSL_malloc(outlen + 1);
    if p = nil then
    begin
        if free_out > 0 then
            ASN1_STRING_free(dest);
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    dest.length := outlen;
    dest.data := p;
    p[outlen] := 0;
    traverse_string(_in, len, inform, cpyfunc, @p);
    Result := str_type;
end;


function traverse_string( p : PByte; len, inform : integer; rfunc : Trfunc; arg : Pointer):integer;
var
  value : Cardinal;

  ret : integer;
begin
    while len > 0 do
    begin
        if inform = MBSTRING_ASC then
        begin
            value := PostInc(p)^;
            Dec(len);
        end
        else
        if (inform = MBSTRING_BMP) then
        begin
            value := PostInc(p)^  shl  8;
            value  := value  or ( PostInc(p)^);
            len  := len - 2;
        end
        else
        if (inform = MBSTRING_UNIV) then
        begin
            value := ulong(PostInc(p)^)  shl  24;
            value  := value  or (ulong(PostInc(p)^)  shl  16);
            value  := value  or ( PostInc(p)^  shl  8);
            value  := value  or ( PostInc(p)^);
            len  := len - 4;
        end
        else
        begin
            ret := UTF8_getc(p, len, @value);
            if ret < 0 then Exit(-1);
            len  := len - ret;
            p  := p + ret;
        end;
        if Assigned(rfunc) then
        begin
            ret := rfunc(value, arg);
            if ret <= 0 then Exit(ret);
        end;
    end;
    Result := 1;
end;


function in_utf8( value : Cardinal; arg : Pointer):integer;
var
  nchar : PInteger;
begin
    if not is_unicode_valid(value ) then
        Exit(-2);
    nchar := arg;
    PostInc(nchar^);
    Result := 1;
end;


function out_utf8( value : Cardinal; arg : Pointer):integer;
var
  outlen : PInteger;
  len : Integer;
begin
    len := UTF8_putc(nil, -1, value);
    if len <= 0 then Exit(len);
    outlen := arg;
    outlen^  := outlen^ + len;
    Result := 1;
end;


function type_str( value : Cardinal; arg : Pointer):integer;
var
  types : Cardinal;
  native : integer;
begin
    types := PUint32(arg)^;
    if value > INT_MAX then
       native := INT_MAX
    else
       native := ossl_fromascii(value);

    if ( (types and B_ASN1_NUMERICSTRING)>0)  and
       ( (not ossl_isdigit(UTF8Char(native))) or  (UTF8Char(native) = ' ')) then
        types := types and not B_ASN1_NUMERICSTRING;
    if ((types and B_ASN1_PRINTABLESTRING)>0)  and  (not ossl_isasn1print(native)) then
        types := types and not B_ASN1_PRINTABLESTRING;
    if ((types and B_ASN1_IA5STRING )>0)  and  (not ossl_isascii(native)) then
        types := types and not B_ASN1_IA5STRING;
    if ((types and B_ASN1_T61STRING )>0)  and  (value > $ff) then
        types := types and not B_ASN1_T61STRING;
    if ((types and B_ASN1_BMPSTRING )>0)  and  (value > $ffff) then
        types := types and not B_ASN1_BMPSTRING;
    if ((types and B_ASN1_UTF8STRING )>0)  and  (not is_unicode_valid(value)) then
        types := types and not B_ASN1_UTF8STRING;
    if 0>= types then
       Exit(-1);
    PUint32(arg)^ := types;
    Result := 1;
end;


function cpy_asc( value : Cardinal; arg : Pointer):integer;
var
  p: PPByte;
  q: PByte;
begin
    p := arg;
    q := p^;
    q^ := Byte( value);
    inc(p^);
    Result := 1;
end;


function cpy_bmp( value : Cardinal; arg : Pointer):integer;
var
  p: PPByte;
  q: PByte;
begin
    p := arg;
    q := p^;
    PostInc(q)^ :=  Byte((value  shr  8) and $ff);
    q^ := Byte(value and $ff);
    p^ := p^ + 2;
    Result := 1;
end;


function cpy_univ( value : Cardinal; arg : Pointer):integer;
var
   p: PPByte;
  q: PByte;
begin
    p := arg;
    q := p^;
    PostInc(q)^ :=  Byte ((value  shr  24) and $ff);
    PostInc(q)^ :=  Byte ((value  shr  16) and $ff);
    PostInc(q)^ :=  Byte ((value  shr  8) and $ff);
    q^ := Byte(value and $ff);
    p^  := p^ + 4;
    Result := 1;
end;


function cpy_utf8( value : Cardinal; arg : Pointer):integer;
var
  p : PPByte;
  ret : integer;
begin
    p := arg;
    { We already know there is enough room so pass $ff as the length }
    ret := UTF8_putc( p^, $ff, value);
    p^  := p^ + ret;
    Result := 1;
end;

end.
