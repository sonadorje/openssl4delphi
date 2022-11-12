unit openssl3.crypto.asn1.asn1_lib;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;

type
   sk_const_ASN1_VALUE_compfunc = function(const a, b : PPASN1_VALUE):integer;
   sk_const_ASN1_VALUE_freefunc = procedure( a : PASN1_VALUE);
   sk_const_ASN1_VALUE_copyfunc = function (const a : PASN1_VALUE):PASN1_VALUE;

function sk_const_ASN1_VALUE_num(const sk : Pstack_st_const_ASN1_VALUE):integer;
  function sk_const_ASN1_VALUE_new( compare : sk_const_ASN1_VALUE_compfunc):Pstack_st_const_ASN1_VALUE;
  function sk_const_ASN1_VALUE_new_null:Pstack_st_const_ASN1_VALUE;
  function sk_const_ASN1_VALUE_new_reserve( compare : sk_const_ASN1_VALUE_compfunc; n : integer):Pstack_st_const_ASN1_VALUE;
  function sk_const_ASN1_VALUE_reserve( sk : Pstack_st_const_ASN1_VALUE; n : integer):integer;
  procedure sk_const_ASN1_VALUE_free( sk : Pstack_st_const_ASN1_VALUE);
  procedure sk_const_ASN1_VALUE_zero( sk : Pstack_st_const_ASN1_VALUE);
  function sk_const_ASN1_VALUE_delete( sk : Pstack_st_const_ASN1_VALUE; i : integer):PASN1_VALUE;
  function sk_const_ASN1_VALUE_push(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE):integer;
  function sk_const_ASN1_VALUE_unshift(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE):integer;
  function sk_const_ASN1_VALUE_pop( sk : Pstack_st_const_ASN1_VALUE):PASN1_VALUE;
  procedure sk_const_ASN1_VALUE_pop_free( sk : Pstack_st_const_ASN1_VALUE; freefunc : sk_const_ASN1_VALUE_freefunc);
  function sk_const_ASN1_VALUE_insert(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE; idx : integer):integer;
  function sk_const_ASN1_VALUE_find(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE):integer;
  function sk_const_ASN1_VALUE_find_ex(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE):integer;
  function sk_const_ASN1_VALUE_find_all(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE; pnum : PInteger):integer;
  procedure sk_const_ASN1_VALUE_sort( sk : Pstack_st_const_ASN1_VALUE);
  function sk_const_ASN1_VALUE_is_sorted(const sk : Pstack_st_const_ASN1_VALUE):integer;
  function sk_const_ASN1_VALUE_dup(const sk : Pstack_st_const_ASN1_VALUE):Pstack_st_const_ASN1_VALUE;
  function sk_const_ASN1_VALUE_deep_copy(const sk : Pstack_st_const_ASN1_VALUE; copyfunc : sk_const_ASN1_VALUE_copyfunc; freefunc : sk_const_ASN1_VALUE_freefunc):Pstack_st_const_ASN1_VALUE;
  function sk_const_ASN1_VALUE_set_cmp_func( sk : Pstack_st_const_ASN1_VALUE; compare : sk_const_ASN1_VALUE_compfunc):sk_const_ASN1_VALUE_compfunc;
  function sk_const_ASN1_VALUE_value(const sk : Pstack_st_const_ASN1_VALUE; idx : integer):PASN1_VALUE;
  function sk_const_ASN1_VALUE_set(sk : Pstack_st_const_ASN1_VALUE; idx : integer;const ptr : PASN1_VALUE):PASN1_VALUE;
   function ASN1_STRING_set(str : PASN1_STRING;const _data : Pointer; len_in : integer):integer;
   procedure ASN1_put_object( pp : PPByte; constructed, length, tag, xclass : integer);
  procedure asn1_put_length( pp : PPByte; _length : integer);
  function ASN1_put_eoc( pp : PPByte):integer;
  procedure ASN1_STRING_set0( str : PASN1_STRING; data : Pointer; len : integer);
   procedure ossl_asn1_string_embed_free( a : PASN1_STRING; embed : integer);
   function ASN1_object_size( constructed, length, tag : integer):integer;
  function ASN1_STRING_type_new( _type : integer):PASN1_STRING;
  procedure ASN1_STRING_free( a : PASN1_STRING);
  function ASN1_STRING_dup(const str : PASN1_STRING):PASN1_STRING;
  function ASN1_STRING_new:PASN1_STRING;
  function ASN1_STRING_copy(dst : PASN1_STRING;const str : PASN1_STRING):integer;
  function ASN1_STRING_cmp(const a, b : PASN1_STRING):integer;
  function ASN1_get_object(const pp : PPByte; plength : Plong; ptag, pclass : PInteger; omax : long):integer;
  function asn1_get_length(const pp : PPByte; inf : PInteger; rl : Plong; max : long):integer;
  function ASN1_STRING_get0_data(const x : PASN1_STRING):PByte;
  function ASN1_STRING_length(const x : PASN1_STRING):integer;
   procedure ASN1_STRING_clear_free( a : PASN1_STRING);



implementation

uses
  openssl3.crypto.stack, openssl3.crypto.mem, OpenSSL3.Err;


procedure ASN1_STRING_clear_free( a : PASN1_STRING);
begin
    if a = nil then exit;
    if (a.data <> nil) and  (0>= a.flags and ASN1_STRING_FLAG_NDEF)  then
        OPENSSL_cleanse(Pointer(a.data), a.length);
    ASN1_STRING_free(a);
end;




function ASN1_STRING_length(const x : PASN1_STRING):integer;
begin
    Result := x.length;
end;


function ASN1_STRING_get0_data(const x : PASN1_STRING):PByte;
begin
    Result := x.data;
end;

function asn1_get_length(const pp : PPByte; inf : PInteger; rl : Plong; max : long):integer;
var
  p : PByte;
  ret : Cardinal;
  i : integer;
begin
   p := pp^;
    ret := 0;
    if PostDec(max) < 1  then
        Exit(0);
    if p^ = $80 then
    begin
        inf^ := 1;
        Inc(p);
    end
    else
    begin
        inf^ := 0;
        i := p^ and $7f;
        if (PostInc(p)^ and $80) > 0  then
        begin

            if max < i + 1 then
                Exit(0);
            { Skip leading zeroes }
            while (i > 0)  and  (p^ = 0) do
            begin
                Inc(p);
                Dec(i);
            end;
            if i > int (sizeof(long)) then
                Exit(0);
            while i > 0 do
            begin
                ret  := ret shl  8;
                ret  := ret  or p^;
                Inc(p);
                Dec(i);
            end;
            if ret > LONG_MAX then
               Exit(0);
        end
        else
        begin
            ret := i;
        end;
    end;
    pp^ := p;
    rl^ := long(ret);
    Result := 1;
end;

function ASN1_get_object(const pp : PPByte; plength : Plong; ptag, pclass : PInteger; omax : long):integer;
var
  i, ret : integer;
  len : long;
  p : PByte;
  tag, xclass, inf : integer;
  max : long;
  label _err;
begin
    p := pp^;
    max := omax;
    if omax <= 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL);
        Exit($80);
    end;
    ret := ( p^ and V_ASN1_CONSTRUCTED);
    xclass := ( p^ and V_ASN1_PRIVATE);
    i := p^ and V_ASN1_PRIMITIVE_TAG;
    if i = V_ASN1_PRIMITIVE_TAG then
    begin  { high-tag }
        Inc(p);
        if PreDec(max) = 0  then
            goto _err ;
        len := 0;
        while (p^ and $80) > 0 do
        begin
            len  := len shl 7;
            len  := len  or (PostInc(p)^ and $7f);
            if PreDec(max) = 0  then
                goto _err ;
            if len > (INT_MAX  shr  7) then
                goto _err ;
        end;
        len  := len shl 7;
        len  := len  or (PostInc(p)^ and $7f);
        if PreDec(max) = 0  then
            goto _err ;
    end
    else
    begin
        tag := i;
        Inc(p);
        if PreDec(max) = 0  then
            goto _err ;
    end;
    ptag^ := tag;
    pclass^ := xclass;
    if 0>= asn1_get_length(@p, @inf, plength, max) then
        goto _err ;
    if (inf > 0)  and  (0>= (ret and V_ASN1_CONSTRUCTED)) then
        goto _err ;
    if plength^ > (omax - (p - pp^ ))  then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
        {
         * Set this so that even if things are not long enough the values are
         * set correctly
         }
        ret  := ret  or $80;
    end;
    pp^ := p;
    Exit(ret or inf);
 _err:
    ERR_raise(ERR_LIB_ASN1, ASN1_R_HEADER_TOO_LONG);
    Result := $80;
end;


function ASN1_STRING_cmp(const a, b : PASN1_STRING):integer;
var
  i : integer;
begin
    i := (a.length - b.length);
    if i = 0 then
    begin
        if a.length <> 0 then
            i := memcmp(a.data, b.data, a.length);
        if i = 0 then
           Exit(a.&type - b.&type)
        else
            Exit(i);
    end
    else
    begin
        Exit(i);
    end;
end;


function ASN1_STRING_copy(dst : PASN1_STRING;const str : PASN1_STRING):integer;
begin
    if str = nil then Exit(0);
    dst.&type := str.&type;
    if 0>= ASN1_STRING_set(dst, str.data, str.length ) then
        Exit(0);
    { Copy flags but preserve embed value }
    dst.flags := dst.flags and ASN1_STRING_FLAG_EMBED;
    dst.flags  := dst.flags  or (str.flags and not ASN1_STRING_FLAG_EMBED);
    Result := 1;
end;

function ASN1_STRING_new:PASN1_STRING;
begin
    Result := ASN1_STRING_type_new(V_ASN1_OCTET_STRING);
end;

function ASN1_STRING_dup(const str : PASN1_STRING):PASN1_STRING;
var
  ret : PASN1_STRING;
begin
    if nil = str then Exit(nil);
    ret := ASN1_STRING_new();
    if ret = nil then Exit(nil);
    if 0>= ASN1_STRING_copy(ret, str) then
    begin
        ASN1_STRING_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;


procedure ASN1_STRING_free( a : PASN1_STRING);
begin
    if a = nil then
       Exit;
    ossl_asn1_string_embed_free(a, a.flags and ASN1_STRING_FLAG_EMBED);
end;

function ASN1_STRING_type_new( _type : integer):PASN1_STRING;
var
  ret : PASN1_STRING;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.&type := _type;
    Result := ret;
end;




function ASN1_object_size( constructed, length, tag : integer):integer;
var
  ret, tmplen : integer;
begin
    ret := 1;
    if length < 0 then Exit(-1);
    if tag >= 31 then
    begin
        while tag > 0 do
        begin
            tag := tag shr  7;
            Inc(ret);
        end;
    end;
    if constructed = 2 then
    begin
        ret  := ret + 3;
    end
    else
    begin
        Inc(ret);
        if length > 127 then
        begin
            tmplen := length;
            while tmplen > 0 do
            begin
                tmplen := tmplen shr  8;
                Inc(ret);
            end;
        end;
    end;
    if ret >= INT_MAX - length then
       Exit(-1);
    Result := ret + length;
end;

function ASN1_put_eoc( pp : PPByte):integer;
var
  p : PByte;
begin
    p := pp^;
    (PostInc(p))^ := 0;
    (PostInc(p))^ := 0;
    pp^ := p;
    Result := 2;
end;




procedure asn1_put_length( pp : PPByte; _length : integer);
var
  p : PByte;
  i, len : integer;
begin
    p := pp^;
    if _length <= 127 then
    begin
        PostInc(p)^ := Byte( _length);
    end
    else
    begin
        len := _length;
        i := 0;
        while len > 0 do
        begin
            len := len shr 8;
            Inc(i);
        end;
        PostInc(p)^ := i or $80;
        len := i;
        while PostDec(i) > 0 do
        begin
            p[i] := _length and $ff;
            _length := _length shr 8;
        end;
        p  := p + len;
    end;
    pp^ := p;
end;

procedure ASN1_put_object( pp : PPByte; constructed, length, tag, xclass : integer);
var
  p : PByte;
  i, ttag : integer;
begin
    p := pp^;
    i := get_result(constructed>0 , V_ASN1_CONSTRUCTED , 0);
    i  := i  or ((xclass and V_ASN1_PRIVATE));
    if tag < 31 then
    begin
        PostInc(p)^ := i or (tag and V_ASN1_PRIMITIVE_TAG);
    end
    else
    begin
        PostInc(p)^ := i or V_ASN1_PRIMITIVE_TAG;
        i := 0; ttag := tag;
        while ttag > 0 do
        begin
            ttag  := ttag shr 7;
            Inc(i);
        end;
        ttag := i;
        while PostDec(i) > 0 do
        begin
            p[i] := tag and $7f;
            if i <> (ttag - 1) then
                p[i]  := p[i]  or $80;
            tag  := tag shr 7;
        end;
        p  := p + ttag;
    end;
    if constructed = 2 then
       PostInc(p)^ := $80
    else
        asn1_put_length(@p, length);
    pp^ := p;
end;




procedure ossl_asn1_string_embed_free( a : PASN1_STRING; embed : integer);
begin
    if a = nil then exit;
    if 0>= (a.flags and ASN1_STRING_FLAG_NDEF) then
       OPENSSL_free(Pointer(a.data));
    if embed = 0 then
       OPENSSL_free(Pointer(a));
end;



function ASN1_STRING_set(str : PASN1_STRING;const _data : Pointer; len_in : integer):integer;
var
  c : PByte;
  data : PUTF8Char;
  len : size_t;
begin
    data := _data;
    if len_in < 0 then
    begin
        if data = nil then
            Exit(0);
        len := Length(data);
    end
    else
    begin
        len := size_t( len_in);
    end;
    {
     * Verify that the length fits within an integer for assignment to
     * str.length below.  The additional 1 is subtracted to allow for the
     * #0 terminator even though this isn't strictly necessary.
     }
    if len > INT_MAX - 1 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LARGE);
        Exit(0);
    end;
    if (size_t( str.length) <= len)  or  (str.data = nil) then
    begin
        c := str.data;
{$IFDEF FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION}
        { No NUL terminator in fuzzing builds }
        str.data := OPENSSL_realloc(c, len <> 0 ? len : 1);
{$ELSE}
        str.data := OPENSSL_realloc(c, len + 1);
{$ENDIF}
        if str.data = nil then begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            str.data := c;
            Exit(0);
        end;
    end;
    str.length := len;
    if data <> nil then
    begin
        memcpy(str.data, data, len);
{$IFDEF FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION}
        { Set the unused byte to something non NUL and printable. }
        if len = 0 then str.data[len] = '~';
{$ELSE} {
         * Add a NUL terminator. This should not be necessary - but we add it as
         * a safety precaution
         }
        str.data[len] := Ord(#0);
{$ENDIF}
    end;
    Result := 1;
end;




procedure ASN1_STRING_set0( str : PASN1_STRING; data : Pointer; len : integer);
begin
    OPENSSL_free(Pointer(str.data));
    str.data := data;
    str.length := len;
end;


function sk_const_ASN1_VALUE_set(sk : Pstack_st_const_ASN1_VALUE; idx : integer;const ptr : PASN1_VALUE):PASN1_VALUE;
begin
   Result := PASN1_VALUE(OPENSSL_sk_set(POPENSSL_STACK( sk), idx, Pointer( ptr)));
end;



function sk_const_ASN1_VALUE_value(const sk : Pstack_st_const_ASN1_VALUE; idx : integer):PASN1_VALUE;
begin
 Result := PASN1_VALUE (OPENSSL_sk_value(POPENSSL_STACK( sk), idx));
end;



function sk_const_ASN1_VALUE_num(const sk : Pstack_st_const_ASN1_VALUE):integer;
begin
  Exit(OPENSSL_sk_num(POPENSSL_STACK( sk)));
end;


function sk_const_ASN1_VALUE_new( compare : sk_const_ASN1_VALUE_compfunc):Pstack_st_const_ASN1_VALUE;
begin
   Exit(Pstack_st_const_ASN1_VALUE( OPENSSL_sk_new(OPENSSL_sk_compfunc(compare))));
end;


function sk_const_ASN1_VALUE_new_null:Pstack_st_const_ASN1_VALUE;
begin
    Exit(Pstack_st_const_ASN1_VALUE( OPENSSL_sk_new_null));
end;


function sk_const_ASN1_VALUE_new_reserve( compare : sk_const_ASN1_VALUE_compfunc; n : integer):Pstack_st_const_ASN1_VALUE;
begin
 Exit(Pstack_st_const_ASN1_VALUE( OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n)));
end;


function sk_const_ASN1_VALUE_reserve( sk : Pstack_st_const_ASN1_VALUE; n : integer):integer;
begin
 Exit(OPENSSL_sk_reserve(POPENSSL_STACK( sk), n));
end;


procedure sk_const_ASN1_VALUE_free( sk : Pstack_st_const_ASN1_VALUE);
begin
 OPENSSL_sk_free(POPENSSL_STACK( sk));
end;


procedure sk_const_ASN1_VALUE_zero( sk : Pstack_st_const_ASN1_VALUE);
begin
 OPENSSL_sk_zero(POPENSSL_STACK( sk));
end;


function sk_const_ASN1_VALUE_delete( sk : Pstack_st_const_ASN1_VALUE; i : integer):PASN1_VALUE;
begin
 Exit(PASN1_VALUE(OPENSSL_sk_delete(POPENSSL_STACK( sk), i)));
end;


function sk_const_ASN1_VALUE_push(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE):integer;
begin
 Exit(OPENSSL_sk_push(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_const_ASN1_VALUE_unshift(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE):integer;
begin
 Exit(OPENSSL_sk_unshift(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_const_ASN1_VALUE_pop( sk : Pstack_st_const_ASN1_VALUE):PASN1_VALUE;
begin
 Exit(PASN1_VALUE(OPENSSL_sk_pop(POPENSSL_STACK( sk))));
end;


procedure sk_const_ASN1_VALUE_pop_free( sk : Pstack_st_const_ASN1_VALUE; freefunc : sk_const_ASN1_VALUE_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc) );
end;


function sk_const_ASN1_VALUE_insert(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE; idx : integer):integer;
begin
 Exit(OPENSSL_sk_insert(POPENSSL_STACK( sk), Pointer( ptr), idx));
end;


function sk_const_ASN1_VALUE_find(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE):integer;
begin
 Exit(OPENSSL_sk_find(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_const_ASN1_VALUE_find_ex(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE):integer;
begin
 Exit(OPENSSL_sk_find_ex(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_const_ASN1_VALUE_find_all(sk : Pstack_st_const_ASN1_VALUE;const ptr : PASN1_VALUE; pnum : PInteger):integer;
begin
 Exit(OPENSSL_sk_find_all(POPENSSL_STACK( sk), Pointer( ptr), pnum));
end;


procedure sk_const_ASN1_VALUE_sort( sk : Pstack_st_const_ASN1_VALUE);
begin
 OPENSSL_sk_sort(POPENSSL_STACK( sk));
end;


function sk_const_ASN1_VALUE_is_sorted(const sk : Pstack_st_const_ASN1_VALUE):integer;
begin
 Exit(OPENSSL_sk_is_sorted(POPENSSL_STACK( sk)));
end;


function sk_const_ASN1_VALUE_dup(const sk : Pstack_st_const_ASN1_VALUE):Pstack_st_const_ASN1_VALUE;
begin
 Exit(Pstack_st_const_ASN1_VALUE( OPENSSL_sk_dup(POPENSSL_STACK( sk))));
end;


function sk_const_ASN1_VALUE_deep_copy(const sk : Pstack_st_const_ASN1_VALUE; copyfunc : sk_const_ASN1_VALUE_copyfunc; freefunc : sk_const_ASN1_VALUE_freefunc):Pstack_st_const_ASN1_VALUE;
begin
 Exit(Pstack_st_const_ASN1_VALUE( OPENSSL_sk_deep_copy(POPENSSL_STACK( sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc))));
end;


function sk_const_ASN1_VALUE_set_cmp_func( sk : Pstack_st_const_ASN1_VALUE; compare : sk_const_ASN1_VALUE_compfunc):sk_const_ASN1_VALUE_compfunc;
begin
  Result := sk_const_ASN1_VALUE_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK( sk),
                                         OPENSSL_sk_compfunc(compare)));
end;


end.
