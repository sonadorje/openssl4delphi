unit openssl3.crypto.asn1.a_object;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;

 function ossl_c2i_ASN1_OBJECT(a : PPASN1_OBJECT;const pp : PPByte; len : long):PASN1_OBJECT;
  procedure ASN1_OBJECT_free( a : PASN1_OBJECT);
 function ASN1_OBJECT_new:PASN1_OBJECT;
 function a2d_ASN1_OBJECT(_out : PByte; olen : integer;const buf : PUTF8Char; num : integer):integer;
 function d2i_ASN1_OBJECT(a : PPASN1_OBJECT;const pp : PPByte; length : long):PASN1_OBJECT;
 function i2a_ASN1_OBJECT(bp : PBIO;const a : PASN1_OBJECT):integer;
 function i2t_ASN1_OBJECT(buf : PUTF8Char; buf_len : integer;const a : PASN1_OBJECT):integer;

implementation

uses
  openssl3.crypto.stack, openssl3.crypto.mem, OpenSSL3.Err,
  openssl3.crypto.ctype, openssl3.crypto.bn.bn_lib,
  openssl3.crypto.bn.bn_word,  openssl3.crypto.bio.bio_lib,
  openssl3.crypto.bio.bio_dump,
  openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.asn1_lib;


function i2t_ASN1_OBJECT(buf : PUTF8Char; buf_len : integer;const a : PASN1_OBJECT):integer;
begin
    Result := OBJ_obj2txt(buf, buf_len, a, 0);
end;




function i2a_ASN1_OBJECT(bp : PBIO;const a : PASN1_OBJECT):integer;
var
  buf : array[0..79] of UTF8Char;
  p : PUTF8Char;
  i : integer;
begin
    p := @buf;
    if (a = nil)  or  (a.data = nil) then
        Exit(BIO_write(bp, PUTF8Char('NULL'), 4));
    i := i2t_ASN1_OBJECT(@buf, sizeof(buf), a);
    if i > int (sizeof(buf) - 1)  then
    begin
        if i > INT_MAX - 1 then
        begin   { catch an integer overflow }
            ERR_raise(ERR_LIB_ASN1, ASN1_R_LENGTH_TOO_LONG);
            Exit(-1);
        end;
        p := OPENSSL_malloc(i + 1);
        if p = nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(-1);
        end;
        i2t_ASN1_OBJECT(p, i + 1, a);
    end;
    if i <= 0 then
    begin
        i := BIO_write(bp, PUTF8Char('<INVALID>'), 9);
        i  := i + (BIO_dump(bp, PUTF8Char(a.data), a.length));
        Exit(i);
    end;
    BIO_write(bp, p, i);
    if p <> buf then
       OPENSSL_free(Pointer(p));
    Result := i;
end;




function d2i_ASN1_OBJECT(a : PPASN1_OBJECT;const pp : PPByte; length : long):PASN1_OBJECT;
var
  p : PByte;
  len : long;
  tag, xclass, inf, i : integer;
  ret : PASN1_OBJECT;
  label _err;
begin
    ret := nil;
    p := pp^;
    inf := ASN1_get_object(@p, @len, @tag, @xclass, length);
    if (inf and $80)>0 then
    begin
        i := ASN1_R_BAD_OBJECT_HEADER;
        goto _err ;
    end;
    if tag <> V_ASN1_OBJECT then
    begin
        i := ASN1_R_EXPECTING_AN_OBJECT;
        goto _err ;
    end;
    ret := ossl_c2i_ASN1_OBJECT(a, @p, len);
    if ret <> nil then
       pp^ := p;
    Exit(ret);
 _err:
    ERR_raise(ERR_LIB_ASN1, i);
    Result := nil;
end;

function a2d_ASN1_OBJECT(_out : PByte; olen : integer;const buf : PUTF8Char; num : integer):integer;
var
  i, first, c, use_bn, len : integer;
  ftmp : array[0..23] of byte;
  tmp : PUTF8Char;
  tmpsize : integer;
  p : PUTF8Char;
  l : Cardinal;
  bl : PBIGNUM;
  blsize : integer;
  t : BN_ULONG;
  label _err;
begin
    len := 0;
    tmp := @ftmp;
    tmpsize := sizeof(ftmp);
    bl := nil;
    if num = 0 then
       Exit(0)
    else
    if (num = -1) then
        num := Length(buf);
    p := buf;
    c := Ord(PostInc(p)^);
    Dec(num);
    if (c >= ord('0'))  and  (c <= Ord('2')) then
    begin
        first := c - Ord('0');
    end
    else
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_FIRST_NUM_TOO_LARGE);
        goto _err ;
    end;
    if num <= 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_MISSING_SECOND_NUMBER);
        goto _err ;
    end;
    c := Ord(PostInc(p)^);
    Dec(num);
    while true do
    begin
        if num <= 0 then break;
        if (c <> Ord('.'))  and  (c <> Ord(' ')) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_SEPARATOR);
            goto _err ;
        end;
        l := 0;
        use_bn := 0;
        while true do
        begin
            if num <= 0 then break;
            PostDec(num);
            c := ord(PostInc(p)^);
            if (c = Ord(' '))  or  (c = Ord('.')) then
                break;
            if not ossl_isdigit(UTF8Char(c)) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_DIGIT);
                goto _err ;
            end;
            if (0>= use_bn)  and  (l >= (ULONG_MAX - 80 ) div 10) then
            begin
                use_bn := 1;
                if bl = nil then
                   bl := BN_new();
                if (bl = nil)  or  (0>= BN_set_word(bl, l)) then
                    goto _err ;
            end;
            if use_bn > 0 then
            begin
                if (0>= BN_mul_word(bl, 10))
                     or  (0>= BN_add_word(bl, c - Ord('0'))) then
                    goto _err ;
            end
            else
                l := l * 10 + long(c - Ord('0'));
        end;
        if len = 0 then
        begin
            if (first < 2)  and  (l >= 40) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_SECOND_NUMBER_TOO_LARGE);
                goto _err ;
            end;
            if use_bn > 0 then
            begin
                if 0>= BN_add_word(bl, first * 40) then
                    goto _err ;
            end
            else
                l  := l + (long(first) *40);
        end;
        i := 0;
        if use_bn>0 then
        begin
            blsize := BN_num_bits(bl);
            blsize := (blsize + 6) div 7;
            if blsize > tmpsize then
            begin
                if tmp <> @ftmp then
                    OPENSSL_free(Pointer(tmp));
                tmpsize := blsize + 32;
                tmp := OPENSSL_malloc(tmpsize);
                if tmp = nil then
                begin
                    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                    goto _err ;
                end;
            end;
            while PostDec(blsize) > 0 do
            begin
                t := BN_div_word(bl, $80);
                if t = BN_ULONG(-1)  then
                    goto _err ;
                tmp[PostInc(i)] := UTF8Char(Byte( t));
            end;
        end
        else
        begin
            while true do
            begin
                tmp[PostInc(i)] := UTF8Char(Byte( l and $7f));
                l  := l shr 7;
                if l = 0 then break;
            end;
        end;
        if _out <> nil then
        begin
            if len + i > olen then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_BUFFER_TOO_SMALL);
                goto _err ;
            end;
            while PreDec(i) > 0 do
                _out[PostInc(len)] := Ord(tmp[i]) or $80;
            _out[PostInc(len)] := Ord(tmp[0]);
        end
        else
            len  := len + i;
    end;
    if tmp <> @ftmp then
       OPENSSL_free(Pointer(tmp));
    BN_free(bl);
    Exit(len);
 _err:
    if tmp <> @ftmp then
       OPENSSL_free(Pointer(tmp));
    BN_free(bl);
    Result := 0;
end;



function ASN1_OBJECT_new:PASN1_OBJECT;
var
  ret : PASN1_OBJECT;
begin
    ret := OPENSSL_zalloc(sizeof(ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.flags := ASN1_OBJECT_FLAG_DYNAMIC;
    Result := ret;
end;

procedure ASN1_OBJECT_free( a : PASN1_OBJECT);
begin
    if a = nil then exit;
    if (a.flags and ASN1_OBJECT_FLAG_DYNAMIC_STRINGS)>0 then
    begin
{$IFNDEF CONST_STRICT}
        {
         * Disable purely for compile-time strict const checking.  Doing this
         * on a 'real' compile will cause memory leaks
         }
        OPENSSL_free(Pointer(a.sn));
        OPENSSL_free(Pointer(a.ln));
{$ENDIF}
        a.sn := nil; a.ln := nil;
    end;
    if (a.flags and ASN1_OBJECT_FLAG_DYNAMIC_DATA)>0 then
    begin
        OPENSSL_free(Pointer(a.data));
        a.data := nil;
        a.length := 0;
    end;
    if (a.flags and ASN1_OBJECT_FLAG_DYNAMIC)>0 then
       OPENSSL_free(Pointer(a));
end;

function ossl_c2i_ASN1_OBJECT(a : PPASN1_OBJECT;const pp : PPByte; len : long):PASN1_OBJECT;
var
  ret  : PASN1_OBJECT;
  tobj : TASN1_OBJECT;
  p, data : PByte;
  i, _length : integer;
  label _err;
begin
    ret := nil;
    {
     * Sanity check OID encoding. Need at least one content octet. MSB must
     * be clear in the last octet. can't have leading $80 in subidentifiers,
     * see: X.690 8.19.2
     }
    p := pp^;
    if (len <= 0)  or  (len > INT_MAX)  or  (pp = nil)  or  (p =  nil)  or
        ( (p[len - 1] and $80)>0) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_OBJECT_ENCODING);
        Exit(nil);
    end;
    { Now 0 < len <= INT_MAX, so the cast is safe. }
    _length := int(len);
    {
     * Try to lookup OID in table: these are all valid encodings so if we get
     * a match we know the OID is valid.
     }
    tobj.nid := NID_undef;
    tobj.data := p;
    tobj.length := _length;
    tobj.flags := 0;
    i := OBJ_obj2nid(@tobj);
    if i <> NID_undef then
    begin
        {
         * Return shared registered OID object: this improves efficiency
         * because we don't have to return a dynamically allocated OID
         * and NID lookups can use the cached value.
         }
        ret := OBJ_nid2obj(i);
        if a <> nil then
        begin
            ASN1_OBJECT_free( a^);
            a^ := ret;
        end;
        pp^  := pp^ + len;
        Exit(ret);
    end;
    for i := 0 to _length-1 do
    begin
        if (p^ = $80)  and ( (0>= i)  or  (0>= (p[-1] and $80) ) ) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_OBJECT_ENCODING);
            Exit(nil);
        end;
        Inc(p);
    end;
    if (a = nil)  or  (a^ = nil)  or
         (0>= (a^.flags and ASN1_OBJECT_FLAG_DYNAMIC)) then
    begin
        ret := ASN1_OBJECT_new();
        if ret = nil then
            Exit(nil);
    end
    else
    begin
        ret := a^;
    end;
    p := pp^;
    { detach data from object }
    data := PByte( ret.data);
    ret.data := nil;
    { once detached we can change it }
    if (data = nil) or  (ret.length < _length) then
    begin
        ret.length := 0;
        OPENSSL_free(Pointer(data));
        data := OPENSSL_malloc(_length);
        if data = nil then
        begin
            i := ERR_R_MALLOC_FAILURE;
            goto _err ;
        end;
        ret.flags  := ret.flags  or ASN1_OBJECT_FLAG_DYNAMIC_DATA;
    end;
    memcpy(data, p, _length);
    { If there are dynamic strings, free them here, and clear the flag }
    if (ret.flags and ASN1_OBJECT_FLAG_DYNAMIC_STRINGS) <> 0 then
    begin
        OPENSSL_free(Pointer(ret.sn));
        OPENSSL_free(Pointer(ret.ln));
        ret.flags := ret.flags and (not ASN1_OBJECT_FLAG_DYNAMIC_STRINGS);
    end;
    { reattach data to object, after which it remains const }
    ret.data := data;
    ret.length := _length;
    ret.sn := nil;
    ret.ln := nil;
    { ret.flags=ASN1_OBJECT_FLAG_DYNAMIC; we know it is dynamic }
    p  := p + _length;
    if a <> nil then a^ := ret;
    pp^ := p;
    Exit(ret);
 _err:
    ERR_raise(ERR_LIB_ASN1, i);
    if (a = nil)  or  ( a^ <> ret) then
        ASN1_OBJECT_free(ret);
    Result := nil;
end;






end.
