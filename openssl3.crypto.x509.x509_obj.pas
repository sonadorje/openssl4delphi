unit openssl3.crypto.x509.x509_obj;

interface
uses OpenSSL.Api;

const
   NAME_ONELINE_MAX =  (1024 * 1024);

function X509_NAME_oneline(const a : PX509_NAME; buf : PUTF8Char; len : integer):PUTF8Char;

implementation
uses openssl3.crypto.buffer.buffer, openssl3.crypto.mem, openssl3.crypto.x509,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.a_object,
     OpenSSL3.Err, openssl3.crypto.ctype;

function X509_NAME_oneline(const a : PX509_NAME; buf : PUTF8Char; len : integer):PUTF8Char;
const
  hex: PUTF8Char = '0123456789ABCDEF';
var
  ne         : PX509_NAME_ENTRY;

  i,
  n,
  lold,
  l,
  l1,
  l2,
  num,
  j,
  _type,
  prev_set   : integer;
  s,
  p          : PUTF8Char;
  q          : PByte;
  b          : PBUF_MEM;
  gs_doit    : array[0..3] of integer;
  tmp_buf    : array[0..79] of UTF8Char;
{$IFDEF CHARSET_EBCDIC}
  ebcdic_buf : array[0..1023] of Byte;
{$ENDIF}
  label _err, _end;
begin
    prev_set := -1;
    b := nil;
    //const char hex[17] = '0123456789ABCDEF';

    if buf = nil then
    begin
        b := BUF_MEM_new();
        if b = nil then
            goto _err ;
        if 0>= BUF_MEM_grow(b, 200) then
            goto _err ;
        b.data[0] := #0;
        len := 200;
    end
    else if (len = 0) then
    begin
        Exit(nil);
    end;
    if a = nil then
    begin
        if b <> nil then
        begin
            buf := b.data;
            OPENSSL_free(Pointer(b));
        end;
        strncpy(buf, 'NO X509_NAME', len);
        buf[len - 1] := #0;
        Exit(buf);
    end;
    Dec(len);
    l := 0;
    for i := 0 to sk_X509_NAME_ENTRY_num(a.entries)-1 do
    begin
        ne := sk_X509_NAME_ENTRY_value(a.entries, i);
        n := OBJ_obj2nid(ne._object);
        s := OBJ_nid2sn(n);
        if (n = NID_undef)  or  (s = nil) then
        begin
            i2t_ASN1_OBJECT(@tmp_buf, sizeof(tmp_buf), ne._object);
            s := tmp_buf;
        end;
        l1 := Length(s);
        _type := ne.value.&type;
        num := ne.value.length;
        if num > NAME_ONELINE_MAX then
        begin
            ERR_raise(ERR_LIB_X509, X509_R_NAME_TOO_LONG);
            goto _end ;
        end;
        q := ne.value.data;
{$IFDEF CHARSET_EBCDIC}
        if _type = V_ASN1_GENERALSTRING  or
            _type := V_ASN1_VISIBLESTRING  or
            _type := V_ASN1_PRINTABLESTRING  or
            _type := V_ASN1_TELETEXSTRING  or
            _type := V_ASN1_IA5STRING then begin
            if num > int sizeof(ebcdic_buf) then
                num := sizeof(ebcdic_buf);
            ascii2ebcdic(ebcdic_buf, q, num);
            q := ebcdic_buf;
        end;
{$ENDIF}
        if (_type = V_ASN1_GENERALSTRING)  and  ((num mod 4) = 0) then
        begin
            gs_doit[0] := 0; gs_doit[1] := 0; gs_doit[2] := 0; gs_doit[3] := 0;
            for j := 0 to num-1 do
                if q[j] <> 0 then
                   gs_doit[j and 3] := 1;
            if (gs_doit[0] or gs_doit[1] or gs_doit[2]) > 0 then
            begin
                gs_doit[0] := 1; gs_doit[1] := 1; gs_doit[2] := 1; gs_doit[3] := 1;
            end
            else
            begin
                gs_doit[0] := 0; gs_doit[1] := 0; gs_doit[2] := 0;
                gs_doit[3] := 1;
            end;
        end
        else
        begin
            gs_doit[0] := 1; gs_doit[1] := 1; gs_doit[2] := 1; gs_doit[3] := 1;
        end;

        l2 := 0;
        for j := 0 to num-1 do
        begin
            if 0>= gs_doit[j and 3] then
               continue;
            Inc(l2);
            if (q[j] = Ord('/'))  or  (q[j] = Ord('+')) then
               Inc(l2) { char needs to be escaped }
            else
            if (ossl_toascii(q[j]) < ossl_toascii(Ord(' ')))  or
               (ossl_toascii(q[j]) > ossl_toascii(Ord('~'))) then
                l2  := l2 + 3;
        end;
        lold := l;
        l  := l + (1 + l1 + 1 + l2);
        if l > NAME_ONELINE_MAX then
        begin
            ERR_raise(ERR_LIB_X509, X509_R_NAME_TOO_LONG);
            goto _end ;
        end;
        if b <> nil then
        begin
            if 0>= BUF_MEM_grow(b, l + 1) then
                goto _err ;
            p := @(b.data[lold]);
        end
        else
        if (l > len) then
        begin
            break;
        end
        else
            p := @(buf[lold]);
        PostInc(p)^  := get_result(prev_set = ne._set , '+' , '/');
        memcpy(p, s, uint32( l1));
        p  := p + l1;
        PostInc(p)^ := '=';
{$ifndef CHARSET_EBCDIC}          { q was assigned above already. }
        q := ne.value.data;
{$ENDIF}
        for j := 0 to num-1 do
        begin
            if 0>= gs_doit[j and 3] then
               continue;
{$IFNDEF CHARSET_EBCDIC}
            n := q[j];
            if (n < Ord(' ')) or  (n > ord('~')) then
            begin
                PostInc(p)^  := '\';
                PostInc(p)^  := 'x';
                PostInc(p)^  := hex[(n  shr  4) and $0f];
                PostInc(p)^  := hex[n and $0f];
            end
            else
            begin
                if (n = Ord('/'))  or  (n = Ord('+')) then
                   PostInc(p)^  := '\';
                PostInc(p)^ := UTF8Char(n);
            end;
{$ELSE} n := os_toascii[q[j]];
            if (n < os_toascii[' '])  or  (n > os_toascii['~']) then
            begin
                 PostInc(p)^  = '\\';
                *PostInc(p)  = 'x';
                *PostInc(p)  = hex[(n  shr  4) and $0f];
                *PostInc(p)  = hex[n and $0f];
            end
            else
            begin
                if n = os_toascii['/']  or  n = os_toascii['+'] then
                   PostInc(p)  = '\\';
                *PostInc(p)  = q[j];
            end;
{$ENDIF}
        end;
        p^ := #0;
        prev_set := ne._set;
    end;
    if b <> nil then
    begin
        p := b.data;
        OPENSSL_free(Pointer(b));
    end
    else
        p := buf;
    if i = 0 then
       p^ := #0;
    Exit(p);
 _err:
    ERR_raise(ERR_LIB_X509, ERR_R_MALLOC_FAILURE);
 _end:
    BUF_MEM_free(b);
    Result := nil;
end;


end.
