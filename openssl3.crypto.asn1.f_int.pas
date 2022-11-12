unit openssl3.crypto.asn1.f_int;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

 function i2a_ASN1_INTEGER(bp : PBIO;const a : PASN1_INTEGER):integer;
  function a2i_ASN1_INTEGER( bp : PBIO; bs : PASN1_INTEGER; buf : PUTF8Char; size : integer):integer;
  function i2a_ASN1_ENUMERATED(bp : PBIO;const a : PASN1_ENUMERATED):integer;
  function a2i_ASN1_ENUMERATED( bp : PBIO; bs : PASN1_ENUMERATED; buf : PUTF8Char; size : integer):integer;



implementation
uses openssl3.crypto.bio.bio_lib, openssl3.crypto.ctype, OpenSSL3.Err,
     openssl3.crypto.mem, openssl3.crypto.o_str;


function i2a_ASN1_INTEGER(bp : PBIO;const a : PASN1_INTEGER):integer;
const
  h : PUTF8Char = '0123456789ABCDEF';
var
  i, n : integer;
  buf : array[0..1] of UTF8Char;
  label _err;
begin
    n := 0;
    if a = nil then Exit(0);
    if (a.&type and V_ASN1_NEG) > 0 then
    begin
        if BIO_write(bp, PUTF8Char('-'), 1) <> 1 then
            goto  _err ;
        n := 1;
    end;
    if a.length = 0 then
    begin
        if BIO_write(bp, PUTF8Char('00'), 2) <> 2 then
            goto _err ;
        n  := n + 2;
    end
    else
    begin
        for i := 0 to a.length-1 do
        begin
            if (i <> 0)  and  (i mod 35 = 0) then
            begin
                if BIO_write(bp, PUTF8Char('\'#10), 2) <> 2 then
                    goto _err ;
                n  := n + 2;
            end;
            buf[0] := h[(Byte( a.data[i]  shr  4) and $0f)];
            buf[1] := h[(Byte( a.data[i]) and $0f)];
            if BIO_write(bp, @buf, 2 )  <> 2 then
                goto _err ;
            n  := n + 2;
        end;
    end;
    Exit(n);
 _err:
    Result := -1;
end;


function a2i_ASN1_INTEGER( bp : PBIO; bs : PASN1_INTEGER; buf : PUTF8Char; size : integer):integer;
var
  i, j, k, m, n, again, bufsize : integer;
  s, bufp, sp : PByte;
  num, slen, first : integer;
  label _err;
begin
    s := nil;
    num := 0; slen := 0; first := 1;
    bs.&type := V_ASN1_INTEGER;
    bufsize := BIO_gets(bp, buf, size);
    while true do
    begin
        if bufsize < 1 then
           goto _err ;
        i := bufsize;
        if (buf[i - 1] = #10) then
            buf[PreDec(i)] := #0;
        if i = 0 then
           goto _err ;
        if buf[i - 1] = #13 then
           buf[PreDec(i)] := #0;
        if i = 0 then
           goto _err ;
        again := int(buf[i - 1] = '\');

        for j := 0 to i-1 do
        begin
            if not ossl_isxdigit(buf[j]) then
            begin
                i := j;
                break;
            end;
        end;
        buf[i] := #0;
        {
         * We have now cleared all the crap off the end of the line
         }
        if i < 2 then goto _err ;
        bufp := PByte( buf);
        if first > 0 then
        begin
            first := 0;
            if (bufp[0] = ord('0'))  and  (bufp[1] = ord('0')) then
            begin
                bufp  := bufp + 2;
                i  := i - 2;
            end;
        end;
        k := 0;
        i  := i - again;
        if i mod 2 <> 0 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_ODD_NUMBER_OF_CHARS);
            OPENSSL_free(s);
            Exit(0);
        end;
        i  := i  div 2;
        if num + i > slen then
        begin
            sp := OPENSSL_clear_realloc(Pointer(s), slen, num + i * 2);
            if sp = nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                OPENSSL_free(s);
                Exit(0);
            end;
            s := sp;
            slen := num + i * 2;
        end;
        for j := 0 to  i-1  do
        begin
            for n := 0 to 1 do
            begin
                m := OPENSSL_hexchar2int(UTF8Char(bufp[k + n]));
                if m < 0 then
                begin
                    ERR_raise(ERR_LIB_ASN1, ASN1_R_NON_HEX_CHARACTERS);
                    goto _err ;
                end;
                s[num + j] := s[num + j] shl  4;
                s[num + j] := s[num + j]  or m;
            end;
            k := k + 2;
        end;
        num  := num + i;
        if again > 0 then
           bufsize := BIO_gets(bp, buf, size)
        else
            break;
    end;
    bs.length := num;
    bs.data := s;
    Exit(1);
 _err:
    ERR_raise(ERR_LIB_ASN1, ASN1_R_SHORT_LINE);
    OPENSSL_free(s);
    Result := 0;
end;


function i2a_ASN1_ENUMERATED(bp : PBIO;const a : PASN1_ENUMERATED):integer;
begin
    Result := i2a_ASN1_INTEGER(bp, a);
end;


function a2i_ASN1_ENUMERATED( bp : PBIO; bs : PASN1_ENUMERATED; buf : PUTF8Char; size : integer):integer;
var
  rv : integer;
begin
    rv := a2i_ASN1_INTEGER(bp, bs, buf, size);
    if rv = 1 then
       bs.&type := V_ASN1_INTEGER or (bs.&type and V_ASN1_NEG);
    Result := rv;
end;


end.
