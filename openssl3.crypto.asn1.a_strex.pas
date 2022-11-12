unit openssl3.crypto.asn1.a_strex;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

const
  FN_WIDTH_LN = 25;
  FN_WIDTH_SN = 10;
  BUF_TYPE_WIDTH_MASK = $7;
  BUF_TYPE_CONVUTF8   = $8;
  CHARTYPE_BS_ESC     = (ASN1_STRFLGS_ESC_2253 or CHARTYPE_FIRST_ESC_2253 or CHARTYPE_LAST_ESC_2253);
  ESC_FLAGS   = (ASN1_STRFLGS_ESC_2253 or
                  ASN1_STRFLGS_ESC_2254 or
                  ASN1_STRFLGS_ESC_QUOTE or
                  ASN1_STRFLGS_ESC_CTRL or
                  ASN1_STRFLGS_ESC_MSB);

  const tag2nbyte: array[0..30] of Int8 = (
    -1, -1, -1, -1, -1,         (* 0-4 *)
    -1, -1, -1, -1, -1,         (* 5-9 *)
    -1, -1,                     (* 10-11 *)
     0,                         (* 12 V_ASN1_UTF8STRING *)
    -1, -1, -1, -1, -1,         (* 13-17 *)
     1,                         (* 18 V_ASN1_NUMERICSTRING *)
     1,                         (* 19 V_ASN1_PRINTABLESTRING *)
     1,                         (* 20 V_ASN1_T61STRING *)
    -1,                         (* 21 *)
     1,                         (* 22 V_ASN1_IA5STRING *)
     1,                         (* 23 V_ASN1_UTCTIME *)
     1,                         (* 24 V_ASN1_GENERALIZEDTIME *)
    -1,                         (* 25 *)
     1,                         (* 26 V_ASN1_ISO64STRING *)
    -1,                         (* 27 *)
     4,                         (* 28 V_ASN1_UNIVERSALSTRING *)
    -1,                         (* 29 *)
     2                          (* 30 V_ASN1_BMPSTRING *)
);

type
  Tchar_io = function(arg: Pointer; const buf: Pointer; len : integer):integer;

 function X509_NAME_print_ex(_out : PBIO;const nm : PX509_NAME; indent : integer; flags : Cardinal):integer;
 function do_name_ex(io_ch : Tchar_io; arg : Pointer;const n : PX509_NAME; indent : integer; flags : Cardinal):integer;
 function do_indent( io_ch : Tchar_io; arg : Pointer; indent : integer):integer;
 function do_print_ex(io_ch : Tchar_io; arg : Pointer; lflags : Cardinal;const str : PASN1_STRING):integer;
 function do_dump(lflags : Cardinal; io_ch : Tchar_io; arg : Pointer;const str : PASN1_STRING):integer;
 function do_hex_dump( io_ch : Tchar_io; arg : Pointer; buf : PByte; buflen : integer):integer;
 function do_buf( buf : PByte; buflen, _type : integer; flags : uint16; quotes : PInt8; io_ch : Tchar_io; arg : Pointer):integer;
 function do_esc_char( c : Cardinal; flags : uint16; do_quotes : PInt8; io_ch : Tchar_io; arg : Pointer):integer;
 function send_bio_chars(arg : Pointer;const buf : Pointer; len : integer):integer;
 function ASN1_STRING_to_UTF8(_out : PPByte;const _in : PASN1_STRING):integer;
 function ASN1_STRING_print_ex(_out : PBIO;const str : PASN1_STRING; flags : Cardinal):integer;


implementation
uses OpenSSL3.crypto.x509.x_name, OpenSSL3.crypto.x509.x509name,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.mem,
     OpenSSL3.Err, openssl3.crypto.asn1.a_utf8,
     openssl3.crypto.bio.bio_print, openssl3.crypto.asn1.a_mbstr,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.asn1_parse;


function ASN1_STRING_print_ex(_out : PBIO;const str : PASN1_STRING; flags : Cardinal):integer;
begin
    Result := do_print_ex(send_bio_chars, _out, flags, str);
end;

function ASN1_STRING_to_UTF8(_out : PPByte;const _in : PASN1_STRING):integer;
var
  stmp : TASN1_STRING;

  str : PASN1_STRING;

  mbflag, _type, ret : integer;
begin
    str := @stmp;
    if nil = _in then
       Exit(-1);
    _type := _in.&type;
    if (_type < 0) or  (_type > 30) then
        Exit(-1);
    mbflag := tag2nbyte[_type];
    if mbflag = -1 then
       Exit(-1);
    mbflag  := mbflag  or MBSTRING_FLAG;
    stmp.data := nil;
    stmp.length := 0;
    stmp.flags := 0;
    ret := ASN1_mbstring_copy(@str, _in.data, _in.length, mbflag,
                           B_ASN1_UTF8STRING);
    if ret < 0 then
       Exit(ret);
    _out^ := stmp.data;
    Result := stmp.length;
end;




function send_bio_chars(arg : Pointer;const buf : Pointer; len : integer):integer;
begin
    if nil = arg then
       Exit(1);
    if BIO_write(arg, buf, len) <> len  then
        Exit(0);
    Result := 1;
end;

function do_esc_char( c : Cardinal; flags : uint16; do_quotes : PInt8; io_ch : Tchar_io; arg : Pointer):integer;
var
  chflgs : uint16;
  chtmp : Byte;
  tmphex : array[0..(sizeof(long)*2 + 3)-1] of UTF8Char;
begin
  if (c > $ffffffff) then
        exit( -1);
    if (c > $ffff) then
    begin
        BIO_snprintf(@tmphex, sizeof(tmphex), '\W%08lX', [c]);
        if (0>= io_ch(arg, @tmphex, 10)) then
            exit( -1);
        exit( 10);
    end;
    if (c > $ff) then
    begin
        BIO_snprintf(tmphex, sizeof(tmphex), '\U%04lX', [c]);
        if (0>= io_ch(arg, @tmphex, 6)) then
            exit( -1);
        exit( 6);
    end;
    chtmp := Byte( c);
    if (chtmp > $7f) then
        chflgs := flags and ASN1_STRFLGS_ESC_MSB
    else
        chflgs := char_type[chtmp] and flags;
    if (chflgs and CHARTYPE_BS_ESC)>0 then
    begin
        (* If we don't escape with quotes, signal we need quotes *)
        if (chflgs and ASN1_STRFLGS_ESC_QUOTE)>0 then
        begin
            if (do_quotes <> nil) then
                do_quotes^ := 1;
            if (0>= io_ch(arg, @chtmp, 1)) then
                exit( -1);
            exit( 1);
        end;
        if (0>= io_ch(arg, PUTF8Char('\'), 1)) then
            exit( -1);
        if (0>= io_ch(arg, @chtmp, 1))then
            exit( -1);
        exit( 2);
    end;
    if (chflgs and (ASN1_STRFLGS_ESC_CTRL
                  or ASN1_STRFLGS_ESC_MSB
                  or ASN1_STRFLGS_ESC_2254)>0) then
    begin
        BIO_snprintf(tmphex, 11, '\%02X', [chtmp]);
        if (0>= io_ch(arg, @tmphex, 3)) then
            exit( -1);
        exit( 3);
    end;
    (*
     * If we get this far and do any escaping at all must escape the escape
     * character itself: backslash.
     *)
    if (chtmp = ord('\')) and ( (flags and ESC_FLAGS)>0) then
    begin
        if (0>= io_ch(arg, PUTF8Char('\\'), 2)) then
            exit( -1);
        exit( 2);
    end;
    if (0>= io_ch(arg, @chtmp, 1)) then
        exit( -1);
    exit( 1);
end;



function do_buf( buf : PByte; buflen, _type : integer; flags : uint16; quotes : PInt8; io_ch : Tchar_io; arg : Pointer):integer;
var
  i,
  outlen,
  len,
  charwidth : integer;
  orflags   : uint16;
  p,
  q         : PByte;
  c         : Cardinal;
  utfbuf    : array[0..5] of Byte;
  utflen    : integer;
begin
    p := buf;
    q := buf + buflen;
    outlen := 0;
    charwidth := _type and BUF_TYPE_WIDTH_MASK;
    case charwidth of
        4:
        begin
            if (buflen and 3)>0 then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_UNIVERSALSTRING_LENGTH);
                Exit(-1);
            end;
        end;
        2:
        begin
            if (buflen and 1)>0 then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_BMPSTRING_LENGTH);
                Exit(-1);
            end;
        end;
        else
        begin
          //
        end;
    end;
    while p <> q do
    begin
        if (p = buf)  and  ( (flags and ASN1_STRFLGS_ESC_2253)>0 ) then
           orflags := CHARTYPE_FIRST_ESC_2253
        else
            orflags := 0;
        case charwidth of
            4:
            begin
                c := ulong(PostInc(p)^)  shl  24;
                c  := c  or (ulong(PostInc(p)^)  shl  16);
                c  := c  or (ulong(PostInc(p)^)  shl  8);
                c  := c  or ( PostInc(p)^);
            end;
            2:
            begin
                c := ulong(PostInc(p)^)  shl  8;
                c  := c  or (PostInc(p)^);
            end;
            1:
            begin
                c := PostInc(p)^;
            end;
            0:
            begin
                i := UTF8_getc(p, buflen, @c);
                if i < 0 then Exit(-1);      { Invalid UTF8String }
                buflen  := buflen - i;
                p  := p + i;
            end;
            else
                Exit(-1);          { invalid width }
        end;
        if (p = q)  and  ( (flags and ASN1_STRFLGS_ESC_2253)>0 ) then
           orflags := CHARTYPE_LAST_ESC_2253;
        if (_type and BUF_TYPE_CONVUTF8)>0 then
        begin
            utflen := UTF8_putc(@utfbuf, sizeof(utfbuf), c);
            for i := 0 to utflen-1 do
            begin
                {
                 * We don't need to worry about setting orflags correctly
                 * because if utflen=1 its value will be correct anyway
                 * otherwise each character will be > $7f and so the
                 * character will never be escaped on first and last.
                 }
                len := do_esc_char(utfbuf[i], flags or orflags, quotes,
                                  io_ch, arg);
                if len < 0 then
                   Exit(-1);
                outlen  := outlen + len;
            end;
        end
        else
        begin
            len := do_esc_char(c, flags or orflags, quotes,
                              io_ch, arg);
            if len < 0 then Exit(-1);
            outlen  := outlen + len;
        end;
    end;
    Result := outlen;
end;




function do_hex_dump( io_ch : Tchar_io; arg : Pointer; buf : PByte; buflen : integer):integer;
const
  hexdig : PUTF8Char = '0123456789ABCDEF';
var
  p, q : PByte;

  hextmp : array[0..1] of byte;
begin
    if arg <> nil then
    begin
        p := buf;
        q := buf + buflen;
        while p <> q do
        begin
            hextmp[0] := Ord(hexdig[p^  shr  4]);
            hextmp[1] := Ord(hexdig[p^ and $f]);
            if 0>= io_ch(arg, @hextmp, 2) then
                Exit(-1);
            Inc(p);
        end;
    end;
    Result := buflen  shl  1;
end;


function do_dump(lflags : Cardinal; io_ch : Tchar_io; arg : Pointer;const str : PASN1_STRING):integer;
var
  t : TASN1_TYPE;

  der_buf, p : PByte;

  outlen, der_len : integer;
begin
    {
     * Placing the ASN1_STRING in a temp ASN1_TYPE allows the DER encoding to
     * readily obtained
     }
    if 0>= io_ch(arg, PUTF8Char('#'), 1 ) then
        Exit(-1);
    { If we don't dump DER encoding just dump content octets }
    if 0>= (lflags and ASN1_STRFLGS_DUMP_DER) then
    begin
        outlen := do_hex_dump(io_ch, arg, str.data, str.length);
        if outlen < 0 then
           Exit(-1);
        Exit(outlen + 1);
    end;
    t._type := str.&type;
    t.value.ptr := PUTF8Char(str);
    der_len := i2d_ASN1_TYPE(@t, nil);
    if der_len <= 0 then
       Exit(-1);
    der_buf := OPENSSL_malloc(der_len);
    if der_buf = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(-1);
    end;
    p := der_buf;
    i2d_ASN1_TYPE(@t, @p);
    outlen := do_hex_dump(io_ch, arg, der_buf, der_len);
    OPENSSL_free(Pointer(der_buf));
    if outlen < 0 then
       Exit(-1);
    Result := outlen + 1;
end;




function do_print_ex(io_ch : Tchar_io; arg : Pointer; lflags : Cardinal;const str : PASN1_STRING):integer;
var
  outlen, len, _type : integer;
  quotes : int8;
  flags : uint16;
  tagname: PUTF8Char;
begin
    quotes := 0;
    { Keep a copy of escape flags }
    flags := UInt16(lflags and ESC_FLAGS);
    _type := str.&type;
    outlen := 0;
    if (lflags and ASN1_STRFLGS_SHOW_TYPE) > 0 then
    begin
        tagname := ASN1_tag2str(_type);
        outlen  := outlen + (Length(tagname));
        if (0>= io_ch(arg, tagname, outlen))  or  (0>= io_ch(arg, PUTF8Char(':'), 1)) then
            Exit(-1);
        Inc(outlen);
    end;
    { Decide what to do with type, either dump content or display it }
    { Dump everything }
    if (lflags and ASN1_STRFLGS_DUMP_ALL) > 0 then
       _type := -1
    { Ignore the string type }
    else
    if (lflags and ASN1_STRFLGS_IGNORE_TYPE) > 0  then
        _type := 1
    else
    begin
        { Else determine width based on type }
        if (_type > 0) and  (_type < 31) then
            _type := tag2nbyte[_type]
        else
            _type := -1;
        if (_type = -1)  and  (0>= (lflags and ASN1_STRFLGS_DUMP_UNKNOWN)) then
            _type := 1;
    end;
    if _type = -1 then
    begin
        len := do_dump(lflags, io_ch, arg, str);
        if len < 0 then
           Exit(-1);
        outlen  := outlen + len;
        Exit(outlen);
    end;
    if (lflags and ASN1_STRFLGS_UTF8_CONVERT) > 0 then
    begin
        {
         * Note: if string is UTF8 and we want to convert to UTF8 then we
         * just interpret it as 1 byte per character to avoid converting
         * twice.
         }
        if 0>= _type then
            _type := 1
        else
            _type  := _type  or BUF_TYPE_CONVUTF8;
    end;
    len := do_buf(str.data, str.length, _type, flags, @quotes, io_ch, nil);
    if len < 0 then
       Exit(-1);
    outlen  := outlen + len;
    if quotes > 0 then
        outlen  := outlen + 2;
    if nil = arg then
       Exit(outlen);
    if (quotes > 0)  and  (0>= io_ch(arg, PUTF8Char('\'), 1)) then
        Exit(-1);
    if do_buf(str.data, str.length, _type, flags, nil, io_ch, arg) < 0  then
        Exit(-1);
    if (quotes>0)  and  (0>= io_ch(arg, PUTF8Char('"'), 1 )) then
        Exit(-1);
    Result := outlen;
end;


function do_indent( io_ch : Tchar_io; arg : Pointer; indent : integer):integer;
var
  i : integer;
begin
    for i := 0 to indent-1 do
        if 0>= io_ch(arg, PUTF8Char(' '), 1) then
            Exit(0);
    Result := 1;
end;



function do_name_ex(io_ch : Tchar_io; arg : Pointer;const n : PX509_NAME; indent : integer; flags : Cardinal):integer;
var
  i,
  prev, orflags, cnt,
  fn_opt,
  fn_nid     : integer;

  fn         : PASN1_OBJECT;
  val        : PASN1_STRING;
  ent        : PX509_NAME_ENTRY;
  objtmp     : array[0..79] of UTF8Char;
  objbuf     : PUTF8Char;
  outlen,
  len        : integer;
  sep_dn,
  sep_mv,
  sep_eq     : PUTF8Char;
  sep_dn_len,
  sep_mv_len,
  sep_eq_len,
  objlen,
  fld_len    : integer;
begin
    prev := -1;
    if indent < 0 then
       indent := 0;
    outlen := indent;
    if 0>= do_indent(io_ch, arg, indent) then
        Exit(-1);
    case (flags and XN_FLAG_SEP_MASK) of
    XN_FLAG_SEP_MULTILINE:
    begin
        sep_dn := #10;
        sep_dn_len := 1;
        sep_mv := ' + ';
        sep_mv_len := 3;
    end;
    XN_FLAG_SEP_COMMA_PLUS:
    begin
        sep_dn := ',';
        sep_dn_len := 1;
        sep_mv := '+';
        sep_mv_len := 1;
        indent := 0;
    end;
    XN_FLAG_SEP_CPLUS_SPC:
    begin
        sep_dn := ', ';
        sep_dn_len := 2;
        sep_mv := ' + ';
        sep_mv_len := 3;
        indent := 0;
    end;
    XN_FLAG_SEP_SPLUS_SPC:
    begin
        sep_dn := '; ';
        sep_dn_len := 2;
        sep_mv := ' + ';
        sep_mv_len := 3;
        indent := 0;
    end;
    else
        Exit(-1);
    end;
    if (flags and XN_FLAG_SPC_EQ) > 0 then
    begin
        sep_eq := ' = ';
        sep_eq_len := 3;
    end
    else
    begin
        sep_eq := '=';
        sep_eq_len := 1;
    end;
    fn_opt := flags and XN_FLAG_FN_MASK;
    cnt := X509_NAME_entry_count(n);
    for i := 0 to cnt-1 do
    begin
        if (flags and XN_FLAG_DN_REV) > 0  then
           ent := X509_NAME_get_entry(n, cnt - i - 1)
        else
           ent := X509_NAME_get_entry(n, i);
        if prev <> -1 then
        begin
            if prev = X509_NAME_ENTRY_set(ent) then
            begin
                if 0>= io_ch(arg, sep_mv, sep_mv_len) then
                    Exit(-1);
                outlen  := outlen + sep_mv_len;
            end
            else
            begin
                if 0>= io_ch(arg, sep_dn, sep_dn_len) then
                    Exit(-1);
                outlen  := outlen + sep_dn_len;
                if 0>= do_indent(io_ch, arg, indent) then
                    Exit(-1);
                outlen  := outlen + indent;
            end;
        end;
        prev := X509_NAME_ENTRY_set(ent);
        fn := X509_NAME_ENTRY_get_object(ent);
        val := X509_NAME_ENTRY_get_data(ent);
        fn_nid := OBJ_obj2nid(fn);
        if fn_opt <> XN_FLAG_FN_NONE then
        begin
            if (fn_opt = XN_FLAG_FN_OID)  or  (fn_nid = NID_undef) then
            begin
                OBJ_obj2txt(objtmp, sizeof(objtmp), fn, 1);
                fld_len := 0;    { XXX: what should this be? }
                objbuf := objtmp;
            end
            else
            begin
                if fn_opt = XN_FLAG_FN_SN then
                begin
                    fld_len := FN_WIDTH_SN;
                    objbuf := OBJ_nid2sn(fn_nid);
                end
                else
                if (fn_opt = XN_FLAG_FN_LN)then
                begin
                    fld_len := FN_WIDTH_LN;
                    objbuf := OBJ_nid2ln(fn_nid);
                end
                else
                begin
                    fld_len := 0; { XXX: what should this be? }
                    objbuf := '';
                end;
            end;
            objlen := Length(objbuf);
            if 0>= io_ch(arg, objbuf, objlen) then
                Exit(-1);
            if (objlen < fld_len)  and ( (flags and XN_FLAG_FN_ALIGN)>0 ) then
            begin
                if 0>= do_indent(io_ch, arg, fld_len - objlen) then
                    Exit(-1);
                outlen  := outlen + (fld_len - objlen);
            end;
            if 0>= io_ch(arg, sep_eq, sep_eq_len) then
                Exit(-1);
            outlen  := outlen + (objlen + sep_eq_len);
        end;
        {
         * If the field name is unknown then fix up the DER dump flag. We
         * might want to limit this further so it will DER dump on anything
         * other than a few 'standard' fields.
         }
        if (fn_nid = NID_undef)  and ( (flags and XN_FLAG_DUMP_UNKNOWN_FIELDS)>0) then
            orflags := ASN1_STRFLGS_DUMP_ALL
        else
            orflags := 0;
        len := do_print_ex(io_ch, arg, flags or orflags, val);
        if len < 0 then
           Exit(-1);
        outlen  := outlen + len;
    end;
    Result := outlen;
end;

function X509_NAME_print_ex(_out : PBIO;const nm : PX509_NAME; indent : integer; flags : Cardinal):integer;
begin
    if flags = XN_FLAG_COMPAT then
       Exit(X509_NAME_print(_out, nm, indent));
    Result := do_name_ex(send_bio_chars, _out, nm, indent, flags);
end;


end.
