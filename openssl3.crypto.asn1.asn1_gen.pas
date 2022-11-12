unit openssl3.crypto.asn1.asn1_gen;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

const
   ASN1_FLAG_EXP_MAX = 20;
   ASN1_GEN_FORMAT_ASCII   =1;
  (* UTF8 *)
   ASN1_GEN_FORMAT_UTF8    =2;
  (* Hex *)
   ASN1_GEN_FORMAT_HEX     =3;
  (* List of bits *)
   ASN1_GEN_FORMAT_BITLIST =4;
   ASN1_GEN_SEQ_MAX_DEPTH  = 50;
   ASN1_GEN_FLAG           = $10000;
    ASN1_GEN_FLAG_IMP       = ASN1_GEN_FLAG or 1;
    ASN1_GEN_FLAG_EXP       = ASN1_GEN_FLAG or 2;
    ASN1_GEN_FLAG_TAG       = ASN1_GEN_FLAG or 3;
    ASN1_GEN_FLAG_BITWRAP   = ASN1_GEN_FLAG or 4;
    ASN1_GEN_FLAG_OCTWRAP   = ASN1_GEN_FLAG or 5;
    ASN1_GEN_FLAG_SEQWRAP   = ASN1_GEN_FLAG or 6;
    ASN1_GEN_FLAG_SETWRAP   = ASN1_GEN_FLAG or 7;
    ASN1_GEN_FLAG_FORMAT    = ASN1_GEN_FLAG or 8;
type
   tag_name_st = record
      strnam : PUTF8Char;
      len, tag : integer;
   end;
   Ptag_name_st = ^tag_name_st;

   Ttag_exp_type = record
      exp_tag,
      exp_class,
      exp_constructed,
      exp_pad         : integer;
      exp_len         : long;
   end;
   Ptag_exp_type = ^Ttag_exp_type;

   Ttag_exp_arg = record
    imp_tag,
    imp_class,
    utype,
    format    : integer;
    str       : PUTF8Char;
    exp_list  : array[0..(ASN1_FLAG_EXP_MAX)-1] of Ttag_exp_type;
    exp_count : integer;
  end;
  Ptag_exp_arg = ^Ttag_exp_arg;

 function ASN1_generate_v3(const str : PUTF8Char; cnf : PX509V3_CTX):PASN1_TYPE;
 function generate_v3(const str : PUTF8Char; cnf : PX509V3_CTX; depth : integer; perr : PInteger):PASN1_TYPE;
 function asn1_cb(const elem : PUTF8Char; len : integer; bitstr : Pointer):integer;
 function asn1_str2tag(const tagstr : PUTF8Char; len : integer):integer;
 function parse_tagging(const vstart : PUTF8Char; vlen : integer; ptag, pclass : PInteger):integer;
 function append_exp( arg : Ptag_exp_arg; exp_tag, exp_class, exp_constructed, exp_pad, imp_ok : integer):integer;
 function asn1_multi(utype : integer;const section : PUTF8Char; cnf : PX509V3_CTX; depth : integer; perr : PInteger):PASN1_TYPE;
 function asn1_str2type(str : PUTF8Char; format, utype : integer):PASN1_TYPE;
 function bitstr_cb(const elem : PUTF8Char; len : integer; bitstr : Pointer):integer;
 function ASN1_str2mask(const str : PUTF8Char; pmask : Pulong):integer;

var
  tntmp: Ptag_name_st;
  tnst : array of tag_name_st;

function mask_cb(const elem : PUTF8Char; len : integer; arg : Pointer):integer;

implementation
uses OpenSSL3.Err,  OpenSSL3.common,  OpenSSL3.openssl.conf,
     openssl3.crypto.asn1.tasn_typ,   openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.asn1_lib,   openssl3.crypto.mem,
     openssl3.crypto.asn1.tasn_dec,   openssl3.crypto.o_str,
     openssl3.crypto.asn1.a_time,     openssl3.crypto.asn1.a_mbstr,
     openssl3.crypto.asn1.a_bitstr,   openssl3.crypto.conf.conf_mod,
     OpenSSL3.crypto.x509.v3_utl,     openssl3.crypto.objects.obj_dat,
     OpenSSL3.include.openssl.asn1,   OpenSSL3.crypto.x509.v3_conf;





function mask_cb(const elem : PUTF8Char; len : integer; arg : Pointer):integer;
var
  pmask : Pulong;
  tmpmask: ulong;
  tag : integer;
begin
    pmask := arg;
    if elem = nil then Exit(0);
    if (len = 3)  and  (HAS_PREFIX(elem, 'DIR')) then
    begin
        pmask^  := pmask^  or B_ASN1_DIRECTORYSTRING;
        Exit(1);
    end;
    tag := asn1_str2tag(elem, len);
    if (0>=tag)  or  (tag and ASN1_GEN_FLAG > 0) then
        Exit(0);
    tmpmask := ASN1_tag2bit(tag);
    if 0>=tmpmask then Exit(0);
    pmask^  := pmask^  or tmpmask;
    Result := 1;
end;


function ASN1_str2mask(const str : PUTF8Char; pmask : Pulong):integer;
begin
    pmask^ := 0;
    Result := CONF_parse_list(str, Ord('|'), 1, mask_cb, pmask);
end;



function bitstr_cb(const elem : PUTF8Char; len : integer; bitstr : Pointer):integer;
var
  bitnum : long;

  eptr : PUTF8Char;
begin
    if nil = elem then Exit(0);
    bitnum := strtoul(elem, @eptr, 10);
    if (eptr <> nil)  and  (eptr^ <> #0)  and  (eptr <> elem + len) then
        Exit(0);
    if bitnum < 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_NUMBER);
        Exit(0);
    end;
    if 0>= ASN1_BIT_STRING_set_bit(bitstr, bitnum, 1) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    Result := 1;
end;


function asn1_str2type(str : PUTF8Char; format, utype : integer):PASN1_TYPE;
var
    atmp      : PASN1_TYPE;
    vtmp      : TCONF_VALUE;
    rdata     : PByte;
    rdlen     : long;
    no_unused : integer;
    label _bad_form, _bad_str;
begin
    atmp := nil;
    no_unused := 1;
    atmp := ASN1_TYPE_new();
    if atmp = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if nil = str then
       str := '';

    case utype of
        V_ASN1_NULL:
        begin
            if (str <> nil)  and  (str^ <> #0) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_NULL_VALUE);
                goto _bad_form ;
            end;
        end;
        V_ASN1_BOOLEAN:
        begin
            if format <> ASN1_GEN_FORMAT_ASCII then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_NOT_ASCII_FORMAT);
                goto _bad_form ;
            end;
            vtmp.name := nil;
            vtmp.section := nil;
            vtmp.value := PUTF8Char(str);
            if 0>= X509V3_get_value_bool(@vtmp, @atmp.value._boolean) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_BOOLEAN);
                goto _bad_str ;
            end;
        end;
        V_ASN1_INTEGER,
        V_ASN1_ENUMERATED:
        begin
            if format <> ASN1_GEN_FORMAT_ASCII then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_INTEGER_NOT_ASCII_FORMAT);
                goto _bad_form ;
            end;
            atmp.value._integer := s2i_ASN1_INTEGER(nil, str);
            if (atmp.value._integer = nil) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_INTEGER);
                goto _bad_str ;
            end;
        end;
        V_ASN1_OBJECT:
        begin
            if format <> ASN1_GEN_FORMAT_ASCII then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_OBJECT_NOT_ASCII_FORMAT);
                goto _bad_form ;
            end;
            atmp.value._object := OBJ_txt2obj(str, 0);
            if atmp.value._object = nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_OBJECT);
                goto _bad_str ;
            end;
        end;
        V_ASN1_UTCTIME,
        V_ASN1_GENERALIZEDTIME:
        begin
            if format <> ASN1_GEN_FORMAT_ASCII then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_TIME_NOT_ASCII_FORMAT);
                goto _bad_form ;
            end;
            atmp.value.asn1_string := ASN1_STRING_new();
            if atmp.value.asn1_string = nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                goto _bad_str ;
            end;
            if 0>= ASN1_STRING_set(atmp.value.asn1_string, str, -1) then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                goto _bad_str ;
            end;
            atmp.value.asn1_string.&type := utype;
            if 0>= ASN1_TIME_check(PASN1_TIME(atmp.value.asn1_string)) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_TIME_VALUE);
                goto _bad_str ;
            end;
        end;
        V_ASN1_BMPSTRING,
        V_ASN1_PRINTABLESTRING,
        V_ASN1_IA5STRING,
        V_ASN1_T61STRING,
        V_ASN1_UTF8STRING,
        V_ASN1_VISIBLESTRING,
        V_ASN1_UNIVERSALSTRING,
        V_ASN1_GENERALSTRING,
        V_ASN1_NUMERICSTRING:
        begin
            if format = ASN1_GEN_FORMAT_ASCII then
               format := MBSTRING_ASC
            else
            if (format = ASN1_GEN_FORMAT_UTF8)then
                format := MBSTRING_UTF8
            else
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_FORMAT);
                goto _bad_form ;
            end;
            if ASN1_mbstring_copy(@atmp.value.asn1_string, PByte( str),
                                   -1, format, ASN1_tag2bit(utype)) <= 0  then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                goto _bad_str ;
            end;
        end;
        V_ASN1_BIT_STRING,
        V_ASN1_OCTET_STRING:
        begin
            atmp.value.asn1_string := ASN1_STRING_new();
            if atmp.value.asn1_string =  nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                goto _bad_form ;
            end;
            if format = ASN1_GEN_FORMAT_HEX then
            begin
                rdata := OPENSSL_hexstr2buf(str, @rdlen);
                if rdata = nil then
                begin
                    ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_HEX);
                    goto _bad_str ;
                end;
                atmp.value.asn1_string.data := rdata;
                atmp.value.asn1_string.length := rdlen;
                atmp.value.asn1_string.&type := utype;
            end
            else
            if (format = ASN1_GEN_FORMAT_ASCII) then
                ASN1_STRING_set(atmp.value.asn1_string, str, -1)
            else
            if ((format = ASN1_GEN_FORMAT_BITLIST)
                      and  (utype = V_ASN1_BIT_STRING)) then
            begin
                if 0>= CONF_parse_list
                    (str, ord(','), 1, bitstr_cb, atmp.value.bit_string) then
                begin
                    ERR_raise(ERR_LIB_ASN1, ASN1_R_LIST_ERROR);
                    goto _bad_str ;
                end;
                no_unused := 0;
            end
            else
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_BITSTRING_FORMAT);
                goto _bad_form ;
            end;
            if (utype = V_ASN1_BIT_STRING)  and  (no_unused >0) then
            begin
                atmp.value.asn1_string.flags := atmp.value.asn1_string.flags
                     and not (ASN1_STRING_FLAG_BITS_LEFT or $07);
                atmp.value.asn1_string.flags  := atmp.value.asn1_string.flags  or ASN1_STRING_FLAG_BITS_LEFT;
            end;
        end
        else
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_UNSUPPORTED_TYPE);
            goto _bad_str ;
        end;
    end;
    atmp._type := utype;
    Exit(atmp);
 _bad_str:
    ERR_add_error_data(2, ['string=', str]);
 _bad_form:
    ASN1_TYPE_free(atmp);
    Exit(nil);
end;

function asn1_multi(utype : integer;const section : PUTF8Char; cnf : PX509V3_CTX; depth : integer; perr : PInteger):PASN1_TYPE;
var
  ret : PASN1_TYPE;
  sk : Pstack_st_ASN1_TYPE;
  sect : Pstack_st_CONF_VALUE;
  der : PByte;
  derlen, i : integer;
  typ : PASN1_TYPE;
  label _bad;
begin
    ret := nil;
    sk := nil;
    sect := nil;
    der := nil;
    sk := sk_ASN1_TYPE_new_null();
    if nil = sk then
       goto _bad ;
    if section <> nil then
    begin
        if nil = cnf then
            goto _bad ;
        sect := X509V3_get_section(cnf, PUTF8Char(section));
        if nil = sect then
           goto _bad ;
        for i := 0 to sk_CONF_VALUE_num(sect)-1 do
        begin
            typ := generate_v3(sk_CONF_VALUE_value(sect, i).value, cnf,
                                              depth + 1, perr);
            if nil = typ then
               goto _bad ;
            if 0>= sk_ASN1_TYPE_push(sk, typ) then
               goto _bad ;
        end;
    end;
    {
     * Now we has a STACK of the components, convert to the correct form
     }
    if utype = V_ASN1_SET then
       derlen := i2d_ASN1_SET_ANY(sk, @der)
    else
        derlen := i2d_ASN1_SEQUENCE_ANY(sk, @der);
    if derlen < 0 then
       goto _bad ;
    ret := ASN1_TYPE_new();
    if ret =  nil then
        goto _bad ;
    ret.value.asn1_string := ASN1_STRING_type_new(utype);
    if ret.value.asn1_string = nil then
        goto _bad ;
    ret._type := utype;
    ret.value.asn1_string.data := der;
    ret.value.asn1_string.length := derlen;
    der := nil;
 _bad:
    OPENSSL_free(der);
    sk_ASN1_TYPE_pop_free(sk, ASN1_TYPE_free);
    X509V3_section_free(cnf, sect);
    Result := ret;
end;




function append_exp( arg : Ptag_exp_arg; exp_tag, exp_class, exp_constructed, exp_pad, imp_ok : integer):integer;
var
  exp_tmp : Ptag_exp_type;
begin
    { Can only have IMPLICIT if permitted }
    if (arg.imp_tag <> -1)  and  (0>= imp_ok) then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_IMPLICIT_TAG);
        Exit(0);
    end;
    if arg.exp_count = ASN1_FLAG_EXP_MAX then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_DEPTH_EXCEEDED);
        Exit(0);
    end;
    exp_tmp := @arg.exp_list[PostInc(arg.exp_count)];
    {
     * If IMPLICIT set tag to implicit value then reset implicit tag since it
     * has been used.
     }
    if arg.imp_tag <> -1 then
    begin
        exp_tmp.exp_tag := arg.imp_tag;
        exp_tmp.exp_class := arg.imp_class;
        arg.imp_tag := -1;
        arg.imp_class := -1;
    end
    else
    begin
        exp_tmp.exp_tag := exp_tag;
        exp_tmp.exp_class := exp_class;
    end;
    exp_tmp.exp_constructed := exp_constructed;
    exp_tmp.exp_pad := exp_pad;
    Result := 1;
end;



function parse_tagging(const vstart : PUTF8Char; vlen : integer; ptag, pclass : PInteger):integer;
var
  tag_num : long;

  eptr : PUTF8Char;
begin
    if nil = vstart then Exit(0);
    tag_num := strtoul(vstart, @eptr, 10);
    { Check we haven't gone past max length: should be impossible }
    if (eptr <> nil)  and  (eptr^ <> #0)  and  (eptr > vstart + vlen) then
        Exit(0);
    if tag_num < 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_NUMBER);
        Exit(0);
    end;
    ptag^ := tag_num;
    { If we have non numeric characters, parse them }
    if eptr <> nil then
       vlen  := vlen - (eptr - vstart)
    else
        vlen := 0;
    if vlen >0 then
    begin
        case  eptr^ of
            'U':
                pclass^ := V_ASN1_UNIVERSAL;
                //break;
            'A':
                pclass^ := V_ASN1_APPLICATION;
                //break;
            'P':
                pclass^ := V_ASN1_PRIVATE;
                //break;
            'C':
                pclass^ := V_ASN1_CONTEXT_SPECIFIC;
                //break;
            else
            begin
                ERR_raise_data(ERR_LIB_ASN1, ASN1_R_INVALID_MODIFIER,
                              format( 'Char=%c', [eptr^]));
                Exit(0);
            end;
        end;
    end
    else
        pclass^ := V_ASN1_CONTEXT_SPECIFIC;
    Exit(1);
end;





function asn1_str2tag(const tagstr : PUTF8Char; len : integer):integer;
var
  i : uint32;
begin
    if len = -1 then
       len := Length(tagstr);
    tntmp := @tnst[0];
    i := 0;
    while i < Length(tnst) do
    begin
        if (len = tntmp.len )  and  (strncasecmp(tntmp.strnam, tagstr, len) = 0) then
            Exit(tntmp.tag);
        Inc(i);
        Inc(tntmp);
    end;
    Result := -1;
end;


function ASN1_GEN_STR(str: PUTF8Char; val: integer): tag_name_st;
begin
   Result.strnam  := str;
   Result.len     := sizeof(str) - 1;
   Result.tag     := val;
end;

function asn1_cb(const elem : PUTF8Char; len : integer; bitstr : Pointer):integer;
var
  arg       : Ptag_exp_arg;
  i,
  utype,
  vlen      : integer;
  p,
  vstart    : PUTF8Char;
  tmp_tag,
  tmp_class : integer;
begin
    arg := bitstr;
    vlen := 0;
    vstart := nil;
    if elem = nil then Exit(-1);
    i := 0; p := elem;
    while i < len do
    begin
        { Look for the ':' in name value pairs }
        if p^ = ':' then
        begin
            vstart := p + 1;
            vlen := len - (vstart - elem);
            len := p - elem;
            break;
        end;
        Inc(p);
        Inc(i);
    end;
    utype := asn1_str2tag(elem, len);
    if utype = -1 then
    begin
        ERR_raise_data(ERR_LIB_ASN1, ASN1_R_UNKNOWN_TAG, Format( 'tag=%s', [elem]));
        Exit(-1);
    end;
    { If this is not a modifier mark end of string and exit }
    if 0>= (utype and ASN1_GEN_FLAG) then
    begin
        arg.utype := utype;
        arg.str := vstart;
        { If no value and not end of string, error }
        if (nil = vstart)  and  (elem[len] <> #0) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_MISSING_VALUE);
            Exit(-1);
        end;
        Exit(0);
    end;

    case utype of
        ASN1_GEN_FLAG_IMP:
        begin
            { Check for illegal multiple IMPLICIT tagging }
            if arg.imp_tag <> -1 then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_NESTED_TAGGING);
                Exit(-1);
            end;
            if 0>= parse_tagging(vstart, vlen, @arg.imp_tag, @arg.imp_class) then
                Exit(-1);
        end;
        ASN1_GEN_FLAG_EXP:
        begin
            if 0>= parse_tagging(vstart, vlen, @tmp_tag, @tmp_class) then
                Exit(-1);
            if 0>= append_exp(arg, tmp_tag, tmp_class, 1, 0, 0) then
                Exit(-1);
        end;
        ASN1_GEN_FLAG_SEQWRAP:
        begin
            if 0>= append_exp(arg, V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL, 1, 0, 1) then
                Exit(-1);
        end;
        ASN1_GEN_FLAG_SETWRAP:
        begin
            if 0>= append_exp(arg, V_ASN1_SET, V_ASN1_UNIVERSAL, 1, 0, 1) then
                Exit(-1);
        end;
        ASN1_GEN_FLAG_BITWRAP:
        begin
            if 0>= append_exp(arg, V_ASN1_BIT_STRING, V_ASN1_UNIVERSAL, 0, 1, 1) then
                Exit(-1);
        end;
        ASN1_GEN_FLAG_OCTWRAP:
        begin
            if 0>= append_exp(arg, V_ASN1_OCTET_STRING, V_ASN1_UNIVERSAL, 0, 0, 1) then
                Exit(-1);
        end;
        ASN1_GEN_FLAG_FORMAT:
        begin
            if nil = vstart then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_FORMAT);
                Exit(-1);
            end;
            if HAS_PREFIX(vstart, 'ASCII' ) then
                arg.format := ASN1_GEN_FORMAT_ASCII
            else if (HAS_PREFIX(vstart, 'UTF8'))  then
                arg.format := ASN1_GEN_FORMAT_UTF8
            else if (HAS_PREFIX(vstart, 'HEX'))  then
                arg.format := ASN1_GEN_FORMAT_HEX
            else if (HAS_PREFIX(vstart, 'BITLIST')) then
                arg.format := ASN1_GEN_FORMAT_BITLIST
            else
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_UNKNOWN_FORMAT);
                Exit(-1);
            end;
        end;
    end;
    Exit(1);
end;

function generate_v3(const str : PUTF8Char; cnf : PX509V3_CTX; depth : integer; perr : PInteger):PASN1_TYPE;
var
    ret             : PASN1_TYPE;
    asn1_tags       : Ttag_exp_arg;
    etmp            : Ptag_exp_type;
    i,
    len             : integer;
    orig_der,
    new_der,
    cpy_start,
    p,
    cp              : PByte;
    cpy_len         : integer;
    hdr_len         : long;

    hdr_constructed,
    r,
    hdr_tag,
    hdr_class       : integer;
    label _err;
begin
{$POINTERMATH ON}
    orig_der := nil;
    new_der := nil;
    hdr_len := 0;
    hdr_constructed := 0;
    asn1_tags.imp_tag := -1;
    asn1_tags.imp_class := -1;
    asn1_tags.format := ASN1_GEN_FORMAT_ASCII;
    asn1_tags.exp_count := 0;
    if CONF_parse_list(str, Ord(','), 1, asn1_cb, @asn1_tags) <> 0  then
    begin
        perr^ := ASN1_R_UNKNOWN_TAG;
        Exit(nil);
    end;
    if (asn1_tags.utype = V_ASN1_SEQUENCE)  or  (asn1_tags.utype = V_ASN1_SET) then
    begin
        if nil = cnf then
        begin
            perr^ := ASN1_R_SEQUENCE_OR_SET_NEEDS_CONFIG;
            Exit(nil);
        end;
        if depth >= ASN1_GEN_SEQ_MAX_DEPTH then
        begin
            perr^ := ASN1_R_ILLEGAL_NESTED_TAGGING;
            Exit(nil);
        end;
        ret := asn1_multi(asn1_tags.utype, asn1_tags.str, cnf, depth, perr);
    end
    else
        ret := asn1_str2type(asn1_tags.str, asn1_tags.format, asn1_tags.utype);
    if nil = ret then
       Exit(nil);
    { If no tagging return base type }
    if (asn1_tags.imp_tag = -1)  and  (asn1_tags.exp_count = 0) then
        Exit(ret);
    { Generate the encoding }
    cpy_len := i2d_ASN1_TYPE(ret, @orig_der);
    ASN1_TYPE_free(ret);
    ret := nil;
    { Set point to start copying for modified encoding }
    cpy_start := orig_der;
    { Do we need IMPLICIT tagging? }
    if asn1_tags.imp_tag <> -1 then
    begin
        { If IMPLICIT we will replace the underlying tag }
        { Skip existing tag+len }
        r := ASN1_get_object(@cpy_start, @hdr_len, @hdr_tag, @hdr_class,
                            cpy_len);
        if (r and $80) > 0 then
           goto _err ;
        { Update copy length }
        cpy_len  := cpy_len - (cpy_start - orig_der);
        {
         * For IMPLICIT tagging the length should match the original length
         * and constructed flag should be consistent.
         }
        if (r and $1) > 0 then
        begin
            { Indefinite length constructed }
            hdr_constructed := 2;
            hdr_len := 0;
        end
        else
            { Just retain constructed flag }
            hdr_constructed := r and V_ASN1_CONSTRUCTED;
        {
         * Work out new length with IMPLICIT tag: ignore constructed because
         * it will mess up if indefinite length
         }
        len := ASN1_object_size(0, hdr_len, asn1_tags.imp_tag);
    end
    else
        len := cpy_len;
    { Work out length in any EXPLICIT, starting from end }
     etmp := Ptag_exp_type(@asn1_tags.exp_list) + asn1_tags.exp_count - 1;
    for i := 0 to asn1_tags.exp_count-1 do
    begin
        { Content length: number of content octets + any padding }
        len  := len + etmp.exp_pad;
        etmp.exp_len := len;
        { Total object length: length including new header }
        len := ASN1_object_size(0, len, etmp.exp_tag);
        Dec(etmp);
    end;
    { Allocate buffer for new encoding }
    new_der := OPENSSL_malloc(len);
    if new_der = nil then goto _err ;
    { Generate tagged encoding }
    p := new_der;
    { Output explicit tags first }
    etmp := @asn1_tags.exp_list;
    for i := 0 to asn1_tags.exp_count-1 do
    begin
        ASN1_put_object(@p, etmp.exp_constructed, etmp.exp_len,
                        etmp.exp_tag, etmp.exp_class);
        if etmp.exp_pad > 0 then
          PostInc(p)^ :=  0;
        Inc(etmp);
    end;
    { If IMPLICIT, output tag }
    if asn1_tags.imp_tag <> -1 then
    begin
        if (asn1_tags.imp_class = V_ASN1_UNIVERSAL)
             and ( (asn1_tags.imp_tag = V_ASN1_SEQUENCE) or
                   (asn1_tags.imp_tag = V_ASN1_SET)) then
            hdr_constructed := V_ASN1_CONSTRUCTED;
        ASN1_put_object(@p, hdr_constructed, hdr_len,
                        asn1_tags.imp_tag, asn1_tags.imp_class);
    end;
    { Copy across original encoding }
    memcpy(p, cpy_start, cpy_len);
    cp := new_der;
    { Obtain new ASN1_TYPE structure }
    ret := d2i_ASN1_TYPE(nil, @cp, len);
 _err:
    OPENSSL_free(orig_der);
    OPENSSL_free(new_der);
    Exit(ret);
 {$POINTERMATH OFF}
end;

function ASN1_generate_v3(const str : PUTF8Char; cnf : PX509V3_CTX):PASN1_TYPE;
var
  err : integer;

  ret : PASN1_TYPE;
begin
    err := 0;
    ret := generate_v3(str, cnf, 0, @err);
    if err > 0 then
       ERR_raise(ERR_LIB_ASN1, err);
    Result := ret;
end;

initialization
    tnst := [
        ASN1_GEN_STR('BOOL', V_ASN1_BOOLEAN),
        ASN1_GEN_STR('BOOLEAN', V_ASN1_BOOLEAN),
        ASN1_GEN_STR('NULL', V_ASN1_NULL),
        ASN1_GEN_STR('INT', V_ASN1_INTEGER),
        ASN1_GEN_STR('INTEGER', V_ASN1_INTEGER),
        ASN1_GEN_STR('ENUM', V_ASN1_ENUMERATED),
        ASN1_GEN_STR('ENUMERATED', V_ASN1_ENUMERATED),
        ASN1_GEN_STR('OID', V_ASN1_OBJECT),
        ASN1_GEN_STR('OBJECT', V_ASN1_OBJECT),
        ASN1_GEN_STR('UTCTIME', V_ASN1_UTCTIME),
        ASN1_GEN_STR('UTC', V_ASN1_UTCTIME),
        ASN1_GEN_STR('GENERALIZEDTIME', V_ASN1_GENERALIZEDTIME),
        ASN1_GEN_STR('GENTIME', V_ASN1_GENERALIZEDTIME),
        ASN1_GEN_STR('OCT', V_ASN1_OCTET_STRING),
        ASN1_GEN_STR('OCTETSTRING', V_ASN1_OCTET_STRING),
        ASN1_GEN_STR('BITSTR', V_ASN1_BIT_STRING),
        ASN1_GEN_STR('BITSTRING', V_ASN1_BIT_STRING),
        ASN1_GEN_STR('UNIVERSALSTRING', V_ASN1_UNIVERSALSTRING),
        ASN1_GEN_STR('UNIV', V_ASN1_UNIVERSALSTRING),
        ASN1_GEN_STR('IA5', V_ASN1_IA5STRING),
        ASN1_GEN_STR('IA5STRING', V_ASN1_IA5STRING),
        ASN1_GEN_STR('UTF8', V_ASN1_UTF8STRING),
        ASN1_GEN_STR('UTF8String', V_ASN1_UTF8STRING),
        ASN1_GEN_STR('BMP', V_ASN1_BMPSTRING),
        ASN1_GEN_STR('BMPSTRING', V_ASN1_BMPSTRING),
        ASN1_GEN_STR('VISIBLESTRING', V_ASN1_VISIBLESTRING),
        ASN1_GEN_STR('VISIBLE', V_ASN1_VISIBLESTRING),
        ASN1_GEN_STR('PRINTABLESTRING', V_ASN1_PRINTABLESTRING),
        ASN1_GEN_STR('PRINTABLE', V_ASN1_PRINTABLESTRING),
        ASN1_GEN_STR('T61', V_ASN1_T61STRING),
        ASN1_GEN_STR('T61STRING', V_ASN1_T61STRING),
        ASN1_GEN_STR('TELETEXSTRING', V_ASN1_T61STRING),
        ASN1_GEN_STR('GeneralString', V_ASN1_GENERALSTRING),
        ASN1_GEN_STR('GENSTR', V_ASN1_GENERALSTRING),
        ASN1_GEN_STR('NUMERIC', V_ASN1_NUMERICSTRING),
        ASN1_GEN_STR('NUMERICSTRING', V_ASN1_NUMERICSTRING),

        (* Special cases *)
        ASN1_GEN_STR('SEQUENCE', V_ASN1_SEQUENCE),
        ASN1_GEN_STR('SEQ', V_ASN1_SEQUENCE),
        ASN1_GEN_STR('SET', V_ASN1_SET),
        (* type modifiers *)
        (* Explicit tag *)
        ASN1_GEN_STR('EXP', ASN1_GEN_FLAG_EXP),
        ASN1_GEN_STR('EXPLICIT', ASN1_GEN_FLAG_EXP),
        (* Implicit tag *)
        ASN1_GEN_STR('IMP', ASN1_GEN_FLAG_IMP),
        ASN1_GEN_STR('IMPLICIT', ASN1_GEN_FLAG_IMP),
        (* OCTET STRING wrapper *)
        ASN1_GEN_STR('OCTWRAP', ASN1_GEN_FLAG_OCTWRAP),
        (* SEQUENCE wrapper *)
        ASN1_GEN_STR('SEQWRAP', ASN1_GEN_FLAG_SEQWRAP),
        (* SET wrapper *)
        ASN1_GEN_STR('SETWRAP', ASN1_GEN_FLAG_SETWRAP),
        (* BIT STRING wrapper *)
        ASN1_GEN_STR('BITWRAP', ASN1_GEN_FLAG_BITWRAP),
        ASN1_GEN_STR('FORM', ASN1_GEN_FLAG_FORMAT),
        ASN1_GEN_STR('FORMAT', ASN1_GEN_FLAG_FORMAT)
   ];
end.
