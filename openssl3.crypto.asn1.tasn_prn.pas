unit openssl3.crypto.asn1.tasn_prn;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ASN1_item_print(_out : PBIO;const ifld : PASN1_VALUE; indent : integer;const it : PASN1_ITEM; pctx : PASN1_PCTX):integer;

var
  default_pctx: TASN1_PCTX  = (
    flags: ASN1_PCTX_FLAGS_SHOW_ABSENT; (* flags *)
    nm_flags: 0;                          (* nm_flags *)
    cert_flags: 0;                          (* cert_flags *)
    oid_flags: 0;                          (* oid_flags *)
    str_flags: 0                           (* str_flags *)
 );

function asn1_item_print_ctx(_out : PBIO;const fld : PPASN1_VALUE; indent : integer;const it : PASN1_ITEM; fname, sname : PUTF8Char; nohdr : integer;const pctx : PASN1_PCTX):integer;
function asn1_print_fsname(_out : PBIO; indent : integer; fname, sname : PUTF8Char; pctx : PASN1_PCTX):integer;
function asn1_template_print_ctx(_out : PBIO;{const} fld : PPASN1_VALUE; indent : integer;const tt : PASN1_TEMPLATE; pctx : PASN1_PCTX):integer;
function asn1_primitive_print(_out : PBIO;{const} fld : PPASN1_VALUE; it : PASN1_ITEM; indent : integer;const fname, sname : PUTF8Char; pctx : PASN1_PCTX):integer;
function asn1_print_boolean( _out : PBIO; boolval : integer):integer;
function asn1_print_integer(_out : PBIO;const str : PASN1_INTEGER):integer;
function asn1_print_oid(_out : PBIO;const oid : PASN1_OBJECT):integer;
function asn1_print_obstring(_out : PBIO;const str : PASN1_STRING; indent : integer):integer;

 const
   spaces: PUTF8Char  = '                    ';
 var
  nspaces : integer = sizeof(spaces) - 1;

implementation
uses openssl3.crypto.bio.bio_lib, openssl3.crypto.bio.bio_print,
     OpenSSL3.crypto.x509.v3_utl,  openssl3.crypto.mem,
     openssl3.crypto.asn1.a_strex,  openssl3.crypto.asn1.tasn_utl,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.bio.bio_dump,
     openssl3.crypto.asn1.a_utctm, openssl3.crypto.asn1.a_gentm,
     openssl3.crypto.asn1.asn1_lib, openssl3.crypto.asn1.asn1_parse;






function asn1_print_obstring(_out : PBIO;const str : PASN1_STRING; indent : integer):integer;
begin
    if str.&type = V_ASN1_BIT_STRING then
    begin
        if BIO_printf(_out, ' (%ld unused bits)'#10, [str.flags and $7]) <= 0 then
            Exit(0);
    end
    else
    if (BIO_puts(_out, #10) <= 0) then
        Exit(0);
    if (str.length > 0)  and  (BIO_dump_indent(_out, PUTF8Char(str.data), str.length,
                           indent + 2) <= 0) then
        Exit(0);
    Result := 1;
end;





function asn1_print_oid(_out : PBIO;const oid : PASN1_OBJECT):integer;
var
  objbuf : array[0..79] of UTF8Char;

  ln : PUTF8Char;
begin
    ln := OBJ_nid2ln(OBJ_obj2nid(oid));
    if nil = ln then ln := '';
    OBJ_obj2txt(objbuf, sizeof(objbuf), oid, 1);
    if BIO_printf(_out, '%s (%s)', [ln, objbuf]) <= 0 then
        Exit(0);
    Result := 1;
end;



function asn1_print_integer(_out : PBIO;const str : PASN1_INTEGER):integer;
var
  s : PUTF8Char;

  ret : integer;
begin
    ret := 1;
    s := i2s_ASN1_INTEGER(nil, str);
    if s = nil then Exit(0);
    if BIO_puts(_out, s) <= 0  then
        ret := 0;
    OPENSSL_free(s);
    Result := ret;
end;

function asn1_print_boolean( _out : PBIO; boolval : integer):integer;
var
  str : PUTF8Char;
begin
    case boolval of
      -1:
          str := 'BOOL ABSENT';
          //break;
      0:
          str := 'FALSE';
          //break;
      else
          str := 'TRUE';
          //break;
    end;
    if BIO_puts(_out, str) <= 0  then
        Exit(0);
    Exit(1);
end;



function asn1_primitive_print(_out : PBIO;{const} fld : PPASN1_VALUE; it : PASN1_ITEM; indent : integer;const fname, sname : PUTF8Char; pctx : PASN1_PCTX):integer;
var
  utype : long;
  str : PASN1_STRING;
  ret, needlf : integer;
  pname : PUTF8Char;
  pf : PASN1_PRIMITIVE_FUNCS;
  atype : PASN1_TYPE;
  boolval : integer;
begin
    ret := 1; needlf := 1;
    pf := it.funcs;
    if 0>= asn1_print_fsname(_out, indent, fname, sname, pctx) then
        Exit(0);
    if (pf <> nil)  and  (Assigned(pf.prim_print)) then
       Exit(pf.prim_print(_out, fld, it, indent, pctx));
    if it.itype = ASN1_ITYPE_MSTRING then
    begin
        str := PASN1_STRING(fld^);
        utype := str.&type and not V_ASN1_NEG;
    end
    else
    begin
        utype := it.utype;
        if utype = V_ASN1_BOOLEAN then
           str := nil
        else
            str := PASN1_STRING(fld^);
    end;
    if utype = V_ASN1_ANY then
    begin
         atype := PASN1_TYPE(fld^);
        utype := atype._type;
        fld := PPASN1_VALUE(@atype.value.asn1_value); { actually is const }
        str := PASN1_STRING(fld^);
        if (pctx.flags and ASN1_PCTX_FLAGS_NO_ANY_TYPE) > 0 then
            pname := nil
        else
            pname := ASN1_tag2str(utype);
    end
    else
    begin
        if (pctx.flags and ASN1_PCTX_FLAGS_SHOW_TYPE) > 0 then
            pname := ASN1_tag2str(utype)
        else
            pname := nil;
    end;
    if utype = V_ASN1_NULL then
    begin
        if BIO_puts(_out, 'null'#10) <= 0 then
            Exit(0);
        Exit(1);
    end;
    if pname <> nil then
    begin
        if BIO_puts(_out, pname) <= 0 then
            Exit(0);
        if BIO_puts(_out, ':') <= 0  then
            Exit(0);
    end;
    case utype of
        V_ASN1_BOOLEAN:
        begin
            boolval := PInteger(fld)^;
            if boolval = -1 then
               boolval := it.size;
            ret := asn1_print_boolean(_out, boolval);
        end;
        //break;
        V_ASN1_INTEGER,
        V_ASN1_ENUMERATED:
            ret := asn1_print_integer(_out, PASN1_INTEGER(str));
            //break;
        V_ASN1_UTCTIME:
            ret := ASN1_UTCTIME_print(_out, PASN1_UTCTIME(str));
            //break;
        V_ASN1_GENERALIZEDTIME:
            ret := ASN1_GENERALIZEDTIME_print(_out, PASN1_TIME(str));
            //break;
        V_ASN1_OBJECT:
            ret := asn1_print_oid(_out, PASN1_OBJECT(fld^));
            //break;
        V_ASN1_OCTET_STRING,
        V_ASN1_BIT_STRING:
        begin
             ret := asn1_print_obstring(_out, str, indent);
            needlf := 0;
        end;
        V_ASN1_SEQUENCE,
        V_ASN1_SET,
        V_ASN1_OTHER:
        begin
             if BIO_puts(_out, #10) <= 0  then
                Exit(0);
            if ASN1_parse_dump(_out, str.data, str.length, indent, 0) <= 0  then
                ret := 0;
            needlf := 0;
        end;
        else
            ret := ASN1_STRING_print_ex(_out, str, pctx.str_flags);
    end;
    if 0>= ret then
       Exit(0);
    if (needlf > 0) and  (BIO_puts(_out, #10) <= 0) then
        Exit(0);
    Result := 1;
end;

function asn1_template_print_ctx(_out : PBIO;{const} fld : PPASN1_VALUE; indent : integer;const tt : PASN1_TEMPLATE; pctx : PASN1_PCTX):integer;
var
  i, flags : integer;
  sname, fname : PUTF8Char;
  tfld : PASN1_VALUE;
  tname : PUTF8Char;
  skitem : PASN1_VALUE;
  stack : Pstack_st_const_ASN1_VALUE;
  item: PASN1_ITEM;
begin
    flags := tt.flags;
    if (pctx.flags and ASN1_PCTX_FLAGS_SHOW_FIELD_STRUCT_NAME) > 0 then
    begin
        item := (tt.item);
        sname := item.sname
    end
    else
        sname := nil;
    if (pctx.flags and ASN1_PCTX_FLAGS_NO_FIELD_NAME) > 0 then
        fname := nil
    else
        fname := tt.field_name;
    {
     * If field is embedded then fld needs fixing so it is a pointer to
     * a pointer to a field.
     }
    if (flags and ASN1_TFLG_EMBED) > 0 then
    begin
        tfld := PASN1_VALUE (fld);
        fld := @tfld;
    end;
    if (flags and ASN1_TFLG_SK_MASK) > 0 then
    begin
        { SET OF, SEQUENCE OF }
        if fname <> nil then
        begin
            if (pctx.flags and ASN1_PCTX_FLAGS_SHOW_SSOF) > 0 then
            begin
                if (flags and ASN1_TFLG_SET_OF) > 0 then
                    tname := 'SET'
                else
                    tname := 'SEQUENCE';
                if BIO_printf(_out, '%*s%s OF %s {'#10,
                               [indent, '', tname, tt.field_name]) <= 0  then
                    Exit(0);
            end
            else
            if (BIO_printf(_out, '%*s%s:'#10, [indent, '', fname]) <= 0) then
                Exit(0);
        end;
        stack := Pstack_st_const_ASN1_VALUE(fld^);
        for i := 0 to sk_const_ASN1_VALUE_num(stack)-1 do
        begin
            if (i > 0) and  (BIO_puts(_out, #10) <= 0) then
                Exit(0);
            skitem := sk_const_ASN1_VALUE_value(stack, i);
            if 0>= asn1_item_print_ctx(_out, @skitem, indent + 2,
                                     tt.item, nil, nil, 1, pctx) then
                Exit(0);
        end;
        if (i = 0)  and  (BIO_printf(_out, '%*s<%s>'#10, [indent + 2, '',
                              get_result(stack = nil , 'ABSENT' , 'EMPTY')]) <= 0)  then
            Exit(0);
        if (pctx.flags and ASN1_PCTX_FLAGS_SHOW_SEQUENCE) > 0 then
        begin
            if BIO_printf(_out, '%*s}'#10, [indent, '']) <= 0 then
                Exit(0);
        end;
        Exit(1);
    end;
    Exit(asn1_item_print_ctx(_out, fld, indent, tt.item,
                               fname, sname, 0, pctx));
end;

function asn1_print_fsname(_out : PBIO; indent : integer; fname, sname : PUTF8Char; pctx : PASN1_PCTX):integer;
begin

    while indent > nspaces do
    begin
        if BIO_write(_out, spaces, nspaces) <> nspaces  then
            Exit(0);
        indent  := indent - nspaces;
    end;
    if BIO_write(_out, spaces, indent) <> indent  then
        Exit(0);
    if (pctx.flags and ASN1_PCTX_FLAGS_NO_STRUCT_NAME) > 0 then
       sname := nil;
    if (pctx.flags and ASN1_PCTX_FLAGS_NO_FIELD_NAME) > 0 then
       fname := nil;
    if (nil = sname)  and  (nil = fname) then
       Exit(1);
    if fname <> nil then
    begin
        if BIO_puts(_out, fname) <= 0 then
            Exit(0);
    end;
    if sname <> nil then
    begin
        if fname <> nil then
        begin
            if BIO_printf(_out, ' (%s)', [sname]) <= 0 then
                Exit(0);
        end
        else
        begin
            if BIO_puts(_out, sname) <= 0  then
                Exit(0);
        end;
    end;
    if BIO_write(_out, PUTF8Char(': '), 2)  <> 2 then
        Exit(0);
    Result := 1;
end;


function asn1_item_print_ctx(_out : PBIO;const fld : PPASN1_VALUE; indent : integer;const it : PASN1_ITEM; fname, sname : PUTF8Char; nohdr : integer;const pctx : PASN1_PCTX):integer;
var
  tt, seqtt : PASN1_TEMPLATE;
  ef : PASN1_EXTERN_FUNCS;
  tmpfld : PPASN1_VALUE;
  aux : PASN1_AUX;
  asn1_cb : TASN1_aux_const_cb;
  parg : ASN1_PRINT_ARG;
  i : integer;
  label _break;
begin
{$POINTERMATH ON}
     aux := it.funcs;
    asn1_cb := nil;
    if aux <> nil then
    begin
        parg.out := _out;
        parg.indent := indent;
        parg.pctx := pctx;
        if (aux.flags and ASN1_AFLG_CONST_CB) <> 0 then
           asn1_cb := aux.asn1_const_cb
        else
           asn1_cb := {(TASN1_aux_const_cb  )}aux.asn1_cb; { backward compatibility }
    end;

   if  ( (it.itype <> ASN1_ITYPE_PRIMITIVE)  or  (it.utype <> V_ASN1_BOOLEAN))  and
        (fld^ = nil) then
   begin
        if (pctx.flags and ASN1_PCTX_FLAGS_SHOW_ABSENT) > 0 then
        begin
            if (0>= nohdr)  and  (0>= asn1_print_fsname(_out, indent, fname, sname, pctx)) then
                Exit(0);
            if BIO_puts(_out, '<ABSENT>'#10) <= 0  then
                Exit(0);
        end;
        Exit(1);
    end;
    case it.itype of
        ASN1_ITYPE_PRIMITIVE:
            if it.templates <> nil then
            begin
                if (0>= asn1_template_print_ctx(_out, fld, indent,
                                             it.templates, pctx)) then
                    Exit(0);
                goto _break;
            end;
            { fall through }
        ASN1_ITYPE_MSTRING:
            if 0>= asn1_primitive_print(_out, fld, it, indent, fname, sname, pctx) then
                Exit(0);
            //break;
        ASN1_ITYPE_EXTERN:
        begin
            if (0>= nohdr)  and  (0>= asn1_print_fsname(_out, indent, fname, sname, pctx)) then
                Exit(0);
            { Use new style print routine if possible }
            ef := it.funcs;
            if (ef <> nil)  and  (Assigned(ef.asn1_ex_print)) then
            begin
                i := ef.asn1_ex_print(_out, fld, indent, '', pctx);
                if 0>= i then Exit(0);
                if (i = 2)  and  (BIO_puts(_out, #10) <= 0) then
                    Exit(0);
                Exit(1);
            end
            else
            if (sname <> nil)  and  (BIO_printf(_out, ':EXTERNAL TYPE %s'#10, [sname]) <= 0) then
                Exit(0);
        end;
        ASN1_ITYPE_CHOICE:
        begin
            { CHOICE type, get selector }
            i := ossl_asn1_get_choice_selector_const(fld, it);
            { This should never happen... }
            if (i < 0) or  (i >= it.tcount) then
            begin
                if BIO_printf(_out, 'ERROR: selector [%d] invalid\n', [i]) <= 0 then
                    Exit(0);
                Exit(1);
            end;
            tt := it.templates + i;
            tmpfld := ossl_asn1_get_const_field_ptr(fld, tt);
            if 0>= asn1_template_print_ctx(_out, tmpfld, indent, tt, pctx) then
                Exit(0);
        end;
        ASN1_ITYPE_SEQUENCE,
        ASN1_ITYPE_NDEF_SEQUENCE:
        begin
            if (0>= nohdr)  and  (0>= asn1_print_fsname(_out, indent, fname, sname, pctx)) then
                Exit(0);
            if (fname <> nil)  or  (sname <> nil) then
            begin
                if (pctx.flags and ASN1_PCTX_FLAGS_SHOW_SEQUENCE)>0 then
                begin
                    if BIO_puts(_out, ' {'#10) <= 0 then
                        Exit(0);
                end
                else
                begin
                    if BIO_puts(_out, #10) <= 0  then
                        Exit(0);
                end;
            end;
            if Assigned(asn1_cb) then
            begin
                i := asn1_cb(ASN1_OP_PRINT_PRE, fld, it, @parg);
                if i = 0 then Exit(0);
                if i = 2 then Exit(1);
            end;
            { Print each field entry }
            tt := it.templates;
            for i := 0 to it.tcount-1 do
            begin
                seqtt := ossl_asn1_do_adb(fld^, tt, 1);
                if nil = seqtt then
                   Exit(0);
                tmpfld := ossl_asn1_get_const_field_ptr(fld, seqtt);
                if 0>= asn1_template_print_ctx(_out, tmpfld, indent + 2, seqtt, pctx) then
                    Exit(0);
                Inc(tt);
            end;
            if (pctx.flags and ASN1_PCTX_FLAGS_SHOW_SEQUENCE) > 0 then
            begin
                if BIO_printf(_out, '%*s}'#10, [indent, '']) < 0 then
                    Exit(0);
            end;
            if Assigned(asn1_cb) then
            begin
                i := asn1_cb(ASN1_OP_PRINT_POST, fld, it, @parg);
                if i = 0 then
                   Exit(0);
            end;
        end;
        else
        begin
            BIO_printf(_out, 'Unprocessed type %d'#10, [it.itype]);
            Exit(0);
        end;
    end;

_break:
    Result := 1;
{$POINTERMATH OFF}
end;



function ASN1_item_print(_out : PBIO;const ifld : PASN1_VALUE; indent : integer;const it : PASN1_ITEM; pctx : PASN1_PCTX):integer;
var
  sname: PUTF8Char;
begin
    if pctx = nil then
       pctx := @default_pctx;
    if (pctx.flags and ASN1_PCTX_FLAGS_NO_STRUCT_NAME) > 0 then
       sname := nil
    else
        sname := it.sname;
    Result := asn1_item_print_ctx(_out, @ifld, indent, it, nil, sname, 0, pctx);
end;


end.
