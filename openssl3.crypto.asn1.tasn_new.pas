unit openssl3.crypto.asn1.tasn_new;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;

function ossl_asn1_item_ex_new_intern(pval : PPASN1_VALUE;const it : PASN1_ITEM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
function asn1_item_embed_new(pval : PPASN1_VALUE;const it : PASN1_ITEM; embed : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):int;

function asn1_template_new(pval : PPASN1_VALUE;const tt : PASN1_TEMPLATE; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
procedure asn1_template_clear(pval : PPASN1_VALUE;const tt : PASN1_TEMPLATE);
procedure asn1_item_clear(pval : PPASN1_VALUE;const it : PASN1_ITEM);
procedure asn1_primitive_clear(pval : PPASN1_VALUE;const it : PASN1_ITEM);
 function asn1_primitive_new(pval : PPASN1_VALUE;const it : PASN1_ITEM; embed : integer):integer;
function ASN1_item_new(const it : PASN1_ITEM):PASN1_VALUE;
function ASN1_item_new_ex(const it : PASN1_ITEM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PASN1_VALUE;
  function ASN1_item_ex_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;



implementation

uses
  openssl3.crypto.stack, openssl3.crypto.mem, OpenSSL3.Err,
  openssl3.crypto.objects.obj_dat,  openssl3.crypto.asn1.asn1_lib,
  OpenSSL3.openssl.asn1t, openssl3.crypto.asn1.tasn_utl, openssl3.crypto.asn1.tasn_fre;


function ASN1_item_ex_new(pval : PPASN1_VALUE;const it : PASN1_ITEM):integer;
begin
    Result := asn1_item_embed_new(pval, it, 0, nil, nil);
end;

function ASN1_item_new_ex(const it : PASN1_ITEM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PASN1_VALUE;
var
  ret : PASN1_VALUE;
begin
    ret := Pointer(0) ;
    if asn1_item_embed_new(@ret, it, 0, libctx, propq) > 0  then
        Exit(ret);
    Result := Pointer(0) ;
end;


function ASN1_item_new(const it : PASN1_ITEM):PASN1_VALUE;
var
  ret : PASN1_VALUE;
begin
    ret := Pointer(0) ;
    if ASN1_item_ex_new(@ret, it) > 0  then
        Exit(ret);
    Result := Pointer(0) ;
end;



function asn1_primitive_new(pval : PPASN1_VALUE;const it : PASN1_ITEM; embed : integer):integer;
var
  typ : PASN1_TYPE;

  str : PASN1_STRING;

  utype : integer;

  pf : PASN1_PRIMITIVE_FUNCS;
begin
    if nil = it then Exit(0);
    if it.funcs <> nil then
    begin
         pf := it.funcs;
        if embed>0 then
        begin
            if Assigned(pf.prim_clear) then
            begin
                pf.prim_clear(pval, it);
                Exit(1);
            end;
        end
        else
        if Assigned(pf.prim_new) then
        begin
            Exit(pf.prim_new(pval, it));
        end;
    end;
    if it.itype = ASN1_ITYPE_MSTRING then
       utype := -1
    else
        utype := it.utype;
    case utype of
    V_ASN1_OBJECT:
    begin
        pval^ := PASN1_VALUE( OBJ_nid2obj(NID_undef));
        Exit(1);
    end;
    V_ASN1_BOOLEAN:
    begin
        PASN1_BOOLEAN( pval)^ := it.size;
        Exit(1);
    end;
    V_ASN1_NULL:
    begin
        pval^ := PASN1_VALUE( 1);
        Exit(1);
    end;
    V_ASN1_ANY:
    begin
        typ := OPENSSL_malloc(sizeof( typ^));
        if typ = nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        typ.value.ptr := nil;
        typ._type := -1;
        pval^ := PASN1_VALUE( typ);
    end;
    else
    begin
        if embed>0 then
        begin
            str := PPASN1_STRING(pval)^;
            memset(str, 0, sizeof( str^));
            str.&type := utype;
            str.flags := ASN1_STRING_FLAG_EMBED;
        end
        else
        begin
            str := ASN1_STRING_type_new(utype);
            pval^ := PASN1_VALUE( str);
        end;
        if (it.itype = ASN1_ITYPE_MSTRING)  and  (str <> nil) then
            str.flags  := str.flags  or ASN1_STRING_FLAG_MSTRING;
    end;
    end;
    if pval^ <> nil then Exit(1);
    Result := 0;
end;

procedure asn1_primitive_clear(pval : PPASN1_VALUE;const it : PASN1_ITEM);
var
  utype : integer;

  pf : PASN1_PRIMITIVE_FUNCS;

begin
    if (it <> nil)  and  (it.funcs <> nil) then
    begin
        pf := it.funcs;
        if Assigned(pf.prim_clear) then
           pf.prim_clear(pval, it)
        else
           pval^ := nil;
        Exit;
    end;
    if (nil = it)  or  (it.itype = ASN1_ITYPE_MSTRING) then
        utype := -1
    else
        utype := it.utype;
    if utype = V_ASN1_BOOLEAN then
       PASN1_BOOLEAN(pval)^ := it.size
    else
       pval^ := nil;
end;




procedure asn1_item_clear(pval : PPASN1_VALUE;const it : PASN1_ITEM);
var
  ef : PASN1_EXTERN_FUNCS;
begin
    case it.itype of
    ASN1_ITYPE_EXTERN:
    begin
        ef := it.funcs;
        if (Assigned(ef))  and  (Assigned(ef.asn1_ex_clear)) then
           ef.asn1_ex_clear(pval, it)
        else
           pval^ := nil;
    end;
    ASN1_ITYPE_PRIMITIVE:
    begin
        if it.templates <> nil then
           asn1_template_clear(pval, it.templates)
        else
            asn1_primitive_clear(pval, it);
    end;
    ASN1_ITYPE_MSTRING:
        asn1_primitive_clear(pval, it);
        //break;
    ASN1_ITYPE_CHOICE,
    ASN1_ITYPE_SEQUENCE,
    ASN1_ITYPE_NDEF_SEQUENCE:
        pval^ := nil;
        //break;
    end;
end;



procedure asn1_template_clear(pval : PPASN1_VALUE;const tt : PASN1_TEMPLATE);
begin
    { If ADB or STACK just nil the field }
    if (tt.flags and (ASN1_TFLG_ADB_MASK or ASN1_TFLG_SK_MASK) )>0 then
        pval^ := nil
    else
        asn1_item_clear(pval, tt.item());
end;

function asn1_template_new(pval : PPASN1_VALUE;const tt : PASN1_TEMPLATE; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  it : PASN1_ITEM;
  embed : integer;
  tval : PASN1_VALUE;
  ret : integer;
  skval : Pstack_st_ASN1_VALUE;
  label _done;
begin
   it := tt.item();
    embed := tt.flags and ASN1_TFLG_EMBED;
    if embed>0 then
    begin
        tval := PASN1_VALUE( pval);
        pval := @tval;
    end;
    if (tt.flags and ASN1_TFLG_OPTIONAL)>0 then
    begin
        asn1_template_clear(pval, tt);
        Exit(1);
    end;
    { If ANY DEFINED BY nothing to do }
    if (tt.flags and ASN1_TFLG_ADB_MASK)>0 then
    begin
        pval^ := nil;
        Exit(1);
    end;
    { If SET OF or SEQUENCE OF, its a STACK }
    if (tt.flags and ASN1_TFLG_SK_MASK)>0 then
    begin
        skval := sk_ASN1_VALUE_new_null();
        if nil = skval then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            ret := 0;
            goto _done ;
        end;
        pval^ := PASN1_VALUE( skval);
        ret := 1;
        goto _done ;
    end;
    { Otherwise pass it back to the item routine }
    ret := asn1_item_embed_new(pval, it, embed, libctx, propq);
 _done:
    Result := ret;
end;



function asn1_item_embed_new(pval : PPASN1_VALUE;const it : PASN1_ITEM; embed : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):int;
var
  tt : PASN1_TEMPLATE;
  ef : PASN1_EXTERN_FUNCS;
  aux : PASN1_AUX;
  asn1_cb : TASN1_aux_cb;
  pseqval : PPASN1_VALUE;
  i : integer;
  label  _memerr, _memerr2,  _auxerr2 , _auxerr;
begin
     tt := nil;
     aux := it.funcs;
    if (aux<>nil)  and  (Assigned(aux.asn1_cb)) then
       asn1_cb := aux.asn1_cb
    else
        asn1_cb := nil;
    case it.itype of
    ASN1_ITYPE_EXTERN:
    begin
        ef := it.funcs;
        if ef <> nil then
        begin
            if Assigned(ef.asn1_ex_new_ex) then
            begin
                if 0>= ef.asn1_ex_new_ex(pval, it, libctx, propq) then
                    goto _memerr ;
            end
            else
            if Assigned(ef.asn1_ex_new) then
            begin
                if 0>= ef.asn1_ex_new(pval, it) then
                    goto _memerr ;
            end;
        end;
    end;
    ASN1_ITYPE_PRIMITIVE:
    begin
        if it.templates <> nil then
        begin
            if 0>= asn1_template_new(pval, it.templates, libctx, propq) then
                goto _memerr ;
        end
        else
        if 0>= asn1_primitive_new(pval, it, embed) then
            goto _memerr ;
    end;
    ASN1_ITYPE_MSTRING:
    begin
        if 0>= asn1_primitive_new(pval, it, embed )then
            goto _memerr ;
    end;
    ASN1_ITYPE_CHOICE:
    begin
        if Assigned(asn1_cb) then
        begin
            i := asn1_cb(ASN1_OP_NEW_PRE, pval, it, nil);
            if 0>= i then goto _auxerr ;
            if i = 2 then
            begin
                Exit(1);
            end;
        end;
        if embed>0 then
        begin
            memset( pval^, 0, it.size);
        end
        else
        begin
            pval^ := OPENSSL_zalloc(it.size);
            if pval^ = nil then goto _memerr ;
        end;
        ossl_asn1_set_choice_selector(pval, -1, it);
        if Assigned(asn1_cb)  and  (0>= asn1_cb(ASN1_OP_NEW_POST, pval, it, nil)) then
            goto _auxerr2 ;
    end ;
    ASN1_ITYPE_NDEF_SEQUENCE,
    ASN1_ITYPE_SEQUENCE:
    begin
        if Assigned(asn1_cb) then
        begin
            i := asn1_cb(ASN1_OP_NEW_PRE, pval, it, nil);
            if 0>= i then goto _auxerr ;
            if i = 2 then
            begin
                Exit(1);
            end;
        end;
        if embed>0 then
        begin
            memset( pval^, 0, it.size);
        end
        else
        begin
            pval^ := OPENSSL_zalloc(it.size);
            if pval^ = nil then goto _memerr ;
        end;
        { 0 : init. lock }
        if ossl_asn1_do_lock(pval, 0, it) < 0  then
        begin
            if 0>= embed then
            begin
                OPENSSL_free(pval^);
                pval^ := nil;
            end;
            goto _memerr ;
        end;
        ossl_asn1_enc_init(pval, it);
        tt := it.templates;
        for i := 0 to it.tcount-1 do
        begin
            pseqval := ossl_asn1_get_field_ptr(pval, tt);
            if 0>= asn1_template_new(pseqval, tt, libctx, propq) then
                goto _memerr2 ;
            Inc(tt);
        end;
        if Assigned(asn1_cb)  and  (0>= asn1_cb(ASN1_OP_NEW_POST, pval, it, nil)) then
            goto _auxerr2 ;
    end;
    end;
    Exit(1);
 _memerr2:
    ossl_asn1_item_embed_free(pval, it, embed);
 _memerr:
    ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
    Exit(0);
 _auxerr2:
    ossl_asn1_item_embed_free(pval, it, embed);
 _auxerr:
    ERR_raise(ERR_LIB_ASN1, ASN1_R_AUX_ERROR);
    Exit(0);
end;

function ossl_asn1_item_ex_new_intern(pval : PPASN1_VALUE;const it : PASN1_ITEM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    Result := asn1_item_embed_new(pval, it, 0, libctx, propq);
end;

end.
