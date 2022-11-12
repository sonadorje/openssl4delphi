unit openssl3.crypto.asn1.tasn_fre;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses
   OpenSSL.Api;

procedure ossl_asn1_template_free(pval : PPASN1_VALUE;const tt : PASN1_TEMPLATE);
procedure ossl_asn1_primitive_free(pval : PPASN1_VALUE;const it : PASN1_ITEM; embed : integer);
procedure ASN1_item_free(val : PASN1_VALUE;const it : PASN1_ITEM);
procedure ASN1_item_ex_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
procedure ossl_asn1_item_embed_free(pval : PPASN1_VALUE;const it : PASN1_ITEM; embed : integer);

implementation

uses
  openssl3.crypto.stack,             OpenSSL3.openssl.asn1t,
  OpenSSL3.Err,openssl3.crypto.mem,  openssl3.crypto.asn1.asn1_lib,
  openssl3.crypto.asn1.tasn_utl,     openssl3.crypto.asn1.a_object;

procedure ASN1_item_ex_free(pval : PPASN1_VALUE;const it : PASN1_ITEM);
begin
    ossl_asn1_item_embed_free(pval, it, 0);
end;


procedure ASN1_item_free(val : PASN1_VALUE;const it : PASN1_ITEM);
begin
    ossl_asn1_item_embed_free(@val, it, 0);
end;

procedure ossl_asn1_primitive_free(pval : PPASN1_VALUE;const it : PASN1_ITEM; embed : integer);
var
  utype : integer;
  pf : PASN1_PRIMITIVE_FUNCS;
  typ : PASN1_TYPE;
begin
    { Special case: if 'it' is a primitive with a free_func, use that. }
    if it <>nil then
    begin
         pf := it.funcs;
        if embed>0 then
        begin
            if (Assigned(pf))  and  (Assigned(pf.prim_clear)) then
            begin
                pf.prim_clear(pval, it);
                exit;
            end;
        end
        else
        if (Assigned(pf))  and  (Assigned(pf.prim_free)) then
        begin
            pf.prim_free(pval, it);
            Exit;
        end;
    end;
    { Special case: if 'it' is nil, free contents of PASN1_TYPE  }
    if nil = it then
    begin
        typ := PASN1_TYPE( pval^);
        utype := typ._type;
        pval := @typ.value.asn1_value;
        if pval^ = nil then exit;
    end
    else
    if (it.itype = ASN1_ITYPE_MSTRING) then
    begin
        utype := -1;
        if pval^ = nil then Exit;
    end
    else
    begin
        utype := it.utype;
        if (utype <> V_ASN1_BOOLEAN)  and  (pval^ = nil) then
            Exit;
    end;
    case utype of
    V_ASN1_OBJECT:
        ASN1_OBJECT_free(PASN1_OBJECT(pval^));
        //break;
    V_ASN1_BOOLEAN:
    begin
        if it<>nil then
           PASN1_BOOLEAN(pval)^ := it.size
        else
           PASN1_BOOLEAN(pval)^ := -1;
        exit;
    end;
    V_ASN1_NULL:
        begin
          //
        end;
    V_ASN1_ANY:
    begin
        ossl_asn1_primitive_free(pval, nil, 0);
        OPENSSL_free( pval^);
    end;
    else
        ossl_asn1_string_embed_free(PASN1_STRING(pval^), embed);
        //break;
    end;
    pval^ := nil;
end;

procedure ossl_asn1_item_embed_free(pval : PPASN1_VALUE;const it : PASN1_ITEM; embed : integer);
var
  tt, seqtt : PASN1_TEMPLATE;
  ef : PASN1_EXTERN_FUNCS;
  aux : PASN1_AUX;
  asn1_cb : TASN1_aux_cb;
  i : integer;
  pchval, pseqval : PPASN1_VALUE;
begin
{$POINTERMATH ON}
     tt := nil;
     aux := it.funcs;
    if pval = nil then exit;
    if (it.itype <> ASN1_ITYPE_PRIMITIVE )  and  (pval^ = nil) then
        exit;
    if (aux<>nil)  and  (Assigned(aux.asn1_cb)) then
        asn1_cb := aux.asn1_cb
    else
        asn1_cb := nil;

    case it.itype of
    ASN1_ITYPE_PRIMITIVE:
    begin
        if it.templates <> nil then
           ossl_asn1_template_free(pval, it.templates)
        else
           ossl_asn1_primitive_free(pval, it, embed);
    end;
    ASN1_ITYPE_MSTRING:
        ossl_asn1_primitive_free(pval, it, embed);
        //break;
    ASN1_ITYPE_CHOICE:
    begin
        if Assigned(asn1_cb) then
        begin
            i := asn1_cb(ASN1_OP_FREE_PRE, pval, it, nil);
            if i = 2 then exit;
        end;
        i := ossl_asn1_get_choice_selector(pval, it);
        if (i >= 0)  and  (i < it.tcount) then
        begin
            tt := it.templates + i;
            pchval := ossl_asn1_get_field_ptr(pval, tt);
            ossl_asn1_template_free(pchval, tt);
        end;
        if Assigned(asn1_cb) then
           asn1_cb(ASN1_OP_FREE_POST, pval, it, nil);
        if embed = 0 then
        begin
            OPENSSL_free( pval^);
            pval^ := nil;
        end;
    end;
    ASN1_ITYPE_EXTERN:
    begin
        ef := it.funcs;
        if (ef <> nil)  and  (Assigned(ef.asn1_ex_free)) then
           ef.asn1_ex_free(pval, it);
    end;
    ASN1_ITYPE_NDEF_SEQUENCE,
    ASN1_ITYPE_SEQUENCE:
    begin
        if ossl_asn1_do_lock(pval, -1, it) <> 0  then { if error or ref-counter > 0 }
            exit;
        if Assigned(asn1_cb) then
        begin
            i := asn1_cb(ASN1_OP_FREE_PRE, pval, it, nil);
            if i = 2 then exit;
        end;
        ossl_asn1_enc_free(pval, it);
        {
         * If we free up as normal we will invalidate any ANY DEFINED BY
         * field and we won't be able to determine the type of the field it
         * defines. So free up in reverse order.
         }
        tt := it.templates + it.tcount;
        for i := 0 to it.tcount-1 do
        begin
            Dec(tt);
            seqtt := ossl_asn1_do_adb( pval^, tt, 0);
            if nil = seqtt then continue;
            pseqval := ossl_asn1_get_field_ptr(pval, seqtt);
            ossl_asn1_template_free(pseqval, seqtt);
        end;
        if Assigned(asn1_cb) then
           asn1_cb(ASN1_OP_FREE_POST, pval, it, nil);
        if embed = 0 then
        begin
            OPENSSL_free( pval^);
            pval^ := nil;
        end;
    end;
    end;
{$POINTERMATH OFF}
end;



procedure ossl_asn1_template_free(pval : PPASN1_VALUE;const tt : PASN1_TEMPLATE);
var
  embed : integer;

  tval : PASN1_VALUE;

  sk : Pstack_st_ASN1_VALUE;

  i : integer;

  vtmp : PASN1_VALUE;
begin
    embed := tt.flags and ASN1_TFLG_EMBED;
    if embed >0 then
    begin
        tval := PASN1_VALUE( pval);
        pval := @tval;
    end;
    if (tt.flags and ASN1_TFLG_SK_MASK)>0 then
    begin
        sk := Pstack_st_ASN1_VALUE(pval^);
        for i := 0 to sk_ASN1_VALUE_num(sk)-1 do
        begin
            vtmp := sk_ASN1_VALUE_value(sk, i);
            ossl_asn1_item_embed_free(&vtmp, tt.item, embed);
        end;
        sk_ASN1_VALUE_free(sk);
        pval^ := nil;
    end
    else
    begin
        ossl_asn1_item_embed_free(pval, tt.item, embed);
    end;
end;



end.
