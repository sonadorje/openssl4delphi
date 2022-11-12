unit openssl3.crypto.asn1.tasn_dec;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

const
  ASN1_MAX_CONSTRUCTED_NEST = 30;
  ASN1_MAX_STRING_NEST      = 5;

  const tag2bit: array[0..31] of Uint32 = (
    (* tags  0 -  3 *)
    0, 0, 0, B_ASN1_BIT_STRING,
    (* tags  4- 7 *)
    B_ASN1_OCTET_STRING, 0, 0, B_ASN1_UNKNOWN,
    (* tags  8-11 *)
    B_ASN1_UNKNOWN, B_ASN1_UNKNOWN, 0, B_ASN1_UNKNOWN,
    (* tags 12-15 *)
    B_ASN1_UTF8STRING, B_ASN1_UNKNOWN, B_ASN1_UNKNOWN, B_ASN1_UNKNOWN,
    (* tags 16-19 *)
    B_ASN1_SEQUENCE, 0, B_ASN1_NUMERICSTRING, B_ASN1_PRINTABLESTRING,
    (* tags 20-22 *)
    B_ASN1_T61STRING, B_ASN1_VIDEOTEXSTRING, B_ASN1_IA5STRING,
    (* tags 23-24 *)
    B_ASN1_UTCTIME, B_ASN1_GENERALIZEDTIME,
    (* tags 25-27 *)
    B_ASN1_GRAPHICSTRING, B_ASN1_ISO64STRING, B_ASN1_GENERALSTRING,
    (* tags 28-31 *)
    B_ASN1_UNIVERSALSTRING, B_ASN1_UNKNOWN, B_ASN1_BMPSTRING, B_ASN1_UNKNOWN
);
 //function ASN1_item_d2i(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM):PASN1_VALUE;
 function ASN1_item_d2i(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM):PASN1_VALUE;
 function ASN1_item_d2i_ex(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PASN1_VALUE;
 function asn1_item_ex_d2i_intern(pval : PPASN1_VALUE;const &in : PPByte; len : long;const it : PASN1_ITEM; tag, aclass : integer; opt : Int8; ctx : PASN1_TLC; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
 function asn1_item_embed_d2i(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM; tag, aclass : integer; opt : Int8; ctx : PASN1_TLC; depth : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
 function asn1_check_tlen(olen : Plong; otag : PInteger; oclass : PByte; inf, cst : PUTF8Char;const _in : PPByte; len : long; exptag, expclass : integer; opt : Int8; ctx : PASN1_TLC):integer;
 function asn1_template_ex_d2i(val : PPASN1_VALUE;const _in : PPByte; inlen : long;const tt : PASN1_TEMPLATE; opt : Int8; ctx : PASN1_TLC; depth : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
 function asn1_template_noexp_d2i(val : PPASN1_VALUE;const _in : PPByte; len : long;const tt : PASN1_TEMPLATE; opt : Int8; ctx : PASN1_TLC; depth : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
 function asn1_check_eoc( _in : PPByte; len : long):integer;
 function asn1_d2i_ex_primitive(pval : PPASN1_VALUE;const _in : PPByte; inlen : long;const it : PASN1_ITEM; tag, aclass : integer; opt : Int8; ctx : PASN1_TLC):integer;
 function asn1_find_end(_in : PPByte; len : long; inf : byte):integer;
 function asn1_collect(buf : PBUF_MEM;_in : PPByte; len : long; inf : byte; tag, aclass, depth : integer):integer;
 function collect_data(buf : PBUF_MEM;const p : PPByte; plen : long):integer;
  function asn1_ex_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
 function ASN1_tag2bit( tag : integer):Cardinal;
 //function ASN1_item_d2i(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM):PASN1_VALUE;
 function ASN1_item_ex_d2i(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM; tag, aclass : integer; opt : Int8; ctx : PASN1_TLC):integer;

implementation
uses openssl3.crypto.evp.evp_lib,        openssl3.crypto.rand.rand_lib,
     openssl3.crypto.mem, OpenSSL3.Err,  openssl3.crypto.asn1.x_algor,
     openssl3.crypto.asn1.tasn_typ,      openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.asn_pack,      OpenSSL3.openssl.asn1t,
     openssl3.crypto.asn1.a_type,        openssl3.crypto.buffer.buffer,
     openssl3.crypto.asn1.a_int,         openssl3.crypto.asn1.tasn_utl,
     openssl3.crypto.asn1.a_object,      openssl3.crypto.asn1.a_bitstr,
     openssl3.crypto.asn1.tasn_fre,      openssl3.crypto.asn1.tasn_new;

function ASN1_item_ex_d2i(pval : PPASN1_VALUE;const _in : PPByte; len : long;
                          const it : PASN1_ITEM; tag, aclass : integer;
                          opt : Int8; ctx : PASN1_TLC):integer;
begin
    Result := asn1_item_ex_d2i_intern(pval, _in, len, it, tag, aclass, opt, ctx,
                                   nil, nil);
end;

function ASN1_tag2bit( tag : integer):Cardinal;
begin
    if (tag < 0) or  (tag > 30) then
        Exit(0);
    Result := tag2bit[tag];
end;

procedure asn1_tlc_clear(c : PASN1_TLC);
begin
   if (c <> nil) then
      c.valid := 0;
end;

function asn1_ex_c2i(pval : PPASN1_VALUE;const cont : PByte; len, utype : integer; free_cont : PUTF8Char;const it : PASN1_ITEM):integer;
var
  opval : PPASN1_VALUE;
  stmp : PASN1_STRING;
  typ : PASN1_TYPE;
  ret : integer;
  pf : PASN1_PRIMITIVE_FUNCS;
  tint : PPASN1_INTEGER;
  tbool : PASN1_BOOLEAN;
  label _err ;
begin
    opval := nil;
    typ := nil;
    ret := 0;
    pf := it.funcs;
    if (pf <> nil)  and  (Assigned(pf.prim_c2i)) then
       Exit(pf.prim_c2i(pval, cont, len, utype, free_cont, it));
    { If ANY type clear type and set pointer to internal value }
    if it.utype = V_ASN1_ANY then
    begin
        if pval^ = nil then
        begin
            typ := ASN1_TYPE_new();
            if typ = nil then goto _err ;
            pval^ := PASN1_VALUE( typ);
        end
        else
            typ := PASN1_TYPE(pval^);
        if utype <> typ._type then
           ASN1_TYPE_set(typ, utype, nil);
        opval := pval;
        pval := @typ.value.asn1_value;
    end;
    case utype of
    V_ASN1_OBJECT:
    begin
        if nil = ossl_c2i_ASN1_OBJECT(PPASN1_OBJECT( pval), @cont, len) then
            goto _err ;
    end;
    V_ASN1_NULL:
    begin
        if len>0 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_NULL_IS_WRONG_LENGTH);
            goto _err ;
        end;
        pval^ := PASN1_VALUE( 1);
    end;
    V_ASN1_BOOLEAN:
    begin
        if len <> 1 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_BOOLEAN_IS_WRONG_LENGTH);
            goto _err ;
        end
        else
        begin
            tbool^ := cont^;
        end;
    end;
    V_ASN1_BIT_STRING:
    begin
        if nil = ossl_c2i_ASN1_BIT_STRING(PPASN1_BIT_STRING( pval), @cont, len) then
            goto _err ;
    end;
    V_ASN1_INTEGER,
    V_ASN1_ENUMERATED:
    begin
        tint := PPASN1_INTEGER(pval);
        if nil = ossl_c2i_ASN1_INTEGER(tint, @cont, len) then
            goto _err ;
        { Fixup type to match the expected form }
        tint^.&type := utype or (tint^.&type and V_ASN1_NEG);
    end;
    V_ASN1_OCTET_STRING,
    V_ASN1_NUMERICSTRING,
    V_ASN1_PRINTABLESTRING,
    V_ASN1_T61STRING,
    V_ASN1_VIDEOTEXSTRING,
    V_ASN1_IA5STRING,
    V_ASN1_UTCTIME,
    V_ASN1_GENERALIZEDTIME,
    V_ASN1_GRAPHICSTRING,
    V_ASN1_VISIBLESTRING,
    V_ASN1_GENERALSTRING,
    V_ASN1_UNIVERSALSTRING,
    V_ASN1_BMPSTRING,
    V_ASN1_UTF8STRING,
    V_ASN1_OTHER,
    V_ASN1_SET,
    V_ASN1_SEQUENCE:
    begin
        if (utype = V_ASN1_BMPSTRING)  and ( (len and 1)>0 )  then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_BMPSTRING_IS_WRONG_LENGTH);
            goto _err ;
        end;
        if (utype = V_ASN1_UNIVERSALSTRING)  and ( (len and 3)>0 )  then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_UNIVERSALSTRING_IS_WRONG_LENGTH);
            goto _err ;
        end;
        { All based on ASN1_STRING and handled the same }
        if pval^ = nil then
        begin
            stmp := ASN1_STRING_type_new(utype);
            if stmp = nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            pval^ := PASN1_VALUE( stmp);
        end
        else
        begin
            stmp := PASN1_STRING(pval^);
            stmp.&type := utype;
        end;
        { If we've already allocated a buffer use it }
        if free_cont^ <> #0 then
        begin
            OPENSSL_free(Pointer(stmp.data));
            stmp.data := PByte( cont); { UGLY CAST! RL }
            stmp.length := len;
            free_cont^ := #0;
        end
        else
        begin
            if 0>= ASN1_STRING_set(stmp, cont, len)  then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                ASN1_STRING_free(stmp);
                pval^ := nil;
                goto _err ;
            end;
        end;
    end;
    end;
    { If ASN1_ANY and nil type fix up value }
    if (typ <> nil)  and  (utype = V_ASN1_NULL)  then
        typ.value.ptr := nil;
    ret := 1;
 _err:
    if 0>= ret then
    begin
        ASN1_TYPE_free(typ);
        if opval <> nil then
           opval^ := nil;
    end;
    Result := ret;
end;



function collect_data(buf : PBUF_MEM;const p : PPByte; plen : long):integer;
var
  len : integer;
begin
    if buf <> nil then
    begin
        len := buf.length;
        if 0>= BUF_MEM_grow_clean(buf, len + plen) then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        memcpy(buf.data + len, p^, plen);
    end;
    p^  := p^ + plen;
    Result := 1;
end;





function asn1_collect(buf : PBUF_MEM;_in : PPByte; len : long; inf : byte; tag, aclass, depth : integer):integer;
var
  p, q : PByte;

  plen : long;

  cst, ininf : byte;
begin
    p := _in^;
    inf := inf and 1;
    {
     * If no buffer and not indefinite length constructed just pass over the
     * encoded data
     }
    if (nil = buf)  and  (0>= inf) then
    begin
        _in^  := _in^ + len;
        Exit(1);
    end;
    while len > 0 do
    begin
        q := p;
        { Check for EOC }
        if asn1_check_eoc(@p, len) >0 then
        begin
            {
             * EOC is illegal outside indefinite length constructed form
             }
            if 0>= inf then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_UNEXPECTED_EOC);
                Exit(0);
            end;
            inf := 0;
            break;
        end;
        if 0>= asn1_check_tlen(@plen, nil, nil, @ininf, @cst, @p,
                             len, tag, aclass, 0, nil) then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            Exit(0);
        end;
        { If indefinite length constructed update max length }
        if cst>0 then
        begin
            if depth >= ASN1_MAX_STRING_NEST then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_NESTED_ASN1_STRING);
                Exit(0);
            end;
            if 0>= asn1_collect(buf, @p, plen, ininf, tag, aclass, depth + 1) then
                Exit(0);
        end
        else if (plen>0)  and  (0>= collect_data(buf, @p, plen)) then
            Exit(0);
        len  := len - (p - q);
    end;
    if inf>0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_MISSING_EOC);
        Exit(0);
    end;
    _in^ := p;
    Result := 1;
end;



function asn1_find_end( _in : PPByte; len : long; inf : byte):integer;
var
    expected_eoc : uint32;

    plen         : long;

    p ,q           : PByte;
begin
    p := _in^;
    { If not indefinite length constructed just add length }
    if inf = 0 then
    begin
        _in^  := _in^ + len;
        Exit(1);
    end;
    expected_eoc := 1;
    {
     * Indefinite length constructed form. Find the end when enough EOCs are
     * found. If more indefinite length constructed headers are encountered
     * increment the expected eoc count otherwise just skip to the end of the
     * data.
     }
    while len > 0 do
    begin
        if asn1_check_eoc(@p, len)>0 then
        begin
            Dec(expected_eoc);
            if expected_eoc = 0 then break;
            len  := len - 2;
            continue;
        end;
        q := p;
        { Just read in a header: only care about the length }
        if 0>= asn1_check_tlen(@plen, nil, nil, @inf, nil, @p, len,
                             -1, 0, 0, nil) then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            Exit(0);
        end;
        if inf>0 then
        begin
            if expected_eoc = UINT32_MAX then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
                Exit(0);
            end;
            Inc(expected_eoc);
        end
        else
        begin
            p  := p + plen;
        end;
        len  := len - (p - q);
    end;
    if expected_eoc>0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_MISSING_EOC);
        Exit(0);
    end;
    _in^ := p;
    Result := 1;
end;


function asn1_d2i_ex_primitive(pval : PPASN1_VALUE;const _in : PPByte; inlen : long;const it : PASN1_ITEM; tag, aclass : integer; opt : Int8; ctx : PASN1_TLC):integer;
var
    ret, utype       : integer;
    plen      : long;
    cst,
    inf,
    free_cont : byte;
    p         : PByte;
    buf       : TBUF_MEM;
    cont      : PByte;
    len       : long;
    oclass    : Byte;
    label _err             ;
begin
    ret := 0;
    free_cont := 0;
    buf := default(TBUF_MEM);

    cont := nil;
    if pval = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_NULL);
        Exit( 0);               { Should never happen }
    end;
    if it.itype = ASN1_ITYPE_MSTRING then
    begin
        utype := tag;
        tag := -1;
    end
    else
        utype := it.utype;
    if utype = V_ASN1_ANY then
    begin
        { If type is ANY need to figure out type from tag }
        if tag >= 0 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_TAGGED_ANY);
            Exit(0);
        end;
        if opt > 0 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_OPTIONAL_ANY);
            Exit(0);
        end;
        p := _in^;
        ret := asn1_check_tlen(nil, @utype, @oclass, nil, nil,
                              @p, inlen, -1, 0, 0, ctx);
        if 0>= ret then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            Exit(0);
        end;
        if oclass <> V_ASN1_UNIVERSAL then
           utype := V_ASN1_OTHER;
    end;
    if tag = -1 then
    begin
        tag := utype;
        aclass := V_ASN1_UNIVERSAL;
    end;
    p := _in^;
    { Check header }
    ret := asn1_check_tlen(@plen, nil, nil, @inf, @cst,
                          @p, inlen, tag, aclass, opt, ctx);
    if 0>= ret then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
        Exit(0);
    end
    else if (ret = -1) then
        Exit(-1);
    ret := 0;
    { SEQUENCE, SET and 'OTHER' are left in encoded form }
    if (utype = V_ASN1_SEQUENCE ) or
       (utype = V_ASN1_SET)  or  (utype = V_ASN1_OTHER) then
    begin
        {
         * Clear context cache for type OTHER because the auto clear when we
         * have a exact match won't work
         }
        if utype = V_ASN1_OTHER then
        begin
            asn1_tlc_clear(ctx);
        end
        { SEQUENCE and SET must be constructed }
        else if (0>= cst) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_TYPE_NOT_CONSTRUCTED);
            Exit(0);
        end;
        cont := _in^;
        { If indefinite length constructed find the real end }
        if inf>0 then
        begin
            if 0>= asn1_find_end(@p, plen, inf) then
                goto _err ;
            len := p - cont;
        end
        else
        begin
            len := p - cont + plen;
            p  := p + plen;
        end;
    end
    else if (cst>0) then
    begin
        if (utype = V_ASN1_NULL)  or  (utype = V_ASN1_BOOLEAN)
             or  (utype = V_ASN1_OBJECT)  or  (utype = V_ASN1_INTEGER)
             or  (utype = V_ASN1_ENUMERATED) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_TYPE_NOT_PRIMITIVE);
            Exit(0);
        end;
        { Free any returned 'buf' content }
        free_cont := 1;
        {
         * Should really check the internal tags are correct but some things
         * may get this wrong. The relevant specs say that constructed string
         * types should be OCTET STRINGs internally irrespective of the type.
         * So instead just check for UNIVERSAL class and ignore the tag.
         }
        if 0>= asn1_collect(@buf, @p, plen, inf, -1, V_ASN1_UNIVERSAL, 0 ) then
        begin
            goto _err ;
        end;
        len := buf.length;
        { Append a final null to string }
        if 0>= BUF_MEM_grow_clean(@buf, len + 1 )then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        buf.data[len] := Chr(0);
        cont := PByte(buf.data);
    end
    else
    begin
        cont := p;
        len := plen;
        p  := p + plen;
    end;
    { We now have content length and type: translate into a structure }
    { asn1_ex_c2i may reuse allocated buffer, and so sets free_cont to 0 }
    if 0>= asn1_ex_c2i(pval, cont, len, utype, @free_cont, it) then
        goto _err ;
    _in^ := p;
    ret := 1;
 _err:
    if free_cont>0 then
       OPENSSL_free(Pointer(buf.data));
    Result := ret;
end;

function asn1_check_eoc( _in : PPByte; len : long):integer;
var
  p : PByte;
begin
    if len < 2 then Exit(0);
    p := _in^;
    if (p[0] = Ord(#0))  and  (p[1] = Ord(#0)) then
    begin
        _in^  := _in^ + 2;
        Exit(1);
    end;
    Result := 0;
end;


function asn1_template_noexp_d2i(val : PPASN1_VALUE;const _in : PPByte;
                                 len : long;const tt : PASN1_TEMPLATE;
                                 opt : Int8; ctx : PASN1_TLC; depth : integer;
                                 libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  flags,
  aclass,
  ret      : integer;
  tval     : PASN1_VALUE;
  p,  q    : PByte;
  sktag,
  skaclass : integer;
  sk_eoc   : byte;
  vtmp,
  skfield  : PASN1_VALUE;
  sktmp: Pstack_st_ASN1_VALUE;
  label _err ;
begin
    if nil = val then Exit(0);
    flags := tt.flags;
    aclass := flags and ASN1_TFLG_TAG_CLASS;
    p := _in^;
    {
     * If field is embedded then val needs fixing so it is a pointer to
     * a pointer to a field.
     }
    if (tt.flags and ASN1_TFLG_EMBED)>0 then
    begin
        tval := PASN1_VALUE( val);
        val := @tval;
    end;
    if (flags and ASN1_TFLG_SK_MASK)>0 then
    begin
        { SET OF, SEQUENCE OF }
        { First work out expected inner tag value }
        if (flags and ASN1_TFLG_IMPTAG)>0 then
        begin
            sktag := tt.tag;
            skaclass := aclass;
        end
        else
        begin
            skaclass := V_ASN1_UNIVERSAL;
            if (flags and ASN1_TFLG_SET_OF)>0 then
               sktag := V_ASN1_SET
            else
                sktag := V_ASN1_SEQUENCE;
        end;
        { Get the tag }
        ret := asn1_check_tlen(@len, nil, nil, @sk_eoc, nil,
                              @p, len, sktag, skaclass, opt, ctx);
        if 0>= ret then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            Exit(0);
        end
        else if (ret = -1) then
            Exit(-1);
        if val^ = nil then
           val^ := PASN1_VALUE( sk_ASN1_VALUE_new_null)
        else
        begin
            {
             * We've got a valid STACK: free up any items present
             }
            sktmp := Pstack_st_ASN1_VALUE (val^);
            while sk_ASN1_VALUE_num(sktmp) > 0 do
            begin
                vtmp := sk_ASN1_VALUE_pop(sktmp);
                ASN1_item_ex_free(@vtmp, tt.item);
            end;
        end;
        if val^ = nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        { Read as many items as we can }
        while len > 0 do
        begin
            q := p;
            { See if EOC found }
            if asn1_check_eoc(@p, len) >0 then
            begin
                if 0>= sk_eoc then
                begin
                    ERR_raise(ERR_LIB_ASN1, ASN1_R_UNEXPECTED_EOC);
                    goto _err ;
                end;
                len  := len - (p - q);
                sk_eoc := 0;
                break;
            end;
            skfield := nil;
            if asn1_item_embed_d2i(@skfield, @p, len,
                                     tt.item  , -1, 0, 0, ctx,
                                     depth, libctx, propq) <= 0 then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
                { |skfield| may be partially allocated despite failure. }
                ASN1_item_free(skfield, tt.item);
                goto _err ;
            end;
            len  := len - (p - q);
            if 0>= sk_ASN1_VALUE_push(Pstack_st_ASN1_VALUE(val^), skfield) then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                ASN1_item_free(skfield, tt.item);
                goto _err ;
            end;
        end;
        if sk_eoc >0 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_MISSING_EOC);
            goto _err ;
        end;
    end
    else
    if (flags and ASN1_TFLG_IMPTAG) >0 then
    begin
        { IMPLICIT tagging }
        ret := asn1_item_embed_d2i(val, @p, len,
                                  tt.item, tt.tag, aclass, opt,
                                  ctx, depth, libctx, propq);
        if 0>= ret then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto _err ;
        end
        else if (ret = -1) then
            Exit(-1);
    end
    else
    begin
        { Nothing special }
        ret := asn1_item_embed_d2i(val, @p, len, tt.item,
                                  -1, 0, opt, ctx, depth, libctx, propq);
        if 0>= ret then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto _err ;
        end
        else if (ret = -1) then
            Exit(-1);
    end;
    _in^ := p;
    Exit(1);

 _err:
    Result := 0;
end;

function asn1_check_tlen(olen : Plong; otag : PInteger; oclass : PByte;
                         inf, cst : PUTF8Char;const _in : PPByte; len : long;
                         exptag, expclass : integer;
                         opt : Int8; ctx : PASN1_TLC):integer;
var
  i, ptag, pclass : integer;
  plen : long;
  p, q : PByte;
  label _err;
begin
    p := _in^;
    q := p;
    if len <= 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL);
        goto _err ;
    end;
    if (ctx <> nil)  and  (ctx.valid>0) then
    begin
        i := ctx.ret;
        plen := ctx.plen;
        pclass := ctx.pclass;
        ptag := ctx.ptag;
        p  := p + ctx.hdrlen;
    end
    else
    begin
        i := ASN1_get_object(@p, @plen, @ptag, @pclass, len);
        if ctx <> nil then
        begin
            ctx.ret := i;
            ctx.plen := plen;
            ctx.pclass := pclass;
            ctx.ptag := ptag;
            ctx.hdrlen := p - q;
            ctx.valid := 1;
            {
             * If definite length, and no error, length + header can't exceed
             * total amount of data available.
             }
            if ( (i and $81) = 0 ) and  (plen + ctx.hdrlen > len) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_LONG);
                goto _err ;
            end;
        end;
    end;
    if (i and $80) <> 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_BAD_OBJECT_HEADER);
        goto _err ;
    end;
    if exptag >= 0 then
    begin
        if (exptag <> ptag)  or  (expclass <> pclass) then
        begin
            {
             * If type is OPTIONAL, not an error: indicate missing type.
             }
            if opt <> 0 then
                Exit(-1);
            ERR_raise(ERR_LIB_ASN1, ASN1_R_WRONG_TAG);
            goto _err ;
        end;
        {
         * We have a tag and class match: assume we are going to do something
         * with it
         }
        asn1_tlc_clear(ctx);
    end;
    if (i and 1) <> 0 then
        plen := len - (p - q);
    if inf <> nil    then inf^ := UTF8Char(i and 1);
    if cst <> nil    then cst^ := UTF8Char(i and V_ASN1_CONSTRUCTED);
    if olen <> nil   then olen^ := plen;
    if oclass <> nil then oclass^ := pclass;
    if otag <> nil   then otag^ := ptag;
    _in^ := p;
    Exit(1);

 _err:
    asn1_tlc_clear(ctx);
    Result := 0;
end;




function asn1_template_ex_d2i(val : PPASN1_VALUE;const _in : PPByte; inlen : long;const tt : PASN1_TEMPLATE; opt : Int8; ctx : PASN1_TLC; depth : integer; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  flags, aclass, ret : integer;
  len : long;
  p, q : PByte;
  exp_eoc, cst : byte;
  label _err;
begin
    if nil = val then Exit(0);
    flags := tt.flags;
    aclass := flags and ASN1_TFLG_TAG_CLASS;
    p := _in^;
    { Check if EXPLICIT tag expected }
    if (flags and ASN1_TFLG_EXPTAG)>0 then
    begin
        {
         * Need to work out amount of data available to the inner content and
         * where it starts: so read in EXPLICIT header to get the info.
         }
        ret := asn1_check_tlen(@len, nil, nil, @exp_eoc, @cst,
                              @p, inlen, tt.tag, aclass, opt, ctx);
        q := p;
        if 0>= ret then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            Exit(0);
        end
        else if (ret = -1) then
            Exit(-1);
        if 0>= cst then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED);
            Exit(0);
        end;
        { We've found the field so it can't be OPTIONAL now }
        ret := asn1_template_noexp_d2i(val, @p, len, tt, 0, ctx, depth, libctx,
                                      propq);
        if 0>= ret then begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            Exit(0);
        end;
        { We read the field in OK so update length }
        len  := len - (p - q);
        if exp_eoc>0 then
        begin
            { If NDEF we must have an EOC here }
            if 0>= asn1_check_eoc(@p, len) then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_MISSING_EOC);
                goto _err ;
            end;
        end
        else
        begin
            {
             * Otherwise we must hit the EXPLICIT tag end or its an error
             }
            if len>0 then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_EXPLICIT_LENGTH_MISMATCH);
                goto _err ;
            end;
        end;
    end
    else
        Exit(asn1_template_noexp_d2i(val, _in, inlen, tt, opt, ctx, depth, libctx, propq));
    _in^ := p;
    Exit(1);
 _err:
    Result := 0;
end;

function asn1_item_embed_d2i(pval : PPASN1_VALUE;const _in : PPByte; len : long;
                             const it : PASN1_ITEM; tag, aclass : integer;
                             opt : Int8; ctx : PASN1_TLC; depth : integer;
                             libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  tt,seqtt,
  errtt     : PASN1_TEMPLATE;
  ef        : PASN1_EXTERN_FUNCS;
  aux       : PASN1_AUX;
  asn1_cb   : TASN1_aux_cb;
  p, q      : PByte;
  oclass    : Byte;
  seq_eoc,
  seq_nolen,
  cst,isopt : int8;
  tmplen    : long;
  i, otag,
  ret       : integer;
  pchptr,
  pseqval   : PPASN1_VALUE;
  label _auxerr, _err;
begin
{$POINTERMATH ON}
    errtt := nil;
    p := nil;
    ret := 0;
    if (pval = nil)  or  (it = nil) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if len <= 0 then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_TOO_SMALL);
        Exit(0);
    end;
    aux := PASN1_AUX(it.funcs);
    if (aux <> nil)  and  (Assigned(aux.asn1_cb)) then
        asn1_cb := aux.asn1_cb
    else
        asn1_cb := nil;

    Inc(depth);
    if depth > ASN1_MAX_CONSTRUCTED_NEST  then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_NESTED_TOO_DEEP);
        goto _err ;
    end;

    case it.itype of
    ASN1_ITYPE_PRIMITIVE:
    begin
        if Assigned(it.templates) then
        begin
            {
             * tagging or OPTIONAL is currently illegal on an item template
             * because the flags can't get passed down. In practice this
             * isn't a problem: we include the relevant flags from the item
             * template in the template itself.
             }
            if (tag <> -1)  or  (opt >0) then
            begin
                ERR_raise(ERR_LIB_ASN1,
                          ASN1_R_ILLEGAL_OPTIONS_ON_ITEM_TEMPLATE);
                goto _err ;
            end;
            Exit(asn1_template_ex_d2i(pval, _in, len, it.templates, opt, ctx, depth, libctx, propq));
        end;
        Exit(asn1_d2i_ex_primitive(pval, _in, len, it, tag, aclass, opt, ctx));
    end;
    ASN1_ITYPE_MSTRING:
    begin
        {
         * It never makes sense for multi-strings to have implicit tagging, so
         * if tag <> -1, then this looks like an error in the template.
         }
        if tag <> -1 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_BAD_TEMPLATE);
            goto _err ;
        end;
        p := _in^;
        { Just read in tag and class }
        ret := asn1_check_tlen(nil, @otag, @oclass, nil, nil,
                              @p, len, -1, 0, 1, ctx);
        if 0>= ret then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto _err ;
        end;
        { Must be UNIVERSAL class }
        if oclass <> V_ASN1_UNIVERSAL then
        begin
            { If OPTIONAL, assume this is OK }
            if opt > 0 then
                Exit(-1);
            ERR_raise(ERR_LIB_ASN1, ASN1_R_MSTRING_NOT_UNIVERSAL);
            goto _err ;
        end;
        { Check tag matches bit map }
        if not ( (ASN1_tag2bit(otag) and (it.utype)) >0)  then
        begin
            { If OPTIONAL, assume this is OK }
            if opt > 0 then
                Exit(-1);
            ERR_raise(ERR_LIB_ASN1, ASN1_R_MSTRING_WRONG_TAG);
            goto _err ;
        end;
        Exit(asn1_d2i_ex_primitive(pval, _in, len, it, otag, 0, 0, ctx));
    end;
    ASN1_ITYPE_EXTERN:
    begin
        { Use new style d2i }
        ef := it.funcs;
        if Assigned(ef.asn1_ex_d2i_ex) then
           Exit(ef.asn1_ex_d2i_ex(pval, _in, len, it, tag, aclass, UTF8Char(opt), ctx, libctx, propq) );

        Exit(ef.asn1_ex_d2i(pval, _in, len, it, tag, aclass, UTF8Char(opt), ctx));
    end;
    ASN1_ITYPE_CHOICE:
    begin
        {
         * It never makes sense for CHOICE types to have implicit tagging, so
         * if tag <> -1, then this looks like an error in the template.
         }
        if tag <> -1 then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_BAD_TEMPLATE);
            goto _err ;
        end;
        if (Assigned(asn1_cb))  and  (0>= asn1_cb(ASN1_OP_D2I_PRE, pval, it, nil)) then
            goto _auxerr ;
        if pval^ <> nil then
        begin
            { Free up and zero CHOICE value if initialised }
            i := ossl_asn1_get_choice_selector(pval, it);
            if (i >= 0)  and  (i < it.tcount) then
            begin
                tt := it.templates + i;
                pchptr := ossl_asn1_get_field_ptr(pval, tt);
                ossl_asn1_template_free(pchptr, tt);
                ossl_asn1_set_choice_selector(pval, -1, it);
            end;
        end
        else
        if (0>= ossl_asn1_item_ex_new_intern(pval, it, libctx, propq)) then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto _err ;
        end;
        { CHOICE type, try each possibility in turn }
        p := _in^;
        tt := it.templates;
        for i := 0 to it.tcount-1 do
        begin
            pchptr := ossl_asn1_get_field_ptr(pval, tt);
            {
             * We mark field as OPTIONAL so its absence can be recognised.
             }
            ret := asn1_template_ex_d2i(pchptr, @p, len, tt, 1, ctx, depth,
                                       libctx, propq);
            Inc(tt);
            { If field not present, try the next one }
            if ret = -1 then continue;
            { If positive return, read OK, break loop }
            if ret > 0 then break;
            {
             * Must be an ASN1 parsing error.
             * Free up any partial choice value
             }
            ossl_asn1_template_free(pchptr, tt);
            errtt := tt;
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto _err ;

        end;
        { Did we fall off the end without reading anything? }
        if i = it.tcount then
        begin
            { If OPTIONAL, this is OK }
            if opt > 0 then
            begin
                { Free and zero it }
                ASN1_item_ex_free(pval, it);
                Exit(-1);
            end;
            ERR_raise(ERR_LIB_ASN1, ASN1_R_NO_MATCHING_CHOICE_TYPE);
            goto _err ;
        end;
        ossl_asn1_set_choice_selector(pval, i, it);
        if Assigned(asn1_cb ) and  (0>= asn1_cb(ASN1_OP_D2I_POST, pval, it, nil)) then
            goto _auxerr ;
        _in^ := p;
        Exit(1);
    end;
    ASN1_ITYPE_NDEF_SEQUENCE,
    ASN1_ITYPE_SEQUENCE:
    begin
        p := _in^;
        tmplen := len;
        { If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL }
        if tag = -1 then
        begin
            tag := V_ASN1_SEQUENCE;
            aclass := V_ASN1_UNIVERSAL;
        end;
        { Get SEQUENCE length and update len, p }
        ret := asn1_check_tlen(@len, nil, nil, @seq_eoc, @cst,
                              @p, len, tag, aclass, opt, ctx);
        if 0>= ret then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto _err ;
        end
        else if (ret = -1) then
            Exit(-1);
        if (aux <> nil)  and  ( (aux.flags and ASN1_AFLG_BROKEN)>0)  then
        begin
            len := tmplen - (p - _in^);
            seq_nolen := 1;
        end
        { If indefinite we don't do a length check }
        else
            seq_nolen := seq_eoc;
        if 0>= cst then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_SEQUENCE_NOT_CONSTRUCTED);
            goto _err ;
        end;
        if (pval^ = nil) and
           (0>= ossl_asn1_item_ex_new_intern(pval, it, libctx, propq )) then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_NESTED_ASN1_ERROR);
            goto _err ;
        end;
        if (Assigned(asn1_cb))  and  (0 >= asn1_cb(ASN1_OP_D2I_PRE, pval, it, nil)) then
            goto _auxerr ;
        { Free up and zero any ADB found }
        tt := it.templates;
        for i := 0 to it.tcount-1 do
        begin
            if (tt.flags and ASN1_TFLG_ADB_MASK) > 0 then
            begin
                seqtt := ossl_asn1_do_adb(pval^, tt, 0);
                if seqtt = nil then continue;
                pseqval := ossl_asn1_get_field_ptr(pval, seqtt);
                ossl_asn1_template_free(pseqval, seqtt);
            end;
            Inc(tt);
        end;
        { Get each field entry }
        tt := it.templates;
        i := 0;
        while i < it.tcount do
        begin
            seqtt := ossl_asn1_do_adb(pval^, tt, 1);
            if seqtt = nil then goto _err ;
            pseqval := ossl_asn1_get_field_ptr(pval, seqtt);
            { Have we ran out of data? }
            if 0 >= len then break;
            q := p;
            if asn1_check_eoc(@p, len) >0 then
            begin
                if 0>= seq_eoc then
                begin
                    ERR_raise(ERR_LIB_ASN1, ASN1_R_UNEXPECTED_EOC);
                    goto _err ;
                end;
                len  := len - (p - q);
                seq_eoc := 0;
                break;
            end;
            {
             * This determines the OPTIONAL flag value. The field cannot be
             * omitted if it is the last of a SEQUENCE and there is still
             * data to be read. This isn't strictly necessary but it
             * increases efficiency in some cases.
             }
            if i = (it.tcount - 1 )then
                isopt := 0
            else
                isopt := (seqtt.flags and ASN1_TFLG_OPTIONAL);
            {
             * attempt to read in field, allowing each to be OPTIONAL
             }
            //if (len = 275) then
              //  Writeln('trace');
            ret := asn1_template_ex_d2i(pseqval, @p, len, seqtt, isopt, ctx,
                                       depth, libctx, propq);
            if 0>= ret then
            begin
                errtt := seqtt;
                goto _err ;
            end
            else
            if (ret = -1) then
            begin
                {
                 * OPTIONAL component absent. Free and zero the field.
                 }
                ossl_asn1_template_free(pseqval, seqtt);
                continue;
            end;
            { Update length }
            len  := len - (p - q);
            Inc(tt); inc(i);
        end; //Get each field entry

        { Check for EOC if expecting one }
        if (seq_eoc>0)  and  (0>= asn1_check_eoc(@p, len)) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_MISSING_EOC);
            goto _err ;
        end;
        { Check all data read }
        if (0>= seq_nolen)  and  (len>0) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_SEQUENCE_LENGTH_MISMATCH);
            goto _err ;
        end;
        {
         * If we get here we've got no more data in the SEQUENCE, however we
         * may not have read all fields so check all remaining are OPTIONAL
         * and clear any that are.
         }
        while i < it.tcount do
        begin
            seqtt := ossl_asn1_do_adb( pval^, tt, 1);
            if seqtt = nil then goto _err ;
            if (seqtt.flags and ASN1_TFLG_OPTIONAL)>0 then
            begin
                pseqval := ossl_asn1_get_field_ptr(pval, seqtt);
                ossl_asn1_template_free(pseqval, seqtt);
            end
            else
            begin
                errtt := seqtt;
                ERR_raise(ERR_LIB_ASN1, ASN1_R_FIELD_MISSING);
                goto _err ;
            end;
            Inc(tt); inc(i);
        end;
        { Save encoding }
        if 0>= ossl_asn1_enc_save(pval, _in^, p - _in^, it) then
            goto _auxerr ;
        if (Assigned(asn1_cb))  and  (0>= asn1_cb(ASN1_OP_D2I_POST, pval, it, nil)) then
            goto _auxerr ;
        _in^ := p;
        Exit(1);
    end
    else
        Exit(0);
    end;

 _auxerr:
    ERR_raise(ERR_LIB_ASN1, ASN1_R_AUX_ERROR);

 _err:
    if errtt <> nil then
       ERR_add_error_data(4, ['Field=', errtt.field_name, ', Type=', it.sname])
    else
        ERR_add_error_data(2, ['Type=', it.sname]);

    Result := 0;
{$POINTERMATH OFF}
end;

function asn1_item_ex_d2i_intern(pval : PPASN1_VALUE;const &in : PPByte; len : long;const it : PASN1_ITEM; tag, aclass : integer; opt : Int8;ctx : PASN1_TLC; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  rv : integer;
begin
    if (pval = nil)  or  (it = nil) then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    rv := asn1_item_embed_d2i(pval, &in, len, it, tag, aclass, opt, ctx, 0, libctx, propq);
    if rv <= 0 then
       ASN1_item_ex_free(pval, it);
    Result := rv;
end;

procedure asn1_tlc_clear_nc(c : PASN1_TLC);
begin
  c.valid := 0;
end;

function ASN1_item_d2i_ex(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):PASN1_VALUE;
var
  c : TASN1_TLC;
  ptmpval : PASN1_VALUE;
begin
    ptmpval := nil;
    if pval = nil then pval := @ptmpval;
    c := default(TASN1_TLC);
    asn1_tlc_clear_nc(@c);
    if asn1_item_ex_d2i_intern(pval, _in, len, it, -1, 0, 0, @c, libctx, propq) > 0  then
        Exit(pval^);
    Result := nil;
end;

function ASN1_item_d2i(pval : PPASN1_VALUE;const _in : PPByte; len : long;const it : PASN1_ITEM):PASN1_VALUE;
begin
    Result := ASN1_item_d2i_ex(pval, _in, len, it, nil, nil);
end;

end.
