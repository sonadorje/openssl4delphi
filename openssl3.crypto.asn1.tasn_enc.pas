unit openssl3.crypto.asn1.tasn_enc;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

function ASN1_item_i2d(const val : PASN1_VALUE; _out : PPByte;const it : PASN1_ITEM):integer;

 function asn1_item_flags_i2d(const val : PASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; flags : integer):integer;
 function ASN1_item_ex_i2d(const pval : PPASN1_VALUE;  _out : PPByte;const it : PASN1_ITEM; tag, aclass : integer):integer;
 function asn1_template_ex_i2d(pval : PPASN1_VALUE; _out : PPByte;const tt : PASN1_TEMPLATE; tag, iclass : integer):integer;
 function asn1_set_seq_out(sk : Pstack_st_const_ASN1_VALUE; _out : PPByte; skcontlen : integer;const item : PASN1_ITEM; do_sort, iclass : integer):integer;
 function der_cmp(const a, b : Pointer):integer;
  function asn1_i2d_ex_primitive(const pval : PPASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; tag, aclass : integer):integer;
 function asn1_ex_i2c( pval : PPASN1_VALUE; cout : PByte; putype : PInteger;const it : PASN1_ITEM):integer;

implementation
uses OpenSSL3.Err, openssl3.crypto.mem, openssl3.crypto.asn1.asn1_lib,
     QuickSORT, openssl3.crypto.asn1.a_bitstr, openssl3.crypto.asn1.a_int,
     openssl3.crypto.asn1.tasn_utl;


function asn1_ex_i2c( pval : PPASN1_VALUE; cout : PByte; putype : PInteger;const it : PASN1_ITEM):integer;
var
  tbool : PASN1_BOOLEAN;
  strtmp : PASN1_STRING;
  otmp : PASN1_OBJECT;
  utype : integer;
  cont : PByte;
  c : Byte;
  len : integer;
  pf : PASN1_PRIMITIVE_FUNCS;
  typ : PASN1_TYPE;
begin
    tbool := nil;
    pf := it.funcs;
    if (pf <> nil) and  (Assigned(pf.prim_i2c)) then
       Exit(pf.prim_i2c(pval, cout, putype, it));
    { Should type be omitted? }
    if (it.itype <> ASN1_ITYPE_PRIMITIVE) or  (it.utype <> V_ASN1_BOOLEAN) then
    begin
        if pval^ = nil then
            Exit(-1);
    end;
    if it.itype = ASN1_ITYPE_MSTRING then
    begin
        { If MSTRING type set the underlying type }
        strtmp := PASN1_STRING(pval^);
        utype := strtmp.&type;
        putype^ := utype;
    end
    else
    if (it.utype = V_ASN1_ANY) then
    begin
        { If ANY set type and pointer to value }
        typ := PASN1_TYPE(pval^);
        utype := typ._type;
        putype^ := utype;
        pval := PPASN1_VALUE(@typ.value.asn1_value); { actually is const }
    end
    else
        utype := putype^;
    case utype of
    V_ASN1_OBJECT:
    begin
        otmp := PASN1_OBJECT(pval^);
        cont := otmp.data;
        len := otmp.length;
        if (cont = nil)  or  (len = 0) then
           Exit(-1);
    end;
    V_ASN1_NULL:
    begin
        cont := nil;
        len := 0;
    end;
    V_ASN1_BOOLEAN:
    begin
        if tbool^ = -1 then Exit(-1);
        if it.utype <> V_ASN1_ANY then
        begin
            {
             * Default handling if value = size field then omit
             }
            if (tbool^>0)  and  (it.size > 0) then
                Exit(-1);
            if (0>= tbool^)  and  (0>= it.size) then Exit(-1);
        end;
        c := Byte( tbool^);
        cont := @c;
        len := 1;
    end;
    V_ASN1_BIT_STRING:
    begin
        if cout <> nil then
           Exit(ossl_i2c_ASN1_BIT_STRING(PASN1_BIT_STRING(pval^), @cout))
        else
           Exit(ossl_i2c_ASN1_BIT_STRING(PASN1_BIT_STRING(pval^), nil));
    end;
    V_ASN1_INTEGER,
    V_ASN1_ENUMERATED:
        {
         * These are all have the same content format as ASN1_INTEGER
         }
    begin
       if cout <> nil then
          Exit(ossl_i2c_ASN1_INTEGER(PASN1_INTEGER(pval^), @cout))
       else
         Exit(ossl_i2c_ASN1_INTEGER(PASN1_INTEGER(pval^), nil));
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
    V_ASN1_SEQUENCE,
    V_ASN1_SET:
    begin
        { All based on ASN1_STRING and handled the same }
        strtmp := PASN1_STRING( pval^);
        { Special handling for NDEF }
        if (it.size = ASN1_TFLG_NDEF)  and ( (strtmp.flags and ASN1_STRING_FLAG_NDEF)>0) then
        begin
            if Assigned(cout) then
            begin
                strtmp.data := cout;
                strtmp.length := 0;
            end;
            { Special return code }
            Exit(-2);
        end;
        cont := strtmp.data;
        len := strtmp.length;
    end;
    end;
    if (Assigned(cout))  and  (len>0) then
       memcpy(cout, cont, len);
    Result := len;
end;



function asn1_i2d_ex_primitive(const pval : PPASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; tag, aclass : integer):integer;
var
  len, utype, usetag, ndef : integer;
begin
    ndef := 0;
    utype := it.utype;
    {
     * Get length of content octets and maybe find out the underlying type.
     }
    len := asn1_ex_i2c(pval, nil, @utype, it);
    {
     * If SEQUENCE, SET or OTHER then header is included in pseudo content
     * octets so don't include tag+length. We need to check here because the
     * call to asn1_ex_i2c() could change utype.
     }
    if (utype = V_ASN1_SEQUENCE)  or  (utype = V_ASN1_SET)   or
        (utype = V_ASN1_OTHER)  then
        usetag := 0
    else
        usetag := 1;
    { -1 means omit type }
    if len = -1 then Exit(0);
    { -2 return is special meaning use ndef }
    if len = -2 then
    begin
        ndef := 2;
        len := 0;
    end;
    { If not implicitly tagged get tag from underlying type }
    if tag = -1 then tag := utype;
    { Output tag+length followed by content octets }
    if _out <> nil then
    begin
        if usetag>0 then
            ASN1_put_object(_out, ndef, len, tag, aclass);
        asn1_ex_i2c(pval, _out^, @utype, it);
        if ndef>0 then
           ASN1_put_eoc(_out)
        else
            _out^  := _out^ + len;
    end;
    if usetag>0 then
       Exit(ASN1_object_size(ndef, len, tag));
    Result := len;
end;

function der_cmp(const a, b : Pointer):integer;
var
  d1, d2 : PDER_ENC;
  cmplen, i : integer;
begin
    d1 := a; d2 := b;
    cmplen := get_result(d1.length < d2.length , d1.length , d2.length);
    i := memcmp(d1.data, d2.data, cmplen);
    if i>0 then Exit(i);
    Result := d1.length - d2.length;
end;

type
      TCompareFunc = function(const a,b: Pointer): Integer;
procedure qsort(base: Pointer; num: Cardinal; width: Cardinal; compare: TCompareFunc);
var
  m: Pointer;
  n: Integer;
  o: Pointer;
  oa,ob,oc: Integer;
  p: Integer;
begin
    if num<2 then exit;
    if compare(base,Pointer(Ptruint(base)+width))<=0 then
      Move(base^,m^,(width shl 1))
    else
    begin
      Move(Pointer(Ptruint(base)+width)^,m^,width);
      Move(base^,Pointer(Ptruint(m)+width)^,width);
    end;
    n:=2;
    while Ptruint(n)<num do
    begin
      o:=Pointer(Ptruint(base)+Ptruint(n)*width);
      if compare(m,o)>=0 then
        ob:=0
      else
      begin
        oa:=0;
        ob:=n;
        while oa+1<ob do
        begin
          oc:=((oa+ob) shr 1);
          p:=compare(Pointer(Ptruint(m)+Ptruint(oc)*width),o);
          if p<0 then
            oa:=oc
          else if p=0 then
          begin
            ob:=oc;
            break;
          end
          else
            ob:=oc;
        end;
      end;
      if ob=0 then
      begin
        Move(m^,Pointer(Ptruint(m)+width)^,Ptruint(n)*width);
        Move(o^,m^,width);
      end
      else if ob=n then
        Move(o^,Pointer(Ptruint(m)+Ptruint(n)*width)^,width)
      else
      begin
        Move(Pointer(Ptruint(m)+Ptruint(ob)*width)^,Pointer(Ptruint(m)+Ptruint(ob+1)*width)^,Ptruint(n-ob)*width);
        Move(o^,Pointer(Ptruint(m)+Ptruint(ob)*width)^,width);
      end;
      Inc(n);
    end;
    system.Move(m^,base^,num*width);
    m := nil;
    FreeMem(m);
end;

function asn1_set_seq_out(sk : Pstack_st_const_ASN1_VALUE; _out : PPByte; skcontlen : integer;const item : PASN1_ITEM; do_sort, iclass : integer):integer;
var
  i, ret : integer;
  skitem : PASN1_VALUE;
  tmpdat, p : PByte;
  derlst,tder : PDER_ENC;
  label _err;
begin
    ret := 0;
    tmpdat := nil; p := nil;
    derlst := nil;
    if do_sort>0 then
    begin
        { Don't need to sort less than 2 items }
        if sk_const_ASN1_VALUE_num(sk) < 2 then
            do_sort := 0
        else
        begin
            derlst := OPENSSL_malloc(sk_const_ASN1_VALUE_num(sk)
                                    * sizeof( derlst^));
            if derlst = nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
            tmpdat := OPENSSL_malloc(skcontlen);
            if tmpdat = nil then
            begin
                ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
        end;
    end;
    { If not sorting just output each item }
    if 0>= do_sort then
    begin
        for i := 0 to sk_const_ASN1_VALUE_num(sk)-1 do
        begin
            skitem := sk_const_ASN1_VALUE_value(sk, i);
            ASN1_item_ex_i2d(&skitem, _out, item, -1, iclass);
        end;
        Exit(1);
    end;
    p := tmpdat;
    { Doing sort: build up a list of each member's DER encoding }
    tder := derlst;
    for i := 0 to sk_const_ASN1_VALUE_num(sk)-1 do
    begin
        skitem := sk_const_ASN1_VALUE_value(sk, i);
        tder.data := p;
        tder.length := ASN1_item_ex_i2d(@skitem, @p, item, -1, iclass);
        tder.field := skitem;
        Inc(tder);
    end;
    { Now sort them }
    qsort(derlst, sk_const_ASN1_VALUE_num(sk), sizeof( derlst^), der_cmp);
    { Output sorted DER encoding }
    p := _out^;
    tder := derlst;
    for i := 0 to  sk_const_ASN1_VALUE_num(sk)-1  do
    begin
        memcpy(p, tder.data, tder.length);
        p  := p + tder.length;
        Inc(tder);
    end;
    _out^ := p;
    { If do_sort is 2 then reorder the STACK }
    if do_sort = 2 then
    begin
        tder := derlst;
        for i := 0 to sk_const_ASN1_VALUE_num(sk)-1 do
        begin
            sk_const_ASN1_VALUE_set(sk, i, tder.field);
            Inc(tder);
        end;
    end;
    ret := 1;
_err:
    OPENSSL_free(Pointer(derlst));
    OPENSSL_free(Pointer(tmpdat));
    Result := ret;
end;



function asn1_template_ex_i2d(pval : PPASN1_VALUE; _out : PPByte;const tt : PASN1_TEMPLATE; tag, iclass : integer):integer;
var
  flags, i,
  ret, ttag,
  tclass, ndef,
  len       : integer;
  tval      : PASN1_VALUE;
  sk        : Pstack_st_const_ASN1_VALUE;
  isset,
  sktag,
  skaclass,
  skcontlen,
  sklen     : integer;
  skitem    : PASN1_VALUE;
begin
     flags := tt.flags;
    {
     * If field is embedded then val needs fixing so it is a pointer to
     * a pointer to a field.
     }
    if (flags and ASN1_TFLG_EMBED)>0 then
    begin
        tval := PASN1_VALUE(pval);
        pval := @tval;
    end;
    {
     * Work out tag and class to use: tagging may come either from the
     * template or the arguments, not both because this would create
     * ambiguity. Additionally the iclass argument may contain some
     * additional flags which should be noted and passed down to other
     * levels.
     }
    if (flags and ASN1_TFLG_TAG_MASK)>0 then
    begin
        { Error if argument and template tagging }
        if tag <> -1 then
            { FIXME: error code here }
            Exit(-1);
        { Get tagging from template }
        ttag := tt.tag;
        tclass := flags and ASN1_TFLG_TAG_CLASS;
    end
    else
    if (tag <> -1) then
    begin
        { No template tagging, get from arguments }
        ttag := tag;
        tclass := iclass and ASN1_TFLG_TAG_CLASS;
    end
    else
    begin
        ttag := -1;
        tclass := 0;
    end;
    {
     * Remove any class mask from iflag.
     }
    iclass := iclass and (not ASN1_TFLG_TAG_CLASS);
    {
     * At this point 'ttag' contains the outer tag to use, 'tclass' is the
     * class and iclass is any flags passed to this function.
     }
    { if template and arguments require ndef, use it }
    if ( (flags and ASN1_TFLG_NDEF)>0)  and  ( (iclass and ASN1_TFLG_NDEF)>0) then
        ndef := 2
    else
        ndef := 1;
    if (flags and ASN1_TFLG_SK_MASK)>0 then
    begin
        { SET OF, SEQUENCE OF }
        sk := Pstack_st_const_ASN1_VALUE (pval);
        if pval^ = nil then Exit(0);
        if (flags and ASN1_TFLG_SET_OF)>0 then
        begin
            isset := 1;
            { 2 means we reorder }
            if (flags and ASN1_TFLG_SEQUENCE_OF)>0 then isset := 2;
        end
        else
            isset := 0;
        {
         * Work out inner tag value: if EXPLICIT or no tagging use underlying
         * type.
         }
        if (ttag <> -1 )  and  (0>= (flags and ASN1_TFLG_EXPTAG)) then
        begin
            sktag := ttag;
            skaclass := tclass;
        end
        else
        begin
            skaclass := V_ASN1_UNIVERSAL;
            if isset>0 then
               sktag := V_ASN1_SET
            else
               sktag := V_ASN1_SEQUENCE;
        end;
        { Determine total length of items }
        skcontlen := 0;

        for i := 0 to sk_const_ASN1_VALUE_num(sk)-1 do
        begin
            skitem := sk_const_ASN1_VALUE_value(sk, i);
            len := ASN1_item_ex_i2d(@skitem, nil, tt.item, -1, iclass);
            if (len = -1)  or  (skcontlen > INT_MAX - len) then
                Exit(-1);
            if (len = 0)  and ( (tt.flags and ASN1_TFLG_OPTIONAL) = 0)  then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_ZERO_CONTENT);
                Exit(-1);
            end;
            skcontlen  := skcontlen + len;
        end;
        sklen := ASN1_object_size(ndef, skcontlen, sktag);
        if sklen = -1 then Exit(-1);
        { If EXPLICIT need length of surrounding tag }
        if (flags and ASN1_TFLG_EXPTAG)>0 then
           ret := ASN1_object_size(ndef, sklen, ttag)
        else
            ret := sklen;
        if (nil =  _out)  or  (ret = -1) then
           Exit(ret);
        { Now encode this lot... }
        { EXPLICIT tag }
        if (flags and ASN1_TFLG_EXPTAG)>0 then
           ASN1_put_object(_out, ndef, sklen, ttag, tclass);
        { SET or SEQUENCE and IMPLICIT tag }
        ASN1_put_object(_out, ndef, skcontlen, sktag, skaclass);
        { And the stuff itself }
        asn1_set_seq_out(sk, _out, skcontlen, tt.item,
                         isset, iclass);
        if ndef = 2 then
        begin
            ASN1_put_eoc(_out);
            if (flags and ASN1_TFLG_EXPTAG)>0 then
               ASN1_put_eoc(_out);
        end;
        Exit(ret);
    end;
    if (flags and ASN1_TFLG_EXPTAG)> 0 then
    begin
        { EXPLICIT tagging }
        { Find length of tagged item }

        i := ASN1_item_ex_i2d(pval, nil, tt.item, -1, iclass);
        if i = 0 then begin
            if (tt.flags and ASN1_TFLG_OPTIONAL) = 0 then
            begin
                ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_ZERO_CONTENT);
                Exit(-1);
            end;
            Exit(0);
        end;
        { Find length of EXPLICIT tag }
        ret := ASN1_object_size(ndef, i, ttag);
        if (_out <> nil)  and  (ret <> -1) then
        begin
            { Output tag and item }
            ASN1_put_object(_out, ndef, i, ttag, tclass);
            ASN1_item_ex_i2d(pval, _out, tt.item, -1, iclass);
            if ndef = 2 then
               ASN1_put_eoc(_out);
        end;
        Exit(ret);
    end;
    { Either normal or IMPLICIT tagging: combine class and flags }
    len := ASN1_item_ex_i2d(pval, _out, tt.item,
                              ttag, tclass or iclass);
    if (len = 0 ) and ( (tt.flags and ASN1_TFLG_OPTIONAL) = 0)  then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ILLEGAL_ZERO_CONTENT);
        Exit(-1);
    end;
    Result := len;
end;



function ASN1_item_ex_i2d(const pval : PPASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; tag, aclass : integer):integer;
var
  tt, seqtt         : PASN1_TEMPLATE;
  i,
  seqcontlen,
  seqlen,
  ndef       : integer;
  chtt: PASN1_TEMPLATE;
  ef         : PASN1_EXTERN_FUNCS;
  aux        : PASN1_AUX;
  asn1_cb    : TASN1_aux_const_cb;
  tmplen     : integer;
  pchval, pseqval     : PPASN1_VALUE;

begin
{$POINTERMATH ON}
    tt := nil;
    ndef := 1;
     aux := it.funcs;
    asn1_cb := nil;
    if (it.itype <> ASN1_ITYPE_PRIMITIVE)  and  (pval^ = nil) then
        Exit(0);
    if aux <> nil then
    begin
       if (aux.flags and ASN1_AFLG_CONST_CB) <> 0  then
          asn1_cb := aux.asn1_const_cb
       else
          asn1_cb := aux.asn1_cb; { backward compatibility }
    end;
    case it.itype of
    ASN1_ITYPE_PRIMITIVE:
    begin
        if it.templates <> nil then
           Exit(asn1_template_ex_i2d(pval, _out, it.templates,
                                        tag, aclass));
        Exit(asn1_i2d_ex_primitive(pval, _out, it, tag, aclass));
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
            Exit(-1);
        end;
        Exit(asn1_i2d_ex_primitive(pval, _out, it, -1, aclass));
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
            Exit(-1);
        end;
        if (Assigned(asn1_cb))  and  (0>= asn1_cb(ASN1_OP_I2D_PRE, pval, it, nil) )then
            Exit(0);
        i := ossl_asn1_get_choice_selector_const(pval, it);
        if (i >= 0)  and  (i < it.tcount) then
        begin
            chtt := it.templates + i;
            pchval := ossl_asn1_get_const_field_ptr(pval, chtt);
            Exit(asn1_template_ex_i2d(pchval, _out, chtt, -1, aclass));
        end;
        { Fixme: error condition if selector out of range }
        if (Assigned(asn1_cb))  and  (0>= asn1_cb(ASN1_OP_I2D_POST, pval, it, nil)) then
            Exit(0);
    end;
    ASN1_ITYPE_EXTERN:
    begin
        { If new style i2d it does all the work }
        ef := it.funcs;
        Exit(ef.asn1_ex_i2d(pval, _out, it, tag, aclass));
    end;
    ASN1_ITYPE_NDEF_SEQUENCE,
        { Use indefinite length constructed if requested }

        { fall through }
    ASN1_ITYPE_SEQUENCE:
    begin
        if (aclass and ASN1_TFLG_NDEF) >0 then
           ndef := 2;
        i := ossl_asn1_enc_restore(@seqcontlen, @_out, pval, it);
        { An error occurred }
        if i < 0 then Exit(0);
        { We have a valid cached encoding... }
        if i > 0 then Exit(seqcontlen);
        { Otherwise carry on }
        seqcontlen := 0;
        { If no IMPLICIT tagging set to SEQUENCE, UNIVERSAL }
        if tag = -1 then
        begin
            tag := V_ASN1_SEQUENCE;
            { Retain any other flags in aclass }
            aclass := (aclass and  not ASN1_TFLG_TAG_CLASS)
                or V_ASN1_UNIVERSAL;
        end;
        if (Assigned(asn1_cb)) and  (0>= asn1_cb(ASN1_OP_I2D_PRE, pval, it, nil)) then
            Exit(0);
        { First work out sequence content length }
        tt := it.templates;
        for i := 0 to it.tcount-1 do
        begin
            seqtt := ossl_asn1_do_adb(pval^, tt, 1);
            if nil = seqtt then
               Exit(0);
            pseqval := ossl_asn1_get_const_field_ptr(pval, seqtt);

            tmplen := asn1_template_ex_i2d(pseqval, nil, seqtt, -1, aclass);
            if (tmplen = -1)  or  (tmplen > INT_MAX - seqcontlen) then
                Exit(-1);
            seqcontlen  := seqcontlen + tmplen;
            Inc(tt);
        end;
        seqlen := ASN1_object_size(ndef, seqcontlen, tag);
        if (nil = _out)  or  (seqlen = -1) then Exit(seqlen);
        { Output SEQUENCE header }
        ASN1_put_object(_out, ndef, seqcontlen, tag, aclass);
        tt := it.templates;
        for i := 0 to it.tcount-1 do
        begin
            seqtt := ossl_asn1_do_adb( pval^, tt, 1);
            if nil = seqtt then Exit(0);
            pseqval := ossl_asn1_get_const_field_ptr(pval, seqtt);
            { FIXME: check for errors in enhanced version }
            asn1_template_ex_i2d(pseqval, _out, seqtt, -1, aclass);
            Inc(tt);
        end;
        if ndef = 2 then
           ASN1_put_eoc(_out);
        if (Assigned(asn1_cb))  and  (0>= asn1_cb(ASN1_OP_I2D_POST, pval, it, nil)) then
            Exit(0);
        Exit(seqlen);
    end;
    else
        Exit(0);
    end;
    Result := 0;
{$POINTERMATH OFF}
end;

function asn1_item_flags_i2d(const val : PASN1_VALUE; _out : PPByte;const it : PASN1_ITEM; flags : integer):integer;
var
  p, buf : PByte;
  len : integer;
begin
    if (_out <> nil)  then
    begin

        len := ASN1_item_ex_i2d(@val, nil, it, -1, flags);
        if len <= 0 then Exit(len);
        buf := OPENSSL_malloc(len);
        if buf =  nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(-1);
        end;
        p := buf;
        ASN1_item_ex_i2d(@val, @p, it, -1, flags);
        _out^ := buf;
        Exit(len);
    end;
    Result := ASN1_item_ex_i2d(@val, _out, it, -1, flags);
end;




function ASN1_item_i2d(const val : PASN1_VALUE; _out : PPByte;const it : PASN1_ITEM):integer;
begin
    Result := asn1_item_flags_i2d(val, _out, it, 0);
end;


end.
