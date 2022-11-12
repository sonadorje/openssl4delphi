unit OpenSSL3.crypto.x509.v3_crld;

interface
uses OpenSSL.Api;

  function gnames_from_sectname( ctx : PX509V3_CTX; sect : PUTF8Char):Pstack_st_GENERAL_NAME;
  function set_dist_point_name( pdp : PPDIST_POINT_NAME; ctx : PX509V3_CTX; cnf : PCONF_VALUE):integer;
  function set_reasons( preas : PPASN1_BIT_STRING; value : PUTF8Char):integer;
  function print_reasons(_out : PBIO;const rname : PUTF8Char; rflags : PASN1_BIT_STRING; indent : integer):integer;
  function crldp_from_section( ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PDIST_POINT;
  function v2i_crld(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
  function dpn_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
  function v2i_idp(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
  function print_gens( _out : PBIO; gens : Pstack_st_GENERAL_NAME; indent : integer):integer;
  function print_distpoint( _out : PBIO; dpn : PDIST_POINT_NAME; indent : integer):integer;
  function i2r_idp(const method : PX509V3_EXT_METHOD; pidp : Pointer; _out : PBIO; indent : integer):integer;
  function i2r_crldp(const method : PX509V3_EXT_METHOD; pcrldp : Pointer; _out : PBIO; indent : integer):integer;
  function DIST_POINT_set_dpname(dpn : PDIST_POINT_NAME;const iname : PX509_NAME):integer;
  function d2i_DIST_POINT_NAME(a : PPDIST_POINT_NAME;const _in : PPByte; len : long):PDIST_POINT_NAME;
  function i2d_DIST_POINT_NAME(const a : PDIST_POINT_NAME; _out : PPByte):integer;
  function DIST_POINT_NAME_new:PDIST_POINT_NAME;
  procedure DIST_POINT_NAME_free( a : PDIST_POINT_NAME);
  function DIST_POINT_NAME_it:PASN1_ITEM;
  function d2i_DIST_POINT(a : PPDIST_POINT;const _in : PPByte; len : long):PDIST_POINT;
  function i2d_DIST_POINT(const a : PDIST_POINT; _out : PPByte):integer;
  function DIST_POINT_new:PDIST_POINT;
  procedure DIST_POINT_free( a : PDIST_POINT);
  function DIST_POINT_it:PASN1_ITEM;
  function ISSUING_DIST_POINT_it:PASN1_ITEM;
  function d2i_ISSUING_DIST_POINT(a : PPISSUING_DIST_POINT;const _in : PPByte; len : long):PISSUING_DIST_POINT;
  function i2d_ISSUING_DIST_POINT(const a : PISSUING_DIST_POINT; _out : PPByte):integer;
  function ISSUING_DIST_POINT_new:PISSUING_DIST_POINT;
  procedure ISSUING_DIST_POINT_free( a : PISSUING_DIST_POINT);
  function ASN1_FBOOLEAN_it:PASN1_ITEM;
  function CRL_DIST_POINTS_it:PASN1_ITEM;

  function d2i_CRL_DIST_POINTS(a : PPCRL_DIST_POINTS;const &in : PPByte; len : long):PCRL_DIST_POINTS;
  function i2d_CRL_DIST_POINTS(const a : PCRL_DIST_POINTS; &out : PPByte):integer;
  function CRL_DIST_POINTS_new:PCRL_DIST_POINTS;
  procedure CRL_DIST_POINTS_free( a : PCRL_DIST_POINTS);

var
  DIST_POINT_NAME_ch_tt: array[0..1] of TASN1_TEMPLATE ;
  DIST_POINT_seq_tt:     array[0..2] of TASN1_TEMPLATE ;
  CRL_DIST_POINTS_item_tt: TASN1_TEMPLATE;
  ISSUING_DIST_POINT_seq_tt: array[0..5] of TASN1_TEMPLATE;
  ossl_v3_freshest_crl, ossl_v3_idp, ossl_v3_crld: TX509V3_EXT_METHOD;

const
  DIST_POINT_NAME_aux: TASN1_AUX  = (
      app_data: nil;
      flags: 0; ref_offset: 0;ref_lock:  0;
      asn1_cb:  dpn_cb;enc_offset:  0;asn1_const_cb: nil);

  reason_flags: array[0..9] of TBIT_STRING_BITNAME = (
    (bitnum: 0; lname: 'Unused'; sname: 'unused'),
    (bitnum: 1; lname: 'Key Compromise'; sname: 'keyCompromise'),
    (bitnum: 2; lname: 'CA Compromise'; sname: 'CACompromise'),
    (bitnum: 3; lname: 'Affiliation Changed'; sname: 'affiliationChanged'),
    (bitnum: 4; lname: 'Superseded'; sname: 'superseded'),
    (bitnum: 5; lname: 'Cessation Of Operation'; sname: 'cessationOfOperation'),
    (bitnum: 6; lname: 'Certificate Hold'; sname: 'certificateHold'),
    (bitnum: 7; lname: 'Privilege Withdrawn'; sname: 'privilegeWithdrawn'),
    (bitnum: 8; lname: 'AA Compromise'; sname: 'AACompromise'),
    (bitnum: -1; lname: nil;sname: nil)
);

implementation
uses  OpenSSL3.crypto.x509.v3_conf, OpenSSL3.crypto.x509.v3_utl,
      OpenSSL3.Err, OpenSSL3.crypto.x509.v3_san, OpenSSL3.common,
      OpenSSL3.crypto.x509, openssl3.crypto.asn1.tasn_dec,
      openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
      openssl3.crypto.asn1.tasn_fre, openssl3.crypto.x509v3,
      openssl3.crypto.asn1.a_bitstr, openssl3.crypto.bio.bio_print,
      openssl3.crypto.x509.v3_genn, openssl3.crypto.asn1.tasn_typ,
      openssl3.crypto.bio.bio_lib,  openssl3.crypto.asn1.a_strex,
      OpenSSL3.crypto.x509.x509name,
      OpenSSL3.openssl.conf, OpenSSL3.crypto.x509.x_name;







function d2i_CRL_DIST_POINTS(a : PPCRL_DIST_POINTS;const &in : PPByte; len : long):PCRL_DIST_POINTS;
begin
 Result := PCRL_DIST_POINTS(ASN1_item_d2i(PPASN1_VALUE(a), &in, len, CRL_DIST_POINTS_it));
end;


function i2d_CRL_DIST_POINTS(const a : PCRL_DIST_POINTS; &out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), &out, CRL_DIST_POINTS_it);
end;


function CRL_DIST_POINTS_new:PCRL_DIST_POINTS;
begin
   Result := PCRL_DIST_POINTS (ASN1_item_new(CRL_DIST_POINTS_it));
end;


procedure CRL_DIST_POINTS_free( a : PCRL_DIST_POINTS);
begin
   ASN1_item_free(PASN1_VALUE(a), CRL_DIST_POINTS_it);
end;



function CRL_DIST_POINTS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
    local_it := get_ASN1_ITEM ($0, -1, @CRL_DIST_POINTS_item_tt, 0,
                                Pointer(0) , 0, 'CRL_DIST_POINTS');
    Result := @local_it;
end;


function ASN1_FBOOLEAN_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($0, 1, Pointer(0) , 0, Pointer(0) , 0, 'ASN1_FBOOLEAN');
  result := @local_it;
end;


function ISSUING_DIST_POINT_it:PASN1_ITEM;
var
  local_it: TASN1_ITEM ;
begin
  local_it := get_ASN1_ITEM($1, 16, @ISSUING_DIST_POINT_seq_tt,
                            sizeof(ISSUING_DIST_POINT_seq_tt) div sizeof(TASN1_TEMPLATE),
                            Pointer(0) , sizeof(ISSUING_DIST_POINT),
                            'ISSUING_DIST_POINT');
  Result := @local_it;
end;


function d2i_ISSUING_DIST_POINT(a : PPISSUING_DIST_POINT;const _in : PPByte; len : long):PISSUING_DIST_POINT;
begin
  Result := PISSUING_DIST_POINT(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, ISSUING_DIST_POINT_it));
end;


function i2d_ISSUING_DIST_POINT(const a : PISSUING_DIST_POINT; _out : PPByte):integer;
begin
  Result := ASN1_item_i2d(PASN1_VALUE(a), _out, ISSUING_DIST_POINT_it);
end;


function ISSUING_DIST_POINT_new:PISSUING_DIST_POINT;
begin
  Result := PISSUING_DIST_POINT(ASN1_item_new(ISSUING_DIST_POINT_it));
end;


procedure ISSUING_DIST_POINT_free( a : PISSUING_DIST_POINT);
begin
  ASN1_item_free(PASN1_VALUE( a), ISSUING_DIST_POINT_it);
end;

function DIST_POINT_it:PASN1_ITEM;
var
  local_it: TASN1_ITEM ;
begin
  local_it := get_ASN1_ITEM($1, 16, @DIST_POINT_seq_tt,
                sizeof(DIST_POINT_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                sizeof(TDIST_POINT), 'DIST_POINT');
  result := @local_it;
end;

function d2i_DIST_POINT(a : PPDIST_POINT;const _in : PPByte; len : long):PDIST_POINT;
begin
  Result := PDIST_POINT(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, DIST_POINT_it));
end;


function i2d_DIST_POINT(const a : PDIST_POINT; _out : PPByte):integer;
begin
  Result := ASN1_item_i2d(PASN1_VALUE(a), _out, DIST_POINT_it);
end;


function DIST_POINT_new:PDIST_POINT;
begin
  Result := PDIST_POINT(ASN1_item_new(DIST_POINT_it));
end;


procedure DIST_POINT_free( a : PDIST_POINT);
begin
 ASN1_item_free(PASN1_VALUE( a), DIST_POINT_it);
end;



function DIST_POINT_NAME_it:PASN1_ITEM;
var
  local_it: TASN1_ITEM ;
begin
  local_it := get_ASN1_ITEM($2, size_t(@PDIST_POINT_NAME(0).&type) ,
                            @DIST_POINT_NAME_ch_tt,
                            sizeof(DIST_POINT_NAME_ch_tt) div sizeof(TASN1_TEMPLATE),
                            @DIST_POINT_NAME_aux, sizeof(DIST_POINT_NAME),
                            'DIST_POINT_NAME');

  Result := @local_it;
end;




function d2i_DIST_POINT_NAME(a : PPDIST_POINT_NAME;const _in : PPByte; len : long):PDIST_POINT_NAME;
begin
  Result := PDIST_POINT_NAME(ASN1_item_d2i(PPASN1_VALUE(a), _in, len, DIST_POINT_NAME_it));
end;


function i2d_DIST_POINT_NAME(const a : PDIST_POINT_NAME; _out : PPByte):integer;
begin
  Result := ASN1_item_i2d(PASN1_VALUE( a), _out, DIST_POINT_NAME_it);
end;


function DIST_POINT_NAME_new:PDIST_POINT_NAME;
begin
  Result := PDIST_POINT_NAME( ASN1_item_new(DIST_POINT_NAME_it));
end;


procedure DIST_POINT_NAME_free( a : PDIST_POINT_NAME);
begin
  ASN1_item_free(PASN1_VALUE(a), DIST_POINT_NAME_it);
end;

function gnames_from_sectname( ctx : PX509V3_CTX; sect : PUTF8Char):Pstack_st_GENERAL_NAME;
var
  gnsect : Pstack_st_CONF_VALUE;
  gens : Pstack_st_GENERAL_NAME;
begin
    if sect^ = '@' then
       gnsect := X509V3_get_section(ctx, sect + 1)
    else
       gnsect := X509V3_parse_list(sect);

    if nil = gnsect then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_SECTION_NOT_FOUND);
        Exit(nil);
    end;
    gens := v2i_GENERAL_NAMES(nil, ctx, gnsect);
    if sect^ = '@' then
       X509V3_section_free(ctx, gnsect)
    else
        sk_CONF_VALUE_pop_free(gnsect, X509V3_conf_free);
    Result := gens;
end;


function set_dist_point_name( pdp : PPDIST_POINT_NAME; ctx : PX509V3_CTX; cnf : PCONF_VALUE):integer;
var
  fnm : Pstack_st_GENERAL_NAME;
  rnm : Pstack_st_X509_NAME_ENTRY;
  ret : integer;
  dnsect : Pstack_st_CONF_VALUE;
  nm : PX509_NAME;
  label _err;
begin
    fnm := nil;
    rnm := nil;
    if HAS_PREFIX(cnf.name, 'fullname') then
    begin
        fnm := gnames_from_sectname(ctx, cnf.value);
        if nil = fnm then
           goto _err ;
    end
    else
    if (strcmp(cnf.name, 'relativename') = 0) then
    begin
        nm := X509_NAME_new();
        if nm = nil then
           Exit(-1);
        dnsect := X509V3_get_section(ctx, cnf.value);
        if nil = dnsect then
        begin
            X509_NAME_free(nm);
            ERR_raise(ERR_LIB_X509V3, X509V3_R_SECTION_NOT_FOUND);
            Exit(-1);
        end;
        ret := X509V3_NAME_from_section(nm, dnsect, MBSTRING_ASC);
        X509V3_section_free(ctx, dnsect);
        rnm := nm.entries;
        nm.entries := nil;
        X509_NAME_free(nm);
        if (0>= ret)  or  (sk_X509_NAME_ENTRY_num(rnm) <= 0) then
            goto _err ;
        {
         * Since its a name fragment can't have more than one RDNSequence
         }
        if sk_X509_NAME_ENTRY_value(rnm,
                                     sk_X509_NAME_ENTRY_num(rnm) - 1)._set > 0  then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_MULTIPLE_RDNS);
            goto _err ;
        end;
    end
    else
        Exit(0);
    if pdp^ <> nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_DISTPOINT_ALREADY_SET);
        goto _err ;
    end;
    pdp^ := DIST_POINT_NAME_new();
    if pdp^ = nil then
       goto _err ;
    if fnm <> nil then
    begin
        (pdp^).&type := 0;
        (pdp^).name.fullname := fnm;
    end
    else
    begin
        (pdp^).&type := 1;
        (pdp^).name.relativename := rnm;
    end;
    Exit(1);
 _err:
    sk_GENERAL_NAME_pop_free(fnm, GENERAL_NAME_free);
    sk_X509_NAME_ENTRY_pop_free(rnm, X509_NAME_ENTRY_free);
    Result := -1;
end;


function set_reasons( preas : PPASN1_BIT_STRING; value : PUTF8Char):integer;
var
  rsk : Pstack_st_CONF_VALUE;
  pbn : PBIT_STRING_BITNAME;
  bnam : PUTF8Char;
  i, ret : integer;
  label _err;
begin
    rsk := nil;
    ret := 0;
    rsk := X509V3_parse_list(value);
    if rsk = nil then
       Exit(0);
    if preas^ <> nil then
       goto _err ;
    for i := 0 to sk_CONF_VALUE_num(rsk)-1 do
    begin
        bnam := sk_CONF_VALUE_value(rsk, i).name;
        if preas^ = nil then
        begin
            preas^ := ASN1_BIT_STRING_new();
            if preas^ = nil then
               goto _err ;
        end;
        pbn := @reason_flags;
        while pbn.lname <> nil do
        begin
            if strcmp(pbn.sname, bnam) = 0  then
            begin
                if 0>= ASN1_BIT_STRING_set_bit(preas^, pbn.bitnum, 1) then
                    goto _err ;
                break;
            end;
            Inc(pbn);
        end;
        if pbn.lname = nil then
           goto _err ;
    end;
    ret := 1;
 _err:
    sk_CONF_VALUE_pop_free(rsk, X509V3_conf_free);
    Result := ret;
end;


function print_reasons(_out : PBIO;const rname : PUTF8Char; rflags : PASN1_BIT_STRING; indent : integer):integer;
var
  first : integer;
  pbn : PBIT_STRING_BITNAME;
begin
    first := 1;
    BIO_printf(_out, '%*s%s:#10%*s', [indent, '', rname, indent + 2, '']);
    pbn := @reason_flags;
    while pbn.lname <> nil do
    begin
        if ASN1_BIT_STRING_get_bit(rflags, pbn.bitnum) > 0 then
        begin
            if first > 0 then
               first := 0
            else
               BIO_puts(_out, ', ');
            BIO_puts(_out, pbn.lname);
        end;
        Inc(pbn);
    end;
    if first >0 then
       BIO_puts(_out, '<EMPTY>'#10)
    else
       BIO_puts(_out, #10);
    Result := 1;
end;


function crldp_from_section( ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PDIST_POINT;
var
  i : integer;
  cnf : PCONF_VALUE;
  point : PDIST_POINT;
  ret : integer;
  label _err;
begin
    point := DIST_POINT_new();
    if point = nil then
       goto _err ;
    for i := 0 to sk_CONF_VALUE_num(nval)-1 do
    begin
        cnf := sk_CONF_VALUE_value(nval, i);
        ret := set_dist_point_name(@point.distpoint, ctx, cnf);
        if ret > 0 then continue;
        if ret < 0 then goto _err ;
        if strcmp(cnf.name, 'reasons') = 0  then
        begin
            if 0>= set_reasons(@point.reasons, cnf.value) then
                goto _err ;
        end
        else
        if (strcmp(cnf.name, 'CRLissuer') = 0) then
        begin
            point.CRLissuer := gnames_from_sectname(ctx, cnf.value);
            if point.CRLissuer = nil then
               goto _err ;
        end;
    end;
    Exit(point);
 _err:
    DIST_POINT_free(point);
    Result := nil;
end;


function v2i_crld(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
var
  crld : Pstack_st_DIST_POINT;
  gens : PGENERAL_NAMES;
  gen : PGENERAL_NAME;
  cnf : PCONF_VALUE;
  i, num : integer;
  point : PDIST_POINT;
  dpsect : Pstack_st_CONF_VALUE;
  label _merr, _err;
begin
    gens := nil;
    gen := nil;
    num := sk_CONF_VALUE_num(nval);
    crld := sk_DIST_POINT_new_reserve(nil, num);
    if crld = nil then
       goto _merr ;
    for i := 0 to num-1 do
    begin
        cnf := sk_CONF_VALUE_value(nval, i);
        if cnf.value = nil then
        begin
            dpsect := X509V3_get_section(ctx, cnf.name);
            if nil = dpsect then
               goto _err ;
            point := crldp_from_section(ctx, dpsect);
            X509V3_section_free(ctx, dpsect);
            if point = nil then
               goto _err ;
            sk_DIST_POINT_push(crld, point); { no failure as it was reserved }
        end
        else
        begin
            gen := v2i_GENERAL_NAME(method, ctx, cnf);
            if gen = nil then
                goto _err ;
            gens := GENERAL_NAMES_new();
            if gens = nil then
                goto _merr ;
            if 0>= sk_GENERAL_NAME_push(gens, gen) then
                goto _merr ;
            gen := nil;
            point := DIST_POINT_new();
            if point = nil then
                goto _merr ;
            sk_DIST_POINT_push(crld, point); { no failure as it was reserved }
            point.distpoint := DIST_POINT_NAME_new();
            if point.distpoint = nil then
                goto _merr ;
            point.distpoint.name.fullname := gens;
            point.distpoint.&type := 0;
            gens := nil;
        end;
    end;
    Exit(crld);
 _merr:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
 _err:
    GENERAL_NAME_free(gen);
    GENERAL_NAMES_free(gens);
    sk_DIST_POINT_pop_free(crld, DIST_POINT_free);
    Result := nil;
end;


function dpn_cb(operation : integer; pval : PPASN1_VALUE;const it : PASN1_ITEM; exarg : Pointer):integer;
var
  dpn : PDIST_POINT_NAME;
begin
    dpn := PDIST_POINT_NAME( pval^);
    case operation of
    ASN1_OP_NEW_POST:
        dpn.dpname := nil;
        //break;
    ASN1_OP_FREE_POST:
        X509_NAME_free(dpn.dpname);
        //break;
    end;
    Result := 1;
end;


function v2i_idp(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):Pointer;
var
  idp : PISSUING_DIST_POINT;
  cnf : PCONF_VALUE;
  name, val : PUTF8Char;
  i, ret : integer;
  label _merr, _err;
begin
    idp := nil;
    idp := ISSUING_DIST_POINT_new();
    if idp = nil then
       goto _merr ;
    for i := 0 to sk_CONF_VALUE_num(nval)-1 do
    begin
        cnf := sk_CONF_VALUE_value(nval, i);
        name := cnf.name;
        val := cnf.value;
        ret := set_dist_point_name(@idp.distpoint, ctx, cnf);
        if ret > 0 then continue;
        if ret < 0 then goto _err ;
        if strcmp(name, 'onlyuser') = 0  then
        begin
            if 0>= X509V3_get_value_bool(cnf, @idp.onlyuser) then
                goto _err ;
        end
        else
        if (strcmp(name, 'onlyCA') = 0) then
        begin
            if 0>= X509V3_get_value_bool(cnf, @idp.onlyCA) then
               goto _err ;
        end
        else
        if (strcmp(name, 'onlyAA') = 0) then
        begin
            if 0>= X509V3_get_value_bool(cnf, @idp.onlyattr) then
               goto _err ;
        end
        else
        if (strcmp(name, 'indirectCRL') = 0) then
        begin
            if 0>= X509V3_get_value_bool(cnf, @idp.indirectCRL) then
               goto _err ;
        end
        else
        if (strcmp(name, 'onlysomereasons') = 0) then
        begin
            if 0>= set_reasons(@idp.onlysomereasons, val) then
               goto _err ;
        end
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NAME);
            X509V3_conf_add_error_name_value(cnf);
            goto _err ;
        end;
    end;
    Exit(idp);
 _merr:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
 _err:
    ISSUING_DIST_POINT_free(idp);
    Result := nil;
end;


function print_gens( _out : PBIO; gens : Pstack_st_GENERAL_NAME; indent : integer):integer;
var
  i : integer;
begin
    for i := 0 to sk_GENERAL_NAME_num(gens)-1 do
    begin
        if i > 0 then
           BIO_puts(_out, #10);
        BIO_printf(_out, '%*s', [indent + 2, '']);
        GENERAL_NAME_print(_out, sk_GENERAL_NAME_value(gens, i));
    end;
    Result := 1;
end;


function print_distpoint(_out : PBIO; dpn : PDIST_POINT_NAME; indent : integer):integer;
var
  ntmp : TX509_NAME;
begin
    if dpn.&type = 0 then
    begin
        BIO_printf(_out, '%*sFull Name:'#10, [indent, '']);
        print_gens(_out, dpn.name.fullname, indent);
    end
    else
    begin
        ntmp.entries := dpn.name.relativename;
        BIO_printf(_out, '%*sRelative Name:'#10'%*s', [indent, '', indent + 2, '']);
        X509_NAME_print_ex(_out, @ntmp, 0, XN_FLAG_ONELINE);
        BIO_puts(_out, #10);
    end;
    Result := 1;
end;


function i2r_idp(const method : PX509V3_EXT_METHOD; pidp : Pointer; _out : PBIO; indent : integer):integer;
var
  idp : PISSUING_DIST_POINT;
begin
    idp := pidp;
    if idp.distpoint <>nil then
       print_distpoint(_out, idp.distpoint, indent);
    if idp.onlyuser > 0 then
       BIO_printf(_out, '%*sOnly User Certificates'#10, [indent, '']);
    if idp.onlyCA > 0 then
       BIO_printf(_out, '%*sOnly CA Certificates'#10, [indent, '']);
    if idp.indirectCRL > 0 then
       BIO_printf(_out, '%*sIndirect CRL'#10, [indent, '']);
    if idp.onlysomereasons <> nil then
       print_reasons(_out, 'Only Some Reasons', idp.onlysomereasons, indent);
    if idp.onlyattr > 0 then
       BIO_printf(_out, '%*sOnly Attribute Certificates'#10, [indent, '']);
    if (nil = idp.distpoint)  and  (idp.onlyuser <= 0)  and  (idp.onlyCA <= 0)
         and  (idp.indirectCRL <= 0)  and  (nil = idp.onlysomereasons)
         and  (idp.onlyattr <= 0) then
        BIO_printf(_out, '%*s<EMPTY>'#10, [indent, '']);
    Result := 1;
end;


function i2r_crldp(const method : PX509V3_EXT_METHOD; pcrldp : Pointer; _out : PBIO; indent : integer):integer;
var
  crld : Pstack_st_DIST_POINT;
  point : PDIST_POINT;
  i : integer;
begin
    crld := pcrldp;
    for i := 0 to sk_DIST_POINT_num(crld)-1 do
    begin
        if i > 0 then
           BIO_puts(_out, #10);
        point := sk_DIST_POINT_value(crld, i);
        if point.distpoint <> nil then
           print_distpoint(_out, point.distpoint, indent);
        if point.reasons <> nil then
           print_reasons(_out, 'Reasons', point.reasons, indent);
        if point.CRLissuer <> nil then
        begin
            BIO_printf(_out, '%*sCRL Issuer:'#10, [indent, '']);
            print_gens(_out, point.CRLissuer, indent);
        end;
    end;
    Result := 1;
end;


function DIST_POINT_set_dpname(dpn : PDIST_POINT_NAME;const iname : PX509_NAME):integer;
var
  i : integer;
  frag : Pstack_st_X509_NAME_ENTRY;
  ne : PX509_NAME_ENTRY;

  label _err;
begin
    if (dpn = nil)  or  (dpn.&type <> 1) then
       Exit(1);
    frag := dpn.name.relativename;
    X509_NAME_free(dpn.dpname); { just in case it was already set }
    dpn.dpname := X509_NAME_dup(iname);
    if dpn.dpname = nil then Exit(0);
    for i := 0 to sk_X509_NAME_ENTRY_num(frag)-1 do
    begin
        ne := sk_X509_NAME_ENTRY_value(frag, i);
        if 0>= X509_NAME_add_entry(dpn.dpname, ne, -1,
               get_result(i>0 , 0 , 1)) then
            goto _err ;
    end;
    { generate cached encoding of name }
    if i2d_X509_NAME(dpn.dpname, nil) >= 0  then
        Exit(1);
 _err:
    X509_NAME_free(dpn.dpname);
    dpn.dpname := nil;
    Result := 0;
end;

initialization

   DIST_POINT_NAME_ch_tt[0] := get_ASN1_TEMPLATE( (($1  shl  3) or ($2 shl 6)) or ($2  shl  1), 0, size_t(@PDIST_POINT_NAME(0).name.fullname), 'name.fullname', GENERAL_NAME_it );
   DIST_POINT_NAME_ch_tt[1] := get_ASN1_TEMPLATE( (($1  shl  3) or ($2 shl 6)) or ($1  shl  1), 1, size_t(@PDIST_POINT_NAME(0).name.relativename), 'name.relativename', X509_NAME_ENTRY_it );

   DIST_POINT_seq_tt[0] := get_ASN1_TEMPLATE( (($2 shl 3) or ($2 shl 6))  or  $1, 0, size_t(@PDIST_POINT(0).distpoint), 'distpoint', DIST_POINT_NAME_it );
   DIST_POINT_seq_tt[1] := get_ASN1_TEMPLATE( (($1 shl 3) or ($2 shl 6))  or  $1, 1, size_t(@PDIST_POINT(0).reasons), 'reasons', ASN1_BIT_STRING_it );
   DIST_POINT_seq_tt[2] := get_ASN1_TEMPLATE( (($1 shl 3) or ($2 shl 6))  or  (($2 shl 1) or $1), 2, size_t(@PDIST_POINT(0).CRLissuer), 'CRLissuer', GENERAL_NAME_it );

   ISSUING_DIST_POINT_seq_tt[0] := get_ASN1_TEMPLATE((($2 shl 3) or ($2 shl 6))  or  $1, 0, size_t(@PISSUING_DIST_POINT(0).distpoint), 'distpoint', DIST_POINT_NAME_it );
   ISSUING_DIST_POINT_seq_tt[1] := get_ASN1_TEMPLATE((($1 shl 3) or ($2 shl 6))  or  $1, 1, size_t(@PISSUING_DIST_POINT(0).onlyuser), 'onlyuser', ASN1_FBOOLEAN_it );
   ISSUING_DIST_POINT_seq_tt[2] := get_ASN1_TEMPLATE((($1 shl 3) or ($2 shl 6))  or  $1, 2, size_t(@PISSUING_DIST_POINT(0).onlyCA), 'onlyCA', ASN1_FBOOLEAN_it );
   ISSUING_DIST_POINT_seq_tt[3] := get_ASN1_TEMPLATE((($1 shl 3) or ($2 shl 6))  or  $1, 3, size_t(@PISSUING_DIST_POINT(0).onlysomereasons), 'onlysomereasons', ASN1_BIT_STRING_it );
   ISSUING_DIST_POINT_seq_tt[4] := get_ASN1_TEMPLATE((($1 shl 3) or ($2 shl 6))  or  $1, 4, size_t(@PISSUING_DIST_POINT(0).indirectCRL), 'indirectCRL', ASN1_FBOOLEAN_it );
   ISSUING_DIST_POINT_seq_tt[5] := get_ASN1_TEMPLATE((($1 shl 3) or ($2 shl 6))  or  $1, 5, size_t(@PISSUING_DIST_POINT(0).onlyattr), 'onlyattr', ASN1_FBOOLEAN_it );

   CRL_DIST_POINTS_item_tt := get_ASN1_TEMPLATE( (($2 shl 1)), 0, 0, 'CRLDistributionPoints', DIST_POINT_it);

   ossl_v3_crld := get_V3_EXT_METHOD(
      NID_crl_distribution_points, 0, CRL_DIST_POINTS_it,
      nil, nil, nil, nil,
      nil, nil,
      nil,
      v2i_crld,
      i2r_crldp, nil,
      nil);

    ossl_v3_idp := get_V3_EXT_METHOD(
        NID_issuing_distribution_point, X509V3_EXT_MULTILINE,
        ISSUING_DIST_POINT_it,
        nil, nil, nil, nil,
        nil, nil,
        nil,
        v2i_idp,
        i2r_idp, nil,
        nil
    );

   ossl_v3_freshest_crl := get_V3_EXT_METHOD (
      NID_freshest_crl, 0, CRL_DIST_POINTS_it,
      nil, nil, nil, nil,
      nil, nil,
      nil,
      v2i_crld,
      i2r_crldp, nil,
      nil
   );
end.
