unit OpenSSL3.crypto.x509.v3_cpols;

interface
uses OpenSSL.Api, SysUtils;



 function CERTIFICATEPOLICIES_it:PASN1_ITEM;
 procedure print_notice( _out : PBIO; notice : PUSERNOTICE; indent : integer);

function i2r_certpol( method : PX509V3_EXT_METHOD; pol : Pstack_st_POLICYINFO; _out : PBIO; indent : integer):integer;
procedure print_qualifiers( _out : PBIO; quals: Pstack_st_POLICYQUALINFO; indent : integer);
 function r2i_certpol(method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const value : PUTF8Char):Pstack_st_POLICYINFO;
function policy_section( ctx : PX509V3_CTX; polstrs : Pstack_st_CONF_VALUE; ia5org : integer):PPOLICYINFO;
function d2i_POLICYINFO(a : PPPOLICYINFO;const _in : PPByte; len : long):PPOLICYINFO;
  function i2d_POLICYINFO(const a : PPOLICYINFO; _out : PPByte):integer;
  function POLICYINFO_new:PPOLICYINFO;
  procedure POLICYINFO_free( a : PPOLICYINFO);
  function POLICYINFO_it:PASN1_ITEM;
  function d2i_POLICYQUALINFO(a : PPPOLICYQUALINFO;const _in : PPByte; len : long):PPOLICYQUALINFO;
  function i2d_POLICYQUALINFO(const a : PPOLICYQUALINFO; _out : PPByte):integer;
  function POLICYQUALINFO_new:PPOLICYQUALINFO;
  procedure POLICYQUALINFO_free( a : PPOLICYQUALINFO);
  function POLICYQUALINFO_it:PASN1_ITEM;
  function notice_section( ctx : PX509V3_CTX; unot : Pstack_st_CONF_VALUE; ia5org : integer):PPOLICYQUALINFO;
  function d2i_USERNOTICE(a : PPUSERNOTICE;const _in : PPByte; len : long):PUSERNOTICE;
  function i2d_USERNOTICE(const a : PUSERNOTICE; _out : PPByte):integer;
  function USERNOTICE_new:PUSERNOTICE;
  procedure USERNOTICE_free( a : PUSERNOTICE);
  function USERNOTICE_it:PASN1_ITEM;
  function displaytext_str2tag(const tagstr : PUTF8Char; tag_len : Puint32):integer;
  function displaytext_get_tag_len(const tagstr : PUTF8Char):integer;
  function d2i_NOTICEREF(a : PPNOTICEREF;const _in : PPByte; len : long):PNOTICEREF;
  function i2d_NOTICEREF(const a : PNOTICEREF; _out : PPByte):integer;
  function NOTICEREF_new:PNOTICEREF;
  procedure NOTICEREF_free( a : PNOTICEREF);
  function NOTICEREF_it:PASN1_ITEM;
  function nref_nos( nnums : Pstack_st_ASN1_INTEGER; nos : Pstack_st_CONF_VALUE):integer;
  function POLICYQUALINFO_adb:PASN1_ITEM;

var
  CERTIFICATEPOLICIES_item_tt, policydefault_tt: TASN1_TEMPLATE;
  POLICYINFO_seq_tt, POLICYQUALINFO_seq_tt,
  USERNOTICE_seq_tt, NOTICEREF_seq_tt: array[0..1] of TASN1_TEMPLATE;
  ossl_v3_cpols: TX509V3_EXT_METHOD;
  POLICYQUALINFO_adbtbl: array[0..1] of TASN1_ADB_TABLE;

implementation
uses openssl3.crypto.x509v3, openssl3.crypto.bio.bio_lib,
     openssl3.crypto.objects.obj_dat, OpenSSL3.include.openssl.asn1,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.mem,
     OpenSSL3.common,
     openssl3.crypto.asn1.tasn_typ, openssl3.crypto.asn1.asn1_lib,
     OpenSSL3.openssl.conf,  OpenSSL3.Err,  openssl3.crypto.asn1.tasn_enc,
     OpenSSL3.crypto.x509.v3_conf, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
     openssl3.crypto.bio.bio_print, openssl3.crypto.asn1.a_object;





function POLICYQUALINFO_adb:PASN1_ITEM;
var
  internal_adb : TASN1_ADB;
begin
  internal_adb := get_ASN1_ADB (0, size_t(@PPOLICYQUALINFO(0). pqualid),
                                nil, @POLICYQUALINFO_adbtbl,
                                sizeof(POLICYQUALINFO_adbtbl) div sizeof(TASN1_ADB_TABLE),
                                @policydefault_tt, Pointer(0));

   Result := PASN1_ITEM(@internal_adb);
end;




function nref_nos( nnums : Pstack_st_ASN1_INTEGER; nos : Pstack_st_CONF_VALUE):integer;
var
  cnf : PCONF_VALUE;
  aint : PASN1_INTEGER;
  i : integer;
  label _merr, _err;
begin
    for i := 0 to sk_CONF_VALUE_num(nos)-1 do
    begin
        cnf := sk_CONF_VALUE_value(nos, i);
        aint := s2i_ASN1_INTEGER(nil, cnf.name);
        if aint = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NUMBER);
            goto _err ;
        end;
        if 0>= sk_ASN1_INTEGER_push(nnums, aint) then
            goto _merr ;
    end;
    Exit(1);
 _merr:
    ASN1_INTEGER_free(aint);
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
 _err:
    Result := 0;
end;





function NOTICEREF_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM ($1, 16, @NOTICEREF_seq_tt,
                    sizeof(NOTICEREF_seq_tt) div sizeof(TASN1_TEMPLATE),
                    Pointer(0) , sizeof(NOTICEREF), ' NOTICEREF');

   Result := @ local_it;
end;




function d2i_NOTICEREF(a : PPNOTICEREF;const _in : PPByte; len : long):PNOTICEREF;
begin
   Result :=  PNOTICEREF(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, NOTICEREF_it));
end;


function i2d_NOTICEREF(const a : PNOTICEREF; _out : PPByte):integer;
begin
   Result :=  ASN1_item_i2d(PASN1_VALUE(a), _out, NOTICEREF_it);
end;


function NOTICEREF_new:PNOTICEREF;
begin
   Result := PNOTICEREF(ASN1_item_new(NOTICEREF_it));
end;


procedure NOTICEREF_free( a : PNOTICEREF);
begin
   ASN1_item_free(PASN1_VALUE( a), NOTICEREF_it);
end;



function displaytext_get_tag_len(const tagstr : PUTF8Char):integer;
var
  colon : PUTF8Char;
begin
    colon := strchr(tagstr, ':');
    Result := get_result(colon = nil , -1 , colon - tagstr);
end;




function displaytext_str2tag(const tagstr : PUTF8Char; tag_len : Puint32):integer;
var
  len : integer;
begin
    tag_len^ := 0;
    len := displaytext_get_tag_len(tagstr);
    if len = -1 then
       Exit(V_ASN1_VISIBLESTRING);
    tag_len^ := len;
    if (len = sizeof('UTF8') - 1)  and  (HAS_PREFIX(tagstr, 'UTF8'))  then
        Exit(V_ASN1_UTF8STRING);
    if (len = sizeof('UTF8String') - 1)  and  (HAS_PREFIX(tagstr, 'UTF8String'))  then
        Exit(V_ASN1_UTF8STRING);
    if (len = sizeof('BMP' ) - 1)  and  (HAS_PREFIX(tagstr, 'BMP')) then
        Exit(V_ASN1_BMPSTRING);
    if (len = sizeof('BMPSTRING' ) - 1)  and  (HAS_PREFIX(tagstr, 'BMPSTRING'))  then
        Exit(V_ASN1_BMPSTRING);
    if (len = sizeof('VISIBLE' ) - 1)  and  (HAS_PREFIX(tagstr, 'VISIBLE')) then
        Exit(V_ASN1_VISIBLESTRING);
    if (len = sizeof('VISIBLESTRING') - 1)  and  (HAS_PREFIX(tagstr, 'VISIBLESTRING'))  then
        Exit(V_ASN1_VISIBLESTRING);
    tag_len^ := 0;
    Result := V_ASN1_VISIBLESTRING;
end;



function USERNOTICE_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @USERNOTICE_seq_tt,
                       sizeof(USERNOTICE_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                         sizeof(TUSERNOTICE), 'USERNOTICE');
  Result := @local_it;
end;




function d2i_USERNOTICE(a : PPUSERNOTICE;const _in : PPByte; len : long):PUSERNOTICE;
begin
   Result := PUSERNOTICE(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, USERNOTICE_it));
end;


function i2d_USERNOTICE(const a : PUSERNOTICE; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, USERNOTICE_it);
end;


function USERNOTICE_new:PUSERNOTICE;
begin
   Result := PUSERNOTICE(ASN1_item_new(USERNOTICE_it));
end;


procedure USERNOTICE_free( a : PUSERNOTICE);
begin
 ASN1_item_free(PASN1_VALUE( a), USERNOTICE_it);
end;




function notice_section( ctx : PX509V3_CTX; unot : Pstack_st_CONF_VALUE; ia5org : integer):PPOLICYQUALINFO;
var
  i, ret, len, tag : integer;
  tag_len : uint32;
  cnf : PCONF_VALUE;
  _not : PUSERNOTICE;
  qual : PPOLICYQUALINFO;
  value : PUTF8Char;
  nref : PNOTICEREF;
  nos : Pstack_st_CONF_VALUE;
  label _merr, _err;
begin
    value := nil;
    qual := POLICYQUALINFO_new();
    if qual = nil then
        goto _merr ;
    qual.pqualid := OBJ_nid2obj(NID_id_qt_unotice);
    if qual.pqualid = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
     _not := USERNOTICE_new();
    if _not =  nil then
        goto _merr ;
    qual.d.usernotice := _not;
    for i := 0 to sk_CONF_VALUE_num(unot)-1 do
    begin
        cnf := sk_CONF_VALUE_value(unot, i);
        value := cnf.value;
        if strcmp(cnf.name, 'explicitText') = 0  then
        begin
            tag := displaytext_str2tag(value, @tag_len);
            _not.exptext := ASN1_STRING_type_new(tag);
            if _not.exptext = nil then
                goto _merr ;
            if tag_len <> 0 then
               value  := value + (tag_len + 1);
            len := Length(value);
            if 0>= ASN1_STRING_set(_not.exptext, value, len) then
                goto _merr ;
        end
        else
        if (strcmp(cnf.name, 'organization') = 0) then
        begin
            if nil = _not.noticeref then
            begin
                nref := NOTICEREF_new();
                if (nref = nil) then
                    goto _merr ;
                _not.noticeref := nref;
            end
            else
                nref := _not.noticeref;
            if ia5org > 0 then
                nref.organization.&type := V_ASN1_IA5STRING
            else
                nref.organization.&type := V_ASN1_VISIBLESTRING;
            if 0>= ASN1_STRING_set(nref.organization, cnf.value,
                                 Length(cnf.value )) then
                goto _merr ;
        end
        else
        if (strcmp(cnf.name, 'noticeNumbers') = 0) then
        begin
            if nil = _not.noticeref then
            begin
                nref := NOTICEREF_new();
                if (nref = nil) then
                    goto _merr ;
                _not.noticeref := nref;
            end
            else
                nref := _not.noticeref;
            nos := X509V3_parse_list(cnf.value);
            if (nil = nos)  or  (0>= sk_CONF_VALUE_num(nos)) then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NUMBERS);
                X509V3_conf_add_error_name_value(cnf);
                sk_CONF_VALUE_pop_free(nos, X509V3_conf_free);
                goto _err ;
            end;
            ret := nref_nos(nref.noticenos, nos);
            sk_CONF_VALUE_pop_free(nos, X509V3_conf_free);
            if 0>= ret then goto _err ;
        end
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OPTION);
            X509V3_conf_add_error_name_value(cnf);
            goto _err ;
        end;
    end;
    if (_not.noticeref <> nil)  and
        (nil = _not.noticeref.noticenos)  or  (nil = _not.noticeref.organization ) then
        begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_NEED_ORGANIZATION_AND_NUMBERS);
        goto _err ;
    end;
    Exit(qual);
 _merr:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
 _err:
    POLICYQUALINFO_free(qual);
    Result := nil;
end;



function POLICYQUALINFO_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @POLICYQUALINFO_seq_tt,
                        sizeof(POLICYQUALINFO_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                        sizeof(POLICYQUALINFO), 'POLICYQUALINFO');

  Result := @local_it;
end;

function d2i_POLICYQUALINFO(a : PPPOLICYQUALINFO;const _in : PPByte; len : long):PPOLICYQUALINFO;
begin
   Result := PPOLICYQUALINFO(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, POLICYQUALINFO_it));
end;


function i2d_POLICYQUALINFO(const a : PPOLICYQUALINFO; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, POLICYQUALINFO_it);
end;


function POLICYQUALINFO_new:PPOLICYQUALINFO;
begin
   Result := PPOLICYQUALINFO(ASN1_item_new(POLICYQUALINFO_it));
end;


procedure POLICYQUALINFO_free( a : PPOLICYQUALINFO);
begin
 ASN1_item_free(PASN1_VALUE( a), POLICYQUALINFO_it);
end;

procedure X509V3_conf_err(val: PCONF_VALUE);
begin
   ERR_add_error_data(6, ['section:', (val).section,
                        ',name:', (val).name, ',value:', (val).value])
end;



function POLICYINFO_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM (  $1, 16, @POLICYINFO_seq_tt,
                sizeof(POLICYINFO_seq_tt) div sizeof(TASN1_TEMPLATE), Pointer(0) ,
                sizeof(POLICYINFO), 'POLICYINFO');

  Result := @local_it;
end;



function d2i_POLICYINFO(a : PPPOLICYINFO;const _in : PPByte; len : long):PPOLICYINFO;
begin
   Result := PPOLICYINFO(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, POLICYINFO_it));
end;


function i2d_POLICYINFO(const a : PPOLICYINFO; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, POLICYINFO_it);
end;


function POLICYINFO_new:PPOLICYINFO;
begin
   Result := PPOLICYINFO(ASN1_item_new(POLICYINFO_it));
end;


procedure POLICYINFO_free( a : PPOLICYINFO);
begin
  ASN1_item_free(PASN1_VALUE( a), POLICYINFO_it);
end;




function policy_section( ctx : PX509V3_CTX; polstrs : Pstack_st_CONF_VALUE; ia5org : integer):PPOLICYINFO;
var
  i : integer;
  cnf : PCONF_VALUE;
  pol : PPOLICYINFO;
  qual : PPOLICYQUALINFO;
  pobj : PASN1_OBJECT;
  unot : Pstack_st_CONF_VALUE;
  label _merr,_err;
begin
    pol := POLICYINFO_new();
    if pol = nil then
        goto _merr ;
    for i := 0 to sk_CONF_VALUE_num(polstrs)-1 do
    begin
        cnf := sk_CONF_VALUE_value(polstrs, i);
        if strcmp(cnf.name, 'policyIdentifier') = 0  then
        begin
            pobj := OBJ_txt2obj(cnf.value, 0);
            if (pobj  = nil) then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER);
                X509V3_conf_err(cnf);
                goto _err ;
            end;
            pol.policyid := pobj;
        end
        else
        if (0>= ossl_v3_name_cmp(cnf.name, 'CPS')) then
        begin
            if pol.qualifiers = nil then
               pol.qualifiers := sk_POLICYQUALINFO_new_null();
            qual := POLICYQUALINFO_new();
            if qual = nil then
                goto _merr ;
            if 0>= sk_POLICYQUALINFO_push(pol.qualifiers, qual) then
                goto _merr ;
            qual.pqualid := OBJ_nid2obj(NID_id_qt_cps);
            if qual.pqualid = nil then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_INTERNAL_ERROR);
                goto _err ;
            end;
            qual.d.cpsuri := ASN1_IA5STRING_new();
            if qual.d.cpsuri = nil then
                goto _merr ;
            if 0>= ASN1_STRING_set(PASN1_STRING(qual.d.cpsuri), cnf.value,
                                 Length(cnf.value )) then
                goto _merr ;
        end
        else
        if (0>= ossl_v3_name_cmp(cnf.name, 'userNotice')) then
        begin
            if cnf.value^ <> '@' then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_EXPECTED_A_SECTION_NAME);
                X509V3_conf_err(cnf);
                goto _err ;
            end;
            unot := X509V3_get_section(ctx, cnf.value + 1);
            if nil = unot then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_SECTION);
                X509V3_conf_err(cnf);
                goto _err ;
            end;
            qual := notice_section(ctx, unot, ia5org);
            X509V3_section_free(ctx, unot);
            if nil = qual then
               goto _err ;
            if pol.qualifiers = nil then
               pol.qualifiers := sk_POLICYQUALINFO_new_null();
            if 0>= sk_POLICYQUALINFO_push(pol.qualifiers, qual) then
                goto _merr ;
        end
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OPTION);
            X509V3_conf_err(cnf);
            goto _err ;
        end;
    end;
    if pol.policyid = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_NO_POLICY_IDENTIFIER);
        goto _err ;
    end;
    Exit(pol);
 _merr:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
 _err:
    POLICYINFO_free(pol);
    Result := nil;
end;




function r2i_certpol(method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX;const value : PUTF8Char):Pstack_st_POLICYINFO;
var
  pols : Pstack_st_POLICYINFO;
  pstr : PUTF8Char;
  pol : PPOLICYINFO;
  pobj : PASN1_OBJECT;
  vals : Pstack_st_CONF_VALUE;
  cnf : PCONF_VALUE;
  num, i, ia5org : integer;
  polsect : Pstack_st_CONF_VALUE;
  label _err;
begin
    vals := X509V3_parse_list(value);
    num := sk_CONF_VALUE_num(vals);
    if vals = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_X509V3_LIB);
        Exit(nil);
    end;
    pols := sk_POLICYINFO_new_reserve(nil, num);
    if pols = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    ia5org := 0;
    for i := 0 to num-1 do
    begin
        cnf := sk_CONF_VALUE_value(vals, i);
        if (cnf.value <> nil)  or  (cnf.name = nil) then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_POLICY_IDENTIFIER);
            X509V3_conf_add_error_name_value(cnf);
            goto _err ;
        end;
        pstr := cnf.name;
        if strcmp(pstr, 'ia5org') = 0  then
        begin
            ia5org := 1;
            continue;
        end
        else
        if ( pstr^ = '@') then
        begin
            polsect := X509V3_get_section(ctx, pstr + 1);
            if polsect = nil then
            begin
                ERR_raise_data(ERR_LIB_X509V3, X509V3_R_INVALID_SECTION,
                              Format('%s', [cnf.name]));
                goto _err ;
            end;
            pol := policy_section(ctx, polsect, ia5org);
            X509V3_section_free(ctx, polsect);
            if pol = nil then
               goto _err ;
        end
        else
        begin
            pobj := OBJ_txt2obj(cnf.name, 0);
            if pobj = nil then
            begin
                ERR_raise_data(ERR_LIB_X509V3,
                               X509V3_R_INVALID_OBJECT_IDENTIFIER,
                              Format( '%s', [cnf.name]));
                goto _err ;
            end;
            pol := POLICYINFO_new();
            if pol = nil then
            begin
                ASN1_OBJECT_free(pobj);
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto _err ;
            end;
            pol.policyid := pobj;
        end;
        if 0>= sk_POLICYINFO_push(pols, pol) then
        begin
            POLICYINFO_free(pol);
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    Exit(pols);
 _err:
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    sk_POLICYINFO_pop_free(pols, POLICYINFO_free);
    Result := nil;
end;



procedure print_notice( _out : PBIO; notice : PUSERNOTICE; indent : integer);
var
  i : integer;

  ref : PNOTICEREF;

  num : PASN1_INTEGER;

  tmp : PUTF8Char;
begin
    if notice.noticeref <> nil then
    begin
        ref := notice.noticeref;
        BIO_printf(_out, '%*sOrganization: %.*s'#10, [indent, '',
                   ref.organization.length,
                   ref.organization.data]);
        BIO_printf(_out, '%*sNumber%s: ', [indent, '',
                 get_result(sk_ASN1_INTEGER_num(ref.noticenos) > 1 , 's' , '')]);
        for i := 0 to sk_ASN1_INTEGER_num(ref.noticenos)-1 do
        begin
            num := sk_ASN1_INTEGER_value(ref.noticenos, i);
            if i > 0 then
               BIO_puts(_out, ', ');
            if num = nil then
               BIO_puts(_out, '(null)')
            else
            begin
                tmp := i2s_ASN1_INTEGER(nil, num);
                if tmp = nil then Exit;
                BIO_puts(_out, tmp);
                OPENSSL_free(tmp);
            end;
        end;
        if notice.exptext <> nil then
           BIO_puts(_out, #10);
    end;
    if notice.exptext <> nil then
       BIO_printf(_out, '%*sExplicit Text: %.*s', [indent, '',
                   notice.exptext.length,
                   notice.exptext.data]);
end;





procedure print_qualifiers( _out : PBIO; quals: Pstack_st_POLICYQUALINFO; indent : integer);
var
    qualinfo : PPOLICYQUALINFO;
    i        : integer;
begin
    for i := 0 to sk_POLICYQUALINFO_num(quals)-1 do
    begin
        if i > 0 then
           BIO_puts(_out, #10);
        qualinfo := sk_POLICYQUALINFO_value(quals, i);
        case (OBJ_obj2nid(qualinfo.pqualid)) of
            NID_id_qt_cps:
                BIO_printf(_out, '%*sCPS: %.*s', [indent, '',
                           qualinfo.d.cpsuri.length,
                           qualinfo.d.cpsuri.data]);
                //break;
            NID_id_qt_unotice:
            begin
                BIO_printf(_out, '%*sUser Notice:'#10, [indent, '']);
                print_notice(_out, qualinfo.d.usernotice, indent + 2);
            end;
            else
            begin
                BIO_printf(_out, '%*sUnknown Qualifier: ', [indent + 2, '']);
                i2a_ASN1_OBJECT(_out, qualinfo.pqualid);
            end;
        end;
    end;
end;

function i2r_certpol( method : PX509V3_EXT_METHOD; pol : Pstack_st_POLICYINFO; _out : PBIO; indent : integer):integer;
var
  i : integer;

  pinfo : PPOLICYINFO;
begin
    { First print out the policy OIDs }
    for i := 0 to sk_POLICYINFO_num(pol)-1 do
    begin
        if i > 0 then
           BIO_puts(_out, #10);
        pinfo := sk_POLICYINFO_value(pol, i);
        BIO_printf(_out, '%*sPolicy: ', [indent, '']);
        i2a_ASN1_OBJECT(_out, pinfo.policyid);
        if pinfo.qualifiers <> nil then
        begin
            BIO_puts(_out, #10);
            print_qualifiers(_out, pinfo.qualifiers, indent + 2);
        end;
    end;
    Result := 1;
end;



function CERTIFICATEPOLICIES_it:PASN1_ITEM;
var
   local_it :TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($0, -1, @CERTIFICATEPOLICIES_item_tt, 0,
                            Pointer(0) , 0, 'CERTIFICATEPOLICIES');

   Result := @local_it;
end;


initialization
   ossl_v3_cpols := get_V3_EXT_METHOD (
    NID_certificate_policies, 0, CERTIFICATEPOLICIES_it,
    nil, nil, nil, nil,
    nil, nil,
    nil, nil,
    PX509V3_EXT_I2R(@i2r_certpol)^,
    PX509V3_EXT_R2I(@r2i_certpol)^,
    nil  );
   CERTIFICATEPOLICIES_item_tt := get_ASN1_TEMPLATE
        ( (($2 shl 1)), (0), 0, 'CERTIFICATEPOLICIES', POLICYINFO_it );

   POLICYINFO_seq_tt[0] := get_ASN1_TEMPLATE( (0), (0), size_t(@PPOLICYINFO(0).policyid), 'policyid', ASN1_OBJECT_it );
   POLICYINFO_seq_tt[1] := get_ASN1_TEMPLATE( (($2 shl 1) or ($1)), (0), size_t(@PPOLICYINFO(0).qualifiers), 'qualifiers', POLICYQUALINFO_it);

   POLICYQUALINFO_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, size_t(@PPOLICYQUALINFO(0).pqualid), 'pqualid', ASN1_OBJECT_it);
   POLICYQUALINFO_seq_tt[1] := get_ASN1_TEMPLATE( ($1 shl 8), -1, 0, 'POLICYQUALINFO', POLICYQUALINFO_adb );

   USERNOTICE_seq_tt[0] := get_ASN1_TEMPLATE($1, 0, size_t(@PUSERNOTICE(0).noticeref), 'noticeref', NOTICEREF_it);
   USERNOTICE_seq_tt[1] := get_ASN1_TEMPLATE($1, 0, size_t(@PUSERNOTICE(0).exptext), 'exptext', DISPLAYTEXT_it);


   NOTICEREF_seq_tt[0] := get_ASN1_TEMPLATE( 0, 0, size_t(@PNOTICEREF(0).organization), ' organization' , DISPLAYTEXT_it);
   NOTICEREF_seq_tt[1] := get_ASN1_TEMPLATE( ($2 shl  1), 0, size_t(@PNOTICEREF(0).noticenos), ' noticenos' , ASN1_INTEGER_it) ;

   POLICYQUALINFO_adbtbl[0] := get_ASN1_ADB_TABLE(164, get_ASN1_TEMPLATE(0, 0, size_t(@PPOLICYQUALINFO(0). d.cpsuri), ' d.cpsuri' , ASN1_IA5STRING_it));
   POLICYQUALINFO_adbtbl[1] := get_ASN1_ADB_TABLE(165, get_ASN1_TEMPLATE(0, 0, size_t(@PPOLICYQUALINFO(0). d.usernotice), ' d.usernotice' , USERNOTICE_it));

   policydefault_tt := get_ASN1_TEMPLATE ( 0,  0,
                         size_t(@PPOLICYQUALINFO(0). d.other), ' d.other' , ASN1_ANY_it);


end.
