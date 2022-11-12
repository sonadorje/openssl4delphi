unit OpenSSL3.crypto.x509.v3_info;

interface
uses OpenSSL.Api, SysUtils;


function AUTHORITY_INFO_ACCESS_it:PASN1_ITEM;
function i2v_AUTHORITY_INFO_ACCESS( method : PX509V3_EXT_METHOD; ainfo : PAUTHORITY_INFO_ACCESS; ret : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
function v2i_AUTHORITY_INFO_ACCESS( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PAUTHORITY_INFO_ACCESS;
function d2i_ACCESS_DESCRIPTION(a : PPACCESS_DESCRIPTION;const _in : PPByte; len : long):PACCESS_DESCRIPTION;
  function i2d_ACCESS_DESCRIPTION(const a : PACCESS_DESCRIPTION; _out : PPByte):integer;
  function ACCESS_DESCRIPTION_new:PACCESS_DESCRIPTION;
  procedure ACCESS_DESCRIPTION_free( a : PACCESS_DESCRIPTION);
  function ACCESS_DESCRIPTION_it:PASN1_ITEM;

var
  ossl_v3_info, ossl_v3_sinfo :TX509V3_EXT_METHOD;
  AUTHORITY_INFO_ACCESS_item_tt :TASN1_TEMPLATE ;
  ACCESS_DESCRIPTION_seq_tt: array of TASN1_TEMPLATE;




implementation
uses OpenSSL3.openssl.conf, openssl3.crypto.x509v3, openssl3.crypto.mem,
     OpenSSL3.crypto.x509.v3_san, openssl3.crypto.asn1.a_object,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.o_str,
     openssl3.crypto.x509.v3_genn,
     openssl3.crypto.objects.obj_dat,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.bio.bio_print, OpenSSL3.Err;


function ACCESS_DESCRIPTION_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @ACCESS_DESCRIPTION_seq_tt,
                        sizeof(ACCESS_DESCRIPTION_seq_tt) div sizeof(TASN1_TEMPLATE),
                        Pointer(0) , sizeof(ACCESS_DESCRIPTION), ' ACCESS_DESCRIPTION');

  Result := @local_it;
end;




function d2i_ACCESS_DESCRIPTION(a : PPACCESS_DESCRIPTION;const _in : PPByte; len : long):PACCESS_DESCRIPTION;
begin
   Result := PACCESS_DESCRIPTION( ASN1_item_d2i(PPASN1_VALUE( a), _in, len, ACCESS_DESCRIPTION_it));
end;


function i2d_ACCESS_DESCRIPTION(const a : PACCESS_DESCRIPTION; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE( a), _out, ACCESS_DESCRIPTION_it);
end;


function ACCESS_DESCRIPTION_new:PACCESS_DESCRIPTION;
begin
   Result := PACCESS_DESCRIPTION(ASN1_item_new(ACCESS_DESCRIPTION_it));
end;


procedure ACCESS_DESCRIPTION_free( a : PACCESS_DESCRIPTION);
begin
   ASN1_item_free(PASN1_VALUE( a), ACCESS_DESCRIPTION_it);
end;




function v2i_AUTHORITY_INFO_ACCESS( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PAUTHORITY_INFO_ACCESS;
var
  ainfo : PAUTHORITY_INFO_ACCESS;
  cnf, ctmp : PCONF_VALUE;
  acc : PACCESS_DESCRIPTION;
  i, num : integer;
  objtmp, ptmp : PUTF8Char;
  label _err;
begin
    ainfo := nil;
    num := sk_CONF_VALUE_num(nval);
    ainfo := sk_ACCESS_DESCRIPTION_new_reserve(nil, num);
    if ainfo = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    for i := 0 to num-1 do
    begin
        cnf := sk_CONF_VALUE_value(nval, i);
        acc := ACCESS_DESCRIPTION_new() ;
        if acc = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        sk_ACCESS_DESCRIPTION_push(ainfo, acc); { Cannot fail due to reserve }
        ptmp := strchr(cnf.name, ';');
        if ptmp = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_SYNTAX);
            goto _err ;
        end;
        ctmp.name := ptmp + 1;
        ctmp.value := cnf.value;
        if nil = v2i_GENERAL_NAME_ex(acc.location, method, ctx, @ctmp, 0 ) then
            goto _err ;
        OPENSSL_strndup(objtmp, cnf.name, ptmp - cnf.name);
        if objtmp  = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        acc.method := OBJ_txt2obj(objtmp, 0);
        if nil = acc.method then
        begin
            ERR_raise_data(ERR_LIB_X509V3, X509V3_R_BAD_OBJECT,
                          Format(' value=%s' , [objtmp]));
            OPENSSL_free(objtmp);
            goto _err ;
        end;
        OPENSSL_free(objtmp);
    end;
    Exit(ainfo);
 _err:
    sk_ACCESS_DESCRIPTION_pop_free(ainfo, ACCESS_DESCRIPTION_free);
    Result := nil;
end;

function i2v_AUTHORITY_INFO_ACCESS( method : PX509V3_EXT_METHOD; ainfo : PAUTHORITY_INFO_ACCESS; ret : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
  desc : PACCESS_DESCRIPTION;
  i, nlen : integer;
  objtmp : array[0..79] of UTF8Char;
  ntmp : PUTF8Char;
  vtmp : PCONF_VALUE;
  tret, tmp : Pstack_st_CONF_VALUE;
  label _err;
begin
    tret := ret;
    for i := 0 to sk_ACCESS_DESCRIPTION_num(ainfo)-1 do
    begin
        desc := sk_ACCESS_DESCRIPTION_value(ainfo, i);
        tmp := i2v_GENERAL_NAME(method, desc.location, tret);
        if tmp = nil then
           goto _err ;
        tret := tmp;
        vtmp := sk_CONF_VALUE_value(tret, i);
        i2t_ASN1_OBJECT(objtmp, sizeof(objtmp), desc.method);
        nlen := strlen(objtmp) + 3 + strlen(vtmp.name) + 1;
        ntmp := OPENSSL_malloc(nlen);
        if ntmp = nil then
           goto _err ;
        BIO_snprintf(ntmp, nlen, ' %s - %s' , [objtmp, vtmp.name]);
        OPENSSL_free(vtmp.name);
        vtmp.name := ntmp;
    end;
    if (ret = nil)  and  (tret = nil) then
       Exit(sk_CONF_VALUE_new_null());
    Exit(tret);
 _err:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    if (ret = nil)  and  (tret <> nil) then
        sk_CONF_VALUE_pop_free(tret, X509V3_conf_free);
    Result := nil;
end;




function AUTHORITY_INFO_ACCESS_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($0, -1, @AUTHORITY_INFO_ACCESS_item_tt, 0,
                             Pointer(0) , 0, ' AUTHORITY_INFO_ACCESS');

   Result := @local_it;
end;



initialization
   ossl_v3_info := get_V3_EXT_METHOD( NID_info_access, X509V3_EXT_MULTILINE,
    AUTHORITY_INFO_ACCESS_it,
    nil, nil, nil, nil,
    nil, nil,
    PX509V3_EXT_I2V(@i2v_AUTHORITY_INFO_ACCESS)^,
    PX509V3_EXT_V2I(@v2i_AUTHORITY_INFO_ACCESS)^,
    nil, nil,
    nil);

   AUTHORITY_INFO_ACCESS_item_tt := get_ASN1_TEMPLATE
        ( (($2 shl  1)), 0,  0, ' GeneralNames' , ACCESS_DESCRIPTION_it);

   ACCESS_DESCRIPTION_seq_tt := [
        get_ASN1_TEMPLATE ( 0,  0,  size_t(@PACCESS_DESCRIPTION(0). method), ' method' , ASN1_OBJECT_it) ,
        get_ASN1_TEMPLATE ( 0,  0,  size_t(@PACCESS_DESCRIPTION(0). location), ' location' , GENERAL_NAME_it)
   ] ;

   ossl_v3_sinfo := get_V3_EXT_METHOD( NID_sinfo_access, X509V3_EXT_MULTILINE,
    AUTHORITY_INFO_ACCESS_it,
    nil, nil, nil, nil,
    nil, nil,
    PX509V3_EXT_I2V(@i2v_AUTHORITY_INFO_ACCESS)^,
    PX509V3_EXT_V2I(@v2i_AUTHORITY_INFO_ACCESS)^,
    nil, nil,
    nil);
end.
