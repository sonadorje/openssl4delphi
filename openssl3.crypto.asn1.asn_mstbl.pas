unit openssl3.crypto.asn1.asn_mstbl;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

procedure ASN1_add_stable_module;
function stbl_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
function do_tcreate(const value, name : PUTF8Char):integer;
procedure stbl_module_finish( md : PCONF_IMODULE);

implementation
uses OpenSSL3.Err,
     OpenSSL3.openssl.conf,                openssl3.crypto.objects.obj_dat,
     OpenSSL3.crypto.x509.v3_utl,          openssl3.crypto.asn1.asn1_gen,
     openssl3.crypto.asn1.a_strnid,
     openssl3.crypto.conf.conf_mod,        openssl3.crypto.conf.conf_lib;




procedure stbl_module_finish( md : PCONF_IMODULE);
begin
    ASN1_STRING_TABLE_cleanup;
end;


function do_tcreate(const value, name : PUTF8Char):integer;
var
  eptr      : PUTF8Char;
  nid,
  i,
  rv        : integer;
  tbl_min,
  tbl_max   : long;
  tbl_mask,
  tbl_flags : Cardinal;
  lst       : Pstack_st_CONF_VALUE;
  cnf       : PCONF_VALUE;
  label _err;
begin
    rv := 0;
    tbl_min := -1;
    tbl_max := -1;
    tbl_mask := 0;
    tbl_flags := 0;
    lst := nil;
    cnf := nil;
    nid := OBJ_sn2nid(name);
    if nid = NID_undef then nid := OBJ_ln2nid(name);
    if nid = NID_undef then goto _err;
    lst := X509V3_parse_list(value);
    if nil =lst then goto _err;
    for i := 0 to sk_CONF_VALUE_num(lst)-1 do
    begin
        cnf := sk_CONF_VALUE_value(lst, i);
        if strcmp(cnf.name, 'min') = 0  then
        begin
            tbl_min := strtoul(cnf.value, @eptr, 0);
            if eptr^ <> #0 then goto _err;
        end
        else
        if (strcmp(cnf.name, 'max') = 0) then
        begin
            tbl_max := strtoul(cnf.value, @eptr, 0);
            if eptr^ <> #0 then goto _err;
        end
        else
        if (strcmp(cnf.name, 'mask') = 0) then
        begin
            if (0>=ASN1_str2mask(cnf.value, @tbl_mask))  or  (0>=tbl_mask) then
                goto _err;
        end
        else
        if (strcmp(cnf.name, 'flags') = 0) then
        begin
            if strcmp(cnf.value, 'nomask') = 0  then
                tbl_flags := STABLE_NO_MASK
            else
            if (strcmp(cnf.value, 'none') = 0) then
                tbl_flags := STABLE_FLAGS_CLEAR
            else
                goto _err;
        end
        else
            goto _err;
    end;
    rv := 1;
 _err:
    if rv = 0 then
    begin
        if cnf <> nil then
            ERR_raise_data(ERR_LIB_ASN1, ASN1_R_INVALID_STRING_TABLE_VALUE,
                           Format('field=%s, value=%s', [cnf.name, cnf.value]))
        else
            ERR_raise_data(ERR_LIB_ASN1, ASN1_R_INVALID_STRING_TABLE_VALUE,
                           Format('name=%s, value=%s', [name, value]));
    end
    else
    begin
        rv := ASN1_STRING_TABLE_add(nid, tbl_min, tbl_max,
                                   tbl_mask, tbl_flags);
        if 0>=rv then ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
    end;
    sk_CONF_VALUE_pop_free(lst, X509V3_conf_free);
    Result := rv;
end;

function stbl_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
var
    i            : integer;
    stbl_section : PUTF8Char;
    sktmp        : Pstack_st_CONF_VALUE;
    mval         : PCONF_VALUE;
begin
    stbl_section := CONF_imodule_get_value(md);
    sktmp := NCONF_get_section(cnf, stbl_section);
    if sktmp = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ERROR_LOADING_SECTION);
        Exit(0);
    end;
    for i := 0 to sk_CONF_VALUE_num(sktmp)-1 do
    begin
        mval := sk_CONF_VALUE_value(sktmp, i);
        if 0>=do_tcreate(mval.value, mval.name) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_INVALID_VALUE);
            Exit(0);
        end;
    end;
    Result := 1;
end;

procedure ASN1_add_stable_module;
begin
    CONF_module_add('stbl_section', stbl_module_init, stbl_module_finish);
end;


end.
