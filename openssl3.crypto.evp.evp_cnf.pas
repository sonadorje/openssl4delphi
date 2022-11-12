unit openssl3.crypto.evp.evp_cnf;

interface
uses OpenSSL.Api, SysUtils;

 function alg_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
 procedure EVP_add_alg_module;

implementation
uses OpenSSL3.Err,  openssl3.openssl.conf,
     openssl3.crypto.conf.conf_mod,          openssl3.crypto.evp.evp_fetch,
     openssl3.crypto.conf.conf_lib,          OpenSSL3.crypto.x509.v3_utl;

function alg_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
var
    i           : integer;
    oid_section : PUTF8Char;
    sktmp       : Pstack_st_CONF_VALUE;
    oval        : PCONF_VALUE;
    m           : integer;
begin
    //OSSL_TRACE2(CONF, 'Loading EVP module: name %s, value %s\n',
      //          CONF_imodule_get_name(md), CONF_imodule_get_value(md));
    oid_section := CONF_imodule_get_value(md);
    sktmp := NCONF_get_section(cnf, oid_section);
    if sktmp  = nil then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_ERROR_LOADING_SECTION);
        Exit(0);
    end;
    for i := 0 to sk_CONF_VALUE_num(sktmp)-1 do
    begin
        oval := sk_CONF_VALUE_value(sktmp, i);
        if strcmp(oval.name, 'fips_mode') = 0  then
        begin
            { Detailed error already reported. }
            if 0>=X509V3_get_value_bool(oval, @m) then
                Exit(0);
            {
             * fips_mode is deprecated and should not be used in new
             * configurations.
             }
            if 0>=evp_default_properties_enable_fips_int(
                    NCONF_get0_libctx(PCONF(cnf)), Int(m > 0), 0) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_SET_DEFAULT_PROPERTY_FAILURE);
                Exit(0);
            end;
        end
        else if (strcmp(oval.name, 'default_properties') = 0) then
        begin
            if 0>=evp_set_default_properties_int(NCONF_get0_libctx(PCONF(cnf)),
                        oval.value, 0, 0) then
            begin
                ERR_raise(ERR_LIB_EVP, EVP_R_SET_DEFAULT_PROPERTY_FAILURE);
                Exit(0);
            end;
        end
        else
        begin
            ERR_raise_data(ERR_LIB_EVP, EVP_R_UNKNOWN_OPTION,
                          Format('name=%s, value=%s', [oval.name, oval.value]));
            Exit(0);
        end;
    end;
    Result := 1;
end;


procedure EVP_add_alg_module;
begin
    //OSSL_TRACE(CONF, 'Adding config module 'alg_section'\n');
    CONF_module_add('alg_section', alg_module_init, nil);
end;


end.
