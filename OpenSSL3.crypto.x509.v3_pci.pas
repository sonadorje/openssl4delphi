unit OpenSSL3.crypto.x509.v3_pci;

interface
uses OpenSSL.Api;


 function process_pci_value( val : PCONF_VALUE; language : PPASN1_OBJECT; pathlen : PPASN1_INTEGER; policy : PPASN1_OCTET_STRING):integer;
  function r2i_pci( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; value : PUTF8Char):PPROXY_CERT_INFO_EXTENSION;
 function i2r_pci( method : PX509V3_EXT_METHOD; pci : PPROXY_CERT_INFO_EXTENSION; _out : PBIO; indent : integer):integer;

var
   ossl_v3_pci: TX509V3_EXT_METHOD;

implementation

uses OpenSSL3.openssl.conf, openssl3.crypto.x509v3, openssl3.crypto.mem,
     OpenSSL3.crypto.x509.v3_san, openssl3.crypto.asn1.a_object,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.asn1.tasn_dec,
     openssl3.crypto.asn1.tasn_enc, openssl3.crypto.asn1.tasn_new,
     openssl3.crypto.asn1.tasn_fre, openssl3.crypto.o_str,
     OpenSSL3.common,  openssl3.crypto.bio.bss_file,
     openssl3.crypto.asn1.f_int,
     openssl3.crypto.bio.bio_lib,   OpenSSL3.crypto.x509.v3_conf,
     openssl3.crypto.x509.v3_genn,  OpenSSL3.crypto.x509.v3_pcia,
     openssl3.crypto.objects.obj_dat,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.bio.bio_print, OpenSSL3.Err;



function i2r_pci( method : PX509V3_EXT_METHOD; pci : PPROXY_CERT_INFO_EXTENSION; _out : PBIO; indent : integer):integer;
begin
    BIO_printf(_out, ' %*sPath Length Constraint: ' , [indent, ' '] );
    if pci.pcPathLengthConstraint <> nil then
       i2a_ASN1_INTEGER(_out, pci.pcPathLengthConstraint)
    else
        BIO_printf(_out, ' infinite',[] );
    BIO_puts(_out, ' '#10 );
    BIO_printf(_out, ' %*sPolicy Language: ' , [indent, ' '] );
    i2a_ASN1_OBJECT(_out, pci.proxyPolicy.policyLanguage);
    if (pci.proxyPolicy.policy <> nil)  and  (pci.proxyPolicy.policy.data <> nil) then
       BIO_printf(_out, ' '#10'%*sPolicy Text: %.*s' , [indent, ' ' ,
                   pci.proxyPolicy.policy.length,
                   pci.proxyPolicy.policy.data]);
    Result := 1;
end;




function process_pci_value( val : PCONF_VALUE; language : PPASN1_OBJECT; pathlen : PPASN1_INTEGER; policy : PPASN1_OCTET_STRING):integer;
var
    free_policy : integer;
    valp        : PUTF8Char;
    tmp_data    : PByte;
    val_len     : long;
    tmp_data2   : PByte;
    buf         : array[0..2047] of Byte;
    n           : integer;
    b           : PBIO;
    label _err;
    function get_n: int;
    begin
       n := BIO_read(b, @buf, sizeof(buf));
       Result := n;
    end;
begin
    free_policy := 0;
    if strcmp(val.name, ' language') = 0   then
    begin
        if language^ <> nil then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_POLICY_LANGUAGE_ALREADY_DEFINED);
            X509V3_conf_err(val);
            Exit(0);
        end;

        language^ := OBJ_txt2obj(val.value, 0);
        if language^ = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OBJECT_IDENTIFIER);
            X509V3_conf_err(val);
            Exit(0);
        end;
    end
    else
    if (strcmp(val.name, ' pathlen' ) = 0) then
    begin
        if pathlen^ <> nil then
        begin
            ERR_raise(ERR_LIB_X509V3,
                      X509V3_R_POLICY_PATH_LENGTH_ALREADY_DEFINED);
            X509V3_conf_err(val);
            Exit(0);
        end;
        if 0>= X509V3_get_value_int(val, pathlen) then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_POLICY_PATH_LENGTH);
            X509V3_conf_err(val);
            Exit(0);
        end;
    end
    else
    if (strcmp(val.name, ' policy' ) = 0) then
    begin
        valp := val.value;
        tmp_data := nil;
        if policy^ = nil then
        begin
            policy^ := ASN1_OCTET_STRING_new();
            if policy^ = nil then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                X509V3_conf_err(val);
                Exit(0);
            end;
            free_policy := 1;
        end;
        if CHECK_AND_SKIP_PREFIX(valp, ' hex:') > 0 then
        begin
            tmp_data2 := OPENSSL_hexstr2buf(valp, @val_len);
            if nil = tmp_data2 then
            begin
                X509V3_conf_err(val);
                goto _err ;
            end;
            OPENSSL_realloc(Pointer( policy^.data),
                                       ( policy^).length + val_len + 1);
            if ( policy^).data <> nil then
            begin
                //( policy^).data := tmp_data;
                memcpy(@( policy^).data[( policy^).length], tmp_data2, val_len);
                ( policy^).length  := ( policy^).length + val_len;
                ( policy^).data[( policy^).length] := Ord(#0);
            end
            else
            begin
                OPENSSL_free(tmp_data2);
                {
                 * realloc failure implies the original data space is b0rked
                 * too!
                 }
                OPENSSL_free(policy^.data);
                ( policy^).data := nil;
                ( policy^).length := 0;
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                X509V3_conf_err(val);
                goto _err ;
            end;
            OPENSSL_free(tmp_data2);
        end
        else
        if (CHECK_AND_SKIP_PREFIX(valp, ' file:' )>0) then
        begin
            b := BIO_new_file(valp, ' r' );
            if nil = b then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_BIO_LIB);
                X509V3_conf_err(val);
                goto _err ;
            end;
            while (get_n > 0) or ( (n = 0)  and  (BIO_should_retry(b)>0) ) do
            begin
                if 0>= n then continue;
                OPENSSL_realloc(Pointer( policy^.data),
                                           ( policy^).length + n + 1);
                if nil = ( policy^).data then
                begin
                    OPENSSL_free(( policy^).data);
                    ( policy^).data := nil;
                    ( policy^).length := 0;
                    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                    X509V3_conf_err(val);
                    BIO_free_all(b);
                    goto _err ;
                end;
                ( policy^).data := tmp_data;
                memcpy(@policy^.data[policy^.length], @buf, n);
                ( policy^).length  := ( policy^).length + n;
                ( policy^).data[( policy^).length] := Ord(#0);
            end;
            BIO_free_all(b);
            if n < 0 then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_BIO_LIB);
                X509V3_conf_err(val);
                goto _err ;
            end;
        end
        else
        if (CHECK_AND_SKIP_PREFIX(valp, ' text:' )>0) then
        begin
            val_len := Length(valp);
           OPENSSL_realloc(Pointer( policy^.data),
                                       ( policy^).length + val_len + 1);
            if ( policy^).data <> nil then
            begin
                ( policy^).data := tmp_data;
                memcpy(@( policy^).data[( policy^).length], val.value + 5, val_len);
                ( policy^).length  := ( policy^).length + val_len;
                ( policy^).data[( policy^).length] := Ord(#0);
            end
            else
            begin
                {
                 * realloc failure implies the original data space is b0rked
                 * too!
                 }
                OPENSSL_free(( policy^).data);
                ( policy^).data := nil;
                ( policy^).length := 0;
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                X509V3_conf_err(val);
                goto _err ;
            end;
        end
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INCORRECT_POLICY_SYNTAX_TAG);
            X509V3_conf_err(val);
            goto _err ;
        end;
        if nil = tmp_data then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            X509V3_conf_err(val);
            goto _err ;
        end;
    end;
    Exit(1);
 _err:
    if free_policy > 0 then
    begin
        ASN1_OCTET_STRING_free( policy^);
        policy^ := nil;
    end;
    Result := 0;
end;


function r2i_pci( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; value : PUTF8Char):PPROXY_CERT_INFO_EXTENSION;
var
    pci       : PPROXY_CERT_INFO_EXTENSION;
    vals      : Pstack_st_CONF_VALUE;
    language  : PASN1_OBJECT;
    pathlen   : PASN1_INTEGER;
    policy    : PASN1_OCTET_STRING;
    i,
    j         : integer;
    cnf       : PCONF_VALUE;
    sect      : Pstack_st_CONF_VALUE;
    success_p : integer;
    label _err, _end;
begin
    pci := nil;
    language := nil;
    pathlen := nil;
    policy := nil;
    vals := X509V3_parse_list(value);
    for i := 0 to sk_CONF_VALUE_num(vals)-1 do
    begin
        cnf := sk_CONF_VALUE_value(vals, i);
        if (nil= cnf.name)  or ( (cnf.name^ <> '@')  and  (nil= cnf.value) ) then
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_PROXY_POLICY_SETTING);
            X509V3_conf_err(cnf);
            goto _err ;
        end;
        if cnf.name^ = '@' then
        begin
            success_p := 1;
            sect := X509V3_get_section(ctx, cnf.name + 1);
            if nil = sect then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_SECTION);
                X509V3_conf_err(cnf);
                goto _err ;
            end;
            j := 0;
            while (success_p > 0) and  (j < sk_CONF_VALUE_num(sect)) do
            begin
                success_p := process_pci_value(sk_CONF_VALUE_value(sect, j),
                                      @language, @pathlen, @policy);
                Inc(j);
            end;
            X509V3_section_free(ctx, sect);
            if 0>= success_p then
               goto _err ;
        end
        else
        begin
            if 0>= process_pci_value(cnf, @language, @pathlen, @policy)  then
            begin
                X509V3_conf_err(cnf);
                goto _err ;
            end;
        end;
    end;
    { Language is mandatory }
    if nil = language then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_NO_PROXY_CERT_POLICY_LANGUAGE_DEFINED);
        goto _err ;
    end;
    i := OBJ_obj2nid(language);
    if ( (i = NID_Independent)  or  (i = NID_id_ppl_inheritAll) )  and  (policy <> nil) then
    begin
        ERR_raise(ERR_LIB_X509V3,
                  X509V3_R_POLICY_WHEN_PROXY_LANGUAGE_REQUIRES_NO_POLICY);
        goto _err ;
    end;
    pci := PROXY_CERT_INFO_EXTENSION_new();
    if pci = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    pci.proxyPolicy.policyLanguage := language;
    language := nil;
    pci.proxyPolicy.policy := policy;
    policy := nil;
    pci.pcPathLengthConstraint := pathlen;
    pathlen := nil;
    goto _end ;
 _err:
    ASN1_OBJECT_free(language);
    ASN1_INTEGER_free(pathlen);
    pathlen := nil;
    ASN1_OCTET_STRING_free(policy);
    policy := nil;
    PROXY_CERT_INFO_EXTENSION_free(pci);
    pci := nil;
 _end:
    sk_CONF_VALUE_pop_free(vals, X509V3_conf_free);
    Result := pci;
end;


initialization
   ossl_v3_pci := get_V3_EXT_METHOD
    ( NID_proxyCertInfo, 0, PROXY_CERT_INFO_EXTENSION_it,
    nil, nil, nil, nil,
    nil, nil,
    nil, nil,
    PX509V3_EXT_I2R(@i2r_pci)^,
    PX509V3_EXT_R2I(@r2i_pci)^,
    nil);
end.
