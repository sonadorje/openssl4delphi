unit OpenSSL3.crypto.x509.v3_san;

interface
uses OpenSSL.Api, SysUtils;

function v2i_GENERAL_NAMES(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PGENERAL_NAMES;
function v2i_GENERAL_NAME(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; cnf : PCONF_VALUE):PGENERAL_NAME;
function v2i_GENERAL_NAME_ex(_out : PGENERAL_NAME;const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; cnf : PCONF_VALUE; is_nc : integer):PGENERAL_NAME;
function a2i_GENERAL_NAME(_out : PGENERAL_NAME;const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; gen_type : integer;const value : PUTF8Char; is_nc : integer):PGENERAL_NAME;
function do_othername(gen : PGENERAL_NAME;const value : PUTF8Char; ctx : PX509V3_CTX):integer;
function do_dirname(gen : PGENERAL_NAME;const value : PUTF8Char; ctx : PX509V3_CTX):integer;
function GENERAL_NAME_print( _out : PBIO; gen : PGENERAL_NAME):integer;
function i2v_GENERAL_NAMES( method : PX509V3_EXT_METHOD; gens : PGENERAL_NAMES; ret : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
function i2v_GENERAL_NAME( method : PX509V3_EXT_METHOD; gen : PGENERAL_NAME; ret : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
function v2i_subject_alt( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PGENERAL_NAMES;
function copy_email( ctx : PX509V3_CTX; gens : PGENERAL_NAMES; move_p : integer):integer;
function v2i_issuer_alt( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PGENERAL_NAMES;
function copy_issuer( ctx : PX509V3_CTX; gens : PGENERAL_NAMES):integer;


var  ossl_v3_alt: array[0..2] of TX509V3_EXT_METHOD ;

implementation
uses openssl3.crypto.stack, openssl3.crypto.x509v3, OpenSSL3.Err,
     OpenSSL3.crypto.x509.v3_utl, openssl3.crypto.x509.v3_genn,
     openssl3.crypto.asn1.asn1_gen, openssl3.crypto.o_str,
     openssl3.crypto.mem, OpenSSL3.crypto.x509.x_name,
     OpenSSL3.crypto.x509.x509name,   OpenSSL3.crypto.x509.x509_cmp,
     OpenSSL3.crypto.x509.x509_req, OpenSSL3.crypto.x509.x509_ext,
     OpenSSL3.openssl.conf,  openssl3.crypto.bio.bio_print,
     OpenSSL3.crypto.x509.v3_lib,
     openssl3.crypto.asn1.a_print, openssl3.crypto.asn1.a_strex,
     OpenSSL3.crypto.x509.v3_conf, openssl3.crypto.asn1.asn1_lib,
     openssl3.crypto.asn1.a_object, openssl3.crypto.x509.x509_obj,
     openssl3.crypto.objects.obj_dat, openssl3.crypto.asn1.tasn_typ;


function copy_issuer( ctx : PX509V3_CTX; gens : PGENERAL_NAMES):integer;
var
  ialt : PGENERAL_NAMES;
  gen : PGENERAL_NAME;
  ext : PX509_EXTENSION;
  i, num : integer;
  label _err;
begin
    if (ctx <> nil)  and ( (ctx.flags and X509V3_CTX_TEST) <> 0) then
        Exit(1);
    if (nil = ctx ) or  (nil = ctx.issuer_cert) then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_NO_ISSUER_DETAILS);
        goto _err ;
    end;
    i := X509_get_ext_by_NID(ctx.issuer_cert, NID_subject_alt_name, -1);
    if i < 0 then Exit(1);
    ext := X509_get_ext(ctx.issuer_cert, i);
    ialt := X509V3_EXT_d2i(ext);
    if (ext = nil) or  (ialt =  nil) then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_ISSUER_DECODE_ERROR);
        goto _err ;
    end;
    num := sk_GENERAL_NAME_num(ialt);
    if 0>= sk_GENERAL_NAME_reserve(gens, num) then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    for i := 0 to num-1 do
    begin
        gen := sk_GENERAL_NAME_value(ialt, i);
        sk_GENERAL_NAME_push(gens, gen);     { no failure as it was reserved }
    end;
    sk_GENERAL_NAME_free(ialt);
    Exit(1);
 _err:
    Exit(0);
end;



function v2i_issuer_alt( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PGENERAL_NAMES;
var
  num : integer;
  gens : PGENERAL_NAMES;
  i : integer;
  cnf : PCONF_VALUE;
  gen : PGENERAL_NAME;
  label _err;
begin
    num := sk_CONF_VALUE_num(nval);
    gens := sk_GENERAL_NAME_new_reserve(nil, num);
    if gens = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        sk_GENERAL_NAME_free(gens);
        Exit(nil);
    end;
    for i := 0 to num-1 do
     begin
        cnf := sk_CONF_VALUE_value(nval, i);
        if (0>= ossl_v3_name_cmp(cnf.name, 'issuer'))  and
           (cnf.value <> nil)  and  (strcmp(cnf.value, 'copy') = 0)  then
        begin
            if 0>= copy_issuer(ctx, gens) then
                goto _err ;
        end
        else
        begin
            gen := v2i_GENERAL_NAME(method, ctx, cnf);
            if gen = nil then goto _err ;
            sk_GENERAL_NAME_push(gens, gen); { no failure as it was reserved }
        end;
    end;
    Exit(gens);
 _err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    Result := nil;
end;




function copy_email( ctx : PX509V3_CTX; gens : PGENERAL_NAMES; move_p : integer):integer;
var
  nm : PX509_NAME;
  email : PASN1_IA5STRING;
  ne : PX509_NAME_ENTRY;
  gen : PGENERAL_NAME;
  i : integer;
  label _err;
  function get_i: int;
  begin
     i := X509_NAME_get_index_by_NID(nm, NID_pkcs9_emailAddress, i);
     Result := i;
  end;

begin
    email := nil;
    gen := nil;
    i := -1;
    if (ctx <> nil)  and ( (ctx.flags and X509V3_CTX_TEST) <> 0) then
        Exit(1);
    if (ctx = nil)
         or ( (ctx.subject_cert = nil)  and  (ctx.subject_req = nil) ) then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_NO_SUBJECT_DETAILS);
        Exit(0);
    end;
    { Find the subject name }
     if ctx.subject_cert <> nil then
        nm :=   X509_get_subject_name(ctx.subject_cert)
     else
        nm :=   X509_REQ_get_subject_name(ctx.subject_req);
    { Now add any email address(es) to STACK }
    while (get_i >= 0) do
    begin
        ne := X509_NAME_get_entry(nm, i);
        email := PASN1_IA5STRING(ASN1_STRING_dup(X509_NAME_ENTRY_get_data(ne)));
        if move_p > 0 then
        begin
            X509_NAME_delete_entry(nm, i);
            X509_NAME_ENTRY_free(ne);
            Dec(i);
        end;
        gen := GENERAL_NAME_new() ;
        if (email = nil)  or  (gen = nil) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        gen.d.ia5 := email;
        email := nil;
        gen.&type := GEN_EMAIL;
        if 0>= sk_GENERAL_NAME_push(gens, gen) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
        gen := nil;
    end;
    Exit(1);
 _err:
    GENERAL_NAME_free(gen);
    ASN1_IA5STRING_free(email);
    Exit(0);
end;




function v2i_subject_alt( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PGENERAL_NAMES;
var
  gens : PGENERAL_NAMES;
  cnf : PCONF_VALUE;
  num, i : integer;
  gen : PGENERAL_NAME;
  label _err;
begin
    num := sk_CONF_VALUE_num(nval);
    gens := sk_GENERAL_NAME_new_reserve(nil, num);
    if gens = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        sk_GENERAL_NAME_free(gens);
        Exit(nil);
    end;
    for i := 0 to num-1 do
    begin
        cnf := sk_CONF_VALUE_value(nval, i);
        if (ossl_v3_name_cmp(cnf.name, 'email') = 0)
             and  (cnf.value <> nil)  and  (strcmp(cnf.value, 'copy') = 0)  then
        begin
            if 0>= copy_email(ctx, gens, 0) then
                goto _err ;
        end
        else
        if (ossl_v3_name_cmp(cnf.name, 'email') = 0)
                    and  (cnf.value <> nil)  and  (strcmp(cnf.value, 'move') = 0) then
        begin
            if 0>= copy_email(ctx, gens, 1 ) then
                goto _err ;
        end
        else
        begin
            gen := v2i_GENERAL_NAME(method, ctx, cnf);
            if gen = nil then
                goto _err ;
            sk_GENERAL_NAME_push(gens, gen); { no failure as it was reserved }
        end;
    end;
    Exit(gens);
 _err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    Result := nil;
end;




function i2v_GENERAL_NAME( method : PX509V3_EXT_METHOD; gen : PGENERAL_NAME; ret : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
    othername : array[0..299] of UTF8Char;
    oline     : array[0..255] of UTF8Char;
    tmp, pc       : PUTF8Char;
begin
    pc := @othername;
    case gen.&type of
    GEN_OTHERNAME:
    begin
        case (OBJ_obj2nid(gen.d.otherName.type_id)) of
            NID_id_on_SmtpUTF8Mailbox:
            begin
                if (gen.d.otherName.value._type <> V_ASN1_UTF8STRING)
                         or  (0>= x509v3_add_len_value_uchar('othername: SmtpUTF8Mailbox:',
                                gen.d.otherName.value.value.utf8string.data,
                                gen.d.otherName.value.value.utf8string.length,
                                @ret)) then
                    Exit(nil);
            end;
            NID_XmppAddr:
            begin
                if (gen.d.otherName.value._type <> V_ASN1_UTF8STRING)
                         or  (0>= x509v3_add_len_value_uchar('othername: XmppAddr:',
                                gen.d.otherName.value.value.utf8string.data,
                                gen.d.otherName.value.value.utf8string.length,
                                @ret)) then
                    Exit(nil);
            end;
            NID_SRVName:
            begin
                if (gen.d.otherName.value._type <> V_ASN1_IA5STRING)
                         or  (0>= x509v3_add_len_value_uchar('othername: SRVName:',
                                gen.d.otherName.value.value.ia5string.data,
                                gen.d.otherName.value.value.ia5string.length,
                                @ret)) then
                    Exit(nil);
            end;
            NID_ms_upn:
            begin
                if (gen.d.otherName.value._type <> V_ASN1_UTF8STRING)
                         or  (0>= x509v3_add_len_value_uchar('othername: UPN:',
                                gen.d.otherName.value.value.utf8string.data,
                                gen.d.otherName.value.value.utf8string.length,
                                @ret)) then
                    Exit(nil);
            end;
            NID_NAIRealm:
            begin
                if (gen.d.otherName.value._type <> V_ASN1_UTF8STRING)
                         or  (0>= x509v3_add_len_value_uchar('othername: NAIRealm:',
                                gen.d.otherName.value.value.utf8string.data,
                                gen.d.otherName.value.value.utf8string.length,
                                @ret)) then
                    Exit(nil);
            end;
            else
            begin
                if OBJ_obj2txt(oline, sizeof(oline), gen.d.otherName.type_id, 0) > 0  then
                    BIO_snprintf(othername, sizeof(othername), 'othername: %s:',
                                 [oline])
                else
                    OPENSSL_strlcpy(pc{othername}, 'othername:', sizeof(othername));
                { check if the value is something printable }
                if gen.d.otherName.value._type = V_ASN1_IA5STRING then
                begin
                    if (x509v3_add_len_value_uchar(othername,
                                 gen.d.otherName.value.value.ia5string.data,
                                 gen.d.otherName.value.value.ia5string.length,
                                 @ret)>0) then
                        Exit(ret);
                end;
                if gen.d.otherName.value._type = V_ASN1_UTF8STRING then
                begin
                    if (x509v3_add_len_value_uchar(othername,
                                 gen.d.otherName.value.value.utf8string.data,
                                 gen.d.otherName.value.value.utf8string.length,
                                 @ret) > 0) then
                        Exit(ret);
                end;
                if 0>= X509V3_add_value(othername, '<unsupported>', @ret ) then
                    Exit(nil);
            end;
        end;
    end;
    GEN_X400:
        if 0>= X509V3_add_value('X400Name', '<unsupported>', @ret ) then
            Exit(nil);
        //break;
    GEN_EDIPARTY:
        if 0>= X509V3_add_value('EdiPartyName', '<unsupported>', @ret ) then
            Exit(nil);
        //break;
    GEN_EMAIL:
        if 0>= x509v3_add_len_value_uchar('email', gen.d.ia5.data,
                                        gen.d.ia5.length, @ret ) then
            Exit(nil);
        //break;
    GEN_DNS:
        if 0>= x509v3_add_len_value_uchar('DNS', gen.d.ia5.data,
                                        gen.d.ia5.length, @ret ) then
            Exit(nil);
        //break;
    GEN_URI:
        if 0>= x509v3_add_len_value_uchar('URI', gen.d.ia5.data,
                                        gen.d.ia5.length, @ret ) then
            Exit(nil);
        //break;
    GEN_DIRNAME:
        if (X509_NAME_oneline(gen.d.dirn, oline, sizeof(oline) )  = nil)
                 or  (0>= X509V3_add_value('DirName', oline, @ret)) then
            Exit(nil);
        //break;
    GEN_IPADD:
    begin
        tmp := ossl_ipaddr_to_asc(gen.d.ip.data, gen.d.ip.length);
        if (tmp = nil)  or  (0>= X509V3_add_value('IP Address', tmp, @ret) ) then
            ret := nil;
        OPENSSL_free(tmp);
    end;
    GEN_RID:
    begin
        i2t_ASN1_OBJECT(oline, 256, gen.d.rid);
        if 0>= X509V3_add_value('Registered ID', oline, @ret ) then
            Exit(nil);
    end;
    end;
    Result := ret;
end;




function i2v_GENERAL_NAMES( method : PX509V3_EXT_METHOD; gens : PGENERAL_NAMES; ret : Pstack_st_CONF_VALUE):Pstack_st_CONF_VALUE;
var
  i : integer;
  gen : PGENERAL_NAME;
  tmpret, origret : Pstack_st_CONF_VALUE;
begin
    tmpret := nil; origret := ret;
    for i := 0 to sk_GENERAL_NAME_num(gens)-1 do
    begin
        gen := sk_GENERAL_NAME_value(gens, i);
        {
         * i2v_GENERAL_NAME allocates ret if it is nil. If something goes
         * wrong we need to free the stack - but only if it was empty when we
         * originally entered this function.
         }
        tmpret := i2v_GENERAL_NAME(method, gen, ret);
        if tmpret = nil then
        begin
            if origret = nil then
                sk_CONF_VALUE_pop_free(ret, X509V3_conf_free);
            Exit(nil);
        end;
        ret := tmpret;
    end;
    if ret = nil then
       Exit(sk_CONF_VALUE_new_null);
    Result := ret;
end;


function GENERAL_NAME_print( _out : PBIO; gen : PGENERAL_NAME):integer;
var
  tmp : PUTF8Char;
  nid : integer;
  label _break;
begin
    case gen.&type of
        GEN_OTHERNAME:
        begin
            nid := OBJ_obj2nid(gen.d.otherName.type_id);
            { Validate the types are as we expect before we use them }
            if ( (nid = NID_SRVName)   and (gen.d.otherName.value._type <> V_ASN1_IA5STRING) )  or
               ( (nid <> NID_SRVName)  and (gen.d.otherName.value._type <> V_ASN1_UTF8STRING) ) then
            begin
                BIO_printf(_out, 'othername:<unsupported>',[]);
                goto _break;
            end;

            case nid of
                NID_id_on_SmtpUTF8Mailbox:
                    BIO_printf(_out, 'othername:SmtpUTF8Mailbox:%.*s',
                               [gen.d.otherName.value.value.utf8string.length,
                               gen.d.otherName.value.value.utf8string.data]);

                NID_XmppAddr:
                    BIO_printf(_out, 'othername:XmppAddr:%.*s',
                               [gen.d.otherName.value.value.utf8string.length,
                               gen.d.otherName.value.value.utf8string.data]);

                NID_SRVName:
                    BIO_printf(_out, 'othername:SRVName:%.*s',
                              [ gen.d.otherName.value.value.ia5string.length,
                               gen.d.otherName.value.value.ia5string.data]);

                NID_ms_upn:
                    BIO_printf(_out, 'othername:UPN:%.*s',
                              [ gen.d.otherName.value.value.utf8string.length,
                               gen.d.otherName.value.value.utf8string.data]);

                NID_NAIRealm:
                    BIO_printf(_out, 'othername:NAIRealm:%.*s',
                              [ gen.d.otherName.value.value.utf8string.length,
                               gen.d.otherName.value.value.utf8string.data]);

                else
                    BIO_printf(_out, 'othername:<unsupported>',[]);

            end;
        end;//
        GEN_X400:
            BIO_printf(_out, 'X400Name:<unsupported>', []);

        GEN_EDIPARTY:
            { Maybe fix this: it is supported now }
            BIO_printf(_out, 'EdiPartyName:<unsupported>', []);

        GEN_EMAIL:
        begin
            BIO_printf(_out, 'email:', []);
            ASN1_STRING_print(_out, PASN1_STRING(gen.d.ia5));
        end;//
        GEN_DNS:
        begin
            BIO_printf(_out, 'DNS:', []);
            ASN1_STRING_print(_out, PASN1_STRING(gen.d.ia5));
        end;//
        GEN_URI:
        begin
            BIO_printf(_out, 'URI:', []);
            ASN1_STRING_print(_out, PASN1_STRING(gen.d.ia5));
        end;//
        GEN_DIRNAME:
        begin
            BIO_printf(_out, 'DirName:', []);
            X509_NAME_print_ex(_out, gen.d.dirn, 0, XN_FLAG_ONELINE);
        end;//
        GEN_IPADD:
        begin
            tmp := ossl_ipaddr_to_asc(gen.d.ip.data, gen.d.ip.length);
            if tmp = nil then Exit(0);
            BIO_printf(_out, 'IP Address:%s', [tmp]);
            OPENSSL_free(tmp);
        end;//
        GEN_RID:
        begin
            BIO_printf(_out, 'Registered ID:', []);
            i2a_ASN1_OBJECT(_out, gen.d.rid);
        end;//
    end;
_break:
    Result := 1;
end;



function do_dirname(gen : PGENERAL_NAME;const value : PUTF8Char; ctx : PX509V3_CTX):integer;
var
  ret : integer;
  sk : Pstack_st_CONF_VALUE;
  nm : PX509_NAME;
  label _err;
begin
    ret := 0;
    sk := nil;
    nm := X509_NAME_new();
    if nm = nil then
        goto _err ;
    sk := X509V3_get_section(ctx, value);
    if nil = sk then
    begin
        ERR_raise_data(ERR_LIB_X509V3, X509V3_R_SECTION_NOT_FOUND,
                      Format( 'section=%s', [value]));
        goto _err ;
    end;
    { FIXME: should allow other character types... }
    ret := X509V3_NAME_from_section(nm, sk, MBSTRING_ASC);
    if 0>= ret then
       goto _err ;
    gen.d.dirn := nm;
_err:
    if ret = 0 then
       X509_NAME_free(nm);
    X509V3_section_free(ctx, sk);
    Result := ret;
end;


function do_othername(gen : PGENERAL_NAME;const value : PUTF8Char; ctx : PX509V3_CTX):integer;
var
  objtmp, p : PUTF8Char;
  objlen : integer;
begin
    objtmp := nil;
    p := strchr(value, ';' );
    if p = nil then
        Exit(0);
    gen.d.otherName := OTHERNAME_new();
    if gen.d.otherName = nil then
        Exit(0);
    {
     * Free this up because we will overwrite it. no need to free type_id
     * because it is static
     }
    ASN1_TYPE_free(gen.d.otherName.value);
    gen.d.otherName.value := ASN1_generate_v3(p + 1, ctx);
    if gen.d.otherName.value = nil then
        Exit(0);
    objlen := p - value;
    OPENSSL_strndup(objtmp, value, objlen);
    if objtmp = nil then
       Exit(0);
    gen.d.otherName.type_id := OBJ_txt2obj(objtmp, 0);
    OPENSSL_free(objtmp);
    if nil = gen.d.otherName.type_id then
       Exit(0);
    Result := 1;
end;



function a2i_GENERAL_NAME(_out : PGENERAL_NAME;const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; gen_type : integer;const value : PUTF8Char; is_nc : integer):PGENERAL_NAME;
var
    is_string : byte;

    gen       : PGENERAL_NAME;

    obj       : PASN1_OBJECT;
    label _err;
begin
    is_string := 0;
    gen := nil;
    if nil = value then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE);
        Exit(nil);
    end;
    if _out <> nil then
       gen := _out
    else
    begin
        gen := GENERAL_NAME_new();
        if gen = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end;
    case gen_type of
        GEN_URI,
        GEN_EMAIL,
        GEN_DNS:
            is_string := 1;
            //break;
        GEN_RID:
        begin
             obj := OBJ_txt2obj(value, 0);
            if obj = nil then
            begin
                ERR_raise_data(ERR_LIB_X509V3, X509V3_R_BAD_OBJECT,
                             Format('value=%s', [value]));
                goto _err ;
            end;
            gen.d.rid := obj;
        end;
            //break;
        GEN_IPADD:
        begin
            if is_nc > 0 then
               gen.d.ip := a2i_IPADDRESS_NC(value)
            else
                gen.d.ip := a2i_IPADDRESS(value);
            if gen.d.ip = nil then
            begin
                ERR_raise_data(ERR_LIB_X509V3, X509V3_R_BAD_IP_ADDRESS,
                              Format( 'value=%s', [value]));
                goto _err ;
            end;
        end;
        GEN_DIRNAME:
        begin
            if 0>= do_dirname(gen, value, ctx) then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_DIRNAME_ERROR);
                goto _err ;
            end;
        end;
        GEN_OTHERNAME:
        begin
            if 0>= do_othername(gen, value, ctx) then
            begin
                ERR_raise(ERR_LIB_X509V3, X509V3_R_OTHERNAME_ERROR);
                goto _err ;
            end;
        end;
        else
        begin
            ERR_raise(ERR_LIB_X509V3, X509V3_R_UNSUPPORTED_TYPE);
            goto _err ;
        end;
    end;
    if is_string > 0 then
    begin
        gen.d.ia5 := ASN1_IA5STRING_new();
        if (gen.d.ia5 = nil)  or
           (0>= ASN1_STRING_set(PASN1_STRING(gen.d.ia5), PByte( value),
                             Length(value))) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _err ;
        end;
    end;
    gen.&type := gen_type;
    Exit(gen);
 _err:
    if nil = _out then
       GENERAL_NAME_free(gen);
    Result := nil;
end;


function v2i_GENERAL_NAME_ex(_out : PGENERAL_NAME;const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; cnf : PCONF_VALUE; is_nc : integer):PGENERAL_NAME;
var
  _type : integer;
  name, value : PUTF8Char;
begin
    name := cnf.name;
    value := cnf.value;
    if nil = value then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE);
        Exit(nil);
    end;
    if 0>= ossl_v3_name_cmp(name, 'email') then
        _type := GEN_EMAIL
    else if (0>= ossl_v3_name_cmp(name, 'URI'))then
        _type := GEN_URI
    else if (0>= ossl_v3_name_cmp(name, 'DNS')) then
        _type := GEN_DNS
    else if (0>= ossl_v3_name_cmp(name, 'RID')) then
        _type := GEN_RID
    else if (0>= ossl_v3_name_cmp(name, 'IP')) then
        _type := GEN_IPADD
    else if (0>= ossl_v3_name_cmp(name, 'dirName')) then
        _type := GEN_DIRNAME
    else if (0>= ossl_v3_name_cmp(name, 'otherName')) then
        _type := GEN_OTHERNAME
    else
    begin
        ERR_raise_data(ERR_LIB_X509V3, X509V3_R_UNSUPPORTED_OPTION,
                      Format( 'name=%s', [name]));
        Exit(nil);
    end;
    Exit(a2i_GENERAL_NAME(_out, method, ctx, _type, value, is_nc));
end;




function v2i_GENERAL_NAME(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; cnf : PCONF_VALUE):PGENERAL_NAME;
begin
    Result := v2i_GENERAL_NAME_ex(nil, method, ctx, cnf, 0);
end;


function v2i_GENERAL_NAMES(const method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PGENERAL_NAMES;
var
  gen : PGENERAL_NAME;
  gens : PGENERAL_NAMES;
  cnf : PCONF_VALUE;
  num, i : integer;
  label _err;
begin
    num := sk_CONF_VALUE_num(nval);
    gens := sk_GENERAL_NAME_new_reserve(nil, num);
    if gens = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        sk_GENERAL_NAME_free(gens);
        Exit(nil);
    end;
    for i := 0 to num-1 do
    begin
        cnf := sk_CONF_VALUE_value(nval, i);
        gen := v2i_GENERAL_NAME(method, ctx, cnf);
        if gen = nil then
            goto _err ;
        sk_GENERAL_NAME_push(gens, gen);    { no failure as it was reserved }
    end;
    Exit(gens);
 _err:
    sk_GENERAL_NAME_pop_free(gens, GENERAL_NAME_free);
    Result := nil;
end;

initialization
  ossl_v3_alt[0] :=  get_V3_EXT_METHOD(NID_subject_alt_name,  0, GENERAL_NAMES_it,
         nil, nil,nil,nil,
         nil,  nil,
        PX509V3_EXT_I2V(@i2v_GENERAL_NAMES)^,
        PX509V3_EXT_V2I(@v2i_subject_alt)^,
        nil, nil,  nil);

  ossl_v3_alt[1] := get_V3_EXT_METHOD(NID_issuer_alt_name, 0, GENERAL_NAMES_it,
        nil, nil,nil,nil,
         nil,  nil,
         PX509V3_EXT_I2V(@i2v_GENERAL_NAMES)^,
         PX509V3_EXT_V2I(@v2i_issuer_alt)^,
         nil, nil,  nil);

  ossl_v3_alt[2] := get_V3_EXT_METHOD(NID_certificate_issuer, 0, GENERAL_NAMES_it,
         nil, nil,nil,nil,
         nil,  nil,
        PX509V3_EXT_I2V(@i2v_GENERAL_NAMES)^,
        nil,
        nil, nil,  nil);
      


end.
