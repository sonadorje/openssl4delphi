unit openssl3.crypto.evp.p_lib;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

type
   Tlegacy_print_func = function(&out : PBIO;const pkey : PEVP_PKEY; indent : integer; pctx : PASN1_PCTX):integer;

const

  SELECT_PARAMETERS = OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS;
  standard_name2type : array[0..11] of TOSSL_ITEM = (
    (id: EVP_PKEY_RSA; ptr: 'RSA'),
    (id: EVP_PKEY_RSA_PSS; ptr: 'RSA-PSS'),
    (id: EVP_PKEY_EC; ptr:   'EC'),
    (id: EVP_PKEY_ED25519; ptr: 'ED25519'),
    (id: EVP_PKEY_ED448; ptr: 'ED448'),
    (id: EVP_PKEY_X25519; ptr: 'X25519'),
    (id: EVP_PKEY_X448; ptr: 'X448'),
    (id: EVP_PKEY_SM2; ptr: 'SM2'),
    (id: EVP_PKEY_DH; ptr: 'DH'),
    (id: EVP_PKEY_DHX; ptr: 'X9.42DH'),
    (id: EVP_PKEY_DHX; ptr: 'DHX'),
    (id: EVP_PKEY_DSA; ptr: 'DSA') );

function EVP_PKEY_is_a(const pkey : PEVP_PKEY; name : PUTF8Char): Boolean;
function evp_pkey_name2type(const name : PUTF8Char):integer;
function EVP_PKEY_get_security_bits(const pkey : PEVP_PKEY):integer;
function EVP_PKEY_get_id(const pkey : PEVP_PKEY):integer;
function EVP_PKEY_get_int_param(const pkey : PEVP_PKEY; key_name : PUTF8Char; _out : Pinteger):integer;
function EVP_PKEY_get_params(const pkey : PEVP_PKEY; params : POSSL_PARAM):integer;
function EVP_PKEY_get_base_id(const pkey : PEVP_PKEY):integer;
function EVP_PKEY_type( &type : integer):integer;
function EVP_PKEY_assign( pkey : PEVP_PKEY; _type : integer; key : Pointer):integer;
function EVP_PKEY_set1_DSA( pkey : PEVP_PKEY; const key : Pointer):integer;
function evp_pkey_get_legacy( pk : PEVP_PKEY):Pointer;
function EVP_PKEY_get0_DH(const pkey : PEVP_PKEY):PDH;
function EVP_PKEY_get0_DSA(const pkey : PEVP_PKEY):PDSA;
function EVP_PKEY_copy_parameters(_to : PEVP_PKEY;from : PEVP_PKEY):integer;
 function EVP_PKEY_up_ref( pkey : PEVP_PKEY):integer;
function EVP_PKEY_set_type_by_keymgmt( pkey : PEVP_PKEY; keymgmt : PEVP_KEYMGMT):integer;
function EVP_PKEY_new:PEVP_PKEY;
function evp_pkey_type2name( _type : integer):PUTF8Char;
procedure EVP_PKEY_free( x : PEVP_PKEY);
function evp_pkey_export_to_provider(pk : PEVP_PKEY; libctx : POSSL_LIB_CTX; keymgmt : PPEVP_KEYMGMT;const propquery : PUTF8Char):Pointer;
function EVP_PKEY_set_type( pkey : PEVP_PKEY; _type : integer):integer;
function pkey_set_type(pkey : PEVP_PKEY; e : PENGINE; _type : integer;const str : PUTF8Char; len : integer; keymgmt : PEVP_KEYMGMT):integer;
 procedure evp_pkey_free_it( x : PEVP_PKEY);
procedure evp_pkey_free_legacy( x : PEVP_PKEY);
procedure find_ameth(const name : PUTF8Char; data : Pointer);
function evp_pkey_copy_downgraded(dest : PPEVP_PKEY;const src : PEVP_PKEY):integer;
function EVP_PKEY_missing_parameters(const pkey : PEVP_PKEY):integer;
function EVP_PKEY_parameters_eq(const a, b : PEVP_PKEY):integer;
function evp_pkey_cmp_any(const a, b : PEVP_PKEY; selection : integer):integer;
function evp_pkey_get0_DSA_int(const pkey : PEVP_PKEY):PDSA;
 function evp_pkey_get0_DH_int(const pkey : PEVP_PKEY):PDH;
procedure detect_foreign_key( pkey : PEVP_PKEY);
function EVP_PKEY_get_default_digest_nid( pkey : PEVP_PKEY; pnid : PInteger):integer;
function EVP_PKEY_get_size(const pkey : PEVP_PKEY):integer;
 function EVP_PKEY_get_group_name(const pkey : PEVP_PKEY; gname : PUTF8Char; gname_sz : size_t; gname_len : Psize_t):integer;
 function EVP_PKEY_eq(const a, b : PEVP_PKEY):integer;
function EVP_PKEY_get_bits(const pkey : PEVP_PKEY):integer;
function EVP_PKEY_get_utf8_string_param(const pkey : PEVP_PKEY; key_name : PUTF8Char; str : PUTF8Char; max_buf_sz : size_t; out_len : Psize_t):integer;
function evp_pkey_asn1_ctrl( pkey : PEVP_PKEY; op, arg1 : integer; arg2 : Pointer):integer;
function legacy_asn1_ctrl_to_param( pkey : PEVP_PKEY; op, arg1 : integer; arg2 : Pointer):integer;
function EVP_PKEY_get_default_digest_name( pkey : PEVP_PKEY; mdname : PUTF8Char; mdname_sz : size_t):integer;
procedure mdname2nid(const mdname : PUTF8Char; data : Pointer);
function EVP_PKEY_get1_DH( pkey : PEVP_PKEY):PDH;
function EVP_PKEY_get1_DSA( pkey : PEVP_PKEY):PDSA;

function ossl_evp_pkey_get1_X25519( pkey : PEVP_PKEY):PECX_KEY;
function ossl_evp_pkey_get1_X448( pkey : PEVP_PKEY):PECX_KEY;
function ossl_evp_pkey_get1_ED25519( pkey : PEVP_PKEY):PECX_KEY;
function ossl_evp_pkey_get1_ED448( pkey : PEVP_PKEY):PECX_KEY;
function evp_pkey_get1_ECX_KEY( pkey : PEVP_PKEY; _type : integer):PECX_KEY;
function evp_pkey_get0_ECX_KEY(const pkey : PEVP_PKEY; _type : integer):PECX_KEY;
function EVP_PKEY_get_octet_string_param(const pkey : PEVP_PKEY; key_name : PUTF8Char; buf : PByte; max_buf_sz : size_t; out_len : Psize_t):integer;
function EVP_PKEY_get_bn_param(const pkey : PEVP_PKEY; key_name : PUTF8Char; bn : PPBIGNUM):integer;
function EVP_PKEY_print_private(&out : PBIO;const pkey : PEVP_PKEY; indent : integer; pctx : PASN1_PCTX):integer;
function print_pkey(const pkey : PEVP_PKEY; &out : PBIO; indent, selection : integer;const propquery : PUTF8Char; legacy_print : Tlegacy_print_func; legacy_pctx : PASN1_PCTX):integer;
function print_set_indent( _out : PPBIO; pop_f_prefix : PInteger; saved_indent : Plong; indent : long):integer;
function print_reset_indent( _out : PPBIO; pop_f_prefix : integer; saved_indent : long):integer;
function unsup_alg(_out : PBIO;const pkey : PEVP_PKEY; indent : integer;const kstr : PUTF8Char):integer;
function EVP_PKEY_set_type_str(pkey : PEVP_PKEY;const str : PUTF8Char; len : integer):integer;

const
   EVP_PKEY_size: function(const pkey : PEVP_PKEY):integer = EVP_PKEY_get_size;
implementation

uses
   OpenSSL3.Err, OpenSSL3.common,    openssl3.crypto.params,
   openssl3.crypto.evp,              openssl3.crypto.evp.keymgmt_meth,
   openssl3.crypto.asn1.ameth_lib,   openssl3.crypto.engine.eng_init,
   openssl3.crypto.evp.pmeth_lib,    OpenSSL3.threads_none,
   openssl3.crypto.ex_data,          openssl3.include.openssl.crypto,
   openssl3.crypto.x509,             openssl3.crypto.x509.x_attrib,
   openssl3.crypto.mem,              openssl3.providers.fips.fipsprov,
   openssl3.crypto.provider_core,    openssl3.crypto.dsa.dsa_lib,
   openssl3.crypto.ec.ec_key,        openssl3.crypto.ec.ec_lib,
   OpenSSL3.crypto.rsa_backend,      openssl3.crypto.ec.ec_backend,
   OpenSSL3.crypto.dsa.dsa_backend,  openssl3.crypto.dh.dh_backend,
   openssl3.crypto.o_str,            openssl3.crypto.evp.digest,
   openssl3.crypto.core_namemap,     openssl3.crypto.dh.dh_lib,
   openssl3.crypto.ec.ecx_key,       openssl3.crypto.evp.ctrl_params_translate,
   openssl3.crypto.objects.obj_dat,  openssl3.include.internal.refcount,
   openssl3.crypto.evp.keymgmt_lib,  openssl3.crypto.bio.bio_lib,
   openssl3.crypto.bio.bf_prefix,    openssl3.crypto.encode_decode.encoder_pkey,
   openssl3.crypto.bio.bio_print,    openssl3.crypto.encode_decode.encoder_meth,
   openssl3.crypto.encode_decode.encoder_lib;





function EVP_PKEY_set_type_str(pkey : PEVP_PKEY;const str : PUTF8Char; len : integer):integer;
begin
    Result := pkey_set_type(pkey, nil, EVP_PKEY_NONE, str, len, nil);
end;

function unsup_alg(_out : PBIO;const pkey : PEVP_PKEY; indent : integer;const kstr : PUTF8Char):integer;
begin
    Result := Int( (BIO_indent(_out, indent, 128) > 0)
         and  (BIO_printf(_out, '%s algorithm "%s" unsupported'#10,
                         [kstr, OBJ_nid2ln(pkey.&type)]) > 0));
end;



function print_reset_indent( _out : PPBIO; pop_f_prefix : integer; saved_indent : long):integer;
var
  next : PBIO;
begin
    BIO_set_indent( _out^, saved_indent);
    if pop_f_prefix > 0 then begin
        next := BIO_pop( _out^);
        BIO_free( _out^);
        _out^ := next;
    end;
    Result := 1;
end;



function print_set_indent( _out : PPBIO; pop_f_prefix : PInteger; saved_indent : Plong; indent : long):integer;
var
  i : long;
begin
    pop_f_prefix^ := 0;
    saved_indent^ := 0;
    if indent > 0 then
    begin
        i := BIO_get_indent( _out^);
        saved_indent^ :=  get_result(i < 0 , 0 , i);
        if BIO_set_indent( _out^, indent) <= 0 then
        begin
            _out^ := BIO_push(BIO_new(BIO_f_prefix), _out^);
            if (_out^  = nil) then
                Exit(0);
            pop_f_prefix^ := 1;
        end;
        if BIO_set_indent( _out^, indent) <= 0 then
        begin
            print_reset_indent(_out, pop_f_prefix^, saved_indent^);
            Exit(0);
        end;
    end;
    Result := 1;
end;

function print_pkey(const pkey : PEVP_PKEY; &out : PBIO; indent, selection : integer;const propquery : PUTF8Char; legacy_print : Tlegacy_print_func; legacy_pctx : PASN1_PCTX):integer;
var
    pop_f_prefix : integer;
    saved_indent : long;
    ctx          : POSSL_ENCODER_CTX;
    ret          : integer;
    label _end;
begin
    ctx := nil;
    ret := -2;
    if 0>=print_set_indent(@out, @pop_f_prefix, @saved_indent, indent) then
        Exit(0);
    ctx := OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, 'TEXT', nil,
                                        propquery);
    if OSSL_ENCODER_CTX_get_num_encoders(ctx) <> 0  then
        ret := OSSL_ENCODER_to_bio(ctx, out);
    OSSL_ENCODER_CTX_free(ctx);
    if ret <> -2 then goto _end;
    { legacy fallback }
    if Assigned(legacy_print) then
       ret := legacy_print(out, pkey, 0, legacy_pctx)
    else
        ret := unsup_alg(out, pkey, 0, 'Public Key');
 _end:
    print_reset_indent(@&out, pop_f_prefix, saved_indent);
    Result := ret;
end;

function EVP_PKEY_print_private(&out : PBIO;const pkey : PEVP_PKEY; indent : integer; pctx : PASN1_PCTX):integer;
var
  func: Tlegacy_print_func;
begin
   if (pkey.ameth <> nil ) then
      func := pkey.ameth.priv_print
   else
      func := nil;

   Result := print_pkey(pkey, out, indent, EVP_PKEY_KEYPAIR, nil, func, pctx);
end;


function EVP_PKEY_get_bn_param(const pkey : PEVP_PKEY; key_name : PUTF8Char; bn : PPBIGNUM):integer;
var
  ret : integer;
  params : array[0..1] of TOSSL_PARAM;
  buffer : array[0..2047] of Byte;
  buf : PByte;
  buf_sz : size_t;
  label _err;
begin
    ret := 0;
    buf := nil;
    buf_sz := 0;
    if (key_name = nil) or  (bn = nil) then Exit(0);
    memset(@buffer, 0, sizeof(buffer));
    params[0] := OSSL_PARAM_construct_BN(key_name, @buffer, sizeof(buffer));
    params[1] := OSSL_PARAM_construct_end;
    if 0>=EVP_PKEY_get_params(pkey, @params) then
    begin
        if (0>=OSSL_PARAM_modified(@params))  or  (params[0].return_size = 0) then
            Exit(0);
        buf_sz := params[0].return_size;
        {
         * If it failed because the buffer was too small then allocate the
         * required buffer size and retry.
         }
        buf := OPENSSL_zalloc(buf_sz);
        if buf = nil then Exit(0);
        params[0].data := buf;
        params[0].data_size := buf_sz;
        if 0>=EVP_PKEY_get_params(pkey, @params) then
            goto _err;
    end;
    { Fail if the param was not found }
    if 0>=OSSL_PARAM_modified(@params) then
        goto _err;
    ret := OSSL_PARAM_get_BN(@params, bn);
_err:
    OPENSSL_free(buf);
    Result := ret;
end;

function EVP_PKEY_get_octet_string_param(const pkey : PEVP_PKEY; key_name : PUTF8Char; buf : PByte; max_buf_sz : size_t; out_len : Psize_t):integer;
var
  params : array[0..1] of TOSSL_PARAM;
  ret1, ret2 : integer;
begin
    ret1 := 0; ret2 := 0;
    if key_name = nil then Exit(0);
    params[0] := OSSL_PARAM_construct_octet_string(key_name, buf, max_buf_sz);
    params[1] := OSSL_PARAM_construct_end;
    if ret1 = EVP_PKEY_get_params(pkey, @params) then
       ret2 := OSSL_PARAM_modified(@params);
    if (ret2 >0)  and  (out_len <> nil) then
       out_len^ := params[0].return_size;
    Result := ret1  and  ret2;
end;

function evp_pkey_get0_ECX_KEY(const pkey : PEVP_PKEY; _type : integer):PECX_KEY;
begin
    if EVP_PKEY_get_base_id(pkey) <> _type  then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_A_ECX_KEY);
        Exit(nil);
    end;
    Result := evp_pkey_get_legacy(PEVP_PKEY(pkey));
end;

function evp_pkey_get1_ECX_KEY( pkey : PEVP_PKEY; _type : integer):PECX_KEY;
var
  ret : PECX_KEY;
begin
    ret := PECX_KEY (evp_pkey_get0_ECX_KEY(pkey, _type));
    if (ret <> nil)  and  (0>=ossl_ecx_key_up_ref(ret)) then
        ret := nil;
    Result := ret;
end;

function ossl_evp_pkey_get1_X25519( pkey : PEVP_PKEY):PECX_KEY;
begin
   result := evp_pkey_get1_ECX_KEY(pkey, 1034);
end;


function ossl_evp_pkey_get1_X448( pkey : PEVP_PKEY):PECX_KEY;
begin
   result := evp_pkey_get1_ECX_KEY(pkey, 1035);
end;


function ossl_evp_pkey_get1_ED25519( pkey : PEVP_PKEY):PECX_KEY;
begin
   result := evp_pkey_get1_ECX_KEY(pkey, 1087);
end;


function ossl_evp_pkey_get1_ED448( pkey : PEVP_PKEY):PECX_KEY;
begin
   result := evp_pkey_get1_ECX_KEY(pkey, 1088);
end;


function EVP_PKEY_get1_DH( pkey : PEVP_PKEY):PDH;
var
  ret : PDH;
begin
    ret := evp_pkey_get0_DH_int(pkey);
    if ret <> nil then DH_up_ref(ret);
    Result := ret;
end;

procedure mdname2nid(const mdname : PUTF8Char; data : Pointer);
var
  nid : PInteger;
begin
    nid := PInteger(data);
    if nid^ <> NID_undef then exit;
    nid^ := OBJ_sn2nid(mdname);
    if nid^ = NID_undef then
       nid^ := OBJ_ln2nid(mdname);
end;


function EVP_PKEY_get_default_digest_name( pkey : PEVP_PKEY; mdname : PUTF8Char; mdname_sz : size_t):integer;
var
  nid, rv : integer;
  name : PUTF8Char;
begin
    if pkey.ameth = nil then
       Exit(evp_keymgmt_util_get_deflt_digest_name(pkey.keymgmt,
                                                      pkey.keydata,
                                                      mdname, mdname_sz));
    begin
        nid := NID_undef;
        rv := EVP_PKEY_get_default_digest_nid(pkey, @nid);
        name := get_result(rv > 0 , OBJ_nid2sn(nid) , nil);
        if rv > 0 then
           OPENSSL_strlcpy(mdname, name, mdname_sz);
        Exit(rv);
    end;
end;

function legacy_asn1_ctrl_to_param( pkey : PEVP_PKEY; op, arg1 : integer; arg2 : Pointer):integer;
var
  mdname : array[0..79] of UTF8Char;
  rv, mdnum : integer;
  libctx : POSSL_LIB_CTX;
  md : PEVP_MD;
  nid : integer;
  namemap: POSSL_NAMEMAP;
begin
    if pkey.keymgmt = nil then Exit(0);
    case op of
        ASN1_PKEY_CTRL_DEFAULT_MD_NID:
        begin
            mdname := '';
            rv := EVP_PKEY_get_default_digest_name(pkey, mdname,
                                                      sizeof(mdname));
            if rv > 0 then
            begin
                libctx := ossl_provider_libctx(pkey.keymgmt.prov);
                { Make sure the MD is in the namemap if available }

                nid := NID_undef;
                ERR_set_mark;
                md := EVP_MD_fetch(libctx, mdname, nil);
                ERR_pop_to_mark;
                namemap := ossl_namemap_stored(libctx);
                {
                 * The only reason to fetch the MD was to make sure it is in the
                 * namemap. We can immediately free it.
                 }
                EVP_MD_free(md);
                mdnum := ossl_namemap_name2num(namemap, mdname);
                if mdnum = 0 then Exit(0);
                {
                 * We have the namemap number - now we need to find the
                 * associated nid
                 }
                if 0>=ossl_namemap_doall_names(namemap, mdnum, mdname2nid, @nid) then
                    Exit(0);
                PInteger(arg2)^ := nid;
            end;
            Exit(rv);
        end;
        else
        Exit(-2);
    end;
end;


function evp_pkey_asn1_ctrl( pkey : PEVP_PKEY; op, arg1 : integer; arg2 : Pointer):integer;
begin
    if pkey.ameth = nil then
       Exit(legacy_asn1_ctrl_to_param(pkey, op, arg1, arg2));
    if not Assigned(pkey.ameth.pkey_ctrl) then
       Exit(-2);
    Result := pkey.ameth.pkey_ctrl(pkey, op, arg1, arg2);
end;

function EVP_PKEY_get_utf8_string_param(const pkey : PEVP_PKEY; key_name : PUTF8Char; str : PUTF8Char; max_buf_sz : size_t; out_len : Psize_t):integer;
var
  params : array[0..1] of TOSSL_PARAM;
  ret1, ret2 : integer;
begin
    ret1 := 0; ret2 := 0;
    if key_name = nil then
       Exit(0);
    params[0] := OSSL_PARAM_construct_utf8_string(key_name, str, max_buf_sz);
    params[1] := OSSL_PARAM_construct_end;
    ret1 := EVP_PKEY_get_params(pkey, @params);
    if ret1 > 0  then
       ret2 := OSSL_PARAM_modified(@params);
    if (ret2 > 0) and  (out_len <> nil) then
       out_len^ := params[0].return_size;
    if (ret2 > 0) and  (params[0].return_size = max_buf_sz) then { There was no space for a NUL byte }
        Exit(0);
    { Add a terminating NUL byte for good measure }
    if (ret2 > 0)  and  (str <> nil) then
       str[params[0].return_size] := #0;
    Result := Int( (ret1 > 0)  and  (ret2 > 0) );
end;

function EVP_PKEY_get_bits(const pkey : PEVP_PKEY):integer;
var
  size : integer;
begin
    size := 0;
    if pkey <> nil then
    begin
        size := pkey.cache.bits;
        if (pkey.ameth <> nil)  and  (Assigned(pkey.ameth.pkey_bits)) then
           size := pkey.ameth.pkey_bits(pkey);
    end;
    Result := get_result(size < 0 , 0 , size);
end;

function EVP_PKEY_eq(const a, b : PEVP_PKEY):integer;
var
  ret : integer;
begin
    {
     * This will just call evp_keymgmt_util_match when legacy support
     * is gone.
     }
    { Trivial shortcuts }
    if a = b then Exit(1);
    if (a = nil)  or  (b = nil) then Exit(0);
    if (a.keymgmt <> nil)  or  (b.keymgmt <> nil) then
       Exit(evp_pkey_cmp_any(a, b, (SELECT_PARAMETERS)
                                       or OSSL_KEYMGMT_SELECT_KEYPAIR));
    { All legacy keys }
    if a.&type <> b.&type then Exit(-1);
    if a.ameth <> nil then begin
        { Compare parameters if the algorithm has them }
        if Assigned(a.ameth.param_cmp) then  begin
            ret := a.ameth.param_cmp(a, b);
            if ret <= 0 then Exit(ret);
        end;
        if Assigned(a.ameth.pub_cmp) then
           Exit(a.ameth.pub_cmp(a, b));
    end;
    Result := -2;
end;


function EVP_PKEY_get_group_name(const pkey : PEVP_PKEY; gname : PUTF8Char; gname_sz : size_t; gname_len : Psize_t):integer;
begin
    Exit(EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                          gname, gname_sz, gname_len));
end;


function EVP_PKEY_get_size(const pkey : PEVP_PKEY):integer;
var
  size : integer;
begin
    size := 0;
    if pkey <> nil then begin
        size := pkey.cache.size;
{$IFNDEF FIPS_MODULE}
        if (pkey.ameth <> nil)  and  (Assigned(pkey.ameth.pkey_size)) then
           size := pkey.ameth.pkey_size(pkey);
{$ENDIF}
    end;
    Result := get_result(size < 0 , 0 , size);
end;

function EVP_PKEY_get_default_digest_nid( pkey : PEVP_PKEY; pnid : PInteger):integer;
begin
    Result := evp_pkey_asn1_ctrl(pkey, ASN1_PKEY_CTRL_DEFAULT_MD_NID, 0, pnid);
end;

procedure detect_foreign_key( pkey : PEVP_PKEY);
begin
    case pkey.&type of
      EVP_PKEY_RSA:
          pkey.foreign := int( (pkey.pkey.rsa <> nil) and
                               (ossl_rsa_is_foreign(pkey.pkey.rsa)));
          //break;
  {$IFNDEF OPENSSL_NO_EC}
      EVP_PKEY_SM2,
      EVP_PKEY_EC:
          pkey.foreign := Int( (pkey.pkey.ec <> nil) and
                               (ossl_ec_key_is_foreign(pkey.pkey.ec) > 0));
          //break;
  {$ENDIF}
  {$IFNDEF OPENSSL_NO_DSA}
      EVP_PKEY_DSA:
          pkey.foreign := Int( (pkey.pkey.dsa <> nil) and
                               (ossl_dsa_is_foreign(pkey.pkey.dsa)>0));
          //break;
  {$ENDIF}
  {$IFNDEF OPENSSL_NO_DH}
      EVP_PKEY_DH:
          pkey.foreign := Int( (pkey.pkey.dh <> nil) and
                               (ossl_dh_is_foreign(pkey.pkey.dh)>0));
          //break;
  {$ENDIF}
      else
          pkey.foreign := 0;
          //break;
    end;
end;

function evp_pkey_get0_DH_int(const pkey : PEVP_PKEY):PDH;
begin
    if (pkey.&type <> EVP_PKEY_DH)  and (pkey.&type <> EVP_PKEY_DHX) then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_A_DH_KEY);
        Exit(nil);
    end;
    Result := evp_pkey_get_legacy(PEVP_PKEY(pkey));
end;

function evp_pkey_get0_DSA_int(const pkey : PEVP_PKEY):PDSA;
begin
    if pkey.&type <> EVP_PKEY_DSA then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_EXPECTING_A_DSA_KEY);
        Exit(nil);
    end;
    Result := evp_pkey_get_legacy(PEVP_PKEY(pkey));
end;

function EVP_PKEY_get1_DSA( pkey : PEVP_PKEY):PDSA;
var
  ret : PDSA;
begin
    ret := evp_pkey_get0_DSA_int(pkey);
    if ret <> nil then
       DSA_up_ref(ret);
    Result := ret;
end;



function evp_pkey_cmp_any(const a, b : PEVP_PKEY; selection : integer):integer;
var
  keymgmt1,
  keymgmt2    : PEVP_KEYMGMT;
  keydata1,
  keydata2,
  tmp_keydata : Pointer;
begin
    keymgmt1 := nil;
    keymgmt2 := nil;
    keydata1 := nil;
    keydata2 := nil;
    tmp_keydata := nil;
    { If none of them are provided, this function shouldn't have been called }
    if (not ossl_assert(evp_pkey_is_provided(a))  or  (evp_pkey_is_provided(b))) then
        Exit(-2);
    { For purely provided keys, we just call the keymgmt utility }
    if (evp_pkey_is_provided(a))  and  (evp_pkey_is_provided(b)) then
        Exit(evp_keymgmt_util_match(PEVP_PKEY(a), PEVP_PKEY(b), selection));
    {
     * At this point, one of them is provided, the other not.  This allows
     * us to compare types using legacy NIDs.
     }
    if (evp_pkey_is_legacy(a)) and
       (not EVP_KEYMGMT_is_a(b.keymgmt, OBJ_nid2sn(a.&type))) then
        Exit( -1);               { not the same key type }
    if (evp_pkey_is_legacy(b)) and
       (not EVP_KEYMGMT_is_a(a.keymgmt, OBJ_nid2sn(b.&type))) then
        Exit(-1);               { not the same key type }
    {
     * We've determined that they both are the same keytype, so the next
     * step is to do a bit of cross export to ensure we have keydata for
     * both keys in the same keymgmt.
     }
    keymgmt1 := a.keymgmt;
    keydata1 := a.keydata;
    keymgmt2 := b.keymgmt;
    keydata2 := b.keydata;
    if (keymgmt2 <> nil)  and  (Assigned(keymgmt2.match)) then
    begin
        tmp_keydata := evp_pkey_export_to_provider(PEVP_PKEY(a), nil, @keymgmt2, nil);
        if tmp_keydata <> nil then
        begin
            keymgmt1 := keymgmt2;
            keydata1 := tmp_keydata;
        end;
    end;
    if (tmp_keydata = nil)  and  (keymgmt1 <> nil)  and
        (Assigned(keymgmt1.match)) then
    begin
        tmp_keydata := evp_pkey_export_to_provider(PEVP_PKEY(b), nil, @keymgmt1, nil);
        if tmp_keydata <> nil then
        begin
            keymgmt2 := keymgmt1;
            keydata2 := tmp_keydata;
        end;
    end;
    { If we still don't have matching keymgmt implementations, we give up }
    if keymgmt1 <> keymgmt2 then
       Exit(-2);
    { If the keymgmt implementations are nil, the export failed }
    if keymgmt1 = nil then
       Exit(-2);
    Result := evp_keymgmt_match(keymgmt1, keydata1, keydata2, selection);
end;

function EVP_PKEY_parameters_eq(const a, b : PEVP_PKEY):integer;
begin
    {
     * This will just call evp_keymgmt_util_match when legacy support
     * is gone.
     }
    if (a.keymgmt <> nil)  or  (b.keymgmt <> nil) then
       Exit(evp_pkey_cmp_any(a, b, SELECT_PARAMETERS));
    { All legacy keys }
    if a.&type <> b.&type then
        Exit(-1);
    if (a.ameth <> nil)  and  (Assigned(a.ameth.param_cmp)) then
        Exit(a.ameth.param_cmp(a, b));
    Result := -2;
end;

function EVP_PKEY_missing_parameters(const pkey : PEVP_PKEY):integer;
begin
    if pkey <> nil then
    begin
        if pkey.keymgmt <> nil then
            Exit( not evp_keymgmt_util_has(PEVP_PKEY(pkey), SELECT_PARAMETERS))
        else
        if (pkey.ameth <> nil)  and  (Assigned(pkey.ameth.param_missing)) then
            Exit(pkey.ameth.param_missing(pkey));
    end;
    Result := 0;
end;

function evp_pkey_copy_downgraded(dest : PPEVP_PKEY;const src : PEVP_PKEY):integer;
var
  keymgmt : PEVP_KEYMGMT;
  keydata : Pointer;
  _type : integer;
  keytype : PUTF8Char;
  libctx : POSSL_LIB_CTX;
  pctx : PEVP_PKEY_CTX;
begin
    if not ossl_assert(dest <> nil) then
        Exit(0);
    if (evp_pkey_is_assigned(src))  and  (evp_pkey_is_provided(src)) then
    begin
        keymgmt := src.keymgmt;
        keydata := src.keydata;
        _type := src.&type;
        keytype := nil;
        keytype := EVP_KEYMGMT_get0_name(keymgmt);
        {
         * If the type is EVP_PKEY_NONE, then we have a problem somewhere
         * else in our code.  If it's not one of the well known EVP_PKEY_xxx
         * values, it should at least be EVP_PKEY_KEYMGMT at this point.
         * The check is kept as a safety measure.
         }
        if not ossl_assert(_type <> EVP_PKEY_NONE) then
        begin
            ERR_raise_data(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR,
                          Format('keymgmt key type = %s but legacy type = EVP_PKEY_NONE',
                           [keytype]));
            Exit(0);
        end;
        { Prefer the legacy key type name for error reporting }
        if _type <> EVP_PKEY_KEYMGMT then
           keytype := OBJ_nid2sn(_type);
        { Make sure we have a clean slate to copy into }
        if dest^ = nil then
        begin
            dest^ := EVP_PKEY_new();
            if dest^ = nil then
            begin
                ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                Exit(0);
            end;
        end
        else
        begin
            evp_pkey_free_it(dest^);
        end;
        if EVP_PKEY_set_type(dest^, _type) > 0 then
        begin
            { If the key is typed but empty, we're done }
            if keydata = nil then
                Exit(1);
            if not Assigned(dest^.ameth.import_from) then
            begin
                ERR_raise_data(ERR_LIB_EVP, EVP_R_NO_IMPORT_FUNCTION,
                            Format('key type = %s', [keytype]));
            end
            else
            begin
                {
                 * We perform the export in the same libctx as the keymgmt
                 * that we are using.
                 }
                libctx := ossl_provider_libctx(keymgmt.prov);
                pctx :=  EVP_PKEY_CTX_new_from_pkey(libctx, dest^, nil);
                if pctx = nil then
                   ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
                if (pctx <> nil)
                     and  (evp_keymgmt_export(keymgmt, keydata,
                                          OSSL_KEYMGMT_SELECT_ALL,
                                          dest^.ameth.import_from,
                                          pctx)>0)  then
                begin
                    { Synchronize the dirty count }
                    dest^.dirty_cnt_copy := dest^.ameth.dirty_cnt(dest^);
                    EVP_PKEY_CTX_free(pctx);
                    Exit(1);
                end;
                EVP_PKEY_CTX_free(pctx);
            end;
            ERR_raise_data(ERR_LIB_EVP, EVP_R_KEYMGMT_EXPORT_FAILURE,
                          Format('key type = %s', [keytype]));
        end;
    end;
    Result := 0;
end;

procedure find_ameth(const name : PUTF8Char; data : Pointer);
var
  str : PPUTF8Char;
begin
{$POINTERMATH ON}
     str := data;
    {
     * The error messages from pkey_set_type() are uninteresting here,
     * and misleading.
     }
    ERR_set_mark();
    if pkey_set_type(nil, nil, EVP_PKEY_NONE, name, Length(name),
                      nil)>0  then
    begin
        if str[0] = nil then
            str[0] := name
        else if (str[1] = nil) then
            str[1] := name;
    end;
    ERR_pop_to_mark();
{$POINTERMATH OFF}
end;


procedure evp_pkey_free_legacy( x : PEVP_PKEY);
var
  ameth : PEVP_PKEY_ASN1_METHOD;
  tmpe  : PENGINE;
begin
    ameth := x.ameth;
    tmpe := nil;
    if (ameth = nil)  and  (x.legacy_cache_pkey.ptr <> nil) then
       ameth := EVP_PKEY_asn1_find(@tmpe, x.&type);
    if ameth <> nil then
    begin
        if x.legacy_cache_pkey.ptr <> nil then
        begin
            {
             * We should never have both a legacy origin key, and a key in the
             * legacy cache.
             }
            assert(x.pkey.ptr = nil);
            {
             * For the purposes of freeing we make the legacy cache look like
             * a legacy origin key.
             }
            x.pkey := x.legacy_cache_pkey;
            x.legacy_cache_pkey.ptr := nil;
        end;
        if Assigned(ameth.pkey_free) then
           ameth.pkey_free(x);
        x.pkey.ptr := nil;
    end;
{$IFNDEF OPENSSL_NO_ENGINE}
    ENGINE_finish(tmpe);
    ENGINE_finish(x.engine);
    x.engine := nil;
    ENGINE_finish(x.pmeth_engine);
    x.pmeth_engine := nil;
{$ENDIF}
end;

procedure evp_pkey_free_it( x : PEVP_PKEY);
begin
    evp_keymgmt_util_clear_operation_cache(x, 1);
{$IFNDEF FIPS_MODULE}
    evp_pkey_free_legacy(x);
{$ENDIF}
    if x.keymgmt <> nil then
    begin
        evp_keymgmt_freedata(x.keymgmt, x.keydata);
        EVP_KEYMGMT_free(x.keymgmt);
        x.keymgmt := nil;
        x.keydata := nil;
    end;
    x.&type := EVP_PKEY_NONE;
end;

function pkey_set_type(pkey : PEVP_PKEY; e : PENGINE; _type : integer;const str : PUTF8Char; len : integer; keymgmt : PEVP_KEYMGMT):integer;
var
  ameth : PEVP_PKEY_ASN1_METHOD;
  eptr : PPENGINE;
  free_it,
  check :Boolean;
begin
{$IFNDEF FIPS_MODULE}
   ameth := nil;
   if (e = nil) then
      eptr := @e
   else
      eptr :=  nil;
{$ENDIF}
    {
     * The setups can't set both legacy and provider side methods.
     * It is forbidden
     }
    if (not ossl_assert( (_type = EVP_PKEY_NONE)  or  (keymgmt = nil) ) )  or
       (not ossl_assert( (e = nil)  or  (keymgmt = nil)) ) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    if pkey <> nil then
    begin
        free_it := Boolean(0);
{$IFNDEF FIPS_MODULE}
        free_it := (free_it) or  (pkey.pkey.ptr <> nil);
{$ENDIF}
        free_it := (free_it)  or (pkey.keydata <> nil);
        if free_it then
           evp_pkey_free_it(pkey);
{$IFNDEF FIPS_MODULE}
        {
         * If key type matches and a method exists then this lookup has
         * succeeded once so just indicate success.
         }
        if (pkey.&type <> EVP_PKEY_NONE)
             and (_type = pkey.save_type)
             and (pkey.ameth <> nil) then Exit(1);
{$IFNDEF OPENSSL_NO_ENGINE}
        { If we have ENGINEs release them }
        ENGINE_finish(pkey.engine);
        pkey.engine := nil;
        ENGINE_finish(pkey.pmeth_engine);
        pkey.pmeth_engine := nil;
{$ENDIF}
{$ENDIF}
    end;
{$IFNDEF FIPS_MODULE}
    if str <> nil then
       ameth := EVP_PKEY_asn1_find_str(eptr, str, len)
    else
    if (_type <> EVP_PKEY_NONE) then
        ameth := EVP_PKEY_asn1_find(eptr, _type);
{$IFNDEF OPENSSL_NO_ENGINE}
    if (pkey = nil)  and  (eptr <> nil) then
       ENGINE_finish(e);
{$ENDIF}
{$ENDIF}
    begin
        check := Boolean(1);
{$IFNDEF FIPS_MODULE}
        check := (check)  and  (ameth = nil);
{$ENDIF}
        check := (check)  and (keymgmt = nil);
        if check then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_UNSUPPORTED_ALGORITHM);
            Exit(0);
        end;
    end;
    if pkey <> nil then
    begin
        if (keymgmt <> nil)  and  (0>= EVP_KEYMGMT_up_ref(keymgmt)) then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
            Exit(0);
        end;
        pkey.keymgmt := keymgmt;
        pkey.save_type := _type;
        pkey.&type := _type;
{$IFNDEF FIPS_MODULE}
        {
         * If the internal 'origin' key is provider side, don't save |ameth|.
         * The main reason is that |ameth| is one factor to detect that the
         * internal 'origin' key is a legacy one.
         }
        if keymgmt = nil then
           pkey.ameth := ameth;
        {
         * The EVP_PKEY_ASN1_METHOD |pkey_id| retains its legacy key purpose
         * for any key type that has a legacy implementation, regardless of
         * if the internal key is a legacy or a provider side one.  When
         * there is no legacy implementation for the key, the type becomes
         * EVP_PKEY_KEYMGMT, which indicates that one should be cautious
         * with functions that expect legacy internal keys.
         }
        if ameth <> nil then
        begin
            if _type = EVP_PKEY_NONE then
                pkey.&type := ameth.pkey_id;
        end
        else
        begin
            pkey.&type := EVP_PKEY_KEYMGMT;
        end;
{$IFNDEF OPENSSL_NO_ENGINE}
        if (eptr = nil)  and  (e <> nil)  and  (0>= ENGINE_init(e)) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_INITIALIZATION_ERROR);
            Exit(0);
        end;
{$ENDIF}
        pkey.engine := e;
{$ENDIF}
    end;
    Result := 1;
end;

function EVP_PKEY_set_type( pkey : PEVP_PKEY; _type : integer):integer;
begin
    Result := pkey_set_type(pkey, nil, _type, nil, -1, nil);
end;



function evp_pkey_export_to_provider(pk : PEVP_PKEY; libctx : POSSL_LIB_CTX; keymgmt : PPEVP_KEYMGMT;const propquery : PUTF8Char):Pointer;
var
  allocated_keymgmt,
  tmp_keymgmt       : PEVP_KEYMGMT;
  keydata           : Pointer;
  check             : integer;
  ctx               : PEVP_PKEY_CTX;
  op                : POP_CACHE_ELEM;
  tmp_keydata       : Pointer;
  label _end;
begin
    allocated_keymgmt := nil;
    tmp_keymgmt := nil;
    keydata := nil;
    if pk = nil then Exit(nil);
    { No key data => nothing to export }
    check := 1;
{$IFNDEF FIPS_MODULE}
    check := int( (check>0)  and  (pk.pkey.ptr = nil));
{$ENDIF}
    check := Int( (check>0)  and  (pk.keydata = nil));
    if check > 0 then
       Exit(nil);
{$IFNDEF FIPS_MODULE}
    if pk.pkey.ptr <> nil then
    begin
        {
         * If the legacy key doesn't have an dirty counter or export function,
         * give up
         }
        if (Assigned(pk.ameth.dirty_cnt))  or
           (Assigned(pk.ameth.export_to)) then
            Exit(nil);
    end;
{$ENDIF}
    if keymgmt <> nil then
    begin
        tmp_keymgmt := keymgmt^;
        keymgmt^ := nil;
    end;
    {
     * If no keymgmt was given or found, get a default keymgmt.  We do so by
     * letting EVP_PKEY_CTX_new_from_pkey() do it for us, then we steal it.
     }
    if tmp_keymgmt = nil then
    begin
        ctx := EVP_PKEY_CTX_new_from_pkey(libctx, pk, propquery);
        if ctx = nil then
           goto _end ;
        tmp_keymgmt := ctx.keymgmt;
        ctx.keymgmt := nil;
        EVP_PKEY_CTX_free(ctx);
    end;
    { If there's still no keymgmt to be had, give up }
    if tmp_keymgmt = nil then
       goto _end ;
{$IFNDEF FIPS_MODULE}
    if pk.pkey.ptr <> nil then begin
        {
         * If the legacy 'origin' hasn't changed since last time, we try
         * to find our keymgmt in the operation cache.  If it has changed,
         * |i| remains zero, and we will clear the cache further down.
         }
        if pk.ameth.dirty_cnt(pk) = pk.dirty_cnt_copy then
        begin
            if 0>= CRYPTO_THREAD_read_lock(pk.lock) then
                goto _end ;
            op := evp_keymgmt_util_find_operation_cache(pk, tmp_keymgmt);
            {
             * If |tmp_keymgmt| is present in the operation cache, it means
             * that export doesn't need to be redone.  In that case, we take
             * token copies of the cached pointers, to have token success
             * values to return.
             }
            if (op <> nil)  and  (op.keymgmt <> nil) then
            begin
                keydata := op.keydata;
                CRYPTO_THREAD_unlock(pk.lock);
                goto _end ;
            end;
            CRYPTO_THREAD_unlock(pk.lock);
        end;
        { Make sure that the keymgmt key type matches the legacy NID }
        if not EVP_KEYMGMT_is_a(tmp_keymgmt, OBJ_nid2sn(pk.&type)) then
            goto _end ;
        keydata := evp_keymgmt_newdata(tmp_keymgmt);
        if keydata = nil then
            goto _end ;
        if 0>= pk.ameth.export_to(pk, keydata, tmp_keymgmt.import,
                                  libctx, propquery) then
        begin
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata := nil;
            goto _end ;
        end;
        {
         * If the dirty counter changed since last time, then clear the
         * operation cache.  In that case, we know that |i| is zero.  Just
         * in case this is a re-export, we increment then decrement the
         * keymgmt reference counter.
         }
        if 0>= EVP_KEYMGMT_up_ref(tmp_keymgmt) then
        begin  { PostInc(refcnt) }
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata := nil;
            goto _end ;
        end;
        if 0>= CRYPTO_THREAD_write_lock(pk.lock) then
            goto _end ;
        if (pk.ameth.dirty_cnt(pk) <> pk.dirty_cnt_copy)
           and  (0>= evp_keymgmt_util_clear_operation_cache(pk, 0))  then
        begin
            CRYPTO_THREAD_unlock(pk.lock);
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata := nil;
            EVP_KEYMGMT_free(tmp_keymgmt);
            goto _end ;
        end;
        EVP_KEYMGMT_free(tmp_keymgmt); { PostDec(refcnt) }
        { Check to make sure some other thread didn't get there first }
        op := evp_keymgmt_util_find_operation_cache(pk, tmp_keymgmt);
        if (op <> nil)  and  (op.keymgmt <> nil) then
        begin
            tmp_keydata := op.keydata;
            CRYPTO_THREAD_unlock(pk.lock);
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata := tmp_keydata;
            goto _end ;
        end;
        { Add the new export to the operation cache }
        if 0>= evp_keymgmt_util_cache_keydata(pk, tmp_keymgmt, keydata) then
        begin
            CRYPTO_THREAD_unlock(pk.lock);
            evp_keymgmt_freedata(tmp_keymgmt, keydata);
            keydata := nil;
            goto _end ;
        end;
        { Synchronize the dirty count }
        pk.dirty_cnt_copy := pk.ameth.dirty_cnt(pk);
        CRYPTO_THREAD_unlock(pk.lock);
        goto _end ;
    end;
{$endif}  { FIPS_MODULE }
    keydata := evp_keymgmt_util_export_to_provider(pk, tmp_keymgmt);
 _end:
    {
     * If nothing was exported, |tmp_keymgmt| might point at a freed
     * EVP_KEYMGMT, so we clear it to be safe.  It shouldn't be useful for
     * the caller either way in that case.
     }
    if keydata = nil then
       tmp_keymgmt := nil;
    if keymgmt <> nil then
       keymgmt^ := tmp_keymgmt;
    EVP_KEYMGMT_free(allocated_keymgmt);
    Result := keydata;
end;



procedure EVP_PKEY_free( x : PEVP_PKEY);
var
  i : integer;
begin
    if x = nil then
       exit;
    CRYPTO_DOWN_REF(x.references, i, x.lock);
    REF_PRINT_COUNT('EVP_PKEY', x);
    if i > 0 then exit;
    REF_ASSERT_ISNT(i < 0);
    evp_pkey_free_it(x);
{$IFNDEF FIPS_MODULE}
    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_EVP_PKEY, x, @x.ex_data);
{$ENDIF}
    CRYPTO_THREAD_lock_free(x.lock);
{$IFNDEF FIPS_MODULE}
    sk_X509_ATTRIBUTE_pop_free(x.attributes, X509_ATTRIBUTE_free);
{$ENDIF}
    OPENSSL_free(x);
end;


function EVP_PKEY_new:PEVP_PKEY;
var
  ret : PEVP_PKEY;
  label _err;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.&type := EVP_PKEY_NONE;
    ret.save_type := EVP_PKEY_NONE;
    ret.references := 1;
    ret.lock := CRYPTO_THREAD_lock_new();
    if ret.lock = nil then
    begin
        EVPerr(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
{$IFNDEF FIPS_MODULE}
    ret.save_parameters := 1;
    if 0>= CRYPTO_new_ex_data(CRYPTO_EX_INDEX_EVP_PKEY, ret, @ret.ex_data) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
{$ENDIF}
    Exit(ret);
 _err:
    CRYPTO_THREAD_lock_free(ret.lock);
    OPENSSL_free(ret);
    Result := nil;
end;


function EVP_PKEY_set_type_by_keymgmt( pkey : PEVP_PKEY; keymgmt : PEVP_KEYMGMT):integer;
var
  str : array[0..1] of PUTF8Char;

{$IFNDEF FIPS_MODULE}
   EVP_PKEY_TYPE_STR: PUTF8Char;
   function EVP_PKEY_TYPE_STRLEN: int;
   begin
       Result := get_result(str[0] = nil , -1 , int(Length(str[0])));
   end;
{$ELSE}
  const EVP_PKEY_TYPE_STR = nil;
        EVP_PKEY_TYPE_STRLEN = -1;
{$ENDIF}
begin
    {
     * Find at most two strings that have an associated EVP_PKEY_ASN1_METHOD
     * Ideally, only one should be found.  If two (or more) are found, the
     * match is ambiguous.  This should never happen, but...
     }
{$IFNDEF FIPS_MODULE}
    str[0] := nil;
    str[1] := nil;

     EVP_PKEY_TYPE_STR := str[0];

    if (0>= EVP_KEYMGMT_names_do_all(keymgmt, find_ameth, @str))  or
       (str[1] <> nil)  then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
{$ENDIF}

    Exit(pkey_set_type(pkey, nil, EVP_PKEY_NONE,
                         EVP_PKEY_TYPE_STR, EVP_PKEY_TYPE_STRLEN,
                         keymgmt));
//#undef EVP_PKEY_TYPE_STR
//#undef EVP_PKEY_TYPE_STRLEN
end;

function EVP_PKEY_up_ref( pkey : PEVP_PKEY):integer;
var
  i : integer;
begin
    if CRYPTO_UP_REF(pkey.references, i, pkey.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('EVP_PKEY', pkey);
    REF_ASSERT_ISNT(i < 2);
    Result := get_result((i > 1) , 1 , 0);
end;

function evp_pkey_type2name( _type : integer):PUTF8Char;
var
    i                  : size_t;
begin
    for i := 0 to Length(standard_name2type)-1 do
    begin
        if _type = int (standard_name2type[i].id) then
           Exit(standard_name2type[i].ptr);
    end;
    Result := OBJ_nid2sn(_type);
end;

function EVP_PKEY_copy_parameters(_to : PEVP_PKEY;from : PEVP_PKEY):integer;
var
    downgraded_from : PEVP_PKEY;
    ok              : integer;
    to_keymgmt      : PEVP_KEYMGMT;
    from_keydata    : Pointer;
    label _end;
begin
    {
     * Clean up legacy stuff from this function when legacy support is gone.
     }
    downgraded_from := nil;
    ok := 0;
    {
     * If |to| is a legacy key and |from| isn't, we must make a downgraded
     * copy of |from|.  If that fails, this function fails.
     }
    if (evp_pkey_is_legacy(_to))  and  (evp_pkey_is_provided(from))  then
    begin
        if 0>= evp_pkey_copy_downgraded(@downgraded_from, from) then
            goto _end ;
        from := downgraded_from;
    end;
    {
     * Make sure |to| is typed.  Content is less important at this early
     * stage.
     *
     * 1.  If |to| is untyped, assign |from|'s key type to it.
     * 2.  If |to| contains a legacy key, compare its |type| to |from|'s.
     *     (|from| was already downgraded above)
     *
     * If |to| is a provided key, there's nothing more to do here, functions
     * like evp_keymgmt_util_copy() and evp_pkey_export_to_provider() called
     * further down help us find out if they are the same or not.
     }
    if evp_pkey_is_blank(_to) then
    begin
        if evp_pkey_is_legacy(from) then
        begin
            if EVP_PKEY_set_type(_to, from.&type) = 0 then
                goto _end ;
        end
        else
        begin
            if EVP_PKEY_set_type_by_keymgmt(_to, from.keymgmt) = 0  then
                goto _end ;
        end;
    end
    else
    if (evp_pkey_is_legacy(_to))then
    begin
        if _to.&type <> from.&type then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
            goto _end ;
        end;
    end;
    if EVP_PKEY_missing_parameters(from) > 0 then
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_MISSING_PARAMETERS);
        goto _end ;
    end;
    if 0>= EVP_PKEY_missing_parameters(_to) then
    begin
        if EVP_PKEY_parameters_eq(_to, from) = 1 then
            ok := 1
        else
            ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_PARAMETERS);
        goto _end ;
    end;
    { For purely provided keys, we just call the keymgmt utility }
    if (_to.keymgmt <> nil)  and  (from.keymgmt <> nil) then
    begin
        ok := evp_keymgmt_util_copy(_to, PEVP_PKEY(from), SELECT_PARAMETERS);
        goto _end ;
    end;
    {
     * If |to| is provided, we know that |from| is legacy at this point.
     * Try exporting |from| to |to|'s keymgmt, then use evp_keymgmt_dup()
     * to copy the appropriate data to |to|'s keydata.
     * We cannot override existing data so do it only if there is no keydata
     * in |to| yet.
     }
    if (_to.keymgmt <> nil)  and  (_to.keydata = nil) then
    begin
        to_keymgmt := _to.keymgmt;
        from_keydata :=
            evp_pkey_export_to_provider(PEVP_PKEY(from), nil, @to_keymgmt,
                                        nil);
        {
         * If we get a nil, it could be an internal error, or it could be
         * that there's a key mismatch.  We're pretending the latter...
         }
        if from_keydata = nil then
           ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES)
        else
        begin
            _to.keydata := evp_keymgmt_dup(_to.keymgmt,
                                                from_keydata,
                                                SELECT_PARAMETERS);
            ok := int(_to.keydata <> nil);
        end;
        goto _end ;
    end;
    { Both keys are legacy }
    if (from.ameth <> nil)  and  (Assigned(from.ameth.param_copy)) then
       ok := from.ameth.param_copy(_to, from);
 _end:
    EVP_PKEY_free(downgraded_from);
    Result := ok;
end;


function EVP_PKEY_get0_DSA(const pkey : PEVP_PKEY):PDSA;
begin
    Result := evp_pkey_get0_DSA_int(pkey);
end;



function EVP_PKEY_get0_DH(const pkey : PEVP_PKEY):PDH;
begin
    Result := evp_pkey_get0_DH_int(pkey);
end;

function evp_pkey_get_legacy( pk : PEVP_PKEY):Pointer;
var
    tmp_copy : PEVP_PKEY;
    ret      : Pointer;
    label _err;
begin
    tmp_copy := nil;
    ret := nil;
    if not ossl_assert(pk <> nil ) then
        Exit(nil);
    {
     * If this isn't an assigned provider side key, we just use any existing
     * origin legacy key.
     }
    if not evp_pkey_is_assigned(pk ) then
        Exit(nil);
    if not evp_pkey_is_provided(pk ) then
        Exit(pk.pkey.ptr);
    if 0>= CRYPTO_THREAD_read_lock(pk.lock ) then
        Exit(nil);
    ret := pk.legacy_cache_pkey.ptr;
    if 0>= CRYPTO_THREAD_unlock(pk.lock ) then
        Exit(nil);
    if ret <> nil then Exit(ret);
    if 0>= evp_pkey_copy_downgraded(@tmp_copy, pk ) then
        Exit(nil);
    if 0>= CRYPTO_THREAD_write_lock(pk.lock ) then
        goto _err ;
    { Check again in case some other thread has updated it in the meantime }
    ret := pk.legacy_cache_pkey.ptr;
    if ret = nil then
    begin
        { Steal the legacy key reference from the temporary copy }
        pk.legacy_cache_pkey.ptr := tmp_copy.pkey.ptr;
        ret := pk.legacy_cache_pkey.ptr;
        tmp_copy.pkey.ptr := nil;
    end;
    if 0>= CRYPTO_THREAD_unlock(pk.lock)  then
    begin
        ret := nil;
        goto _err ;
    end;
 _err:
    EVP_PKEY_free(tmp_copy);
    Result := ret;
end;

function EVP_PKEY_set1_DSA( pkey : PEVP_PKEY; const key : Pointer):integer;
var
  ret : integer;
begin
    ret := EVP_PKEY_assign_DSA(pkey, key);
    if ret>0 then
       DSA_up_ref(key);
    Result := ret;
end;


function EVP_PKEY_assign( pkey : PEVP_PKEY; _type : integer; key : Pointer):integer;
var
  pktype : integer;
  group : PEC_GROUP;
  curve : integer;
begin
{$IFNDEF OPENSSL_NO_EC}
    pktype := EVP_PKEY_type(_type);
    if (key <> nil)  and ( (pktype = EVP_PKEY_EC)  or  (pktype = EVP_PKEY_SM2) ) then
    begin
         group := EC_KEY_get0_group(key);
        if group <> nil then
        begin
            curve := EC_GROUP_get_curve_name(group);
            {
             * Regardless of what is requested the SM2 curve must be SM2 type,
             * and non SM2 curves are EC type.
             }
            if (curve = NID_sm2)  and  (pktype = EVP_PKEY_EC) then
               _type := EVP_PKEY_SM2
            else
            if(curve <> NID_sm2)  and  (pktype = EVP_PKEY_SM2) then
                _type := EVP_PKEY_EC;
        end;
    end;
{$ENDIF}
    if (pkey = nil)  or  (0>= EVP_PKEY_set_type(pkey, _type)) then
        Exit(0);
    pkey.pkey.ptr := key;
    detect_foreign_key(pkey);
    Result := int(key <> nil);
end;

function EVP_PKEY_type( &type : integer):integer;
var
  ret : integer;
  ameth : PEVP_PKEY_ASN1_METHOD;
  e : PENGINE;
begin
    ameth := EVP_PKEY_asn1_find(@e, &type);
    if Assigned(ameth) then
       ret := ameth.pkey_id
    else
        ret := NID_undef;
{$IFNDEF OPENSSL_NO_ENGINE}
    ENGINE_finish(e);
{$ENDIF}
    Result := ret;
end;


function EVP_PKEY_get_base_id(const pkey : PEVP_PKEY):integer;
begin
    Result := EVP_PKEY_type(pkey.&type);
end;

function EVP_PKEY_get_params(const pkey : PEVP_PKEY; params : POSSL_PARAM):integer;
begin
    if pkey <> nil then
    begin
        if evp_pkey_is_provided(pkey) then
            Exit(evp_keymgmt_get_params(pkey.keymgmt, pkey.keydata, params))
{$IFNDEF FIPS_MODULE}
        else if (evp_pkey_is_legacy(pkey)) then
            Exit(evp_pkey_get_params_to_ctrl(pkey, params));
{$ENDIF}
    end;
    ERR_raise(ERR_LIB_EVP, EVP_R_INVALID_KEY);
    Result := 0;
end;

function EVP_PKEY_get_int_param(const pkey : PEVP_PKEY; key_name : PUTF8Char; _out : Pinteger):integer;
var
  params : array[0..1] of TOSSL_PARAM;
begin
    if key_name = nil then Exit(0);
    params[0] := OSSL_PARAM_construct_int(key_name, _out);
    params[1] := OSSL_PARAM_construct_end();
    Result := int( ( EVP_PKEY_get_params(pkey, @params) > 0 ) and
                   ( OSSL_PARAM_modified(@params) > 0  ));
end;

function EVP_PKEY_get_id(const pkey : PEVP_PKEY):integer;
begin
    Result := pkey.&type;
end;

function EVP_PKEY_get_security_bits(const pkey : PEVP_PKEY):integer;
var
  size : integer;
begin
    size := 0;
    if pkey <> nil then begin
        size := pkey.cache.security_bits;
        if (pkey.ameth <> nil)  and  Assigned(pkey.ameth.pkey_security_bits) then
           size := pkey.ameth.pkey_security_bits(pkey);
    end;
    Result := get_result( size < 0 , 0 , size);
end;


function evp_pkey_name2type(const name : PUTF8Char):integer;
var
  &type : integer;
  i : size_t;
  n: int;
begin

    n := Length(standard_name2type);
    for i := 0 to n - 1 do
    begin
        if strcasecmp(name, standard_name2type[i].ptr) = 0 then
            Exit(int(standard_name2type[i].id));
    end;
    &type := EVP_PKEY_type(OBJ_sn2nid(name));
    if &type <> NID_undef then
        Exit(&type);
    Result := EVP_PKEY_type(OBJ_ln2nid(name));
end;

function EVP_PKEY_is_a(const pkey : PEVP_PKEY; name : PUTF8Char): Boolean;
var
  _type : integer;
begin
    if pkey.keymgmt = nil then
    begin
        _type := evp_pkey_name2type(name);
        Exit(pkey.&type = _type);
    end;
    Result := EVP_KEYMGMT_is_a(pkey.keymgmt, name);
end;

end.
