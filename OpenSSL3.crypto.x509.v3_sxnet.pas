unit OpenSSL3.crypto.x509.v3_sxnet;

interface
uses OpenSSL.Api;

{$define SXNET_TEST}

function SXNET_it:PASN1_ITEM;
function sxnet_i2r( method : PX509V3_EXT_METHOD; sx : PSXNET; _out : PBIO; indent : integer):integer;
function sxnet_v2i( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PSXNET;
function SXNET_add_id_asc(psx : PPSXNET;const zone, user : PUTF8Char; userlen : integer):integer;
function SXNET_add_id_INTEGER(psx : PPSXNET; zone : PASN1_INTEGER;const user : PUTF8Char; userlen : integer):integer;
function SXNET_get_id_INTEGER( sx : PSXNET; zone : PASN1_INTEGER):PASN1_OCTET_STRING;

function d2i_SXNET(a : PPSXNET;const _in : PPByte; len : long):PSXNET;
function i2d_SXNET(const a : PSXNET; _out : PPByte):integer;
function SXNET_new:PSXNET;
procedure SXNET_free( a : PSXNET);

function d2i_SXNETID(a : PPSXNETID;const _in : PPByte; len : long):PSXNETID;
function i2d_SXNETID(const a : PSXNETID; _out : PPByte):integer;
function SXNETID_new:PSXNETID;
procedure SXNETID_free( a : PSXNETID);
function SXNETID_it:PASN1_ITEM;

var
   ossl_v3_sxnet: TX509V3_EXT_METHOD;
   SXNET_seq_tt, SXNETID_seq_tt: array of TASN1_TEMPLATE;

implementation
uses openssl3.crypto.bio.bio_print, openssl3.crypto.asn1.a_int,
     openssl3.crypto.x509v3, OpenSSL3.crypto.x509.v3_utl,
     openssl3.crypto.mem, openssl3.crypto.asn1.a_print,
     openssl3.crypto.asn1.a_octet,  openssl3.crypto.asn1.tasn_typ,
     openssl3.crypto.asn1.tasn_dec, openssl3.crypto.asn1.tasn_enc,
     openssl3.crypto.asn1.tasn_new, openssl3.crypto.asn1.tasn_fre,
     OpenSSL3.openssl.conf, OpenSSL3.Err;






function SXNETID_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
   local_it := get_ASN1_ITEM($1, 16, @SXNETID_seq_tt,
                         sizeof(SXNETID_seq_tt) div sizeof(TASN1_TEMPLATE),
             Pointer(0) , sizeof(SXNETID), ' SXNETID');

   Result := @local_it;
end;

function d2i_SXNETID(a : PPSXNETID;const _in : PPByte; len : long):PSXNETID;
begin
 Result := PSXNETID(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, SXNETID_it));
end;


function i2d_SXNETID(const a : PSXNETID; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, SXNETID_it);
end;


function SXNETID_new:PSXNETID;
begin
   Result := PSXNETID(ASN1_item_new(SXNETID_it));
end;


procedure SXNETID_free( a : PSXNETID);
begin
 ASN1_item_free(PASN1_VALUE( a), SXNETID_it);
end;



function SXNET_get_id_INTEGER( sx : PSXNET; zone : PASN1_INTEGER):PASN1_OCTET_STRING;
var
  id : PSXNETID;
  i : integer;
begin
    for i := 0 to sk_SXNETID_num(sx.ids)-1 do
    begin
        id := sk_SXNETID_value(sx.ids, i);
        if 0>= ASN1_INTEGER_cmp(id.zone, zone ) then
            Exit(id.user);
    end;
    Result := nil;
end;


function d2i_SXNET(a : PPSXNET;const _in : PPByte; len : long):PSXNET;
begin
   Result := PSXNET(ASN1_item_d2i(PPASN1_VALUE( a), _in, len, SXNET_it));
end;


function i2d_SXNET(const a : PSXNET; _out : PPByte):integer;
begin
   Result := ASN1_item_i2d(PASN1_VALUE(a), _out, SXNET_it);
end;


function SXNET_new:PSXNET;
begin
   Result := PSXNET(ASN1_item_new(SXNET_it));
end;


procedure SXNET_free( a : PSXNET);
begin
   ASN1_item_free(PASN1_VALUE( a), SXNET_it);
end;

function SXNET_add_id_INTEGER(psx : PPSXNET; zone : PASN1_INTEGER;const user : PUTF8Char; userlen : integer):integer;
var
  sx : PSXNET;
  id : PSXNETID;
  label _err;
begin
    sx := nil;
    id := nil;
    if (psx = nil)  or  (zone = nil)  or  (user = nil) then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_NULL_ARGUMENT);
        Exit(0);
    end;
    if userlen = -1 then
       userlen := Length(user);
    if userlen > 64 then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_USER_TOO_LONG);
        Exit(0);
    end;
    if psx^ = nil then
    begin
        sx := SXNET_new();
        if (sx = nil) then
            goto _err ;
        if 0>= ASN1_INTEGER_set(sx.version, 0 ) then
            goto _err ;
    end
    else
        sx := psx^;
    if SXNET_get_id_INTEGER(sx, zone) <> nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_DUPLICATE_ZONE_ID);
        if psx^ = nil then
           SXNET_free(sx);
        Exit(0);
    end;
    id := SXNETID_new();
    if id = nil then
        goto _err ;
    if 0>= ASN1_OCTET_STRING_set(id.user, PByte( user), userlen) then
        goto _err ;
    if 0>= sk_SXNETID_push(sx.ids, id) then
        goto _err ;
    id.zone := zone;
    psx^ := sx;
    Exit(1);
 _err:
    ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
    SXNETID_free(id);
    if psx^ = nil then
       SXNET_free(sx);
    Result := 0;
end;

function SXNET_add_id_asc(psx : PPSXNET;const zone, user : PUTF8Char; userlen : integer):integer;
var
  izone : PASN1_INTEGER;
begin
    izone := s2i_ASN1_INTEGER(nil, zone );
    if izone  = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, X509V3_R_ERROR_CONVERTING_ZONE);
        Exit(0);
    end;
    Result := SXNET_add_id_INTEGER(psx, izone, user, userlen);
end;




function sxnet_v2i( method : PX509V3_EXT_METHOD; ctx : PX509V3_CTX; nval : Pstack_st_CONF_VALUE):PSXNET;
var
  cnf : PCONF_VALUE;
  sx : PSXNET;
  i : integer;
begin
    sx := nil;
    for i := 0 to sk_CONF_VALUE_num(nval)-1 do
    begin
        cnf := sk_CONF_VALUE_value(nval, i);
        if 0>= SXNET_add_id_asc(@sx, cnf.name, cnf.value, -1) then
            Exit(nil);
    end;
    Result := sx;
end;



function sxnet_i2r( method : PX509V3_EXT_METHOD; sx : PSXNET; _out : PBIO; indent : integer):integer;
var
  v : int64;
  tmp : PUTF8Char;
  id : PSXNETID;
  i : integer;
  vl : long;
begin
    {
     * Since we add 1 to the version number to display it, we don't support
     * LONG_MAX since that would cause on overflow.
     }
    if (0>= ASN1_INTEGER_get_int64(@v, sx.version))  or  (v >= LONG_MAX)
             or  (v < LONG_MIN) then
    begin
        BIO_printf(_out, ' %*sVersion: <unsupported>' , [indent, ' '] );
    end
    else
    begin
        vl := long(v);
        BIO_printf(_out, ' %*sVersion: %ld ($ %lX)' , [indent, ' ' , vl + 1, vl]);
    end;
    for i := 0 to sk_SXNETID_num(sx.ids)-1 do
    begin
        id := sk_SXNETID_value(sx.ids, i);
        tmp := i2s_ASN1_INTEGER(nil, id.zone);
        BIO_printf(_out, ' \n%*sZone: %s, User: ' , [indent, ' ' , tmp]);
        OPENSSL_free(tmp);
        ASN1_STRING_print(_out, PASN1_STRING(id.user));
    end;
    Result := 1;
end;



function SXNET_it:PASN1_ITEM;
var
  local_it : TASN1_ITEM;
begin
  local_it := get_ASN1_ITEM($1, 16, @SXNET_seq_tt,
                       sizeof(SXNET_seq_tt) div sizeof(TASN1_TEMPLATE),
                      Pointer(0) , sizeof(SXNET), ' SXNET');
   Result := @local_it;
end;

initialization
  ossl_v3_sxnet := get_V3_EXT_METHOD(
    NID_sxnet, X509V3_EXT_MULTILINE, SXNET_it,
    nil, nil, nil, nil,
    nil, nil,
    nil,
{$ifdef SXNET_TEST}
    PX509V3_EXT_V2I(@sxnet_v2i)^,
{$else}
    nil,
{$endif}
    PX509V3_EXT_I2R(@sxnet_i2r)^,
    nil,
    nil
);


  SXNET_seq_tt := [
        get_ASN1_TEMPLATE ( 0,  0,  size_t(@PSXNET(0).version), ' version' , ASN1_INTEGER_it ),
        get_ASN1_TEMPLATE ( (($2 shl  1)), 0,  size_t(@PSXNET(0).ids), ' ids' , SXNETID_it )
  ];
  SXNETID_seq_tt := [
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PSXNETID(0). zone), ' zone' , ASN1_INTEGER_it),
        get_ASN1_TEMPLATE( 0,  0,  size_t(@PSXNETID(0). user), ' user' , ASN1_OCTET_STRING_it)
  ]
end.
