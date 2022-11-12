unit openssl3.crypto.engine.eng_fat;

interface
uses OpenSSL.Api, SysUtils;

function ENGINE_set_default( e : PENGINE; flags : uint32):integer;
function int_def_cb(const alg : PUTF8Char; len : integer; arg : Pointer):integer;
function ENGINE_set_default_string(e : PENGINE;const def_list : PUTF8Char):integer;
function ENGINE_register_all_complete:integer;

function ENGINE_register_complete( e : PENGINE):integer;

implementation
uses OpenSSL3.Err,
     openssl3.crypto.engine.tb_cipher,    openssl3.crypto.engine.tb_rsa,
     openssl3.crypto.engine.tb_eckey,     openssl3.crypto.engine.tb_rand,
     openssl3.crypto.engine.tb_pkmeth,    openssl3.crypto.engine.tb_asnmth,
     openssl3.crypto.conf.conf_mod,       openssl3.crypto.engine.eng_list,
     openssl3.crypto.engine.tb_digest,
     openssl3.crypto.engine.tb_dsa,       openssl3.crypto.engine.tb_dh;




function ENGINE_register_complete( e : PENGINE):integer;
begin
    ENGINE_register_ciphers(e);
    ENGINE_register_digests(e);
    ENGINE_register_RSA(e);
{$IFNDEF OPENSSL_NO_DSA}
    ENGINE_register_DSA(e);
{$ENDIF}
{$IFNDEF OPENSSL_NO_DH}
    ENGINE_register_DH(e);
{$ENDIF}
{$IFNDEF OPENSSL_NO_EC}
    ENGINE_register_EC(e);
{$ENDIF}
    ENGINE_register_RAND(e);
    ENGINE_register_pkey_meths(e);
    ENGINE_register_pkey_asn1_meths(e);
    Result := 1;
end;




function ENGINE_register_all_complete:integer;
var
  e : PENGINE;
begin
    e := ENGINE_get_first;
    while e <> nil do
    begin

        if 0>=(e.flags and ENGINE_FLAGS_NO_REGISTER_ALL) then
            ENGINE_register_complete(e);
        e := ENGINE_get_next(e);
    end;
    Result := 1;
end;

function ENGINE_set_default( e : PENGINE; flags : uint32):integer;
begin
    if (flags and ENGINE_METHOD_CIPHERS >0)  and  (0>=ENGINE_set_default_ciphers(e)) then
        Exit(0);
    if (flags and ENGINE_METHOD_DIGESTS >0)  and  (0>=ENGINE_set_default_digests(e)) then
        Exit(0);
    if (flags and ENGINE_METHOD_RSA > 0)  and  (0>=ENGINE_set_default_RSA(e)) then
        Exit(0);
{$IFNDEF OPENSSL_NO_DSA}
    if (flags and ENGINE_METHOD_DSA > 0) and  (0>=ENGINE_set_default_DSA(e)) then
        Exit(0);
{$ENDIF}
{$IFNDEF OPENSSL_NO_DH}
    if (flags and ENGINE_METHOD_DH > 0) and  (0>=ENGINE_set_default_DH(e)) then
        Exit(0);
{$ENDIF}
{$IFNDEF OPENSSL_NO_EC}
    if (flags and ENGINE_METHOD_EC > 0)  and  (0>=ENGINE_set_default_EC(e)) then
        Exit(0);
{$ENDIF}
    if (flags and ENGINE_METHOD_RAND > 0)  and  (0>=ENGINE_set_default_RAND(e)) then
        Exit(0);
    if (flags and ENGINE_METHOD_PKEY_METHS > 0)  and  (0>=ENGINE_set_default_pkey_meths(e)) then
        Exit(0);
    if (flags and ENGINE_METHOD_PKEY_ASN1_METHS > 0) and  (0>=ENGINE_set_default_pkey_asn1_meths(e)) then
        Exit(0);
    Result := 1;
end;


function int_def_cb(const alg : PUTF8Char; len : integer; arg : Pointer):integer;
var
  pflags : Puint32;
begin
    pflags := arg;
    if alg = nil then Exit(0);
    if strncmp(alg, 'ALL', len) = 0  then
        pflags^  := pflags^  or ENGINE_METHOD_ALL
    else if (strncmp(alg, 'RSA', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_RSA
    else if (strncmp(alg, 'DSA', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_DSA
    else if (strncmp(alg, 'DH', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_DH
    else if (strncmp(alg, 'EC', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_EC
    else if (strncmp(alg, 'RAND', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_RAND
    else if (strncmp(alg, 'CIPHERS', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_CIPHERS
    else if (strncmp(alg, 'DIGESTS', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_DIGESTS
    else if (strncmp(alg, 'PKEY', len) = 0) then
        pflags^  := pflags^  or (ENGINE_METHOD_PKEY_METHS or ENGINE_METHOD_PKEY_ASN1_METHS)
    else if (strncmp(alg, 'PKEY_CRYPTO', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_PKEY_METHS
    else if (strncmp(alg, 'PKEY_ASN1', len) = 0) then
        pflags^  := pflags^  or ENGINE_METHOD_PKEY_ASN1_METHS
    else
        Exit(0);
    Result := 1;
end;


function ENGINE_set_default_string(e : PENGINE;const def_list : PUTF8Char):integer;
var
  flags : uint32;
begin
    flags := 0;
    if 0>=CONF_parse_list(def_list, Ord(','), 1, int_def_cb, @flags) then
    begin
        ERR_raise_data(ERR_LIB_ENGINE, ENGINE_R_INVALID_STRING,
                      Format('str=%s', [def_list]));
        Exit(0);
    end;
    Result := ENGINE_set_default(e, flags);
end;


end.
