unit OpenSSL3.providers.common.capabilities;

interface
uses OpenSSL.Api;
type
  TOSSL_PARAM_Array = array[0..9] of TOSSL_PARAM;

const

  group_list: array[0..34] of TLS_GROUP_CONSTANTS = (
     ( group_id:OSSL_TLS_GROUP_ID_sect163k1; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect163r1; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect163r2; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect193r1; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect193r2; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect233k1; secbits:112; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect233r1; secbits:112; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect239k1; secbits:112; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect283k1; secbits:128; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect283r1; secbits:128; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect409k1; secbits:192; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect409r1; secbits:192; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect571k1; secbits:256; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_sect571r1; secbits:256; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp160k1; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp160r1; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp160r2; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp192k1; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp192r1; secbits:80; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp224k1; secbits:112; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp224r1; secbits:112; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp256k1; secbits:128; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_secp256r1; secbits:128; mintls:TLS1_VERSION; maxtls:0; mindtls:DTLS1_VERSION; maxdtls:0 ),
    ( group_id:OSSL_TLS_GROUP_ID_secp384r1; secbits:192; mintls:TLS1_VERSION; maxtls:0; mindtls:DTLS1_VERSION; maxdtls:0 ),
    ( group_id:OSSL_TLS_GROUP_ID_secp521r1; secbits:256; mintls:TLS1_VERSION; maxtls:0; mindtls:DTLS1_VERSION; maxdtls:0 ),
    ( group_id:OSSL_TLS_GROUP_ID_brainpoolP256r1; secbits:128; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_brainpoolP384r1; secbits:192; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_brainpoolP512r1; secbits:256; mintls:TLS1_VERSION; maxtls:TLS1_2_VERSION;
      mindtls:DTLS1_VERSION; maxdtls:DTLS1_2_VERSION ),
    ( group_id:OSSL_TLS_GROUP_ID_x25519; secbits:128; mintls:TLS1_VERSION; maxtls:0; mindtls:DTLS1_VERSION; maxdtls:0 ),
    ( group_id:OSSL_TLS_GROUP_ID_x448; secbits:224; mintls:TLS1_VERSION; maxtls:0; mindtls:DTLS1_VERSION; maxdtls:0 ),
    (* Security bit values as given by BN_security_bits() *)
    ( group_id:OSSL_TLS_GROUP_ID_ffdhe2048; secbits:112; mintls:TLS1_3_VERSION; maxtls:0; mindtls:-1; maxdtls:-1 ),
    ( group_id:OSSL_TLS_GROUP_ID_ffdhe3072; secbits:128; mintls:TLS1_3_VERSION; maxtls:0; mindtls:-1; maxdtls:-1 ),
    ( group_id:OSSL_TLS_GROUP_ID_ffdhe4096; secbits:128; mintls:TLS1_3_VERSION; maxtls:0; mindtls:-1; maxdtls:-1 ),
    ( group_id:OSSL_TLS_GROUP_ID_ffdhe6144; secbits:128; mintls:TLS1_3_VERSION; maxtls:0; mindtls:-1; maxdtls:-1 ),
    ( group_id:OSSL_TLS_GROUP_ID_ffdhe8192; secbits:192; mintls:TLS1_3_VERSION; maxtls:0; mindtls:-1; maxdtls:-1 )
);

function ossl_prov_get_capabilities(provctx : Pointer;const capability : PUTF8Char;cb : POSSL_CALLBACK; arg : Pointer):integer;
function tls_group_capability( cb : POSSL_CALLBACK; arg : Pointer):integer;

var
   param_group_list: array[0..49] of TOSSL_PARAM_Array;

implementation
uses OpenSSL3.openssl.params;


(*OSSL_PARAM_UTF8_STRING      =    4;由于delphi不区分大小写，函数名与常量名重名，故前面加下划线*)
function TLS_GROUP_ENTRY(tlsname, realname, algorithm: PUTF8Char; idx: Integer): TOSSL_PARAM_Array;
begin

   Result[0] := _OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME, tlsname, sizeof(tlsname));
   Result[1] := _OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_NAME_INTERNAL, realname, sizeof(realname));
   Result[2] := _OSSL_PARAM_utf8_string(OSSL_CAPABILITY_TLS_GROUP_ALG, algorithm, sizeof(algorithm));
   Result[3] := _OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_ID, Puint32(@group_list[idx].group_id));
   Result[4] := _OSSL_PARAM_uint(OSSL_CAPABILITY_TLS_GROUP_SECURITY_BITS, Puint32(@group_list[idx].secbits));
   Result[5] := _OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_TLS, Puint32(@group_list[idx].mintls));
   Result[6] := _OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_TLS, Puint32(@group_list[idx].maxtls));
   Result[7] := _OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MIN_DTLS, Puint32(@group_list[idx].mindtls));
   Result[8] := _OSSL_PARAM_int(OSSL_CAPABILITY_TLS_GROUP_MAX_DTLS, Puint32(@group_list[idx].maxdtls));
   Result[9] := OSSL_PARAM_END;
end;

function tls_group_capability( cb : POSSL_CALLBACK; arg : Pointer):integer;
var
  i : size_t;
begin
{$IF not defined(OPENSSL_NO_EC)  or   not defined(OPENSSL_NO_DH)}
    for i := 0 to Length(param_group_list)-1 do
        if  0>= cb(@param_group_list[i], arg) then
            Exit(0);
{$ENDIF}
    Result := 1;
end;

function ossl_prov_get_capabilities(provctx : Pointer;const capability : PUTF8Char;cb : POSSL_CALLBACK; arg : Pointer):integer;
begin
    if strcasecmp(capability, 'TLS-GROUP') = 0  then
        Exit(tls_group_capability(cb, arg));
    { We don't support this capability }
    Result := 0;
end;

initialization

{$ifndef OPENSSL_NO_EC}
  {$ifndef OPENSSL_NO_EC2M}
    param_group_list[0] := TLS_GROUP_ENTRY('sect163k1', 'sect163k1', 'EC', 0);
    param_group_list[1] := TLS_GROUP_ENTRY('K-163', 'sect163k1', 'EC', 0); (* Alias of above *)
  {$endif}
  {$ifndef FIPS_MODULE}
    param_group_list[2] := TLS_GROUP_ENTRY('sect163r1', 'sect163r1', 'EC', 1);
  {$endif}
  {$ifndef OPENSSL_NO_EC2M}
    param_group_list[3] := TLS_GROUP_ENTRY('sect163r2', 'sect163r2', 'EC', 2);
    param_group_list[4] := TLS_GROUP_ENTRY('B-163', 'sect163r2', 'EC', 2); (* Alias of above *)
  {$endif}
  {$ifndef FIPS_MODULE}
    param_group_list[5] := TLS_GROUP_ENTRY('sect193r1', 'sect193r1', 'EC', 3);
    param_group_list[6] := TLS_GROUP_ENTRY('sect193r2', 'sect193r2', 'EC', 4);
  {$endif}
  {$ifndef OPENSSL_NO_EC2M}
    param_group_list[7] := TLS_GROUP_ENTRY('sect233k1', 'sect233k1', 'EC', 5);
    param_group_list[8] := TLS_GROUP_ENTRY('K-233', 'sect233k1', 'EC', 5); (* Alias of above *)
    param_group_list[9] := TLS_GROUP_ENTRY('sect233r1', 'sect233r1', 'EC', 6);
    param_group_list[10] := TLS_GROUP_ENTRY('B-233', 'sect233r1', 'EC', 6); (* Alias of above *)
  {$endif}
  {$ifndef FIPS_MODULE}
    param_group_list[11] := TLS_GROUP_ENTRY('sect239k1', 'sect239k1', 'EC', 7);
  {$endif}
  {$ifndef OPENSSL_NO_EC2M}
    param_group_list[12] := TLS_GROUP_ENTRY('sect283k1', 'sect283k1', 'EC', 8);
    param_group_list[13] := TLS_GROUP_ENTRY('K-283', 'sect283k1', 'EC', 8); (* Alias of above *)
    param_group_list[14] := TLS_GROUP_ENTRY('sect283r1', 'sect283r1', 'EC', 9);
    param_group_list[15] := TLS_GROUP_ENTRY('B-283', 'sect283r1', 'EC', 9); (* Alias of above *)
    param_group_list[16] := TLS_GROUP_ENTRY('sect409k1', 'sect409k1', 'EC', 10);
    param_group_list[17] := TLS_GROUP_ENTRY('K-409', 'sect409k1', 'EC', 10); (* Alias of above *)
    param_group_list[18] := TLS_GROUP_ENTRY('sect409r1', 'sect409r1', 'EC', 11);
    param_group_list[19] := TLS_GROUP_ENTRY('B-409', 'sect409r1', 'EC', 11); (* Alias of above *)
    param_group_list[20] := TLS_GROUP_ENTRY('sect571k1', 'sect571k1', 'EC', 12);
    param_group_list[21] := TLS_GROUP_ENTRY('K-571', 'sect571k1', 'EC', 12); (* Alias of above *)
    param_group_list[22] := TLS_GROUP_ENTRY('sect571r1', 'sect571r1', 'EC', 13);
    param_group_list[23] := TLS_GROUP_ENTRY('B-571', 'sect571r1', 'EC', 13); (* Alias of above *)
  {$endif}
  {$ifndef FIPS_MODULE}
    param_group_list[24] := TLS_GROUP_ENTRY('secp160k1', 'secp160k1', 'EC', 14);
    param_group_list[25] := TLS_GROUP_ENTRY('secp160r1', 'secp160r1', 'EC', 15);
    param_group_list[26] := TLS_GROUP_ENTRY('secp160r2', 'secp160r2', 'EC', 16);
    param_group_list[27] := TLS_GROUP_ENTRY('secp192k1', 'secp192k1', 'EC', 17);
  {$endif}
    param_group_list[28] := TLS_GROUP_ENTRY('secp192r1', 'prime192v1', 'EC', 18);
    param_group_list[29] := TLS_GROUP_ENTRY('P-192', 'prime192v1', 'EC', 18); (* Alias of above *)
  {$ifndef FIPS_MODULE}
    param_group_list[30] := TLS_GROUP_ENTRY('secp224k1', 'secp224k1', 'EC', 19);
  {$endif}
    param_group_list[31] := TLS_GROUP_ENTRY('secp224r1', 'secp224r1', 'EC', 20);
    param_group_list[32] := TLS_GROUP_ENTRY('P-224', 'secp224r1', 'EC', 20); (* Alias of above *)
  {$ifndef FIPS_MODULE}
    param_group_list[33] := TLS_GROUP_ENTRY('secp256k1', 'secp256k1', 'EC', 21);
  {$endif}
    param_group_list[34] := TLS_GROUP_ENTRY('secp256r1', 'prime256v1', 'EC', 22);
    param_group_list[35] := TLS_GROUP_ENTRY('P-256', 'prime256v1', 'EC', 22); (* Alias of above *)
    param_group_list[36] := TLS_GROUP_ENTRY('secp384r1', 'secp384r1', 'EC', 23);
    param_group_list[37] := TLS_GROUP_ENTRY('P-384', 'secp384r1', 'EC', 23); (* Alias of above *)
    param_group_list[38] := TLS_GROUP_ENTRY('secp521r1', 'secp521r1', 'EC', 24);
    param_group_list[39] := TLS_GROUP_ENTRY('P-521', 'secp521r1', 'EC', 24); (* Alias of above *)
  {$ifndef FIPS_MODULE}
    param_group_list[40] := TLS_GROUP_ENTRY('brainpoolP256r1', 'brainpoolP256r1', 'EC', 25);
    param_group_list[41] := TLS_GROUP_ENTRY('brainpoolP384r1', 'brainpoolP384r1', 'EC', 26);
    param_group_list[42] := TLS_GROUP_ENTRY('brainpoolP512r1', 'brainpoolP512r1', 'EC', 27);
  {$endif}
    param_group_list[43] := TLS_GROUP_ENTRY('x25519', 'X25519', 'X25519', 28);
    param_group_list[44] := TLS_GROUP_ENTRY('x448', 'X448', 'X448', 29);
{$endif} (* OPENSSL_NO_EC *)
{$ifndef OPENSSL_NO_DH }
    (* Security bit values for FFDHE groups are as per RFC 7919 *)
    param_group_list[45] := TLS_GROUP_ENTRY('ffdhe2048', 'ffdhe2048', 'DH', 30);
    param_group_list[46] := TLS_GROUP_ENTRY('ffdhe3072', 'ffdhe3072', 'DH', 31);
    param_group_list[47] := TLS_GROUP_ENTRY('ffdhe4096', 'ffdhe4096', 'DH', 32);
    param_group_list[48] := TLS_GROUP_ENTRY('ffdhe6144', 'ffdhe6144', 'DH', 33);
    param_group_list[49] := TLS_GROUP_ENTRY('ffdhe8192', 'ffdhe8192', 'DH', 34);
{$endif}

end.
