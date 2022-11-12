program Test_OpenSSL;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  SysUtils,
  TypInfo,
  rtti,
  openssl3.crypto.params,
  openssl3.crypto.evp.pmeth_lib,
  openssl3.crypto.evp.p_lib,
  openssl3.crypto.evp.pmeth_gn,
  openssl3.crypto.bn.bn_lib,
  OpenSSL3.crypto.err.err_prn,
  openssl3.crypto.bio.bio_dump,
  openssl3.crypto.provider,
  openssl3.crypto.provider_core,
  openssl3.crypto.evp.evp_fetch,
  openssl3.providers.fips.fips_entry,
  OpenSSL.Api,
  OpenSSL3.openssl.asn1t,
  libc.error in 'libc\libc.error.pas',
  openssl3.crypto.init in 'openssl3.crypto.init.pas',
  basic_output in 'test\basic_output.pas',
  bioprinttest in 'test\bioprinttest.pas',
  driver in 'test\driver.pas',
  openssl3.test.testutil.options in 'test\openssl3.test.testutil.options.pas',
  openssl3.test.testutil.output in 'test\openssl3.test.testutil.output.pas',
  openssl3.test.testutil.random in 'test\openssl3.test.testutil.random.pas',
  openssl3.test.testutil.testutil_init in 'test\openssl3.test.testutil.testutil_init.pas',
  rsa_test in 'test\rsa_test.pas',
  test_options in 'test\test_options.pas',
  tests in 'test\tests.pas',
  app.lib.opt in 'app\app.lib.opt.pas',
  app.lib.win32_init in 'app\app.lib.win32_init.pas';

function do_ec_keygen:PEVP_PKEY;
var
    libctx         : POSSL_LIB_CTX;
    propq          : PChar;
    key            : PEVP_PKEY;
    params         : array[0..2] of TOSSL_PARAM;
    genctx         : PEVP_PKEY_CTX;
    curvename      : PChar;
    use_cofactordh : integer;
    label cleanup;

begin
    {
     * The libctx and propq can be set if required, they are included here
     * to show how they are passed to EVP_PKEY_CTX_new_from_name().
     }
    libctx := nil;
    propq := nil;
    key := nil;
    genctx := nil;
    curvename := 'P-256';
    use_cofactordh := 1;
    genctx := EVP_PKEY_CTX_new_from_name(libctx, 'EC', propq);
    if genctx = nil then
    begin
        WriteLn('EVP_PKEY_CTX_new_from_name() failed');
         goto cleanup;
    end;
    if EVP_PKEY_keygen_init(genctx) <= 0 then
    begin
        WriteLn('EVP_PKEY_keygen_init() failed');
         goto cleanup;
    end;
    params[0] := OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                                 PChar(curvename), 0);
    {
     * This is an optional parameter.
     * For many curves where the cofactor is 1, setting this has no effect.
     }
    params[1] := OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                                         @use_cofactordh);
    params[2] := OSSL_PARAM_construct_end();
    if 0>= EVP_PKEY_CTX_set_params(genctx, @params) then
    begin
        WriteLn('EVP_PKEY_CTX_set_params() failed');
        goto cleanup;
    end;

    WriteLn('Generating EC key'#10);

    if EVP_PKEY_generate(genctx, @key) <= 0  then
    begin
        WriteLn('EVP_PKEY_generate() failed');
        goto cleanup;
    end;
cleanup:
    EVP_PKEY_CTX_free(genctx);
    Result := key;
end;


function get_key_values( pkey : PEVP_PKEY):integer;
var
  out_curvename   : array[0..79] of Char;
  out_pubkey,
  out_privkey     : array[0..79] of Byte;
  out_priv        : PBIGNUM;
  i,
  out_pubkey_len,
  out_privkey_len : size_t;
  label _cleanup;
begin
    result := 0;
    out_priv := nil;
    out_privkey_len := 0;
    if 0>=EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        out_curvename, sizeof(out_curvename ) ,
                                        nil) then
    begin
        WriteLn('Failed to get curve name');
        goto _cleanup;
    end;
    if 0>=EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        @out_pubkey, sizeof(out_pubkey) ,
                                        @out_pubkey_len)  then
    begin
        WriteLn('Failed to get public key');
        goto _cleanup;
    end;
    if 0>=EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, @out_priv) then
    begin
        WriteLn('Failed to get private key');
        goto _cleanup;
    end;
    out_privkey_len := BN_bn2bin(out_priv, @out_privkey);
    if (out_privkey_len <= 0)  or  (out_privkey_len > sizeof(out_privkey))  then
    begin
        WriteLn('BN_bn2bin failed');
        goto _cleanup;
    end;
    WriteLn(Format('Curve name: %s',[out_curvename]));
    WriteLn('Public key:');
    BIO_dump_indent_fp(@System.Output{stdout}, @out_pubkey, out_pubkey_len, 2);
    WriteLn('Private Key:');
    BIO_dump_indent_fp(@System.Output{stdout}, @out_privkey, out_privkey_len, 2);
    result := 1;
_cleanup:
    { Zeroize the private key data when we free it }
    BN_clear_free(out_priv);
    Result := result;
end;

var
  provider_callbacks: POSSL_DISPATCH;
  provctx : Pointer = nil;

function main:integer;
const
  gn:PGENERAL_NAME = PGENERAL_NAME(0);
var
  pkey : PEVP_PKEY;
  _result, sz: int;
  prov: POSSL_PROVIDER;
  libctx: POSSL_LIB_CTX;
  label cleanup;
begin
    libctx := nil;
    sz := offsetof(TypeInfo(TGENERAL_NAME), 'd');
    sz := size_t(@gn.&type);
    sz := size_t(@gn.d);
    sz := size_t(@TGENERAL_NAME(nil^).&type);
    sz := size_t(@TGENERAL_NAME(nil^).d);
    EVP_set_default_properties(libctx, 'fips=yes');
    prov := OSSL_PROVIDER_load(libctx, 'default');
    //OSSL_provider_init(prov, core_dispatch, @provider_callbacks, provctx);
    _result := 0;
    pkey := do_ec_keygen();
    if pkey = nil then
      goto cleanup;
    if (0>= get_key_values(pkey)) then
      goto cleanup;
    {
     * At this point we can write out the generated key using
     * i2d_PrivateKey() and i2d_PublicKey() if required.
     }
    _result := 1;
cleanup:
    if _result <> 1 then
       ERR_print_errors_fp(@System.ErrOutput{stderr});
    EVP_PKEY_free(pkey);
    exit(Int(_result = 0));
end;

begin
  try
    main;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
