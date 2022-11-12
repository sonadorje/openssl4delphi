unit openssl3.crypto.engine.eng_openssl;

interface
 uses OpenSSL.Api;

 const
    engine_openssl_id: PUTF8Char = 'openssl';
    engine_openssl_name: PUTF8Char = 'Software engine support';

procedure engine_load_openssl_int;
function engine_openssl:PENGINE;
function bind_helper( e : PENGINE):integer;
function openssl_destroy( e : PENGINE):integer;
procedure test_sha_md_destroy;
function test_digest_nids( nids : PPInteger):integer;

var
   sha1_md: PEVP_MD = nil;

function test_sha_md:PEVP_MD;
function test_sha1_init( ctx : PEVP_MD_CTX):integer;
function test_sha1_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;

function test_sha1_final( ctx : PEVP_MD_CTX; md : PByte):integer;

implementation


uses openssl3.providers.fips.fipsprov,     openssl3.crypto.engine.eng_lib,
     openssl3.crypto.sha.sha1dgst,         openssl3.crypto.engine.tb_rsa,
     openssl3.crypto.rsa.rsa_ossl,         openssl3.crypto.engine.tb_dsa,
     openssl3.crypto.dsa.dsa_ossl,         openssl3.crypto.engine.tb_eckey,
     openssl3.crypto.ec.ec_kmeth,          openssl3.crypto.engine.tb_dh,
     openssl3.crypto.dh.dh_key,            openssl3.crypto.engine.tb_rand,
     openssl3.crypto.rand.rand_meth,       openssl3.crypto.engine.eng_list,
     openssl3.crypto.evp.evp_lib,          openssl3.crypto.sha.sha_local;

var
  digest_nids : array[0..1] of integer;
  pos,
  init        : integer;





function test_sha1_final( ctx : PEVP_MD_CTX; md : PByte):integer;
begin
{$IFDEF TEST_ENG_OPENSSL_SHA_P_FINAL}
    WriteLn('(TEST_ENG_OPENSSL_SHA) test_sha1_final called');
{$ENDIF}
    Result := _SHA1_Final(md, EVP_MD_CTX_get0_md_data(ctx));
end;


function test_sha1_update(ctx : PEVP_MD_CTX;const data : Pointer; count : size_t):integer;
begin
{$IFDEF TEST_ENG_OPENSSL_SHA_P_UPDATE}
    WriteLn('(TEST_ENG_OPENSSL_SHA) test_sha1_update called');
{$ENDIF}
    Result := _SHA1_Update(EVP_MD_CTX_get0_md_data(ctx), data, count);
end;

function test_sha1_init( ctx : PEVP_MD_CTX):integer;
begin
{$IFDEF TEST_ENG_OPENSSL_SHA_P_INIT}
    WriteLn('(TEST_ENG_OPENSSL_SHA) test_sha1_init called');
{$ENDIF}
    Result := _SHA1_Init(EVP_MD_CTX_get0_md_data(ctx));
end;


function test_sha_md:PEVP_MD;
var
  md : PEVP_MD;
begin
    if sha1_md = nil then
    begin
        md := EVP_MD_meth_new(NID_sha1, NID_sha1WithRSAEncryption);
        if (md = nil)
             or  (0>=EVP_MD_meth_set_result_size(md, SHA_DIGEST_LENGTH))
             or  (0>=EVP_MD_meth_set_input_blocksize(md, SHA_CBLOCK))
             or  (0>=EVP_MD_meth_set_app_datasize(md,
                                             sizeof(PEVP_MD) + sizeof(TSHA_CTX)))
             or  (0>=EVP_MD_meth_set_flags(md, 0))
             or  (0>=EVP_MD_meth_set_init(md, test_sha1_init))
             or  (0>=EVP_MD_meth_set_update(md, test_sha1_update))
             or  (0>=EVP_MD_meth_set_final(md, test_sha1_final)) then
        begin
            EVP_MD_meth_free(md);
            md := nil;
        end;
        sha1_md := md;
    end;
    Result := sha1_md;
end;


procedure test_sha_md_destroy;
begin
    EVP_MD_meth_free(sha1_md);
    sha1_md := nil;
end;


function test_digest_nids( nids : PPInteger):integer;
var
  md          : PEVP_MD;
begin
      digest_nids[0] := 0;
      digest_nids[1] := 0;
      pos := 0;
      init := 0;
    if 0>=init then
    begin
        md := test_sha_md;
        if (md <> nil) then
            digest_nids[PostInc(pos)] := EVP_MD_get_type(md);
        digest_nids[pos] := 0;
        init := 1;
    end;
    nids^ := @digest_nids;
    Result := pos;
end;



function openssl_destroy( e : PENGINE):integer;
begin
    test_sha_md_destroy;
{$IFDEF TEST_ENG_OPENSSL_RC4}
    test_r4_cipher_destroy;
    test_r4_40_cipher_destroy;
{$ENDIF}
    Result := 1;
end;

function bind_helper( e : PENGINE):integer;
begin
    if ( (0>=ENGINE_set_id(e, engine_openssl_id))  or  (0>=ENGINE_set_name(e, engine_openssl_name))
         or  (0>=ENGINE_set_destroy_function(e, openssl_destroy))
{$IFNDEF TEST_ENG_OPENSSL_NO_ALGORITHMS}
         or  (0>=ENGINE_set_RSA(e, RSA_get_default_method))
{$IFNDEF OPENSSL_NO_DSA}
         or  (0>=ENGINE_set_DSA(e, DSA_get_default_method))
{$ENDIF}
{$IFNDEF OPENSSL_NO_EC}
         or  (0>=ENGINE_set_EC(e, EC_KEY_OpenSSL))
{$ENDIF}
{$IFNDEF OPENSSL_NO_DH}
         or  (0>=ENGINE_set_DH(e, DH_get_default_method))
{$ENDIF}
         or  (0>=ENGINE_set_RAND(e, RAND_OpenSSL))
{$IFDEF TEST_ENG_OPENSSL_RC4}
         or  (0>=ENGINE_set_ciphers(e, openssl_ciphers))
{$ENDIF}
{$IFDEF TEST_ENG_OPENSSL_SHA}
         or  (0>=ENGINE_set_digests(e, openssl_digests))
{$ENDIF}
{$ENDIF}
{$IFDEF TEST_ENG_OPENSSL_PKEY}
         or  (0>=ENGINE_set_load_privkey_function(e, openssl_load_privkey)
{$ENDIF}
{$IFDEF TEST_ENG_OPENSSL_HMAC}
         or  (0>=ossl_register_hmac_meth
         or  (0>=ENGINE_set_pkey_meths(e, ossl_pkey_meths)
{$ENDIF}
        ) then
        Exit(0);
    {
     * If we add errors to this ENGINE, ensure the error handling is setup
     * here
     }
    { openssl_load_error_strings; }
    Result := 1;
end;




function engine_openssl:PENGINE;
var
  ret : PENGINE;
begin
    ret := ENGINE_new;
    if ret = nil then Exit(nil);
    if 0>=bind_helper(ret) then
    begin
        ENGINE_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;

procedure engine_load_openssl_int;
var
  toadd : PENGINE;
begin
    toadd := engine_openssl;
    if nil =toadd then exit;
    ERR_set_mark;
    ENGINE_add(toadd);
    {
     * If the 'add' worked, it gets a structural reference. So either way, we
     * release our just-created reference.
     }
    ENGINE_free(toadd);
    {
     * If the 'add' didn't work, it was probably a conflict because it was
     * already added (eg. someone calling ENGINE_load_blah then calling
     * ENGINE_load_builtin_engines perhaps).
     }
    ERR_pop_to_mark;
end;


end.
