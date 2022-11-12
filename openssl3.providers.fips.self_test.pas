unit openssl3.providers.fips.self_test;

interface
 uses OpenSSL.Api;

const
   FIPS_STATE_INIT     =0;
   FIPS_STATE_SELFTEST =1;
   FIPS_STATE_RUNNING  =2;
   FIPS_STATE_ERROR    =3;
   DEP_INITIAL_STATE   = FIPS_STATE_INIT;
   FIPS_ERROR_REPORTING_RATE_LIMIT  =   10;
   MAX_MD_SIZE = 64;
   MAC_NAME    = 'HMAC';
   DIGEST_NAME = 'SHA256';
   INTEGRITY_BUF_SIZE = (4096);

  fixed_key : array[0..31] of byte = (
    $f4, $55, $66, $50, $ac, $31, $d3, $54, $61, $61, $0b, $ac, $4e, $d8,
    $1b, $1a, $18, $1b, $2d, $8a, $43, $ea, $28, $54, $cb, $ae, $22, $ca,
    $74, $56, $08, $13 );

function ossl_prov_is_running:Boolean;
procedure set_fips_state( state : integer);
procedure ossl_set_error_state(const &type : PUTF8Char);
procedure OSSL_SELF_TEST_free( st : POSSL_SELF_TEST);
procedure SELF_TEST_disable_conditional_error_state;
function SELF_TEST_post(st : PSELF_TEST_POST_PARAMS; on_demand_test : integer):integer;
procedure do_fips_self_test_init_ossl_;
function do_fips_self_test_init:integer;
function verify_integrity(bio : POSSL_CORE_BIO; read_ex_cb : TOSSL_FUNC_BIO_read_ex_fn; expected : PByte; expected_len : size_t; libctx : POSSL_LIB_CTX; ev : POSSL_SELF_TEST;const event_type : PUTF8Char):integer;



var
  fips_state_lock: PCRYPTO_RWLOCK  = nil;
  FIPS_state: int  = DEP_INITIAL_STATE;
  rate_limit: uint;
  FIPS_conditional_error_check:int  = 1;
  fips_self_test_init: CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;
  do_fips_self_test_init_ossl_ret_: int = 0;
  self_test_lock: PCRYPTO_RWLOCK  = nil;

implementation
uses OpenSSL3.Err, OpenSSL3.common,   openssl3.crypto.mem,OpenSSL3.threads_none,
     openssl3.crypto.self_test_core,  openssl3.crypto.o_str,
     openssl3.crypto.params,          openssl3.crypto.self_test_kats,
     openssl3.crypto.evp.mac_meth,    openssl3.crypto.evp.mac_lib;





function verify_integrity(bio : POSSL_CORE_BIO; read_ex_cb : TOSSL_FUNC_BIO_read_ex_fn; expected : PByte; expected_len : size_t; libctx : POSSL_LIB_CTX; ev : POSSL_SELF_TEST;const event_type : PUTF8Char):integer;
var
    ret, status        : integer;
    _out       : array[0..(MAX_MD_SIZE)-1] of Byte;
    buf        : array[0..(INTEGRITY_BUF_SIZE)-1] of Byte;
    bytes_read, out_len : size_t;
    mac        : PEVP_MAC;
    ctx        : PEVP_MAC_CTX;
    params     : array[0..1] of TOSSL_PARAM;
    p: POSSL_PARAM;
    label _err;
begin
    ret := 0;
    bytes_read := 0; out_len := 0;
    mac := nil;
    ctx := nil;
    p := @params;
    OSSL_SELF_TEST_onbegin(ev, event_type, OSSL_SELF_TEST_DESC_INTEGRITY_HMAC);
    mac := EVP_MAC_fetch(libctx, MAC_NAME, nil);
    if mac = nil then goto _err;
    ctx := EVP_MAC_CTX_new(mac);
    if ctx = nil then goto _err;
    PostInc(p)^ := OSSL_PARAM_construct_utf8_string('digest', DIGEST_NAME, 0);
    p^ := OSSL_PARAM_construct_end;
    if 0>=EVP_MAC_init(ctx, @fixed_key, sizeof(fixed_key), @params) then
        goto _err;
    while Boolean(1) do
    begin
        status := read_ex_cb(bio, @buf, sizeof(buf), @bytes_read);
        if status <> 1 then break;
        if 0>=EVP_MAC_update(ctx, @buf, bytes_read) then
            goto _err;
    end;
    if 0>=EVP_MAC_final(ctx, @_out, @out_len, sizeof(_out)) then
        goto _err;
    OSSL_SELF_TEST_oncorrupt_byte(ev, @_out);
    if (expected_len <> out_len)
             or  (memcmp(expected, @_out, out_len) <> 0)  then
        goto _err;
    ret := 1;
_err:
    OSSL_SELF_TEST_onend(ev, ret);
    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    Result := ret;
end;



procedure do_fips_self_test_init_ossl_;
begin
   do_fips_self_test_init_ossl_ret_ := do_fips_self_test_init;
end;


function do_fips_self_test_init:integer;
begin
    self_test_lock := CRYPTO_THREAD_lock_new;
    fips_state_lock := CRYPTO_THREAD_lock_new;
    Result := Int(self_test_lock <> nil) ;
end;


function SELF_TEST_post( st : PSELF_TEST_POST_PARAMS; on_demand_test : integer):integer;
var
  ok,
  kats_already_passed : integer;
  checksum_len        : long;
  bio_module,
  bio_indicator       : POSSL_CORE_BIO;
  module_checksum,
  indicator_checksum  : PByte;
  loclstate           : integer;
  ev                  : POSSL_SELF_TEST;
  label _end;
begin
    ok := 0;
    kats_already_passed := 0;
    bio_module := nil;
    bio_indicator := nil;
    module_checksum := nil;
    indicator_checksum := nil;
    ev := nil;
    if 0>= get_result(CRYPTO_THREAD_run_once(@fips_self_test_init,
                          do_fips_self_test_init_ossl_)>0 , do_fips_self_test_init_ossl_ret_ , 0) then
        Exit(0);
    if 0>=CRYPTO_THREAD_read_lock(fips_state_lock) then
        Exit(0);
    loclstate := FIPS_state;
    CRYPTO_THREAD_unlock(fips_state_lock);
    if loclstate = FIPS_STATE_RUNNING then begin
        if 0>=on_demand_test then
            Exit(1);
    end
    else if (loclstate <> FIPS_STATE_SELFTEST) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        Exit(0);
    end;
    if 0>=CRYPTO_THREAD_write_lock(self_test_lock) then
        Exit(0);
    if 0>=CRYPTO_THREAD_read_lock(fips_state_lock) then
    begin
        CRYPTO_THREAD_unlock(self_test_lock);
        Exit(0);
    end;
    if FIPS_state = FIPS_STATE_RUNNING then begin
        CRYPTO_THREAD_unlock(fips_state_lock);
        if 0>=on_demand_test then begin
            CRYPTO_THREAD_unlock(self_test_lock);
            Exit(1);
        end;
        set_fips_state(FIPS_STATE_SELFTEST);
    end
    else if (FIPS_state <> FIPS_STATE_SELFTEST) then
    begin
        CRYPTO_THREAD_unlock(fips_state_lock);
        CRYPTO_THREAD_unlock(self_test_lock);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_STATE);
        Exit(0);
    end
    else
    begin
        CRYPTO_THREAD_unlock(fips_state_lock);
    end;
    if (st = nil) or  (st.module_checksum_data = nil) then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
        goto _end;
    end;
    ev := OSSL_SELF_TEST_new(st.cb, st.cb_arg);
    if ev = nil then goto _end;
    module_checksum := OPENSSL_hexstr2buf(st.module_checksum_data,
                                         @checksum_len);
    if module_checksum = nil then begin
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
        goto _end;
    end;
    bio_module := st.bio_new_file_cb(st.module_filename, 'rb');
    { Always check the integrity of the fips module }
    if (bio_module = nil)
             or  (0>=verify_integrity(bio_module, st.bio_read_ex_cb,
                                 module_checksum, checksum_len, st.libctx,
                                 ev, OSSL_SELF_TEST_TYPE_MODULE_INTEGRITY) ) then
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_MODULE_INTEGRITY_FAILURE);
        goto _end;
    end;
    { This will be nil during installation - so the self test KATS will run }
    if st.indicator_data <> nil then begin
        {
         * If the kats have already passed indicator is set - then check the
         * integrity of the indicator.
         }
        if st.indicator_checksum_data = nil then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_CONFIG_DATA);
            goto _end;
        end;
        indicator_checksum := OPENSSL_hexstr2buf(st.indicator_checksum_data,
                                                @checksum_len);
        if indicator_checksum = nil then begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CONFIG_DATA);
            goto _end;
        end;
        bio_indicator := st.bio_new_buffer_cb(st.indicator_data,
                                     Length(st.indicator_data));
        if (bio_indicator = nil)
                 or  (0>=verify_integrity(bio_indicator, st.bio_read_ex_cb,
                                     indicator_checksum, checksum_len,
                                     st.libctx, ev,
                                     OSSL_SELF_TEST_TYPE_INSTALL_INTEGRITY)) then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_INDICATOR_INTEGRITY_FAILURE);
            goto _end;
        end
        else begin
            kats_already_passed := 1;
        end;
    end;
    {
     * Only runs the KAT's during installation OR on_demand.
     * NOTE: If the installation option 'self_test_onload' is chosen then this
     * path will always be run, since kats_already_passed will always be 0.
     }
    if on_demand_test  or  kats_already_passed = 0 then
    begin
        if 0>=SELF_TEST_kats(ev, st.libctx) then  begin
            ERR_raise(ERR_LIB_PROV, PROV_R_SELF_TEST_KAT_FAILURE);
            goto _end;
        end;
    end;
    ok := 1;
_end:
    OSSL_SELF_TEST_free(ev);
    OPENSSL_free(Pointer(module_checksum));
    OPENSSL_free(Pointer(indicator_checksum));
    if st <> nil then
    begin
        st.bio_free_cb(bio_indicator);
        st.bio_free_cb(bio_module);
    end;
    if ok > 0 then
       set_fips_state(FIPS_STATE_RUNNING)
    else
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_NONE);
    CRYPTO_THREAD_unlock(self_test_lock);
    Result := ok;
end;


procedure SELF_TEST_disable_conditional_error_state;
begin
    FIPS_conditional_error_check := 0;
end;

procedure OSSL_SELF_TEST_free( st : POSSL_SELF_TEST);
begin
    OPENSSL_free(st);
end;

procedure ossl_set_error_state(const &type : PUTF8Char);
var
  cond_test : Boolean;
begin
    cond_test := (&type <> nil)  and  (strcmp(&type, OSSL_SELF_TEST_TYPE_PCT) = 0);
    if  (not cond_test)  or  (FIPS_conditional_error_check = 1) then
    begin
        set_fips_state(FIPS_STATE_ERROR);
        ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_ENTERING_ERROR_STATE);
    end
    else
    begin
        ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_CONDITIONAL_ERROR);
    end;
end;




procedure set_fips_state( state : integer);
begin
    if ossl_assert(CRYPTO_THREAD_write_lock(fips_state_lock) <> 0) then
    begin
        FIPS_state := state;
        CRYPTO_THREAD_unlock(fips_state_lock);
    end;
end;


function ossl_prov_is_running:Boolean;
var
  res : Boolean;
begin
    rate_limit := 0;
    if  0>= CRYPTO_THREAD_read_lock(fips_state_lock)  then
        Exit(false);
    res := (FIPS_state = FIPS_STATE_RUNNING)
                         or  (FIPS_state = FIPS_STATE_SELFTEST);
    if FIPS_state = FIPS_STATE_ERROR then
    begin
        CRYPTO_THREAD_unlock(fips_state_lock);
        if  0>= CRYPTO_THREAD_write_lock(fips_state_lock ) then
            Exit(False);
        if rate_limit < FIPS_ERROR_REPORTING_RATE_LIMIT  then
        begin
            ERR_raise(ERR_LIB_PROV, PROV_R_FIPS_MODULE_IN_ERROR_STATE);
            Inc(rate_limit);
        end;
    end;
    CRYPTO_THREAD_unlock(fips_state_lock);
    Result := res;
end;


end.
