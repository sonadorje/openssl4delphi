unit openssl3.crypto.init;

interface
uses OpenSSL.Api, SysUtils;

{$I config.inc}
type
  POPENSSL_INIT_STOP = ^TOPENSSL_INIT_STOP;
  ossl_init_stop_st = record
    handler: procedure();
    next: POPENSSL_INIT_STOP ;
  end;
  TOPENSSL_INIT_STOP = ossl_init_stop_st ;

function ossl_init_base:integer;
function OPENSSL_init_crypto(opts : uint64;const settings : POPENSSL_INIT_SETTINGS):integer;
function ossl_init_no_register_atexit:integer;
function ossl_init_register_atexit:integer;
function win32atexit:integer;
function ossl_init_no_load_crypto_strings:integer;
function ossl_init_load_crypto_nodelete:integer;
function ossl_init_load_crypto_strings:integer;
function ossl_init_no_add_all_ciphers:integer;
function ossl_init_add_all_ciphers:integer;
function ossl_init_no_add_all_digests:integer;
function ossl_init_add_all_digests:integer;
function ossl_init_no_config:integer;
function ossl_init_config:integer;
function ossl_init_config_settings:integer;
function ossl_init_async:integer;
function ossl_init_engine_openssl:integer;
function ossl_init_engine_rdrand:integer;
function ossl_init_engine_dynamic:integer;

procedure ossl_init_register_atexit_ossl_;
procedure ossl_init_base_ossl_;
procedure ossl_init_no_register_atexit_ossl_;
procedure OPENSSL_cleanup;
procedure ossl_store_cleanup_int;
procedure ossl_init_load_crypto_nodelete_ossl_;
procedure ossl_init_load_crypto_strings_ossl_;
procedure ossl_init_no_load_crypto_strings_ossl_;
procedure ossl_init_no_add_all_ciphers_ossl_;
procedure ossl_init_add_all_ciphers_ossl_;
procedure ossl_init_no_add_all_digests_ossl_;
procedure ossl_init_add_all_digests_ossl_;
procedure ossl_init_config_ossl_;
procedure ossl_init_no_config_ossl_;
procedure ossl_init_config_settings_ossl_;
procedure ossl_init_async_ossl_;
procedure ossl_init_engine_openssl_ossl_;
procedure ossl_init_engine_rdrand_ossl_;
procedure ossl_init_engine_dynamic_ossl_;


var
  stopped: int = 0;
  optsdone: uint64 = 0;
  base_inited: int = 0;
  load_crypto_strings_inited: int = 0;
  init_lock: PCRYPTO_RWLOCK  = nil;
  in_init_config_local: CRYPTO_THREAD_LOCAL ;
  base:  CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;
  register_atexit:  CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;
  ossl_init_base_ossl_ret_: int = 0;
  ossl_init_register_atexit_ossl_ret_: int = 0;
  stop_handlers: POPENSSL_INIT_STOP  = nil;
  load_crypto_nodelete: CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;
  async_inited: int = 0;
  ossl_init_load_crypto_nodelete_ossl_ret_: int = 0;
  load_crypto_strings: CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;
  ossl_init_load_crypto_strings_ossl_ret_: int = 0;
  add_all_ciphers: CRYPTO_ONCE  = CRYPTO_ONCE_STATIC_INIT;
  ossl_init_add_all_ciphers_ossl_ret_: int = 0;
  add_all_digests: CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;
  ossl_init_add_all_digests_ossl_ret_ : Int = 0;
  config: CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;
  ossl_init_config_ossl_ret_: int = 0;
  config_inited: int = 0;
  conf_settings: POPENSSL_INIT_SETTINGS = nil;
  async:  CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;
  ossl_init_async_ossl_ret_: int = 0;
  engine_openssl: CRYPTO_ONCE = CRYPTO_ONCE_STATIC_INIT;
  ossl_init_engine_openssl_ossl_ret_: int = 0;
  engine_rdrand: CRYPTO_ONCE  = 0;
  ossl_init_engine_rdrand_ossl_ret_ : int = 0;
  engine_dynamic: CRYPTO_ONCE  = 0;
  ossl_init_engine_dynamic_ossl_ret_ : Int = 0;

implementation

uses OpenSSL3.Err, OpenSSL3.threads_none, openssl3.crypto.cpuid,
     openssl3.crypto.initthread,          openssl3.crypto.mem,
     openssl3.crypto.rand.rand_lib,       openssl3.crypto.conf.conf_mod,
     openssl3.crypto.engine.eng_lib,      openssl3.crypto.store.store_register,
     openssl3.crypto.context,             openssl3.crypto.bio.bio_lib,
     openssl3.crypto.evp.names,           openssl3.crypto.objects.obj_dat,
     openssl3.crypto.mem_sec,             openssl3.crypto.cmp.cmp_util,
     openssl3.crypto.err.err_all,         openssl3.crypto.evp.c_allc,
     {$IFDEF MSWINDOWS}
        libc.win, {$IFDEF FPC} windows, {$ELSE} winapi.Windows,{$ENDIF}
     {$ENDIF}
     openssl3.crypto.trace,               openssl3.crypto.evp.c_alld,
     openssl3.crypto.engine.eng_fat,
     openssl3.crypto.conf.conf_sap,       openssl3.crypto.engine.eng_openssl,
     openssl3.crypto.engine.eng_rdrand,   openssl3.crypto.engine.eng_dyn,
     openssl3.crypto.comp.c_zlib,         openssl3.crypto.async.async;

procedure ossl_init_engine_dynamic_ossl_;
begin
 ossl_init_engine_dynamic_ossl_ret_ := ossl_init_engine_dynamic;
end;


function ossl_init_engine_dynamic:integer;
begin

    engine_load_dynamic_int;
    Result := 1;
end;


procedure ossl_init_engine_rdrand_ossl_;
begin
 ossl_init_engine_rdrand_ossl_ret_ := ossl_init_engine_rdrand;
end;


function ossl_init_engine_rdrand:integer;
begin
    //((void)0);
    engine_load_rdrand_int;
    Result := 1;
end;



procedure ossl_init_engine_openssl_ossl_;
begin
 ossl_init_engine_openssl_ossl_ret_ := ossl_init_engine_openssl;
end;


function ossl_init_engine_openssl:integer;
begin
    //((void)0);
    engine_load_openssl_int;
    Result := 1;
end;

procedure ossl_init_async_ossl_;
begin
 ossl_init_async_ossl_ret_ := ossl_init_async;
end;


function ossl_init_async:integer;
begin

    if 0>=async_init then Exit(0);
    async_inited := 1;
    Result := 1;
end;



procedure ossl_init_config_settings_ossl_;
begin
 ossl_init_config_ossl_ret_ := ossl_init_config_settings;
end;


function ossl_init_config_settings:integer;
var
  ret : integer;
begin
    ret := ossl_config_int(conf_settings);
    config_inited := 1;
    Result := ret;
end;


procedure ossl_init_config_ossl_;
begin
   ossl_init_config_ossl_ret_ := ossl_init_config();
end;


function ossl_init_config:integer;
var
  ret : integer;
begin
    ret := ossl_config_int(nil);
    config_inited := 1;
    Result := ret;
end;



procedure ossl_init_no_config_ossl_;
begin
   ossl_init_config_ossl_ret_ := ossl_init_no_config;
end;


function ossl_init_no_config:integer;
begin
    ossl_no_config_int;
    config_inited := 1;
    Result := 1;
end;



procedure ossl_init_add_all_digests_ossl_;
begin
 ossl_init_add_all_digests_ossl_ret_ := ossl_init_add_all_digests;
end;


function ossl_init_add_all_digests:integer;
begin
   //((void)0);
    openssl_add_all_digests_int;
    Result := 1;
end;


procedure ossl_init_no_add_all_digests_ossl_;
begin
 ossl_init_add_all_digests_ossl_ret_ := ossl_init_no_add_all_digests;
end;


function ossl_init_no_add_all_digests:integer;
begin
    Result := 1;
end;

procedure ossl_init_add_all_ciphers_ossl_;
begin
 ossl_init_add_all_ciphers_ossl_ret_ := ossl_init_add_all_ciphers;
end;


function ossl_init_add_all_ciphers:integer;
begin
    openssl_add_all_ciphers_int();
    Result := 1;
end;

procedure ossl_init_no_add_all_ciphers_ossl_;
begin
 ossl_init_add_all_ciphers_ossl_ret_ := ossl_init_no_add_all_ciphers();
end;


function ossl_init_no_add_all_ciphers:integer;
begin
    Result := 1;
end;

procedure ossl_init_load_crypto_strings_ossl_;
begin
   ossl_init_load_crypto_strings_ossl_ret_ := ossl_init_load_crypto_strings;
end;


function ossl_init_load_crypto_strings:integer;
var
  ret : integer;
begin
    ret := 1;
    //((void)0);
    ret := ossl_err_load_crypto_strings();
    load_crypto_strings_inited := 1;
    Result := ret;
end;



procedure ossl_init_no_load_crypto_strings_ossl_;
begin
  ossl_init_load_crypto_strings_ossl_ret_ := ossl_init_no_load_crypto_strings();
end;


function ossl_init_no_load_crypto_strings:integer;
begin
    Exit(1);
end;

procedure ossl_init_load_crypto_nodelete_ossl_;
begin
   ossl_init_load_crypto_nodelete_ossl_ret_ := ossl_init_load_crypto_nodelete;
end;


function ossl_init_load_crypto_nodelete:integer;
var
  handle : HMODULE;
  ret : Boolean;
begin
    begin
        handle := (0) ;
        ret := GetModuleHandleExW(($00000004) or ($00000001),
                                Pointer(@base_inited), handle);
        {OSSL_TRACE1(INIT,
                    "ossl_init_load_crypto_nodelete: "
                    "obtained DSO reference? %s\n",
                    (ret == TRUE ? "No!" : "Yes."));}
        Result := get_result(ret , 1 , 0);
    end;
    Exit(1);
end;


procedure ossl_store_cleanup_int;
begin
    ossl_store_destroy_loaders_int;
end;

procedure OPENSSL_cleanup;
var
  currhandler,
  lasthandler : POPENSSL_INIT_STOP;
begin
    {
     * At some point we should consider looking at this function with a view to
     * moving most/all of this into onfree handlers in OSSL_LIB_CTX.
     }
    { If we've not been inited then no need to deinit }
    if 0>= base_inited then Exit;
    { Might be explicitly called and also by atexit }
    if stopped>0 then Exit;
    stopped := 1;
    {
     * Thread stop may not get automatically called by the thread library for
     * the very last thread in some situations, so call it directly.
     }
    OPENSSL_thread_stop();
    currhandler := stop_handlers;
    while currhandler <> nil do
    begin
        currhandler.handler();
        lasthandler := currhandler;
        currhandler := currhandler.next;
        OPENSSL_free(Pointer(lasthandler));
    end;
    stop_handlers := nil;
    CRYPTO_THREAD_lock_free(init_lock);
    init_lock := nil;
    CRYPTO_THREAD_cleanup_local(@in_init_config_local);
    {
     * We assume we are single-threaded for this function, i.e. no race
     * conditions for the various '*_inited' vars below.
     }
{$IFNDEF OPENSSL_NO_COMP}
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: ossl_comp_zlib_cleanup()\n');
    ossl_comp_zlib_cleanup();
{$ENDIF}
    if async_inited > 0 then
    begin
        //OSSL_TRACE(INIT, 'OPENSSL_cleanup: async_deinit()\n');
        async_deinit();
    end;
    if load_crypto_strings_inited >0 then
    begin
        //OSSL_TRACE(INIT, 'OPENSSL_cleanup: err_free_strings_int()\n');
        err_free_strings_int();
    end;
    {
     * Note that cleanup order is important:
     * - ossl_rand_cleanup_int could call an ENGINE's RAND cleanup function so
     * must be called before engine_cleanup_int()
     * - ENGINEs use CRYPTO_EX_DATA and therefore, must be cleaned up
     * before the ex data handlers are wiped during default ossl_lib_ctx deinit.
     * - ossl_config_modules_free() can end up in ENGINE code so must be called
     * before engine_cleanup_int()
     * - ENGINEs and additional EVP algorithms might use added OIDs names so
     * ossl_obj_cleanup_int() must be called last
     }
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: ossl_rand_cleanup_int()'#10);
    ossl_rand_cleanup_int();
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: ossl_config_modules_free()'#10);
    ossl_config_modules_free();
{$IFNDEF OPENSSL_NO_ENGINE}
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: engine_cleanup_int()'#10);
    engine_cleanup_int();
{$ENDIF}
{$IFNDEF OPENSSL_NO_DEPRECATED_3_0}
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: ossl_store_cleanup_int()'#10);
    ossl_store_cleanup_int();
{$ENDIF}
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: ossl_lib_ctx_default_deinit()'#10);
    ossl_lib_ctx_default_deinit();
    ossl_cleanup_thread();
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: bio_cleanup()'#10);
    bio_cleanup();
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: evp_cleanup_int()'#10);
    evp_cleanup_int();
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: ossl_obj_cleanup_int()'#10);
    ossl_obj_cleanup_int();
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: err_int()'#10);
    err_cleanup();
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: CRYPTO_secure_malloc_done()'#10);
    CRYPTO_secure_malloc_done();
{$IFNDEF OPENSSL_NO_CMP}
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: OSSL_CMP_log_close()'#10);
    OSSL_CMP_log_close();
{$ENDIF}
    //OSSL_TRACE(INIT, 'OPENSSL_cleanup: ossl_trace_cleanup()'#10);
    ossl_trace_cleanup();
    base_inited := 0;
end;

{$if not defined(OPENSSL_SYS_UEFI) and defined(MSWINDOWS)}
function win32atexit:integer;
begin
    OPENSSL_cleanup();
    Result := 0;
end;
{$ENDIF}


procedure ossl_init_register_atexit_ossl_;
begin
 ossl_init_register_atexit_ossl_ret_ := ossl_init_register_atexit();
end;


function ossl_init_register_atexit:integer;
begin
{$ifndef OPENSSL_SYS_UEFI}
 {$if defined(MSWINDOWS) and not defined(__BORLANDC__)}
    if not Assigned(_onexit(win32atexit)) then
        Exit(0);
 {$else}  //atexit()函数注册的函数，在程序退出时候按照注册的顺序相反被调用
    try
      AddExitProc(OPENSSL_cleanup);
    except
      exit( 0);
    end;

  {$endif}
{$endif}
    Result := 1;
end;



function ossl_init_no_register_atexit:integer;
begin
    Result := 1;
end;

procedure ossl_init_no_register_atexit_ossl_;
begin
  ossl_init_register_atexit_ossl_ret_ := ossl_init_no_register_atexit();
end;

procedure ossl_init_base_ossl_;
begin
   ossl_init_base_ossl_ret_ := ossl_init_base();
end;

function ossl_init_base:integer;
label _err;
begin
    //((void)0);
    init_lock := CRYPTO_THREAD_lock_new();
    if init_lock = Pointer(0)  then
        goto _err ;
    OPENSSL_cpuid_setup();
    if 0>= ossl_init_thread() then
        goto _err ;
    if 0>= CRYPTO_THREAD_init_local(@in_init_config_local, Pointer(0))  then
        goto _err ;
    base_inited := 1;
    Exit(1);
_err:
    //((void)0);
    CRYPTO_THREAD_lock_free(init_lock);
    init_lock := Pointer(0) ;
    Result := 0;
end;


function OPENSSL_init_crypto(opts : uint64;const settings : POPENSSL_INIT_SETTINGS):integer;
var
  tmp       : uint64;
  aloaddone,
  loading,
  ret       : integer;
begin
    aloaddone := 0;
   { Applications depend on 0 being returned when cleanup was already done }
    if stopped > 0 then
    begin
        if 0>= (opts and OPENSSL_INIT_BASE_ONLY) then
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_INIT_FAIL);
        Exit(0);
    end;
    {
     * We ignore failures from this function. It is probably because we are
     * on a platform that doesn't support lockless atomic loads (we may not
     * have created init_lock yet so we can't use it). This is just an
     * optimisation to skip the full checks in this function if we don't need
     * to, so we carry on regardless in the event of failure.
     *
     * There could be a race here with other threads, so that optsdone has not
     * been updated yet, even though the options have in fact been initialised.
     * This doesn't matter - it just means we will run the full function
     * unnecessarily - but all the critical code is contained in RUN_ONCE
     * functions anyway so we are safe.
     }
    if CRYPTO_atomic_load(@optsdone, @tmp, nil)>0 then
    begin
        if (tmp and opts) = opts then
            Exit(1);
        aloaddone := 1;
    end;
    {
     * At some point we should look at this function with a view to moving
     * most/all of this into OSSL_LIB_CTX.
     *
     * When the caller specifies OPENSSL_INIT_BASE_ONLY, that should be the
     * *only* option specified.  With that option we return immediately after
     * doing the requested limited initialization.  Note that
     * err_shelve_state() called by us via ossl_init_load_crypto_nodelete()
     * re-enters OPENSSL_init_crypto() with OPENSSL_INIT_BASE_ONLY, but with
     * base already initialized this is a harmless NOOP.
     *
     * If we remain the only caller of err_shelve_state() the recursion should
     * perhaps be removed, but if in doubt, it can be left in place.
     }
     if 0>= get_result(CRYPTO_THREAD_run_once(@base, ossl_init_base_ossl_)>0 , ossl_init_base_ossl_ret_ , 0) then
        Exit(0);
    if (opts and OPENSSL_INIT_BASE_ONLY) > 0 then
        Exit(1);
    {
     * init_lock should definitely be set up now, so we can now repeat the
     * same check from above but be sure that it will work even on platforms
     * without lockless CRYPTO_atomic_load
     }
    if 0>= aloaddone then
    begin
        if 0>= CRYPTO_atomic_load(@optsdone, @tmp, init_lock) then
            Exit(0);
        if (tmp and opts) = opts then
            Exit(1);
    end;
    {
     * Now we don't always set up exit handlers, the INIT_BASE_ONLY calls
     * should not have the side-effect of setting up exit handlers, and
     * therefore, this code block is below the INIT_BASE_ONLY-conditioned early
     * return above.
     }
    if (opts and OPENSSL_INIT_NO_ATEXIT ) <> 0 then
    begin
        if 0>= get_result(CRYPTO_THREAD_run_once(@register_atexit, ossl_init_no_register_atexit_ossl_) >0,
                         ossl_init_register_atexit_ossl_ret_ , 0) then

            Exit(0);
    end
    else
    if 0>= get_result(CRYPTO_THREAD_run_once(@register_atexit, ossl_init_register_atexit_ossl_) > 0,
               ossl_init_register_atexit_ossl_ret_ , 0) then
    begin
        Exit(0);
    end;
    //if 0>= RUN_ONCE(&load_crypto_nodelete, ossl_init_load_crypto_nodelete then )
    if 0>= get_result(CRYPTO_THREAD_run_once(@load_crypto_nodelete, ossl_init_load_crypto_nodelete_ossl_) >0,
             ossl_init_load_crypto_nodelete_ossl_ret_ , 0) then

        Exit(0);
    if (opts and OPENSSL_INIT_NO_LOAD_CRYPTO_STRINGS > 0) and
           (0>= get_result(CRYPTO_THREAD_run_once(@load_crypto_strings, ossl_init_no_load_crypto_strings_ossl_) > 0, ossl_init_load_crypto_strings_ossl_ret_ , 0)) then

        Exit(0);
    if (opts and OPENSSL_INIT_LOAD_CRYPTO_STRINGS >0)
           and (0>= get_result(CRYPTO_THREAD_run_once(@load_crypto_strings, ossl_init_load_crypto_strings_ossl_) >0, ossl_init_load_crypto_strings_ossl_ret_ , 0)) then
        Exit(0);
    if (opts and OPENSSL_INIT_NO_ADD_ALL_CIPHERS >0)
            and (0>=get_result(CRYPTO_THREAD_run_once(@add_all_ciphers, ossl_init_no_add_all_ciphers_ossl_) >0, ossl_init_add_all_ciphers_ossl_ret_ , 0)) then
        Exit(0);
    if (opts and OPENSSL_INIT_ADD_ALL_CIPHERS > 0)
           and (0>=get_result(CRYPTO_THREAD_run_once(@add_all_ciphers, ossl_init_add_all_ciphers_ossl_) > 0, ossl_init_add_all_ciphers_ossl_ret_ , 0)) then

        Exit(0);
    if (opts and OPENSSL_INIT_NO_ADD_ALL_DIGESTS >0)
            and (0>=get_result(CRYPTO_THREAD_run_once(@add_all_digests, ossl_init_no_add_all_digests_ossl_) > 0, ossl_init_add_all_digests_ossl_ret_ , 0)) then
        Exit(0);
    if (opts and OPENSSL_INIT_ADD_ALL_DIGESTS > 0)
            and (0>=get_result(CRYPTO_THREAD_run_once(@add_all_digests, ossl_init_add_all_digests_ossl_) >0, ossl_init_add_all_digests_ossl_ret_ , 0)) then
        Exit(0);
    if (opts and OPENSSL_INIT_ATFORK > 0)  and  (0>= openssl_init_fork_handlers) then
        Exit(0);
    if (opts and OPENSSL_INIT_NO_LOAD_CONFIG > 0)
            and (0>=get_result(CRYPTO_THREAD_run_once(@config, ossl_init_no_config_ossl_) >0, ossl_init_config_ossl_ret_ , 0)) then
        Exit(0);
    if opts and OPENSSL_INIT_LOAD_CONFIG > 0 then
    begin
        loading := Int(CRYPTO_THREAD_get_local(@in_init_config_local) <> nil);
        { If called recursively from OBJ_ calls, just skip it. }
        if 0>= loading then
        begin
            if 0>= CRYPTO_THREAD_set_local(@in_init_config_local, Pointer( -1)) then
                Exit(0);
            if settings = nil then begin
                ret := get_result(CRYPTO_THREAD_run_once(@config, ossl_init_config_ossl_) > 0, ossl_init_config_ossl_ret_ , 0);
            end
            else
            begin
                if 0>= CRYPTO_THREAD_write_lock(init_lock) then
                    Exit(0);
                conf_settings := settings;
                ret := get_result(CRYPTO_THREAD_run_once(@config, ossl_init_config_settings_ossl_) > 0, ossl_init_config_ossl_ret_ , 0);
                conf_settings := nil;
                CRYPTO_THREAD_unlock(init_lock);
            end;
            if ret <= 0 then Exit(0);
        end;
    end;
    if (opts and OPENSSL_INIT_ASYNC > 0)
       and  (0>=get_result(CRYPTO_THREAD_run_once(@async, ossl_init_async_ossl_) > 0, ossl_init_async_ossl_ret_ , 0)) then
        Exit(0);
{$IFNDEF OPENSSL_NO_ENGINE}
    if (opts and OPENSSL_INIT_ENGINE_OPENSSL > 0)
       and  (0>= get_result(CRYPTO_THREAD_run_once(@engine_openssl, ossl_init_engine_openssl_ossl_) > 0, ossl_init_engine_openssl_ossl_ret_ , 0)) then
        Exit(0);
{$IFNDEF OPENSSL_NO_RDRAND}
    if (opts and OPENSSL_INIT_ENGINE_RDRAND > 0)
    and  (0>= get_result(CRYPTO_THREAD_run_once(@engine_rdrand, ossl_init_engine_rdrand_ossl_) >0, ossl_init_engine_rdrand_ossl_ret_ , 0)) then
        Exit(0);
{$ENDIF}
    if (opts and OPENSSL_INIT_ENGINE_DYNAMIC > 0)
       and  (0>= get_result(CRYPTO_THREAD_run_once(@engine_dynamic, ossl_init_engine_dynamic_ossl_) > 0, ossl_init_engine_dynamic_ossl_ret_ , 0)) then
        Exit(0);
{$IFNDEF OPENSSL_NO_STATIC_ENGINE}
{$IFNDEF OPENSSL_NO_DEVCRYPTOENG}
    if opts and OPENSSL_INIT_ENGINE_CRYPTODEV then  and  (0>= RUN_ONCE(@engine_devcrypto, ossl_init_engine_devcrypto) then
        Exit(0);
{$ENDIF}
{$IF not defined(OPENSSL_NO_PADLOCKENG)}
    if opts and OPENSSL_INIT_ENGINE_PADLOCK then  and  (0>= RUN_ONCE(@engine_padlock, ossl_init_engine_padlock) then
        Exit(0);
{$ENDIF}
{$IF defined(OPENSSL_SYS_WIN32)  and  not defined(OPENSSL_NO_CAPIENG)}
    if opts and OPENSSL_INIT_ENGINE_CAPI then  and  (0>= RUN_ONCE(@engine_capi, ossl_init_engine_capi) then
        Exit(0);
{$ENDIF}
{$IF not defined(OPENSSL_NO_AFALGENG)}
    if opts and OPENSSL_INIT_ENGINE_AFALG then  and  (0>= RUN_ONCE(@engine_afalg, ossl_init_engine_afalg) then
        Exit(0);
{$ENDIF}
{$ENDIF}
    if opts and (OPENSSL_INIT_ENGINE_ALL_BUILTIN
                or OPENSSL_INIT_ENGINE_OPENSSL
                or OPENSSL_INIT_ENGINE_AFALG) > 0 then
    begin
        ENGINE_register_all_complete();
    end;
{$ENDIF}
    if 0>= CRYPTO_atomic_or(@optsdone, opts, @tmp, init_lock) then
        Exit(0);
    Result := 1;
end;

end.
