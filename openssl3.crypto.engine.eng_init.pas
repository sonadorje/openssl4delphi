unit openssl3.crypto.engine.eng_init;

interface
uses OpenSSL.Api;

function ENGINE_init( e : PENGINE):integer;
function engine_unlocked_init( e : PENGINE):integer;
function engine_unlocked_finish( e : PENGINE; unlock_for_handlers : integer):integer;
 function ENGINE_finish( e : PENGINE):integer;

implementation
uses OpenSSL3.Err, OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib,
     openssl3.include.internal.refcount;





function ENGINE_finish( e : PENGINE):integer;
var
  to_return : integer;
begin
    to_return := 1;
    if e = nil then
       Exit(1);
    if 0>= CRYPTO_THREAD_write_lock(global_engine_lock) then
        Exit(0);
    to_return := engine_unlocked_finish(e, 1);
    CRYPTO_THREAD_unlock(global_engine_lock);
    if 0>= to_return then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_FINISH_FAILED);
        Exit(0);
    end;
    Result := to_return;
end;



function engine_unlocked_finish( e : PENGINE; unlock_for_handlers : integer):integer;
var
  to_return : integer;
begin
    to_return := 1;
    {
     * Reduce the functional reference count here so if it's the terminating
     * case, we can release the lock safely and call the finish() handler
     * without risk of a race. We get a race if we leave the count until
     * after and something else is calling 'finish' at the same time -
     * there's a chance that both threads will together take the count from 2
     * to 0 without either calling finish().
     }
    Dec(e.funct_ref);
    ENGINE_REF_PRINT(e, 1, -1);
    if (e.funct_ref = 0 ) and  (Assigned(e.finish)) then
    begin
        if unlock_for_handlers > 0 then
            CRYPTO_THREAD_unlock(global_engine_lock);
        to_return := e.finish(e);
        if unlock_for_handlers > 0 then
           if (0>= CRYPTO_THREAD_write_lock(global_engine_lock)) then
                Exit(0);
        if 0>= to_return then Exit(0);
    end;
    REF_ASSERT_ISNT(e.funct_ref < 0);
    { Release the structural reference too }
    if 0>= engine_free_util(e, 0 ) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_FINISH_FAILED);
        Exit(0);
    end;
    Result := to_return;
end;

function engine_unlocked_init( e : PENGINE):integer;
var
  to_return : integer;
begin
    to_return := 1;
    if (e.funct_ref = 0 )  and (Assigned(e.init)) then
        {
         * This is the first functional reference and the engine requires
         * initialisation so we do it now.
         }
        to_return := e.init(e);
    if to_return>0 then
    begin
        {
         * OK, we return a functional reference which is also a structural
         * reference.
         }
        Inc(e.struct_ref);
        Inc(e.funct_ref);
        //ENGINE_REF_PRINT(e, 0, 1);
        //ENGINE_REF_PRINT(e, 1, 1);
    end;
    Result := to_return;
end;




function ENGINE_init( e : PENGINE):integer;
var
  ret : integer;
  function RUN_ONCE( once : PCRYPTO_ONCE; init: Tthreads_none_init_func2):integer;
  begin
     if CRYPTO_THREAD_run_once(@engine_lock_init, do_engine_lock_init_ossl_)>0 then
        Result := do_engine_lock_init_ossl_ret_
     else
        Result := 0;
  end;
begin
    if e = nil then
    begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if  0>= RUN_ONCE(@engine_lock_init, do_engine_lock_init) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if  0>= CRYPTO_THREAD_write_lock(global_engine_lock)  then
        Exit(0);
    ret := engine_unlocked_init(e);
    CRYPTO_THREAD_unlock(global_engine_lock);
    Result := ret;
end;
end.
