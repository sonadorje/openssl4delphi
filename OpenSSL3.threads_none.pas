unit OpenSSL3.threads_none;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

type
  Tthreads_none_init_func1 = procedure();
  Tthreads_none_init_func2 = function(): int;
  Tcleanup_func = procedure(p1: Pointer);

const
  OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX = 256;

function CRYPTO_THREAD_read_lock(lock : PCRYPTO_RWLOCK):integer;
function CRYPTO_THREAD_run_once( once : PCRYPTO_ONCE; init: Tthreads_none_init_func1):integer; overload;
function CRYPTO_THREAD_run_once( once : PCRYPTO_ONCE; init: Tthreads_none_init_func2):integer; overload;
function CRYPTO_THREAD_init_local( key : PCRYPTO_THREAD_LOCAL; cleanup : Tcleanup_func):integer;
function openssl_get_fork_id:integer;
function CRYPTO_THREAD_write_lock( lock : PCRYPTO_RWLOCK):integer;
function CRYPTO_THREAD_unlock( lock : PCRYPTO_RWLOCK):integer;
procedure CRYPTO_THREAD_lock_free(lock : PCRYPTO_RWLOCK);
function CRYPTO_THREAD_lock_new:PCRYPTO_RWLOCK;
function CRYPTO_THREAD_get_local( key : PCRYPTO_THREAD_LOCAL):Pointer;
function CRYPTO_THREAD_set_local( key : PCRYPTO_THREAD_LOCAL; val : Pointer):integer;
function CRYPTO_atomic_load( val, ret : Puint64_t; lock : PCRYPTO_RWLOCK):integer;
function CRYPTO_THREAD_cleanup_local( key : PCRYPTO_THREAD_LOCAL):integer;
function CRYPTO_THREAD_compare_id( a, b : CRYPTO_THREAD_ID):integer;
function CRYPTO_THREAD_get_current_id:CRYPTO_THREAD_ID;
function CRYPTO_atomic_add( val : PInteger; amount : integer; ret : PInteger; lock : PCRYPTO_RWLOCK):integer;

var
  thread_local_storage : array[0..(OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX)-1] of Pointer;
  thread_local_key: uint32 = 0;

function openssl_init_fork_handlers:integer;
function CRYPTO_atomic_or( val : Puint64_t; op : uint64; ret : Puint64_t; lock : PCRYPTO_RWLOCK):integer;

implementation

uses OpenSSL3.common, openssl3.crypto.mem;

function CRYPTO_atomic_or( val : Puint64_t; op : uint64; ret : Puint64_t; lock : PCRYPTO_RWLOCK):integer;
begin
    val^  := val^  or op;
    ret^  := val^;
    Result := 1;
end;



function openssl_init_fork_handlers:integer;
begin
    Result := 0;
end;

function CRYPTO_atomic_add( val : PInteger; amount : integer; ret : PInteger; lock : PCRYPTO_RWLOCK):integer;
begin
    val^  := val^ + amount;
    ret^  := val^;
    Result := 1;
end;


function CRYPTO_THREAD_get_current_id:CRYPTO_THREAD_ID;
begin
    Result := 0;
end;



function CRYPTO_THREAD_compare_id( a, b : CRYPTO_THREAD_ID):integer;
begin
    Result := int(a = b);
end;

function CRYPTO_THREAD_cleanup_local( key : PCRYPTO_THREAD_LOCAL):integer;
begin
    key^ := OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX + 1;
    Result := 1;
end;


function CRYPTO_atomic_load( val, ret : Puint64_t; lock : PCRYPTO_RWLOCK):integer;
begin
    ret^  := val^;
    Result := 1;
end;

function CRYPTO_THREAD_set_local( key : PCRYPTO_THREAD_LOCAL; val : Pointer):integer;
begin
    if key^ >= OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX then
       Exit(0);
    thread_local_storage[key^] := val;
    Result := 1;
end;

function CRYPTO_THREAD_get_local(key : PCRYPTO_THREAD_LOCAL):Pointer;
begin
    if key^ >= OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX then
       Exit(nil);
    Result := thread_local_storage[key^];
end;

function CRYPTO_THREAD_lock_new:PCRYPTO_RWLOCK;
begin
    Result := OPENSSL_zalloc(sizeof(uint32));
    if Result = nil then
    begin
        { Don't set error, to avoid recursion blowup. }
        Exit(nil);
    end;
    Puint32(Result)^ := 1;
end;

procedure CRYPTO_THREAD_lock_free( lock : PCRYPTO_RWLOCK);
begin
    if lock = nil then exit;
    Puint32(lock)^ := 0;
    OPENSSL_free(Pointer(lock));
    exit;
end;

function CRYPTO_THREAD_unlock( lock : PCRYPTO_RWLOCK):integer;
begin
    if not ossl_assert(Puint32(lock)^ = 1) then
        Exit(0);
    Result := 1;
end;

function CRYPTO_THREAD_write_lock( lock : PCRYPTO_RWLOCK):integer;
begin
    if not ossl_assert(lock^ = 1) then
        Exit(0);
    Result := 1;
end;

function openssl_get_fork_id:integer;
begin
{$IF defined(OPENSSL_SYS_UNIX)}
    Exit(getpid());
{$ELSE}
    Exit(0);
{$ENDIF}
end;


function CRYPTO_THREAD_init_local( key : PCRYPTO_THREAD_LOCAL; cleanup : Tcleanup_func):integer;
begin
    if thread_local_key >= OPENSSL_CRYPTO_THREAD_LOCAL_KEY_MAX then
       Exit(0);

    key^ := thread_local_key;
    Inc(thread_local_key);
    thread_local_storage[key^] := nil;
    Result := 1;
end;

function CRYPTO_THREAD_run_once( once : PCRYPTO_ONCE; init: Tthreads_none_init_func1):integer;
begin
    if once^ <> 0 then
       Exit(1);
    init();
    once^ := 1;
    Result := 1;
end;

function CRYPTO_THREAD_run_once( once : PCRYPTO_ONCE; init: Tthreads_none_init_func2):integer;
begin
    if once^ <> 0 then
       Exit(1);
    init();
    once^ := 1;
    Result := 1;
end;

function CRYPTO_THREAD_read_lock(lock : PCRYPTO_RWLOCK):integer;
begin
    if not ossl_assert((Puint32(lock)^ = 1))  then
       Exit(0);
    Result := 1;
end;

end.
