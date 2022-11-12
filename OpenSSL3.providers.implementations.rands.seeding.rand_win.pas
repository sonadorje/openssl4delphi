unit OpenSSL3.providers.implementations.rands.seeding.rand_win;

interface
uses OpenSSL.Api, windows, Types;

const
   PROV_INTEL_SEC = 22;
   INTEL_DEF_PROV = 'Intel Hardware Cryptographic Service Provider';

function ossl_pool_acquire_entropy( pool : PRAND_POOL):size_t;
function ossl_pool_add_nonce_data( pool : PRAND_POOL):integer;
function ossl_rand_pool_add_additional_data( pool : PRAND_POOL):integer;
function ossl_rand_pool_init:integer;
procedure ossl_rand_pool_cleanup;
procedure ossl_rand_pool_keep_random_devices_open( keep : integer);

implementation
uses {$IFDEF  MSWINDOWS}jwawincrypt,{$ENDIF}
    openssl3.crypto.rand.rand_pool;

function ossl_pool_acquire_entropy( pool : PRAND_POOL):size_t;
var
{$IFNDEF USE_BCRYPTGENRANDOM}
  hProvider         : HCRYPTPROV;
{$ENDIF}
  buffer            : PByte;
  bytes_needed,
  entropy_available,
  bytes             : size_t;
begin
    entropy_available := 0;
{$IFDEF OPENSSL_RAND_SEED_RDTSC}
    entropy_available := ossl_prov_acquire_entropy_from_tsc(pool);
    if entropy_available > 0 then Exit(entropy_available);
{$ENDIF}
{$IFDEF OPENSSL_RAND_SEED_RDCPU}
    entropy_available := ossl_prov_acquire_entropy_from_cpu(pool);
    if entropy_available > 0 then Exit(entropy_available);
{$ENDIF}
{$IFDEF USE_BCRYPTGENRANDOM}
    bytes_needed := ossl_rand_pool_bytes_needed(pool, 1 {entropy_factor});
    buffer := ossl_rand_pool_add_begin(pool, bytes_needed);
    if buffer <> nil then
    begin
        bytes := 0;
        if BCryptGenRandom(nil, buffer, bytes_needed,
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) = STATUS_SUCCESS) then
            bytes := bytes_needed;
        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available := ossl_rand_pool_entropy_available(pool);
    end;
    if entropy_available > 0 then
       Exit(entropy_available);
{$ELSE}
    bytes_needed := ossl_rand_pool_bytes_needed(pool, 1); {entropy_factor}

    buffer := ossl_rand_pool_add_begin(pool, bytes_needed);
    if buffer <> nil then
    begin
        bytes := 0;
        { poll the CryptoAPI PRNG }
        if CryptAcquireContextW(hProvider, nil, nil, PROV_RSA_FULL,
                 CRYPT_VERIFYCONTEXT or CRYPT_SILENT) <> Boolean(0) then
        begin
            if CryptGenRandom(hProvider, bytes_needed, buffer) <> Boolean(0) then
                bytes := bytes_needed;
            CryptReleaseContext(hProvider, 0);
        end;
        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available := ossl_rand_pool_entropy_available(pool);
    end;
    if entropy_available > 0 then Exit(entropy_available);
    bytes_needed := ossl_rand_pool_bytes_needed(pool, 1 {entropy_factor});
    buffer := ossl_rand_pool_add_begin(pool, bytes_needed);
    if buffer <> nil then
    begin
        bytes := 0;
        { poll the Pentium PRG with CryptoAPI }
        if CryptAcquireContextW(hProvider, nil,
                                 INTEL_DEF_PROV, PROV_INTEL_SEC,
                                 CRYPT_VERIFYCONTEXT or CRYPT_SILENT)  <> Boolean(0) then
        begin
            if CryptGenRandom(hProvider, bytes_needed, buffer) <> Boolean(0) then
                bytes := bytes_needed;
            CryptReleaseContext(hProvider, 0);
        end;
        ossl_rand_pool_add_end(pool, bytes, 8 * bytes);
        entropy_available := ossl_rand_pool_entropy_available(pool);
    end;
    if entropy_available > 0 then Exit(entropy_available);
{$ENDIF}
    Result := ossl_rand_pool_entropy_available(pool);
end;

function ossl_pool_add_nonce_data( pool : PRAND_POOL):integer;
type
  data_st = record
    pid, tid : DWORD;
    time : FILETIME;
  end;
var
  pid, tid : DWORD;
  data: data_st;
  time : FILETIME;
begin

    { Erase the entire structure including any padding }
    memset(@data, 0, sizeof(data));
    {
     * Add process id, thread id, and a high resolution timestamp to
     * ensure that the nonce is unique with high probability for
     * different process instances.
     }
    data.pid := GetCurrentProcessId;
    data.tid := GetCurrentThreadId;
    GetSystemTimeAsFileTime(&data.time);
    Result := ossl_rand_pool_add(pool, PByte(@data), sizeof(data), 0);
end;

function ossl_rand_pool_add_additional_data( pool : PRAND_POOL):integer;
type
  data_st = record
    tid : DWORD;
    time : TLargeInteger;
  end;

var
  tid : DWORD;
  data: data_st;

begin

    { Erase the entire structure including any padding }
    memset(@data, 0, sizeof(data));
    {
     * Add some noise from the thread id and a high resolution timer.
     * The thread id adds a little randomness if the drbg is accessed
     * concurrently (which is the case for the <master> drbg).
     }
    data.tid := GetCurrentThreadId;
    QueryPerformanceCounter(data.time);
    Result := ossl_rand_pool_add(pool, PByte(@data), sizeof(data), 0);
end;


function ossl_rand_pool_init:integer;
begin
    Result := 1;
end;


procedure ossl_rand_pool_cleanup;
begin

end;

procedure ossl_rand_pool_keep_random_devices_open( keep : integer);
begin

end;
end.
