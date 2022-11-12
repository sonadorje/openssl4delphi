unit openssl3.crypto.rand.rand_pool;

interface
uses OpenSSL.Api;

const
   RAND_POOL_FACTOR = 256;
   RAND_POOL_MAX_LENGTH =  (RAND_POOL_FACTOR *
                                  3 * (RAND_DRBG_STRENGTH div 16));

function ossl_rand_pool_new( entropy_requested, secure : integer; min_len, max_len : size_t):PRAND_POOL;
function ossl_rand_pool_bytes_needed( pool : PRAND_POOL; entropy_factor : uint32):size_t;
function ossl_rand_pool_entropy_needed( pool : PRAND_POOL):size_t;
function ENTROPY_TO_BYTES(bits: size_t; entropy_factor: UInt32) :size_t;
function rand_pool_grow( pool : PRAND_POOL; len : size_t):integer;
function ossl_rand_pool_add_begin( pool : PRAND_POOL; len : size_t):PByte;
 function ossl_rand_pool_add_end( pool : PRAND_POOL; len, entropy : size_t):integer;
function ossl_rand_pool_entropy_available( pool : PRAND_POOL):size_t;
function ossl_rand_pool_buffer( pool : PRAND_POOL):PByte;
function ossl_rand_pool_length( pool : PRAND_POOL):size_t;
procedure ossl_rand_pool_free( pool : PRAND_POOL);
function ossl_rand_pool_add(pool : PRAND_POOL;const buffer : PByte; len, entropy : size_t):integer;
function ossl_rand_pool_detach( pool : PRAND_POOL):PByte;

implementation
uses openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.mem_sec;


function ossl_rand_pool_detach( pool : PRAND_POOL):PByte;
var
  ret : PByte;
begin
    ret := pool.buffer;
    pool.buffer := nil;
    pool.entropy := 0;
    Result := ret;
end;



function ossl_rand_pool_add(pool : PRAND_POOL;const buffer : PByte; len, entropy : size_t):integer;
begin
    if len > pool.max_len - pool.len then begin
        ERR_raise(ERR_LIB_RAND, RAND_R_ENTROPY_INPUT_TOO_LONG);
        Exit(0);
    end;
    if pool.buffer = nil then begin
        ERR_raise(ERR_LIB_RAND, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    if len > 0 then begin
        {
         * This is to protect us from accidentally passing the buffer
         * returned from ossl_rand_pool_add_begin.
         * The check for alloc_len makes sure we do not compare the
         * address of the end of the allocated memory to something
         * different, since that comparison would have an
         * indeterminate result.
         }
        if (pool.alloc_len > pool.len)  and  (pool.buffer + pool.len = buffer) then
        begin
            ERR_raise(ERR_LIB_RAND, ERR_R_INTERNAL_ERROR);
            Exit(0);
        end;
        {
         * We have that only for cases when a pool is used to collect
         * additional data.
         * For entropy data, as long as the allocation request stays within
         * the limits given by ossl_rand_pool_bytes_needed this rand_pool_grow
         * below is guaranteed to succeed, thus no allocation happens.
         }
        if 0>=rand_pool_grow(pool, len) then
            Exit(0);
        memcpy(pool.buffer + pool.len, buffer, len);
        pool.len  := pool.len + len;
        pool.entropy  := pool.entropy + entropy;
    end;
    Result := 1;
end;


procedure ossl_rand_pool_free( pool : PRAND_POOL);
begin
    if pool = nil then exit;
    {
     * Although it would be advisable from a cryptographical viewpoint,
     * we are not allowed to clear attached buffers, since they are passed
     * to ossl_rand_pool_attach() as `const PByte `.
     * (see corresponding comment in ossl_rand_pool_attach()).
     }
    if  0>= pool.attached then
    begin
        if pool.secure>0 then
            OPENSSL_secure_clear_free(pool.buffer, pool.alloc_len)
        else
            OPENSSL_clear_free(Pointer(pool.buffer), pool.alloc_len);
    end;
    OPENSSL_free(Pointer(pool));
end;



function ossl_rand_pool_length( pool : PRAND_POOL):size_t;
begin
    Result := pool.len;
end;

function ossl_rand_pool_buffer( pool : PRAND_POOL):PByte;
begin
    Result := pool.buffer;
end;

function ossl_rand_pool_entropy_available( pool : PRAND_POOL):size_t;
begin
    if pool.entropy < pool.entropy_requested then Exit(0);
    if pool.len < pool.min_len then Exit(0);
    Result := pool.entropy;
end;

function ossl_rand_pool_add_end( pool : PRAND_POOL; len, entropy : size_t):integer;
begin
    if len > pool.alloc_len - pool.len then begin
        ERR_raise(ERR_LIB_RAND, RAND_R_RANDOM_POOL_OVERFLOW);
        Exit(0);
    end;
    if len > 0 then begin
        pool.len  := pool.len + len;
        pool.entropy  := pool.entropy + entropy;
    end;
    Result := 1;
end;

function ossl_rand_pool_add_begin( pool : PRAND_POOL; len : size_t):PByte;
begin
    if len = 0 then Exit(nil);
    if len > pool.max_len - pool.len then begin
        ERR_raise(ERR_LIB_RAND, RAND_R_RANDOM_POOL_OVERFLOW);
        Exit(nil);
    end;
    if pool.buffer = nil then begin
        ERR_raise(ERR_LIB_RAND, ERR_R_INTERNAL_ERROR);
        Exit(nil);
    end;
    {
     * As long as the allocation request stays within the limits given
     * by ossl_rand_pool_bytes_needed this rand_pool_grow below is guaranteed
     * to succeed, thus no allocation happens.
     * We have that only for cases when a pool is used to collect
     * additional data. Then the buffer might need to grow here,
     * and of course the caller is responsible to check the return
     * value of this function.
     }
    if  0>= rand_pool_grow(pool, len)  then
        Exit(nil);
    Result := pool.buffer + pool.len;
end;


function rand_pool_grow( pool : PRAND_POOL; len : size_t):integer;
var
  p : PByte;
  limit, newlen : size_t;
begin
    if len > pool.alloc_len - pool.len then
    begin
         limit := pool.max_len div 2;
        newlen := pool.alloc_len;
        if (pool.attached>0)  or  (len > pool.max_len - pool.len) then
        begin
            ERR_raise(ERR_LIB_RAND, ERR_R_INTERNAL_ERROR);
            Exit(0);
        end;
        repeat
            if newlen < limit then
               newlen := newlen * 2
            else
               newlen := pool.max_len;
        until not( len > newlen - pool.len) ;

        if pool.secure >0 then
           p := OPENSSL_secure_zalloc(newlen)
        else
            p := OPENSSL_zalloc(newlen);
        if p = nil then
        begin
            ERR_raise(ERR_LIB_RAND, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        memcpy(p, pool.buffer, pool.len);
        if pool.secure>0 then
           OPENSSL_secure_clear_free(pool.buffer, pool.alloc_len)
        else
            OPENSSL_clear_free(Pointer(pool.buffer), pool.alloc_len);
        pool.buffer := p;
        pool.alloc_len := newlen;
    end;
    Result := 1;
end;

function ENTROPY_TO_BYTES(bits: size_t; entropy_factor: UInt32) :size_t;
begin
  Result := (((bits) * (entropy_factor) + 7) div 8)
end;


function ossl_rand_pool_entropy_needed( pool : PRAND_POOL):size_t;
begin
    if pool.entropy < pool.entropy_requested then
       Exit(pool.entropy_requested - pool.entropy);
    Result := 0;
end;

function ossl_rand_pool_bytes_needed( pool : PRAND_POOL; entropy_factor : uint32):size_t;
var
  bytes_needed,
  entropy_needed : size_t;
begin
    entropy_needed := ossl_rand_pool_entropy_needed(pool);
    if entropy_factor < 1 then begin
        ERR_raise(ERR_LIB_RAND, RAND_R_ARGUMENT_OUT_OF_RANGE);
        Exit(0);
    end;
    bytes_needed := ENTROPY_TO_BYTES(entropy_needed, entropy_factor);
    if bytes_needed > pool.max_len - pool.len then
    begin
        { not enough space left }
        ERR_raise(ERR_LIB_RAND, RAND_R_RANDOM_POOL_OVERFLOW);
        Exit(0);
    end;
    if (pool.len < pool.min_len)  and
       ( bytes_needed < pool.min_len - pool.len) then { to meet the min_len requirement }
        bytes_needed := pool.min_len - pool.len;
    {
     * Make sure the buffer is large enough for the requested amount
     * of data. This guarantees that existing code patterns where
     * ossl_rand_pool_add_begin, ossl_rand_pool_add_end or ossl_rand_pool_add
     * are used to collect entropy data without any error handling
     * whatsoever, continue to be valid.
     * Furthermore if the allocation here fails once, make sure that
     * we don't fall back to a less secure or even blocking random source,
     * as that could happen by the existing code patterns.
     * This is not a concern for additional data, therefore that
     * is not needed if rand_pool_grow fails in other places.
     }
    if  0>= rand_pool_grow(pool, bytes_needed) then
    begin
        { persistent error for this pool }
        pool.max_len := 0;pool.len := 0;
        Exit(0);
    end;
    Result := bytes_needed;
end;

function ossl_rand_pool_new( entropy_requested, secure : integer; min_len, max_len : size_t):PRAND_POOL;
var
    pool           : PRAND_POOL;
    min_alloc_size : size_t;
    label _err;
begin
    pool := OPENSSL_zalloc(sizeof( pool^));
    min_alloc_size := RAND_POOL_MIN_ALLOCATION(secure);
    if pool = nil then
    begin
        ERR_raise(ERR_LIB_RAND, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    pool.min_len := min_len;
    pool.max_len := get_result(max_len > RAND_POOL_MAX_LENGTH,
                             RAND_POOL_MAX_LENGTH , max_len);
    pool.alloc_len := get_result( min_len < min_alloc_size , min_alloc_size , min_len);
    if pool.alloc_len > pool.max_len then
       pool.alloc_len := pool.max_len;
    if secure>0 then
       pool.buffer := OPENSSL_secure_zalloc(pool.alloc_len)
    else
        pool.buffer := OPENSSL_zalloc(pool.alloc_len);
    if pool.buffer = nil then
    begin
        ERR_raise(ERR_LIB_RAND, ERR_R_MALLOC_FAILURE);
        goto _err ;
    end;
    pool.entropy_requested := entropy_requested;
    pool.secure := secure;
    Exit(pool);
_err:
    OPENSSL_free(pool);
    Result := nil;
end;


end.
