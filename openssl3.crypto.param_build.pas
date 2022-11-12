unit openssl3.crypto.param_build;

interface
uses OpenSSL.Api;
type
  sk_OSSL_PARAM_BLD_DEF_compfunc = function (const  a, b: POSSL_PARAM_BLD_DEF):integer;
  sk_OSSL_PARAM_BLD_DEF_freefunc = procedure(a: POSSL_PARAM_BLD_DEF);
  sk_OSSL_PARAM_BLD_DEF_copyfunc = function(const a: POSSL_PARAM_BLD_DEF): POSSL_PARAM_BLD_DEF;

 function sk_OSSL_PARAM_BLD_DEF_num( sk : Pointer):integer;
  function sk_OSSL_PARAM_BLD_DEF_value( sk : Pointer;idx: integer):POSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_new( cmp : sk_OSSL_PARAM_BLD_DEF_compfunc):PSTACK_st_OSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_new_null:PSTACK_st_OSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_new_reserve( cmp : sk_OSSL_PARAM_BLD_DEF_compfunc; n : integer):PSTACK_st_OSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_reserve( sk : Pointer; n : integer):integer;
  procedure sk_OSSL_PARAM_BLD_DEF_free( sk : Pointer);
  procedure sk_OSSL_PARAM_BLD_DEF_zero( sk : Pointer);
  function sk_OSSL_PARAM_BLD_DEF_delete( sk : Pointer; i : integer):POSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_delete_ptr( sk, ptr : Pointer):POSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_push( sk, ptr : Pointer):integer;
  function sk_OSSL_PARAM_BLD_DEF_unshift( sk, ptr : Pointer):integer;
  function sk_OSSL_PARAM_BLD_DEF_pop( sk : Pointer):POSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_shift( sk : Pointer):POSSL_PARAM_BLD_DEF;
  procedure sk_OSSL_PARAM_BLD_DEF_pop_free( sk : Pointer; freefunc : sk_OSSL_PARAM_BLD_DEF_freefunc);
  function sk_OSSL_PARAM_BLD_DEF_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_OSSL_PARAM_BLD_DEF_set( sk : Pointer; idx : integer; ptr : Pointer):POSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_find( sk, ptr : Pointer):integer;
  function sk_OSSL_PARAM_BLD_DEF_find_ex( sk, ptr : Pointer):integer;
  function sk_OSSL_PARAM_BLD_DEF_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_OSSL_PARAM_BLD_DEF_sort( sk : Pointer);
  function sk_OSSL_PARAM_BLD_DEF_is_sorted( sk : Pointer):integer;
  function sk_OSSL_PARAM_BLD_DEF_dup( sk : Pointer):PSTACK_st_OSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_deep_copy( sk : Pointer; copyfunc : sk_OSSL_PARAM_BLD_DEF_copyfunc; freefunc : sk_OSSL_PARAM_BLD_DEF_freefunc):PSTACK_st_OSSL_PARAM_BLD_DEF;
  function sk_OSSL_PARAM_BLD_DEF_set_cmp_func( sk : Pointer; cmp : sk_OSSL_PARAM_BLD_DEF_compfunc):sk_OSSL_PARAM_BLD_DEF_compfunc;
  function push_BN(bld : POSSL_PARAM_BLD;const key : PUTF8Char; bn : PBIGNUM; sz : size_t; &type : integer):integer;

function OSSL_PARAM_BLD_push_BN(bld : POSSL_PARAM_BLD;const key : PUTF8Char; bn : PBIGNUM):integer;
function param_push(bld : POSSL_PARAM_BLD;const key : PUTF8Char; size : integer; alloc : size_t; &type, secure : integer):POSSL_PARAM_BLD_DEF;
function OSSL_PARAM_BLD_push_int(bld : POSSL_PARAM_BLD;const key : PUTF8Char; num : integer):integer;
function param_push_num(bld : POSSL_PARAM_BLD;const key : PUTF8Char; num : Pointer; size : size_t; &type : integer):integer;
function OSSL_PARAM_BLD_push_octet_string(bld : POSSL_PARAM_BLD;const key : PUTF8Char; buf : Pointer; bsize : size_t):integer;
function OSSL_PARAM_BLD_push_utf8_string(bld : POSSL_PARAM_BLD;const key, buf : PUTF8Char; bsize : size_t):integer;
function OSSL_PARAM_BLD_push_long(bld : POSSL_PARAM_BLD;const key : PUTF8Char; num : LongInt):integer;
function OSSL_PARAM_BLD_to_param( bld : POSSL_PARAM_BLD):POSSL_PARAM;
function OSSL_PARAM_BLD_new:POSSL_PARAM_BLD;
function param_bld_convert( bld : POSSL_PARAM_BLD; param : POSSL_PARAM; blk, secure : POSSL_PARAM_ALIGNED_BLOCK):POSSL_PARAM;
procedure free_all_params( bld : POSSL_PARAM_BLD);
procedure OSSL_PARAM_BLD_free( bld : POSSL_PARAM_BLD);
 function OSSL_PARAM_BLD_push_BN_pad(bld : POSSL_PARAM_BLD;const key : PUTF8Char; bn : PBIGNUM; sz : size_t):integer;


implementation
uses openssl3.crypto.mem, openssl3.crypto.stack, OpenSSL3.common,
     OpenSSL3.Err, openssl3.crypto.bn.bn_lib, openssl3.crypto.params_dup,
     openssl3.crypto.mem_sec, openssl3.crypto.params;




function OSSL_PARAM_BLD_push_BN_pad(bld : POSSL_PARAM_BLD;const key : PUTF8Char; bn : PBIGNUM; sz : size_t):integer;
begin
    if BN_is_negative(bn )>0 then
        Exit(push_BN(bld, key, bn, get_result(bn = nil , 0 , BN_num_bytes(bn)),
                       OSSL_PARAM_INTEGER));
    Result := push_BN(bld, key, bn, sz, OSSL_PARAM_UNSIGNED_INTEGER);
end;

procedure OSSL_PARAM_BLD_free( bld : POSSL_PARAM_BLD);
begin
    if bld = nil then exit;
    free_all_params(bld);
    sk_OSSL_PARAM_BLD_DEF_free(bld.params);
    OPENSSL_free(Pointer(bld));
end;

procedure free_all_params( bld : POSSL_PARAM_BLD);
var
  i, n : integer;
  p: Pointer;
begin
    n := sk_OSSL_PARAM_BLD_DEF_num(bld.params);
    for i := 0 to n-1 do
    begin
        p := sk_OSSL_PARAM_BLD_DEF_pop(bld.params);
        OPENSSL_free(P);
    end;
end;




function param_bld_convert( bld : POSSL_PARAM_BLD; param : POSSL_PARAM; blk, secure : POSSL_PARAM_ALIGNED_BLOCK):POSSL_PARAM;
var
  i, num : integer;

  pd : POSSL_PARAM_BLD_DEF;

  p : Pointer;
begin
{$POINTERMATH ON}
    num := sk_OSSL_PARAM_BLD_DEF_num(bld.params);
    for i := 0 to num-1 do
    begin
        pd := sk_OSSL_PARAM_BLD_DEF_value(bld.params, i);
        param[i].key := pd.key;
        param[i].data_type := pd.&type;
        param[i].data_size := pd.size;
        param[i].return_size := OSSL_PARAM_UNMODIFIED;
        if pd.secure>0 then
        begin
            p := secure;
            secure  := secure + pd.alloc_blocks;
        end
        else
        begin
            p := blk;
            blk  := blk + pd.alloc_blocks;
        end;
        param[i].data := p;
        if pd.bn <> nil then
        begin
            { PBIGNUM }
            if pd.&type = OSSL_PARAM_UNSIGNED_INTEGER then
                BN_bn2nativepad(pd.bn, PByte(p), pd.size)
            else
                BN_signed_bn2native(pd.bn, PByte(p), pd.size);
        end
        else
        if (pd.&type = OSSL_PARAM_OCTET_PTR )
                    or  (pd.&type = OSSL_PARAM_UTF8_PTR) then
        begin
            { PTR }
            PPointer( p)^ := pd.&string;
        end
        else
        if (pd.&type = OSSL_PARAM_OCTET_STRING)
                    or  (pd.&type = OSSL_PARAM_UTF8_STRING) then
        begin
            if pd.&string <> nil then
               memcpy(p, pd.&string, pd.size)
            else
                memset(p, 0, pd.size);
            if pd.&type = OSSL_PARAM_UTF8_STRING then
               PUTF8Char(p)[pd.size] := #0;
        end
        else
        begin
            { Number, but could also be a nil PBIGNUM }
            if pd.size > sizeof(pd.num)  then
                memset(p, 0, pd.size)
            else if (pd.size > 0) then
                memcpy(p, @pd.num, pd.size);
        end;
    end;
    param[i] := OSSL_PARAM_construct_end();
    Result := param + i;
 {$POINTERMATH OFF}
end;

function OSSL_PARAM_BLD_to_param( bld : POSSL_PARAM_BLD):POSSL_PARAM;
var
  blk, s : POSSL_PARAM_ALIGNED_BLOCK;
  params, last : POSSL_PARAM;
  num : integer;
  p_blks, total, ss : size_t;
begin
    s := nil;
     num := sk_OSSL_PARAM_BLD_DEF_num(bld.params);
     p_blks := ossl_param_bytes_to_blocks((1 + num) * sizeof( params^));
     total := OSSL_PARAM_ALIGN_SIZE * (p_blks + bld.total_blocks);
     ss := OSSL_PARAM_ALIGN_SIZE * bld.secure_blocks;
    if ss > 0 then
    begin
        s := OPENSSL_secure_malloc(ss);
        if s = nil then
        begin
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_SECURE_MALLOC_FAILURE);
            Exit(nil);
        end;
    end;
    params := OPENSSL_malloc(total);
    if params = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        OPENSSL_secure_free(s);
        Exit(nil);
    end;
    //blk = p_blks + (OSSL_PARAM_ALIGNED_BLOCK *)(params);
    blk := POSSL_PARAM_ALIGNED_BLOCK(params);
    Inc(blk, p_blks);
    last := param_bld_convert(bld, params, blk, s);
    ossl_param_set_secure_block(last, s, ss);
    { Reset builder for reuse }
    bld.total_blocks := 0;
    bld.secure_blocks := 0;
    free_all_params(bld);
    Result := params;
end;

function OSSL_PARAM_BLD_push_long(bld : POSSL_PARAM_BLD;const key : PUTF8Char; num : LongInt):integer;
begin
    Result := param_push_num(bld, key, @num, sizeof(num), OSSL_PARAM_INTEGER);
end;




function OSSL_PARAM_BLD_push_utf8_string(bld : POSSL_PARAM_BLD;const key, buf : PUTF8Char; bsize : size_t):integer;
var
  pd : POSSL_PARAM_BLD_DEF;

  secure : integer;
begin
    if bsize = 0 then
    begin
        bsize := Length(buf);
    end
    else
    if (bsize > INT_MAX) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_STRING_TOO_LONG);
        Exit(0);
    end;
    secure := CRYPTO_secure_allocated(buf);
    pd := param_push(bld, key, bsize, bsize + 1, OSSL_PARAM_UTF8_STRING, secure);
    if pd = nil then Exit(0);
    pd.&string := buf;
    Result := 1;
end;





function OSSL_PARAM_BLD_push_octet_string(bld : POSSL_PARAM_BLD;const key : PUTF8Char; buf : Pointer; bsize : size_t):integer;
var
  pd : POSSL_PARAM_BLD_DEF;

  secure : integer;
begin
    if bsize > INT_MAX then
    begin
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_STRING_TOO_LONG);
        Exit(0);
    end;
    secure := CRYPTO_secure_allocated(buf);
    pd := param_push(bld, key, bsize, bsize, OSSL_PARAM_OCTET_STRING, secure);
    if pd = nil then Exit(0);
    pd.&string := buf;
    Result := 1;
end;



function param_push_num(bld : POSSL_PARAM_BLD;const key : PUTF8Char; num : Pointer; size : size_t; &type : integer):integer;
var
  pd : POSSL_PARAM_BLD_DEF;
begin
   pd := param_push(bld, key, size, size, &type, 0);
    if pd = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if size > sizeof(pd.num  )then
    begin
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_MANY_BYTES);
        Exit(0);
    end;
    memcpy(@pd.num, num, size);
    Result := 1;
end;




function OSSL_PARAM_BLD_push_int(bld : POSSL_PARAM_BLD;const key : PUTF8Char; num : integer):integer;
begin
    Result := param_push_num(bld, key, @num, sizeof(num), OSSL_PARAM_INTEGER);
end;



function param_push(bld : POSSL_PARAM_BLD;const key : PUTF8Char; size : integer; alloc : size_t; &type, secure : integer):POSSL_PARAM_BLD_DEF;
var
  pd : POSSL_PARAM_BLD_DEF;
begin
    pd := OPENSSL_zalloc(sizeof( pd^));
    if pd = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    pd.key := key;
    pd.&type := &type;
    pd.size := size;
    pd.alloc_blocks := ossl_param_bytes_to_blocks(alloc);
    pd.secure := secure ;
    if pd.secure <> 0 then
        bld.secure_blocks  := bld.secure_blocks + pd.alloc_blocks
    else
        bld.total_blocks  := bld.total_blocks + pd.alloc_blocks;
    if sk_OSSL_PARAM_BLD_DEF_push(bld.params, pd) <= 0 then
    begin
        OPENSSL_free(Pointer(pd));
        pd := nil;
    end;
    Result := pd;
end;

function push_BN(bld : POSSL_PARAM_BLD;const key : PUTF8Char; bn : PBIGNUM; sz : size_t; &type : integer):integer;
var
  n, secure : integer;
  pd: POSSL_PARAM_BLD_DEF;
begin
    secure := 0;
    if  not ossl_assert( (&type = OSSL_PARAM_UNSIGNED_INTEGER)
                      or (&type = OSSL_PARAM_INTEGER )) then
        Exit(0);
    if bn <> nil then
    begin
        if (&type = OSSL_PARAM_UNSIGNED_INTEGER)  and  (BN_is_negative(bn)>0) then
        begin
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_UNSUPPORTED,
                           'Negative big numbers are unsupported for OSSL_PARAM_UNSIGNED_INTEGER');
            Exit(0);
        end;
        n := BN_num_bytes(bn);
        if n < 0 then
        begin
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_ZERO_LENGTH_NUMBER);
            Exit(0);
        end;
        if sz < size_t(n) then
        begin
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER);
            Exit(0);
        end;
        if BN_get_flags(bn, BN_FLG_SECURE) = BN_FLG_SECURE then
            secure := 1;
    end;
    pd := param_push(bld, key, sz, sz, &type, secure);
    if pd = nil then Exit(0);
    pd.bn := bn;
    Result := 1;
end;

function OSSL_PARAM_BLD_push_BN(bld : POSSL_PARAM_BLD;const key : PUTF8Char; bn : PBIGNUM):integer;
begin
    if BN_is_negative(bn)>0  then
        Exit(push_BN(bld, key, bn, get_result(bn = nil , 0 , BN_num_bytes(bn) + 1),
                       OSSL_PARAM_INTEGER));
    Exit(push_BN(bld, key, bn, get_result(bn = nil , 0 , BN_num_bytes(bn) ),
                   OSSL_PARAM_UNSIGNED_INTEGER) );
end;


function sk_OSSL_PARAM_BLD_DEF_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_OSSL_PARAM_BLD_DEF_value( sk : Pointer; idx: integer):POSSL_PARAM_BLD_DEF;
begin
   Result := POSSL_PARAM_BLD_DEF(OPENSSL_sk_value(POPENSSL_STACK(sk), (idx)))
end;


function sk_OSSL_PARAM_BLD_DEF_new( cmp : sk_OSSL_PARAM_BLD_DEF_compfunc):PSTACK_st_OSSL_PARAM_BLD_DEF;
begin
   Result := PSTACK_st_OSSL_PARAM_BLD_DEF (OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp)))
end;


function sk_OSSL_PARAM_BLD_DEF_new_null:PSTACK_st_OSSL_PARAM_BLD_DEF;
begin
   Result := PSTACK_st_OSSL_PARAM_BLD_DEF (OPENSSL_sk_new_null())
end;


function sk_OSSL_PARAM_BLD_DEF_new_reserve( cmp : sk_OSSL_PARAM_BLD_DEF_compfunc; n : integer):PSTACK_st_OSSL_PARAM_BLD_DEF;
begin
   Result := PSTACK_st_OSSL_PARAM_BLD_DEF (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_OSSL_PARAM_BLD_DEF_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_OSSL_PARAM_BLD_DEF_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_OSSL_PARAM_BLD_DEF_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_OSSL_PARAM_BLD_DEF_delete( sk : Pointer; i : integer):POSSL_PARAM_BLD_DEF;
begin
   Result := POSSL_PARAM_BLD_DEF(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_OSSL_PARAM_BLD_DEF_delete_ptr( sk, ptr : Pointer):POSSL_PARAM_BLD_DEF;
begin
   Result := POSSL_PARAM_BLD_DEF(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_OSSL_PARAM_BLD_DEF_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PARAM_BLD_DEF_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PARAM_BLD_DEF_pop( sk : Pointer):POSSL_PARAM_BLD_DEF;
begin
   Result := POSSL_PARAM_BLD_DEF(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_OSSL_PARAM_BLD_DEF_shift( sk : Pointer):POSSL_PARAM_BLD_DEF;
begin
   Result := POSSL_PARAM_BLD_DEF(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_OSSL_PARAM_BLD_DEF_pop_free( sk : Pointer; freefunc : sk_OSSL_PARAM_BLD_DEF_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk),OPENSSL_sk_freefunc(freefunc))
end;


function sk_OSSL_PARAM_BLD_DEF_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_OSSL_PARAM_BLD_DEF_set( sk : Pointer; idx : integer; ptr : Pointer):POSSL_PARAM_BLD_DEF;
begin
   Result := POSSL_PARAM_BLD_DEF(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_OSSL_PARAM_BLD_DEF_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PARAM_BLD_DEF_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_OSSL_PARAM_BLD_DEF_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_OSSL_PARAM_BLD_DEF_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_OSSL_PARAM_BLD_DEF_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_OSSL_PARAM_BLD_DEF_dup( sk : Pointer):PSTACK_st_OSSL_PARAM_BLD_DEF;
begin
   Result := PSTACK_st_OSSL_PARAM_BLD_DEF (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_OSSL_PARAM_BLD_DEF_deep_copy( sk : Pointer; copyfunc : sk_OSSL_PARAM_BLD_DEF_copyfunc; freefunc : sk_OSSL_PARAM_BLD_DEF_freefunc):PSTACK_st_OSSL_PARAM_BLD_DEF;
begin
   Result := PSTACK_st_OSSL_PARAM_BLD_DEF (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_OSSL_PARAM_BLD_DEF_set_cmp_func( sk : Pointer; cmp : sk_OSSL_PARAM_BLD_DEF_compfunc):sk_OSSL_PARAM_BLD_DEF_compfunc;
begin
   Result := sk_OSSL_PARAM_BLD_DEF_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;

function OSSL_PARAM_BLD_new:POSSL_PARAM_BLD;
var
  r : POSSL_PARAM_BLD;
begin
    r := OPENSSL_zalloc(sizeof(TOSSL_PARAM_BLD));
    if r <> nil then
    begin
        r.params := sk_OSSL_PARAM_BLD_DEF_new_null();
        if r.params = nil then
        begin
            OPENSSL_free(Pointer(r));
            r := nil;
        end;
    end;
    Result := r;
end;


end.
