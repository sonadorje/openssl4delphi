unit openssl3.crypto.bn.bn_ctx;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

const
   BN_CTX_POOL_SIZE   =     16;
   BN_CTX_START_FRAMES  =   32;

function BN_CTX_new_ex( ctx : POSSL_LIB_CTX):PBN_CTX;
procedure BN_POOL_init( p : PBN_POOL);
procedure BN_POOL_finish( p : PBN_POOL);
procedure BN_STACK_init( st : PBN_STACK);
function ossl_bn_get_libctx( ctx : PBN_CTX):POSSL_LIB_CTX;
procedure BN_CTX_free( ctx : PBN_CTX);
procedure BN_STACK_finish(st : PBN_STACK);
procedure BN_CTX_start( ctx : PBN_CTX);
procedure _ctxdbg(channel : PBIO;const text : PUTF8Char; ctx : PBN_CTX);
procedure CTXDBG(str: PUTF8Char; ctx: PBN_CTX);
function BN_STACK_push( st : PBN_STACK; idx : uint32):integer;
function BN_CTX_get( ctx : PBN_CTX):PBIGNUM;
function BN_POOL_get( p : PBN_POOL; flag : integer):PBIGNUM;
procedure BN_CTX_end( ctx : PBN_CTX);
function BN_STACK_pop( st : PBN_STACK):uint32;
procedure BN_POOL_release( p : PBN_POOL; num : uint32);
function BN_CTX_new:PBN_CTX;
function BN_CTX_secure_new:PBN_CTX;
function BN_CTX_secure_new_ex( ctx : POSSL_LIB_CTX):PBN_CTX;

implementation
uses  openssl3.crypto.mem, OpenSSL3.Err, openssl3.crypto.bn.bn_lib,
      openssl3.crypto.bio.bio_print;

function BN_CTX_secure_new_ex( ctx : POSSL_LIB_CTX):PBN_CTX;
var
  ret : PBN_CTX;
begin
    ret := BN_CTX_new_ex(ctx);
    if ret <> nil then
       ret.flags := BN_FLG_SECURE;
    Result := ret;
end;

function BN_CTX_secure_new:PBN_CTX;
begin
    Result := BN_CTX_secure_new_ex(nil);
end;

function BN_CTX_new:PBN_CTX;
begin
    Result := BN_CTX_new_ex(nil);
end;

procedure BN_POOL_release( p : PBN_POOL; num : uint32);
var
  offset : uint32;
  a: PBIGNUM;
begin
{$POINTERMATH ON}
    offset := (p.used - 1) mod BN_CTX_POOL_SIZE;
    p.used  := p.used - num;
    while num > 0 do
    begin

        bn_check_top(PBIGNUM(@p.current.vals) + offset);
        if offset = 0 then
        begin
            offset := BN_CTX_POOL_SIZE - 1;
            p.current := p.current.prev;
        end
        else
            Dec(offset);

        Dec(num);
    end;
{$POINTERMATH OFF}
end;

function BN_STACK_pop( st : PBN_STACK):uint32;
begin
{$POINTERMATH ON}
    Dec(st.depth);
    Result := st.indexes[st.depth];
{$POINTERMATH OFF}
end;


procedure BN_CTX_end( ctx : PBN_CTX);
var
  fp : uint32;
begin
    if ctx = nil then exit;
    CTXDBG('ENTER BN_CTX_end()', ctx);
    if ctx.err_stack>0 then
       Dec(ctx.err_stack)
    else
    begin
        fp := BN_STACK_pop(@ctx.stack);
        { Does this stack frame have anything to release? }
        if fp < ctx.used then
           BN_POOL_release(@ctx.pool, ctx.used - fp);
        ctx.used := fp;
        { Unjam 'too_many" in case "get' had failed }
        ctx.too_many := 0;
    end;
    CTXDBG('LEAVE BN_CTX_end()', ctx);
end;

function BN_POOL_get( p : PBN_POOL; flag : integer):PBIGNUM;
var
  bn, pb : PBIGNUM;
  loop : size_t;
  idx: int;
  item : PBN_POOL_ITEM;
begin
    { Full; allocate a new pool item and link it in. }
    if p.used = p.size then
    begin
        item := OPENSSL_malloc(sizeof( item^));
        if item = nil then
        begin
            ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
        loop := 0; bn := @item.vals;
        while( PostInc(loop) < BN_CTX_POOL_SIZE) do
        begin
            bn_init(bn);
            if (flag and BN_FLG_SECURE ) <> 0 then
                BN_set_flags(bn, BN_FLG_SECURE);
            Inc(bn);
        end;
        item.prev := p.tail;
        item.next := nil;
        if p.head = nil then
        begin
           p.head := item;
           p.current := item;
           p.tail := item ;
        end
        else
        begin
            p.tail.next := item;
            p.tail := item;
            p.current := item;
        end;
        p.size  := p.size + BN_CTX_POOL_SIZE;
        Inc(p.used);
        { Return the first bignum from the new pool }
        Exit(@item.vals);
    end;
    if  0>= p.used then
       p.current := p.head
    else
    if (p.used mod BN_CTX_POOL_SIZE) = 0 then
        p.current := p.current.next;

    idx := (PostInc(p.used) mod BN_CTX_POOL_SIZE);
    Result := @p.current.vals[idx];
end;

function BN_CTX_get( ctx : PBN_CTX):PBIGNUM;
var
  ret : PBIGNUM;
begin
    CTXDBG('ENTER BN_CTX_get()', ctx);
    if (ctx.err_stack>0)  or  (ctx.too_many>0) then
       Exit(nil);
    ret := BN_POOL_get(@ctx.pool, ctx.flags);
    if ret = nil then
    begin
        {
         * Setting too_many prevents repeated 'get' attempts from cluttering
         * the error stack.
         }
        ctx.too_many := 1;
        ERR_raise(ERR_LIB_BN, BN_R_TOO_MANY_TEMPORARY_VARIABLES);
        Exit(nil);
    end;
    { OK, make sure the returned bignum is 'zero' }
    BN_zero(ret);
    { clear BN_FLG_CONSTTIME if leaked from previous frames }
    ret.flags := ret.flags and  (not BN_FLG_CONSTTIME);
    Inc(ctx.used);
    CTXDBG('LEAVE BN_CTX_get()', ctx);
    Result := ret;
end;

function BN_STACK_push( st : PBN_STACK; idx : uint32):integer;
var
    newsize  : size_t;
    newitems : Puint;
begin
{$POINTERMATH ON}
    if st.depth = st.size then
    begin
        { Need to expand }
        newsize := get_result(
            st.size>0 , (st.size * 3 div 2) , BN_CTX_START_FRAMES);
        newitems := OPENSSL_malloc(sizeof(newitems^)* newsize);
        if newitems = nil then
        begin
            ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        if st.depth>0 then
           memcpy(newitems, st.indexes, sizeof( newitems^) * st.depth);
        OPENSSL_free(st.indexes);
        st.indexes := newitems;
        st.size := newsize;
    end;
    st.indexes[st.depth] := idx;
    Inc(st.depth);
    Result := 1;
{$POINTERMATH OFF}
end;




procedure _ctxdbg(channel : PBIO;const text : PUTF8Char; ctx : PBN_CTX);
var
  bnidx,fpidx : size_t;
  item : PBN_POOL_ITEM;
  stack : PBN_STACK;
begin
{$POINTERMATH ON}
    bnidx := 0; fpidx := 0;
    item := ctx.pool.head;
    stack := @ctx.stack;
    BIO_printf(channel, '%s'#10, [text]);
    BIO_printf(channel, '  (%16p): ', [Pointer (ctx)]);
    while bnidx < ctx.used do
    begin
        BIO_printf(channel, '%03x ', [item.vals[PostInc(bnidx) mod BN_CTX_POOL_SIZE].dmax]);
        if  0>= (bnidx mod BN_CTX_POOL_SIZE) then
            item := item.next;
    end;
    BIO_printf(channel, #10, []);
    bnidx := 0;
    BIO_printf(channel, '   %16s : ', [PUTF8Char(', "')]);
    while fpidx < stack.depth do
    begin
        while PostInc(bnidx) < stack.indexes[fpidx] do
            BIO_printf(channel, '    ',[]);
        BIO_printf(channel, '^^^ ',[]);
        PostInc(bnidx);
        PostInc(fpidx);
    end;
    BIO_printf(channel, #10, []);
{$POINTERMATH OFF}
end;

procedure CTXDBG(str: PUTF8Char; ctx: PBN_CTX);
var
  trc_out: PBIO;
begin
    trc_out := nil;
    _ctxdbg(trc_out, str, ctx);

end;

procedure BN_CTX_start( ctx : PBN_CTX);
begin
    CTXDBG('ENTER BN_CTX_start()', ctx);
    { If we're already overflowing ... }
    if (ctx.err_stack>0)  or  (ctx.too_many>0) then
       Inc(ctx.err_stack)
    { (Try to) get a new frame pointer }
    else
    if ( 0>= BN_STACK_push(@ctx.stack, ctx.used)) then
    begin
        ERR_raise(ERR_LIB_BN, BN_R_TOO_MANY_TEMPORARY_VARIABLES);
        Inc(ctx.err_stack);
    end;
    CTXDBG('LEAVE BN_CTX_start()', ctx);
end;

procedure BN_STACK_finish(st : PBN_STACK);
begin
    OPENSSL_free(Pointer(st.indexes));
    st.indexes := nil;
end;

procedure BN_CTX_free( ctx : PBN_CTX);
var
  pool : PBN_POOL_ITEM;
  trc_out: PBIO;
  loop : uint32;
begin
    if ctx = nil then exit;
{$IFNDEF FIPS_MODULE}
    trc_out := nil;
    if Boolean(0) then
    begin
        pool := ctx.pool.head;
        BIO_printf(trc_out,
                   'BN_CTX_free(): stack-size=%d, pool-bignums=%d'#10,
                   [ctx.stack.size, ctx.pool.size]);
        BIO_printf(trc_out, '  dmaxs: ',[]);
        while Assigned(pool) do
        begin
            loop := 0;
            while loop < BN_CTX_POOL_SIZE do
            begin
                BIO_printf(trc_out, '%02x ', [pool.vals[loop].dmax]);
                Inc(loop);
            end;
            pool := pool.next;
        end;
        BIO_printf(trc_out, #10, []);
    end;
 //OSSL_TRACE_END(BN_CTX);
{$ENDIF}
    BN_STACK_finish(@ctx.stack);
    BN_POOL_finish(@ctx.pool);
    OPENSSL_free(ctx);
end;




function ossl_bn_get_libctx( ctx : PBN_CTX):POSSL_LIB_CTX;
begin
    if ctx = nil then Exit(nil);
    Result := ctx.libctx;
end;

procedure BN_STACK_init( st : PBN_STACK);
begin
    st.indexes := nil;
    st.depth := 0;
    st.size := 0;
end;

procedure BN_POOL_init( p : PBN_POOL);
begin
    p.head := nil;
    p.current := nil;
    p.tail := nil;
    p.used := 0;
    p.size := 0;
end;


procedure BN_POOL_finish( p : PBN_POOL);
var
  loop : uint;
  bn : PBIGNUM;
begin
    while Assigned(p.head) do
    begin
        loop := 0;
        bn := @p.head.vals;
        while loop < BN_CTX_POOL_SIZE do
        begin
            if Assigned(bn.d) then
               BN_clear_free(bn);
            Inc(bn);
            Inc(loop);
        end;
        p.current := p.head.next;
        OPENSSL_free(p.head);
        p.head := p.current;
    end;
end;

function BN_CTX_new_ex( ctx : POSSL_LIB_CTX):PBN_CTX;
begin
    result := OPENSSL_zalloc(sizeof( result^));
    if result = nil then
    begin
        ERR_raise(ERR_LIB_BN, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    { Initialise the structure }
    BN_POOL_init(@result.pool);
    BN_STACK_init(@result.stack);
    result.libctx := ctx;

end;


end.
