unit openssl3.crypto.mem_sec;

interface
uses OpenSSL.Api;

const
  ONE = size_t(1);

type
  sh_st = record
    map_result: PUTF8Char;
    map_size: size_t;
    arena: PUTF8Char;
    arena_size: size_t;
    freelist: PPUTF8Char;
    freelist_size: Int64;
    minsize: size_t;
    bittable: PByte;
    bitmalloc: PByte;
    bittable_size: size_t;
  end;
  TSH = sh_st;

  Psh_list_st = ^sh_list_st;
  PPsh_list_st = ^Psh_list_st;
  PSH_LIST = ^TSH_LIST;
  PPSH_LIST = ^PSH_LIST;
  sh_list_st = record
    next: PSH_LIST;
    p_next: PPSH_LIST;
  end;
  TSH_LIST = sh_list_st;


function CRYPTO_secure_zalloc( num : size_t):Pointer;
function CRYPTO_secure_malloc( num : size_t):Pointer;
function sh_malloc( size : size_t):Pointer;
function sh_testbit( ptr : PUTF8Char; list : integer; table : PByte):integer;
function  TESTBIT( t : PByte; b : size_t): integer;
procedure sh_clearbit( ptr : PUTF8Char; list : integer; table : PByte);
procedure CLEARBIT( t : PByte; b : size_t);
procedure sh_remove_from_list( ptr : PUTF8Char);
function WITHIN_ARENA( p : PPointer):Boolean;
function WITHIN_FREELIST( p : PPointer):Boolean;
procedure sh_setbit( ptr : PUTF8Char; list : integer; table : PByte);
procedure sh_add_to_list( list : PPUTF8Char; ptr : PUTF8Char);
function sh_find_my_buddy( ptr : PUTF8Char; list : integer):PUTF8Char;
function sh_actual_size( ptr : PUTF8Char):size_t;
function sh_getlist( ptr : PUTF8Char):size_t;
function OPENSSL_secure_zalloc(num: size_t):Pointer;
procedure CRYPTO_secure_clear_free( ptr : Pointer; num : size_t);
function CRYPTO_secure_allocated(const ptr : Pointer):integer;
function sh_allocated(const ptr : PUTF8Char):integer;
procedure sh_free( ptr : Pointer);
procedure OPENSSL_secure_clear_free(addr: Pointer; num : size_t) ;
function OPENSSL_secure_malloc(num: size_t): Pointer;
procedure OPENSSL_secure_free(addr: Pointer);
procedure CRYPTO_secure_free(ptr : Pointer);
procedure  CLEAR(p : Pointer; s : size_t);
function CRYPTO_secure_malloc_done:integer;
procedure sh_done;

var
  secure_mem_initialized: int;
  secure_mem_used: size_t;
  sec_malloc_lock : PCRYPTO_RWLOCK = nil;
  sh: TSH;

implementation

uses openssl3.crypto.mem,
     {$IFDEF MSWINDOWS}
        windows,
     {$ENDIF}
     OpenSSL3.threads_none;

procedure sh_done;
begin
    OPENSSL_free(Pointer(sh.freelist));
    OPENSSL_free(Pointer(sh.bittable));
    OPENSSL_free(Pointer(sh.bitmalloc));
{$IF not defined(MSWINDOWS)}
    if sh.map_result <> MAP_FAILED  and  sh.map_size then munmap(sh.map_result, sh.map_size);
{$ELSE}
    if (sh.map_result <> nil)  and  (sh.map_size > 0) then
        VirtualFree(sh.map_result, 0, MEM_RELEASE);
{$ENDIF}
    memset(@sh, 0, sizeof(sh));
end;



function CRYPTO_secure_malloc_done:integer;
begin
{$IFNDEF OPENSSL_NO_SECURE_MEMORY}
    if secure_mem_used = 0 then begin
        sh_done();
        secure_mem_initialized := 0;
        CRYPTO_THREAD_lock_free(sec_malloc_lock);
        sec_malloc_lock := nil;
        Exit(1);
    end;
{$endif} { OPENSSL_NO_SECURE_MEMORY }
    Result := 0;
end;

procedure  CLEAR(p: Pointer; s: size_t);
begin
   OPENSSL_cleanse(p, s)
end;


procedure CRYPTO_secure_free(ptr : Pointer);
var
  actual_size : size_t;
begin
{$IFNDEF OPENSSL_NO_SECURE_MEMORY}
    if ptr = nil then exit;
    if  0>= CRYPTO_secure_allocated(ptr) then
    begin
        CRYPTO_free(ptr);
        exit;
    end;
    if  0>= CRYPTO_THREAD_write_lock(sec_malloc_lock) then
        exit;
    actual_size := sh_actual_size(ptr);
    CLEAR(ptr, actual_size);
    secure_mem_used  := secure_mem_used - actual_size;
    sh_free(ptr);
    CRYPTO_THREAD_unlock(sec_malloc_lock);
{$ELSE}
    CRYPTO_free(ptr, file, line);
{$endif} { OPENSSL_NO_SECURE_MEMORY }
end;

procedure OPENSSL_secure_free(addr: Pointer);
begin
   CRYPTO_secure_free(addr)
end;

function OPENSSL_secure_malloc(num: size_t): Pointer;
begin
   Result := CRYPTO_secure_malloc(num)
end;


 procedure OPENSSL_secure_clear_free(addr: Pointer; num : size_t) ;
begin
   CRYPTO_secure_clear_free(addr, num);
end;

procedure sh_free( ptr : Pointer);
var
  list : size_t;
  buddy : Pointer;
begin
{$POINTERMATH ON}
    if ptr = nil then exit;
    assert(WITHIN_ARENA(ptr));
    if  not WITHIN_ARENA(ptr  ) then
        exit;
    list := sh_getlist(ptr);
    assert(sh_testbit(ptr, list, sh.bittable)>0);
    sh_clearbit(ptr, list, sh.bitmalloc);
    sh_add_to_list(@sh.freelist[list], ptr);
    { Try to coalesce two adjacent free areas. }
    buddy := sh_find_my_buddy(ptr, list);
    while buddy <> nil do
    begin
        assert(ptr = sh_find_my_buddy(buddy, list));
        assert(ptr <> nil);
        assert( 0>= sh_testbit(ptr, list, sh.bitmalloc));
        sh_clearbit(ptr, list, sh.bittable);
        sh_remove_from_list(ptr);
        assert( 0>= sh_testbit(ptr, list, sh.bitmalloc));
        sh_clearbit(buddy, list, sh.bittable);
        sh_remove_from_list(buddy);
        Dec(list);
        { Zero the higher addressed block's free list pointers }
        if PByte(ptr) > PByte(buddy) then
           memset(ptr , 0, sizeof(TSH_LIST))
        else
           memset(buddy, 0, sizeof(TSH_LIST));
        if PByte(ptr) > PByte(buddy) then
           ptr := buddy;
        assert( 0>= sh_testbit(ptr, list, sh.bitmalloc));
        sh_setbit(ptr, list, sh.bittable);
        sh_add_to_list(@sh.freelist[list], ptr);
        assert(sh.freelist[list] = ptr);
        buddy := sh_find_my_buddy(ptr, list);
    end;
{$POINTERMATH OFF}
end;


function sh_allocated(const ptr : PUTF8Char):integer;
begin
    Result := get_result(WITHIN_ARENA(@ptr) , 1 , 0);
end;

function CRYPTO_secure_allocated(const ptr : Pointer):integer;
begin
{$IFNDEF OPENSSL_NO_SECURE_MEMORY}
    if  0>= secure_mem_initialized then Exit(0);
    {
     * Only read accesses to the arena take place in sh_allocated() and this
     * is only changed by the sh_init() and sh_done() calls which are not
     * locked.  Hence, it is safe to make this check without a lock too.
     }
    Exit(sh_allocated(ptr));
{$ELSE}
   Exit(0);
{$endif} { OPENSSL_NO_SECURE_MEMORY }
end;


procedure CRYPTO_secure_clear_free( ptr : Pointer; num : size_t);
var
  actual_size : size_t;
begin
{$IFNDEF OPENSSL_NO_SECURE_MEMORY}
    if ptr = nil then exit;
    if  0>= CRYPTO_secure_allocated(ptr ) then
    begin
        OPENSSL_cleanse(ptr, num);
        CRYPTO_free(ptr);
        exit;
    end;
    if  0>= CRYPTO_THREAD_write_lock(sec_malloc_lock) then
        exit;
    actual_size := sh_actual_size(ptr);
    CLEAR(ptr, actual_size);
    secure_mem_used  := secure_mem_used - actual_size;
    sh_free(ptr);
    CRYPTO_THREAD_unlock(sec_malloc_lock);
{$ELSE}
    if ptr = nil then exit;
    OPENSSL_cleanse(ptr, num);
    CRYPTO_free(ptr, file, line);
{$endif} { OPENSSL_NO_SECURE_MEMORY }
end;

function sh_getlist( ptr : PUTF8Char):size_t;
var
  list : ossl_ssize_t;
  bit : size_t;
begin
{$POINTERMATH ON}
    list := sh.freelist_size - 1;
    bit := (sh.arena_size + ptr - sh.arena) div sh.minsize;
    while( bit>0) do
    begin
        if TESTBIT(sh.bittable, bit)>0 then
            break;
        assert((bit and 1) = 0);
        bit := bit shr  1;
        Dec(list);
    end;
    Result := list;
{$POINTERMATH OFF}
end;



function sh_actual_size( ptr : PUTF8Char):size_t;
var
  list : integer;
begin
    assert(WITHIN_ARENA(@ptr));
    if  not WITHIN_ARENA(@ptr)  then
        Exit(0);
    list := sh_getlist(ptr);
    assert(sh_testbit(ptr, list, sh.bittable)>0);
    Result := sh.arena_size div (ONE  shl  list);
end;

function sh_find_my_buddy( ptr : PUTF8Char; list : integer):PUTF8Char;
var
  bit : size_t;

  chunk : PUTF8Char;
begin
    chunk := nil;
    bit := (ONE  shl  list) + (ptr - sh.arena) DIV (sh.arena_size  shr  list);
    bit  := bit xor 1;
    if (TESTBIT(sh.bittable, bit) > 0)  and   (0>= TESTBIT(sh.bitmalloc, bit)) then
        chunk := sh.arena + ((bit and ((ONE  shl  list) - 1)) * (sh.arena_size  shr  list));
    Result := chunk;
end;




procedure sh_add_to_list( list : PPUTF8Char; ptr : PUTF8Char);
var
  temp : PSH_LIST;
begin
    assert(WITHIN_FREELIST(PPointer(list)));
    assert(WITHIN_ARENA(@ptr));
    temp := PSH_LIST (ptr);
    temp.next := PPSH_LIST (list)^;
    assert( (temp.next = nil)  or  (WITHIN_ARENA(@temp.next)));
    temp.p_next := PPSH_LIST (list);
    if temp.next <> nil then
    begin
        assert(PPUTF8char (temp.next.p_next) = list);
        temp.next.p_next := @(temp.next);
    end;
    list^ := ptr;
end;

procedure SETBIT( t : PByte; b : size_t);
var
  idx: Integer;
begin
  idx := (b)  shr  3;
  t[idx] := t[idx] or (ONE  shl  ((b) and 7))
end;





procedure sh_setbit( ptr : PUTF8Char; list : integer; table : PByte);
var
  bit : size_t;
begin
    assert( (list >= 0)  and  (list < sh.freelist_size) );
    assert(((ptr - sh.arena) and ((sh.arena_size  shr  list) - 1)) = 0);
    bit := (ONE  shl  list) + ((ptr - sh.arena) div (sh.arena_size  shr  list));
    assert( (bit > 0)  and  (bit < sh.bittable_size) );
    assert( 0>= TESTBIT(table, bit));
    SETBIT(table, bit);
end;


//#define WITHIN_ARENA(p) \
//    ((char*)(p) >= sh.arena && (char*)(p) < &sh.arena[sh.arena_size])
//#define WITHIN_FREELIST(p) \
//    ((char*)(p) >= (char*)sh.freelist && (char*)(p) < (char*)&sh.freelist[sh.freelist_size])

function WITHIN_ARENA( p : PPointer):Boolean;
begin
   Result := (PPUTF8Char(p)^ >= sh.arena ) and  (PPUTF8Char(p)^ < @sh.arena[sh.arena_size]);
end;


function WITHIN_FREELIST( p : PPointer):Boolean;
begin
{$POINTERMATH ON}
  Result := ( PPUTF8Char(p)^ >= sh.freelist^ )  and
            ( PPUTF8Char(p)^ < sh.freelist[sh.freelist_size]);
{$POINTERMATH OFF}
end;



procedure sh_remove_from_list( ptr : PUTF8Char);
var
  temp, temp2 : PSH_LIST;
begin
    temp := PSH_LIST (ptr);
    if temp.next <> nil then
       temp.next.p_next := temp.p_next;
    temp.p_next^ := temp.next;
    if temp.next = nil then
       exit;
    temp2 := PSH_LIST(temp.next);
    assert( (WITHIN_FREELIST(PPointer(temp2.p_next)))  or
            (WITHIN_ARENA(PPointer(temp2.p_next))) );
end;

procedure CLEARBIT( t : PByte; b : size_t);
var
  idx: Integer;
begin
  idx := (b)  shr  3;
   t[idx] := t[idx] and ($FF and not(ONE  shl  (b and 7)))
end;





procedure sh_clearbit( ptr : PUTF8Char; list : integer; table : PByte);
var
  bit : size_t;
begin
    assert((list >= 0)  and  (list < sh.freelist_size));
    assert(((ptr - sh.arena) and ((sh.arena_size  shr  list) - 1)) = 0);
    bit := (ONE  shl  list) + ((ptr - sh.arena) div (sh.arena_size  shr  list));
    assert((bit > 0)  and  (bit < sh.bittable_size));
    assert(TESTBIT(table, bit)>0);
    CLEARBIT(table, bit);
end;

function  TESTBIT( t : PByte; b : size_t): integer;
begin
   Result := (t[(b)  shr  3] and  (ONE  shl  ((b) and 7)));
end;


function sh_testbit( ptr : PUTF8Char; list : integer; table : PByte):integer;
var
  bit : size_t;
begin
    assert( (list >= 0)  and  (list < sh.freelist_size));
    assert(((ptr - sh.arena) and ((sh.arena_size  shr  list) - 1)) = 0);
    bit := (ONE  shl  list) + ((ptr - sh.arena) div (sh.arena_size  shr  list));
    assert( (bit > 0)  and  (bit < sh.bittable_size));
    Result := TESTBIT(table, bit);
end;


function sh_malloc( size : size_t):Pointer;
var
  list, slist : ossl_ssize_t;
  i : size_t;
  chunk : PUTF8Char;
  temp : PUTF8Char;
begin
{$POINTERMATH ON}
    if size > sh.arena_size then Exit(nil);
    list := sh.freelist_size - 1;
    i := sh.minsize;
    while ( i < size) do
    begin
        Dec(list);
        i := i shl  1;
    end;
    if list < 0 then Exit(nil);
    { try to find a larger entry to split }
    slist := list;
    while( slist >= 0) do
    begin
        if sh.freelist[slist] <> nil then
           break;
        Dec(slist);
    end;
    if slist < 0 then Exit(nil);
    { split larger entry }
    while slist <> list do
    begin
        temp := sh.freelist[slist];
        { remove from bigger list }
        assert( 0>= sh_testbit(temp, slist, sh.bitmalloc));
        sh_clearbit(temp, slist, sh.bittable);
        sh_remove_from_list(temp);
        assert(temp <> sh.freelist[slist]);
        { done with bigger list }
        Inc(slist);
        { add to smaller list }
        assert( 0>= sh_testbit(temp, slist, sh.bitmalloc));
        sh_setbit(temp, slist, sh.bittable);
        sh_add_to_list(@sh.freelist[slist], temp);
        assert(sh.freelist[slist] = temp);
        { split in 2 }
        temp  := temp + (sh.arena_size  shr  slist);
        assert( 0>= sh_testbit(temp, slist, sh.bitmalloc));
        sh_setbit(temp, slist, sh.bittable);
        sh_add_to_list(@sh.freelist[slist], temp);
        assert(sh.freelist[slist] = temp);
        assert(temp-(sh.arena_size  shr  slist) = sh_find_my_buddy(temp, slist));
    end;
    { peel off memory to hand back }
    chunk := sh.freelist[list];
    assert(sh_testbit(chunk, list, sh.bittable)>0);
    sh_setbit(chunk, list, sh.bitmalloc);
    sh_remove_from_list(chunk);
    assert(WITHIN_ARENA(@chunk));
    { zero the free list header as a precaution against information leakage }
    memset(chunk, 0, sizeof(TSH_LIST));
    Result := chunk;
{$POINTERMATH OFF}
end;

function CRYPTO_secure_malloc( num : size_t):Pointer;
var
    ret         : Pointer;
    actual_size : size_t;
begin
{$IFNDEF OPENSSL_NO_SECURE_MEMORY}
    if  0>= secure_mem_initialized then
    begin
        Exit(CRYPTO_malloc(num));
    end;
    if  0>= CRYPTO_THREAD_write_lock(sec_malloc_lock) then
        Exit(nil);
    ret := sh_malloc(num);
    actual_size := get_result( ret <> nil, sh_actual_size(ret) , 0);
    secure_mem_used  := secure_mem_used + actual_size;
    CRYPTO_THREAD_unlock(sec_malloc_lock);
    Exit(ret);
{$ELSE}
   Exit(CRYPTO_malloc(num, file, line));
{$endif} { OPENSSL_NO_SECURE_MEMORY }
end;

function CRYPTO_secure_zalloc( num : size_t):Pointer;
begin
{$IFNDEF OPENSSL_NO_SECURE_MEMORY}
    if secure_mem_initialized > 0 then { CRYPTO_secure_malloc() zeroes allocations when it is implemented }
        Exit(CRYPTO_secure_malloc(num));
{$ENDIF}
    Result := CRYPTO_zalloc(num);
end;


function OPENSSL_secure_zalloc(num: size_t):Pointer;
begin
   Result :=  CRYPTO_secure_zalloc(num);
end;

end.
