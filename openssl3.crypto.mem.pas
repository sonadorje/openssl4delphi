{$I config.inc}
unit openssl3.crypto.mem;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface

uses OpenSSL.Api, SysUtils, {$IFDEF MSWINDOWS} windows, {$ENDIF} TypInfo;

type
  TCRYPTO_free_fn = procedure(addr: Pointer);
  PCRYPTO_free_fn = ^TCRYPTO_free_fn;
  TCRYPTO_malloc_fn = function (num: size_t): Pointer;
  PCRYPTO_malloc_fn = ^TCRYPTO_malloc_fn;

  Tmemset_t = function(dst : Pointer; c : integer; n : size_t): Pointer;
  TCRYPTO_realloc_fn = function(addr : Pointer; num : size_t):Pointer;
  PCRYPTO_realloc_fn = ^TCRYPTO_realloc_fn;

function CRYPTO_malloc(num: size_t): Pointer;
function CRYPTO_zalloc( num :size_t):Pointer;
procedure CRYPTO_free(str : Pointer);
function OPENSSL_malloc(num: size_t): Pointer;
function OPENSSL_zalloc(num: size_t): Pointer ;
procedure OPENSSL_cleanse(ptr: Pointer; len : size_t);
procedure OPENSSL_free(addr: Pointer);
procedure OPENSSL_clear_free(addr: Pointer; num: size_t);
procedure CRYPTO_clear_free(str : Pointer; num : size_t);

function OPENSSL_realloc(addr: Pointer; num: size_t): Pointer;
function CRYPTO_realloc(addr : Pointer; num : size_t):Pointer;

function CRYPTO_clear_realloc(str : Pointer; old_len, new_num : size_t):Pointer;
function OPENSSL_clear_realloc(addr: Pointer; old_num, new_num: size_t): Pointer ;
procedure CRYPTO_get_mem_functions( malloc_fn : PCRYPTO_malloc_fn; realloc_fn : PCRYPTO_realloc_fn; free_fn : PCRYPTO_free_fn);

var
   malloc_count: int;
   free_count: int;
   realloc_count: int = 0;
   //memset_func: Tmemset_t  = memset;
   malloc_impl: TCRYPTO_malloc_fn = CRYPTO_malloc;
   realloc_impl: TCRYPTO_realloc_fn  = CRYPTO_realloc;
   allow_customize:  int  = 1;
   free_impl: TCRYPTO_free_fn  = CRYPTO_free;


(*SysGetMem allocates Size bytes of memory using Delphi’s built-in memory manager. It returns a pointer to the newly allocated memory or nil for an error. The memory is not initialized.

SysGetMem is a real function.

Tips and Tricks
If you write your own memory manager, you can call SysGetMem to perform the memory allocation.

If you are not implementing a new memory manager, use New or GetMem, not SysGetMem, to allocate memory.

  OldMemMgr       : TMemoryManagerEx;
  MyMemMgr        : TMemoryManagerEx;
  GetMemCalls     : Integer;
  FreeMemCalls    : Integer;
  ReallocMemCalls : Integer;
  AllocMemCalls   : Integer;
  *)

implementation

(***************************CRYPTO functions***********************************)
function CRYPTO_zalloc( num :size_t):Pointer;
begin
    Result := CRYPTO_malloc(num);
end;

procedure CRYPTO_free(str : Pointer);
begin
    //INCREMENT(free_count);
    if str = nil then
       Exit;

    if @free_impl <> @CRYPTO_free then
    begin
        free_impl(str);
        exit;
    end;
    //str := nil;
    FreeMem(str);
end;

function CRYPTO_malloc(num: size_t): Pointer;
begin
    //INCREMENT(malloc_count);
    if @malloc_impl <> @CRYPTO_malloc then
       Exit(malloc_impl(num));


    if num = 0 then
       Exit(nil);
    //FAILTEST();
    if allow_customize > 0 then
    begin
        {
         * Disallow customization after the first allocation. We only set this
         * if necessary to avoid a store to the same cache line on every
         * allocation.
         }
        allow_customize := 0;
    end;
    Result := AllocMem(num);

    //SysUtils.AssertErrorHandler(Message, Filename, LineNumber, ErrorAddr);
end;

procedure CRYPTO_get_mem_functions( malloc_fn : PCRYPTO_malloc_fn; realloc_fn : PCRYPTO_realloc_fn; free_fn : PCRYPTO_free_fn);
begin
    if malloc_fn <> nil then
       malloc_fn^ := malloc_impl;
    if realloc_fn <> nil then
       realloc_fn^ := realloc_impl;
    if free_fn <> nil then
       free_fn^ := free_impl;
end;

function CRYPTO_clear_realloc(str : Pointer; old_len, new_num : size_t):Pointer;
var
  p: Pointer;
begin
{$POINTERMATH ON}
    result := nil;
    if str = nil then
       Exit(CRYPTO_malloc(new_num));
    if new_num = 0 then
    begin
        CRYPTO_clear_free(str, old_len);
        Exit(nil);
    end;
    { Can't shrink the buffer since memcpy below copies |old_len| bytes. }
    if new_num < old_len then
    begin
        p := PByte(str) + new_num;
        OPENSSL_cleanse(p, old_len - new_num);
        Exit(p);
    end;
    result  := CRYPTO_malloc(new_num);
    if result  <> nil then
    begin
        Move( str^, result^ , old_len);
        CRYPTO_clear_free(str, old_len);
    end;
{$POINTERMATH ON}
end;

function CRYPTO_realloc(addr : Pointer; num : size_t):Pointer;
begin
    //INCREMENT(realloc_count);
    if @realloc_impl <> @CRYPTO_realloc then
       Exit(realloc_impl(addr, num));

    if addr = nil then
    begin
       Exit(CRYPTO_malloc(num));
    end;
    if num = 0 then
    begin
        CRYPTO_free(addr);
        Exit(nil);
    end;
    Result := ReallocMemory(addr, num);

end;

procedure CRYPTO_clear_free(str : Pointer; num : size_t);
begin
    if str = nil then exit;
    if num >0 then
    begin
       //OPENSSL_cleanse(str, num);
       str := memset(str, 0, num);
    end;
    CRYPTO_free(str);
end;

(*************************OPENSSL functions************************************)
function OPENSSL_clear_realloc(addr: Pointer; old_num, new_num: size_t): Pointer ;
begin
   Result := CRYPTO_clear_realloc(addr, old_num, new_num);
end;


function OPENSSL_realloc(addr: Pointer; num: size_t): Pointer;
begin
   Result :=  CRYPTO_realloc(addr, num);
end;

procedure OPENSSL_clear_free(addr: Pointer; num: size_t);
begin
   if addr = nil then exit;
    if num >0 then
       OPENSSL_cleanse(addr, num);
    CRYPTO_free(addr);
end;

// 清理ptr执向的一维数组
procedure OPENSSL_cleanse(ptr: Pointer; len : size_t);
begin
    memset(ptr, 0, len);
    //FillChar(ptr, len, 0);
end;


function OPENSSL_malloc(num: size_t): Pointer;
begin
   Result := CRYPTO_malloc(num);
end;

procedure OPENSSL_free(addr: Pointer);
begin
   CRYPTO_free(addr);
end;

function OPENSSL_zalloc(num: size_t): Pointer;
begin
   Result := CRYPTO_zalloc(num);
end;

initialization
   //UseMyMemMgr();

finalization
    { Set the old memory manager back. }
  {if IsMemoryManagerSet then
     SetMemoryManager(OldMemMgr);}

end.
