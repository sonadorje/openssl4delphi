unit openssl3.crypto.lhash;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

const
  MIN_NODES  =     16;
  UP_LOAD    =     (2*LH_LOAD_MULT); // load times 256 (default 2)
  DOWN_LOAD  =     (LH_LOAD_MULT); // load times 256 (default 1)


  function OPENSSL_LH_strhash(c : PUTF8Char):uint32;
  procedure OPENSSL_LH_flush( lh : POPENSSL_LHASH);
  function OPENSSL_LH_new( hash : TOPENSSL_LH_HASHFUNC; cmp : TOPENSSL_LH_COMPFUNC):POPENSSL_LHASH;
  procedure OPENSSL_LH_free( lh : POPENSSL_LHASH);
  function OPENSSL_LH_insert( lh : POPENSSL_LHASH;const data : Pointer):Pointer;
  function expand( lh : POPENSSL_LHASH):integer;
  function getrn(lh : POPENSSL_LHASH;const data : Pointer;var rhash : Uint32):PPOPENSSL_LH_NODE;
  procedure tsan_unlock(const lh : POPENSSL_LHASH);
  function OPENSSL_LH_delete(lh : POPENSSL_LHASH;const data : Pointer):Pointer;
  procedure contract( lh : POPENSSL_LHASH);
  function OPENSSL_LH_retrieve(lh : POPENSSL_LHASH;const data : Pointer):Pointer;
  function tsan_lock(const lh : POPENSSL_LHASH):integer;
  function OPENSSL_LH_error( lh : POPENSSL_LHASH):integer;
  function OPENSSL_LH_num_items(const lh : POPENSSL_LHASH):Cardinal;
  function OPENSSL_LH_get_down_load(const lh : POPENSSL_LHASH):Cardinal;
  procedure OPENSSL_LH_set_down_load( lh : POPENSSL_LHASH; down_load : Cardinal);
  procedure OPENSSL_LH_doall( lh : POPENSSL_LHASH; func : TOPENSSL_LH_DOALL_FUNC);
  procedure OPENSSL_LH_doall_arg( lh : POPENSSL_LHASH; func : TOPENSSL_LH_DOALL_FUNCARG; arg : Pointer);
  procedure doall_util_fn( lh : POPENSSL_LHASH; use_arg : integer; func : TOPENSSL_LH_DOALL_FUNC; func_arg : TOPENSSL_LH_DOALL_FUNCARG; arg : Pointer);
  function ossl_lh_strcasehash(c : PUTF8Char):Cardinal;

implementation
uses openssl3.crypto.mem,       openssl3.tsan_assist,
     openssl3.crypto.lh_stats,  openssl3.crypto.ctype;

function strcmp(const p1, p2 : Pointer):integer;
var
  s1, s2: PByte;
  c1, c2 : byte;
begin
  s1 := PByte(p1);
  s2 := PByte(p2);

  while (c1 = c2) do
  begin
    c1 := Byte(s1^);
    Inc(s1);
    c2 := Byte(s2^);
    Inc(s2);
    if c1 = ord(#0) then
       Exit(c1 - c2);
  end;

  Result := c1 - c2;
end;


function ossl_lh_strcasehash(c : PUTF8Char):Cardinal;
var
  ret : Cardinal;
  n : long;
  v : Cardinal;
  r : integer;
begin
    ret := 0;
    if (c = nil)  or  (c^ = #0) then Exit(ret);
    n := $100;
    while c^ <> #0 do
    begin
        v := n or Ord(ossl_tolower( c^));
        r := int ((v  shr  2)  xor  v) and $0f;
        ret := (ret  shl  r) or (ret  shr  (32 - r));
        ret := ret and uint32($FFFFFFFF);
        ret  := ret xor (v * v);
        Inc(c);
        n := n + $100;
    end;
    Result := (ret  shr  16)  xor  ret;
end;



procedure doall_util_fn( lh : POPENSSL_LHASH; use_arg : integer; func : TOPENSSL_LH_DOALL_FUNC; func_arg : TOPENSSL_LH_DOALL_FUNCARG; arg : Pointer);
var
  i : integer;
  a, n : POPENSSL_LH_NODE;
begin
{$POINTERMATH ON}
    if lh = nil then exit;
    {
     * reverse the order so we search from 'top to bottom' We were having
     * memory leaks otherwise
     }

    for i := lh.num_nodes - 1 downto 0 do
    begin
        a := lh.b[i];
        while a <> nil do
        begin
            n := a.next;
            if use_arg>0 then
               func_arg(a.data, arg)
            else
               func(a.data);
            a := n;
        end;
        //if i <= 6  then
          // Writeln('lhash-->doall_util_fn: i=' + IntToStr(i));
    end;
{$POINTERMATH OFF}
end;



procedure OPENSSL_LH_doall( lh : POPENSSL_LHASH; func : TOPENSSL_LH_DOALL_FUNC);
begin
    doall_util_fn(lh, 0, func, TOPENSSL_LH_DOALL_FUNCARG(0), nil);
end;


procedure OPENSSL_LH_doall_arg( lh : POPENSSL_LHASH; func : TOPENSSL_LH_DOALL_FUNCARG; arg : Pointer);
begin
    doall_util_fn(lh, 1, TOPENSSL_LH_DOALL_FUNC(0), func, arg);
end;


procedure OPENSSL_LH_set_down_load( lh : POPENSSL_LHASH; down_load : Cardinal);
begin
    lh.down_load := down_load;
end;


function OPENSSL_LH_get_down_load(const lh : POPENSSL_LHASH):Cardinal;
begin
    Result := lh.down_load;
end;


function OPENSSL_LH_num_items(const lh : POPENSSL_LHASH):Cardinal;
begin
    if lh <> nil then
       Result := lh.num_items
    else
       Result := 0;
end;

function OPENSSL_LH_error( lh : POPENSSL_LHASH):integer;
begin
    Result := lh.error;
end;

function tsan_lock(const lh : POPENSSL_LHASH):integer;
begin
{$IFDEF TSAN_REQUIRES_LOCKING}
    if 0>= CRYPTO_THREAD_write_lock(lh.tsan_lock ) then
        Exit(0);
{$ENDIF}
    Result := 1;
end;

function OPENSSL_LH_retrieve(lh : POPENSSL_LHASH;const data : Pointer):Pointer;
var
  hash : Cardinal;
  p: PInteger;
  rn : PPOPENSSL_LH_NODE;
begin
    {-
     * This should be atomic without tsan.
     * It's not clear why it was done this way and not elsewhere.
     }
    //tsan_store(PInteger(@lh.error), 0);
    //(*((volatile int *)&lh->error) = (0));
    PInteger(@lh.error)^ := 0;
    rn := getrn(lh, data, hash);
    if tsan_lock(lh)>0  then
    begin
        if rn^ = nil then
           tsan_counter(@lh.num_retrieve_miss, SizeOf(uint32))
        else
           tsan_counter(@lh.num_retrieve, SizeOf(uint32));

        tsan_unlock(lh);
    end;
    if rn^ = nil then
      Result :=  nil
    else
      Result := rn^.data;
end;


procedure contract( lh : POPENSSL_LHASH);
var
  n1, np : POPENSSL_LH_NODE;
begin
{$POINTERMATH ON}
    np := lh.b[lh.p + lh.pmax - 1];
    lh.b[lh.p + lh.pmax - 1] := nil; { 24/07-92 - eay - weird but :-( }
    if lh.p = 0 then
    begin
        OPENSSL_realloc(Pointer(lh.b),
                            Uint32 (sizeof(POPENSSL_LH_NODE  ) * lh.pmax));
        if lh.b = nil then
        begin
            { fWriteLn('realloc error in lhash', stderr); }
            Inc(lh.error);
            exit;
        end;
        Inc(lh.num_contract_reallocs);
        lh.num_alloc_nodes  := lh.num_alloc_nodes  div 2;
        lh.pmax  := lh.pmax  div 2;
        lh.p := lh.pmax - 1;
        //lh.b := n;
    end
    else
        Dec(lh.p);
    Dec(lh.num_nodes);
    Inc(lh.num_contracts);
    n1 := lh.b[int(lh.p)];
    if n1 = nil then
       lh.b[int(lh.p)] := np
    else
    begin
        while n1.next <> nil do
            n1 := n1.next;
        n1.next := np;
    end;
 {$POINTERMATH OFF}
end;

function OPENSSL_LH_delete(lh : POPENSSL_LHASH;const data : Pointer):Pointer;
var
  hash : Cardinal;
  nn : POPENSSL_LH_NODE;
  rn : PPOPENSSL_LH_NODE;
  ret : Pointer;
begin
    lh.error := 0;
    rn := getrn(lh, data, hash);
    if rn^ = nil then
    begin
        Inc(lh.num_no_delete);
        Exit(nil);
    end
    else
    begin
        nn := rn^;
        rn^ := nn.next;
        ret := nn.data;
        OPENSSL_free(Pointer(nn));
        Inc(lh.num_delete);
    end;
    Inc(lh.num_items);
    if (lh.num_nodes > MIN_NODES)  and
        (lh.down_load >= (lh.num_items * LH_LOAD_MULT div lh.num_nodes)) then
        contract(lh);
    Result := ret;
end;

procedure tsan_unlock(const lh : POPENSSL_LHASH);
begin
{$IFDEF TSAN_REQUIRES_LOCKING}
    CRYPTO_THREAD_unlock(lh.tsan_lock);
{$ENDIF}
end;

function getrn(lh : POPENSSL_LHASH;const data : Pointer;var rhash : Uint32):PPOPENSSL_LH_NODE;
var
  n1 : POPENSSL_LH_NODE;
  hash, nn : Cardinal;
  cf : TOPENSSL_LH_COMPFUNC;
  do_tsan, I : integer;
  ret: PPOPENSSL_LH_NODE;
  function get_n1: POPENSSL_LH_NODE;
  begin
     if I = 0 then
        n1 := ret^
     else
        n1 := n1.next;
     Inc(I);
     Exit(n1);
  end;
begin
{$POINTERMATH ON}
    do_tsan := 1;
{$IFDEF TSAN_REQUIRES_LOCKING}
    do_tsan := tsan_lock(lh);
{$ENDIF}
    hash := lh.hash(data);
    if do_tsan>0 then
       tsan_counter(@lh.num_hash_calls, SizeOf(lh.num_hash_calls));
    rhash := hash;
    nn := hash mod lh.pmax;
    if nn < lh.p then
       nn := hash mod lh.num_alloc_nodes;
    cf := lh.comp;
    ret := @lh.b[int(nn)];
    I := 0;
    //for (n1 = *ret; n1 != NULL; n1 = n1->next)
    while get_n1 <> nil do
    begin
        if do_tsan>0 then
           tsan_counter(@lh.num_hash_comps, SizeOf(lh.num_hash_comps));
        if n1.hash <> hash then
        begin
            ret := @n1.next;
            continue;
        end;
        if do_tsan>0 then
           tsan_counter(@lh.num_comp_calls, SizeOf(lh.num_comp_calls));
        if cf(n1.data, data ) = 0 then
           break;
        ret := @n1.next;

    end;
    if do_tsan > 0 then
       tsan_unlock(lh);

    Exit(ret);
{$POINTERMATH OFF}
end;

function expand( lh : POPENSSL_LHASH):integer;
var
  np : POPENSSL_LH_NODE;
  n, n1, n2:PPOPENSSL_LH_NODE;
  p, pmax, nni, j, i : uint32;
  hash : Cardinal;
begin
{$POINTERMATH ON}
    nni := lh.num_alloc_nodes;
    p := lh.p;
    pmax := lh.pmax;
    if p + 1 >= pmax then
    begin
        j := nni * 2;
        {n := OPENSSL_realloc(lh.b, sizeof(POPENSSL_LH_NODE  ) * j);
        if n = nil then
        begin
            Inc(lh.error);
            Exit(0);
        end;
        lh.b := n;}
        SetLength(lh.b, j);
        //memset(lh.b + nni, 0, sizeof( lh.b^) * (j - nni));
        lh.pmax := nni;
        
        lh.num_alloc_nodes := j;
        Inc(lh.num_expand_reallocs);
        lh.p := 0;
    end
    else
    begin
        Inc(lh.p);
    end;
    Inc(lh.num_nodes);
    Inc(lh.num_expands);
    n1 := @(lh.b[p]);
    n2 := @(lh.b[p + pmax]);
    n2^ := nil;
    np := n1^;
    while ( np <> nil) do
    begin
        hash := np.hash;
        if (hash mod nni ) <> p then
        begin  { move it }
            n1^ := ( n1)^.next;
            np.next := n2^;
            n2^ := np;
        end
        else
            n1 := @(n1^.next);
        np := n1^;
    end;
    Result := 1;
 {$POINTERMATH OFF}
end;

function OPENSSL_LH_insert( lh : POPENSSL_LHASH;const data : Pointer):Pointer;
var
  hash : Cardinal;
  nn : POPENSSL_LH_NODE;
  rn : PPOPENSSL_LH_NODE;
  //ret : Pointer;
begin
    lh.error := 0;
    if (lh.up_load <= lh.num_items * LH_LOAD_MULT div lh.num_nodes )  and
       (0 >= expand(lh)) then
          Exit(nil);        { 'lh.PostInc(error)' already done in 'expand' }
    rn := getrn(lh, data, hash);
    if rn^ = nil then
    begin
        nn := OPENSSL_malloc(sizeof( nn^));
        if (nn) = nil then
        begin
            Inc(lh.error);
            Exit(nil);
        end;
        nn.data := data;
        nn.next := nil;
        nn.hash := hash;
        rn^ := nn;
        Result := nil;
        Inc(lh.num_insert);
        Inc(lh.num_items);
    end
    else
    begin                     { replace same key }
        Result := rn^.data;
        rn^.data := data;
        Inc(lh.num_replace);
    end;
    //Result := ret;
end;




procedure OPENSSL_LH_free( lh : POPENSSL_LHASH);
begin
    if lh = nil then exit;
    OPENSSL_LH_flush(lh);
{$IFDEF TSAN_REQUIRES_LOCKING}
    CRYPTO_THREAD_lock_free(lh.tsan_lock);
{$ENDIF}
    //OPENSSL_free(Pointer(lh.b));
    SetLength(lh.b, 0);
    OPENSSL_free(lh);
end;


procedure OPENSSL_LH_flush( lh : POPENSSL_LHASH);
var
  i : uint32;
  n, nn : POPENSSL_LH_NODE;
begin
{$POINTERMATH ON}
    if lh = nil then exit;
    for i := 0 to lh.num_nodes-1 do
    begin
        n := lh.b[i];
        while n <> nil do
        begin
            nn := n.next;
            OPENSSL_free(Pointer(n));
            n := nn;
        end;
        lh.b[i] := nil;
    end;
{$POINTERMATH OFF}
end;

function OPENSSL_LH_strhash(c : PUTF8Char):uint32;
var
  ret : uint32;
  n : long;
  v : uint32;
  r : integer;
begin
    ret := 0;
    if (c = nil )  or  (c^ = #0) then
        Exit(ret);
    n := $100;
    while c^<>#0  do
    begin
        v := n or Ord(c^);
        n  := n + $100;
        r := int((v  shr  2)  xor  v) and $0f;
        ret := (ret  shl  r) or (ret  shr  (32 - r));
        ret := ret and $FFFFFFFF;
        ret  := ret xor (v * v);
        Inc(c);
    end;
    Result := (ret  shr  16)  xor  ret;
end;


function OPENSSL_LH_new( hash : TOPENSSL_LH_HASHFUNC; cmp : TOPENSSL_LH_COMPFUNC):POPENSSL_LHASH;
  label _err;
begin
    Result := OPENSSL_zalloc(sizeof(Result^));
    if Result = nil then
    begin

        Exit(nil);
    end;
    //Result.b := OPENSSL_zalloc(sizeof(Result.b^)  * MIN_NODES)  ;
    SetLength(Result.b, MIN_NODES);
    if Result.b = nil then
        goto _err;
{$IFDEF TSAN_REQUIRES_LOCKING}
    if (Result.tsan_lock = CRYPTO_THREAD_lock_new()) = nil then
        goto _err;
{$ENDIF}
    if not Assigned(cmp) then
       Result.comp := strcmp
    else
       Result.comp := cmp;
    if not Assigned(hash)  then
       Result.hash := @OPENSSL_LH_strhash
    else
       Result.hash := hash;
    Result.num_nodes := MIN_NODES div 2;
    Result.num_alloc_nodes := MIN_NODES;
    Result.pmax := MIN_NODES div 2;
    Result.up_load := UP_LOAD;
    Result.down_load := DOWN_LOAD;
    Exit;

_err:
    OPENSSL_free(Result.b);
    OPENSSL_free(Result);
    Result := nil;
end;



end.
