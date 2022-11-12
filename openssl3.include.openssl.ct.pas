unit openssl3.include.openssl.ct;

interface
uses OpenSSL.Api;


  function ossl_check_SCT_type( ptr : PSCT):PSCT;
  function ossl_check_SCT_sk_type( sk : Pstack_st_SCT):POPENSSL_STACK;
  function ossl_check_SCT_compfunc_type( cmp : sk_SCT_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_SCT_copyfunc_type( cpy : sk_SCT_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_SCT_freefunc_type( fr : sk_SCT_freefunc):OPENSSL_sk_freefunc;
  procedure sk_SCT_pop_free(sk: Pointer; freefunc: sk_SCT_freefunc);
  procedure n2s(c: PByte; s: size_t);
  procedure n2l8(c: PByte; var l: UInt64);
  function sk_SCT_new_null: Pstack_st_SCT;
  function sk_SCT_pop(sk: Pointer): PSCT;
  procedure sk_SCT_free(sk: Pointer);
  function sk_SCT_push(sk, ptr: Pointer): int;
  function sk_SCT_num(sk: Pointer): int;
  function ossl_check_const_SCT_sk_type(const sk : Pstack_st_SCT):POPENSSL_STACK;
   function sk_SCT_value(sk: Pointer; idx: int): PSCT;
  procedure l2n8(l: UInt64; c: PByte);
  procedure s2n(s: size_t; c: PByte);
  function sk_CTLOG_new_null: Pstack_st_CTLOG;
  procedure sk_CTLOG_pop_free(sk: Pointer; freefunc: sk_CTLOG_freefunc);

  function ossl_check_CTLOG_type( ptr : PCTLOG):PCTLOG;
  function ossl_check_CTLOG_sk_type( sk : Pstack_st_CTLOG):POPENSSL_STACK;
  function ossl_check_CTLOG_compfunc_type( cmp : sk_CTLOG_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_CTLOG_copyfunc_type( cpy : sk_CTLOG_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_CTLOG_freefunc_type( fr : sk_CTLOG_freefunc):OPENSSL_sk_freefunc;
  function sk_CTLOG_push(sk, ptr: Pointer): int;
  function sk_CTLOG_value(sk: Pointer; idx: int): PCTLOG;
  function ossl_check_const_CTLOG_sk_type(const sk : Pstack_st_CTLOG):POPENSSL_STACK;
  function sk_CTLOG_num(sk: Pointer): int;


implementation
uses openssl3.crypto.stack;



function sk_CTLOG_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_CTLOG_sk_type(sk))
end;

function ossl_check_const_CTLOG_sk_type(const sk : Pstack_st_CTLOG):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk)
end;

function sk_CTLOG_value(sk: Pointer; idx: int): PCTLOG;
begin
    Result := PCTLOG(OPENSSL_sk_value(ossl_check_const_CTLOG_sk_type(sk), idx))
end;

function sk_CTLOG_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_CTLOG_sk_type(sk), ossl_check_CTLOG_type(ptr))
end;

function ossl_check_CTLOG_type( ptr : PCTLOG):PCTLOG;
begin
 Exit(ptr);
end;


function ossl_check_CTLOG_sk_type( sk : Pstack_st_CTLOG):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_CTLOG_compfunc_type( cmp : sk_CTLOG_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_CTLOG_copyfunc_type( cpy : sk_CTLOG_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_CTLOG_freefunc_type( fr : sk_CTLOG_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

procedure sk_CTLOG_pop_free(sk: Pointer; freefunc: sk_CTLOG_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_CTLOG_sk_type(sk),
                       ossl_check_CTLOG_freefunc_type(freefunc))
end;

function sk_CTLOG_new_null: Pstack_st_CTLOG;
begin
   Result := Pstack_st_CTLOG(OPENSSL_sk_new_null)
end;

procedure s2n(s: size_t; c: PByte);
begin
   c[0] := Byte((s shr 8) and $ff);
   c[1] := Byte((s    )   and $ff);
   c := c + 2;
end;

procedure l2n8(l: UInt64; c: PByte);
begin
   PostInc(c) ^ := Byte ((l shr 56) and $ff);
   PostInc(c) ^ := Byte ((l shr 48) and $ff);
   PostInc(c) ^ := Byte ((l shr 40) and $ff);
   PostInc(c) ^ := Byte ((l shr 32) and $ff);
   PostInc(c) ^ := Byte ((l shr 24) and $ff);
   PostInc(c) ^ := Byte ((l shr 16) and $ff);
   PostInc(c) ^ := Byte ((l shr  8) and $ff);
   PostInc(c) ^ := Byte ((l       ) and $ff);
end;

function sk_SCT_value(sk: Pointer; idx: int): PSCT;
begin
   Result := PSCT(OPENSSL_sk_value(ossl_check_const_SCT_sk_type(sk), (idx)))
end;



function ossl_check_const_SCT_sk_type(const sk : Pstack_st_SCT):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK(sk);
end;

function sk_SCT_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_SCT_sk_type(sk))
end;

function sk_SCT_push(sk, ptr: Pointer): int;
begin
  Result := OPENSSL_sk_push(ossl_check_SCT_sk_type(sk), ossl_check_SCT_type(ptr))
end;


procedure n2l8(c: PByte; var l: UInt64);
begin
   l := uint64(PostInc(c)^) shl 56;
	 l := l or (uint64(PostInc(c)^) shl 48);
	 l := l or (uint64(PostInc(c)^) shl 40);
	 l := l or (uint64(PostInc(c)^) shl 32);
	 l := l or (uint64(PostInc(c)^) shl 24);
	 l := l or (uint64(PostInc(c)^) shl 16);
	 l := l or (uint64(PostInc(c)^) shl  8);
	 l := l or uint64(PostInc(c)^);
end;

procedure sk_SCT_free(sk: Pointer);
begin
   OPENSSL_sk_free(ossl_check_SCT_sk_type(sk))
end;

function sk_SCT_pop(sk: Pointer): PSCT;
begin
   Result := PSCT(OPENSSL_sk_pop(ossl_check_SCT_sk_type(sk)))
end;

function sk_SCT_new_null: Pstack_st_SCT;
begin
   Result := Pstack_st_SCT(OPENSSL_sk_new_null)
end;

procedure  n2s(c: PByte; s: size_t);
begin
{$POINTERMATH ON}
    s := (uint32(c[0]) shl  8) or  uint32(c[1]);
    c := c + 2;
{$POINTERMATH OFF}
end;

function ossl_check_SCT_type( ptr : PSCT):PSCT;
begin
 Exit(ptr);
end;


function ossl_check_SCT_sk_type( sk : Pstack_st_SCT):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_SCT_compfunc_type( cmp : sk_SCT_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_SCT_copyfunc_type( cpy : sk_SCT_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_SCT_freefunc_type( fr : sk_SCT_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

procedure sk_SCT_pop_free(sk: Pointer; freefunc: sk_SCT_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_SCT_sk_type(sk),
                       ossl_check_SCT_freefunc_type(freefunc))
end;

end.
