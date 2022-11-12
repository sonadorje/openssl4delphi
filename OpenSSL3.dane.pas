unit OpenSSL3.dane;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

const
  DANETLS_USAGE_PKIX_TA = 0;
  DANETLS_USAGE_PKIX_EE = 1;
  DANETLS_USAGE_DANE_TA = 2;
  DANETLS_USAGE_DANE_EE = 3;
  DANETLS_USAGE_LAST = DANETLS_USAGE_DANE_EE;
  DANETLS_SELECTOR_CERT = 0;
  DANETLS_SELECTOR_SPKI = 1;
  DANETLS_SELECTOR_LAST = DANETLS_SELECTOR_SPKI;
  DANETLS_MATCHING_FULL = 0;
  DANETLS_MATCHING_2256 = 1;
  DANETLS_MATCHING_2512 = 2;
  DANETLS_MATCHING_LAST = DANETLS_MATCHING_2512;

  DANETLS_PKIX_TA_MASK = uint32(1) shl DANETLS_USAGE_PKIX_TA;
  DANETLS_PKIX_EE_MASK = uint32(1) shl DANETLS_USAGE_PKIX_EE;
  DANETLS_DANE_TA_MASK = uint32(1) shl DANETLS_USAGE_DANE_TA;
  DANETLS_DANE_EE_MASK = uint32(1) shl DANETLS_USAGE_DANE_EE;
  DANETLS_EE_MASK      = DANETLS_PKIX_EE_MASK or DANETLS_DANE_EE_MASK;
  DANETLS_TA_MASK      = (DANETLS_PKIX_TA_MASK or DANETLS_DANE_TA_MASK);
  DANETLS_PKIX_MASK = (DANETLS_PKIX_TA_MASK or DANETLS_PKIX_EE_MASK);
  DANETLS_DANE_MASK = (DANETLS_DANE_TA_MASK or DANETLS_DANE_EE_MASK);

type


  sk_danetls_record_compfunc = function(const a: PPdanetls_record; const b: PPdanetls_record): Integer;

  sk_danetls_record_freefunc = procedure(a: Pdanetls_record);

  sk_danetls_record_copyfunc = function(const a: Pdanetls_record): Pdanetls_record;
function sk_danetls_record_num( sk : PSTACK_st_danetls_record):integer;
  function sk_danetls_record_value( sk : PSTACK_st_danetls_record; idx : integer):Pdanetls_record;
  function sk_danetls_record_new( compare : sk_danetls_record_compfunc):PSTACK_st_danetls_record;
  function sk_danetls_record_new_null:PSTACK_st_danetls_record;
  function sk_danetls_record_new_reserve( compare : sk_danetls_record_compfunc; n : integer):PSTACK_st_danetls_record;
  function sk_danetls_record_reserve( sk : PSTACK_st_danetls_record; n : integer):integer;
  procedure sk_danetls_record_free( sk : PSTACK_st_danetls_record);
  procedure sk_danetls_record_zero( sk : PSTACK_st_danetls_record);
  function sk_danetls_record_delete( sk : PSTACK_st_danetls_record; i : integer):Pdanetls_record;
  function sk_danetls_record_delete_ptr( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):Pdanetls_record;
  function sk_danetls_record_push( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):integer;
  function sk_danetls_record_unshift( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):integer;
  function sk_danetls_record_pop( sk : PSTACK_st_danetls_record):Pdanetls_record;
  function sk_danetls_record_shift( sk : PSTACK_st_danetls_record):Pdanetls_record;
  procedure sk_danetls_record_pop_free( sk : PSTACK_st_danetls_record; freefunc : sk_danetls_record_freefunc);
  function sk_danetls_record_insert( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record; idx : integer):integer;
  function sk_danetls_record_set( sk : PSTACK_st_danetls_record; idx : integer; ptr : Pdanetls_record):Pdanetls_record;
  function sk_danetls_record_find( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):integer;
  function sk_danetls_record_find_ex( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):integer;
  function sk_danetls_record_find_all(sk : PSTACK_st_danetls_record; ptr : Pdanetls_record;pnum : Pinteger):integer;
  procedure sk_danetls_record_sort( sk : PSTACK_st_danetls_record);
  function sk_danetls_record_is_sorted( sk : PSTACK_st_danetls_record):integer;
  function sk_danetls_record_dup( sk : PSTACK_st_danetls_record):PSTACK_st_danetls_record;
  function sk_danetls_record_deep_copy( sk : PSTACK_st_danetls_record; copyfunc : sk_danetls_record_copyfunc; freefunc : sk_danetls_record_freefunc):PSTACK_st_danetls_record;
  function sk_danetls_record_set_cmp_func( sk : PSTACK_st_danetls_record; compare : sk_danetls_record_compfunc):sk_danetls_record_compfunc;
  function DANETLS_ENABLED(dane: PSSL_DANE): Boolean;
  function DANETLS_HAS_TA(dane: PSSL_DANE): Boolean;
  function DANETLS_USAGE_BIT(u: uint32): UInt32;
  function DANETLS_HAS_PKIX(dane: PSSL_DANE): Boolean;
  function DANETLS_HAS_DANE(dane: PSSL_DANE): Boolean;
  function  DANETLS_HAS_DANE_TA(dane: PSSL_DANE): Boolean;

implementation

USES openssl3.crypto.stack;

function  DANETLS_HAS_DANE_TA(dane: PSSL_DANE): Boolean;
begin
   Result :=  (Assigned(dane)) and ((dane.umask and DANETLS_DANE_TA_MASK)>0)
end;

function DANETLS_HAS_DANE(dane: PSSL_DANE): Boolean;
begin
   Result := ( Assigned(dane) ) and ((dane.umask and DANETLS_DANE_MASK)>0);
 end;

function DANETLS_HAS_PKIX(dane: PSSL_DANE): Boolean;
begin
  Result := (Assigned(dane)) and ( (dane.umask and DANETLS_PKIX_MASK)>0);
end;

function DANETLS_USAGE_BIT(u: uint32): UInt32;
begin
   Result := uint32(1) shl u;
end;

function DANETLS_HAS_TA(dane: PSSL_DANE): Boolean;
begin
   Result := (Assigned(dane)) and ((dane.umask and DANETLS_TA_MASK) > 0) ;
end;

function DANETLS_ENABLED(dane: PSSL_DANE): Boolean;
begin
   Result := (dane <> nil) and (sk_danetls_record_num(dane.trecs) > 0);
end;

function sk_danetls_record_num( sk : PSTACK_st_danetls_record):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK (sk));
end;


function sk_danetls_record_value( sk : PSTACK_st_danetls_record; idx : integer):Pdanetls_record;
begin
   Result := Pdanetls_record (OPENSSL_sk_value(POPENSSL_STACK (sk), idx));
end;


function sk_danetls_record_new( compare : sk_danetls_record_compfunc):PSTACK_st_danetls_record;
begin
   Result := PSTACK_st_danetls_record (OPENSSL_sk_new(OPENSSL_sk_compfunc(compare)));
end;


function sk_danetls_record_new_null:PSTACK_st_danetls_record;
begin
   Result := PSTACK_st_danetls_record (OPENSSL_sk_new_null());
end;


function sk_danetls_record_new_reserve( compare : sk_danetls_record_compfunc; n : integer):PSTACK_st_danetls_record;
begin
   Result := PSTACK_st_danetls_record (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n));
end;


function sk_danetls_record_reserve( sk : PSTACK_st_danetls_record; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK (sk), n);
end;


procedure sk_danetls_record_free( sk : PSTACK_st_danetls_record);
begin
   OPENSSL_sk_free(POPENSSL_STACK (sk));
end;


procedure sk_danetls_record_zero( sk : PSTACK_st_danetls_record);
begin
   OPENSSL_sk_zero(POPENSSL_STACK (sk));
end;


function sk_danetls_record_delete( sk : PSTACK_st_danetls_record; i : integer):Pdanetls_record;
begin
   Result := Pdanetls_record (OPENSSL_sk_delete(POPENSSL_STACK (sk), i));
end;


function sk_danetls_record_delete_ptr( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):Pdanetls_record;
begin
   Result := Pdanetls_record (OPENSSL_sk_delete_ptr(POPENSSL_STACK (sk),
                                           Pointer(ptr)));
end;


function sk_danetls_record_push( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK (sk), Pointer(ptr));
end;


function sk_danetls_record_unshift( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK (sk), Pointer(ptr));
end;


function sk_danetls_record_pop( sk : PSTACK_st_danetls_record):Pdanetls_record;
begin
   Result := Pdanetls_record (OPENSSL_sk_pop(POPENSSL_STACK (sk)));
end;


function sk_danetls_record_shift( sk : PSTACK_st_danetls_record):Pdanetls_record;
begin
   Result := Pdanetls_record (OPENSSL_sk_shift(POPENSSL_STACK (sk)));
end;


procedure sk_danetls_record_pop_free( sk : PSTACK_st_danetls_record; freefunc : sk_danetls_record_freefunc);
begin
    OPENSSL_sk_pop_free(POPENSSL_STACK (sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_danetls_record_insert( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK (sk), Pointer(ptr), idx);
end;


function sk_danetls_record_set( sk : PSTACK_st_danetls_record; idx : integer; ptr : Pdanetls_record):Pdanetls_record;
begin
   Result := Pdanetls_record (OPENSSL_sk_set(POPENSSL_STACK (sk), idx, Pointer(ptr)));
end;


function sk_danetls_record_find( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK (sk), Pointer(ptr));
end;


function sk_danetls_record_find_ex( sk : PSTACK_st_danetls_record; ptr : Pdanetls_record):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK (sk), Pointer(ptr));
end;


function sk_danetls_record_find_all(sk : PSTACK_st_danetls_record; ptr : Pdanetls_record;pnum : Pinteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK (sk), Pointer(ptr), pnum);
end;


procedure sk_danetls_record_sort( sk : PSTACK_st_danetls_record);
begin
   OPENSSL_sk_sort(POPENSSL_STACK (sk));
end;


function sk_danetls_record_is_sorted( sk : PSTACK_st_danetls_record):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK (sk));
end;


function sk_danetls_record_dup( sk : PSTACK_st_danetls_record):PSTACK_st_danetls_record;
begin
   Result := PSTACK_st_danetls_record (OPENSSL_sk_dup(POPENSSL_STACK (sk)) );
end;


function sk_danetls_record_deep_copy( sk : PSTACK_st_danetls_record; copyfunc : sk_danetls_record_copyfunc; freefunc : sk_danetls_record_freefunc):PSTACK_st_danetls_record;
begin
  Result := PSTACK_st_danetls_record (OPENSSL_sk_deep_copy(POPENSSL_STACK (sk),
                                            OPENSSL_sk_copyfunc(copyfunc),
                                            OPENSSL_sk_freefunc(freefunc)));
end;


function sk_danetls_record_set_cmp_func( sk : PSTACK_st_danetls_record; compare : sk_danetls_record_compfunc):sk_danetls_record_compfunc;
begin
   Result := sk_danetls_record_compfunc(OPENSSL_sk_set_cmp_func(
                                   POPENSSL_STACK (sk), OPENSSL_sk_compfunc(compare)));
end;



end.
