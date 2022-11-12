unit openssl3.crypto.x509v3;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
 uses OpenSSL.Api;

 const
   X509V3_CTX_TEST = $1;

  function ossl_check_DIST_POINT_type( ptr : PDIST_POINT):PDIST_POINT;
  function ossl_check_const_DIST_POINT_sk_type(const sk : PSTACK_st_DIST_POINT):POPENSSL_STACK;
  function ossl_check_DIST_POINT_sk_type( sk : PSTACK_st_DIST_POINT):POPENSSL_STACK;
  function ossl_check_DIST_POINT_compfunc_type( cmp : sk_DIST_POINT_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_DIST_POINT_copyfunc_type( cpy : sk_DIST_POINT_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_DIST_POINT_freefunc_type( fr : sk_DIST_POINT_freefunc):OPENSSL_sk_freefunc;

function sk_DIST_POINT_num( sk : Pointer):integer;
function sk_DIST_POINT_value( sk : Pointer; idx : integer): PDIST_POINT;
function sk_DIST_POINT_new(cmp: sk_DIST_POINT_compfunc): PSTACK_st_DIST_POINT;
function sk_DIST_POINT_new_null: PSTACK_st_DIST_POINT;
function sk_DIST_POINT_new_reserve(cmp : sk_DIST_POINT_compfunc;n: Integer): PSTACK_st_DIST_POINT;
function sk_DIST_POINT_reserve( sk : Pointer; n : integer):integer;
procedure sk_DIST_POINT_free( sk : Pointer);
procedure sk_DIST_POINT_zero( sk : Pointer);
function sk_DIST_POINT_delete(sk: Pointer; i : integer):PDIST_POINT;
function sk_DIST_POINT_delete_ptr( sk : Pointer; ptr : pointer):PDIST_POINT;
function sk_DIST_POINT_push( sk, ptr : Pointer):integer;
function sk_DIST_POINT_unshift( sk, ptr : Pointer):integer;
function sk_DIST_POINT_pop( sk : Pointer):PDIST_POINT;
function sk_DIST_POINT_shift( sk : Pointer):PDIST_POINT;
procedure sk_DIST_POINT_pop_free( sk : Pointer; freefunc : sk_DIST_POINT_freefunc);
function sk_DIST_POINT_insert( sk, ptr : Pointer; idx : integer):integer;
function sk_DIST_POINT_set( sk : Pointer; idx : integer; ptr : Pointer):PDIST_POINT;
function sk_DIST_POINT_find( sk, ptr : Pointer):integer;
function sk_DIST_POINT_find_ex( sk, ptr : Pointer):integer;
function sk_DIST_POINT_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
function sk_DIST_POINT_sort( sk : Pointer):integer;
function sk_DIST_POINT_is_sorted( sk : Pointer):integer;
function sk_DIST_POINT_dup( sk : Pointer): PSTACK_st_DIST_POINT;
function sk_DIST_POINT_deep_copy(sk: Pointer; copyfunc : sk_DIST_POINT_copyfunc;
                                 freefunc : sk_DIST_POINT_freefunc):PSTACK_st_DIST_POINT;
function sk_DIST_POINT_set_cmp_func(sk: Pointer; cmp: sk_DIST_POINT_compfunc):sk_DIST_POINT_compfunc;

function ossl_check_GENERAL_NAME_type( ptr : PGENERAL_NAME):PGENERAL_NAME;
function ossl_check_GENERAL_NAME_sk_type( sk : PSTACK_st_GENERAL_NAME):POPENSSL_STACK;
function ossl_check_GENERAL_NAME_compfunc_type( cmp : sk_GENERAL_NAME_compfunc):OPENSSL_sk_compfunc;
function ossl_check_GENERAL_NAME_copyfunc_type( cpy : sk_GENERAL_NAME_copyfunc):OPENSSL_sk_copyfunc;
function ossl_check_GENERAL_NAME_freefunc_type( fr : sk_GENERAL_NAME_freefunc):OPENSSL_sk_freefunc;

function sk_GENERAL_NAME_num( sk : Pointer):integer;
function sk_GENERAL_NAME_reserve( sk : Pointer; n: Integer):integer;
function sk_GENERAL_NAME_free( sk : Pointer):integer;
function sk_GENERAL_NAME_zero( sk : Pointer):integer;
function sk_GENERAL_NAME_delete( sk : Pointer; i : integer):PGENERAL_NAME;
function sk_GENERAL_NAME_delete_ptr( sk, ptr : Pointer):PGENERAL_NAME;
function sk_GENERAL_NAME_push( sk, ptr : Pointer):integer;
function sk_GENERAL_NAME_unshift( sk, ptr : Pointer):integer;
function sk_GENERAL_NAME_pop( sk : Pointer):PGENERAL_NAME;
function sk_GENERAL_NAME_shift( sk : Pointer):PGENERAL_NAME;
procedure sk_GENERAL_NAME_pop_free( sk : Pointer; freefunc : sk_GENERAL_NAME_freefunc);
function sk_GENERAL_NAME_insert( sk, ptr : Pointer; idx : integer):integer;
function sk_GENERAL_NAME_set( sk : Pointer; idx : integer; ptr : Pointer):PGENERAL_NAME;
function sk_GENERAL_NAME_find( sk, ptr : Pointer):integer;
function sk_GENERAL_NAME_find_ex( sk, ptr : Pointer):integer;
function sk_GENERAL_NAME_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
procedure sk_GENERAL_NAME_sort( sk : Pointer);
function sk_GENERAL_NAME_is_sorted( sk : Pointer):integer;
function sk_GENERAL_NAME_dup( sk : Pointer):PSTACK_st_GENERAL_NAME;
function sk_GENERAL_NAME_deep_copy( sk : Pointer; copyfunc : sk_GENERAL_NAME_copyfunc; freefunc : sk_GENERAL_NAME_freefunc):PSTACK_st_GENERAL_NAME;
function sk_GENERAL_NAME_set_cmp_func( sk : Pointer; cmp : sk_GENERAL_NAME_compfunc):sk_GENERAL_NAME_compfunc;
function sk_GENERAL_NAME_value(sk: Pointer; idx: integer): PGENERAL_NAME;
function ossl_check_IPAddressOrRange_type( ptr : PIPAddressOrRange):PIPAddressOrRange;
function ossl_check_IPAddressOrRange_sk_type( sk : PSTACK_st_IPAddressOrRange):POPENSSL_STACK;
function ossl_check_IPAddressOrRange_compfunc_type( cmp : sk_IPAddressOrRange_compfunc):OPENSSL_sk_compfunc;
function ossl_check_IPAddressOrRange_copyfunc_type( cpy : sk_IPAddressOrRange_copyfunc):OPENSSL_sk_copyfunc;
function ossl_check_IPAddressOrRange_freefunc_type( fr : sk_IPAddressOrRange_freefunc):OPENSSL_sk_freefunc;

function sk_IPAddressOrRange_num( sk : Pointer):integer;
function sk_IPAddressOrRange_reserve( sk : Pointer; n: Integer):integer;
function sk_IPAddressOrRange_free( sk : Pointer):integer;
function sk_IPAddressOrRange_zero( sk : Pointer):integer;
function sk_IPAddressOrRange_delete( sk : Pointer; i : integer):PIPAddressOrRange;
function sk_IPAddressOrRange_delete_ptr( sk, ptr : Pointer):PIPAddressOrRange;
function sk_IPAddressOrRange_push( sk, ptr : Pointer):integer;
function sk_IPAddressOrRange_unshift( sk, ptr : Pointer):integer;
function sk_IPAddressOrRange_pop( sk : Pointer):PIPAddressOrRange;
function sk_IPAddressOrRange_shift( sk : Pointer):PIPAddressOrRange;
procedure sk_IPAddressOrRange_pop_free( sk : Pointer; freefunc : sk_IPAddressOrRange_freefunc);
function sk_IPAddressOrRange_insert( sk, ptr : Pointer; idx : integer):integer;
function sk_IPAddressOrRange_set( sk : Pointer; idx : integer; ptr : Pointer):PIPAddressOrRange;
function sk_IPAddressOrRange_find( sk, ptr : Pointer):integer;
function sk_IPAddressOrRange_find_ex( sk, ptr : Pointer):integer;
function sk_IPAddressOrRange_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
procedure sk_IPAddressOrRange_sort( sk : Pointer);
function sk_IPAddressOrRange_is_sorted( sk : Pointer):integer;
function sk_IPAddressOrRange_dup( sk : Pointer):PSTACK_st_IPAddressOrRange;
function sk_IPAddressOrRange_deep_copy( sk : Pointer; copyfunc : sk_IPAddressOrRange_copyfunc; freefunc : sk_IPAddressOrRange_freefunc):PSTACK_st_IPAddressOrRange;
function sk_IPAddressOrRange_set_cmp_func( sk : Pointer; cmp : sk_IPAddressOrRange_compfunc):sk_IPAddressOrRange_compfunc;
function sk_IPAddressOrRange_value(sk: Pointer; idx: integer): PIPAddressOrRange;
function sk_IPAddressOrRange_new_null(): PSTACK_st_IPAddressOrRange;

function ossl_check_IPAddressFamily_type( ptr : PIPAddressFamily):PIPAddressFamily;
function ossl_check_IPAddressFamily_sk_type( sk : PSTACK_st_IPAddressFamily):POPENSSL_STACK;
function ossl_check_IPAddressFamily_compfunc_type( cmp : sk_IPAddressFamily_compfunc):OPENSSL_sk_compfunc;
function ossl_check_IPAddressFamily_copyfunc_type( cpy : sk_IPAddressFamily_copyfunc):OPENSSL_sk_copyfunc;
function ossl_check_IPAddressFamily_freefunc_type( fr : sk_IPAddressFamily_freefunc):OPENSSL_sk_freefunc;

function sk_IPAddressFamily_num( sk : Pointer):integer;
function sk_IPAddressFamily_reserve( sk : Pointer; n: Integer):integer;
function sk_IPAddressFamily_free( sk : Pointer):integer;
function sk_IPAddressFamily_zero( sk : Pointer):integer;
function sk_IPAddressFamily_delete( sk : Pointer; i : integer):PIPAddressFamily;
function sk_IPAddressFamily_delete_ptr( sk, ptr : Pointer):PIPAddressFamily;
function sk_IPAddressFamily_push( sk, ptr : Pointer):integer;
function sk_IPAddressFamily_unshift( sk, ptr : Pointer):integer;
function sk_IPAddressFamily_pop( sk : Pointer):PIPAddressFamily;
function sk_IPAddressFamily_shift( sk : Pointer):PIPAddressFamily;
procedure sk_IPAddressFamily_pop_free( sk : Pointer; freefunc : sk_IPAddressFamily_freefunc);
function sk_IPAddressFamily_insert( sk, ptr : Pointer; idx : integer):integer;
function sk_IPAddressFamily_set( sk : Pointer; idx : integer; ptr : Pointer):PIPAddressFamily;
function sk_IPAddressFamily_find( sk, ptr : Pointer):integer;
function sk_IPAddressFamily_find_ex( sk, ptr : Pointer):integer;
function sk_IPAddressFamily_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
procedure sk_IPAddressFamily_sort( sk : Pointer);
function sk_IPAddressFamily_is_sorted( sk : Pointer):integer;
function sk_IPAddressFamily_dup( sk : Pointer):PSTACK_st_IPAddressFamily;
function sk_IPAddressFamily_deep_copy( sk : Pointer; copyfunc : sk_IPAddressFamily_copyfunc; freefunc : sk_IPAddressFamily_freefunc):PSTACK_st_IPAddressFamily;
function sk_IPAddressFamily_set_cmp_func( sk : Pointer; cmp : sk_IPAddressFamily_compfunc):sk_IPAddressFamily_compfunc;
function sk_IPAddressFamily_value(sk: Pointer; idx: integer): PIPAddressFamily;
function sk_IPAddressFamily_new(cmp:sk_IPAddressFamily_compfunc) : PSTACK_st_IPAddressFamily;
function sk_GENERAL_NAME_new_reserve(cmp:sk_GENERAL_NAME_compfunc; n: int):Pstack_st_GENERAL_NAME;
function sk_POLICYINFO_num(sk: Pointer): int;
function ossl_check_const_POLICYINFO_sk_type(const sk: Pstack_st_POLICYINFO):POPENSSL_STACK;
function sk_POLICYINFO_value(sk: Pointer; idx: int): PPOLICYINFO;
function sk_POLICYQUALINFO_num(sk: Pointer): int;
function ossl_check_const_POLICYQUALINFO_sk_type(const sk : Pstack_st_POLICYQUALINFO):POPENSSL_STACK;
function sk_POLICYQUALINFO_value(sk: Pointer; idx: int): PPOLICYQUALINFO;
function ossl_check_POLICYINFO_compfunc_type( cmp : sk_POLICYINFO_compfunc):OPENSSL_sk_compfunc;
function sk_POLICYINFO_new_reserve(cmp: sk_POLICYINFO_compfunc; n: int): Pstack_st_POLICYINFO;
function sk_POLICYQUALINFO_new_null: Pstack_st_POLICYQUALINFO;
function sk_POLICYQUALINFO_new(cmp: sk_POLICYQUALINFO_compfunc): Pstack_st_POLICYQUALINFO;
function ossl_check_POLICYQUALINFO_compfunc_type( cmp : sk_POLICYQUALINFO_compfunc):OPENSSL_sk_compfunc;
function ossl_check_POLICYQUALINFO_sk_type(sk: Pstack_st_POLICYQUALINFO):POPENSSL_STACK;
function ossl_check_POLICYQUALINFO_type( ptr : PPOLICYQUALINFO):PPOLICYQUALINFO;
function sk_POLICYQUALINFO_push(sk, ptr: Pointer): int;
function ossl_check_POLICYINFO_type( ptr : PPOLICYINFO):PPOLICYINFO;
function ossl_check_POLICYINFO_sk_type( sk : Pstack_st_POLICYINFO):POPENSSL_STACK;
function sk_POLICYINFO_push(sk, ptr: Pointer):int;
procedure sk_POLICYINFO_pop_free(sk: Pointer; freefunc: sk_POLICYINFO_freefunc) ;
function ossl_check_POLICYINFO_freefunc_type( fr : sk_POLICYINFO_freefunc):OPENSSL_sk_freefunc;
function sk_GENERAL_NAME_new_null: Pstack_st_GENERAL_NAME;
function sk_SXNETID_num(sk: Pointer): int;
function ossl_check_SXNETID_type( ptr : PSXNETID):PSXNETID;
  function ossl_check_const_SXNETID_sk_type(const sk : Pstack_st_SXNETID):POPENSSL_STACK;
  function ossl_check_SXNETID_sk_type( sk : Pstack_st_SXNETID):POPENSSL_STACK;
  function ossl_check_SXNETID_compfunc_type( cmp : sk_SXNETID_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_SXNETID_copyfunc_type( cpy : sk_SXNETID_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_SXNETID_freefunc_type( fr : sk_SXNETID_freefunc):OPENSSL_sk_freefunc;
  function sk_SXNETID_value(sk: Pointer; idx: int): PSXNETID;
  function sk_SXNETID_push(sk, ptr: Pointer):int;
  function sk_ACCESS_DESCRIPTION_num(sk: Pointer): int;

  function ossl_check_ACCESS_DESCRIPTION_type( ptr : PACCESS_DESCRIPTION):PACCESS_DESCRIPTION;
  function ossl_check_const_ACCESS_DESCRIPTION_sk_type(const sk : Pstack_st_ACCESS_DESCRIPTION):POPENSSL_STACK;
  function ossl_check_ACCESS_DESCRIPTION_sk_type( sk : Pstack_st_ACCESS_DESCRIPTION):POPENSSL_STACK;
  function ossl_check_ACCESS_DESCRIPTION_compfunc_type( cmp : sk_ACCESS_DESCRIPTION_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_ACCESS_DESCRIPTION_copyfunc_type( cpy : sk_ACCESS_DESCRIPTION_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_ACCESS_DESCRIPTION_freefunc_type( fr : sk_ACCESS_DESCRIPTION_freefunc):OPENSSL_sk_freefunc;
  function sk_ACCESS_DESCRIPTION_value(sk: Pointer; idx: int):PACCESS_DESCRIPTION;
  function sk_ACCESS_DESCRIPTION_new_reserve(cmp: sk_ACCESS_DESCRIPTION_compfunc; n: int): Pstack_st_ACCESS_DESCRIPTION;
  function sk_ACCESS_DESCRIPTION_push(sk, ptr: Pointer): int;
  procedure sk_ACCESS_DESCRIPTION_pop_free(sk: Pointer; freefunc: sk_ACCESS_DESCRIPTION_freefunc) ;

  function ossl_check_ASIdOrRange_type( ptr : PASIdOrRange):PASIdOrRange;
  function ossl_check_const_ASIdOrRange_sk_type(const sk : Pstack_st_ASIdOrRange):POPENSSL_STACK;
  function ossl_check_ASIdOrRange_sk_type( sk : Pstack_st_ASIdOrRange):POPENSSL_STACK;
  function ossl_check_ASIdOrRange_compfunc_type( cmp : sk_ASIdOrRange_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_ASIdOrRange_copyfunc_type( cpy : sk_ASIdOrRange_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_ASIdOrRange_freefunc_type( fr : sk_ASIdOrRange_freefunc):OPENSSL_sk_freefunc;
  function sk_ASIdOrRange_new(cmp: sk_ASIdOrRange_compfunc): Pstack_st_ASIdOrRange;
  function  sk_ASIdOrRange_push(sk, ptr: Pointer): int;
  function sk_ASIdOrRange_num(sk: Pointer): int;
  procedure sk_ASIdOrRange_sort(sk: Pointer);
  function sk_ASIdOrRange_value(sk: Pointer; idx: int): PASIdOrRange;
  function sk_ASIdOrRange_delete(sk: Pointer; i: int): PASIdOrRange;
  procedure X509V3_conf_err(val: PCONF_VALUE);
  function sk_GENERAL_SUBTREE_new_null: Pstack_st_GENERAL_SUBTREE;
  function sk_GENERAL_SUBTREE_push(sk, ptr: Pointer): int;

  function ossl_check_GENERAL_SUBTREE_type( ptr : PGENERAL_SUBTREE):PGENERAL_SUBTREE;
  function ossl_check_GENERAL_SUBTREE_sk_type( sk : Pstack_st_GENERAL_SUBTREE):POPENSSL_STACK;
  function ossl_check_GENERAL_SUBTREE_compfunc_type( cmp : sk_GENERAL_SUBTREE_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_GENERAL_SUBTREE_copyfunc_type( cpy : sk_GENERAL_SUBTREE_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_GENERAL_SUBTREE_freefunc_type( fr : sk_GENERAL_SUBTREE_freefunc):OPENSSL_sk_freefunc;
  function ossl_check_const_GENERAL_SUBTREE_sk_type(const sk : Pstack_st_GENERAL_SUBTREE):POPENSSL_STACK;

  function sk_GENERAL_SUBTREE_num(sk: Pointer): int;
  function sk_GENERAL_SUBTREE_value(sk: Pointer; idx: int): PGENERAL_SUBTREE;

  function sk_POLICY_MAPPING_num(sk: Pointer): int;

  function ossl_check_POLICY_MAPPING_type( ptr : PPOLICY_MAPPING):PPOLICY_MAPPING;
  function ossl_check_const_POLICY_MAPPING_sk_type(const sk : Pstack_st_POLICY_MAPPING):POPENSSL_STACK;
  function ossl_check_POLICY_MAPPING_sk_type( sk : Pstack_st_POLICY_MAPPING):POPENSSL_STACK;
  function ossl_check_POLICY_MAPPING_compfunc_type( cmp : sk_POLICY_MAPPING_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_POLICY_MAPPING_copyfunc_type( cpy : sk_POLICY_MAPPING_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_POLICY_MAPPING_freefunc_type( fr : sk_POLICY_MAPPING_freefunc):OPENSSL_sk_freefunc;

  function sk_POLICY_MAPPING_value(sk: Pointer; idx: int): PPOLICY_MAPPING;
  function sk_POLICY_MAPPING_new_reserve(cmp: sk_POLICY_MAPPING_compfunc; n: int): Pstack_st_POLICY_MAPPING;
   function sk_POLICY_MAPPING_push(sk, ptr: Pointer): int;
  procedure sk_POLICY_MAPPING_pop_free(sk: Pointer; freefunc: sk_POLICY_MAPPING_freefunc);

  function ossl_check_GENERAL_NAMES_type( ptr : PGENERAL_NAMES):PGENERAL_NAMES;
  function ossl_check_const_GENERAL_NAMES_sk_type(const sk : Pstack_st_GENERAL_NAMES):POPENSSL_STACK;
  function ossl_check_GENERAL_NAMES_sk_type( sk : Pstack_st_GENERAL_NAMES):POPENSSL_STACK;
  function ossl_check_GENERAL_NAMES_compfunc_type( cmp : sk_GENERAL_NAMES_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_GENERAL_NAMES_copyfunc_type( cpy : sk_GENERAL_NAMES_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_GENERAL_NAMES_freefunc_type( fr : sk_GENERAL_NAMES_freefunc):OPENSSL_sk_freefunc;
  procedure sk_GENERAL_NAMES_pop_free(sk: Pointer; freefunc: sk_GENERAL_NAMES_freefunc);
  function sk_GENERAL_NAMES_new_null: Pstack_st_GENERAL_NAMES;
  function sk_GENERAL_NAMES_push(sk, ptr: Pointer): int;
  function sk_X509_PURPOSE_find(sk, ptr: Pointer): int;

  function ossl_check_X509_PURPOSE_type( ptr : PX509_PURPOSE):PX509_PURPOSE;
  function ossl_check_const_X509_PURPOSE_sk_type(const sk : Pstack_st_X509_PURPOSE):POPENSSL_STACK;
  function ossl_check_X509_PURPOSE_sk_type( sk : Pstack_st_X509_PURPOSE):POPENSSL_STACK;
  function ossl_check_X509_PURPOSE_compfunc_type( cmp : sk_X509_PURPOSE_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_PURPOSE_copyfunc_type( cpy : sk_X509_PURPOSE_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_PURPOSE_freefunc_type( fr : sk_X509_PURPOSE_freefunc):OPENSSL_sk_freefunc;
  function sk_X509_PURPOSE_value(sk: Pointer; idx: int): PX509_PURPOSE;
  procedure sk_POLICYQUALINFO_pop_free(sk: Pointer; freefunc: sk_POLICYQUALINFO_freefunc);

  function ossl_check_POLICYQUALINFO_copyfunc_type( cpy : sk_POLICYQUALINFO_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_POLICYQUALINFO_freefunc_type( fr : sk_POLICYQUALINFO_freefunc):OPENSSL_sk_freefunc;

  function ossl_check_X509_POLICY_NODE_type( ptr : PX509_POLICY_NODE):PX509_POLICY_NODE;
  function ossl_check_const_X509_POLICY_NODE_sk_type(const sk : Pstack_st_X509_POLICY_NODE):POPENSSL_STACK;
  function ossl_check_X509_POLICY_NODE_sk_type( sk : Pstack_st_X509_POLICY_NODE):POPENSSL_STACK;
  function ossl_check_X509_POLICY_NODE_compfunc_type( cmp : sk_X509_POLICY_NODE_compfunc):OPENSSL_sk_compfunc;
  function ossl_check_X509_POLICY_NODE_copyfunc_type( cpy : sk_X509_POLICY_NODE_copyfunc):OPENSSL_sk_copyfunc;
  function ossl_check_X509_POLICY_NODE_freefunc_type( fr : sk_X509_POLICY_NODE_freefunc):OPENSSL_sk_freefunc;
  function sk_X509_POLICY_NODE_new(cmp: sk_X509_POLICY_NODE_compfunc): Pstack_st_X509_POLICY_NODE;
  function sk_X509_POLICY_NODE_find(sk, ptr: Pointer): int;
  function sk_X509_POLICY_NODE_value(sk: Pointer; idx: int): PX509_POLICY_NODE;
  function sk_X509_POLICY_NODE_num(sk: Pointer): int;
  function sk_X509_POLICY_NODE_push(sk, ptr: Pointer): int;
  procedure sk_X509_POLICY_NODE_pop_free(sk: Pointer; freefunc: sk_X509_POLICY_NODE_freefunc);
  procedure sk_X509_POLICY_NODE_free(sk: Pointer);
  function sk_X509_POLICY_NODE_delete(sk: Pointer; i: int): PX509_POLICY_NODE;
  function sk_X509_POLICY_NODE_new_null: Pstack_st_X509_POLICY_NODE;

implementation
uses
    openssl3.crypto.stack, OpenSSL3.Err;

function sk_X509_POLICY_NODE_new_null: Pstack_st_X509_POLICY_NODE;
begin
   Result := Pstack_st_X509_POLICY_NODE(OPENSSL_sk_new_null)
end;

function sk_X509_POLICY_NODE_delete(sk: Pointer; i: int): PX509_POLICY_NODE;
begin
  Result := PX509_POLICY_NODE(OPENSSL_sk_delete(ossl_check_X509_POLICY_NODE_sk_type(sk), i))
end;

procedure sk_X509_POLICY_NODE_pop_free(sk: Pointer; freefunc: sk_X509_POLICY_NODE_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_X509_POLICY_NODE_sk_type(sk),
                       ossl_check_X509_POLICY_NODE_freefunc_type(freefunc))
end;

procedure sk_X509_POLICY_NODE_free(sk: Pointer);
begin
    OPENSSL_sk_free(ossl_check_X509_POLICY_NODE_sk_type(sk))
end;

function sk_X509_POLICY_NODE_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_X509_POLICY_NODE_sk_type(sk),
                             ossl_check_X509_POLICY_NODE_type(ptr))
end;

function sk_X509_POLICY_NODE_num(sk: Pointer): int;
begin
   Result :=  OPENSSL_sk_num(ossl_check_const_X509_POLICY_NODE_sk_type(sk))
end;
function sk_X509_POLICY_NODE_value(sk: Pointer; idx: int): PX509_POLICY_NODE;
begin
   Result := PX509_POLICY_NODE(OPENSSL_sk_value(ossl_check_const_X509_POLICY_NODE_sk_type(sk), (idx)))
end;

function sk_X509_POLICY_NODE_find(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_find(ossl_check_X509_POLICY_NODE_sk_type(sk),
                             ossl_check_X509_POLICY_NODE_type(ptr))
end;


function ossl_check_X509_POLICY_NODE_type( ptr : PX509_POLICY_NODE):PX509_POLICY_NODE;
begin
 Exit(ptr);
end;


function ossl_check_const_X509_POLICY_NODE_sk_type(const sk : Pstack_st_X509_POLICY_NODE):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_POLICY_NODE_sk_type( sk : Pstack_st_X509_POLICY_NODE):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_X509_POLICY_NODE_compfunc_type( cmp : sk_X509_POLICY_NODE_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_POLICY_NODE_copyfunc_type( cpy : sk_X509_POLICY_NODE_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_POLICY_NODE_freefunc_type( fr : sk_X509_POLICY_NODE_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_X509_POLICY_NODE_new(cmp: sk_X509_POLICY_NODE_compfunc): Pstack_st_X509_POLICY_NODE;
begin
    Result := Pstack_st_X509_POLICY_NODE(OPENSSL_sk_new(ossl_check_X509_POLICY_NODE_compfunc_type(cmp)))
end;

function ossl_check_POLICYQUALINFO_copyfunc_type( cpy : sk_POLICYQUALINFO_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_POLICYQUALINFO_freefunc_type( fr : sk_POLICYQUALINFO_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

procedure sk_POLICYQUALINFO_pop_free(sk: Pointer; freefunc: sk_POLICYQUALINFO_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_POLICYQUALINFO_sk_type(sk),
                      ossl_check_POLICYQUALINFO_freefunc_type(freefunc))
end;

function sk_X509_PURPOSE_value(sk: Pointer; idx: int): PX509_PURPOSE;
begin
   Result := PX509_PURPOSE(OPENSSL_sk_value(ossl_check_const_X509_PURPOSE_sk_type(sk), idx))
end;


function ossl_check_X509_PURPOSE_type( ptr : PX509_PURPOSE):PX509_PURPOSE;
begin
   Exit(ptr);
end;


function ossl_check_const_X509_PURPOSE_sk_type(const sk : Pstack_st_X509_PURPOSE):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_PURPOSE_sk_type( sk : Pstack_st_X509_PURPOSE):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK (sk);
end;


function ossl_check_X509_PURPOSE_compfunc_type( cmp : sk_X509_PURPOSE_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_X509_PURPOSE_copyfunc_type( cpy : sk_X509_PURPOSE_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_X509_PURPOSE_freefunc_type( fr : sk_X509_PURPOSE_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_X509_PURPOSE_find(sk, ptr: Pointer): int;
begin
  Result := OPENSSL_sk_find(ossl_check_X509_PURPOSE_sk_type(sk),
                            ossl_check_X509_PURPOSE_type(ptr))
end;

function sk_GENERAL_NAMES_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_GENERAL_NAMES_sk_type(sk),
                    ossl_check_GENERAL_NAMES_type(ptr))
end;

function sk_GENERAL_NAMES_new_null: Pstack_st_GENERAL_NAMES;
begin
  Result := Pstack_st_GENERAL_NAMES(OPENSSL_sk_new_null)
end;

function ossl_check_GENERAL_NAMES_type( ptr : PGENERAL_NAMES):PGENERAL_NAMES;
begin
 Exit(ptr);
end;


function ossl_check_const_GENERAL_NAMES_sk_type(const sk : Pstack_st_GENERAL_NAMES):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_GENERAL_NAMES_sk_type( sk : Pstack_st_GENERAL_NAMES):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_GENERAL_NAMES_compfunc_type( cmp : sk_GENERAL_NAMES_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_GENERAL_NAMES_copyfunc_type( cpy : sk_GENERAL_NAMES_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_GENERAL_NAMES_freefunc_type( fr : sk_GENERAL_NAMES_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

procedure sk_GENERAL_NAMES_pop_free(sk: Pointer; freefunc: sk_GENERAL_NAMES_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_GENERAL_NAMES_sk_type(sk),
                   ossl_check_GENERAL_NAMES_freefunc_type(freefunc))
end;

procedure sk_POLICY_MAPPING_pop_free(sk: Pointer; freefunc: sk_POLICY_MAPPING_freefunc);
begin
    OPENSSL_sk_pop_free(ossl_check_POLICY_MAPPING_sk_type(sk),
                        ossl_check_POLICY_MAPPING_freefunc_type(freefunc))
end;

function sk_POLICY_MAPPING_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_POLICY_MAPPING_sk_type(sk),
                             ossl_check_POLICY_MAPPING_type(ptr))
end;

function sk_POLICY_MAPPING_new_reserve(cmp: sk_POLICY_MAPPING_compfunc; n: int): Pstack_st_POLICY_MAPPING;
begin
  Result := Pstack_st_POLICY_MAPPING( OPENSSL_sk_new_reserve(ossl_check_POLICY_MAPPING_compfunc_type(cmp), (n)))
end;

function sk_POLICY_MAPPING_value(sk: Pointer; idx: int): PPOLICY_MAPPING;
begin
   Result := PPOLICY_MAPPING(OPENSSL_sk_value(ossl_check_const_POLICY_MAPPING_sk_type(sk), (idx)))
end;

function ossl_check_POLICY_MAPPING_type( ptr : PPOLICY_MAPPING):PPOLICY_MAPPING;
begin
 Exit(ptr);
end;


function ossl_check_const_POLICY_MAPPING_sk_type(const sk : Pstack_st_POLICY_MAPPING):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_POLICY_MAPPING_sk_type( sk : Pstack_st_POLICY_MAPPING):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_POLICY_MAPPING_compfunc_type( cmp : sk_POLICY_MAPPING_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_POLICY_MAPPING_copyfunc_type( cpy : sk_POLICY_MAPPING_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_POLICY_MAPPING_freefunc_type( fr : sk_POLICY_MAPPING_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_POLICY_MAPPING_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_POLICY_MAPPING_sk_type(sk))
end;

function sk_GENERAL_SUBTREE_value(sk: Pointer; idx: int): PGENERAL_SUBTREE;
begin
   Result := PGENERAL_SUBTREE(OPENSSL_sk_value(ossl_check_const_GENERAL_SUBTREE_sk_type(sk), (idx)))
end;

function ossl_check_const_GENERAL_SUBTREE_sk_type(const sk : Pstack_st_GENERAL_SUBTREE):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;

function sk_GENERAL_SUBTREE_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_GENERAL_SUBTREE_sk_type(sk))
end;

function ossl_check_GENERAL_SUBTREE_type( ptr : PGENERAL_SUBTREE):PGENERAL_SUBTREE;
begin
 Exit(ptr);
end;


function ossl_check_GENERAL_SUBTREE_sk_type( sk : Pstack_st_GENERAL_SUBTREE):POPENSSL_STACK;
begin
 Result := POPENSSL_STACK(sk);
end;


function ossl_check_GENERAL_SUBTREE_compfunc_type( cmp : sk_GENERAL_SUBTREE_compfunc):OPENSSL_sk_compfunc;
begin
 Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_GENERAL_SUBTREE_copyfunc_type( cpy : sk_GENERAL_SUBTREE_copyfunc):OPENSSL_sk_copyfunc;
begin
 Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_GENERAL_SUBTREE_freefunc_type( fr : sk_GENERAL_SUBTREE_freefunc):OPENSSL_sk_freefunc;
begin
 Result := OPENSSL_sk_freefunc(fr);
end;

function sk_GENERAL_SUBTREE_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_GENERAL_SUBTREE_sk_type(sk),
                        ossl_check_GENERAL_SUBTREE_type(ptr))
end;

function sk_GENERAL_SUBTREE_new_null: Pstack_st_GENERAL_SUBTREE;
begin
    Result := Pstack_st_GENERAL_SUBTREE(OPENSSL_sk_new_null())
end;

procedure X509V3_conf_err(val: PCONF_VALUE);
begin
    ERR_add_error_data(6, ['section:', (val).section,
                        ',name:', (val).name, ',value:', (val).value])

end;

function sk_ASIdOrRange_delete(sk: Pointer; i: int): PASIdOrRange;
begin
    Result := PASIdOrRange(OPENSSL_sk_delete(ossl_check_ASIdOrRange_sk_type(sk), i))
end;


function sk_ASIdOrRange_value(sk: Pointer; idx: int): PASIdOrRange;
begin
   Result := OPENSSL_sk_value(ossl_check_const_ASIdOrRange_sk_type(sk), idx)
end;

procedure sk_ASIdOrRange_sort(sk: Pointer);
begin
   OPENSSL_sk_sort(ossl_check_ASIdOrRange_sk_type(sk))
end;

function sk_ASIdOrRange_num(sk: Pointer): int;
begin
  Result := OPENSSL_sk_num(ossl_check_const_ASIdOrRange_sk_type(sk))
end;


function  sk_ASIdOrRange_push(sk, ptr: Pointer): int;
begin
  Result := OPENSSL_sk_push(ossl_check_ASIdOrRange_sk_type(sk),
                            ossl_check_ASIdOrRange_type(ptr))
end;



function ossl_check_ASIdOrRange_type( ptr : PASIdOrRange):PASIdOrRange;
begin
 Exit(ptr);
end;


function ossl_check_const_ASIdOrRange_sk_type(const sk : Pstack_st_ASIdOrRange):POPENSSL_STACK;
begin
 Exit(POPENSSL_STACK( sk));
end;


function ossl_check_ASIdOrRange_sk_type( sk : Pstack_st_ASIdOrRange):POPENSSL_STACK;
begin
 Exit(POPENSSL_STACK( sk));
end;


function ossl_check_ASIdOrRange_compfunc_type( cmp : sk_ASIdOrRange_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_ASIdOrRange_copyfunc_type( cpy : sk_ASIdOrRange_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_ASIdOrRange_freefunc_type( fr : sk_ASIdOrRange_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

function sk_ASIdOrRange_new(cmp: sk_ASIdOrRange_compfunc): Pstack_st_ASIdOrRange;
begin
  Result := Pstack_st_ASIdOrRange( OPENSSL_sk_new(ossl_check_ASIdOrRange_compfunc_type(cmp)))
end;


procedure sk_ACCESS_DESCRIPTION_pop_free(sk: Pointer; freefunc: sk_ACCESS_DESCRIPTION_freefunc) ;
begin
   OPENSSL_sk_pop_free(ossl_check_ACCESS_DESCRIPTION_sk_type(sk),
                       ossl_check_ACCESS_DESCRIPTION_freefunc_type(freefunc))
end;

function sk_ACCESS_DESCRIPTION_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_ACCESS_DESCRIPTION_sk_type(sk),
                             ossl_check_ACCESS_DESCRIPTION_type(ptr))
end;

function sk_ACCESS_DESCRIPTION_new_reserve(cmp: sk_ACCESS_DESCRIPTION_compfunc; n: int): Pstack_st_ACCESS_DESCRIPTION;
begin
   Result := Pstack_st_ACCESS_DESCRIPTION(OPENSSL_sk_new_reserve
              (ossl_check_ACCESS_DESCRIPTION_compfunc_type(cmp), n))
end;

function sk_ACCESS_DESCRIPTION_value(sk: Pointer; idx: int):PACCESS_DESCRIPTION;
begin
   Result := PACCESS_DESCRIPTION(OPENSSL_sk_value(
       ossl_check_const_ACCESS_DESCRIPTION_sk_type(sk), (idx)))
end;

function ossl_check_ACCESS_DESCRIPTION_type( ptr : PACCESS_DESCRIPTION):PACCESS_DESCRIPTION;
begin
 Exit(ptr);
end;


function ossl_check_const_ACCESS_DESCRIPTION_sk_type(const sk : Pstack_st_ACCESS_DESCRIPTION):POPENSSL_STACK;
begin
 Exit(POPENSSL_STACK( sk));
end;


function ossl_check_ACCESS_DESCRIPTION_sk_type( sk : Pstack_st_ACCESS_DESCRIPTION):POPENSSL_STACK;
begin
 Exit(POPENSSL_STACK( sk));
end;


function ossl_check_ACCESS_DESCRIPTION_compfunc_type( cmp : sk_ACCESS_DESCRIPTION_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_ACCESS_DESCRIPTION_copyfunc_type( cpy : sk_ACCESS_DESCRIPTION_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_ACCESS_DESCRIPTION_freefunc_type( fr : sk_ACCESS_DESCRIPTION_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

function sk_ACCESS_DESCRIPTION_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_ACCESS_DESCRIPTION_sk_type(sk))
end;

function  sk_SXNETID_push(sk, ptr: Pointer):int;
begin
   Result := OPENSSL_sk_push(ossl_check_SXNETID_sk_type(sk), ossl_check_SXNETID_type(ptr))
end;

function sk_SXNETID_value(sk: Pointer; idx: int): PSXNETID;
begin
    Result := PSXNETID(OPENSSL_sk_value(ossl_check_const_SXNETID_sk_type(sk),idx))
end;



function ossl_check_SXNETID_type( ptr : PSXNETID):PSXNETID;
begin
 Exit(ptr);
end;


function ossl_check_const_SXNETID_sk_type(const sk : Pstack_st_SXNETID):POPENSSL_STACK;
begin
 Exit(POPENSSL_STACK( sk));
end;


function ossl_check_SXNETID_sk_type( sk : Pstack_st_SXNETID):POPENSSL_STACK;
begin
 Exit(POPENSSL_STACK( sk));
end;


function ossl_check_SXNETID_compfunc_type( cmp : sk_SXNETID_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_SXNETID_copyfunc_type( cpy : sk_SXNETID_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_SXNETID_freefunc_type( fr : sk_SXNETID_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

function sk_SXNETID_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_SXNETID_sk_type(sk))
end;

function sk_GENERAL_NAME_new_null: Pstack_st_GENERAL_NAME;
begin
   Result := Pstack_st_GENERAL_NAME(OPENSSL_sk_new_null)
end;

function ossl_check_POLICYINFO_freefunc_type( fr : sk_POLICYINFO_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

procedure sk_POLICYINFO_pop_free(sk: Pointer; freefunc: sk_POLICYINFO_freefunc) ;
begin
   OPENSSL_sk_pop_free(ossl_check_POLICYINFO_sk_type(sk),
                ossl_check_POLICYINFO_freefunc_type(freefunc))
end;

function ossl_check_POLICYINFO_sk_type( sk : Pstack_st_POLICYINFO):POPENSSL_STACK;
begin
 Exit(POPENSSL_STACK( sk));
end;



function ossl_check_POLICYINFO_type( ptr : PPOLICYINFO):PPOLICYINFO;
begin
 Exit(ptr);
end;



function sk_POLICYINFO_push(sk, ptr: Pointer):int;
begin
   Result := OPENSSL_sk_push(ossl_check_POLICYINFO_sk_type(sk), ossl_check_POLICYINFO_type(ptr))
end;


function ossl_check_POLICYQUALINFO_type( ptr : PPOLICYQUALINFO):PPOLICYQUALINFO;
begin
   Result := ptr;
end;

function ossl_check_POLICYQUALINFO_sk_type(sk: Pstack_st_POLICYQUALINFO):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK(sk);
end;

function sk_POLICYQUALINFO_push(sk, ptr: Pointer): int;
begin
   Result := OPENSSL_sk_push(ossl_check_POLICYQUALINFO_sk_type(sk),
                             ossl_check_POLICYQUALINFO_type(ptr))
end;

function ossl_check_POLICYQUALINFO_compfunc_type( cmp : sk_POLICYQUALINFO_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;

function sk_POLICYQUALINFO_new(cmp: sk_POLICYQUALINFO_compfunc): Pstack_st_POLICYQUALINFO;
begin
   Result := Pstack_st_POLICYQUALINFO(OPENSSL_sk_new(
              ossl_check_POLICYQUALINFO_compfunc_type(cmp)))
end;

function sk_POLICYQUALINFO_new_null: Pstack_st_POLICYQUALINFO;
begin
    Result := Pstack_st_POLICYQUALINFO(OPENSSL_sk_new_null)
end;



function ossl_check_POLICYINFO_compfunc_type( cmp : sk_POLICYINFO_compfunc):OPENSSL_sk_compfunc;
begin
 result := OPENSSL_sk_compfunc(cmp);
end;

function sk_POLICYINFO_new_reserve(cmp: sk_POLICYINFO_compfunc; n: int): Pstack_st_POLICYINFO;
begin
   RESULT := Pstack_st_POLICYINFO(OPENSSL_sk_new_reserve(
              ossl_check_POLICYINFO_compfunc_type(cmp), (n)))
end;

function sk_POLICYQUALINFO_value(sk: Pointer; idx: int): PPOLICYQUALINFO;
begin
   Result := PPOLICYQUALINFO(OPENSSL_sk_value(ossl_check_const_POLICYQUALINFO_sk_type(sk), (idx)))
end;

function ossl_check_const_POLICYQUALINFO_sk_type(const sk : Pstack_st_POLICYQUALINFO):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK( sk);
end;

function sk_POLICYQUALINFO_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_POLICYQUALINFO_sk_type(sk))
end;

function sk_POLICYINFO_value(sk: Pointer; idx: int): PPOLICYINFO;
begin
   Result := PPOLICYINFO(OPENSSL_sk_value(ossl_check_const_POLICYINFO_sk_type
                         (sk), idx))
end;




function ossl_check_const_POLICYINFO_sk_type(const sk: Pstack_st_POLICYINFO):POPENSSL_STACK;
begin
 result := POPENSSL_STACK( sk);
end;

function sk_POLICYINFO_num(sk: Pointer): int;
begin
   Result := OPENSSL_sk_num(ossl_check_const_POLICYINFO_sk_type(sk))
end;

function sk_GENERAL_NAME_new_reserve(cmp:sk_GENERAL_NAME_compfunc; n: int):Pstack_st_GENERAL_NAME;
begin
   Result := Pstack_st_GENERAL_NAME(OPENSSL_sk_new_reserve
                          (ossl_check_GENERAL_NAME_compfunc_type(cmp), n))
end;

(******************************IPAddressFamily*********************************)
function sk_IPAddressFamily_new(cmp:sk_IPAddressFamily_compfunc) : PSTACK_st_IPAddressFamily;
begin
   Result := PSTACK_st_IPAddressFamily(OPENSSL_sk_new(ossl_check_IPAddressFamily_compfunc_type(cmp)));
end;

function sk_IPAddressFamily_value(sk: Pointer; idx: integer): PIPAddressFamily;
begin
   Result := PIPAddressFamily (OPENSSL_sk_value(ossl_check_IPAddressFamily_sk_type(sk), idx));
end;

function sk_IPAddressFamily_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_IPAddressFamily_sk_type(sk));
end;


function sk_IPAddressFamily_reserve( sk : Pointer; n: integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_IPAddressFamily_sk_type(sk), n);
end;


function sk_IPAddressFamily_free( sk : Pointer):integer;
begin
OPENSSL_sk_free(ossl_check_IPAddressFamily_sk_type(sk))
end;


function sk_IPAddressFamily_zero( sk : Pointer):integer;
begin
OPENSSL_sk_zero(ossl_check_IPAddressFamily_sk_type(sk))
end;


function sk_IPAddressFamily_delete( sk : Pointer; i : integer): PIPAddressFamily;
begin
  Result := PIPAddressFamily (OPENSSL_sk_delete(ossl_check_IPAddressFamily_sk_type(sk), i));
end;


function sk_IPAddressFamily_delete_ptr( sk, ptr : Pointer):PIPAddressFamily;
begin
  Result := PIPAddressFamily (OPENSSL_sk_delete_ptr(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr)));
end;


function sk_IPAddressFamily_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr))
end;


function sk_IPAddressFamily_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr))
end;


function sk_IPAddressFamily_pop( sk : Pointer):PIPAddressFamily;
begin
   Result := PIPAddressFamily (OPENSSL_sk_pop(ossl_check_IPAddressFamily_sk_type(sk)));
end;


function sk_IPAddressFamily_shift( sk : Pointer):PIPAddressFamily;
begin
  Result := PIPAddressFamily (OPENSSL_sk_shift(ossl_check_IPAddressFamily_sk_type(sk)))
end;


procedure sk_IPAddressFamily_pop_free( sk : Pointer; freefunc : sk_IPAddressFamily_freefunc);
begin
  OPENSSL_sk_pop_free(ossl_check_IPAddressFamily_sk_type(sk),
             ossl_check_IPAddressFamily_freefunc_type(freefunc)) ;
end;


function sk_IPAddressFamily_insert( sk, ptr : Pointer; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr), (idx))
end;


function sk_IPAddressFamily_set( sk : Pointer; idx : integer; ptr : Pointer):PIPAddressFamily;
begin
  Result := PIPAddressFamily (OPENSSL_sk_set(ossl_check_IPAddressFamily_sk_type(sk), (idx), ossl_check_IPAddressFamily_type(ptr)))
end;


function sk_IPAddressFamily_find( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr))
end;


function sk_IPAddressFamily_find_ex( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find_ex(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr))
end;


function sk_IPAddressFamily_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_type(ptr), pnum);
end;


procedure sk_IPAddressFamily_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_IPAddressFamily_sk_type(sk));
end;


function sk_IPAddressFamily_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_IPAddressFamily_sk_type(sk));
end;


function sk_IPAddressFamily_dup( sk : Pointer):PSTACK_st_IPAddressFamily;
begin
   Result := PSTACK_st_IPAddressFamily(OPENSSL_sk_dup(ossl_check_IPAddressFamily_sk_type(sk)))
end;


function sk_IPAddressFamily_deep_copy( sk : Pointer; copyfunc : sk_IPAddressFamily_copyfunc; freefunc : sk_IPAddressFamily_freefunc):PSTACK_st_IPAddressFamily;
begin
   Result := PSTACK_st_IPAddressFamily(OPENSSL_sk_deep_copy(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_copyfunc_type(copyfunc), ossl_check_IPAddressFamily_freefunc_type(freefunc)))
end;


function sk_IPAddressFamily_set_cmp_func( sk : Pointer; cmp : sk_IPAddressFamily_compfunc):sk_IPAddressFamily_compfunc;
begin
   Result := sk_IPAddressFamily_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_IPAddressFamily_sk_type(sk), ossl_check_IPAddressFamily_compfunc_type(cmp)))
end;

function ossl_check_IPAddressFamily_type( ptr : PIPAddressFamily):PIPAddressFamily;
begin
   Result := ptr;
end;


function ossl_check_IPAddressFamily_sk_type( sk : PSTACK_st_IPAddressFamily):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_IPAddressFamily_compfunc_type( cmp : sk_IPAddressFamily_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_IPAddressFamily_copyfunc_type( cpy : sk_IPAddressFamily_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_IPAddressFamily_freefunc_type( fr : sk_IPAddressFamily_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

(*******************************IPAddressOrRange*******************************)
function sk_IPAddressOrRange_new_null(): PSTACK_st_IPAddressOrRange;
begin
   Result := PSTACK_st_IPAddressOrRange(OPENSSL_sk_new_null())
end;

function sk_IPAddressOrRange_value(sk: Pointer; idx: integer): PIPAddressOrRange;
begin
   Result := PIPAddressOrRange (OPENSSL_sk_value(ossl_check_IPAddressOrRange_sk_type(sk), idx));
end;

function sk_IPAddressOrRange_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_IPAddressOrRange_sk_type(sk));
end;


function sk_IPAddressOrRange_reserve( sk : Pointer; n: integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_IPAddressOrRange_sk_type(sk), n);
end;


function sk_IPAddressOrRange_free( sk : Pointer):integer;
begin
OPENSSL_sk_free(ossl_check_IPAddressOrRange_sk_type(sk))
end;


function sk_IPAddressOrRange_zero( sk : Pointer):integer;
begin
OPENSSL_sk_zero(ossl_check_IPAddressOrRange_sk_type(sk))
end;


function sk_IPAddressOrRange_delete( sk : Pointer; i : integer): PIPAddressOrRange;
begin
  Result := PIPAddressOrRange (OPENSSL_sk_delete(ossl_check_IPAddressOrRange_sk_type(sk), i));
end;


function sk_IPAddressOrRange_delete_ptr( sk, ptr : Pointer):PIPAddressOrRange;
begin
  Result := PIPAddressOrRange (OPENSSL_sk_delete_ptr(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr)));
end;


function sk_IPAddressOrRange_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr))
end;


function sk_IPAddressOrRange_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr))
end;


function sk_IPAddressOrRange_pop( sk : Pointer):PIPAddressOrRange;
begin
   Result := PIPAddressOrRange (OPENSSL_sk_pop(ossl_check_IPAddressOrRange_sk_type(sk)));
end;


function sk_IPAddressOrRange_shift( sk : Pointer):PIPAddressOrRange;
begin
  Result := PIPAddressOrRange (OPENSSL_sk_shift(ossl_check_IPAddressOrRange_sk_type(sk)))
end;


procedure sk_IPAddressOrRange_pop_free( sk : Pointer; freefunc : sk_IPAddressOrRange_freefunc);
begin
  OPENSSL_sk_pop_free(ossl_check_IPAddressOrRange_sk_type(sk),
             ossl_check_IPAddressOrRange_freefunc_type(freefunc)) ;
end;


function sk_IPAddressOrRange_insert( sk, ptr : Pointer; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr), (idx))
end;


function sk_IPAddressOrRange_set( sk : Pointer; idx : integer; ptr : Pointer):PIPAddressOrRange;
begin
  Result := PIPAddressOrRange (OPENSSL_sk_set(ossl_check_IPAddressOrRange_sk_type(sk), (idx), ossl_check_IPAddressOrRange_type(ptr)))
end;


function sk_IPAddressOrRange_find( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr))
end;


function sk_IPAddressOrRange_find_ex( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find_ex(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr))
end;


function sk_IPAddressOrRange_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_type(ptr), pnum);
end;


procedure sk_IPAddressOrRange_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_IPAddressOrRange_sk_type(sk));
end;


function sk_IPAddressOrRange_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_IPAddressOrRange_sk_type(sk));
end;


function sk_IPAddressOrRange_dup( sk : Pointer):PSTACK_st_IPAddressOrRange;
begin
   Result := PSTACK_st_IPAddressOrRange(OPENSSL_sk_dup(ossl_check_IPAddressOrRange_sk_type(sk)))
end;


function sk_IPAddressOrRange_deep_copy( sk : Pointer; copyfunc : sk_IPAddressOrRange_copyfunc; freefunc : sk_IPAddressOrRange_freefunc):PSTACK_st_IPAddressOrRange;
begin
   Result := PSTACK_st_IPAddressOrRange(OPENSSL_sk_deep_copy(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_copyfunc_type(copyfunc), ossl_check_IPAddressOrRange_freefunc_type(freefunc)))
end;


function sk_IPAddressOrRange_set_cmp_func( sk : Pointer; cmp : sk_IPAddressOrRange_compfunc):sk_IPAddressOrRange_compfunc;
begin
   Result := sk_IPAddressOrRange_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_IPAddressOrRange_sk_type(sk), ossl_check_IPAddressOrRange_compfunc_type(cmp)))
end;

function ossl_check_IPAddressOrRange_type( ptr : PIPAddressOrRange):PIPAddressOrRange;
begin
   Result := ptr;
end;


function ossl_check_IPAddressOrRange_sk_type( sk : PSTACK_st_IPAddressOrRange):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_IPAddressOrRange_compfunc_type( cmp : sk_IPAddressOrRange_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_IPAddressOrRange_copyfunc_type( cpy : sk_IPAddressOrRange_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_IPAddressOrRange_freefunc_type( fr : sk_IPAddressOrRange_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

function sk_GENERAL_NAME_value(sk: Pointer; idx: integer): PGENERAL_NAME;
begin
   Result := PGENERAL_NAME (OPENSSL_sk_value(ossl_check_GENERAL_NAME_sk_type(sk), idx));
end;

function sk_GENERAL_NAME_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_GENERAL_NAME_sk_type(sk));
end;


function sk_GENERAL_NAME_reserve( sk : Pointer; n: integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_GENERAL_NAME_sk_type(sk), n);
end;


function sk_GENERAL_NAME_free( sk : Pointer):integer;
begin
OPENSSL_sk_free(ossl_check_GENERAL_NAME_sk_type(sk))
end;


function sk_GENERAL_NAME_zero( sk : Pointer):integer;
begin
OPENSSL_sk_zero(ossl_check_GENERAL_NAME_sk_type(sk))
end;


function sk_GENERAL_NAME_delete( sk : Pointer; i : integer): PGENERAL_NAME;
begin
  Result := PGENERAL_NAME (OPENSSL_sk_delete(ossl_check_GENERAL_NAME_sk_type(sk), i));
end;


function sk_GENERAL_NAME_delete_ptr( sk, ptr : Pointer):PGENERAL_NAME;
begin
  Result := PGENERAL_NAME (OPENSSL_sk_delete_ptr(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr)));
end;


function sk_GENERAL_NAME_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr))
end;


function sk_GENERAL_NAME_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr))
end;


function sk_GENERAL_NAME_pop( sk : Pointer):PGENERAL_NAME;
begin
   Result := PGENERAL_NAME (OPENSSL_sk_pop(ossl_check_GENERAL_NAME_sk_type(sk)));
end;


function sk_GENERAL_NAME_shift( sk : Pointer):PGENERAL_NAME;
begin
  Result := PGENERAL_NAME (OPENSSL_sk_shift(ossl_check_GENERAL_NAME_sk_type(sk)))
end;


procedure sk_GENERAL_NAME_pop_free( sk : Pointer; freefunc : sk_GENERAL_NAME_freefunc);
begin
  OPENSSL_sk_pop_free(ossl_check_GENERAL_NAME_sk_type(sk),
             ossl_check_GENERAL_NAME_freefunc_type(freefunc)) ;
end;


function sk_GENERAL_NAME_insert( sk, ptr : Pointer; idx : integer):integer;
begin
   Result := OPENSSL_sk_insert(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr), (idx))
end;


function sk_GENERAL_NAME_set( sk : Pointer; idx : integer; ptr : Pointer):PGENERAL_NAME;
begin
  Result := PGENERAL_NAME (OPENSSL_sk_set(ossl_check_GENERAL_NAME_sk_type(sk), (idx), ossl_check_GENERAL_NAME_type(ptr)))
end;


function sk_GENERAL_NAME_find( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr))
end;


function sk_GENERAL_NAME_find_ex( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find_ex(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr))
end;


function sk_GENERAL_NAME_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
begin
   Result := OPENSSL_sk_find_all(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_type(ptr), pnum);
end;


procedure sk_GENERAL_NAME_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(ossl_check_GENERAL_NAME_sk_type(sk));
end;


function sk_GENERAL_NAME_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(ossl_check_GENERAL_NAME_sk_type(sk));
end;


function sk_GENERAL_NAME_dup( sk : Pointer):PSTACK_st_GENERAL_NAME;
begin
   Result := PSTACK_st_GENERAL_NAME(OPENSSL_sk_dup(ossl_check_GENERAL_NAME_sk_type(sk)))
end;


function sk_GENERAL_NAME_deep_copy( sk : Pointer; copyfunc : sk_GENERAL_NAME_copyfunc; freefunc : sk_GENERAL_NAME_freefunc):PSTACK_st_GENERAL_NAME;
begin
   Result := PSTACK_st_GENERAL_NAME(OPENSSL_sk_deep_copy(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_copyfunc_type(copyfunc), ossl_check_GENERAL_NAME_freefunc_type(freefunc)))
end;


function sk_GENERAL_NAME_set_cmp_func( sk : Pointer; cmp : sk_GENERAL_NAME_compfunc):sk_GENERAL_NAME_compfunc;
begin
   Result := sk_GENERAL_NAME_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_GENERAL_NAME_sk_type(sk), ossl_check_GENERAL_NAME_compfunc_type(cmp)))
end;

function ossl_check_GENERAL_NAME_type( ptr : PGENERAL_NAME):PGENERAL_NAME;
begin
   Result := ptr;
end;


function ossl_check_GENERAL_NAME_sk_type( sk : PSTACK_st_GENERAL_NAME):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_GENERAL_NAME_compfunc_type( cmp : sk_GENERAL_NAME_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_GENERAL_NAME_copyfunc_type( cpy : sk_GENERAL_NAME_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;


function ossl_check_GENERAL_NAME_freefunc_type( fr : sk_GENERAL_NAME_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;
(***************************GENERAL_NAME end***********************************)



function sk_DIST_POINT_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(ossl_check_const_DIST_POINT_sk_type(sk))
end;


function sk_DIST_POINT_value( sk : Pointer; idx : integer): PDIST_POINT;
begin
  Result := PDIST_POINT (OPENSSL_sk_value(ossl_check_const_DIST_POINT_sk_type(sk),
                                          (idx)));
end;


function sk_DIST_POINT_new(cmp: sk_DIST_POINT_compfunc): PSTACK_st_DIST_POINT;
begin
  Result := PSTACK_st_DIST_POINT (OPENSSL_sk_new(ossl_check_DIST_POINT_compfunc_type(cmp)))
end;


function sk_DIST_POINT_new_null: PSTACK_st_DIST_POINT;
begin
  Result := PSTACK_st_DIST_POINT (OPENSSL_sk_new_null());
end;


function sk_DIST_POINT_new_reserve(cmp : sk_DIST_POINT_compfunc;n: Integer): PSTACK_st_DIST_POINT;
begin
  Result :=PSTACK_st_DIST_POINT (OPENSSL_sk_new_reserve(ossl_check_DIST_POINT_compfunc_type(cmp), n));
end;


function sk_DIST_POINT_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(ossl_check_DIST_POINT_sk_type(sk), (n))
end;


procedure sk_DIST_POINT_free( sk : Pointer);
begin
  OPENSSL_sk_free(ossl_check_DIST_POINT_sk_type(sk))
end;


procedure sk_DIST_POINT_zero( sk : Pointer);
begin
  OPENSSL_sk_zero(ossl_check_DIST_POINT_sk_type(sk))
end;


function sk_DIST_POINT_delete(sk: Pointer; i : integer):PDIST_POINT;
begin
  Result := PDIST_POINT (OPENSSL_sk_delete(ossl_check_DIST_POINT_sk_type(sk), i));
end;


function sk_DIST_POINT_delete_ptr( sk : Pointer; ptr : pointer):PDIST_POINT;
begin
  Result := PDIST_POINT (OPENSSL_sk_delete_ptr(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr)));
end;


function sk_DIST_POINT_push( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_push(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr))
end;


function sk_DIST_POINT_unshift( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_unshift(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr))
end;


function sk_DIST_POINT_pop( sk : Pointer):PDIST_POINT;
begin
  Result := PDIST_POINT (OPENSSL_sk_pop(ossl_check_DIST_POINT_sk_type(sk)));
end;


function sk_DIST_POINT_shift( sk : Pointer):PDIST_POINT;
begin
  Result := PDIST_POINT (OPENSSL_sk_shift(ossl_check_DIST_POINT_sk_type(sk)));
end;


procedure sk_DIST_POINT_pop_free( sk : Pointer; freefunc : sk_DIST_POINT_freefunc);
begin
   OPENSSL_sk_pop_free(ossl_check_DIST_POINT_sk_type(sk),ossl_check_DIST_POINT_freefunc_type(freefunc))
end;


function sk_DIST_POINT_insert( sk, ptr : Pointer; idx : integer):integer;
begin
  Result := OPENSSL_sk_insert(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr), (idx))
end;


function sk_DIST_POINT_set( sk : Pointer; idx : integer; ptr : Pointer):PDIST_POINT;
begin
  Result := PDIST_POINT (OPENSSL_sk_set(ossl_check_DIST_POINT_sk_type(sk), idx,
                         ossl_check_DIST_POINT_type(ptr)));
end;


function sk_DIST_POINT_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr))
end;


function sk_DIST_POINT_find_ex( sk, ptr : Pointer):integer;
begin
  Result := OPENSSL_sk_find_ex(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr))
end;


function sk_DIST_POINT_find_all( sk, ptr : Pointer; pnum : Pinteger):integer;
begin
  OPENSSL_sk_find_all(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_type(ptr), pnum)
end;


function sk_DIST_POINT_sort( sk : Pointer):integer;
begin
OPENSSL_sk_sort(ossl_check_DIST_POINT_sk_type(sk))
end;


function sk_DIST_POINT_is_sorted( sk : Pointer):integer;
begin
OPENSSL_sk_is_sorted(ossl_check_const_DIST_POINT_sk_type(sk))
end;


function sk_DIST_POINT_dup( sk : Pointer): PSTACK_st_DIST_POINT;
begin
   Result := PSTACK_st_DIST_POINT (OPENSSL_sk_dup(ossl_check_const_DIST_POINT_sk_type(sk)));
end;


function sk_DIST_POINT_deep_copy(sk: Pointer; copyfunc : sk_DIST_POINT_copyfunc;
                                 freefunc : sk_DIST_POINT_freefunc):PSTACK_st_DIST_POINT;
begin
   Result := PSTACK_st_DIST_POINT (OPENSSL_sk_deep_copy(ossl_check_const_DIST_POINT_sk_type(sk),
                  ossl_check_DIST_POINT_copyfunc_type(copyfunc),
                  ossl_check_DIST_POINT_freefunc_type(freefunc)));
end;


function sk_DIST_POINT_set_cmp_func(sk: Pointer; cmp: sk_DIST_POINT_compfunc):sk_DIST_POINT_compfunc;
begin
   Result := sk_DIST_POINT_compfunc(OPENSSL_sk_set_cmp_func(ossl_check_DIST_POINT_sk_type(sk), ossl_check_DIST_POINT_compfunc_type(cmp)));
end;

function ossl_check_DIST_POINT_freefunc_type( fr : sk_DIST_POINT_freefunc):OPENSSL_sk_freefunc;
begin
   Result := OPENSSL_sk_freefunc(fr);
end;

function ossl_check_DIST_POINT_type( ptr : PDIST_POINT):PDIST_POINT;
begin
   Result := ptr;
end;


function ossl_check_const_DIST_POINT_sk_type(const sk : PSTACK_st_DIST_POINT):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_DIST_POINT_sk_type( sk : PSTACK_st_DIST_POINT):POPENSSL_STACK;
begin
   Result := POPENSSL_STACK (sk);
end;


function ossl_check_DIST_POINT_compfunc_type( cmp : sk_DIST_POINT_compfunc):OPENSSL_sk_compfunc;
begin
   Result := OPENSSL_sk_compfunc(cmp);
end;


function ossl_check_DIST_POINT_copyfunc_type( cpy : sk_DIST_POINT_copyfunc):OPENSSL_sk_copyfunc;
begin
   Result := OPENSSL_sk_copyfunc(cpy);
end;

end.
