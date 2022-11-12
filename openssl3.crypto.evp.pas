unit openssl3.crypto.evp;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, openssl3.crypto.evp.evp_lib, openssl3.crypto.evp.p_lib,
     openssl3.crypto.evp.e_des3,               openssl3.crypto.evp.e_idea,
     openssl3.crypto.evp.e_seed,               openssl3.crypto.evp.e_sm4,
     openssl3.crypto.evp.e_rc2,                openssl3.crypto.evp.e_bf,
     openssl3.crypto.evp.e_aes,                openssl3.crypto.evp.e_cast,
     openssl3.crypto.evp.digest,               openssl3.crypto.evp.e_des;


type
  sk_EVP_PKEY_METHOD_compfunc = function (const  a, b: PEVP_PKEY_METHOD):integer;
  sk_EVP_PKEY_METHOD_freefunc = procedure(a: PEVP_PKEY_METHOD);
  sk_EVP_PKEY_METHOD_copyfunc = function(const a: PEVP_PKEY_METHOD): PEVP_PKEY_METHOD;

const
    EVP_PKEY_OP_ENCAPSULATE  = (1 shl 12);
    EVP_PKEY_OP_DECAPSULATE  = (1 shl 13);
    EVP_PKEY_OP_FROMDATA     = (1 shl 3);
    EVP_PKEY_FLAG_DYNAMIC    = 1;
    EVP_PKEY_KEYMGMT = -1;
    EVP_PKEY_STATE_UNKNOWN = 0;
    EVP_PKEY_STATE_LEGACY = 1;
    EVP_PKEY_STATE_PROVIDER = 2;
    EVP_ENCODE_CTX_NO_NEWLINES      = 1;
    EVP_ENCODE_CTX_USE_SRP_ALPHABET = 2;
    EVP_PKEY_KEY_PARAMETERS = ( OSSL_KEYMGMT_SELECT_ALL_PARAMETERS );
    EVP_PKEY_PUBLIC_KEY = ( EVP_PKEY_KEY_PARAMETERS or OSSL_KEYMGMT_SELECT_PUBLIC_KEY ) ;
    EVP_PKEY_KEYPAIR  =   ( EVP_PKEY_PUBLIC_KEY or OSSL_KEYMGMT_SELECT_PRIVATE_KEY );

    EVP_MD_name: function(const md : PEVP_MD):PUTF8Char = EVP_MD_get0_name;
    EVP_PKEY_base_id: function(const pkey : PEVP_PKEY):integer = EVP_PKEY_get_base_id;
    EVP_MD_CTX_create: function: PEVP_MD_CTX =  EVP_MD_CTX_new;
    EVP_MD_CTX_destroy: procedure(ctx: PEVP_MD_CTX) = EVP_MD_CTX_free;
    EVP_MD_block_size:function(const md: PEVP_MD): int = EVP_MD_get_block_size;
    EVP_MAXCHUNK = size_t(1 shl (sizeof(long)*8-2));
    EVP_des_cfb: function:PEVP_CIPHER = EVP_des_cfb64;
    EVP_des_ede_cfb:function:PEVP_CIPHER = EVP_des_ede_cfb64;
    EVP_des_ede3_cfb: function :PEVP_CIPHER = EVP_des_ede3_cfb64;
    EVP_idea_cfb: function :PEVP_CIPHER = EVP_idea_cfb64;
    EVP_seed_cfb: function :PEVP_CIPHER = EVP_seed_cfb128;
    EVP_sm4_cfb:  function :PEVP_CIPHER = EVP_sm4_cfb128;
    EVP_rc2_cfb:  function :PEVP_CIPHER = EVP_rc2_cfb64;
    EVP_bf_cfb:   function :PEVP_CIPHER = EVP_bf_cfb64;
    EVP_aes_128_cfb: function :PEVP_CIPHER = EVP_aes_128_cfb128;
    EVP_aes_192_cfb: function :PEVP_CIPHER = EVP_aes_192_cfb128;
    EVP_aes_256_cfb: function :PEVP_CIPHER = EVP_aes_256_cfb128;
    EVP_cast5_cfb: function: PEVP_CIPHER = EVP_cast5_cfb64;

function  evp_pkey_is_provided(const pk: PEVP_PKEY) :Boolean;
function evp_pkey_is_legacy(const pk: PEVP_PKEY) :Boolean;
function EVP_PKEY_CTX_IS_SIGNATURE_OP( ctx : PEVP_PKEY_CTX):Boolean;
function EVP_PKEY_CTX_IS_DERIVE_OP(ctx: PEVP_PKEY_CTX):Boolean;
function EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx: PEVP_PKEY_CTX):Boolean;
function EVP_PKEY_CTX_IS_KEM_OP(ctx: PEVP_PKEY_CTX):Boolean;
function EVP_PKEY_CTX_IS_GEN_OP(ctx: PEVP_PKEY_CTX):Boolean;
function EVP_PKEY_CTX_IS_FROMDATA_OP(ctx: PEVP_PKEY_CTX):Boolean;



function sk_EVP_PKEY_METHOD_num( sk : Pointer):integer;
  function sk_EVP_PKEY_METHOD_value( sk : Pointer;idx: integer):PEVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_new( cmp : sk_EVP_PKEY_METHOD_compfunc):PSTACK_st_EVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_new_null:PSTACK_st_EVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_new_reserve( cmp : sk_EVP_PKEY_METHOD_compfunc; n : integer):PSTACK_st_EVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_reserve( sk : Pointer; n : integer):integer;
  procedure sk_EVP_PKEY_METHOD_free( sk : Pointer);
  procedure sk_EVP_PKEY_METHOD_zero( sk : Pointer);
  function sk_EVP_PKEY_METHOD_delete( sk : Pointer; i : integer):PEVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_delete_ptr( sk, ptr : Pointer):PEVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_push( sk, ptr : Pointer):integer;
  function sk_EVP_PKEY_METHOD_unshift( sk, ptr : Pointer):integer;
  function sk_EVP_PKEY_METHOD_pop( sk : Pointer):PEVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_shift( sk : Pointer):PEVP_PKEY_METHOD;
  procedure sk_EVP_PKEY_METHOD_pop_free( sk : Pointer; freefunc : sk_EVP_PKEY_METHOD_freefunc);
  function sk_EVP_PKEY_METHOD_insert( sk, ptr : Pointer;idx: integer):integer;
  function sk_EVP_PKEY_METHOD_set( sk : Pointer; idx : integer; ptr : Pointer):PEVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_find( sk, ptr : Pointer):integer;
  function sk_EVP_PKEY_METHOD_find_ex( sk, ptr : Pointer):integer;
  function sk_EVP_PKEY_METHOD_find_all( sk, ptr : Pointer;pnum: PInteger):integer;
  procedure sk_EVP_PKEY_METHOD_sort( sk : Pointer);
  function sk_EVP_PKEY_METHOD_is_sorted( sk : Pointer):integer;
  function sk_EVP_PKEY_METHOD_dup( sk : Pointer):PSTACK_st_EVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_deep_copy( sk : Pointer; copyfunc : sk_EVP_PKEY_METHOD_copyfunc; freefunc : sk_EVP_PKEY_METHOD_freefunc):PSTACK_st_EVP_PKEY_METHOD;
  function sk_EVP_PKEY_METHOD_set_cmp_func( sk : Pointer; cmp : sk_EVP_PKEY_METHOD_compfunc):sk_EVP_PKEY_METHOD_compfunc;
  function EVP_get_cipherbynid(a: Integer) :PEVP_CIPHER;
  function EVP_get_digestbynid(a: Integer) :PEVP_MD;
  function evp_pkey_ctx_is_legacy(ctx: PEVP_PKEY_CTX): Boolean;
  function EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): Int;
  function EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): Int;
  function EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: PEC_KEY): int;
  function evp_pkey_ctx_is_provided(ctx: PEVP_PKEY_CTX): Boolean;
  function EVP_get_digestbyobj(a: Pointer): PEVP_MD;
  function evp_pkey_is_assigned(pk: PEVP_PKEY): Boolean;
  function evp_pkey_is_blank(pk: PEVP_PKEY): Boolean;
  function EVP_VerifyInit_ex(a : PEVP_MD_CTX;const b: PEVP_MD; c: PENGINE): int;
  function EVP_VerifyUpdate(a : PEVP_MD_CTX;const b: PByte; c: size_t): int;
  function EVP_SignInit_ex(a : PEVP_MD_CTX;const b: PEVP_MD; c: PENGINE): Int;
  function EVP_SignUpdate(a : PEVP_MD_CTX;const b: PByte; c: size_t): int;
  function EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): int;
  function EVP_CIPHER_CTX_get_mode(c: PEVP_CIPHER_CTX): Int;
  procedure EVP_add_cipher_alias(n,alias: PUTF8Char) ;
  procedure EVP_add_digest_alias(n,alias: PUTF8Char) ;

implementation

uses
   openssl3.crypto.stack,              openssl3.crypto.evp.names,
   openssl3.crypto.objects.obj_dat,    openssl3.crypto.objects.o_names;

procedure EVP_add_digest_alias(n,alias: PUTF8Char) ;
begin
   OBJ_NAME_add((alias),OBJ_NAME_TYPE_MD_METH or OBJ_NAME_ALIAS,(n))
end;

procedure EVP_add_cipher_alias(n,alias: PUTF8Char) ;
begin
    OBJ_NAME_add(alias, OBJ_NAME_TYPE_CIPHER_METH or OBJ_NAME_ALIAS, n)
end;

function EVP_CIPHER_CTX_get_mode(c: PEVP_CIPHER_CTX): Int;
begin
   Result := EVP_CIPHER_get_mode(EVP_CIPHER_CTX_get0_cipher(c));
end;

function EVP_PKEY_assign_RSA(pkey: PEVP_PKEY; rsa: Pointer): int;
begin
   Result := EVP_PKEY_assign(pkey,EVP_PKEY_RSA, rsa)
end;

function EVP_SignUpdate(a : PEVP_MD_CTX;const b: PByte; c: size_t): int;
begin
   Result := EVP_DigestUpdate(a,b,c);
end;

function EVP_SignInit_ex(a : PEVP_MD_CTX;const b: PEVP_MD; c: PENGINE): Int;
begin
    Result := EVP_DigestInit_ex(a,b,c);
end;

function EVP_VerifyUpdate(a : PEVP_MD_CTX;const b: PByte; c: size_t): int;
begin
   Result := EVP_DigestUpdate(a,b,c)
end;

function EVP_VerifyInit_ex(a : PEVP_MD_CTX;const b: PEVP_MD; c: PENGINE): int;
begin
  Result := EVP_DigestInit_ex(a,b,c)
end;

{$ifndef OPENSSL_NO_DSA}
function  EVP_PKEY_assign_DSA(pkey: PEVP_PKEY; dsa: Pointer): int;
begin
  Result := EVP_PKEY_assign(pkey,EVP_PKEY_DSA, (dsa))
end;
{$ENDIF}

function evp_pkey_is_blank(pk: PEVP_PKEY): Boolean;
begin
    Result := (pk.&type = EVP_PKEY_NONE) and (pk.keymgmt = nil)
end;

{$ifndef FIPS_MODULE}
function evp_pkey_is_assigned(pk: PEVP_PKEY): Boolean;
begin
   Result := (pk.pkey.ptr <> nil) or (pk.keydata <> nil)
end;
{$ENDIF}

function EVP_get_digestbyobj(a: Pointer): PEVP_MD;
begin
   Result := EVP_get_digestbynid(OBJ_obj2nid(a))
end;

{
# define EVP_get_cipherbynid(a) EVP_get_cipherbyname(OBJ_nid2sn(a))
# define EVP_get_cipherbyobj(a) EVP_get_cipherbynid(OBJ_obj2nid(a))
}

function evp_pkey_ctx_is_provided(ctx: PEVP_PKEY_CTX): Boolean;
begin
    Result := (not evp_pkey_ctx_is_legacy(ctx))
end;

function EVP_PKEY_assign_EC_KEY(pkey: PEVP_PKEY; eckey: PEC_KEY): int;
begin
    Result := EVP_PKEY_assign(pkey, EVP_PKEY_EC, eckey)
end;

{$if not defined(OPENSSL_NO_DH) and not defined(OPENSSL_NO_DEPRECATED_3_0)}
function EVP_PKEY_assign_DH(pkey: PEVP_PKEY; dh: Pointer): Int;
begin
   Result := EVP_PKEY_assign(pkey,EVP_PKEY_DH, dh)
end;
{$endif}

function evp_pkey_ctx_is_legacy(ctx: PEVP_PKEY_CTX): Boolean;
begin
    Result := ctx.keymgmt = nil;
end;


function EVP_get_cipherbynid(a: Integer) :PEVP_CIPHER;
begin
  Result := EVP_get_cipherbyname(OBJ_nid2sn(a))
end;

function  EVP_get_digestbynid(a: Integer) :PEVP_MD;
begin
  Result := EVP_get_digestbyname(OBJ_nid2sn(a))
end;

(******************************EVP_PKEY_METHOD*********************************)
function sk_EVP_PKEY_METHOD_num( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK(sk))
end;


function sk_EVP_PKEY_METHOD_value( sk : Pointer; idx: integer):PEVP_PKEY_METHOD;
begin
   Result := PEVP_PKEY_METHOD(OPENSSL_sk_value(POPENSSL_STACK(sk), (idx)))
end;


function sk_EVP_PKEY_METHOD_new( cmp : sk_EVP_PKEY_METHOD_compfunc):PSTACK_st_EVP_PKEY_METHOD;
begin
   Result := PSTACK_st_EVP_PKEY_METHOD (OPENSSL_sk_new(OPENSSL_sk_compfunc(cmp)))
end;


function sk_EVP_PKEY_METHOD_new_null:PSTACK_st_EVP_PKEY_METHOD;
begin
   Result := PSTACK_st_EVP_PKEY_METHOD (OPENSSL_sk_new_null())
end;


function sk_EVP_PKEY_METHOD_new_reserve( cmp : sk_EVP_PKEY_METHOD_compfunc; n : integer):PSTACK_st_EVP_PKEY_METHOD;
begin
   Result := PSTACK_st_EVP_PKEY_METHOD (OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(cmp), (n)))
end;


function sk_EVP_PKEY_METHOD_reserve( sk : Pointer; n : integer):integer;
begin
   Result := OPENSSL_sk_reserve(POPENSSL_STACK(sk), (n))
end;


procedure sk_EVP_PKEY_METHOD_free( sk : Pointer);
begin
   OPENSSL_sk_free(POPENSSL_STACK(sk))
end;


procedure sk_EVP_PKEY_METHOD_zero( sk : Pointer);
begin
   OPENSSL_sk_zero(POPENSSL_STACK(sk))
end;


function sk_EVP_PKEY_METHOD_delete( sk : Pointer; i : integer):PEVP_PKEY_METHOD;
begin
   Result := PEVP_PKEY_METHOD(OPENSSL_sk_delete(POPENSSL_STACK(sk), (i)))
end;


function sk_EVP_PKEY_METHOD_delete_ptr( sk, ptr : Pointer):PEVP_PKEY_METHOD;
begin
   Result := PEVP_PKEY_METHOD(OPENSSL_sk_delete_ptr(POPENSSL_STACK(sk), (ptr)))
end;


function sk_EVP_PKEY_METHOD_push( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK(sk), (ptr))
end;


function sk_EVP_PKEY_METHOD_unshift( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_unshift(POPENSSL_STACK(sk), (ptr))
end;


function sk_EVP_PKEY_METHOD_pop( sk : Pointer):PEVP_PKEY_METHOD;
begin
   Result := PEVP_PKEY_METHOD(OPENSSL_sk_pop(POPENSSL_STACK(sk)))
end;


function sk_EVP_PKEY_METHOD_shift( sk : Pointer):PEVP_PKEY_METHOD;
begin
   Result := PEVP_PKEY_METHOD(OPENSSL_sk_shift(POPENSSL_STACK(sk)))
end;


procedure sk_EVP_PKEY_METHOD_pop_free( sk : Pointer; freefunc : sk_EVP_PKEY_METHOD_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK(sk),OPENSSL_sk_freefunc(freefunc))
end;


function sk_EVP_PKEY_METHOD_insert( sk, ptr : Pointer;idx: integer):integer;
begin
   Result := OPENSSL_sk_insert(POPENSSL_STACK(sk), (ptr), (idx))
end;


function sk_EVP_PKEY_METHOD_set( sk : Pointer; idx : integer; ptr : Pointer):PEVP_PKEY_METHOD;
begin
   Result := PEVP_PKEY_METHOD(OPENSSL_sk_set(POPENSSL_STACK(sk), (idx), (ptr)))
end;


function sk_EVP_PKEY_METHOD_find( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find(POPENSSL_STACK(sk), (ptr))
end;


function sk_EVP_PKEY_METHOD_find_ex( sk, ptr : Pointer):integer;
begin
   Result := OPENSSL_sk_find_ex(POPENSSL_STACK(sk), (ptr))
end;


function sk_EVP_PKEY_METHOD_find_all( sk, ptr : Pointer; pnum: PInteger):integer;
begin
   Result := OPENSSL_sk_find_all(POPENSSL_STACK(sk), (ptr), pnum)
end;


procedure sk_EVP_PKEY_METHOD_sort( sk : Pointer);
begin
   OPENSSL_sk_sort(POPENSSL_STACK(sk))
end;


function sk_EVP_PKEY_METHOD_is_sorted( sk : Pointer):integer;
begin
   Result := OPENSSL_sk_is_sorted(POPENSSL_STACK(sk))
end;


function sk_EVP_PKEY_METHOD_dup( sk : Pointer):PSTACK_st_EVP_PKEY_METHOD;
begin
   Result := PSTACK_st_EVP_PKEY_METHOD (OPENSSL_sk_dup(POPENSSL_STACK(sk)))
end;


function sk_EVP_PKEY_METHOD_deep_copy( sk : Pointer; copyfunc : sk_EVP_PKEY_METHOD_copyfunc; freefunc : sk_EVP_PKEY_METHOD_freefunc):PSTACK_st_EVP_PKEY_METHOD;
begin
   Result := PSTACK_st_EVP_PKEY_METHOD (OPENSSL_sk_deep_copy(POPENSSL_STACK(sk), OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc)))
end;


function sk_EVP_PKEY_METHOD_set_cmp_func( sk : Pointer; cmp : sk_EVP_PKEY_METHOD_compfunc):sk_EVP_PKEY_METHOD_compfunc;
begin
   Result := sk_EVP_PKEY_METHOD_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK(sk), OPENSSL_sk_compfunc(cmp)))
end;

function EVP_PKEY_CTX_IS_FROMDATA_OP(ctx: PEVP_PKEY_CTX):Boolean;
begin
   Result := (ctx.operation = EVP_PKEY_OP_FROMDATA)
end;

function EVP_PKEY_CTX_IS_GEN_OP(ctx: PEVP_PKEY_CTX):Boolean;
begin
   Result :=  (ctx.operation = EVP_PKEY_OP_PARAMGEN ) or
               (ctx.operation = EVP_PKEY_OP_KEYGEN);
end;

function EVP_PKEY_CTX_IS_KEM_OP(ctx: PEVP_PKEY_CTX):Boolean;
begin
   Result :=  (ctx.operation = EVP_PKEY_OP_ENCAPSULATE ) or
              (ctx.operation = EVP_PKEY_OP_DECAPSULATE)
end;

function EVP_PKEY_CTX_IS_ASYM_CIPHER_OP(ctx: PEVP_PKEY_CTX):Boolean;
begin
   Result := (ctx.operation = EVP_PKEY_OP_ENCRYPT ) or
               (ctx.operation = EVP_PKEY_OP_DECRYPT)
end;

function EVP_PKEY_CTX_IS_DERIVE_OP(ctx: PEVP_PKEY_CTX):Boolean;
begin
   Result := (ctx.operation = EVP_PKEY_OP_DERIVE)
end;

function EVP_PKEY_CTX_IS_SIGNATURE_OP( ctx : PEVP_PKEY_CTX):Boolean;
begin
    result := (ctx.operation = EVP_PKEY_OP_SIGN)  or
              (ctx.operation = EVP_PKEY_OP_SIGNCTX)  or
              (ctx.operation = EVP_PKEY_OP_VERIFY)  or
              (ctx.operation = EVP_PKEY_OP_VERIFYCTX)  or
              (ctx.operation = EVP_PKEY_OP_VERIFYRECOVER);
end;


function  evp_pkey_is_provided(const pk: PEVP_PKEY) :Boolean;
begin
    Result := (pk.keymgmt <> nil);
end;

function evp_pkey_is_legacy(const pk: PEVP_PKEY) :Boolean;
begin
   Result := (pk.&type <> EVP_PKEY_NONE) and (pk.keymgmt =nil);
end;

end.
