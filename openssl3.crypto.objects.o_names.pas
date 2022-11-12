unit openssl3.crypto.objects.o_names;

interface
uses OpenSSL.Api;

type
  To_names_fn = procedure(const p1: POBJ_NAME; p2: Pointer);
  To_names_doall = procedure(p1: POBJ_NAME);
  sk_NAME_FUNCS_freefunc = procedure(a: PNAME_FUNCS);

function OBJ_NAME_get(const name : PUTF8Char; _type : integer):PUTF8Char;
function OBJ_NAME_init:integer;
function OBJ_NAME_remove(const name : PUTF8Char; _type : integer):integer;
function OBJ_NAME_add(const name : PUTF8Char; _type : integer;const data : Pointer):integer;
function o_names_init:integer;
function obj_name_hash(const a : Pointer):Cardinal;
function obj_name_cmp(const a, b : Pointer):integer;
function sk_NAME_FUNCS_num(const sk : Pstack_st_NAME_FUNCS):integer;
function sk_NAME_FUNCS_value(const sk : Pstack_st_NAME_FUNCS; idx : integer): PNAME_FUNCS;
function lh_OBJ_NAME_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC):Plhash_st_OBJ_NAME;
function lh_OBJ_NAME_retrieve(lh : Plhash_st_OBJ_NAME;const d : POBJ_NAME):POBJ_NAME;
function lh_OBJ_NAME_get_down_load( lh : Plhash_st_OBJ_NAME):Cardinal;
function lh_OBJ_NAME_delete(lh : Plhash_st_OBJ_NAME;const d : POBJ_NAME):POBJ_NAME;
function lh_OBJ_NAME_insert(lh: Plhash_st_OBJ_NAME; data : POBJ_NAME):POBJ_NAME;
function lh_OBJ_NAME_error( lh : Plhash_st_OBJ_NAME):integer;

procedure OBJ_NAME_do_all( _type : integer; fn: To_names_fn; arg : Pointer);
procedure OBJ_NAME_cleanup( _type : integer);
procedure do_all_fn(const name : POBJ_NAME; d : Pointer);
procedure o_names_init_ossl_;
procedure lh_OBJ_NAME_doall_OBJ_DOALL( lh : Plhash_st_OBJ_NAME; fn : To_names_fn; arg : POBJ_DOALL);
procedure lh_OBJ_NAME_set_down_load( lh : Plhash_st_OBJ_NAME; dl : Cardinal);
procedure lh_OBJ_NAME_doall( lh : Plhash_st_OBJ_NAME; doall: To_names_doall);
procedure lh_OBJ_NAME_free( lh : Plhash_st_OBJ_NAME);
procedure sk_NAME_FUNCS_pop_free(sk: Pstack_st_NAME_FUNC; freefunc : sk_NAME_FUNCS_freefunc);
procedure name_funcs_free( ptr : PNAME_FUNCS);
procedure names_lh_free_doall( onp : POBJ_NAME);

implementation

uses OpenSSL3.threads_none,          openssl3.crypto.lhash,
     openssl3.crypto.stack,          openssl3.crypto.mem;

var
  o_names_init_ossl_ret_: int = 0;
  init:                   CRYPTO_ONCE  = 0;
  names_lh:               Plhash_st_OBJ_NAME = nil;
  obj_lock:               PCRYPTO_RWLOCK  = nil;
  free_type:int ;
  name_funcs_stack: Pstack_st_NAME_FUNCS;


function lh_OBJ_NAME_error( lh : Plhash_st_OBJ_NAME):integer;
begin
    Result := OPENSSL_LH_error(POPENSSL_LHASH (lh));
end;



function lh_OBJ_NAME_insert(lh: Plhash_st_OBJ_NAME; data : POBJ_NAME):POBJ_NAME;
begin
   Result := OPENSSL_LH_insert(POPENSSL_LHASH (lh), data);
end;


function OBJ_NAME_add(const name : PUTF8Char; _type : integer;const data : Pointer):integer;
var
  onp, ret : POBJ_NAME;
  alias, ok : integer;
  label _unlock;
begin
    //if name ='sha1WithRSAEncryption' then
      // writeln('function OBJ_NAME_add trace...');
    ok := 0;
    if 0 >= OBJ_NAME_init() then Exit(0);
    alias := _type and OBJ_NAME_ALIAS;
    _type := _type and (not OBJ_NAME_ALIAS);
    onp := OPENSSL_malloc(sizeof( onp^));
    if onp = nil then Exit(0);
    onp.name := name;
    onp.alias := alias;
    onp.&type := _type;
    onp.data := data;
    if 0>=CRYPTO_THREAD_write_lock(obj_lock) then  begin
        OPENSSL_free(onp);
        Exit(0);
    end;
    ret := lh_OBJ_NAME_insert(names_lh, onp);
    if ret <> nil then
    begin
        { free things }
        if (name_funcs_stack <> nil)
             and  (sk_NAME_FUNCS_num(name_funcs_stack) > ret.&type) then
        begin
            {
             * XXX: I'm not sure I understand why the free function should
             * get three arguments... -- Richard Levitte
             }
            sk_NAME_FUNCS_value(name_funcs_stack,
                                ret.&type).free_func(ret.name, ret.&type,
                                                      ret.data);
        end;
        OPENSSL_free(ret);
    end
    else
    begin
        if lh_OBJ_NAME_error(names_lh) > 0 then
        begin
            { ERROR }
            OPENSSL_free(onp);
            goto _unlock;
        end;
    end;
    ok := 1;

_unlock:
    CRYPTO_THREAD_unlock(obj_lock);
    Result := ok;
end;

procedure name_funcs_free( ptr : PNAME_FUNCS);
begin
    OPENSSL_free(ptr);
end;



procedure sk_NAME_FUNCS_pop_free(sk: Pstack_st_NAME_FUNC; freefunc : sk_NAME_FUNCS_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK(sk), OPENSSL_sk_freefunc(freefunc));
end;



procedure lh_OBJ_NAME_free( lh : Plhash_st_OBJ_NAME);
begin
 OPENSSL_LH_free(POPENSSL_LHASH (lh));
end;



function lh_OBJ_NAME_delete(lh : Plhash_st_OBJ_NAME;const d : POBJ_NAME):POBJ_NAME;
begin
 Result := POBJ_NAME (OPENSSL_LH_delete(POPENSSL_LHASH (lh), d));
end;



function OBJ_NAME_remove(const name : PUTF8Char; _type : integer):integer;
var
  _on: TOBJ_NAME;
  ret : POBJ_NAME;
  ok : integer;
begin
    ok := 0;
    if 0>=OBJ_NAME_init then
       Exit(0);
    if 0>=CRYPTO_THREAD_write_lock(obj_lock) then
        Exit(0);
    _type := _type and not OBJ_NAME_ALIAS;
    _on.name := name;
    _on.&type := _type;
    ret := lh_OBJ_NAME_delete(names_lh, @_on);
    if ret <> nil then
    begin
        { free things }
        if (name_funcs_stack <> nil)
             and  (sk_NAME_FUNCS_num(name_funcs_stack) > ret.&type)  then
        begin
            {
             * XXX: I'm not sure I understand why the free function should
             * get three arguments... -- Richard Levitte
             }
            sk_NAME_FUNCS_value(name_funcs_stack,
                                ret.&type).free_func(ret.name, ret.&type,
                                                      ret.data);
        end;
        OPENSSL_free(ret);
        ok := 1;
    end;
    CRYPTO_THREAD_unlock(obj_lock);
    Result := ok;
end;




procedure names_lh_free_doall( onp : POBJ_NAME);
begin
    if onp = nil then exit;
    if (free_type < 0)  or  (free_type = onp.&type) then
        OBJ_NAME_remove(onp.name, onp.&type);
end;



procedure lh_OBJ_NAME_doall( lh : Plhash_st_OBJ_NAME; doall: To_names_doall);
begin
   OPENSSL_LH_doall(POPENSSL_LHASH (lh), TOPENSSL_LH_DOALL_FUNC(doall));
end;




procedure lh_OBJ_NAME_set_down_load( lh : Plhash_st_OBJ_NAME; dl : Cardinal);
begin
 OPENSSL_LH_set_down_load(POPENSSL_LHASH (lh), dl);
end;

function lh_OBJ_NAME_get_down_load( lh : Plhash_st_OBJ_NAME):Cardinal;
begin
 Exit(OPENSSL_LH_get_down_load(POPENSSL_LHASH (lh)));
end;



procedure OBJ_NAME_cleanup( _type : integer);
var
  down_load : Cardinal;
begin
    if names_lh = nil then exit;
    free_type := _type;
    down_load := lh_OBJ_NAME_get_down_load(names_lh);
    lh_OBJ_NAME_set_down_load(names_lh, 0);
    lh_OBJ_NAME_doall(names_lh, names_lh_free_doall);
    if _type < 0 then
    begin
        lh_OBJ_NAME_free(names_lh);
        sk_NAME_FUNCS_pop_free(name_funcs_stack, name_funcs_free);
        CRYPTO_THREAD_lock_free(obj_lock);
        names_lh := nil;
        name_funcs_stack := nil;
        obj_lock := nil;
    end
    else
        lh_OBJ_NAME_set_down_load(names_lh, down_load);
end;



procedure do_all_fn(const name : POBJ_NAME; d : Pointer);
begin
    if POBJ_NAME(name).&type = POBJ_DOALL(d).&type then
       POBJ_DOALL(d).fn(name, POBJ_DOALL(d).arg);
end;




procedure lh_OBJ_NAME_doall_OBJ_DOALL( lh : Plhash_st_OBJ_NAME; fn : To_names_fn; arg : POBJ_DOALL);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh), TOPENSSL_LH_DOALL_FUNCARG(fn), arg);
end;

procedure OBJ_NAME_do_all( _type : integer; fn: To_names_fn; arg : Pointer);
var
  d : TOBJ_DOALL;
begin
    d.&type := _type;
    d.fn := fn;
    d.arg := arg;
    lh_OBJ_NAME_doall_OBJ_DOALL(names_lh, do_all_fn, @d);
end;



function lh_OBJ_NAME_retrieve(lh : Plhash_st_OBJ_NAME;const d : POBJ_NAME):POBJ_NAME;
begin
   Exit(POBJ_NAME(OPENSSL_LH_retrieve(POPENSSL_LHASH(lh), d)));
end;


function obj_name_cmp(const a, b : Pointer):integer;
var
  ret : integer;
begin
    ret := POBJ_NAME(a).&type - POBJ_NAME(b).&type;
    if ret = 0 then
    begin
        if (name_funcs_stack <> nil) and
           (sk_NAME_FUNCS_num(name_funcs_stack) > POBJ_NAME(a).&type)  then
        begin
            ret := sk_NAME_FUNCS_value(name_funcs_stack,
                                      POBJ_NAME(a).&type).cmp_func(POBJ_NAME(a).name, POBJ_NAME(b).name);
        end
        else
            ret := strcasecmp(POBJ_NAME(a).name, POBJ_NAME(b).name);
    end;
    Result := ret;
end;


function sk_NAME_FUNCS_value(const sk : Pstack_st_NAME_FUNCS; idx : integer): PNAME_FUNCS;
begin
   Exit(PNAME_FUNCS(OPENSSL_sk_value(POPENSSL_STACK( sk), idx)));
end;

function sk_NAME_FUNCS_num(const sk : Pstack_st_NAME_FUNCS):integer;
begin
   Exit(OPENSSL_sk_num(POPENSSL_STACK( sk)));
end;



function obj_name_hash(const a : Pointer):Cardinal;
var
  ret : Cardinal;
begin
    if (name_funcs_stack <> nil)  and
       (sk_NAME_FUNCS_num(name_funcs_stack) > POBJ_NAME(a).&type) then
    begin
        ret := sk_NAME_FUNCS_value(name_funcs_stack,
                                POBJ_NAME(a).&type).hash_func(POBJ_NAME(a).name);
    end
    else
    begin
        ret := ossl_lh_strcasehash(POBJ_NAME(a).name);
    end;
    ret  := ret xor POBJ_NAME(a).&type;
    Result := ret;
end;


function lh_OBJ_NAME_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC): Plhash_st_OBJ_NAME;
begin
   Result := Plhash_st_OBJ_NAME(OPENSSL_LH_new(hfn, cfn));
end;

function o_names_init:integer;
begin
    names_lh := nil ;
    obj_lock := CRYPTO_THREAD_lock_new();
    if obj_lock <> nil   then
        names_lh := lh_OBJ_NAME_new(obj_name_hash, obj_name_cmp);
    if names_lh = nil  then
    begin
        CRYPTO_THREAD_lock_free(obj_lock);
        obj_lock := nil ;
    end;
    Result := Int( (names_lh <> nil)   and  (obj_lock <> nil) ) ;
end;


procedure o_names_init_ossl_;
begin
  o_names_init_ossl_ret_ := o_names_init();
end;

function OBJ_NAME_init:integer;
begin
    if CRYPTO_THREAD_run_once(@init, o_names_init_ossl_) >0 then
       Result := o_names_init_ossl_ret_
    else
       Result := 0;
end;

function OBJ_NAME_get(const name : PUTF8Char; _type : integer):PUTF8Char;
var
  _on: TOBJ_NAME;
  ret : POBJ_NAME;
  num, alias : integer;
  value : PUTF8Char;
begin
    num := 0;
    value := nil;
    if name = nil then Exit(nil);
    if 0>= OBJ_NAME_init()  then
        Exit(nil);
    if 0>= CRYPTO_THREAD_read_lock(obj_lock) then
        Exit(nil);
    alias := _type and OBJ_NAME_ALIAS;
    _type := _type and (not OBJ_NAME_ALIAS);
    _on.name := name;
    _on.&type := _type;
    while true do
    begin
        ret := lh_OBJ_NAME_retrieve(names_lh, @_on);
        if ret = nil then break;
        if (ret.alias>0)  and  (0>= alias) then
        begin
            if PreInc(num) > 10 then
                break;
            _on.name := ret.data;
        end
        else
        begin
            value := ret.data;
            break;
        end;
    end;
    CRYPTO_THREAD_unlock(obj_lock);
    Result := value;
end;


end.
