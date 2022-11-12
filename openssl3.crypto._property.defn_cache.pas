unit openssl3.crypto._property.defn_cache;

interface
uses OpenSSL.Api;

type
  Thfn = function(const a: Pointer ): Ulong;
  Tcfn = function(const a, b: Pointer ): int;
  Tdoall_func = procedure(p1: Pointer);
  Tdoallarg_func = procedure(p1: PPROPERTY_DEFN_ELEM; p2: Pointer);

function lh_PROPERTY_DEFN_ELEM_new(hfn: Thfn; cfn: Tcfn ): Plhash_st_PROPERTY_DEFN_ELEM;
function lh_PROPERTY_DEFN_ELEM_insert( lh : Plhash_st_PROPERTY_DEFN_ELEM; d : PPROPERTY_DEFN_ELEM):PPROPERTY_DEFN_ELEM;
function lh_PROPERTY_DEFN_ELEM_delete(lh : Plhash_st_PROPERTY_DEFN_ELEM;const d : PPROPERTY_DEFN_ELEM):PPROPERTY_DEFN_ELEM;
function lh_PROPERTY_DEFN_ELEM_retrieve(lh : Plhash_st_PROPERTY_DEFN_ELEM;const d : PPROPERTY_DEFN_ELEM):PPROPERTY_DEFN_ELEM;
function lh_PROPERTY_DEFN_ELEM_error( lh : Plhash_st_PROPERTY_DEFN_ELEM):integer;
function lh_PROPERTY_DEFN_ELEM_num_items( lh : Plhash_st_PROPERTY_DEFN_ELEM):uint64;
function ossl_prop_defn_set(ctx : POSSL_LIB_CTX;const prop : PUTF8Char; pl : POSSL_PROPERTY_LIST):integer;
function ossl_prop_defn_get(ctx : POSSL_LIB_CTX;const prop : PUTF8Char):POSSL_PROPERTY_LIST;
function property_defns_new( ctx : POSSL_LIB_CTX):Pointer;
function lh_PROPERTY_DEFN_ELEM_get_down_load( lh : Plhash_st_PROPERTY_DEFN_ELEM):uint64;
function property_defn_hash(const a : PPROPERTY_DEFN_ELEM):Cardinal;
function property_defn_cmp(const a, b : PPROPERTY_DEFN_ELEM):integer;
function ossl_lib_ctx_unlock( ctx : POSSL_LIB_CTX):integer;

procedure lh_PROPERTY_DEFN_ELEM_free( lh : Plhash_st_PROPERTY_DEFN_ELEM);
procedure lh_PROPERTY_DEFN_ELEM_flush( lh : Plhash_st_PROPERTY_DEFN_ELEM);
procedure lh_PROPERTY_DEFN_ELEM_node_stats_bio(const lh : Plhash_st_PROPERTY_DEFN_ELEM; _out : PBIO);
procedure lh_PROPERTY_DEFN_ELEM_node_usage_stats_bio(const lh : Plhash_st_PROPERTY_DEFN_ELEM; _out : PBIO);
procedure lh_PROPERTY_DEFN_ELEM_stats_bio(const lh : Plhash_st_PROPERTY_DEFN_ELEM; _out : PBIO);
procedure lh_PROPERTY_DEFN_ELEM_set_down_load( lh : Plhash_st_PROPERTY_DEFN_ELEM; dl : uint64);
procedure lh_PROPERTY_DEFN_ELEM_doall( lh : Plhash_st_PROPERTY_DEFN_ELEM; doall : Tdoall_func);
procedure lh_PROPERTY_DEFN_ELEM_doall_arg( lh : Plhash_st_PROPERTY_DEFN_ELEM; doallarg : Tdoallarg_func; arg : Pointer);
procedure property_defns_free( vproperty_defns : Pointer);
procedure property_defn_free( elem : PPROPERTY_DEFN_ELEM);


const
    property_defns_method: TOSSL_LIB_CTX_METHOD  = (
        priority :OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY;
        new_func: property_defns_new;
        free_func:property_defns_free
    );

implementation

uses   openssl3.crypto.context,          openssl3.crypto.lhash,
       openssl3.crypto.property_parse,   openssl3.crypto.mem,
       OpenSSL3.threads_none,            openssl3.crypto.lh_stats;

function ossl_prop_defn_set(ctx : POSSL_LIB_CTX;const prop : PUTF8Char; pl : POSSL_PROPERTY_LIST):integer;
var
    elem           : TPROPERTY_DEFN_ELEM;
    p,old          : PPROPERTY_DEFN_ELEM;
    len            : size_t;
    property_defns : Plhash_st_PROPERTY_DEFN_ELEM;
    res            : integer;
    label _end;
begin
    p := nil;
    res := 1;
    property_defns := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_PROPERTY_DEFN_INDEX,
                                           @property_defns_method);
    if property_defns = nil then Exit(0);
    if prop = nil then Exit(1);
    if  0>= ossl_lib_ctx_write_lock(ctx ) then
        Exit(0);
    if pl = nil then
    begin
        elem.prop := prop;
        lh_PROPERTY_DEFN_ELEM_delete(property_defns, @elem);
        goto _end;
    end;
    len := StrSize(prop);
    p := OPENSSL_malloc(sizeof( p^));
   
    if p <> nil then
    begin
        p.prop := @p.body[0];
        p.defn := pl;
        memcpy(@p.body[0], prop, len);
        old := lh_PROPERTY_DEFN_ELEM_insert(property_defns, p);
        if old <> nil then
        begin
            property_defn_free(old);
            goto _end;
        end;
        if  0>= lh_PROPERTY_DEFN_ELEM_error(property_defns) then
           goto _end;
    end;
  
    OPENSSL_free(p);
    res := 0;

 _end:
    ossl_lib_ctx_unlock(ctx);
    Result := res;
end;

function ossl_lib_ctx_unlock( ctx : POSSL_LIB_CTX):integer;
begin
    Result := CRYPTO_THREAD_unlock(ossl_lib_ctx_get_concrete(ctx).lock);
end;

function property_defn_cmp(const a, b : PPROPERTY_DEFN_ELEM):integer;
begin
    Result := strcmp(a.prop, b.prop);
end;

function property_defn_hash(const a : PPROPERTY_DEFN_ELEM):Cardinal;
begin
    Result := OPENSSL_LH_strhash(a.prop);
end;

procedure property_defn_free( elem : PPROPERTY_DEFN_ELEM);
begin
    ossl_property_free(elem.defn);
    OPENSSL_free(elem);
end;

function lh_PROPERTY_DEFN_ELEM_new(hfn: Thfn; cfn: Tcfn ): Plhash_st_PROPERTY_DEFN_ELEM;
begin
   Result := Plhash_st_PROPERTY_DEFN_ELEM (
            OPENSSL_LH_new(TOPENSSL_LH_HASHFUNC(hfn), TOPENSSL_LH_COMPFUNC(cfn)));
end;

procedure lh_PROPERTY_DEFN_ELEM_free( lh : Plhash_st_PROPERTY_DEFN_ELEM);
begin
   OPENSSL_LH_free(POPENSSL_LHASH(lh));
end;


procedure lh_PROPERTY_DEFN_ELEM_flush( lh : Plhash_st_PROPERTY_DEFN_ELEM);
begin
   OPENSSL_LH_flush(POPENSSL_LHASH(lh));
end;


function lh_PROPERTY_DEFN_ELEM_insert( lh : Plhash_st_PROPERTY_DEFN_ELEM; d : PPROPERTY_DEFN_ELEM):PPROPERTY_DEFN_ELEM;
begin
   Result := PPROPERTY_DEFN_ELEM (OPENSSL_LH_insert(POPENSSL_LHASH(lh), d));
end;


function lh_PROPERTY_DEFN_ELEM_delete(lh : Plhash_st_PROPERTY_DEFN_ELEM;const d : PPROPERTY_DEFN_ELEM):PPROPERTY_DEFN_ELEM;
begin
   Result := PPROPERTY_DEFN_ELEM (OPENSSL_LH_delete(POPENSSL_LHASH(lh), d));
end;


function lh_PROPERTY_DEFN_ELEM_retrieve(lh : Plhash_st_PROPERTY_DEFN_ELEM;const d : PPROPERTY_DEFN_ELEM):PPROPERTY_DEFN_ELEM;
begin
   Result := PPROPERTY_DEFN_ELEM (OPENSSL_LH_retrieve(POPENSSL_LHASH(lh), d));
end;


function lh_PROPERTY_DEFN_ELEM_error( lh : Plhash_st_PROPERTY_DEFN_ELEM):integer;
begin
   Result := OPENSSL_LH_error(POPENSSL_LHASH(lh));
end;


function lh_PROPERTY_DEFN_ELEM_num_items( lh : Plhash_st_PROPERTY_DEFN_ELEM):uint64;
begin
   Result := OPENSSL_LH_num_items(POPENSSL_LHASH(lh));
end;


procedure lh_PROPERTY_DEFN_ELEM_node_stats_bio(const lh : Plhash_st_PROPERTY_DEFN_ELEM; _out : PBIO);
begin
   OPENSSL_LH_node_stats_bio(POPENSSL_LHASH (lh), _out);
end;


procedure lh_PROPERTY_DEFN_ELEM_node_usage_stats_bio(const lh : Plhash_st_PROPERTY_DEFN_ELEM; _out : PBIO);
begin
   OPENSSL_LH_node_usage_stats_bio(POPENSSL_LHASH (lh), _out);
end;


procedure lh_PROPERTY_DEFN_ELEM_stats_bio(const lh : Plhash_st_PROPERTY_DEFN_ELEM; _out : PBIO);
begin
   OPENSSL_LH_stats_bio(POPENSSL_LHASH (lh), _out);
end;


function lh_PROPERTY_DEFN_ELEM_get_down_load( lh : Plhash_st_PROPERTY_DEFN_ELEM):uint64;
begin
   Result := OPENSSL_LH_get_down_load(POPENSSL_LHASH(lh));
end;


procedure lh_PROPERTY_DEFN_ELEM_set_down_load( lh : Plhash_st_PROPERTY_DEFN_ELEM; dl : uint64);
begin
   OPENSSL_LH_set_down_load(POPENSSL_LHASH(lh), dl);
end;


procedure lh_PROPERTY_DEFN_ELEM_doall( lh : Plhash_st_PROPERTY_DEFN_ELEM; doall : Tdoall_func);
begin
   OPENSSL_LH_doall(POPENSSL_LHASH(lh), TOPENSSL_LH_DOALL_FUNC(doall));
end;


procedure lh_PROPERTY_DEFN_ELEM_doall_arg( lh : Plhash_st_PROPERTY_DEFN_ELEM; doallarg : Tdoallarg_func; arg : Pointer);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh),
                             TOPENSSL_LH_DOALL_FUNCARG(doallarg), arg);
end;


procedure property_defns_free( vproperty_defns : Pointer);
var
  property_defns : Plhash_st_PROPERTY_DEFN_ELEM;
begin
    property_defns := vproperty_defns;
    if property_defns <> nil then
    begin
        lh_PROPERTY_DEFN_ELEM_doall(property_defns,
                                    @property_defn_free);
        lh_PROPERTY_DEFN_ELEM_free(property_defns);
    end;
end;

function property_defns_new( ctx : POSSL_LIB_CTX):Pointer;
begin
    Result := lh_PROPERTY_DEFN_ELEM_new(@property_defn_hash, @property_defn_cmp);
end;

function ossl_prop_defn_get(ctx : POSSL_LIB_CTX;const prop : PUTF8Char):POSSL_PROPERTY_LIST;
var
  elem           : TPROPERTY_DEFN_ELEM;
  r              : PPROPERTY_DEFN_ELEM;
  property_defns : Plhash_st_PROPERTY_DEFN_ELEM;
begin
    property_defns := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_PROPERTY_DEFN_INDEX,
                                           @property_defns_method);
    if( property_defns = nil)  or   (0>= ossl_lib_ctx_read_lock(ctx) ) then
        Exit(nil);
    elem.prop := prop;
    r := lh_PROPERTY_DEFN_ELEM_retrieve(property_defns, @elem);
    ossl_lib_ctx_unlock(ctx);
    if r <> nil then
       Result := r.defn
    else
       Result := nil;
end;

end.
