unit openssl3.crypto.property_string;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, openssl3.crypto.lhash;

type
  find_str_st = record
    str: PUTF8Char;
    idx: OSSL_PROPERTY_IDX ;
  end;
//property_string.c
//DEFINE_LHASH_OF(PROPERTY_STRING);
function ossl_property_name(ctx : POSSL_LIB_CTX;const s : PUTF8Char; create : integer):OSSL_PROPERTY_IDX;
function property_string_data_new( ctx : POSSL_LIB_CTX):Pointer;
procedure property_string_data_free( vpropdata : Pointer);
procedure property_table_free( pt : PPPROP_TABLE);
procedure property_free( ps : Pointer);
function property_hash(const a : Pointer):uint32;
function property_cmp(const a, b : Pointer):integer;
function new_property_string(const s : PUTF8Char; pidx : POSSL_PROPERTY_IDX):PPROPERTY_STRING;
function ossl_property_value(ctx : POSSL_LIB_CTX;const s : PUTF8Char; create : integer):OSSL_PROPERTY_IDX;
function ossl_property_string(ctx : POSSL_LIB_CTX; name, create : integer;const s : PUTF8Char):OSSL_PROPERTY_IDX;
function ossl_property_name_str( ctx : POSSL_LIB_CTX; idx : OSSL_PROPERTY_IDX):PUTF8Char;
function ossl_property_str( name : integer; ctx : POSSL_LIB_CTX; idx : OSSL_PROPERTY_IDX):PUTF8Char;
function ossl_property_value_str( ctx : POSSL_LIB_CTX; idx : OSSL_PROPERTY_IDX):PUTF8Char;

function lh_PROPERTY_STRING_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC): Plhash_st_PROPERTY_STRING;
procedure lh_PROPERTY_STRING_free( lh : Plhash_st_PROPERTY_STRING);
procedure lh_PROPERTY_STRING_flush( lh : Plhash_st_PROPERTY_STRING);
function lh_PROPERTY_STRING_insert( lh : Plhash_st_PROPERTY_STRING;const d : PPROPERTY_STRING):PPROPERTY_STRING;
function lh_PROPERTY_STRING_delete(lh :  Plhash_st_PROPERTY_STRING;const d : PPROPERTY_STRING):PPROPERTY_STRING;
function lh_PROPERTY_STRING_retrieve(lh : Plhash_st_PROPERTY_STRING;const d : PPROPERTY_STRING):PPROPERTY_STRING;
function lh_PROPERTY_STRING_error( lh : Plhash_st_PROPERTY_STRING):integer;
procedure lh_PROPERTY_STRING_node_stats_bio(const lh : Plhash_st_PROPERTY_STRING;&out : PBIO);
procedure lh_PROPERTY_STRING_node_usage_stats_bio(const lh : Plhash_st_PROPERTY_STRING; &out : PBIO);
procedure lh_PROPERTY_STRING_stats_bio(const lh : Plhash_st_PROPERTY_STRING; &out : PBIO);
procedure lh_PROPERTY_STRING_set_down_load( lh : Plhash_st_PROPERTY_STRING; dl : uint32);
procedure lh_PROPERTY_STRING_doall( lh : Plhash_st_PROPERTY_STRING; doall: Tdoall_func);
procedure lh_PROPERTY_STRING_doall_arg(lh : Plhash_st_PROPERTY_STRING; doallarg: Tdoallarg_func;  arg: Pointer);

var
   property_string_data_method: TOSSL_LIB_CTX_METHOD = (
    priority :OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY;
    new_func :property_string_data_new;
    free_func: property_string_data_free;
   );
implementation

uses OpenSSL3.Err,                openssl3.crypto.context,
     openssl3.crypto.mem,         openssl3.crypto.o_str,
     openssl3.crypto.stack,       openssl3.crypto.lh_stats,
     openssl3.crypto.safestack,   OpenSSL3.threads_none  ;


function lh_PROPERTY_STRING_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC): Plhash_st_PROPERTY_STRING;
begin
   Result := Plhash_st_PROPERTY_STRING(OPENSSL_LH_new(hfn, cfn)) ;
end;


procedure lh_PROPERTY_STRING_free( lh : Plhash_st_PROPERTY_STRING);
begin
   OPENSSL_LH_free(POPENSSL_LHASH (lh));
end;


procedure lh_PROPERTY_STRING_flush( lh : Plhash_st_PROPERTY_STRING);
begin
   OPENSSL_LH_flush(POPENSSL_LHASH (lh) );
end;


function lh_PROPERTY_STRING_insert( lh : Plhash_st_PROPERTY_STRING;const d : PPROPERTY_STRING):PPROPERTY_STRING;
begin
   Result := PPROPERTY_STRING (OPENSSL_LH_insert(POPENSSL_LHASH (lh), d));
end;


function lh_PROPERTY_STRING_delete(lh : Plhash_st_PROPERTY_STRING;const d : PPROPERTY_STRING):PPROPERTY_STRING;
begin
    Result := PPROPERTY_STRING (OPENSSL_LH_delete(POPENSSL_LHASH (lh), d));
end;


function lh_PROPERTY_STRING_retrieve(lh : Plhash_st_PROPERTY_STRING;const d : PPROPERTY_STRING):PPROPERTY_STRING;
begin
   Result := PPROPERTY_STRING (OPENSSL_LH_retrieve(POPENSSL_LHASH (lh), d));
end;


function lh_PROPERTY_STRING_error( lh : Plhash_st_PROPERTY_STRING):integer;
begin
  Result := OPENSSL_LH_error(POPENSSL_LHASH (lh));
end;


procedure lh_PROPERTY_STRING_node_stats_bio(const lh : Plhash_st_PROPERTY_STRING;&out : PBIO);
begin
   OPENSSL_LH_node_stats_bio(POPENSSL_LHASH (lh), &out);
end;


procedure lh_PROPERTY_STRING_node_usage_stats_bio(const lh : Plhash_st_PROPERTY_STRING;&out : PBIO);
begin
   OPENSSL_LH_node_usage_stats_bio(POPENSSL_LHASH (lh), out);
end;


procedure lh_PROPERTY_STRING_stats_bio(const lh : Plhash_st_PROPERTY_STRING;&out : PBIO);
begin
   OPENSSL_LH_stats_bio(POPENSSL_LHASH (lh), &out);
end;


procedure lh_PROPERTY_STRING_set_down_load( lh : Plhash_st_PROPERTY_STRING; dl : uint32);
begin
   OPENSSL_LH_set_down_load(POPENSSL_LHASH (lh), dl);
end;


procedure lh_PROPERTY_STRING_doall( lh : Plhash_st_PROPERTY_STRING; doall: Tdoall_func);
begin
   OPENSSL_LH_doall(POPENSSL_LHASH (lh), TOPENSSL_LH_DOALL_FUNC(doall));
end;


procedure lh_PROPERTY_STRING_doall_arg(lh : Plhash_st_PROPERTY_STRING;
                                       doallarg: Tdoallarg_func;  arg: Pointer);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH (lh),
                             TOPENSSL_LH_DOALL_FUNCARG(doallarg), arg);
end;

function ossl_property_value_str( ctx : POSSL_LIB_CTX; idx : OSSL_PROPERTY_IDX):PUTF8Char;
begin
    Result := ossl_property_str(0, ctx, idx);
end;

function ossl_property_str( name : integer; ctx : POSSL_LIB_CTX; idx : OSSL_PROPERTY_IDX):PUTF8Char;
var
    r        : PUTF8Char;
    p        : Pointer;
    propdata : PPROPERTY_STRING_DATA;
    findstr  : find_str_st;
begin
    propdata := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_PROPERTY_STRING_INDEX,
                                @property_string_data_method);
    if propdata = nil then Exit(nil);
    if  0>= CRYPTO_THREAD_read_lock(propdata.lock) then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_UNABLE_TO_GET_READ_LOCK);
        Exit(nil);
    end;
{$IFDEF OPENSSL_SMALL_FOOTPRINT}
    begin
        findstr.str := nil;
        findstr.idx := idx;
        lh_PROPERTY_STRING_doall_arg(name ? propdata.prop_names
                                          : propdata.prop_values,
                                     find_str_fn, &findstr);
        r := findstr.str;
    end;
{$ELSE}
    if Boolean(name)  then
       p := propdata.prop_namelist
    else
       p := propdata.prop_valuelist;
    r := sk_OPENSSL_CSTRING_value(p, idx - 1);
{$ENDIF}
    CRYPTO_THREAD_unlock(propdata.lock);
    Result := r;
end;

function ossl_property_name_str( ctx : POSSL_LIB_CTX; idx : OSSL_PROPERTY_IDX):PUTF8Char;
begin
    Result := ossl_property_str(1, ctx, idx);
end;

function ossl_property_value(ctx : POSSL_LIB_CTX;const s : PUTF8Char; create : integer):OSSL_PROPERTY_IDX;
begin
    Result := ossl_property_string(ctx, 0, create, s);
end;

function new_property_string(const s : PUTF8Char; pidx : POSSL_PROPERTY_IDX):PPROPERTY_STRING;
begin

    Result := OPENSSL_malloc(sizeof(Result^));
    if Result <> nil then
    begin
        //SetLength(Result.body, len+1);
        //memcpy(@Result.body, s, len + 1);
        OPENSSL_strdup(Result.body, s);
        Result.s := Result.body;
        Result.idx := PreInc(pidx^);
        if Result.idx = 0 then
        begin
            OPENSSL_free(Result);
            Exit(nil);
        end;
    end;

end;

procedure property_free( ps : Pointer);
begin
    OPENSSL_free(ps);
end;

procedure property_table_free( pt : PPPROP_TABLE);
var
  t : PPROP_TABLE;
begin
    t := pt^;
    if t <> nil then
    begin
        lh_PROPERTY_STRING_doall(Plhash_st_PROPERTY_STRING(t), &property_free);
        lh_PROPERTY_STRING_free(Plhash_st_PROPERTY_STRING(t));
        pt^ := nil;
    end;
end;

procedure property_string_data_free( vpropdata : Pointer);
var
  propdata : PPROPERTY_STRING_DATA;
begin
    propdata := vpropdata;
    if propdata = nil then exit;
    CRYPTO_THREAD_lock_free(propdata.lock);
    property_table_free(@propdata.prop_names);
    property_table_free(@propdata.prop_values);
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    sk_OPENSSL_CSTRING_free(propdata.prop_namelist);
    sk_OPENSSL_CSTRING_free(propdata.prop_valuelist);
    propdata.prop_namelist := nil;
    propdata.prop_valuelist := nil;
{$ENDIF}
    propdata.prop_name_idx := 0;
    propdata.prop_value_idx := 0;
    OPENSSL_free(propdata);
end;

function property_hash(const a : Pointer):uint32;
begin
    Result := OPENSSL_LH_strhash(PPROPERTY_STRING(a).s);
end;

function property_cmp(const a, b : Pointer):integer;
begin
    Result := strcmp(PPROPERTY_STRING(a).s, PPROPERTY_STRING(b).s);
end;

function property_string_data_new( ctx : POSSL_LIB_CTX):Pointer;
var
  propdata : PPROPERTY_STRING_DATA;
begin
    propdata := OPENSSL_zalloc(sizeof(propdata^));
    if propdata = nil then
       Exit(nil);
    propdata.lock := CRYPTO_THREAD_lock_new();
    propdata.prop_names := PPROP_TABLE(lh_PROPERTY_STRING_new(property_hash, property_cmp));
    propdata.prop_values := PPROP_TABLE(lh_PROPERTY_STRING_new(property_hash, property_cmp));
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    propdata.prop_namelist := sk_OPENSSL_CSTRING_new_null();
    propdata.prop_valuelist := sk_OPENSSL_CSTRING_new_null();
{$ENDIF}
    if (propdata.lock = nil)
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
             or  (propdata.prop_namelist = nil)
             or  (propdata.prop_valuelist = nil)
{$ENDIF}
             or  (propdata.prop_names = nil)
             or  (propdata.prop_values = nil) then
    begin
        property_string_data_free(propdata);
        Exit(nil);
    end;
    Result := propdata;
end;

function ossl_property_string(ctx : POSSL_LIB_CTX; name, create : integer;const s : PUTF8Char):OSSL_PROPERTY_IDX;
var
  p        : TPROPERTY_STRING;
  ps,
  ps_new   : PPROPERTY_STRING;
  t        : PPROP_TABLE;
  pidx     : POSSL_PROPERTY_IDX;
  propdata : PPROPERTY_STRING_DATA;
  {$IFNDEF OPENSSL_SMALL_FOOTPRINT}
  slist:   PSTACK_st_OPENSSL_CSTRING;
  {$ENDIF}
begin
     ps_new := nil;
     propdata := ossl_lib_ctx_get_data(ctx, OSSL_LIB_CTX_PROPERTY_STRING_INDEX, @property_string_data_method);
    if propdata = nil then
       Exit(0);
    if name > 0 then
       t :=  propdata.prop_names
    else
       t := propdata.prop_values;

    p.s := s;
    if  0>= CRYPTO_THREAD_read_lock(propdata.lock  )then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_UNABLE_TO_GET_READ_LOCK);
        Exit(0);
    end;
    ps := lh_PROPERTY_STRING_retrieve(Plhash_st_PROPERTY_STRING(t), @p);
    if (ps = nil)  and  (create > 0) then
    begin
        CRYPTO_THREAD_unlock(propdata.lock);
        if  0>= CRYPTO_THREAD_write_lock(propdata.lock) then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_UNABLE_TO_GET_WRITE_LOCK);
            Exit(0);
        end;
        if name > 0 then
           pidx :=  @propdata.prop_name_idx
        else
           pidx := @propdata.prop_value_idx;
        ps := lh_PROPERTY_STRING_retrieve(Plhash_st_PROPERTY_STRING(t), @p);
        ps_new := new_property_string(s, pidx );
        if (ps = nil)  and  (ps_new <> nil) then
        begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
            if name > 0 then
               slist :=  propdata.prop_namelist
            else
               slist :=  propdata.prop_valuelist;
            if sk_OPENSSL_CSTRING_push(slist, ps_new.s)  <= 0 then
            begin
                property_free(ps_new);
                CRYPTO_THREAD_unlock(propdata.lock);
                Exit(0);
            end;
{$ENDIF}
            lh_PROPERTY_STRING_insert(Plhash_st_PROPERTY_STRING(t), ps_new);
            if lh_PROPERTY_STRING_error(Plhash_st_PROPERTY_STRING(t))>0 then
            begin
                {-
                 * Undo the previous push which means also decrementing the
                 * index and freeing the allocated storage.
                 }
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
                sk_OPENSSL_CSTRING_pop(slist);
{$ENDIF}
                property_free(ps_new);
                Dec(pidx^);
                CRYPTO_THREAD_unlock(propdata.lock);
                Exit(0);
            end;
            ps := ps_new;
        end;
    end;
    CRYPTO_THREAD_unlock(propdata.lock);
    if ps <> nil  then
       Result :=  ps.idx
    else
      Result := 0;
end;

function ossl_property_name(ctx : POSSL_LIB_CTX;const s : PUTF8Char; create : integer):OSSL_PROPERTY_IDX;
begin
    Result := ossl_property_string(ctx, 1, create, s);
end;

end.
