unit openssl3.crypto.evp.keymgmt_lib;

interface
uses OpenSSL.Api;

function match_type(const keymgmt1, keymgmt2 : PEVP_KEYMGMT):integer;
  function evp_keymgmt_util_try_import(const params : POSSL_PARAM; arg : Pointer):integer;
  function evp_keymgmt_util_assign_pkey( pkey : PEVP_PKEY; keymgmt : PEVP_KEYMGMT; keydata : Pointer):integer;
  function evp_keymgmt_util_make_pkey( keymgmt : PEVP_KEYMGMT; keydata : Pointer):PEVP_PKEY;
  function evp_keymgmt_util_export(const pk : PEVP_PKEY; selection : integer; export_cb : POSSL_CALLBACK; export_cbarg : Pointer):integer;
  function evp_keymgmt_util_export_to_provider( pk : PEVP_PKEY; keymgmt : PEVP_KEYMGMT):Pointer;
  procedure op_cache_free( e : POP_CACHE_ELEM);
  function evp_keymgmt_util_clear_operation_cache( pk : PEVP_PKEY; locking : integer):integer;
  function evp_keymgmt_util_find_operation_cache( pk : PEVP_PKEY; keymgmt : PEVP_KEYMGMT):POP_CACHE_ELEM;
  function evp_keymgmt_util_cache_keydata( pk : PEVP_PKEY; keymgmt : PEVP_KEYMGMT; keydata : Pointer):integer;
  procedure evp_keymgmt_util_cache_keyinfo( pk : PEVP_PKEY);
  function evp_keymgmt_util_fromdata(target : PEVP_PKEY; keymgmt : PEVP_KEYMGMT; selection : integer;const params : POSSL_PARAM):Pointer;
  function evp_keymgmt_util_has( pk : PEVP_PKEY; selection : integer):integer;
  function evp_keymgmt_util_match( pk1, pk2 : PEVP_PKEY; selection : integer):integer;
  function evp_keymgmt_util_copy( _to, from : PEVP_PKEY; selection : integer):integer;
  function evp_keymgmt_util_gen( target : PEVP_PKEY; keymgmt : PEVP_KEYMGMT; genctx : Pointer; cb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
  function evp_keymgmt_util_get_deflt_digest_name( keymgmt : PEVP_KEYMGMT; keydata : Pointer; mdname : PUTF8Char; mdname_sz : size_t):integer;
  function evp_keymgmt_util_query_operation_name( keymgmt : PEVP_KEYMGMT; op_id : integer):PUTF8Char;

implementation
uses openssl3.crypto.evp.keymgmt_meth, OpenSSL3.Err, openssl3.crypto.evp.p_lib,
     openssl3.crypto.evp.evp_lib, openssl3.crypto.params,
     openssl3.crypto.o_str,
     OpenSSL3.threads_none, OpenSSL3.common, openssl3.crypto.mem;

function match_type(const keymgmt1, keymgmt2 : PEVP_KEYMGMT):integer;
var
  name2 : PUTF8Char;
begin
     name2 := EVP_KEYMGMT_get0_name(keymgmt2);
    Result := Int(EVP_KEYMGMT_is_a(keymgmt1, name2));
end;


function evp_keymgmt_util_try_import(const params : POSSL_PARAM; arg : Pointer):integer;
var
    data            : Pevp_keymgmt_util_try_import_data_st;
    delete_on_error : integer;
begin
{$POINTERMATH ON}
    data := arg;
    delete_on_error := 0;
    { Just in time creation of keydata }
    if data.keydata = nil then
    begin
       data.keydata := evp_keymgmt_newdata(data.keymgmt);
        if data.keydata = nil then
        begin
            ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        delete_on_error := 1;
    end;
    {
     * It's fine if there was no data to transfer, we just end up with an
     * empty destination key.
     }
    if params[0].key = nil then Exit(1);
    if evp_keymgmt_import(data.keymgmt, data.keydata, data.selection,
                           params) > 0 then
        Exit(1);
    if delete_on_error > 0 then
    begin
        evp_keymgmt_freedata(data.keymgmt, data.keydata);
        data.keydata := nil;
    end;
    Result := 0;
{$POINTERMATH OFF}
end;


function evp_keymgmt_util_assign_pkey( pkey : PEVP_PKEY; keymgmt : PEVP_KEYMGMT; keydata : Pointer):integer;
begin
    if (pkey = nil)  or  (keymgmt = nil)  or  (keydata = nil)
         or  (0>= EVP_PKEY_set_type_by_keymgmt(pkey, keymgmt)) then
    begin
        ERR_raise(ERR_LIB_EVP, ERR_R_INTERNAL_ERROR);
        Exit(0);
    end;
    pkey.keydata := keydata;
    evp_keymgmt_util_cache_keyinfo(pkey);
    Result := 1;
end;


function evp_keymgmt_util_make_pkey( keymgmt : PEVP_KEYMGMT; keydata : Pointer):PEVP_PKEY;
var
  pkey : PEVP_PKEY;
begin
    pkey := nil;
    pkey := EVP_PKEY_new();
    if (keymgmt = nil)
         or  (keydata = nil)
         or  (pkey =  nil)
         or  (0>= evp_keymgmt_util_assign_pkey(pkey, keymgmt, keydata)) then
    begin
        EVP_PKEY_free(pkey);
        Exit(nil);
    end;
    Result := pkey;
end;


function evp_keymgmt_util_export(const pk : PEVP_PKEY; selection : integer; export_cb : POSSL_CALLBACK; export_cbarg : Pointer):integer;
begin
    if (pk = nil)  or  (not Assigned(export_cb)) then Exit(0);
       Exit(evp_keymgmt_export(pk.keymgmt, pk.keydata, selection,
                              export_cb, export_cbarg));
end;


function evp_keymgmt_util_export_to_provider( pk : PEVP_PKEY; keymgmt : PEVP_KEYMGMT):Pointer;
var
    import_data : evp_keymgmt_util_try_import_data_st;
    op          : POP_CACHE_ELEM;
    ret         : Pointer;
begin
    { Export to where? }
    if keymgmt = nil then Exit(nil);
    { If we have an unassigned key, give up }
    if pk.keydata = nil then Exit(nil);
    {
     * If |keymgmt| matches the 'origin' |keymgmt|, there is no more to do.
     * The 'origin' is determined by the |keymgmt| pointers being identical
     * or when the provider and the name ID match.  The latter case handles the
     * situation where the fetch cache is flushed and a 'new' key manager is
     * created.
     }
    if (pk.keymgmt = keymgmt)
         or ( (pk.keymgmt.name_id = keymgmt.name_id )
             and  (pk.keymgmt.prov = keymgmt.prov)) then
        Exit(pk.keydata);
    if 0>= CRYPTO_THREAD_read_lock(pk.lock) then
        Exit(nil);
    {
     * If the provider native 'origin' hasn't changed since last time, we
     * try to find our keymgmt in the operation cache.  If it has changed
     * and our keymgmt isn't found, we will clear the cache further down.
     }
    if pk.dirty_cnt = pk.dirty_cnt_copy then begin
        { If this key is already exported to |keymgmt|, no more to do }
        op := evp_keymgmt_util_find_operation_cache(pk, keymgmt);
        if (op <> nil)  and  (op.keymgmt <> nil) then
        begin
            ret := op.keydata;
            CRYPTO_THREAD_unlock(pk.lock);
            Exit(ret);
        end;
    end;
    CRYPTO_THREAD_unlock(pk.lock);
    { If the 'origin' |keymgmt| doesn't support exporting, give up }
    if not Assigned(pk.keymgmt.export) then Exit(nil);
    {
     * Make sure that the type of the keymgmt to export to matches the type
     * of the 'origin'
     }
    if not ossl_assert(match_type(pk.keymgmt, keymgmt)>0) then
        Exit(nil);
    {
     * We look at the already cached provider keys, and import from the
     * first that supports it (i.e. use its export function), and export
     * the imported data to the new provider.
     }
    { Setup for the export callback }
    import_data.keydata := nil;  { evp_keymgmt_util_try_import will create it }
    import_data.keymgmt := keymgmt;
    import_data.selection := OSSL_KEYMGMT_SELECT_ALL;
    {
     * The export function calls the callback (evp_keymgmt_util_try_import),
     * which does the import for us.  If successful, we're done.
     }
    if 0>= evp_keymgmt_util_export(pk, OSSL_KEYMGMT_SELECT_ALL,
                                 @evp_keymgmt_util_try_import, @import_data ) then
        { If there was an error, bail out }
        Exit(nil);
    if 0>= CRYPTO_THREAD_write_lock(pk.lock) then
    begin
        evp_keymgmt_freedata(keymgmt, import_data.keydata);
        Exit(nil);
    end;
    { Check to make sure some other thread didn't get there first }
    op := evp_keymgmt_util_find_operation_cache(pk, keymgmt);
    if (op <> nil)  and  (op.keydata <> nil) then
    begin
        ret := op.keydata;
        CRYPTO_THREAD_unlock(pk.lock);
        {
         * Another thread seemms to have already exported this so we abandon
         * all the work we just did.
         }
        evp_keymgmt_freedata(keymgmt, import_data.keydata);
        Exit(ret);
    end;
    {
     * If the dirty counter changed since last time, then clear the
     * operation cache.  In that case, we know that |i| is zero.
     }
    if pk.dirty_cnt <> pk.dirty_cnt_copy then evp_keymgmt_util_clear_operation_cache(pk, 0);
    { Add the new export to the operation cache }
    if 0>= evp_keymgmt_util_cache_keydata(pk, keymgmt, import_data.keydata ) then
    begin
        CRYPTO_THREAD_unlock(pk.lock);
        evp_keymgmt_freedata(keymgmt, import_data.keydata);
        Exit(nil);
    end;
    { Synchronize the dirty count }
    pk.dirty_cnt_copy := pk.dirty_cnt;
    CRYPTO_THREAD_unlock(pk.lock);
    Result := import_data.keydata;
end;


procedure op_cache_free( e : POP_CACHE_ELEM);
begin
    evp_keymgmt_freedata(e.keymgmt, e.keydata);
    EVP_KEYMGMT_free(e.keymgmt);
    OPENSSL_free(Pointer(e));
end;


function evp_keymgmt_util_clear_operation_cache( pk : PEVP_PKEY; locking : integer):integer;
begin
    if pk <> nil then
    begin
        if (locking>0)  and  (pk.lock <> nil)  and  (0>= CRYPTO_THREAD_write_lock(pk.lock)) then
            Exit(0);
        sk_OP_CACHE_ELEM_pop_free(pk.operation_cache, op_cache_free);
        pk.operation_cache := nil;
        if (locking > 0)  and  (pk.lock <> nil) then
           CRYPTO_THREAD_unlock(pk.lock);
    end;
    Result := 1;
end;


function evp_keymgmt_util_find_operation_cache( pk : PEVP_PKEY; keymgmt : PEVP_KEYMGMT):POP_CACHE_ELEM;
var
  i, _end : integer;

  p : POP_CACHE_ELEM;
begin
    _end := sk_OP_CACHE_ELEM_num(pk.operation_cache);
    {
     * A comparison and sk_P_CACHE_ELEM_find() are avoided to not cause
     * problems when we've only a read lock.
     }
    for i := 0 to _end-1 do
    begin
        p := sk_OP_CACHE_ELEM_value(pk.operation_cache, i);
        if keymgmt = p.keymgmt then Exit(p);
    end;
    Result := nil;
end;


function evp_keymgmt_util_cache_keydata( pk : PEVP_PKEY; keymgmt : PEVP_KEYMGMT; keydata : Pointer):integer;
var
  p : POP_CACHE_ELEM;
begin
    p := nil;
    if keydata <> nil then
    begin
        if pk.operation_cache = nil then
        begin
            pk.operation_cache := sk_OP_CACHE_ELEM_new_null();
            if pk.operation_cache = nil then Exit(0);
        end;
        p := OPENSSL_malloc(sizeof( p^));
        if p = nil then Exit(0);
        p.keydata := keydata;
        p.keymgmt := keymgmt;
        if 0>= EVP_KEYMGMT_up_ref(keymgmt) then
        begin
            OPENSSL_free(Pointer(p));
            Exit(0);
        end;
        if 0>= sk_OP_CACHE_ELEM_push(pk.operation_cache, p) then
        begin
            EVP_KEYMGMT_free(keymgmt);
            OPENSSL_free(Pointer(p));
            Exit(0);
        end;
    end;
    Result := 1;
end;


procedure evp_keymgmt_util_cache_keyinfo( pk : PEVP_PKEY);
var
  bits,
security_bits,
  size          : integer;

    params        : array[0..3] of TOSSL_PARAM;
begin
    {
     * Cache information about the provider 'origin' key.
     *
     * This services functions like EVP_PKEY_get_size, EVP_PKEY_get_bits, etc
     }
    if pk.keydata <> nil then
    begin
        bits := 0;
        security_bits := 0;
        size := 0;
        params[0] := OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_BITS, @bits);
        params[1] := OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_SECURITY_BITS,
                                             @security_bits);
        params[2] := OSSL_PARAM_construct_int(OSSL_PKEY_PARAM_MAX_SIZE, @size);
        params[3] := OSSL_PARAM_construct_end();
        if evp_keymgmt_get_params(pk.keymgmt, pk.keydata, @params) > 0 then
        begin
            pk.cache.size := size;
            pk.cache.bits := bits;
            pk.cache.security_bits := security_bits;
        end;
    end;
end;


function evp_keymgmt_util_fromdata(target : PEVP_PKEY; keymgmt : PEVP_KEYMGMT; selection : integer;const params : POSSL_PARAM):Pointer;
var
  keydata : Pointer;
begin
    keydata := nil;
    keydata := evp_keymgmt_newdata(keymgmt);
    if (keydata = nil)
         or  (0>= evp_keymgmt_import(keymgmt, keydata, selection, params))
         or  (0>= evp_keymgmt_util_assign_pkey(target, keymgmt, keydata)) then
    begin
        evp_keymgmt_freedata(keymgmt, keydata);
        keydata := nil;
    end;
    Result := keydata;
end;


function evp_keymgmt_util_has( pk : PEVP_PKEY; selection : integer):integer;
begin
    { Check if key is even assigned }
    if pk.keymgmt = nil then Exit(0);
    Result := evp_keymgmt_has(pk.keymgmt, pk.keydata, selection);
end;


function evp_keymgmt_util_match( pk1, pk2 : PEVP_PKEY; selection : integer):integer;
var
  keymgmt1,
  keymgmt2    : PEVP_KEYMGMT;
  keydata1,
  keydata2    : Pointer;
  ok          : integer;
  tmp_keydata : Pointer;
begin
    keymgmt1 := nil; keymgmt2 := nil;
    keydata1 := nil;
    keydata2 := nil;
    if (pk1 = nil)  or  (pk2 = nil) then
    begin
        if (pk1 = nil)  and  (pk2 = nil) then
            Exit(1);
        Exit(0);
    end;
    keymgmt1 := pk1.keymgmt;
    keydata1 := pk1.keydata;
    keymgmt2 := pk2.keymgmt;
    keydata2 := pk2.keydata;
    if keymgmt1 <> keymgmt2 then
    begin
        {
         * The condition for a successful cross export is that the
         * keydata to be exported is nil (typed, but otherwise empty
         * EVP_PKEY), or that it was possible to export it with
         * evp_keymgmt_util_export_to_provider().
         *
         * We use |ok| to determine if it's ok to cross export one way,
         * but also to determine if we should attempt a cross export
         * the other way.  There's no point doing it both ways.
         }
        ok := 0;
        { Complex case, where the keymgmt differ }
        if (keymgmt1 <> nil)
             and  (keymgmt2 <> nil)
             and  (0>= match_type(keymgmt1, keymgmt2)) then
        begin
            ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
            Exit( -1);           { Not the same type }
        end;
        {
         * The key types are determined to match, so we try cross export,
         * but only to keymgmt's that supply a matching function.
         }
        if (keymgmt2 <> nil)
             and  (Assigned(keymgmt2.match)) then
        begin
            tmp_keydata := nil;
            ok := 1;
            if keydata1 <> nil then
            begin
                tmp_keydata := evp_keymgmt_util_export_to_provider(pk1, keymgmt2);
                ok := int(tmp_keydata <> nil);
            end;
            if ok > 0 then
            begin
                keymgmt1 := keymgmt2;
                keydata1 := tmp_keydata;
            end;
        end;
        {
         * If we've successfully cross exported one way, there's no point
         * doing it the other way, hence the |!ok| check.
         }
        if (0>= ok)
             and  (keymgmt1 <> nil)
             and  (Assigned(keymgmt1.match)) then
        begin
            tmp_keydata := nil;
            ok := 1;
            if keydata2 <> nil then
            begin
                tmp_keydata := evp_keymgmt_util_export_to_provider(pk2, keymgmt1);
                ok := int(tmp_keydata <> nil);
            end;
            if ok > 0 then
            begin
                keymgmt2 := keymgmt1;
                keydata2 := tmp_keydata;
            end;
        end;
    end;
    { If we still don't have matching keymgmt implementations, we give up }
    if keymgmt1 <> keymgmt2 then Exit(-2);
    { If both keydata are nil, then they're the same key }
    if (keydata1 = nil)  and  (keydata2 = nil) then Exit(1);
    { If only one of the keydata is nil, then they're different keys }
    if (keydata1 = nil)  or  (keydata2 = nil) then Exit(0);
    { If both keydata are non-nil, we let the backend decide }
    Result := evp_keymgmt_match(keymgmt1, keydata1, keydata2, selection);
end;


function evp_keymgmt_util_copy( _to, from : PEVP_PKEY; selection : integer):integer;
var
    to_keymgmt    : PEVP_KEYMGMT;
    to_keydata,
    alloc_keydata : Pointer;
    import_data   : evp_keymgmt_util_try_import_data_st;
begin
    { Save copies of pointers we want to play with without affecting |to| }
    to_keymgmt := _to.keymgmt;
    to_keydata := _to.keydata;
    alloc_keydata := nil;
    { An unassigned key can't be copied }
    if (from = nil)  or  (from.keydata = nil) then Exit(0);
    {
     * If |to| is unassigned, ensure it gets the same KEYMGMT as |from|,
     * Note that the final setting of KEYMGMT is done further down, with
     * EVP_PKEY_set_type_by_keymgmt(); we don't want to do that prematurely.
     }
    if to_keymgmt = nil then
       to_keymgmt := from.keymgmt;
    if (to_keymgmt = from.keymgmt)  and  (Assigned(to_keymgmt.dup))
         and  (to_keydata = nil) then
    begin
        alloc_keydata := evp_keymgmt_dup(to_keymgmt,
                                                     from.keydata,
                                                     selection);
        to_keydata := alloc_keydata ;
        if to_keydata = nil then Exit(0);
    end
    else
    if (match_type(to_keymgmt, from.keymgmt)>0) then
    begin
        import_data.keymgmt := to_keymgmt;
        import_data.keydata := to_keydata;
        import_data.selection := selection;
        if 0>= evp_keymgmt_util_export(from, selection,
                                     @evp_keymgmt_util_try_import,
                                     @import_data) then
            Exit(0);
        {
         * In case to_keydata was previously unallocated,
         * evp_keymgmt_util_try_import() may have created it for us.
         }
        if to_keydata = nil then
        begin
           to_keydata := import_data.keydata;
           alloc_keydata := import_data.keydata;
        end;
    end
    else
    begin
        ERR_raise(ERR_LIB_EVP, EVP_R_DIFFERENT_KEY_TYPES);
        Exit(0);
    end;
    {
     * We only need to set the |to| type when its |keymgmt| isn't set.
     * We can then just set its |keydata| to what we have, which might
     * be exactly what it had when entering this function.
     * This is a bit different from using evp_keymgmt_util_assign_pkey(),
     * which isn't as careful with |to|'s original |keymgmt|, since it's
     * meant to forcibly reassign an EVP_PKEY no matter what, which is
     * why we don't use that one here.
     }
    if (_to.keymgmt = nil)
         and  (0>= EVP_PKEY_set_type_by_keymgmt(_to, to_keymgmt)) then
    begin
        evp_keymgmt_freedata(to_keymgmt, alloc_keydata);
        Exit(0);
    end;
    _to.keydata := to_keydata;
    evp_keymgmt_util_cache_keyinfo(_to);
    Result := 1;
end;


function evp_keymgmt_util_gen( target : PEVP_PKEY; keymgmt : PEVP_KEYMGMT; genctx : Pointer; cb : POSSL_CALLBACK; cbarg : Pointer):Pointer;
var
  keydata : Pointer;
begin
    keydata := nil;
    keydata := evp_keymgmt_gen(keymgmt, genctx, cb, cbarg);
    if (keydata = nil)   or
       (0>= evp_keymgmt_util_assign_pkey(target, keymgmt, keydata)) then
    begin
        evp_keymgmt_freedata(keymgmt, keydata);
        keydata := nil;
    end;
    Result := keydata;
end;


function evp_keymgmt_util_get_deflt_digest_name( keymgmt : PEVP_KEYMGMT; keydata : Pointer; mdname : PUTF8Char; mdname_sz : size_t):integer;
var
    params      : array[0..2] of TOSSL_PARAM;
    mddefault,
    mdmandatory : array[0..99] of UTF8Char;
    result1      : PUTF8Char;
    rv          : integer;
begin
{$POINTERMATH ON}
    mddefault := '';
    mdmandatory := '';
    result1 := nil;
    rv := -2;
    params[0] := OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST,
                                         mddefault, sizeof(mddefault));
    params[1] := OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST,
                                         mdmandatory,
                                         sizeof(mdmandatory));
    params[2] := OSSL_PARAM_construct_end();
    if 0>= evp_keymgmt_get_params(keymgmt, keydata, @params ) then
        Exit(0);
    if OSSL_PARAM_modified(POSSL_PARAM(@params) + 1)>0 then
    begin
        if params[1].return_size <= 1 then  { Only a NUL byte }
            result1 := SN_undef
        else
            result1 := mdmandatory;
        rv := 2;
    end
    else
    if (OSSL_PARAM_modified(@params)>0) then
    begin
        if params[0].return_size <= 1 then { Only a NUL byte }
            result1 := SN_undef
        else
            result1 := mddefault;
        rv := 1;
    end;
    if rv > 0 then
       OPENSSL_strlcpy(mdname, result1, mdname_sz);
    Exit(rv);
{$POINTERMATH OFF}
end;


function evp_keymgmt_util_query_operation_name( keymgmt : PEVP_KEYMGMT; op_id : integer):PUTF8Char;
var
  name : PUTF8Char;
begin
    name := nil;
    if keymgmt <> nil then
    begin
        if Assigned(keymgmt.query_operation_name) then
           name := keymgmt.query_operation_name(op_id);
        if name = nil then
           name := EVP_KEYMGMT_get0_name(keymgmt);
    end;
    Result := name;
end;


end.
