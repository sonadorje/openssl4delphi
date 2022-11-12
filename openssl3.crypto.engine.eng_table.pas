unit openssl3.crypto.engine.eng_table;

interface
uses OpenSSL.Api;

type
   Tengine_table_doall_cb = procedure( nid : integer; sk : Pstack_st_ENGINE; def : PENGINE; arg : Pointer);
   Tengine_table_doall = procedure(p1: PENGINE_PILE);
   Tengine_table_doallarg = procedure(p1: PENGINE_PILE; p2: Pointer);

  st_engine_pile_doall = record
    cb : Tengine_table_doall_cb;
    arg : Pointer;
  end;
  TENGINE_PILE_DOALL = st_engine_pile_doall;
  PENGINE_PILE_DOALL = ^TENGINE_PILE_DOALL;
  Teng_table_fn = procedure (const p1 : PENGINE_PILE; p2 : PENGINE_PILE_DOALL);
  Teng_table_fn2 = procedure (p1 : PENGINE_PILE; p2 : PENGINE);

  function ossl_engine_table_select(table : PPENGINE_TABLE; nid : integer;const f : PUTF8Char; l : integer):PENGINE;
  function int_table_check( t : PPENGINE_TABLE; create : integer):integer;
  function lh_ENGINE_PILE_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC):Plhash_st_ENGINE_PILE;
  function engine_pile_hash(const c : Pointer):Cardinal;
  function engine_pile_cmp(const a, b : Pointer):integer;
 function lh_ENGINE_PILE_retrieve(lh : Plhash_st_ENGINE_PILE;const d : PENGINE_PILE):PENGINE_PILE;
 function sk_ENGINE_value(const sk: Pstack_st_ENGINE; idx : integer):PENGINE;
 procedure engine_table_doall( table : PENGINE_TABLE; cb : Tengine_table_doall_cb; arg : Pointer);
 procedure lh_ENGINE_PILE_doall_ENGINE_PILE_DOALL( lh : Plhash_st_ENGINE_PILE; fn : Teng_table_fn; arg : PENGINE_PILE_DOALL);
 procedure int_dall(const pile : PENGINE_PILE; dall : PENGINE_PILE_DOALL);
 procedure engine_table_unregister( table : PPENGINE_TABLE; e : PENGINE);
  procedure lh_ENGINE_PILE_doall_ENGINE( lh : Plhash_st_ENGINE_PILE; fn : Teng_table_fn2; arg : PENGINE);
  procedure int_unregister_cb( pile : PENGINE_PILE; e : PENGINE);
 procedure engine_table_cleanup( table : PPENGINE_TABLE);


  procedure lh_ENGINE_PILE_free( lh : Plhash_st_ENGINE_PILE);
  procedure lh_ENGINE_PILE_flush( lh : Plhash_st_ENGINE_PILE);
  function lh_ENGINE_PILE_insert( lh : Plhash_st_ENGINE_PILE; d : PENGINE_PILE):PENGINE_PILE;
  function lh_ENGINE_PILE_delete(lh : Plhash_st_ENGINE_PILE;const d : PENGINE_PILE):PENGINE_PILE;

  function lh_ENGINE_PILE_error( lh : Plhash_st_ENGINE_PILE):integer;
  function lh_ENGINE_PILE_num_items( lh : Plhash_st_ENGINE_PILE):Cardinal;
  procedure lh_ENGINE_PILE_node_stats_bio(const lh : Plhash_st_ENGINE_PILE; &out : PBIO);
  procedure lh_ENGINE_PILE_node_usage_stats_bio(const lh : Plhash_st_ENGINE_PILE; &out : PBIO);
  procedure lh_ENGINE_PILE_stats_bio(const lh : Plhash_st_ENGINE_PILE; &out : PBIO);
  function lh_ENGINE_PILE_get_down_load( lh : Plhash_st_ENGINE_PILE):Cardinal;
  procedure lh_ENGINE_PILE_set_down_load( lh : Plhash_st_ENGINE_PILE; dl : Cardinal);
  procedure lh_ENGINE_PILE_doall( lh : Plhash_st_ENGINE_PILE; doall : Tengine_table_doall);
  procedure lh_ENGINE_PILE_doall_arg( lh : Plhash_st_ENGINE_PILE; doallarg : Tengine_table_doallarg; arg : Pointer);
  procedure int_cleanup_cb_doall( p : PENGINE_PILE);
  function engine_table_register(table : PPENGINE_TABLE; cleanup : TENGINE_CLEANUP_CB; e : PENGINE;{const} nids : PInteger; num_nids, setdefault : integer):integer;

implementation
uses openssl3.crypto.init, OpenSSL3.Err, openssl3.providers.fips.fipsprov,
     OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib,
     openssl3.crypto.stack, openssl3.crypto.lh_stats,
     openssl3.crypto.mem,
     openssl3.crypto.engine.eng_init, openssl3.crypto.lhash;

var table_flags: uint32 = 0;






function engine_table_register(table : PPENGINE_TABLE; cleanup : TENGINE_CLEANUP_CB; e : PENGINE;{const} nids : PInteger; num_nids, setdefault : integer):integer;
var
  ret, added : integer;
  tmplate, fnd : PENGINE_PILE;
  label _end;
begin
    ret := 0; added := 0;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock) then
        Exit(0);
    if nil =( table^) then
        added := 1;
    if 0>=int_table_check(table, 1) then
        goto _end;
    if added > 0 then { The cleanup callback needs to be added }
        engine_cleanup_add_first(cleanup);
    while PostDec(num_nids) > 0 do
    begin
        tmplate.nid := nids^;
        fnd := lh_ENGINE_PILE_retrieve(@( table^).piles, @tmplate);
        if nil =fnd then
        begin
            fnd := OPENSSL_malloc(sizeof( fnd^));
            if fnd = nil then goto _end;
            fnd.uptodate := 1;
            fnd.nid := nids^;
            fnd.sk := sk_ENGINE_new_null;
            if nil =fnd.sk then
            begin
                OPENSSL_free(Pointer(fnd));
                goto _end;
            end;
            fnd.funct := nil;
            lh_ENGINE_PILE_insert(@(table^).piles, fnd);
            if lh_ENGINE_PILE_retrieve(@(table^).piles, &tmplate) <> fnd then
            begin
                sk_ENGINE_free(fnd.sk);
                OPENSSL_free(Pointer(fnd));
                goto _end;
            end;
        end;
        { A registration shouldn't add duplicate entries }
        sk_ENGINE_delete_ptr(fnd.sk, e);
        {
         * if 'setdefault', this ENGINE goes to the head of the list
         }
        if 0>=sk_ENGINE_push(fnd.sk, e) then
            goto _end;
        { 'touch' this PENGINE_PILE }
        fnd.uptodate := 0;
        if setdefault > 0 then
        begin
            if 0>=engine_unlocked_init(e) then  begin
                ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INIT_FAILED);
                goto _end;
            end;
            if fnd.funct <> nil then
               engine_unlocked_finish(fnd.funct, 0);
            fnd.funct := e;
            fnd.uptodate := 1;
        end;
        Inc(nids);
    end;
    ret := 1;
 _end:
    CRYPTO_THREAD_unlock(global_engine_lock);
    Result := ret;
end;

procedure int_cleanup_cb_doall( p : PENGINE_PILE);
begin
    if p = nil then exit;
    sk_ENGINE_free(p.sk);
    if p.funct <> nil then
       engine_unlocked_finish(p.funct, 0);
    OPENSSL_free(Pointer(p));
end;


procedure lh_ENGINE_PILE_free( lh : Plhash_st_ENGINE_PILE);
begin
 OPENSSL_LH_free(POPENSSL_LHASH (lh));
end;


procedure lh_ENGINE_PILE_flush( lh : Plhash_st_ENGINE_PILE);
begin
 OPENSSL_LH_flush(POPENSSL_LHASH (lh));
end;


function lh_ENGINE_PILE_insert( lh : Plhash_st_ENGINE_PILE; d : PENGINE_PILE):PENGINE_PILE;
begin
 Result := PENGINE_PILE (OPENSSL_LH_insert(POPENSSL_LHASH (lh), d));
end;


function lh_ENGINE_PILE_delete(lh : Plhash_st_ENGINE_PILE;const d : PENGINE_PILE):PENGINE_PILE;
begin
 Result := PENGINE_PILE (OPENSSL_LH_delete(POPENSSL_LHASH (lh), d));
end;


function lh_ENGINE_PILE_error( lh : Plhash_st_ENGINE_PILE):integer;
begin
   Result := OPENSSL_LH_error(POPENSSL_LHASH (lh));
end;


function lh_ENGINE_PILE_num_items( lh : Plhash_st_ENGINE_PILE):Cardinal;
begin
   Result := OPENSSL_LH_num_items(POPENSSL_LHASH(lh));
end;


procedure lh_ENGINE_PILE_node_stats_bio(const lh : Plhash_st_ENGINE_PILE; &out : PBIO);
begin
   OPENSSL_LH_node_stats_bio(POPENSSL_LHASH (lh), &out);
end;


procedure lh_ENGINE_PILE_node_usage_stats_bio(const lh : Plhash_st_ENGINE_PILE; &out : PBIO);
begin
   OPENSSL_LH_node_usage_stats_bio(POPENSSL_LHASH (lh), &out);
end;


procedure lh_ENGINE_PILE_stats_bio(const lh : Plhash_st_ENGINE_PILE; &out : PBIO);
begin
 OPENSSL_LH_stats_bio(POPENSSL_LHASH(lh), &out);
end;


function lh_ENGINE_PILE_get_down_load( lh : Plhash_st_ENGINE_PILE):Cardinal;
begin
   Result := OPENSSL_LH_get_down_load(POPENSSL_LHASH(lh));
end;


procedure lh_ENGINE_PILE_set_down_load( lh : Plhash_st_ENGINE_PILE; dl : Cardinal);
begin
 OPENSSL_LH_set_down_load(POPENSSL_LHASH(lh), dl);
end;


procedure lh_ENGINE_PILE_doall( lh : Plhash_st_ENGINE_PILE; doall : Tengine_table_doall);
begin
 OPENSSL_LH_doall(POPENSSL_LHASH(lh), TOPENSSL_LH_DOALL_FUNC(doall));
end;


procedure lh_ENGINE_PILE_doall_arg( lh : Plhash_st_ENGINE_PILE; doallarg : Tengine_table_doallarg; arg : Pointer);
begin
 OPENSSL_LH_doall_arg(POPENSSL_LHASH (lh), TOPENSSL_LH_DOALL_FUNCARG(doallarg), arg);
end;


procedure engine_table_cleanup( table : PPENGINE_TABLE);
begin
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock) then
        exit;
    if table^ <> nil then
    begin
        lh_ENGINE_PILE_doall(@(table^).piles, int_cleanup_cb_doall);
        lh_ENGINE_PILE_free(@(table^).piles);
        table^ := nil;
    end;
    CRYPTO_THREAD_unlock(global_engine_lock);
end;



procedure int_unregister_cb( pile : PENGINE_PILE; e : PENGINE);
var
  n : integer;
  function get_n: int;
  begin
    n := sk_ENGINE_find(pile.sk, e);
    Result := n;
  end;
begin
    { Iterate the 'c.sk' stack removing any occurrence of 'e' }
    while (get_n  >= 0) do  begin
        sk_ENGINE_delete(pile.sk, n);
        pile.uptodate := 0;
    end;
    if pile.funct = e then begin
        engine_unlocked_finish(e, 0);
        pile.funct := nil;
    end;
end;

procedure lh_ENGINE_PILE_doall_ENGINE( lh : Plhash_st_ENGINE_PILE; fn : Teng_table_fn2; arg : PENGINE);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh),  TOPENSSL_LH_DOALL_FUNCARG(fn), Pointer(arg));
end;




procedure engine_table_unregister( table : PPENGINE_TABLE; e : PENGINE);
begin
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock ) then
        { Can't return a value. :( }
        exit;
    if int_table_check(table, 0) > 0 then
        lh_ENGINE_PILE_doall_ENGINE(@( table^).piles, int_unregister_cb, e);
    CRYPTO_THREAD_unlock(global_engine_lock);
end;




procedure int_dall(const pile : PENGINE_PILE; dall : PENGINE_PILE_DOALL);
begin
    dall.cb(pile.nid, pile.sk, pile.funct, dall.arg);
end;

procedure lh_ENGINE_PILE_doall_ENGINE_PILE_DOALL( lh : Plhash_st_ENGINE_PILE; fn : Teng_table_fn; arg : PENGINE_PILE_DOALL);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh), TOPENSSL_LH_DOALL_FUNCARG(fn), Pointer(arg));
end;

procedure engine_table_doall( table : PENGINE_TABLE; cb : Tengine_table_doall_cb; arg : Pointer);
var
  dall : TENGINE_PILE_DOALL;
begin
    dall.cb := cb;
    dall.arg := arg;
    if table <> nil then
       lh_ENGINE_PILE_doall_ENGINE_PILE_DOALL(@table.piles, int_dall, @dall);
end;


function sk_ENGINE_value(const sk: Pstack_st_ENGINE; idx : integer):PENGINE;
begin
   Result := PENGINE(OPENSSL_sk_value(POPENSSL_STACK(sk), idx));
end;

function lh_ENGINE_PILE_retrieve(lh : Plhash_st_ENGINE_PILE;const d : PENGINE_PILE):PENGINE_PILE;
begin
   Result := PENGINE_PILE(OPENSSL_LH_retrieve(POPENSSL_LHASH(lh), d));
end;


function engine_pile_cmp(const a, b : Pointer):integer;
begin
    Result := PENGINE_PILE(a).nid - PENGINE_PILE(b).nid;
end;


function engine_pile_hash(const c : Pointer):Cardinal;
begin
    Result := PENGINE_PILE(c).nid;
end;


function lh_ENGINE_PILE_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC):Plhash_st_ENGINE_PILE;
begin
   Result := Plhash_st_ENGINE_PILE(OPENSSL_LH_new(hfn, cfn));
end;

function int_table_check( t : PPENGINE_TABLE; create : integer):integer;
var
  lh : Plhash_st_ENGINE_PILE;
begin
    if t^ <> nil then Exit(1);
    if 0>= create then Exit(0);
    lh := lh_ENGINE_PILE_new(engine_pile_hash, engine_pile_cmp);
    if lh = nil then
        Exit(0);
    t^ := PENGINE_TABLE(lh);
    Result := 1;
end;

function ossl_engine_table_select(table : PPENGINE_TABLE; nid : integer;const f : PUTF8Char; l : integer):PENGINE;
var
  ret : PENGINE;
  tmplate : TENGINE_PILE;
  fnd : PENGINE_PILE;
  initres, loop : integer;
  label _trynext, _end;
begin
    ret := nil;
    fnd := nil;
    loop := 0;
    { Load the config before trying to check if engines are available }
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil);
    if nil = ( table^) then
    begin
        {OSSL_TRACE3(ENGINE_TABLE,
                   '%s:%d, nid=%d, nothing registered!\n',
                   f, l, nid);}
        Exit(nil);
    end;
    ERR_set_mark();
    if 0>= CRYPTO_THREAD_write_lock(global_engine_lock)  then
        goto _end ;
    {
     * Check again inside the lock otherwise we could race against cleanup
     * operations. But don't worry about a debug printout
     }
    if 0>= int_table_check(table, 0) then
        goto _end ;
    tmplate.nid := nid;
    fnd := lh_ENGINE_PILE_retrieve(@table^.piles, @tmplate);
    if nil = fnd then goto _end ;
    if (Assigned(fnd.funct))  and  (engine_unlocked_init(fnd.funct)>0) then
    begin
        {OSSL_TRACE4(ENGINE_TABLE,
                   '%s:%d, nid=%d, using ENGINE '%s' cached\n',
                   f, l, nid, fnd.funct.id);}
        ret := fnd.funct;
        goto _end ;
    end;
    if fnd.uptodate>0 then
    begin
        ret := fnd.funct;
        goto _end ;
    end;
 _trynext:
    ret := sk_ENGINE_value(fnd.sk, PostInc(loop));
    if nil = ret then
    begin
        {OSSL_TRACE3(ENGINE_TABLE,
                    '%s:%d, nid=%d, '
                    'no registered implementations would initialise\n',
                    f, l, nid);}
        goto _end ;
    end;
    { Try to initialise the ENGINE? }
    if (ret.funct_ref > 0)  or  (0>= (table_flags and ENGINE_TABLE_FLAG_NOINIT)) then
        initres := engine_unlocked_init(ret)
    else
        initres := 0;
    if initres>0 then
    begin
        { Update 'funct' }
        if (fnd.funct <> ret)  and  (engine_unlocked_init(ret)>0) then
        begin
            { If there was a previous default we release it. }
            if Assigned(fnd.funct) then
                engine_unlocked_finish(fnd.funct, 0);
            fnd.funct := ret;
            {OSSL_TRACE4(ENGINE_TABLE,
                        '%s:%d, nid=%d, setting default to '%s'\n',
                        f, l, nid, ret.id);}
        end;
        {OSSL_TRACE4(ENGINE_TABLE,
                    '%s:%d, nid=%d, using newly initialised '%s'\n',
                    f, l, nid, ret.id); }
        goto _end ;
    end;
    goto _trynext ;
 _end:
    {
     * If it failed, it is unlikely to succeed again until some future
     * registrations have taken place. In all cases, we cache.
     }
    if Assigned(fnd) then
       fnd.uptodate := 1;
    {if ret then
         OSSL_TRACE4(ENGINE_TABLE,
                   '%s:%d, nid=%d, caching ENGINE '%s'\n',
                   f, l, nid, ret.id);
    else
        OSSL_TRACE3(ENGINE_TABLE,
                    '%s:%d, nid=%d, caching 'no matching ENGINE'\n',
                    f, l, nid);
    }
    CRYPTO_THREAD_unlock(global_engine_lock);
    {
     * Whatever happened, any failed init()s are not failures in this
     * context, so clear our error state.
     }
    ERR_pop_to_mark();
    Result := ret;
end;

end.
