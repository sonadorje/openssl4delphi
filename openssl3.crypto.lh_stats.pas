unit openssl3.crypto.lh_stats;

interface
uses OpenSSL.Api;

 procedure OPENSSL_LH_node_stats_bio(const lh : POPENSSL_LHASH; &out : PBIO);
 procedure OPENSSL_LH_node_usage_stats_bio(const lh : POPENSSL_LHASH; &out : PBIO);
 procedure OPENSSL_LH_stats_bio(const lh : POPENSSL_LHASH; &out : PBIO);

implementation
uses openssl3.crypto.bio.bio_print;

procedure OPENSSL_LH_stats_bio(const lh : POPENSSL_LHASH; &out : PBIO);
var
  omit_tsan : integer;
begin
    omit_tsan := 0;
{$IFDEF TSAN_REQUIRES_LOCKING}
    if 0>= CRYPTO_THREAD_read_lock(lh.tsan_lock then ) begin
        BIO_printf(out, 'unable to lock table, omitting TSAN counters'#10);
        omit_tsan := 1;
    end;
{$ENDIF}
    BIO_printf(out, 'num_items             = %lu'#10, [lh.num_items]);
    BIO_printf(out, 'num_nodes             = %u'#10,  [lh.num_nodes]);
    BIO_printf(out, 'num_alloc_nodes       = %u'#10,  [lh.num_alloc_nodes]);
    BIO_printf(out, 'num_expands           = %lu'#10, [lh.num_expands]);
    BIO_printf(out, 'num_expand_reallocs   = %lu'#10, [lh.num_expand_reallocs]);
    BIO_printf(out, 'num_contracts         = %lu'#10, [lh.num_contracts]);
    BIO_printf(out, 'num_contract_reallocs = %lu'#10, [lh.num_contract_reallocs]);
    if 0>= omit_tsan then begin
        BIO_printf(out, 'num_hash_calls        = %lu'#10, [lh.num_hash_calls]);
        BIO_printf(out, 'num_comp_calls        = %lu'#10, [lh.num_comp_calls]);
    end;
    BIO_printf(out, 'num_insert            = %lu'#10, [lh.num_insert]);
    BIO_printf(out, 'num_replace           = %lu'#10, [lh.num_replace]);
    BIO_printf(out, 'num_delete            = %lu'#10, [lh.num_delete]);
    BIO_printf(out, 'num_no_delete         = %lu'#10, [lh.num_no_delete]);
    if 0>= omit_tsan then begin
        BIO_printf(out, 'num_retrieve          = %lu'#10, [lh.num_retrieve]);
        BIO_printf(out, 'num_retrieve_miss     = %lu'#10, [lh.num_retrieve_miss]);
        BIO_printf(out, 'num_hash_comps        = %lu'#10, [lh.num_hash_comps]);
{$IFDEF TSAN_REQUIRES_LOCKING}
        CRYPTO_THREAD_unlock(lh.tsan_lock);
{$ENDIF}
    end;
end;

procedure OPENSSL_LH_node_usage_stats_bio(const lh : POPENSSL_LHASH; &out : PBIO);
var
  n : POPENSSL_LH_NODE;
  num : Cardinal;
  i : uint32;
  total,n_used : Cardinal;
begin
{$POINTERMATH ON}
    total := 0; n_used := 0;
    for i := 0 to lh.num_nodes-1 do
    begin
       n := lh.b[i]; num := 0;
       while n <> nil do
       begin
          Inc(num);
          n := n.next;
       end;
        if num <> 0 then
        begin
            Inc(n_used);
            total  := total + num;
        end;
    end;
    BIO_printf(out, '%lu nodes used out of %u'#10, [n_used, lh.num_nodes]);
    BIO_printf(out, '%lu items'#10, [total]);
    if n_used = 0 then exit;
    BIO_printf(out, 'load %d.%02d  actual load %d.%02d'#10,
               [int (total div lh.num_nodes),
               int ((total mod lh.num_nodes) * 100 div lh.num_nodes),
               int (total div n_used), int ((total mod n_used) * 100 div n_used)]);
{$POINTERMATH OFF}
end;

procedure OPENSSL_LH_node_stats_bio(const lh : POPENSSL_LHASH; &out : PBIO);
var
  n : POPENSSL_LH_NODE;
  i, num : uint32;
begin
{$POINTERMATH ON}
    for i := 0 to lh.num_nodes-1 do
    begin
        n := lh.b[i]; num := 0;
        while n <> nil do
        begin
            Inc(num);
            n := n.next;
        end;
        BIO_printf(out, 'node %6u . %3u'#10, [i, num]);
    end;
{$POINTERMATH OFF}
end;

end.
