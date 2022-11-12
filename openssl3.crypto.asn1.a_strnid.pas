unit openssl3.crypto.asn1.a_strnid;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

  function ASN1_STRING_set_default_mask_asc(var p : PUTF8Char):integer;
  function ASN1_STRING_set_by_NID(_out : PPASN1_STRING;const _in : PByte; inlen, inform, nid : integer):PASN1_STRING;
  function sk_table_cmp(const a, b : PPASN1_STRING_TABLE):integer;
  function table_cmp(const a, b : PASN1_STRING_TABLE):integer;
  function ASN1_STRING_TABLE_get( nid : integer):PASN1_STRING_TABLE;
  function stable_get( nid : integer):PASN1_STRING_TABLE;
  function ASN1_STRING_TABLE_add( nid : integer; minsize, maxsize : long; mask, flags : Cardinal):integer;
  procedure ASN1_STRING_TABLE_cleanup;
  procedure st_free( tbl : PASN1_STRING_TABLE);
  procedure ASN1_STRING_set_default_mask( mask : Cardinal);
  function table_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
  function OBJ_bsearch_table(key : PASN1_STRING_TABLE;const base : PASN1_STRING_TABLE; num : integer):PASN1_STRING_TABLE;

var
  global_mask: UInt32 = B_ASN1_UTF8STRING;
  stable: Pstack_st_ASN1_STRING_TABLE = nil;

implementation
uses OpenSSL3.common, openssl3.crypto.asn1.a_mbstr, openssl3.crypto.init,
     OpenSSL3.include.openssl.asn1, openssl3.crypto.objects.obj_dat, openssl3.crypto.mem,
     openssl3.crypto.asn1.tbl_standard, OpenSSL3.Err;

function table_cmp_BSEARCH_CMP_FN(const a_, b_ : Pointer):integer;
var
  a, b : PASN1_STRING_TABLE;
begin
   a := a_;
   b := b_;
  result := table_cmp(a,b);
end;


function OBJ_bsearch_table(key : PASN1_STRING_TABLE;const base : PASN1_STRING_TABLE; num : integer):PASN1_STRING_TABLE;
begin
   result := PASN1_STRING_TABLE(OBJ_bsearch_(key, base, num,
                      sizeof(TASN1_STRING_TABLE), table_cmp_BSEARCH_CMP_FN));
end;



procedure ASN1_STRING_set_default_mask( mask : Cardinal);
begin
    global_mask := mask;
end;

function ASN1_STRING_set_default_mask_asc(var p : PUTF8Char):integer;
var
  mask : Cardinal;
  _end : PUTF8Char;
begin
    if CHECK_AND_SKIP_PREFIX(p, 'MASK:') > 0 then
    begin
        if p^ = #0 then
            Exit(0);
        mask := strtoul(p, @_end, 0);
        if _end^ <> #0 then
           Exit(0);
    end
    else
    if (strcmp(p, 'nombstr') = 0) then
        mask := not (ulong(B_ASN1_BMPSTRING or B_ASN1_UTF8STRING))
    else if (strcmp(p, 'pkix') = 0) then
        mask := not ulong(B_ASN1_T61STRING)
    else if (strcmp(p, 'utf8only') = 0) then
        mask := B_ASN1_UTF8STRING
    else if (strcmp(p, 'default') = 0) then
        mask := $FFFFFFFF
    else
        Exit(0);
    ASN1_STRING_set_default_mask(mask);
    Result := 1;
end;


function ASN1_STRING_set_by_NID(_out : PPASN1_STRING;const _in : PByte; inlen, inform, nid : integer):PASN1_STRING;
var
  tbl : PASN1_STRING_TABLE;
  str : PASN1_STRING;
  mask : Cardinal;
  ret : integer;
begin
    str := nil;
    if _out = nil then
       _out := @str;
    tbl := ASN1_STRING_TABLE_get(nid);
    if tbl <> nil then
    begin
        mask := tbl.mask;
        if 0>= (tbl.flags and STABLE_NO_MASK) then
            mask := mask and global_mask;
        ret := ASN1_mbstring_ncopy(_out, _in, inlen, inform, mask,
                                  tbl.minsize, tbl.maxsize);
    end
    else
    begin
        ret := ASN1_mbstring_copy(_out, _in, inlen, inform,
                                 DIRSTRING_TYPE and global_mask);
    end;
    if ret <= 0 then Exit(nil);
    Result := _out^;
end;


function sk_table_cmp(const a, b : PPASN1_STRING_TABLE):integer;
begin
    Result := ( a^).nid - ( b^).nid;
end;


function table_cmp(const a, b : PASN1_STRING_TABLE):integer;
begin
    Result := a.nid - b.nid;
end;


function ASN1_STRING_TABLE_get( nid : integer):PASN1_STRING_TABLE;
var
  idx : integer;

  fnd : TASN1_STRING_TABLE;
begin
    { 'stable' can be impacted by config, so load the config file first }
    OPENSSL_init_crypto(OPENSSL_INIT_LOAD_CONFIG, nil);
    fnd.nid := nid;
    if stable <> nil then
    begin
        idx := sk_ASN1_STRING_TABLE_find(stable, @fnd);
        if idx >= 0 then
           Exit(sk_ASN1_STRING_TABLE_value(stable, idx));
    end;
    Result := OBJ_bsearch_table(@fnd, @tbl_standard, Length(tbl_standard));
end;


function stable_get( nid : integer):PASN1_STRING_TABLE;
var
  tmp, rv : PASN1_STRING_TABLE;
begin
    { Always need a string table so allocate one if nil }
    if stable = nil then
    begin
        stable := sk_ASN1_STRING_TABLE_new(sk_table_cmp);
        if stable = nil then Exit(nil);
    end;
    tmp := ASN1_STRING_TABLE_get(nid);
    if (tmp <> nil)  and  ( (tmp.flags and STABLE_FLAGS_MALLOC) > 0) then
        Exit(tmp);
    rv := OPENSSL_zalloc(sizeof(rv^));
    if rv = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    if 0>= sk_ASN1_STRING_TABLE_push(stable, rv) then
    begin
        OPENSSL_free(Pointer(rv));
        Exit(nil);
    end;
    if tmp <> nil then
    begin
        rv.nid := tmp.nid;
        rv.minsize := tmp.minsize;
        rv.maxsize := tmp.maxsize;
        rv.mask := tmp.mask;
        rv.flags := tmp.flags or STABLE_FLAGS_MALLOC;
    end
    else
    begin
        rv.nid := nid;
        rv.minsize := -1;
        rv.maxsize := -1;
        rv.flags := STABLE_FLAGS_MALLOC;
    end;
    Result := rv;
end;


function ASN1_STRING_TABLE_add( nid : integer; minsize, maxsize : long; mask, flags : Cardinal):integer;
var
  tmp : PASN1_STRING_TABLE;
begin
    tmp := stable_get(nid);
    if tmp = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if minsize >= 0 then
       tmp.minsize := minsize;
    if maxsize >= 0 then
       tmp.maxsize := maxsize;
    if mask > 0 then
       tmp.mask := mask;
    if flags > 0 then
       tmp.flags := STABLE_FLAGS_MALLOC or flags;
    Result := 1;
end;


procedure ASN1_STRING_TABLE_cleanup;
var
  tmp : Pstack_st_ASN1_STRING_TABLE;
begin
    tmp := stable;
    if tmp = nil then exit;
    stable := nil;
    sk_ASN1_STRING_TABLE_pop_free(tmp, st_free);
end;


procedure st_free( tbl : PASN1_STRING_TABLE);
begin
    if (tbl.flags and STABLE_FLAGS_MALLOC) > 0 then
       OPENSSL_free(Pointer(tbl));
end;


end.

