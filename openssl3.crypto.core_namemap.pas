unit openssl3.crypto.core_namemap;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api, SysUtils;

type
  doall_names_data_st = record
    number : integer;
    names : PPUTF8Char;
    found : integer;
  end;
  TDOALL_NAMES_DATA = doall_names_data_st;
  PDOALL_NAMES_DATA = ^TDOALL_NAMES_DATA;


  num2name_data_st = record
    idx : size_t;
    name : PUTF8Char;
  end;
  Pnum2name_data_st = ^num2name_data_st;

  Tcore_namemap_fn = procedure(const p1: PUTF8Char; arg: Pointer);

function stored_namemap_new( libctx : POSSL_LIB_CTX):Pointer;
function ossl_namemap_stored( libctx : POSSL_LIB_CTX):POSSL_NAMEMAP;
function ossl_namemap_new:POSSL_NAMEMAP;
function ossl_lh_strcasehash(c : PUTF8Char):uint64;
function ossl_namemap_empty( namemap : POSSL_NAMEMAP):Boolean;
function ossl_namemap_add_name(namemap : POSSL_NAMEMAP; number : integer;const name : PUTF8Char):integer;
function ossl_namemap_add_name_n(namemap : POSSL_NAMEMAP; number : integer;const name : PUTF8Char; name_len : size_t):integer;
function ossl_namemap_name2num(const namemap : POSSL_NAMEMAP;const name : PUTF8Char):integer;
function namemap_name2num_n(const namemap : POSSL_NAMEMAP; name : PUTF8Char; name_len : size_t):integer;
function ossl_namemap_doall_names(const namemap : POSSL_NAMEMAP; number : integer; fn : Tcore_namemap_fn; data : Pointer):integer;
function ossl_namemap_name2num_n({const} namemap : POSSL_NAMEMAP;const name : PUTF8Char; name_len : size_t):integer;
function ossl_namemap_add_names(namemap : POSSL_NAMEMAP; number : integer;const names : PUTF8Char; separator : UTF8Char):integer;
function namemap_add_name_n(namemap : POSSL_NAMEMAP; number : integer;const name : PUTF8Char; name_len : size_t):integer;
function ossl_namemap_num2name(const namemap : POSSL_NAMEMAP; number : integer; idx : size_t):PUTF8Char;
procedure stored_namemap_free( vnamemap : Pointer);
procedure ossl_namemap_free( namemap : POSSL_NAMEMAP);
procedure do_num2name(const name : PUTF8Char; vdata : Pointer);
procedure get_legacy_evp_names(base_nid, nid : integer;const pem_name : PUTF8Char; arg: Pointer);
procedure get_legacy_pkey_meth_names(const ameth : PEVP_PKEY_ASN1_METHOD; arg : Pointer);
procedure namenum_free( n : Pointer);

function lh_NAMENUM_ENTRY_get_down_load( lh : Plhash_st_NAMENUM_ENTRY):uint64;
function lh_NAMENUM_ENTRY_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC): Plhash_st_NAMENUM_ENTRY;
function lh_NAMENUM_ENTRY_insert( lh : Plhash_st_NAMENUM_ENTRY; d : PNAMENUM_ENTRY):PNAMENUM_ENTRY;
function lh_NAMENUM_ENTRY_delete(lh : Plhash_st_NAMENUM_ENTRY;const d : PNAMENUM_ENTRY):PNAMENUM_ENTRY;
function lh_NAMENUM_ENTRY_retrieve(lh : Plhash_st_NAMENUM_ENTRY;const d : PNAMENUM_ENTRY):PNAMENUM_ENTRY;
function lh_NAMENUM_ENTRY_error( lh : Plhash_st_NAMENUM_ENTRY):integer;
function lh_NAMENUM_ENTRY_num_items( lh : Plhash_st_NAMENUM_ENTRY):uint64;
procedure lh_NAMENUM_ENTRY_node_stats_bio(const lh : Plhash_st_NAMENUM_ENTRY; _out : PBIO);
procedure lh_NAMENUM_ENTRY_node_usage_stats_bio(const lh : Plhash_st_NAMENUM_ENTRY; _out : PBIO);
procedure lh_NAMENUM_ENTRY_stats_bio(const lh : Plhash_st_NAMENUM_ENTRY; _out : PBIO);
procedure lh_NAMENUM_ENTRY_free( lh : Plhash_st_NAMENUM_ENTRY);
procedure lh_NAMENUM_ENTRY_flush( lh : Plhash_st_NAMENUM_ENTRY);
procedure lh_NAMENUM_ENTRY_set_down_load( lh : Plhash_st_NAMENUM_ENTRY; dl : uint64);
procedure lh_NAMENUM_ENTRY_doall( lh : Plhash_st_NAMENUM_ENTRY; doall : Tdoall_func);
procedure lh_NAMENUM_ENTRY_doall_arg( lh : Plhash_st_NAMENUM_ENTRY; doallarg : Tdoallarg_func; arg : Pointer);

const
   stored_namemap_method: TOSSL_LIB_CTX_METHOD = (
      priority :OSSL_LIB_CTX_METHOD_DEFAULT_PRIORITY;
      new_func :stored_namemap_new;
      free_func :stored_namemap_free
   );

implementation

uses OpenSSL3.common, OpenSSL3.Err,  openssl3.crypto.lh_stats,
     openssl3.crypto.context,        openssl3.crypto.lhash,
     openssl3.crypto.ctype,          openssl3.crypto.o_str,
     openssl3.crypto.evp.evp_lib,    openssl3.crypto.mem,
     OpenSSL3.threads_none,          openssl3.tsan_assist,
     openssl3.crypto.init,           openssl3.crypto.objects.obj_dat,
     openssl3.crypto.asn1.ameth_lib, openssl3.crypto.objects.o_names;

type
  Tcore_namemap_doall_func = procedure(const p1: Pointer ; p2: PDOALL_NAMES_DATA );

function lh_NAMENUM_ENTRY_new(hfn: TOPENSSL_LH_HASHFUNC; cfn: TOPENSSL_LH_COMPFUNC): Plhash_st_NAMENUM_ENTRY;
begin
   Result := Plhash_st_NAMENUM_ENTRY(OPENSSL_LH_new(hfn, cfn));
end;

procedure lh_NAMENUM_ENTRY_free( lh : Plhash_st_NAMENUM_ENTRY);
begin
   OPENSSL_LH_free(POPENSSL_LHASH(lh));
end;


procedure lh_NAMENUM_ENTRY_flush( lh : Plhash_st_NAMENUM_ENTRY);
begin
   OPENSSL_LH_flush(POPENSSL_LHASH(lh));
end;


function lh_NAMENUM_ENTRY_insert( lh : Plhash_st_NAMENUM_ENTRY; d : PNAMENUM_ENTRY):PNAMENUM_ENTRY;
begin
   Result := OPENSSL_LH_insert(POPENSSL_LHASH(lh), d);
end;


function lh_NAMENUM_ENTRY_delete(lh : Plhash_st_NAMENUM_ENTRY;const d : PNAMENUM_ENTRY):PNAMENUM_ENTRY;
begin
   Result := PNAMENUM_ENTRY (OPENSSL_LH_delete(POPENSSL_LHASH(lh), d));
end;


function lh_NAMENUM_ENTRY_retrieve(lh : Plhash_st_NAMENUM_ENTRY;const d : PNAMENUM_ENTRY):PNAMENUM_ENTRY;
begin
   Result := OPENSSL_LH_retrieve(POPENSSL_LHASH(lh), d);
end;


function lh_NAMENUM_ENTRY_error( lh : Plhash_st_NAMENUM_ENTRY):integer;
begin
   Result := OPENSSL_LH_error(POPENSSL_LHASH(lh));
end;


function lh_NAMENUM_ENTRY_num_items( lh : Plhash_st_NAMENUM_ENTRY):uint64;
begin
   Result := OPENSSL_LH_num_items(POPENSSL_LHASH(lh));
end;


procedure lh_NAMENUM_ENTRY_node_stats_bio(const lh : Plhash_st_NAMENUM_ENTRY; _out : PBIO);
begin
   OPENSSL_LH_node_stats_bio(POPENSSL_LHASH (lh), _out);
end;


procedure lh_NAMENUM_ENTRY_node_usage_stats_bio(const lh : Plhash_st_NAMENUM_ENTRY; _out : PBIO);
begin
   OPENSSL_LH_node_usage_stats_bio(POPENSSL_LHASH (lh), _out);
end;


procedure lh_NAMENUM_ENTRY_stats_bio(const lh : Plhash_st_NAMENUM_ENTRY; _out : PBIO);
begin
   OPENSSL_LH_stats_bio(POPENSSL_LHASH (lh), _out);
end;


function lh_NAMENUM_ENTRY_get_down_load( lh : Plhash_st_NAMENUM_ENTRY):uint64;
begin
   Result := OPENSSL_LH_get_down_load(POPENSSL_LHASH(lh));
end;


procedure lh_NAMENUM_ENTRY_set_down_load( lh : Plhash_st_NAMENUM_ENTRY; dl : uint64);
begin
   OPENSSL_LH_set_down_load(POPENSSL_LHASH(lh), dl);
end;


procedure lh_NAMENUM_ENTRY_doall( lh : Plhash_st_NAMENUM_ENTRY; doall : Tdoall_func);
begin
   OPENSSL_LH_doall(POPENSSL_LHASH(lh), TOPENSSL_LH_DOALL_FUNC(doall));
end;


procedure lh_NAMENUM_ENTRY_doall_arg( lh : Plhash_st_NAMENUM_ENTRY; doallarg : Tdoallarg_func; arg : Pointer);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh),
                             TOPENSSL_LH_DOALL_FUNCARG(doallarg), arg);
end;

procedure do_num2name(const name : PUTF8Char; vdata : Pointer);
var
  data : Pnum2name_data_st;
begin
    data := vdata;
    if data.idx > 0 then
       Dec(data.idx)
    else
    if (data.name = nil) then
        data.name := name;
end;

function ossl_namemap_num2name(const namemap : POSSL_NAMEMAP; number : integer; idx : size_t):PUTF8Char;
var
  data : num2name_data_st;
begin
    data.idx := idx;
    data.name := nil;
    if 0>= ossl_namemap_doall_names(namemap, number, do_num2name, @data) then
        Exit(nil);
    Result := data.name;
end;

function ossl_namemap_add_names(namemap : POSSL_NAMEMAP; number : integer;const names : PUTF8Char; separator : UTF8Char):integer;
var
  p,  q       : PUTF8Char;
  len           : size_t;
  this_number : integer;
  s: string;
  label _err;
begin
{$POINTERMATH ON}
    { Check that we have a namemap }
    if  not ossl_assert(namemap <> nil)   then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if  0>= CRYPTO_THREAD_write_lock(namemap.lock) then
        Exit(0);
    {
     * Check that no name is an empty string, and that all names have at
     * most one numeric identity together.
     }
    p := names;
    while p^ <> #0 do
    begin
        q := strchr(p, separator );
        if q = nil then
            len := Length(p)       { offset to \0 }
        else
            len := q - p;           { offset to the next separator }
        this_number := namemap_name2num_n(namemap, p, len);
        if (p^ = #0)  or  (p^ = separator) then
        begin
            ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_BAD_ALGORITHM_NAME);
            goto _err;
        end;
        if number = 0 then
        begin
            number := this_number;
        end
        else
        if (this_number <> 0)  and  (this_number <> number) then
        begin
            ERR_raise_data(ERR_LIB_CRYPTO, CRYPTO_R_CONFLICTING_NAMES,
                         Format('"%.*s" has an existing different identity %d (from "%s")',
                           [len, p, this_number, names]));
            goto _err;
        end;
        if q = nil then
           p := p + len
        else
           p := q + 1;
    end;
    { Now that we have checked, register all names }
    p := names;
    while ( p^ <> #0) do
    begin
        q := strchr(p, separator );
        if q = nil then
            len := Length(p)       { offset to \0 }
        else
            len := q - p;           { offset to the next separator }
        this_number := namemap_add_name_n(namemap, number, p, len);
        if number = 0 then
        begin
            number := this_number;
        end
        else
        if (this_number <> number) then
        begin
            ERR_raise_data(ERR_LIB_CRYPTO, ERR_R_INTERNAL_ERROR,
                          Format('Got number %d when expecting %d',
                           [this_number, number]));
            goto _err;
        end;
        if q = nil then
           p :=  p + len
        else
           p := q + 1;
    end;
    CRYPTO_THREAD_unlock(namemap.lock);
    Exit(number);

 _err:
    CRYPTO_THREAD_unlock(namemap.lock);
    Result := 0;
 {$POINTERMATH OFF}
end;

function ossl_namemap_name2num_n({const} namemap : POSSL_NAMEMAP;const name : PUTF8Char; name_len : size_t):integer;
begin
{$IFNDEF FIPS_MODULE}
    if namemap = nil then
       namemap := ossl_namemap_stored(nil);
{$ENDIF}
    if namemap = nil then Exit(0);
    if  0>= CRYPTO_THREAD_read_lock(namemap.lock)  then
        Exit(0);
    Result  := namemap_name2num_n(namemap, name, name_len);
    CRYPTO_THREAD_unlock(namemap.lock);

end;

procedure do_name(const namenum : Pointer; data : PDOALL_NAMES_DATA);
begin
{$POINTERMATH ON}
    if PNAMENUM_ENTRY(namenum).number = data.number then
    begin
      data.names[data.found] := PNAMENUM_ENTRY(namenum).name;
      Inc(data.found);
    end;
{$POINTERMATH OFF}
end;

procedure lh_NAMENUM_ENTRY_doall_DOALL_NAMES_DATA( lh: Plhash_st_NAMENUM_ENTRY;
                                   fn: Tcore_namemap_doall_func;
                                   arg: PDOALL_NAMES_DATA);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh), TOPENSSL_LH_DOALL_FUNCARG(fn), Pointer(arg));
end;

function ossl_namemap_doall_names(const namemap : POSSL_NAMEMAP; number : integer; fn : Tcore_namemap_fn; data : Pointer):integer;
var
    cbdata    : TDOALL_NAMES_DATA;
    num_names : size_t;
    i         : integer;
begin
{$POINTERMATH ON}
    cbdata.number := number;
    cbdata.found := 0;
    {
     * We collect all the names first under a read lock. Subsequently we call
     * the user function, so that we're not holding the read lock when in user
     * code. This could lead to deadlocks.
     }
    if  0>= CRYPTO_THREAD_read_lock(namemap.lock ) then
        Exit(0);
    num_names := lh_NAMENUM_ENTRY_num_items(namemap.namenum);
    if num_names = 0 then begin
        CRYPTO_THREAD_unlock(namemap.lock);
        Exit(0);
    end;
    cbdata.names := OPENSSL_malloc(sizeof( cbdata.names^) * num_names);
    if cbdata.names = nil then
    begin
        CRYPTO_THREAD_unlock(namemap.lock);
        Exit(0);
    end;
    lh_NAMENUM_ENTRY_doall_DOALL_NAMES_DATA(namemap.namenum, do_name, @cbdata);
    CRYPTO_THREAD_unlock(namemap.lock);
    for i := 0 to cbdata.found-1 do
        fn(cbdata.names[i], data);
    OPENSSL_free(Pointer(cbdata.names));
    Result := 1;
{$POINTERMATH OFF}
end;

function ossl_namemap_name2num(const namemap : POSSL_NAMEMAP;const name : PUTF8Char):integer;
var
  len: uint32;
begin
    if name = nil then
       Exit(0);
    len := Length(name);
    Result := ossl_namemap_name2num_n(namemap, name, len);
end;

procedure get_legacy_evp_names(base_nid, nid : integer;const pem_name : PUTF8Char; arg: Pointer);
var
  num : integer;
  obj : PASN1_OBJECT;
  txtoid : array[0..(OSSL_MAX_NAME_SIZE)-1] of UTF8Char;
begin
    num := 0;
    //writeln(Format('get_legacy_evp_names:baseid_sn=%s, nid_sn=%s', [OBJ_nid2sn(base_nid), OBJ_nid2sn(nid)]));
    if base_nid <> NID_undef then
    begin
        num := ossl_namemap_add_name(arg, num, OBJ_nid2sn(base_nid));
        num := ossl_namemap_add_name(arg, num, OBJ_nid2ln(base_nid));
    end;
    if nid <> NID_undef then
    begin
        num := ossl_namemap_add_name(arg, num, OBJ_nid2sn(nid));
        num := ossl_namemap_add_name(arg, num, OBJ_nid2ln(nid));
        obj := OBJ_nid2obj(nid );
        if obj <> nil then
        begin
            if OBJ_obj2txt(@txtoid, sizeof(txtoid), obj, 1) > 0 then
                num := ossl_namemap_add_name(arg, num, txtoid);
        end;
    end;
    if pem_name <> nil then
       num := ossl_namemap_add_name(arg, num, pem_name);
end;

procedure get_legacy_pkey_meth_names(const ameth : PEVP_PKEY_ASN1_METHOD; arg : Pointer);
var
    nid,
    base_nid,
    flags      : integer;
    pem_name : PUTF8Char;
begin
    nid := 0; base_nid := 0; flags := 0;
    pem_name := nil;
    EVP_PKEY_asn1_get0_info(@nid, @base_nid, @flags, nil, @pem_name, ameth);
    if nid <> NID_undef then
    begin
        if (flags and ASN1_PKEY_ALIAS) = 0 then
        begin
            case nid of
            EVP_PKEY_DHX:
                { We know that the name 'DHX' is used too }
                get_legacy_evp_names(0, nid, 'DHX', arg);
                { FALLTHRU }
            else
                get_legacy_evp_names(0, nid, pem_name, arg);
            end;
        end
        else
        begin
            {
             * Treat aliases carefully, some of them are undesirable, or
             * should not be treated as such for providers.
             }
            case nid of
            EVP_PKEY_SM2:
                {
                 * SM2 is a separate keytype with providers, not an alias for
                 * EC.
                 }
                get_legacy_evp_names(0, nid, pem_name, arg);

            else
                { Use the short name of the base nid as the common reference }
                get_legacy_evp_names(base_nid, nid, pem_name, arg);
            end;
        end;
    end;
end;

procedure namenum_free( n : Pointer);
var
  p: Pointer;
begin
    if n <> nil then
       if PNAMENUM_ENTRY(n).name <> '' then
       begin
          p := PNAMENUM_ENTRY(n).name;
          OPENSSL_free(P);
       end;
    OPENSSL_free(n);
end;

function namemap_name2num_n(const namemap : POSSL_NAMEMAP; name : PUTF8Char; name_len : size_t):integer;
var
  namenum_entry: PNAMENUM_ENTRY;
  namenum_tmpl : TNAMENUM_ENTRY;
  len: size_t;
  s: string;
begin

    OPENSSL_strndup(namenum_tmpl.name, name, name_len );
   
    if namenum_tmpl.name = nil then
        Exit(0);
    namenum_tmpl.number := 0;
    namenum_entry := lh_NAMENUM_ENTRY_retrieve(namemap.namenum, @namenum_tmpl);
    OPENSSL_free(namenum_tmpl.name);

    if namenum_entry <> nil then
       Result := namenum_entry.number
    else
       Result := 0;
end;

function namemap_add_name_n(namemap : POSSL_NAMEMAP; number : integer;const name : PUTF8Char; name_len : size_t):integer;
var
  namenum    : PNAMENUM_ENTRY;
  tmp_number : integer;
  ptr: Pointer;
  label _err;
begin
    namenum := nil;
    { If it already exists, we don't add it }
    tmp_number := namemap_name2num_n(namemap, name, name_len );
    if tmp_number <> 0 then
        Exit(tmp_number);
    namenum := OPENSSL_zalloc(sizeof( namenum^));
     OPENSSL_strndup(namenum.name, name, name_len);
    if  (namenum  = nil) or  (namenum.name = nil) then
       goto _err;
    { The tsan_counter use here is safe since we're under lock }
    if number <> 0  then
       namenum.number :=  number
    else
       namenum.number :=  1 + tsan_counter(@namemap.max_number, sizeof(namemap.max_number));

    lh_NAMENUM_ENTRY_insert(namemap.namenum, namenum);
    if lh_NAMENUM_ENTRY_error(namemap.namenum )>0 then
       goto _err;

    //writeln(Format('namemap_add_name_n: name=%s, namenum=%d', [name, namenum.number]));
    //if name= 'RC2-CBC' then
      // writeln('trace into..');
    Exit(namenum.number);
 _err:
    namenum_free(namenum);
    Result := 0;
end;



function ossl_namemap_add_name_n(namemap : POSSL_NAMEMAP; number : integer;const name : PUTF8Char; name_len : size_t):integer;
begin
{$IFNDEF FIPS_MODULE}
    if namemap = nil then
       namemap := ossl_namemap_stored(nil);
{$ENDIF}
    if (name = nil)  or  (name_len = 0)  or  (namemap = nil) then Exit(0);
    if  0>= CRYPTO_THREAD_write_lock(namemap.lock ) then
        Exit(0);
    Result := namemap_add_name_n(namemap, number, name, name_len);
    CRYPTO_THREAD_unlock(namemap.lock);

end;

function ossl_namemap_add_name(namemap : POSSL_NAMEMAP; number : integer;const name : PUTF8Char):integer;
begin
    if name = nil then
       Exit(0);
    Result := ossl_namemap_add_name_n(namemap, number, name, Length(name));
end;

procedure get_legacy_md_names(const _on : POBJ_NAME; arg : Pointer);
var
  md : PEVP_MD;
begin
    md := Pointer (OBJ_NAME_get(_on.name, _on.&type));
    if md <> nil then
       get_legacy_evp_names(0, EVP_MD_get_type(md), nil, arg);
end;

procedure get_legacy_cipher_names(const _on : POBJ_NAME; arg : Pointer);
var
  cipher : PEVP_CIPHER;
begin
    cipher := Pointer (OBJ_NAME_get(_on.name, _on.&type));
    if cipher <> nil then
       get_legacy_evp_names(NID_undef, EVP_CIPHER_get_type(cipher), nil{pem_name}, arg);
end;

function ossl_namemap_empty( namemap : POSSL_NAMEMAP):Boolean;
var
  rv : integer;
begin
{$IFDEF TSAN_REQUIRES_LOCKING}
    { No TSAN support }
    if namemap = nil then Exit(1);
    if  not CRYPTO_THREAD_read_lock(namemap.lock then )
        Exit(-1);
    rv := namemap.max_number = 0;
    CRYPTO_THREAD_unlock(namemap.lock);
    Exit(rv);
{$ELSE} { Have TSAN support }
    Result := (namemap = nil)  or  (tsan_load(@namemap.max_number) = 0);
{$ENDIF}
end;

function namenum_cmp(const a, b : Pointer):integer;
begin
    Result := strcasecmp(PNAMENUM_ENTRY(a).name, PNAMENUM_ENTRY(b).name);
end;

function ossl_lh_strcasehash(c : PUTF8Char):uint64;
var
  ret : uint64;
  n : long;
  v : uint64;
  r : integer;
begin
    ret := 0;
    if (c = nil)  or  (c^ = #0) then
       Exit(ret);
    n := $100;
    while ( c^ <> #0) do
    begin
        v := n or Ord(ossl_tolower(c^));
        r := int((v  shr  2)  xor  v) and $0f;
        ret := (ret  shl  r) or (ret  shr  (32 - r));
        ret := ret and $FFFFFFFF;
        ret  := ret xor (v * v);
        Inc(c);
        n := n+$100;
    end;
    Result := (ret  shr  16)  xor  ret;
end;

function namenum_hash(const n : Pointer):ulong;
begin
    Result := ossl_lh_strcasehash(PNAMENUM_ENTRY(n).name);
end;

function ossl_namemap_new:POSSL_NAMEMAP;
begin
   Result := OPENSSL_zalloc(sizeof(Result^));
   Result.namenum :=  lh_NAMENUM_ENTRY_new(namenum_hash, namenum_cmp);
   Result.lock := CRYPTO_THREAD_lock_new();
   if (Result <> nil) and (Result.lock <> nil ) and (Result.namenum <> nil) then
       Exit;

   ossl_namemap_free(Result);
   Result := nil;
end;



procedure ossl_namemap_free( namemap : POSSL_NAMEMAP);
begin
    if (namemap = nil)  or  (namemap.stored > 0) then
       exit;
    lh_NAMENUM_ENTRY_doall(namemap.namenum, namenum_free);
    lh_NAMENUM_ENTRY_free(namemap.namenum);
    CRYPTO_THREAD_lock_free(namemap.lock);
    OPENSSL_free(Pointer(namemap));
end;

procedure stored_namemap_free( vnamemap : Pointer);
var
  namemap : POSSL_NAMEMAP;
begin
    namemap := vnamemap;
    if namemap <> nil then
    begin
        { Pretend it isn't stored, or ossl_namemap_free() will do nothing }
        namemap.stored := 0;
        ossl_namemap_free(namemap);
    end;
end;

function stored_namemap_new( libctx : POSSL_LIB_CTX):Pointer;
var
  namemap : POSSL_NAMEMAP;
begin
    namemap := ossl_namemap_new();
    if namemap <> nil then
       namemap.stored := 1;
    Result := namemap;
end;

function ossl_namemap_stored( libctx : POSSL_LIB_CTX):POSSL_NAMEMAP;
var
  {$IFNDEF FIPS_MODULE}
  nms : integer;
  {$ENDIF}
  i, _end : integer;

  map: POSSL_NAMEMAP;
  namenum: POPENSSL_LHASH;
  dynidx: int;
begin
    Result := ossl_lib_ctx_get_data(libctx, OSSL_LIB_CTX_NAMEMAP_INDEX, @stored_namemap_method);
    //delphi ”Îfpc£¨ num_nodes÷µ“ª÷¬
    namenum := POPENSSL_LHASH(Result.namenum);
    if Result = nil then
       Exit(nil);
{$IFNDEF FIPS_MODULE}
    nms := Int(ossl_namemap_empty(Result));
    if nms < 0 then
    begin
        {
         * Could not get lock to make the count, so maybe internal objects
         * weren't added. This seems safest.
         }
        Exit(nil);
    end;
    if nms = 1 then
    begin
        { Before pilfering, we make sure the legacy database is populated }
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS  or OPENSSL_INIT_ADD_ALL_DIGESTS, nil);
        OBJ_NAME_do_all(OBJ_NAME_TYPE_CIPHER_METH, get_legacy_cipher_names, Result);
        //≤‚ ‘

        namenum := POPENSSL_LHASH(Result.namenum);
        OBJ_NAME_do_all(OBJ_NAME_TYPE_MD_METH, get_legacy_md_names, Result);
        { We also pilfer data from the legacy EVP_PKEY_ASN1_METHODs }

        _end := EVP_PKEY_asn1_get_count();
        for i := 0 to _end-1 do
            get_legacy_pkey_meth_names(EVP_PKEY_asn1_get0(i), Result);


    end;
{$ENDIF}

end;


end.
