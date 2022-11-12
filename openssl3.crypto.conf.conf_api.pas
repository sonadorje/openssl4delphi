unit openssl3.crypto.conf.conf_api;

interface
uses OpenSSL.Api, SysUtils;

{$RangeChecks On}
type
   TLH_CONF_VALUE = lhash_st_CONF_VALUE;
   PLH_CONF_VALUE = Plhash_st_CONF_VALUE;
   Tconf_api_fn = procedure (const p1 : PCONF_VALUE; p2 : PLH_CONF_VALUE);

function _CONF_get_string(const conf : PCONF; section, name : PUTF8Char):PUTF8Char;
function _CONF_new_data( conf : PCONF):integer;
function conf_value_hash(const v : PCONF_VALUE):Cardinal;
function conf_value_cmp(const a, b : PCONF_VALUE):integer;
function _CONF_new_section(conf : PCONF;const section : PUTF8Char):PCONF_VALUE;
function _CONF_get_section(const conf : PCONF; section : PUTF8Char):PCONF_VALUE;
function _CONF_add_string( conf : PCONF; section, value : PCONF_VALUE):integer;
procedure _CONF_free_data( conf : PCONF);
procedure lh_CONF_VALUE_doall_LH_CONF_VALUE( lh : Plhash_st_CONF_VALUE; fn : Tconf_api_fn; arg : PLH_CONF_VALUE);
procedure value_free_hash(const a : PCONF_VALUE; conf : PLH_CONF_VALUE{Plhash_st_CONF_VALUE});
procedure value_free_stack_doall( a : PCONF_VALUE);
function _CONF_get_section_values(const conf : PCONF; section : PUTF8Char):Pstack_st_CONF_VALUE;

implementation
uses openssl3.crypto.getenv,              OpenSSL3.openssl.conf,
     openssl3.crypto.lhash,                openssl3.crypto.mem,
     openssl3.crypto.o_str;


function _CONF_get_section_values(const conf : PCONF; section : PUTF8Char):Pstack_st_CONF_VALUE;
var
  v : PCONF_VALUE;
begin
    v := _CONF_get_section(conf, section);
    if v = nil then Exit(nil);
    Result := Pstack_st_CONF_VALUE (v.value);
end;



procedure value_free_stack_doall( a : PCONF_VALUE);
var
  vv : PCONF_VALUE;
  sk : Pstack_st_CONF_VALUE;
  i : integer;
begin
    if a.name <> nil then
       exit;
    sk := Pstack_st_CONF_VALUE  (a.value);
    for i := sk_CONF_VALUE_num(sk) - 1 downto 0 do
    begin
        vv := sk_CONF_VALUE_value(sk, i);
        //Writeln('vv.name: ', vv.name, '  vv.value: ', vv.value, ', i=', i);
        try
          OPENSSL_free(vv.value);
          OPENSSL_free(vv.name);
          OPENSSL_free(vv);
        except on E: exception do
          Writeln('openssl3.crypto.conf.conf_api.value_free_stack_doall: ' + E.Message);
        end;
    end;
    sk_CONF_VALUE_free(sk);
    OPENSSL_free(a.section);
    OPENSSL_free(a);
end;


procedure value_free_hash(const a : PCONF_VALUE; conf : PLH_CONF_VALUE{Plhash_st_CONF_VALUE});
begin
    if a.name <> nil then
       lh_CONF_VALUE_delete((conf), a);
end;

procedure lh_CONF_VALUE_doall_LH_CONF_VALUE( lh : Plhash_st_CONF_VALUE; fn : Tconf_api_fn; arg : PLH_CONF_VALUE);
begin
   OPENSSL_LH_doall_arg(POPENSSL_LHASH(lh), TOPENSSL_LH_DOALL_FUNCARG(fn), Pointer( arg));
end;


procedure _CONF_free_data( conf : PCONF);
begin
    if conf = nil then exit;
    OPENSSL_free(Pointer(conf.includedir));
    if conf.data = nil then exit;
    { evil thing to make sure the 'OPENSSL_free()' works as expected }
    lh_CONF_VALUE_set_down_load(conf.data, 0);
    lh_CONF_VALUE_doall_LH_CONF_VALUE(conf.data, value_free_hash, conf.data);
    {
     * We now have only 'section' entries in the hash table. Due to problems
     * with
     }
    lh_CONF_VALUE_doall(conf.data, value_free_stack_doall);
    lh_CONF_VALUE_free(conf.data);
end;


function _CONF_add_string( conf : PCONF; section, value : PCONF_VALUE):integer;
var
  v : PCONF_VALUE;
  ts : Pstack_st_CONF_VALUE;
begin
    v := nil;
    ts := Pstack_st_CONF_VALUE(section.value);
    value.section := section.section;
    if 0>= sk_CONF_VALUE_push(ts, value) then
        Exit(0);
    v := lh_CONF_VALUE_insert(conf.data, value);
    if v <> nil then
    begin
        sk_CONF_VALUE_delete_ptr(ts, v);
        OPENSSL_free(Pointer(v.name));
        OPENSSL_free(Pointer(v.value));
        OPENSSL_free(Pointer(v));
    end;
    Result := 1;
end;

function _CONF_get_section(const conf : PCONF; section : PUTF8Char):PCONF_VALUE;
var
  vv : TCONF_VALUE;
begin
    if (conf = nil)  or  (section = nil) then Exit(nil);
    vv.name := nil;
    vv.section := PUTF8Char(section);
    if conf.data <> nil then
       Result :=  lh_CONF_VALUE_retrieve(conf.data, @vv)
    else
       Result := nil;
end;

function _CONF_new_section(conf : PCONF;const section : PUTF8Char):PCONF_VALUE;
var
  sk : Pstack_st_CONF_VALUE;
  i : integer;
  v: PCONF_VALUE;
  vv : PCONF_VALUE;
  label _err;
begin
    sk := nil;
    v := nil;
    sk := sk_CONF_VALUE_new_null();
    if sk = nil then
        goto _err ;

    v := OPENSSL_malloc(sizeof(v^));
    if v = nil then
        goto _err ;
    //i := strlen(section) + Char_Size;

    OPENSSL_strdup(v.section, section);
    if v.section = nil then
        goto _err ;
    {memcpy(v.section, section, i);}
    v.name := nil;
    v.value := PUTF8Char(sk);
    vv := lh_CONF_VALUE_insert(conf.data, v);
    if (vv <> nil)  or  (lh_CONF_VALUE_error(conf.data) > 0)  then
        goto _err ;
    Exit(v);

 _err:
    sk_CONF_VALUE_free(sk);
    if v <> nil then
       OPENSSL_free(v.section);
    OPENSSL_free(v);
    Result := nil;
end;



function conf_value_cmp(const a, b : PCONF_VALUE):integer;
var
  i : integer;
begin
    if a.section <> b.section then
    begin
        i := strcmp(a.section, b.section);
        if i <> 0 then Exit(i);
    end;
    if (a.name <> nil)  and  (b.name <> nil) then
       Exit(strcmp(a.name, b.name));
    if a.name = b.name then Exit(0);
    Result := get_result(a.name = nil , -1 , 1);
end;

function conf_value_hash(const v : PCONF_VALUE):Cardinal;
begin
    Result := (OPENSSL_LH_strhash(v.section) shl  2)  xor  OPENSSL_LH_strhash(v.name);
end;


function _CONF_new_data( conf : PCONF):integer;
begin
    if conf = nil then Exit(0);
    if conf.data = nil then
    begin
        conf.data := lh_CONF_VALUE_new(conf_value_hash, conf_value_cmp);
        if conf.data = nil then
           Exit(0);
    end;
    Result := 1;
end;

function _CONF_get_string(const conf : PCONF; section, name : PUTF8Char):PUTF8Char;
var
  v : PCONF_VALUE;
  vv : TCONF_VALUE;
  p : PUTF8Char;
  s: AnsiString;
begin
    if name = nil then Exit(nil);
    if conf = nil then Exit(ossl_safe_getenv(name));
    if conf.data = nil then Exit(nil);
    if section <> nil then
    begin
        vv.name := (name);
        vv.section := (section);
        v := lh_CONF_VALUE_retrieve(conf.data, @vv);
        if v <> nil then
        begin
          //s := v.value;
          Exit(v.value);
        end;
        if strcmp(section, PUTF8Char('ENV')) = 0   then
        begin
            p := ossl_safe_getenv(name);
            if p <> nil then Exit(p);
        end;
    end;
    vv.section := 'default' ;
    vv.name := (name);
    v := lh_CONF_VALUE_retrieve(conf.data, @vv);
    if v = nil then Exit(nil);
    Result := v.value;
end;


end.
