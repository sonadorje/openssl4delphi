unit openssl3.crypto.asn1.asn_moid;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.Api;

 procedure ASN1_add_oid_module;

function oid_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
function do_create(const value, name : PUTF8Char):integer;
procedure oid_module_finish( md : PCONF_IMODULE);

implementation
uses OpenSSL3.Err,   openssl3.crypto.mem,  openssl3.crypto.objects.obj_dat,
     OpenSSL3.openssl.conf,                openssl3.crypto.ctype,
     openssl3.crypto.conf.conf_mod,        openssl3.crypto.conf.conf_lib;




procedure oid_module_finish( md : PCONF_IMODULE);
begin

end;



function do_create(const value, name : PUTF8Char):integer;
var
  nid : integer;
  ln, ostr, p, lntmp : PUTF8Char;
begin
    lntmp := nil;
    p := strrchr(value, ',');
    if p = nil then begin
        ln := name;
        ostr := value;
    end
    else
    begin
        ln := value;
        ostr := p + 1;
        if ostr^ = #0 then Exit(0);
        while ossl_isspace( ostr^) do
            PostInc(ostr);
        while ossl_isspace( ln^) do
            PostInc(ln);
        Dec(p);
        while ossl_isspace( p^) do
        begin
            if p = ln then Exit(0);
            Dec(p);
        end;
        PostInc(p);
        lntmp := OPENSSL_malloc((p - ln) + 1);
        if lntmp = nil then
        begin
            ERR_raise(ERR_LIB_ASN1, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        memcpy(lntmp, ln, p - ln);
        lntmp[p - ln] := #0;
        ln := lntmp;
    end;
    nid := OBJ_create(ostr, name, ln);
    OPENSSL_free(lntmp);
    Result := Int(nid <> NID_undef);
end;




function oid_module_init(md : PCONF_IMODULE;const cnf : PCONF):integer;
var
  i : integer;
  sktmp : Pstack_st_CONF_VALUE;
  oval : PCONF_VALUE;
  oid_section: PUTF8Char;
begin
    oid_section := CONF_imodule_get_value(md);
    sktmp := NCONF_get_section(cnf, oid_section);
    if sktmp = nil then
    begin
        ERR_raise(ERR_LIB_ASN1, ASN1_R_ERROR_LOADING_SECTION);
        Exit(0);
    end;
    for i := 0 to sk_CONF_VALUE_num(sktmp)-1 do
    begin
        oval := sk_CONF_VALUE_value(sktmp, i);
        if 0>=do_create(oval.value, oval.name) then
        begin
            ERR_raise(ERR_LIB_ASN1, ASN1_R_ADDING_OBJECT);
            Exit(0);
        end;
    end;
    Result := 1;
end;

procedure ASN1_add_oid_module;
begin
    CONF_module_add('oid_section', oid_module_init, oid_module_finish);
end;

end.
