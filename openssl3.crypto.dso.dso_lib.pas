unit openssl3.crypto.dso.dso_lib;

interface
uses OpenSSL.Api;

const
  DSO_CTRL_GET_FLAGS =     1;
  DSO_CTRL_SET_FLAGS =     2;
  DSO_CTRL_OR_FLAGS  =     3;


function DSO_free( dso : PDSO):integer;
function DSO_new:PDSO;
function DSO_new_method( meth : PDSO_METHOD):PDSO;
function DSO_convert_filename(dso : PDSO;{const} filename : PUTF8Char):PUTF8Char;
function DSO_ctrl( dso : PDSO; cmd : integer; larg : long; parg : Pointer):long;
function DSO_merge(dso : PDSO;const filespec1, filespec2 : PUTF8Char):PUTF8Char;
function DSO_load(dso : PDSO;{const} filename : PUTF8Char; meth : PDSO_METHOD; flags : integer):PDSO;
function DSO_set_filename(dso : PDSO;const filename : PUTF8Char):integer;
function DSO_bind_func(dso : PDSO;const symname : PUTF8Char):TDSO_FUNC_TYPE;
function DSO_get_filename( dso : PDSO):PUTF8Char;


implementation



uses
   openssl3.include.internal.refcount, openssl3.crypto.mem, OpenSSL3.Err,
   {$IFDEF MSWINDOWS} openssl3.crypto.dso.dso_win32, {$ENDIF}
   openssl3.crypto.o_str,
   openssl3.include.openssl.crypto,    OpenSSL3.threads_none;






function DSO_get_filename( dso : PDSO):PUTF8Char;
begin
    if dso = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    Result := dso.filename;
end;



function DSO_bind_func(dso : PDSO;const symname : PUTF8Char):TDSO_FUNC_TYPE;
var
  ret : TDSO_FUNC_TYPE;
begin
    ret := nil;
    if (dso = nil)  or  (symname = nil) then
    begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if not Assigned(dso.meth.dso_bind_func) then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        Exit(nil);
    end;
    ret := dso.meth.dso_bind_func(dso, symname);
    if not Assigned(ret) then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_SYM_FAILURE);
        Exit(nil);
    end;
    { Success }
    Result := ret;
end;



function DSO_set_filename(dso : PDSO;const filename : PUTF8Char):integer;
var
  copied : PUTF8Char;
begin
    if (dso = nil)  or  (filename = nil) then
    begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if dso.loaded_filename <> nil then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_DSO_ALREADY_LOADED);
        Exit(0);
    end;
    { We'll duplicate filename }
    OPENSSL_strdup(copied ,filename);
    if copied = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    OPENSSL_free(Pointer(dso.filename));
    dso.filename := copied;
    Result := 1;
end;


function DSO_load(dso : PDSO;{const} filename : PUTF8Char; meth : PDSO_METHOD; flags : integer):PDSO;
var
    ret       : PDSO;
    allocated : integer;
    label _err;

begin
    allocated := 0;
    if dso = nil then
    begin
        ret := DSO_new_method(meth);
        if ret = nil then begin
            ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
            goto _err;
        end;
        allocated := 1;
        { Pass the provided flags to the new DSO object }
        if DSO_ctrl(ret, DSO_CTRL_SET_FLAGS, flags, nil ) < 0 then
        begin
            ERR_raise(ERR_LIB_DSO, DSO_R_CTRL_FAILED);
            goto _err;
        end;
    end
    else
        ret := dso;
    { Don't load if we're currently already loaded }
    if ret.filename <> nil then begin
        ERR_raise(ERR_LIB_DSO, DSO_R_DSO_ALREADY_LOADED);
        goto _err;
    end;
    {
     * filename can only be nil if we were passed a dso that already has one
     * set.
     }
    if (filename <> nil) then
       if (0>=DSO_set_filename(ret, filename)) then
       begin
            ERR_raise(ERR_LIB_DSO, DSO_R_SET_FILENAME_FAILED);
            goto _err;
       end;
    filename := ret.filename;
    if filename = nil then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_NO_FILENAME);
        goto _err;
    end;
    if not Assigned(ret.meth.dso_load) then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        goto _err;
    end;
    if 0>=ret.meth.dso_load(ret) then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_LOAD_FAILED);
        goto _err;
    end;
    { Load succeeded }
    Exit(ret);
 _err:
    if allocated > 0 then DSO_free(ret);
    Result := nil;
end;


function DSO_merge(dso : PDSO;const filespec1, filespec2 : PUTF8Char):PUTF8Char;
begin
    result := nil;
    if (dso = nil)  or  (filespec1 = nil) then
    begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if dso.flags and DSO_FLAG_NO_NAME_TRANSLATION = 0 then
    begin
        if Assigned(dso.merger) then
            result := dso.merger(dso, filespec1, filespec2)
        else
        if Assigned(dso.meth.dso_merger) then
            result := dso.meth.dso_merger(dso, filespec1, filespec2);
    end;

end;



function DSO_ctrl( dso : PDSO; cmd : integer; larg : long; parg : Pointer):long;
begin
    if dso = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(-1);
    end;
    {
     * We should intercept certain generic commands and only pass control to
     * the method-specific ctrl function if it's something we don't handle.
     }
    case cmd of
    DSO_CTRL_GET_FLAGS:
        Exit(dso.flags);
    DSO_CTRL_SET_FLAGS:
    begin
        dso.flags := int(larg);
        Exit(0);
    end;
    DSO_CTRL_OR_FLAGS:
    begin
        dso.flags  := dso.flags  or int(larg);
        Exit(0);
    end
    else
        begin
          //break;
        end;
    end;
    if (dso.meth = nil)  or  (not Assigned(dso.meth.dso_ctrl)) then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        Exit(-1);
    end;
    Result := dso.meth.dso_ctrl(dso, cmd, larg, parg);
end;




function DSO_convert_filename(dso : PDSO;{const} filename : PUTF8Char):PUTF8Char;
begin
    result := nil;
    if dso = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if filename = nil then filename := dso.filename;
    if filename = nil then begin
        ERR_raise(ERR_LIB_DSO, DSO_R_NO_FILENAME);
        Exit(nil);
    end;
    if dso.flags and DSO_FLAG_NO_NAME_TRANSLATION  = 0 then
    begin
        if Assigned(dso.name_converter) then
            result := dso.name_converter(dso, filename)
        else
        if Assigned(dso.meth.dso_name_converter) then
            result := dso.meth.dso_name_converter(dso, filename);
    end;
    if result = nil then
    begin
        OPENSSL_strdup(result ,filename);
        if result = nil then begin
            ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end;

end;


function DSO_new_method( meth : PDSO_METHOD):PDSO;
var
  ret : PDSO;
begin
    ret := OPENSSL_zalloc(sizeof( ret^));
    if ret = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    ret.meth_data := sk_void_new_null;
    if ret.meth_data = nil then begin
        { sk_new doesn't generate any errors so we do }
        ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(Pointer(ret));
        Exit(nil);
    end;
    ret.meth := DSO_METHOD_openssl;
    ret.references := 1;
    ret.lock := CRYPTO_THREAD_lock_new;
    if ret.lock = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
        sk_void_free(ret.meth_data);
        OPENSSL_free(Pointer(ret));
        Exit(nil);
    end;
    if (Assigned(ret.meth.init))  and  (0>=ret.meth.init(ret)) then
    begin
        DSO_free(ret);
        ret := nil;
    end;
    Result := ret;
end;

function DSO_new:PDSO;
begin
    Result := DSO_new_method(nil);
end;

function DSO_free( dso : PDSO):integer;
var
  i : integer;
begin
    if dso = nil then Exit(1);
    if CRYPTO_DOWN_REF(dso.references, i, dso.lock) <= 0  then
        Exit(0);
    REF_PRINT_COUNT('DSO', dso);
    if i > 0 then Exit(1);
    REF_ASSERT_ISNT(i < 0);
    if (dso.flags and DSO_FLAG_NO_UNLOAD_ON_FREE ) = 0 then
    begin
        if (Assigned(dso.meth.dso_unload))  and   (0>= dso.meth.dso_unload(dso) )then
        begin
            ERR_raise(ERR_LIB_DSO, DSO_R_UNLOAD_FAILED);
            Exit(0);
        end;
    end;
    if ( Assigned(dso.meth.finish) ) and   (0>= dso.meth.finish(dso) )then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_FINISH_FAILED);
        Exit(0);
    end;
    sk_void_free(dso.meth_data);
    OPENSSL_free(Pointer(dso.filename));
    OPENSSL_free(Pointer(dso.loaded_filename));
    CRYPTO_THREAD_lock_free(dso.lock);
    OPENSSL_free(Pointer(dso));
    Result := 1;
end;


end.
