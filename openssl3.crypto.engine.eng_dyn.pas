unit openssl3.crypto.engine.eng_dyn;

interface
uses OpenSSL.Api;

type
  Teng_dyn_func = procedure;

  st_dynamic_data_ctx = record
    dynamic_dso     : PDSO;
    v_check         : dynamic_v_check_fn;
    bind_engine     : dynamic_bind_engine;
    DYNAMIC_LIBNAME : PUTF8Char;
    no_vcheck       : integer;
    engine_id       : PUTF8Char;
    list_add_value  : integer;
    DYNAMIC_F1,
    DYNAMIC_F2      : PUTF8Char;
    dir_load        : integer;
    dirs            : Pstack_st_OPENSSL_STRING;
  end;
  dynamic_data_ctx = st_dynamic_data_ctx;
  Pdynamic_data_ctx = ^dynamic_data_ctx;
  PPdynamic_data_ctx = ^Pdynamic_data_ctx;

const
  engine_dynamic_id: PUTF8Char = 'dynamic';
  engine_dynamic_name: PUTF8Char = 'Dynamic engine loading support';
   DYNAMIC_CMD_SO_PATH             = (ENGINE_CMD_BASE + 0);
 DYNAMIC_CMD_NO_VCHECK           = (ENGINE_CMD_BASE + 1);
 DYNAMIC_CMD_ID                  = (ENGINE_CMD_BASE + 2);
 DYNAMIC_CMD_LIST_ADD            = (ENGINE_CMD_BASE + 3);
 DYNAMIC_CMD_DIR_LOAD            = (ENGINE_CMD_BASE + 4);
 DYNAMIC_CMD_DIR_ADD             = (ENGINE_CMD_BASE + 5);
 DYNAMIC_CMD_LOAD                = (ENGINE_CMD_BASE + 6);

var dynamic_ex_data_idx:int  = -1;
procedure engine_load_dynamic_int;
function engine_dynamic:PENGINE;
function dynamic_init( e : PENGINE):integer;
function dynamic_finish( e : PENGINE):integer;
function dynamic_ctrl( e : PENGINE; cmd : integer; i : long; p : Pointer; f : Teng_ctrl_fn):integer;
function dynamic_get_data_ctx( e : PENGINE):Pdynamic_data_ctx;
procedure dynamic_data_ctx_free_func( parent, ptr : Pointer; ad : PCRYPTO_EX_DATA; idx : integer; argl : long; argp : Pointer);
procedure int_free_str( s : PUTF8Char);
function dynamic_set_data_ctx(e : PENGINE;ctx : PPdynamic_data_ctx):integer;

function dynamic_load( e : PENGINE; ctx : Pdynamic_data_ctx):integer;

function int_load( ctx : Pdynamic_data_ctx):integer;

var
  dynamic_cmd_defns :array of TENGINE_CMD_DEFN;

implementation

uses OpenSSL3.Err,
     openssl3.crypto.mem,               openssl3.crypto.stack,
     openssl3.crypto.engine.eng_lib,    openssl3.crypto.ex_data,
     openssl3.providers.fips.fipsprov,
     openssl3.crypto.o_str,             openssl3.crypto.engine.eng_list,
     openssl3.crypto.dso.dso_lib,       OpenSSL3.threads_none;




function int_load( ctx : Pdynamic_data_ctx):integer;
var
  num, loop : integer;

  s, merge : PUTF8Char;
begin
    { Unless told not to, try a direct load }
    if (ctx.dir_load <> 2)  and  (DSO_load(ctx.dynamic_dso,
                                          ctx.DYNAMIC_LIBNAME, nil,
                                          0) <> nil) then
        Exit(1);
    { If we're not allowed to use 'dirs' or we have none, fail }
    num := sk_OPENSSL_STRING_num(ctx.dirs);
    if (0>=ctx.dir_load)  or  (num  < 1) then
        Exit(0);
    for loop := 0 to num-1 do
    begin
         s := sk_OPENSSL_STRING_value(ctx.dirs, loop);
        merge := DSO_merge(ctx.dynamic_dso, ctx.DYNAMIC_LIBNAME, s);
        if nil =merge then Exit(0);
        if DSO_load(ctx.dynamic_dso, merge, nil, 0 ) <> nil then  begin
            { Found what we're looking for }
            OPENSSL_free(merge);
            Exit(1);
        end;
        OPENSSL_free(merge);
    end;
    Result := 0;
end;


function dynamic_load( e : PENGINE; ctx : Pdynamic_data_ctx):integer;
var
    cpy        : TENGINE;
    fns        : dynamic_fns;
    vcheck_res : Cardinal;
begin
    if ctx.dynamic_dso = nil then ctx.dynamic_dso := DSO_new;
    if ctx.dynamic_dso = nil then Exit(0);
    if nil =ctx.DYNAMIC_LIBNAME then
    begin
        if nil=ctx.engine_id then
            Exit(0);
        DSO_ctrl(ctx.dynamic_dso, DSO_CTRL_SET_FLAGS,
                 DSO_FLAG_NAME_TRANSLATION_EXT_ONLY, nil);
        ctx.DYNAMIC_LIBNAME := DSO_convert_filename(ctx.dynamic_dso, ctx.engine_id);
    end;
    if 0>=int_load(ctx) then  begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_DSO_NOT_FOUND);
        DSO_free(ctx.dynamic_dso);
        ctx.dynamic_dso := nil;
        Exit(0);
    end;
    { We have to find a bind function otherwise it'll always end badly }
    ctx.bind_engine := dynamic_bind_engine(DSO_bind_func(ctx.dynamic_dso,
                                             ctx.DYNAMIC_F2));
    if not Assigned(ctx.bind_engine) then
    begin
        ctx.bind_engine := nil;
        DSO_free(ctx.dynamic_dso);
        ctx.dynamic_dso := nil;
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_DSO_FAILURE);
        Exit(0);
    end;
    { Do we perform version checking? }
    if 0>=ctx.no_vcheck then begin
        vcheck_res := 0;
        {
         * Now we try to find a version checking function and decide how to
         * cope with failure if/when it fails.
         }
        ctx.v_check := dynamic_v_check_fn(DSO_bind_func(ctx.dynamic_dso,
                                               ctx.DYNAMIC_F1));
        if Assigned(ctx.v_check) then
           vcheck_res := ctx.v_check(OSSL_DYNAMIC_VERSION);
        {
         * We fail if the version checker veto'd the load *or* if it is
         * deferring to us (by returning its version) and we think it is too
         * old.
         }
        if vcheck_res < OSSL_DYNAMIC_OLDEST then
        begin
            { Fail }
            ctx.bind_engine := nil;
            ctx.v_check := nil;
            DSO_free(ctx.dynamic_dso);
            ctx.dynamic_dso := nil;
            ERR_raise(ERR_LIB_ENGINE, ENGINE_R_VERSION_INCOMPATIBILITY);
            Exit(0);
        end;
    end;
    {
     * First binary copy the ENGINE structure so that we can roll back if the
     * hand-over fails
     }
    memcpy(@cpy, e, sizeof(TENGINE));
    {
     * Provide the ERR, 'ex_data', memory, and locking callbacks so the
     * loaded library uses our state rather than its own. FIXME: As noted in
     * engine.h, much of this would be simplified if each area of code
     * provided its own 'summary' structure of all related callbacks. It
     * would also increase opaqueness.
     }
    CRYPTO_get_mem_functions(@fns.mem_fns.malloc_fn, @fns.mem_fns.realloc_fn,
                             @fns.mem_fns.free_fn);
    {
     * Now that we've loaded the dynamic engine, make sure no 'dynamic'
     * ENGINE elements will show through.
     }
    engine_set_all_null(e);
    { Try to bind the ENGINE onto our own ENGINE structure }
    if (0>=engine_add_dynamic_id(e, TENGINE_DYNAMIC_ID(ctx.bind_engine), 1))
             or  (0>=ctx.bind_engine(e, ctx.engine_id, @fns)) then
    begin
        engine_remove_dynamic_id(e, 1);
        ctx.bind_engine := nil;
        ctx.v_check := nil;
        DSO_free(ctx.dynamic_dso);
        ctx.dynamic_dso := nil;
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INIT_FAILED);
        { Copy the original ENGINE structure back }
        memcpy(e, @cpy, sizeof(TENGINE));
        Exit(0);
    end;
    { Do we try to add this ENGINE to the internal list too? }
    if ctx.list_add_value > 0 then begin
        if 0>=ENGINE_add(e) then  begin
            { Do we tolerate this or fail? }
            if ctx.list_add_value > 1 then  begin
                {
                 * Fail - NB: By this time, it's too late to rollback, and
                 * trying to do so allows the bind_engine code to have
                 * created leaks. We just have to fail where we are, after
                 * the ENGINE has changed.
                 }
                ERR_raise(ERR_LIB_ENGINE, ENGINE_R_CONFLICTING_ENGINE_ID);
                Exit(0);
            end;
            { Tolerate }
            ERR_clear_error;
        end;
    end;
    Result := 1;
end;



function dynamic_set_data_ctx(e : PENGINE;ctx : PPdynamic_data_ctx):integer;
var
  c : Pdynamic_data_ctx;
  ret : integer;
  label _end;
begin
    c := OPENSSL_zalloc(sizeof( c^));
    ret := 0;
    if c = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    c.dirs := sk_OPENSSL_STRING_new_null;
    if c.dirs = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
        goto _end;
    end;
    c.DYNAMIC_F1 := 'v_check';
    c.DYNAMIC_F2 := 'bind_engine';
    c.dir_load := 1;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock) then
        goto _end;
    ctx^ := Pdynamic_data_ctx(ENGINE_get_ex_data(e, dynamic_ex_data_idx));
    if (ctx = nil) then
    begin
        { Good, we're the first }
        ret := ENGINE_set_ex_data(e, dynamic_ex_data_idx, c);
        if ret > 0 then
        begin
            ctx^ := c;
            c := nil;
        end;
    end;
    CRYPTO_THREAD_unlock(global_engine_lock);
    ret := 1;
    {
     * If we lost the race to set the context, c is non-nil and *ctx is the
     * context of the thread that won.
     }
_end:
    if c <> nil then sk_OPENSSL_STRING_free(c.dirs);
    OPENSSL_free(c);
    Result := ret;
end;


procedure int_free_str( s : PUTF8Char);
begin
    OPENSSL_free(s);
end;




procedure dynamic_data_ctx_free_func( parent, ptr : Pointer; ad : PCRYPTO_EX_DATA; idx : integer; argl : long; argp : Pointer);
var
  ctx : Pdynamic_data_ctx;
begin
    if ptr <> nil then
    begin
        ctx := Pdynamic_data_ctx (ptr);
        DSO_free(ctx.dynamic_dso);
        OPENSSL_free(ctx.DYNAMIC_LIBNAME);
        OPENSSL_free(ctx.engine_id);
        sk_OPENSSL_STRING_pop_free(ctx.dirs, int_free_str);
        OPENSSL_free(ctx);
    end;
end;



function dynamic_get_data_ctx( e : PENGINE):Pdynamic_data_ctx;
var
  ctx : Pdynamic_data_ctx;
  new_idx : integer;
begin
    if dynamic_ex_data_idx < 0 then
    begin
        {
         * Create and register the ENGINE ex_data, and associate our 'free'
         * function with it to ensure any allocated contexts get freed when
         * an ENGINE goes underground.
         }
        new_idx := CRYPTO_get_ex_new_index(10, 0, nil, nil, nil, dynamic_data_ctx_free_func);
        //ENGINE_get_ex_new_index(0, nil, nil, nil,
          //                                    dynamic_data_ctx_free_func);
        if new_idx = -1 then
        begin
            ERR_raise(ERR_LIB_ENGINE, ENGINE_R_NO_INDEX);
            Exit(nil);
        end;
        if 0>=CRYPTO_THREAD_write_lock(global_engine_lock) then
            Exit(nil);
        { Avoid a race by checking again inside this lock }
        if dynamic_ex_data_idx < 0 then
        begin
            { Good, someone didn't beat us to it }
            dynamic_ex_data_idx := new_idx;
            new_idx := -1;
        end;
        CRYPTO_THREAD_unlock(global_engine_lock);
        {
         * In theory we could 'give back' the index here if (new_idx>-1), but
         * it's not possible and wouldn't gain us much if it were.
         }
    end;
    ctx := Pdynamic_data_ctx (ENGINE_get_ex_data(e, dynamic_ex_data_idx));
    { Check if the context needs to be created }
    if (ctx = nil) and  (0>=dynamic_set_data_ctx(e, @ctx)) then
        { 'set_data' will set errors if necessary }
        Exit(nil);
    Result := ctx;
end;


function dynamic_ctrl( e : PENGINE; cmd : integer; i : long; p : Pointer; f : Teng_ctrl_fn):integer;
var
    ctx         : Pdynamic_data_ctx;
    initialised : integer;
    tmp_str     : PUTF8Char;
begin
    ctx := dynamic_get_data_ctx(e);
    if nil =ctx then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_NOT_LOADED);
        Exit(0);
    end;
    initialised := get_result((ctx.dynamic_dso = nil) , 0 , 1);
    { All our control commands require the ENGINE to be uninitialised }
    if initialised > 0 then begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_ALREADY_LOADED);
        Exit(0);
    end;
    case cmd of
        DYNAMIC_CMD_SO_PATH:
        begin
            { a nil 'p' or a string of zero-length is the same thing }
            if (p <> nil)  and  (Length(PUTF8Char(p)) < 1) then
                p := nil;
            OPENSSL_free(ctx.DYNAMIC_LIBNAME);
            if p <> nil then
               OPENSSL_strdup(ctx.DYNAMIC_LIBNAME, p)
            else
                ctx.DYNAMIC_LIBNAME := nil;
            Exit(get_result(ctx.DYNAMIC_LIBNAME <> nil, 1 , 0));
        end;
        DYNAMIC_CMD_NO_VCHECK:
        begin
            ctx.no_vcheck := get_result((i = 0) , 0 , 1);
            Exit(1);
        end;
        DYNAMIC_CMD_ID:
        begin
            { a nil 'p' or a string of zero-length is the same thing }
            if (p <> nil)  and  (Length(PUTF8Char(p)) < 1) then
                p := nil;
            OPENSSL_free(ctx.engine_id);
            if p <> nil then
               OPENSSL_strdup(ctx.engine_id ,p)
            else
                ctx.engine_id := nil;
            Exit(get_result(ctx.engine_id <>nil, 1 , 0));
        end;
        DYNAMIC_CMD_LIST_ADD:
        begin
            if (i < 0)  or  (i > 2) then
            begin
                ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_ARGUMENT);
                Exit(0);
            end;
            ctx.list_add_value := int(i);
            Exit(1);
        end;
        DYNAMIC_CMD_LOAD:
            Exit(dynamic_load(e, ctx));
        DYNAMIC_CMD_DIR_LOAD:
        begin
            if (i < 0)  or  (i > 2) then
            begin
                ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_ARGUMENT);
                Exit(0);
            end;
            ctx.dir_load := int(i);
            Exit(1);
        end;
        DYNAMIC_CMD_DIR_ADD:
        begin
            { a nil 'p' or a string of zero-length is the same thing }
            if (p = nil)  or  (Length(PUTF8Char(p)) < 1) then
            begin
                ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_ARGUMENT);
                Exit(0);
            end;
            begin
                OPENSSL_strdup(tmp_str ,p);
                if tmp_str = nil then
                begin
                    ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
                    Exit(0);
                end;
                if 0>=sk_OPENSSL_STRING_push(ctx.dirs, tmp_str) then
                begin
                    OPENSSL_free(tmp_str);
                    ERR_raise(ERR_LIB_ENGINE, ERR_R_MALLOC_FAILURE);
                    Exit(0);
                end;
            end;
            Exit(1);
        end
        else
        begin
           //break;
        end;
    end;
    ERR_raise(ERR_LIB_ENGINE, ENGINE_R_CTRL_COMMAND_NOT_IMPLEMENTED);
    Result := 0;
end;




function dynamic_finish( e : PENGINE):integer;
begin
    {
     * This should never be called on account of 'dynamic_init' always
     * failing.
     }
    Result := 0;
end;

function dynamic_init( e : PENGINE):integer;
begin
    {
     * We always return failure - the 'dynamic' engine itself can't be used
     * for anything.
     }
    Result := 0;
end;

function engine_dynamic:PENGINE;
var
  ret : PENGINE;
begin
    ret := ENGINE_new;
    if ret = nil then Exit(nil);
    if (0>=ENGINE_set_id(ret, engine_dynamic_id))  or
         (0>= ENGINE_set_name(ret, engine_dynamic_name))  or
         (0>= ENGINE_set_init_function(ret, dynamic_init))  or
         (0>= ENGINE_set_finish_function(ret, dynamic_finish))  or
         (0>= ENGINE_set_ctrl_function(ret, dynamic_ctrl))  or
         (0>= ENGINE_set_flags(ret, ENGINE_FLAGS_BY_ID_COPY))  or
         (0>= ENGINE_set_cmd_defns(ret, @dynamic_cmd_defns)) then
    begin
        ENGINE_free(ret);
        Exit(nil);
    end;
    Result := ret;
end;



procedure engine_load_dynamic_int;
var
  toadd : PENGINE;
begin
    toadd := engine_dynamic;
    if nil =toadd then exit;
    ERR_set_mark;
    ENGINE_add(toadd);
    {
     * If the 'add' worked, it gets a structural reference. So either way, we
     * release our just-created reference.
     }
    ENGINE_free(toadd);
    {
     * If the 'add' didn't work, it was probably a conflict because it was
     * already added (eg. someone calling ENGINE_load_blah then calling
     * ENGINE_load_builtin_engines perhaps).
     }
    ERR_pop_to_mark;
end;

initialization
   dynamic_cmd_defns := [
    get_ENGINE_CMD_DEFN(DYNAMIC_CMD_SO_PATH,
     'SO_PATH',
     'Specifies the path to the new ENGINE shared library',
     ENGINE_CMD_FLAG_STRING),
    get_ENGINE_CMD_DEFN(DYNAMIC_CMD_NO_VCHECK,
     'NO_VCHECK',
     'Specifies to continue even if version checking fails (boolean)',
     ENGINE_CMD_FLAG_NUMERIC),
    get_ENGINE_CMD_DEFN(DYNAMIC_CMD_ID,
     'ID',
     'Specifies an ENGINE id name for loading',
     ENGINE_CMD_FLAG_STRING),
    get_ENGINE_CMD_DEFN(DYNAMIC_CMD_LIST_ADD,
     'LIST_ADD',
     'Whether to add a loaded ENGINE to the internal list (0=no,1=yes,2=mandatory)',
     ENGINE_CMD_FLAG_NUMERIC),
    get_ENGINE_CMD_DEFN(DYNAMIC_CMD_DIR_LOAD,
     'DIR_LOAD',
     'Specifies whether to load from ''DIR_ADD'' directories (0=no,1=yes,2=mandatory)',
     ENGINE_CMD_FLAG_NUMERIC),
    get_ENGINE_CMD_DEFN(DYNAMIC_CMD_DIR_ADD,
     'DIR_ADD',
     'Adds a directory from which ENGINEs can be loaded',
     ENGINE_CMD_FLAG_STRING),
    get_ENGINE_CMD_DEFN(DYNAMIC_CMD_LOAD,
     'LOAD',
     'Load up the ENGINE specified by other settings',
     ENGINE_CMD_FLAG_NO_INPUT),
    get_ENGINE_CMD_DEFN(0, nil, nil, 0)
];

end.
