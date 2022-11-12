unit openssl3.crypto.engine.eng_ctrl;

interface
uses OpenSSL.Api;


function ENGINE_ctrl_cmd_string(e : PENGINE;const cmd_name, arg : PUTF8Char; cmd_optional : integer):integer;
 function ENGINE_ctrl( e : PENGINE; cmd : integer; i : long; p : Pointer; f : Teng_ctrl_fn):integer;
function int_ctrl_helper( e : PENGINE; cmd : integer; i : long; p : Pointer; f : Teng_ctrl_fn):integer;
function int_ctrl_cmd_by_name({const} defn : PENGINE_CMD_DEFN;const s : PUTF8Char):integer;
 function int_ctrl_cmd_is_null(const defn : PENGINE_CMD_DEFN):integer;
 function int_ctrl_cmd_by_num({const} defn : PENGINE_CMD_DEFN; num : uint32):integer;
 function ENGINE_cmd_is_executable( e : PENGINE; cmd : integer):integer;

var
  int_no_description: PUTF8Char = '';

implementation
uses openssl3.err, OpenSSL3.threads_none, openssl3.crypto.engine.eng_lib;






function ENGINE_cmd_is_executable( e : PENGINE; cmd : integer):integer;
var
  flags : integer;
begin
    flags := ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, cmd, nil, nil);
    if (flags < 0)  then begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_CMD_NUMBER);
        Exit(0);
    end;
    if ( 0>= flags and ENGINE_CMD_FLAG_NO_INPUT)  and
       ( 0>= flags and ENGINE_CMD_FLAG_NUMERIC)  and
       ( 0>= flags and ENGINE_CMD_FLAG_STRING) then
        Exit(0);
    Result := 1;
end;



function int_ctrl_cmd_by_num({const} defn : PENGINE_CMD_DEFN; num : uint32):integer;
var
  idx : integer;
begin
    idx := 0;
    {
     * NB: It is stipulated that 'cmd_defn' lists are ordered by cmd_num. So
     * our searches don't need to take any longer than necessary.
     }
    while (0>=int_ctrl_cmd_is_null(defn))  and  (defn.cmd_num < num) do  begin
        PostInc(idx);
        Inc(defn);
    end;
    if defn.cmd_num = num then Exit(idx);
    { The given cmd_num wasn't found }
    Result := -1;
end;


function int_ctrl_cmd_is_null(const defn : PENGINE_CMD_DEFN):integer;
begin
    if (defn.cmd_num = 0) or  (defn.cmd_name = nil) then
        Exit(1);
    Result := 0;
end;


function int_ctrl_cmd_by_name({const} defn : PENGINE_CMD_DEFN;const s : PUTF8Char):integer;
var
  idx : integer;
begin
    idx := 0;
    while (0>=int_ctrl_cmd_is_null(defn))  and  (strcmp(defn.cmd_name, s) <> 0) do
    begin
        Inc(idx);
        Inc(defn);
    end;
    if int_ctrl_cmd_is_null(defn) > 0 then
        { The given name wasn't found }
        Exit(-1);
    Result := idx;
end;




function int_ctrl_helper( e : PENGINE; cmd : integer; i : long; p : Pointer; f : Teng_ctrl_fn):integer;
var
  idx : integer;
  s : PUTF8Char;
  cdp : PENGINE_CMD_DEFN;
begin
{$POINTERMATH ON}
    s := PUTF8Char( p);
    { Take care of the easy one first (eg. it requires no searches) }
    if cmd = ENGINE_CTRL_GET_FIRST_CMD_TYPE then begin
        if (e.cmd_defns = nil)  or  (int_ctrl_cmd_is_null(e.cmd_defns) > 0) then
            Exit(0);
        Exit(e.cmd_defns.cmd_num);
    end;
    { One or two commands require that 'p' be a valid string buffer }
    if (cmd = ENGINE_CTRL_GET_CMD_FROM_NAME)  or
        (cmd = ENGINE_CTRL_GET_NAME_FROM_CMD)  or
        (cmd = ENGINE_CTRL_GET_DESC_FROM_CMD)  then
    begin
        if s = nil then  begin
            ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
            Exit(-1);
        end;
    end;
    { Now handle cmd_name . cmd_num conversion }
    if cmd = ENGINE_CTRL_GET_CMD_FROM_NAME then
    begin
        idx := int_ctrl_cmd_by_name(e.cmd_defns, s);
        if (e.cmd_defns = nil) or  (idx < 0)  then
        begin
            ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_CMD_NAME);
            Exit(-1);
        end;
        Exit(e.cmd_defns[idx].cmd_num);
    end;
    {
     * For the rest of the commands, the 'long' argument must specify a valid
     * command number - so we need to conduct a search.
     }
    idx := int_ctrl_cmd_by_num(e.cmd_defns, uint32(i));
    if (e.cmd_defns = nil) or  (idx  < 0) then
    begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_CMD_NUMBER);
        Exit(-1);
    end;
    { Now the logic splits depending on command type }
    cdp := @e.cmd_defns[idx];
    case cmd of
        ENGINE_CTRL_GET_NEXT_CMD_TYPE:
        begin
            Inc(cdp);
            Exit(get_result(int_ctrl_cmd_is_null(cdp) > 0 , 0 , cdp.cmd_num));
        end;
        ENGINE_CTRL_GET_NAME_LEN_FROM_CMD:
            Exit(Length(cdp.cmd_name));
        ENGINE_CTRL_GET_NAME_FROM_CMD:
            Exit(Length(strcpy(s, cdp.cmd_name)));
        ENGINE_CTRL_GET_DESC_LEN_FROM_CMD:
            Exit(Length(get_result(cdp.cmd_desc = nil , int_no_description
                                                , cdp.cmd_desc)));
        ENGINE_CTRL_GET_DESC_FROM_CMD:
            Exit(Length(strcpy(s, get_result(cdp.cmd_desc = nil , int_no_description
                                                          , cdp.cmd_desc))));
        ENGINE_CTRL_GET_CMD_FLAGS:
            Exit(cdp.cmd_flags);
    end;
    { Shouldn't really be here ... }
    ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR);
    Result := -1;
{$POINTERMATH OFF}
end;



function ENGINE_ctrl( e : PENGINE; cmd : integer; i : long; p : Pointer; f : Teng_ctrl_fn):integer;
var
  ctrl_exists,
  ref_exists  : integer;
begin
    if e = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if 0>=CRYPTO_THREAD_write_lock(global_engine_lock) then
        Exit(0);
    ref_exists := get_result((e.struct_ref > 0) , 1 , 0);
    CRYPTO_THREAD_unlock(global_engine_lock);
    ctrl_exists := get_result(not Assigned(e.ctrl) , 0 , 1);
    if 0>=ref_exists then begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_NO_REFERENCE);
        Exit(0);
    end;
    {
     * Intercept any 'root-level' commands before trying to hand them on to
     * ctrl handlers.
     }
    case cmd of
        ENGINE_CTRL_HAS_CTRL_FUNCTION:
            Exit(ctrl_exists);
        ENGINE_CTRL_GET_FIRST_CMD_TYPE,
        ENGINE_CTRL_GET_NEXT_CMD_TYPE,
        ENGINE_CTRL_GET_CMD_FROM_NAME,
        ENGINE_CTRL_GET_NAME_LEN_FROM_CMD,
        ENGINE_CTRL_GET_NAME_FROM_CMD,
        ENGINE_CTRL_GET_DESC_LEN_FROM_CMD,
        ENGINE_CTRL_GET_DESC_FROM_CMD,
        ENGINE_CTRL_GET_CMD_FLAGS:
        begin
            if (ctrl_exists > 0) and  (0>=(e.flags and ENGINE_FLAGS_MANUAL_CMD_CTRL) ) then
                Exit(int_ctrl_helper(e, cmd, i, p, f));
            if 0>=ctrl_exists then begin
                ERR_raise(ERR_LIB_ENGINE, ENGINE_R_NO_CONTROL_FUNCTION);
                {
                 * For these cmd-related functions, failure is indicated by a -1
                 * return value (because 0 is used as a valid return in some
                 * places).
                 }
                Exit(-1);
            end;
        end
        else
        begin
          //break;
        end;
    end;
    { Anything else requires a ctrl handler to exist. }
    if 0>=ctrl_exists then begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_NO_CONTROL_FUNCTION);
        Exit(0);
    end;
    Result := e.ctrl(e, cmd, i, p, f);
end;

function ENGINE_ctrl_cmd_string(e : PENGINE;const cmd_name, arg : PUTF8Char; cmd_optional : integer):integer;
var
  num, flags : integer;
  l : long;
  ptr : PUTF8Char;
begin
    if (e = nil)  or  (cmd_name = nil) then begin
        ERR_raise(ERR_LIB_ENGINE, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;

    num := ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FROM_NAME, 0, Pointer(cmd_name), nil);
    if (not Assigned(e.ctrl)) or  (num <= 0) then
    begin
        {
         * If the command didn't *have* to be supported, we fake success.
         * This allows certain settings to be specified for multiple ENGINEs
         * and only require a change of ENGINE id (without having to
         * selectively apply settings). Eg. changing from a hardware device
         * back to the regular software ENGINE without editing the config
         * file, etc.
         }
        if cmd_optional > 0 then  begin
            ERR_clear_error;
            Exit(1);
        end;
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INVALID_CMD_NAME);
        Exit(0);
    end;
    if 0>=ENGINE_cmd_is_executable(e, num) then  begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_CMD_NOT_EXECUTABLE);
        Exit(0);
    end;
    flags := ENGINE_ctrl(e, ENGINE_CTRL_GET_CMD_FLAGS, num, nil, nil);
    if flags < 0 then begin
        {
         * Shouldn't happen, given that ENGINE_cmd_is_executable returned
         * success.
         }
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR);
        Exit(0);
    end;
    {
     * If the command takes no input, there must be no input. And vice versa.
     }
    if flags and ENGINE_CMD_FLAG_NO_INPUT > 0 then
    begin
        if arg <> nil then  begin
            ERR_raise(ERR_LIB_ENGINE, ENGINE_R_COMMAND_TAKES_NO_INPUT);
            Exit(0);
        end;
        {
         * We deliberately force the result of ENGINE_ctrl to 0 or 1 rather
         * than returning it as 'return data'. This is to ensure usage of
         * these commands is consistent across applications and that certain
         * applications don't understand it one way, and others another.
         }
        if ENGINE_ctrl(e, num, 0, Pointer(arg), nil) > 0  then
            Exit(1);
        Exit(0);
    end;
    { So, we require input }
    if arg = nil then begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_COMMAND_TAKES_INPUT);
        Exit(0);
    end;
    { If it takes string input, that's easy }
    if flags and ENGINE_CMD_FLAG_STRING > 0 then begin
        { Same explanation as above }
        if ENGINE_ctrl(e, num, 0, Pointer(arg), nil) > 0 then
            Exit(1);
        Exit(0);
    end;
    {
     * If it doesn't take numeric either, then it is unsupported for use in a
     * config-setting situation, which is what this function is for. This
     * should never happen though, because ENGINE_cmd_is_executable was
     * used.
     }
    if 0>=(flags and ENGINE_CMD_FLAG_NUMERIC) then  begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_INTERNAL_LIST_ERROR);
        Exit(0);
    end;
    l := strtol(arg, @ptr, 10);
    if (arg = ptr)   or  ( ptr^ <> #0) then  begin
        ERR_raise(ERR_LIB_ENGINE, ENGINE_R_ARGUMENT_IS_NOT_A_NUMBER);
        Exit(0);
    end;
    {
     * Force the result of the control command to 0 or 1, for the reasons
     * mentioned before.
     }
    if ENGINE_ctrl(e, num, l, nil, nil) > 0  then
        Exit(1);
    Result := 0;
end;

end.
