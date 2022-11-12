unit openssl3.crypto.dso.dso_win32;

interface
uses OpenSSL.Api, types,
     {$IFNDEF FPC} Winapi.TlHelp32, Winapi.Windows,
     {$ELSE} jwawindows, windows,
     {$ENDIF}

     SysUtils;

type
TCREATETOOLHELP32SNAPSHOT = function (p1: DWORD; p2: DWORD): THANDLE stdcall;
TCLOSETOOLHELP32SNAPSHOT = function (p1: THANDLE): LongBool stdcall;
TMODULE32                = function(p1: THANDLE; p2: PMODULEENTRY32): Boolean stdcall;
HINSTANCE = THandle;
PHINSTANCE = ^HINSTANCE;

file_st = record
    node      : PUTF8Char;
    nodelen   : integer;
    device    : PUTF8Char;
    devicelen : integer;
    predir    : PUTF8Char;
    predirlen : integer;
    dir       : PUTF8Char;
    dirlen    : integer;
    &file     : PUTF8Char;
    filelen   : integer;
end;
Pfile_st = ^file_st;

const
  DLLNAME = 'KERNEL32.DLL';

function DSO_METHOD_openssl:PDSO_METHOD;
function win32_load( dso : PDSO):integer;
function win32_unload( dso : PDSO):integer;
function win32_bind_func(dso : PDSO;const symname : PUTF8Char):TDSO_FUNC_TYPE;
function win32_name_converter(dso : PDSO;const filename : PUTF8Char):PUTF8Char;
  function openssl_strnchr(const &string : PUTF8Char; c : integer; len : size_t):PUTF8Char;
function win32_merger(dso : PDSO;const filespec1, filespec2 : PUTF8Char):PUTF8Char;
function win32_pathbyaddr( addr : Pointer; path : PUTF8Char; sz : integer):integer;
function win32_globallookup(const name : PUTF8Char):Pointer;

var
   dso_meth_win32: TDSO_METHOD = (
    name: 'OpenSSL ''win32'' shared library method';
    dso_load: win32_load;
    dso_unload: win32_unload;
    dso_bind_func: win32_bind_func;
    dso_ctrl: nil;                      // ctrl *)
    dso_name_converter : win32_name_converter;
    dso_merger: win32_merger;
    init: nil;                      // init *)
    finish: nil;                      // finish *)
    pathbyaddr: win32_pathbyaddr;          // pathbyaddr *)
    globallookup: win32_globallookup
);



function win32_splitter(dso : PDSO;{const} filename : PUTF8Char; assume_last_is_dir : integer):Pfile_st;
 function win32_joiner(dso : PDSO;const file_split : Pfile_st):PUTF8Char;

implementation

uses OpenSSL3.Err, openssl3.crypto.o_str, openssl3.crypto.mem,
     openssl3.crypto.dso.dso_lib, openssl3.include.openssl.crypto;





function win32_joiner(dso : PDSO;const file_split : Pfile_st):PUTF8Char;
var
  len, offset : integer;
  start, _end : PUTF8Char;
begin
    len := 0; offset := 0;
    result := nil;
    if nil =file_split then
    begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if file_split.node <> nil then
    begin
        len  := len + (2 + file_split.nodelen);
        if (file_split.predir <> nil)  or  (file_split.dir <> nil)  or  (file_split.&file <> nil) then
           PostInc(len);
    end
    else
    if (file_split.device <> nil) then
    begin
        len  := len + (file_split.devicelen + 1);
    end;
    len  := len + file_split.predirlen;
    if (file_split.predir <> nil)  and
       ( (file_split.dir <> nil)  or  (file_split.&file <> nil) ) then
    begin
        PostInc(len);
    end;
    len  := len + file_split.dirlen;
    if (file_split.dir <> nil) and  (file_split.&file <> nil) then
    begin
        PostInc(len);
    end;
    len  := len + file_split.filelen;
    if 0>=len then begin
        ERR_raise(ERR_LIB_DSO, DSO_R_EMPTY_FILE_STRUCTURE);
        Exit(nil);
    end;
    result := OPENSSL_malloc(len + 1);
    if result = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;

     if file_split.node <> nil then
     begin
        strcpy(@result[offset], '\\');
        offset  := offset + 2;
        strncpy(@result[offset], file_split.node, file_split.nodelen);
        offset  := offset + file_split.nodelen;
        if (file_split.predir <> nil)  or  (file_split.dir <> nil)  or  (file_split.&file <> nil) then
        begin
            result[offset] := '\';
            PostInc(offset);
        end;
    end
    else
    if (file_split.device<> nil) then
    begin
        strncpy(@result[offset], file_split.device, file_split.devicelen);
        offset  := offset + file_split.devicelen;
        result[offset] := ':';
        PostInc(offset);
    end;
    start := file_split.predir;
    while file_split.predirlen > (start - file_split.predir) do
    begin
       _end := openssl_strnchr(start, Ord('/'),
                                          file_split.predirlen - (start -
                                                                   file_split.predir));
        if nil = _end then
           _end := start
                + file_split.predirlen - (start - file_split.predir);
        strncpy(@result[offset], start, _end - start);
        offset  := offset + (int(_end - start));
        result[offset] := '\';
        PostInc(offset);
        start := _end + 1;
    end;
    start := file_split.dir;
    while file_split.dirlen > (start - file_split.dir) do
    begin
        _end := openssl_strnchr(start, Ord('/'),
                                          file_split.dirlen - (start -
                                                                file_split.dir));
        if nil =_end then
           _end := start + file_split.dirlen - (start - file_split.dir);
        strncpy(@result[offset], start, _end - start);
        offset  := offset + (int(_end - start));
        result[offset] := '\';
        PostInc(offset);
        start := _end + 1;
    end;
    strncpy(@result[offset], file_split.&file, file_split.filelen);
    offset  := offset + file_split.filelen;
    result[offset] := #0;
    Exit(result);
end;



function win32_splitter(dso : PDSO;{const} filename : PUTF8Char; assume_last_is_dir : integer):Pfile_st;
type
  Tposition = (IN_NODE, IN_DEVICE, IN_FILE);
var
   start : PUTF8Char;
   last : UTF8Char;
   position: Tposition;
begin
    result := nil;

    start := filename;
    if nil =filename then begin
        ERR_raise(ERR_LIB_DSO, DSO_R_NO_FILENAME);
        Exit(nil);
    end;
    result := OPENSSL_zalloc(sizeof( result^));
    if result = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    position := IN_DEVICE;

     if ( (filename[0] = '\')  and  (filename[1] = '\') )  or
        ( (filename[0] = '/')  and  (filename[1] = '/') ) then
     begin
        position := IN_NODE;
        filename  := filename + 2;
        start := filename;
        result.node := start;
    end;
    repeat
        last := filename[0];
        case last of
        ':':
        begin
            if position <> IN_DEVICE then begin
                ERR_raise(ERR_LIB_DSO, DSO_R_INCORRECT_FILE_SYNTAX);
                OPENSSL_free(Pointer(result));
                Exit(nil);
            end;
            result.device := start;
            result.devicelen := int(filename - start);
            position := IN_FILE;
            start := PreInc(filename);
            result.dir := start;
        end;

        '\',
        '/':
        begin
            if position = IN_NODE then
            begin
                result.nodelen := int(filename - start);
                position := IN_FILE;
                start := PreInc(filename);
                result.dir := start;
            end
            else if (position = IN_DEVICE) then
            begin
                position := IN_FILE;
                PostInc(filename);
                result.dir := start;
                result.dirlen := int(filename - start);
                start := filename;
            end
            else
            begin
                PostInc(filename);
                result.dirlen  := result.dirlen + (int(filename - start));
                start := filename;
            end;
        end;
        #0:
        begin
            if position = IN_NODE then
            begin
                result.nodelen := int(filename - start);
            end
            else
            begin
                if filename - start > 0 then
                begin
                    if assume_last_is_dir > 0 then
                    begin
                        if position = IN_DEVICE then
                        begin
                            result.dir := start;
                            result.dirlen := 0;
                        end;
                        result.dirlen  := result.dirlen + (int(filename - start));
                    end
                    else
                    begin
                        result.&file := start;
                        result.filelen := int(filename - start);
                    end;
                end;
            end;
        end;
        else
            PostInc(filename);
            break;
        end;
    until not (Ord(last) > 0);
    if 0>=result.nodelen then result.node := nil;
    if 0>=result.devicelen then result.device := nil;
    if 0>=result.dirlen then result.dir := nil;
    if 0>=result.filelen then result.&file := nil;

end;

function win32_globallookup(const name : PUTF8Char):Pointer;
type
  ret_st = record
    case int of
      0: (p: Pointer);
      1: (f:  TFARPROC);
  end;
var
    dll          : HMODULE;
    hModuleSnap  : THANDLE;
    me32         : TMODULEENTRY32;
    create_snap  : TCREATETOOLHELP32SNAPSHOT;
    close_snap   : TCLOSETOOLHELP32SNAPSHOT;
    module_first,
    module_next  : TMODULE32;
    p            : Pointer;
    f            : TFARPROC;
    ret: ret_st;
begin
    hModuleSnap := INVALID_HANDLE_VALUE;
   
    dll := LoadLibrary({TEXT}(DLLNAME));
    if dll <= 0 then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        Exit(nil);
    end;
    create_snap := {CREATETOOLHELP32SNAPSHOT}
        GetProcAddress(dll, 'CreateToolhelp32Snapshot');
    if not Assigned(create_snap) then
    begin
        FreeLibrary(dll);
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        Exit(nil);
    end;
    { We take the rest for granted... }
{$IFDEF _WIN32_WCE}
    close_snap := (CLOSETOOLHELP32SNAPSHOT)
        GetProcAddress(dll, 'CloseToolhelp32Snapshot');
{$ELSE}
    close_snap := {CLOSETOOLHELP32SNAPSHOT} CloseHandle;
{$ENDIF}
    module_first := {MODULE32} GetProcAddress(dll, 'Module32First');
    module_next := {MODULE32} GetProcAddress(dll, 'Module32Next');
    hModuleSnap := create_snap(TH32CS_SNAPMODULE, 0);
    if hModuleSnap = INVALID_HANDLE_VALUE then
    begin
        FreeLibrary(dll);
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        Exit(nil);
    end;
    me32.dwSize := sizeof(me32);
    if not module_first(hModuleSnap, @me32) then
    begin
        close_snap (hModuleSnap);
        FreeLibrary(dll);
        Exit(nil);
    end;
    repeat
        if ret.f = GetProcAddress(me32.hModule, name) then
        begin
            close_snap (hModuleSnap);
            FreeLibrary(dll);
            Exit(ret.p);
        end;
    until not module_next(hModuleSnap, @me32);
    close_snap(hModuleSnap);
    FreeLibrary(dll);
    Result := nil;
end;


function win32_pathbyaddr( addr : Pointer; path : PUTF8Char; sz : integer):integer;
type
  t_st = record
    case int of
       0: (f: function(p1: Pointer; p2: PUTF8Char; p3: int): int;);
       1: (p: Pointer);
  end;
var
    dll          : HMODULE;
    hModuleSnap  : THANDLE;
    me32         : MODULEENTRY32;
    create_snap  : TCREATETOOLHELP32SNAPSHOT;
    close_snap   : TCLOSETOOLHELP32SNAPSHOT;
    module_first,
    module_next  : TMODULE32;
    p            : Pointer;
    t: t_st;
  i,
  len          : integer;
begin
    hModuleSnap := INVALID_HANDLE_VALUE;
    if addr = nil then
    begin
        t.f := win32_pathbyaddr;
        addr := t.p;
    end;
    dll := LoadLibrary({TEXT}(DLLNAME));
    if dll = 0 then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        Exit(-1);
    end;
    create_snap := {CREATETOOLHELP32SNAPSHOT}
        GetProcAddress(dll, 'CreateToolhelp32Snapshot');
    if not Assigned(create_snap) then
    begin
        FreeLibrary(dll);
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        Exit(-1);
    end;
    { We take the rest for granted... }
{$IFDEF _WIN32_WCE}
    close_snap := (CLOSETOOLHELP32SNAPSHOT)
        GetProcAddress(dll, 'CloseToolhelp32Snapshot');
{$ELSE}
    close_snap := {CLOSETOOLHELP32SNAPSHOT} CloseHandle;
{$ENDIF}
    module_first := {MODULE32} GetProcAddress(dll, 'Module32First');
    module_next := {MODULE32} GetProcAddress(dll, 'Module32Next');
    {
     * Take a snapshot of current process which includes
     * list of all involved modules.
     }
    hModuleSnap := create_snap (TH32CS_SNAPMODULE, 0);
    if hModuleSnap = INVALID_HANDLE_VALUE then
    begin
        FreeLibrary(dll);
        ERR_raise(ERR_LIB_DSO, DSO_R_UNSUPPORTED);
        Exit(-1);
    end;
    me32.dwSize := sizeof(me32);
    if not module_first(hModuleSnap, @me32) then
    begin
        close_snap(hModuleSnap);
        FreeLibrary(dll);
        ERR_raise(ERR_LIB_DSO, DSO_R_FAILURE);
        Exit(-1);
    end;
    { Enumerate the modules to find one which includes me. }
    repeat
        if (size_t( addr) >= size_t( me32.modBaseAddr))  and
           (size_t( addr) < size_t(me32.modBaseAddr + me32.modBaseSize)) then
        begin
            close_snap(hModuleSnap);
            FreeLibrary(dll);
  {$IFDEF _WIN32_WCE}
   
  {$ELSE} begin
                len := int(Length(me32.szExePath));
                if sz <= 0 then Exit(len + 1);
                if len >= sz then len := sz - 1;
                memcpy(path, @me32.szExePath, len);
                path[PostInc(len)] := #0;
                Exit(len);
            end;
  {$ENDIF}
        end;
    until not (module_next(hModuleSnap, @me32));
    close_snap (hModuleSnap);
    FreeLibrary(dll);
    Result := 0;
end;


function win32_merger(dso : PDSO;const filespec1, filespec2 : PUTF8Char):PUTF8Char;
var
  merged          : PUTF8Char;
  filespec1_split,
  filespec2_split : Pfile_st;
begin
    merged := nil;
    filespec1_split := nil;
    filespec2_split := nil;
    if (nil =filespec1)  and  (nil =filespec2) then
    begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if nil =filespec2 then
    begin
        OPENSSL_strdup(merged, filespec1);
        if merged = nil then begin
            ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end
    else if (nil =filespec1) then
    begin
        OPENSSL_strdup(merged, filespec2);
        if merged = nil then begin
            ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
    end
    else
    begin
        filespec1_split := win32_splitter(dso, filespec1, 0);
        if nil =filespec1_split then begin
            ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
            Exit(nil);
        end;
        filespec2_split := win32_splitter(dso, filespec2, 1);
        if nil =filespec2_split then begin
            ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
            OPENSSL_free(Pointer(filespec1_split));
            Exit(nil);
        end;
        { Fill in into filespec1_split }
        if (nil =filespec1_split.node)  and  (nil =filespec1_split.device) then
        begin
            filespec1_split.node := filespec2_split.node;
            filespec1_split.nodelen := filespec2_split.nodelen;
            filespec1_split.device := filespec2_split.device;
            filespec1_split.devicelen := filespec2_split.devicelen;
        end;
        if nil =filespec1_split.dir then
        begin
            filespec1_split.dir := filespec2_split.dir;
            filespec1_split.dirlen := filespec2_split.dirlen;
        end
        else
        if (filespec1_split.dir[0] <> '\')
                    and  (filespec1_split.dir[0] <> '/') then
        begin
            filespec1_split.predir := filespec2_split.dir;
            filespec1_split.predirlen := filespec2_split.dirlen;
        end;

        if nil =filespec1_split.&file then
        begin
            filespec1_split.&file := filespec2_split.&file;
            filespec1_split.filelen := filespec2_split.filelen;
        end;
        merged := win32_joiner(dso, filespec1_split);
    end;
    OPENSSL_free(Pointer(filespec1_split));
    OPENSSL_free(Pointer(filespec2_split));
    Result := merged;
end;



function win32_name_converter(dso : PDSO;const filename : PUTF8Char):PUTF8Char;
var
  translated : PUTF8Char;
  len,
  transform  : integer;
  s: string;
begin
    len := Length(filename);
    transform := int( (strstr(filename, '/') = nil) and
                      (strstr(filename, '\\') = nil) and
                      (strstr(filename, ':') = nil) );

    if transform > 0 then { We will convert this to '%s.dll' }
        translated := OPENSSL_malloc(len + 5)
    else
        { We will simply duplicate filename }
        translated := OPENSSL_malloc(len + 1);
    if translated = nil then begin
        ERR_raise(ERR_LIB_DSO, DSO_R_NAME_TRANSLATION_FAILED);
        Exit(nil);
    end;
    if transform >0 then
       s :=format('%s.dll', [filename])
    else
       s := Format('%s', [filename]);
    Result := PUTF8Char(s);//translated;
end;


function openssl_strnchr(const &string : PUTF8Char; c : integer; len : size_t):PUTF8Char;
var
  i : size_t;
  p : PUTF8Char;
begin
    i := 0; p := &string;
    while (i < len)  and  (p^ <> #0) do
    begin
        if Ord(p^) = c then
           Exit(p);
        Inc(i); Inc(p);
    end;
    Result := nil;
end;

function win32_load( dso : PDSO):integer;
var
    h: HINSTANCE;
    p  : PHINSTANCE;
    filename : PUTF8Char;
    s: AnsiString;
    label _err;
begin
    h := 0; p := nil;
    { See applicable comments from dso_dl.c }
    filename := DSO_convert_filename(dso, nil);
    if filename = nil then begin
        ERR_raise(ERR_LIB_DSO, DSO_R_NO_FILENAME);
        goto _err;
    end;
    s := filename;
    h := LoadLibraryA(PAnsiChar(s));
    if h = 0 then begin
        ERR_raise_data(ERR_LIB_DSO, DSO_R_LOAD_FAILED,
                      Format('filename(%s)', [filename]));
        goto _err;
    end;
    p := OPENSSL_malloc(sizeof( p^));
    if p = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_MALLOC_FAILURE);
        goto _err;
    end;
    p^ := h;
    if 0>=sk_void_push(dso.meth_data, p) then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_STACK_ERROR);
        goto _err;
    end;
    { Success }
    dso.loaded_filename := filename;
    Exit(1);
 _err:
    { Cleanup ! }
    OPENSSL_free(Pointer(filename));
    OPENSSL_free(Pointer(p));
    if h <> 0 then FreeLibrary(h);
    Result := 0;
end;


function win32_unload( dso : PDSO):integer;
var
  p : PHINSTANCE;
begin
    if dso = nil then begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if sk_void_num(dso.meth_data) < 1  then
        Exit(1);
    p := sk_void_pop(dso.meth_data);
    if p = nil then begin
        ERR_raise(ERR_LIB_DSO, DSO_R_NULL_HANDLE);
        Exit(0);
    end;
    if not FreeLibrary( p^) then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_UNLOAD_FAILED);
        {
         * We should push the value back onto the stack in case of a retry.
         }
        sk_void_push(dso.meth_data, p);
        Exit(0);
    end;
    { Cleanup }
    OPENSSL_free(Pointer(p));
    Result := 1;
end;


function win32_bind_func(dso : PDSO;const symname : PUTF8Char): TDSO_FUNC_TYPE;
type
  ret_st = record
    case int of
      0: (p: Pointer);
      1: (f:  TFARPROC);
  end;
var
  ptr : PHINSTANCE;
  p : Pointer;
  f : FARPROC;
  sym: ret_st;
begin

    if (dso = nil)  or  (symname = nil) then
    begin
        ERR_raise(ERR_LIB_DSO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(nil);
    end;
    if sk_void_num(dso.meth_data) < 1  then
    begin
        ERR_raise(ERR_LIB_DSO, DSO_R_STACK_ERROR);
        Exit(nil);
    end;
    ptr := sk_void_value(dso.meth_data, sk_void_num(dso.meth_data) - 1);
    if ptr = nil then begin
        ERR_raise(ERR_LIB_DSO, DSO_R_NULL_HANDLE);
        Exit(nil);
    end;
    sym.f := GetProcAddress( ptr^, symname);
    if sym.p = nil then begin
        ERR_raise_data(ERR_LIB_DSO, DSO_R_SYM_FAILURE, Format('symname(%s)', [symname]));
        Exit(nil);
    end;
    Result := {DSO_FUNC_TYPE}sym.f;
end;



function DSO_METHOD_openssl:PDSO_METHOD;
begin
    Result := @dso_meth_win32;
end;


end.
