unit openssl3.crypto.buffer.buffer;

interface
 uses OpenSSL.Api, SysUtils;

 const
   LIMIT_BEFORE_EXPANSION = $5ffffffc;

function BUF_MEM_grow( str : PBUF_MEM; len : size_t):size_t;
function sec_alloc_realloc( Astr : PBUF_MEM; Alen : size_t): TArray<UTF8Char>;
function BUF_MEM_new:PBUF_MEM;
procedure BUF_MEM_free( a : PBUF_MEM);
function BUF_MEM_grow_clean( str : PBUF_MEM; len : size_t):size_t;
function BUF_MEM_new_ex( flags : Cardinal):PBUF_MEM;
procedure BUF_reverse(_out : PByte;{const} _in : PByte; size : size_t);

implementation
uses OpenSSL3.Err, openssl3.crypto.mem_sec, openssl3.crypto.mem;

{$POINTERMATH ON}
procedure BUF_reverse(_out : PByte;{const} _in : PByte; size : size_t);
var
  i : size_t;
  q : PByte;
  c : byte;
begin
    if _in <> nil then
    begin
        _out  := _out + (size - 1);
        for i := 0 to size-1 do
            PostDec(_out)^ := PostInc(_in)^;
    end
    else
    begin
        q := _out + size - 1;
        for i := 0 to size div 2-1 do
        begin
            c := q^;
            PostDec(q)^ := _out^;
            PostInc(_out)^ := c;
        end;
    end;
end;

function BUF_MEM_new_ex( flags : Cardinal):PBUF_MEM;
var
  ret : PBUF_MEM;
begin
    ret := BUF_MEM_new();
    if ret <> nil then
       ret.flags := flags;
    Result := ret;
end;



function BUF_MEM_new: PBUF_MEM;
begin
    Result := OPENSSL_zalloc(sizeof(TBUF_MEM));
    if Result = nil then
    begin
        ERR_raise(ERR_LIB_BUF, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;

end;


procedure BUF_MEM_free( a : PBUF_MEM);
begin
    if a = nil then exit;
    if a.data <> nil then
    begin
        if (a.flags and BUF_MEM_FLAG_SECURE) > 0 then
        begin
            //OPENSSL_secure_clear_free(a.data, a.max)
            SetLength(a.buffer, 0);
            a.buffer := nil;
            a.data := nil;
        end
        else
        begin
           if Length(a.buffer) > 0 then
              SetLength(a.buffer, 0);
           a.data := nil;
           //OPENSSL_clear_free(a.data, a.max);
        end;
    end;
    OPENSSL_free(a);
end;



function sec_alloc_realloc( Astr : PBUF_MEM; Alen : size_t): TArray<UTF8Char>;
begin
    SetLength(Result, Alen);
    if Astr.data <> nil then
    begin
        if Result <> nil then
        begin
            memcpy(Result, Astr.data, Astr.length);
            //OPENSSL_secure_clear_free(str.data, str.length);
            SetLength(Astr.buffer, 0);
            Astr.data := nil;
        end;
    end;

end;

//https://www.delphibasics.co.uk/RTL.php?Name=ReallocMem
function BUF_MEM_grow( str : PBUF_MEM; len : size_t):size_t;
var
  ret : TArray<UTF8Char>;
  n : size_t;
begin

    if str.length >= len then
    begin
        str.length := len;
        Exit(len);
    end;
    if str.max >= len then
    begin
        if str.data <> nil then
        begin
           memset(@str.data[str.length], 0, len - str.length);
        end;
        str.length := len;
        Exit(len);
    end;
    // This limit is sufficient to ensure (len+3)/3*4 < 2**31
    if len > LIMIT_BEFORE_EXPANSION then
    begin
        ERR_raise(ERR_LIB_BUF, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    n := (len + 3) div 3 * 4;
    if (str.flags and BUF_MEM_FLAG_SECURE) > 0  then
    begin
        ret := sec_alloc_realloc(str, n);
        str.buffer := ret;
        str.data := @str.buffer[0];
    end
    else
    begin
        if (str.data = nil) then
        begin
          str.data := CRYPTO_malloc(n);
        end
        else
        begin
            if n = 0 then
            begin
                CRYPTO_free(str.data);
                str.data := nil;
            end
            else
            begin
               Inc(str.data, str.length);
               ReallocMem(str.data, n);
            end;
        end;

    end;

    if str.data = nil then
    begin
        ERR_raise(ERR_LIB_BUF, ERR_R_MALLOC_FAILURE);
        len := 0;
    end
    else
    begin
        str.max := n;
        memset(@str.data[str.length], 0, len - str.length);
        str.length := len;

    end;
    Result := len;
end;

function BUF_MEM_grow_clean( str : PBUF_MEM; len : size_t):size_t;
var
  ret : TArray<UTF8Char>;
  n : size_t;
  p: Pointer;
  i: Integer;
  old_len, new_num : size_t;
begin

    if str.length >= len then
    begin
        if str.data <> nil then
            memset(@str.buffer[len], 0, str.length - len);
        str.length := len;
        Exit(len);
    end;
    if str.max >= len then
    begin
        //memset(@str.buffer[str.length], 0, len - str.length);
        for i := str.length to len - str.length -1 do
            str.buffer[i] := #0;
        str.length := len;
        Exit(len);
    end;
    // This limit is sufficient to ensure (len+3)/3*4 < 2**31
    if len > LIMIT_BEFORE_EXPANSION then
    begin
        ERR_raise(ERR_LIB_BUF, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;

    n := (len + 3) div 3 * 4;
    if (str.data = nil) then
    begin
       if n > 0 then
       begin
          Setlength(str.buffer, n);
          str.data := @str.buffer[0];
       end;
    end
    else //str.data <> nil
    begin
       if n = 0 then
       begin
          Setlength(str.buffer, 0);
          str.data := nil;
          Exit(0);
       end;
       old_len := str.max;
       new_num := len;
       if new_num < old_len then
       begin
            for i := new_num to old_len - new_num do
               str.buffer[i] := #0;
            str.data := @Str.buffer[0];
       end
       else
       begin
          //ret := sec_alloc_realloc(str, n) ;
          SetLength(str.buffer, n);
          str.data := @str.buffer[0];
       end;

    end;

    if str.data = nil then
    begin
        ERR_raise(ERR_LIB_BUF, ERR_R_MALLOC_FAILURE);
        len := 0;
    end
    else
    begin
        //str.data := ret;
        str.max := n;
        //memset(@str.data[str.length], 0, len - str.length);
        str.length := len;
    end;
    Result := len;
end;

end.

