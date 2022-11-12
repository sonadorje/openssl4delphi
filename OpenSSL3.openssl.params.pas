unit OpenSSL3.openssl.params;

interface
uses OpenSSL.Api;

const
   OSSL_PARAM_UNMODIFIED = size_t(-1);

function OSSL_PARAM_END: TOSSL_PARAM;
function OSSL_PARAM_DEFN(key:PUTF8Char; data_type:Integer; addr:Pointer; sz: size_t): TOSSL_PARAM; overload;
function OSSL_PARAM_DEFN(key:PUTF8Char; data_type:Integer; addr:Pointer; sz, return_sz: size_t): TOSSL_PARAM;overload;
function _OSSL_PARAM_utf8_string(key:PUTF8Char; addr:Pointer; sz: size_t): TOSSL_PARAM;
function _OSSL_PARAM_uint(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
function _OSSL_PARAM_int(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
function _OSSL_PARAM_size_t(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
function _OSSL_PARAM_octet_string(key:PUTF8Char; addr:Pointer; sz: size_t): TOSSL_PARAM;
function _OSSL_PARAM_uint64(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
function _OSSL_PARAM_uint32(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
function _OSSL_PARAM_time_t(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
function _OSSL_PARAM_BN(const key: PUTF8Char; bn: Pointer; sz: size_t):TOSSL_PARAM;

implementation

function _OSSL_PARAM_BN(const key: PUTF8Char; bn: Pointer; sz: size_t):TOSSL_PARAM;
begin
   Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_UNSIGNED_INTEGER, (bn), (sz))
end;

function _OSSL_PARAM_uint32(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
begin
    Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_UNSIGNED_INTEGER, (addr),
                    sizeof(uint32_t))
end;

function _OSSL_PARAM_time_t(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
begin
   Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_INTEGER, (addr), sizeof(time_t))
end;

function _OSSL_PARAM_uint64(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
begin
   Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_UNSIGNED_INTEGER, (addr),
                    sizeof(uint64_t))
end;

function OSSL_PARAM_END: TOSSL_PARAM;
begin
  { NULL, 0, NULL, 0, 0 }
   Result.key         := nil;
   Result.data_type   := 0;
   Result.data        := nil;
   Result.data_size   := 0;
   Result.return_size := 0;
end;

function OSSL_PARAM_DEFN(key:PUTF8Char; data_type:Integer; addr:Pointer; sz, return_sz: size_t): TOSSL_PARAM;
begin
   Result.key         := key;
   Result.data_type   := data_type;
   Result.data        := addr;
   Result.data_size   := sz;
   Result.return_size := return_sz;
end;

function OSSL_PARAM_DEFN(key:PUTF8Char; data_type:Integer; addr:Pointer; sz: size_t): TOSSL_PARAM;
begin
   Result.key         := key;
   Result.data_type   := data_type;
   Result.data        := addr;
   Result.data_size   := sz;
   Result.return_size := OSSL_PARAM_UNMODIFIED;
end;

function _OSSL_PARAM_octet_string(key:PUTF8Char; addr:Pointer; sz: size_t): TOSSL_PARAM;
begin
   Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_OCTET_STRING, (addr), sz)
end;

function _OSSL_PARAM_utf8_string(key:PUTF8Char; addr:Pointer; sz: size_t): TOSSL_PARAM;
begin
   Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_UTF8_STRING, (addr), sz)
end;

function _OSSL_PARAM_uint(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
begin
   Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(uint32))
end;

function _OSSL_PARAM_int(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
begin
   Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_INTEGER, (addr), sizeof(int));
end;

function _OSSL_PARAM_size_t(key:PUTF8Char; addr:Pointer): TOSSL_PARAM;
begin
    Result := OSSL_PARAM_DEFN(key, OSSL_PARAM_UNSIGNED_INTEGER, (addr), sizeof(size_t))
end;

end.
