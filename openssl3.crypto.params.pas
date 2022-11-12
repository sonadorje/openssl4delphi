unit openssl3.crypto.params;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses  OpenSSL.Api, SysUtils;

const
   OSSL_PARAM_UNMODIFIED = size_t(-1);
   OSSL_PARAM_END: TOSSL_PARAM = (key         : nil;
                                  data_type   : 0;
                                  data        : nil;
                                  data_size: 0;
                                  return_size :0);
function OSSL_PARAM_construct_int(const key : PUTF8Char; buf : Pinteger):TOSSL_PARAM;
function ossl_param_construct(const key : PUTF8Char; data_type : uint32; data : Pointer; data_size : size_t):TOSSL_PARAM;
function OSSL_PARAM_construct_end: TOSSL_PARAM;
function OSSL_PARAM_construct_BN(const key : PUTF8Char; buf : PByte; bsize : size_t):TOSSL_PARAM;
function OSSL_PARAM_construct_uint(const key : PUTF8Char; buf : Puint32):TOSSL_PARAM;
function OSSL_PARAM_construct_utf8_string(const key : PUTF8Char; buf : PUTF8Char; bsize : size_t):TOSSL_PARAM;
 function OSSL_PARAM_construct_utf8_ptr(const key : PUTF8Char; buf : PPUTF8Char; bsize : size_t):TOSSL_PARAM;
function OSSL_PARAM_construct_octet_string(const key : PUTF8Char; buf : Pointer; bsize : size_t):TOSSL_PARAM;
function OSSL_PARAM_construct_octet_ptr(const key : PUTF8Char; buf : PPointer; bsize : size_t):TOSSL_PARAM;
function OSSL_PARAM_locate_const(const p : POSSL_PARAM; key : PUTF8Char):POSSL_PARAM;
function OSSL_PARAM_locate(p : POSSL_PARAM;const key : PUTF8Char):POSSL_PARAM;
function OSSL_PARAM_get_int(const p : POSSL_PARAM;val : Pinteger):integer;
function OSSL_PARAM_get_int32(const p : POSSL_PARAM;val : Pint32_t):integer;
function general_get_int(const p : POSSL_PARAM; val : Pointer; val_size : size_t):integer;
function signed_from_signed(dest : Pointer; dest_len : size_t;const src : Pointer; src_len : size_t):integer;
function copy_integer(dest : PByte; dest_len : size_t;const src : PByte; src_len : size_t; pad : Byte; signed_int : integer):integer;
function check_sign_bytes(const p : PByte; n : size_t; s : Byte):integer;
function is_negative(const number : Pointer; s : size_t):integer;
function signed_from_unsigned(dest : Pointer; dest_len : size_t;const src : Pointer; src_len : size_t):integer;
procedure err_out_of_range;
procedure err_unsupported_real;
function OSSL_PARAM_get_int64(const p : POSSL_PARAM; val : Pint64_t):integer;
procedure err_null_argument ;
procedure err_inexact ;
procedure err_bad_type ;
procedure err_unsigned_negative ;
procedure err_not_integer;
procedure err_too_small;
function OSSL_PARAM_get_BN(const p : POSSL_PARAM; val : PPBIGNUM):integer;
function OSSL_PARAM_get_uint32(const p : POSSL_PARAM; val : Puint32_t):integer;
function general_get_uint(const p : POSSL_PARAM; val : Pointer; val_size : size_t):integer;
function unsigned_from_signed(dest : Pointer; dest_len : size_t;const src : Pointer; src_len : size_t):integer;
function unsigned_from_unsigned(dest : Pointer; dest_len : size_t;const src : Pointer; src_len : size_t):integer;
function OSSL_PARAM_get_utf8_string(const p : POSSL_PARAM; val : PPUTF8Char; max_len : size_t):integer;
function get_string_internal(const p : POSSL_PARAM; val : PPointer; max_len, used_len : Psize_t; _type : uint32):integer;
function OSSL_PARAM_get_octet_ptr(const p : POSSL_PARAM; val : PPointer; used_len : Psize_t):integer;
function get_ptr_internal(const p : POSSL_PARAM; val : PPointer; used_len : Psize_t; &type : uint32):integer;
function OSSL_PARAM_set_int( p : POSSL_PARAM; val : integer):integer;
function OSSL_PARAM_set_int32( p : POSSL_PARAM; val : integer):integer;
function general_set_int( p : POSSL_PARAM; val : Pointer; val_size : size_t):integer;
function real_shift:uint32;
function OSSL_PARAM_set_int64( p : POSSL_PARAM; val : int64):integer;
function OSSL_PARAM_set_BN(p : POSSL_PARAM;const val : PBIGNUM):integer;
function OSSL_PARAM_set_uint( p : POSSL_PARAM; val : uint32):integer;
function OSSL_PARAM_set_uint32( p : POSSL_PARAM; val : uint32):integer;
function general_set_uint( p : POSSL_PARAM; val : Pointer; val_size : size_t):integer;
function OSSL_PARAM_set_uint64( p : POSSL_PARAM; val : uint64):integer;
function OSSL_PARAM_set_utf8_string(p : POSSL_PARAM;const val : PUTF8Char):integer;
function set_string_internal(p : POSSL_PARAM;const val : Pointer; len : size_t; &type : uint):integer;
function OSSL_PARAM_set_octet_ptr(p : POSSL_PARAM;const val : Pointer; used_len : size_t):integer;
function set_ptr_internal(p : POSSL_PARAM;const val : Pointer; &type : uint; len : size_t):integer;
function OSSL_PARAM_modified(const p : POSSL_PARAM):integer;
function OSSL_PARAM_set_size_t( p : POSSL_PARAM; val : size_t):integer;
function OSSL_PARAM_construct_size_t(const key : PUTF8Char; buf : Psize_t):TOSSL_PARAM;
function OSSL_PARAM_get_octet_string(const p : POSSL_PARAM; val : PPointer; max_len : size_t; used_len : Psize_t):integer;
function OSSL_PARAM_get_size_t(const p : POSSL_PARAM; val : Psize_t):integer;
function OSSL_PARAM_get_uint64(const p : POSSL_PARAM; val : Puint64_t):integer;
function OSSL_PARAM_get_utf8_string_ptr(const p : POSSL_PARAM; val : PPUTF8Char):integer;
function OSSL_PARAM_get_utf8_ptr(const p : POSSL_PARAM; val : PPUTF8Char):integer;
function get_string_ptr_internal(const p : POSSL_PARAM; val : PPointer; used_len : Psize_t; &type : uint32):integer;
 function OSSL_PARAM_set_time_t( p : POSSL_PARAM; val : time_t):integer;
function OSSL_PARAM_get_uint(const p : POSSL_PARAM; val : Puint32):integer;
function OSSL_PARAM_get_time_t(const p : POSSL_PARAM; val : Ptime_t):integer;
function OSSL_PARAM_set_long( p : POSSL_PARAM; val : LongInt):integer;
function OSSL_PARAM_get_long(const p : POSSL_PARAM; val : PLongInt):integer;
function OSSL_PARAM_construct_time_t(const key : PUTF8Char; buf : Ptime_t):TOSSL_PARAM;
function OSSL_PARAM_set_utf8_ptr(p : POSSL_PARAM;const val : PUTF8Char):integer;
procedure ossl_prov_cache_exported_algorithms(_in : POSSL_ALGORITHM_CAPABLE; _out : POSSL_ALGORITHM);
function OSSL_PARAM_construct_uint64(const key : PUTF8Char; buf : Puint64_t):TOSSL_PARAM;
procedure OSSL_PARAM_set_all_unmodified( p : POSSL_PARAM);
function OSSL_PARAM_get_octet_string_ptr(const p : POSSL_PARAM; val : PPointer; used_len : Psize_t):integer;
function OSSL_PARAM_set_octet_string(p : POSSL_PARAM;const val : Pointer; len : size_t):integer;

implementation
uses
    OpenSSL3.Err,               openssl3.crypto.mem,
    openssl3.crypto.bn.bn_lib,  openssl3.crypto.o_str;


function OSSL_PARAM_set_octet_string(p : POSSL_PARAM;const val : Pointer; len : size_t):integer;
begin
    if p = nil then begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    if val = nil then begin
        err_null_argument;
        Exit(0);
    end;
    Result := set_string_internal(p, val, len, OSSL_PARAM_OCTET_STRING);
end;

function OSSL_PARAM_get_octet_string_ptr(const p : POSSL_PARAM; val : PPointer; used_len : Psize_t):integer;
begin
    Exit(Int( (OSSL_PARAM_get_octet_ptr(p, val, used_len) > 0 ) or
             (get_string_ptr_internal(p, val, used_len, OSSL_PARAM_OCTET_STRING) > 0)) );
end;

procedure OSSL_PARAM_set_all_unmodified( p : POSSL_PARAM);
begin
    if p <> nil then
      while (p.key <> nil) do
      begin
          p.return_size := OSSL_PARAM_UNMODIFIED;
          Inc(p);
      end;
end;


function OSSL_PARAM_construct_uint64(const key : PUTF8Char; buf : Puint64_t):TOSSL_PARAM;
begin
    Exit(ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,
                                sizeof(uint64)) );
end;

procedure ossl_prov_cache_exported_algorithms(_in : POSSL_ALGORITHM_CAPABLE; _out : POSSL_ALGORITHM);
var
  i, j : integer;
begin
{$POINTERMATH ON}
    if _out[0].algorithm_names = nil then
    begin
        i := 0;j := 0;
        while _in[i].alg.algorithm_names <> nil do
        begin
            if ( not Assigned(_in[i].capable))  or (Assigned(_in[i].capable))  then
                _out[PostInc(j)] := _in[i].alg;
            Inc(i);
        end;
        _out[PostInc(j)] := _in[i].alg;
    end;
{$POINTERMATH OFF}
end;

function OSSL_PARAM_set_utf8_ptr(p : POSSL_PARAM;const val : PUTF8Char):integer;
begin
    if p = nil then
    begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    Exit(set_ptr_internal(p, val, OSSL_PARAM_UTF8_PTR,
                           get_result( val = nil , 0 , Length(val))));
end;


function OSSL_PARAM_construct_time_t(const key : PUTF8Char; buf : Ptime_t):TOSSL_PARAM;
begin
    Result := ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(time_t));
end;



function OSSL_PARAM_get_long(const p : POSSL_PARAM; val : PLongInt):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(longint)) of
    sizeof(int32_t):
        Exit(OSSL_PARAM_get_int32(p, Pint32_t ( val)));
    sizeof(int64_t):
        Exit(OSSL_PARAM_get_int64(p, Pint64_t ( val)));
    end;
{$ENDIF}
    Result := general_get_int(p, val, sizeof( val^));
end;


function OSSL_PARAM_set_long( p : POSSL_PARAM; val : LongInt):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(longint)) of
    sizeof(int32_t):
        Exit(OSSL_PARAM_set_int32(p, val));
    sizeof(int64_t):
        Exit(OSSL_PARAM_set_int64(p, val));
    end;
{$ENDIF}
    Result := general_set_int(p, @val, sizeof(val));
end;



function OSSL_PARAM_get_time_t(const p : POSSL_PARAM;val : Ptime_t):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(time_t)) of
    sizeof(int32_t):
        Exit(OSSL_PARAM_get_int32(p, Pint32_t ( val)));
    sizeof(int64_t):
        Exit(OSSL_PARAM_get_int64(p, Pint64_t ( val)));
    end;
{$ENDIF}
    Result := general_get_int(p, val, sizeof( val^));
end;

function OSSL_PARAM_get_uint(const p : POSSL_PARAM; val : Puint32):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(Uint32 )) of
    sizeof(uint32_t):
        Exit(OSSL_PARAM_get_uint32(p, Puint32_t  (val)));
    sizeof(uint64_t):
        Exit(OSSL_PARAM_get_uint64(p, Puint64_t  (val)));
    end;
{$ENDIF}
    Result := general_get_uint(p, val, sizeof( val^));
end;

function OSSL_PARAM_set_time_t( p : POSSL_PARAM; val : time_t):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(time_t)) of
    sizeof(int32_t):
        Exit(OSSL_PARAM_set_int32(p, val));
    sizeof(int64_t):
        Exit(OSSL_PARAM_set_int64(p, val));
    end;
{$ENDIF}
    Result := general_set_int(p, @val, sizeof(val));
end;


function get_string_ptr_internal(const p : POSSL_PARAM; val : PPointer; used_len : Psize_t; &type : uint32):integer;
begin
    if (val = nil)  or  (p = nil) then
    begin
        err_null_argument;
        Exit(0);
    end;
    if p.data_type <> &type then
    begin
        err_bad_type;
        Exit(0);
    end;
    if used_len <> nil then
       used_len^ := p.data_size;
    val^ := p.data;
    Result := 1;
end;


function OSSL_PARAM_get_utf8_ptr(const p : POSSL_PARAM; val : PPUTF8Char):integer;
begin
    Result := get_ptr_internal(p, PPointer (val), nil, OSSL_PARAM_UTF8_PTR);
end;



function OSSL_PARAM_get_utf8_string_ptr(const p : POSSL_PARAM; val : PPUTF8Char):integer;
begin
    Result := int(OSSL_PARAM_get_utf8_ptr(p, val))
                  or  get_string_ptr_internal(p, PPointer(val), nil,
                                   OSSL_PARAM_UTF8_STRING);
end;



function OSSL_PARAM_get_uint64(const p : POSSL_PARAM; val : Puint64_t):integer;
var
  d : Double;
  i32 : integer;
  i64 : int64;
begin
    if (val = nil)  or  (p = nil) then
    begin
        err_null_argument;
        Exit(0);
    end;
    if p.data_type = OSSL_PARAM_UNSIGNED_INTEGER then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
          sizeof(uint32_t):
          Begin
              val^ := Puint32_t(p.data)^;
              Exit(1);
          End;
          sizeof(uint64_t):
          begin
              val^ := Puint64_t(p.data)^;
              Exit(1);
          end;
        end;
{$ENDIF}
        Exit(general_get_uint(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_INTEGER) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
        sizeof(int32_t):
        begin
            i32 := Pint32_t(p.data)^;
            if i32 >= 0 then
            begin
                val^ := uint64_t(i32);
                Exit(1);
            end;
            err_unsigned_negative;
            Exit(0);
        end;
        sizeof(int64_t):
        begin
            i64 := Pint64_t(p.data)^;
            if i64 >= 0 then
            begin
                val^ := uint64_t(i64);
                Exit(1);
            end;
            err_unsigned_negative;
            Exit(0);
        end;
        end;
{$ENDIF}
        Exit(general_get_uint(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        case p.data_size of
            sizeof(double):
            begin


                d := Pdouble(p.data)^;
                if (d >= 0)
                        {
                         * By subtracting 65535 (2^16-1 then we cancel the low order
                         * 15 bits of UINT64_MAX to avoid using imprecise floating
                         * point values.
                         }
                         and  (d < (UINT64_MAX - 65535) + 65536.0)
                         and  (d = Round(d)) then
                begin
                    val^ := Round(d);
                    Exit(1);
                end;
                err_inexact;
                Exit(0);
            end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;


function OSSL_PARAM_get_size_t(const p : POSSL_PARAM; val : Psize_t):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(size_t)) of
    sizeof(uint32_t):
        Exit(OSSL_PARAM_get_uint32(p, Puint32_t (val)));
    sizeof(uint64_t):
        Exit(OSSL_PARAM_get_uint64(p, Puint64_t (val)));
    end;
{$ENDIF}
    Result := general_get_uint(p, val, sizeof( val^));
end;



function OSSL_PARAM_get_octet_string(const p : POSSL_PARAM; val : PPointer; max_len : size_t; used_len : Psize_t):integer;
begin
    Result := get_string_internal(p, val, @max_len, used_len, OSSL_PARAM_OCTET_STRING);
end;


function OSSL_PARAM_construct_size_t(const key : PUTF8Char; buf : Psize_t):TOSSL_PARAM;
begin
    Result := ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf, sizeof(size_t));
end;


function OSSL_PARAM_set_size_t( p : POSSL_PARAM; val : size_t):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(size_t)) of
    sizeof(uint32_t):
        Exit(OSSL_PARAM_set_uint32(p, uint32_t(val)));
    sizeof(uint64_t):
        Exit(OSSL_PARAM_set_uint64(p, uint64_t(val)));
    end;
{$ENDIF}
    Result := general_set_uint(p, @val, sizeof(val));
end;


function OSSL_PARAM_modified(const p : POSSL_PARAM):integer;
begin
    Result := Int( (p <> nil)  and  (p.return_size <> OSSL_PARAM_UNMODIFIED) );
end;

function set_ptr_internal(p : POSSL_PARAM;const val : Pointer; &type : uint; len : size_t):integer;
begin
    p.return_size := len;
    if p.data_type <> &type then begin
        err_bad_type;
        Exit(0);
    end;
    if p.data <> nil then
       PPointer(p.data)^ := val;
    Result := 1;
end;

function OSSL_PARAM_set_octet_ptr(p : POSSL_PARAM;const val : Pointer; used_len : size_t):integer;
begin
    if p = nil then begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    Result := set_ptr_internal(p, val, OSSL_PARAM_OCTET_PTR, used_len);
end;

function set_string_internal(p : POSSL_PARAM;const val : Pointer; len : size_t; &type : uint):integer;
begin
    p.return_size := len;
    if p.data = nil then Exit(1);
    if p.data_type <> &type then begin
        err_bad_type;
        Exit(0);
    end;
    if p.data_size < len then begin
        err_too_small;
        Exit(0);
    end;
    memcpy(p.data, val, len);
    { If possible within the size of p.data, add a NUL terminator byte }
    if (&type = OSSL_PARAM_UTF8_STRING)  and  (p.data_size > len) then
       PUTF8Char(p.data)[len] := #0;
    Result := 1;
end;



function OSSL_PARAM_set_utf8_string(p : POSSL_PARAM;const val : PUTF8Char):integer;
begin
    if p = nil then begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    if val = nil then begin
        err_null_argument;
        Exit(0);
    end;
    Result := set_string_internal(p, val, Length(val), OSSL_PARAM_UTF8_STRING);
end;

function OSSL_PARAM_set_uint64( p : POSSL_PARAM; val : uint64):integer;
begin
    if p = nil then begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    if p.data_type = OSSL_PARAM_UNSIGNED_INTEGER then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        p.return_size := sizeof(uint64_t); { Expected size }
        if p.data = nil then Exit(1);
        case p.data_size of
            sizeof(uint32_t):
            begin
                if val <= UINT32_MAX then
                begin
                    p.return_size := sizeof(uint32_t);
                    Puint32_t(p.data)^ := uint32_t(val);
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
            sizeof(uint64_t):
            begin
                Puint64_t(p.data)^ := val;
                Exit(1);
            end;
        end;
{$ENDIF}
        Exit(general_set_uint(p, @val, sizeof(val)));
    end
    else
    if (p.data_type = OSSL_PARAM_INTEGER) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        p.return_size := sizeof(int64_t); { Expected size }
        if p.data = nil then Exit(1);
        case p.data_size of
            sizeof(int32_t):
            begin
                if val <= INT32_MAX then
                begin
                    p.return_size := sizeof(int32_t);
                   Pint32_t(p.data)^ := val;
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
            sizeof(int64_t):
            begin
                if val <= INT64_MAX then
                begin
                    Pint64_t(p.data)^ := int64_t(val);
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
        end;
{$ENDIF}
        Exit(general_set_uint(p, @val, sizeof(val)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        p.return_size := sizeof(double);
        case p.data_size of
            sizeof(double):
            begin
                if (val  shr  real_shift() ) = 0 then
                begin
                    Pdouble(p.data)^ := val;
                    Exit(1);
                end;
                err_inexact;
                Exit(0);
            end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;


function general_set_uint( p : POSSL_PARAM; val : Pointer; val_size : size_t):integer;
var
  r : integer;
begin
    r := 0;
    p.return_size := val_size; { Expected size }
    if p.data = nil then Exit(1);
    if p.data_type = OSSL_PARAM_INTEGER then
       r := signed_from_unsigned(p.data, p.data_size, val, val_size)
    else
    if (p.data_type = OSSL_PARAM_UNSIGNED_INTEGER) then
        r := unsigned_from_unsigned(p.data, p.data_size, val, val_size)
    else
        err_not_integer;
    p.return_size := get_result(r >0, p.data_size , val_size);
    Result := r;
end;

function OSSL_PARAM_set_uint32( p : POSSL_PARAM; val : uint32):integer;
var
  shift : uint;
begin
    if p = nil then
    begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    if p.data_type = OSSL_PARAM_UNSIGNED_INTEGER then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        p.return_size := sizeof(uint32_t); { Minimum expected size }
        if p.data = nil then Exit(1);
        case p.data_size of
            sizeof(uint32_t):
            begin
                Puint32_t(p.data)^ := val;
                Exit(1);
            end;
            sizeof(uint64_t):
            begin
                p.return_size := sizeof(uint64_t);
                Puint64_t(p.data)^ := val;
                Exit(1);
            end;
        end;
{$ENDIF}
        Exit(general_set_uint(p, @val, sizeof(val)));
    end
    else
    if (p.data_type = OSSL_PARAM_INTEGER) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        p.return_size := sizeof(int32_t); { Minimum expected size }
        if p.data = nil then Exit(1);
        case p.data_size of
            sizeof(int32_t):
            begin
                if val <= INT32_MAX then
                begin
                    Pint32_t(p.data)^ := val;
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
            sizeof(int64_t):
            begin
                p.return_size := sizeof(int64_t);
                Pint64_t(p.data)^ := int64_t(val);
                Exit(1);
            end;
        end;
{$ENDIF}
        Exit(general_set_uint(p, @val, sizeof(val)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        p.return_size := sizeof(double);
        if p.data = nil then Exit(1);
        case p.data_size of
          sizeof(double):
          begin
              shift := real_shift();
              if (shift < 8 * sizeof(val)) and ( (val  shr  shift) <> 0) then
              begin
                  err_inexact;
                  Exit(0);
              end;
              Pdouble (p.data)^ := val;
              Exit(1);
          end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;

function OSSL_PARAM_set_uint( p : POSSL_PARAM; val : uint32):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(uint)) of
    sizeof(uint32_t):
        Exit(OSSL_PARAM_set_uint32(p, uint32_t(val)));
    sizeof(uint64_t):
        Exit(OSSL_PARAM_set_uint64(p, uint64_t(val)));
    end;
{$ENDIF}
    Result := general_set_uint(p, @val, sizeof(val));
end;

function OSSL_PARAM_set_BN(p : POSSL_PARAM;const val : PBIGNUM):integer;
var
  bytes : size_t;
begin
    if p = nil then begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    if val = nil then begin
        err_null_argument;
        Exit(0);
    end;
    if (p.data_type = OSSL_PARAM_UNSIGNED_INTEGER)  and  (BN_is_negative(val)>0) then
    begin
        err_bad_type;
        Exit(0);
    end;
    bytes := size_t(BN_num_bytes(val));
    { We add 1 byte for signed numbers, to make space for a sign extension }
    if p.data_type = OSSL_PARAM_INTEGER then
       Inc(bytes);
    p.return_size := bytes;
    if p.data = nil then Exit(1);
    if p.data_size >= bytes then begin
        p.return_size := p.data_size;
        case p.data_type of
          OSSL_PARAM_UNSIGNED_INTEGER:
          begin
              if BN_bn2nativepad(val, p.data, p.data_size) >= 0 then
                  Exit(1);
              ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_INTEGER_OVERFLOW);
          end;
          OSSL_PARAM_INTEGER:
          begin
              if BN_signed_bn2native(val, p.data, p.data_size) >= 0 then
                  Exit(1);
              ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_INTEGER_OVERFLOW);
          end;
          else
              err_bad_type;
              //break;
        end;
        Exit(0);
    end;
    err_too_small;
    Result := 0;
end;

function OSSL_PARAM_set_int64( p : POSSL_PARAM; val : int64):integer;
var
  u64 : uint64;
begin
    if p = nil then
    begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    if p.data_type = OSSL_PARAM_INTEGER then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        p.return_size := sizeof(int64_t); { Expected size }
        if p.data = nil then Exit(1);
        case p.data_size of
          sizeof(int32_t):
          begin
              if (val >= INT32_MIN)  and  (val <= INT32_MAX) then
              begin
                  p.return_size := sizeof(int32_t);
                  Pint32_t(p.data)^ := val;
                  Exit(1);
              end;
              err_out_of_range;
              Exit(0);
          end;
          sizeof(int64_t):
          begin
              Pint64_t(p.data)^ := val;
              Exit(1);
          end;
        end;
{$ENDIF}
        Exit(general_set_int(p, @val, sizeof(val)));
    end
    else
    if (p.data_type = OSSL_PARAM_UNSIGNED_INTEGER)  and  (val >= 0) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        p.return_size := sizeof(uint64_t); { Expected size }
        if p.data = nil then Exit(1);
        case p.data_size of
            sizeof(uint32_t):
            begin
                if val <= UINT32_MAX then begin
                    p.return_size := sizeof(uint32_t);
                    Puint32_t(p.data)^ := uint32_t(val);
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
            sizeof(uint64_t):
            begin
                Puint64_t(p.data)^ := uint64_t(val);
                Exit(1);
            end;
        end;
{$ENDIF}
        Exit(general_set_int(p, @val, sizeof(val)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        p.return_size := sizeof(double);
        if p.data = nil then Exit(1);
        case p.data_size of
          sizeof(double):
          begin
             if val < 0 then
                u64 := -val
             else
                u64 := val;
              if u64  shr  real_shift() = 0 then
              begin
                  Pdouble (p.data)^ := val;
                  Exit(1);
              end;
              err_inexact;
              Exit(0);
          end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;

function real_shift:uint32;
begin
    if sizeof(double) = 4 then
       Result := 24
    else
       Result := 53;
end;

function general_set_int( p : POSSL_PARAM; val : Pointer; val_size : size_t):integer;
var
  r : integer;
begin
    r := 0;
    p.return_size := val_size; { Expected size }
    if p.data = nil then Exit(1);
    if p.data_type = OSSL_PARAM_INTEGER then
       r := signed_from_signed(p.data, p.data_size, val, val_size)
    else
    if (p.data_type = OSSL_PARAM_UNSIGNED_INTEGER) then
        r := unsigned_from_signed(p.data, p.data_size, val, val_size)
    else
        err_not_integer;
    p.return_size := get_result( r >0, p.data_size , val_size);
    Result := r;
end;

function OSSL_PARAM_set_int32( p : POSSL_PARAM; val : integer):integer;
var
  u32, shift : uint32;
begin
    if p = nil then begin
        err_null_argument;
        Exit(0);
    end;
    p.return_size := 0;
    if p.data_type = OSSL_PARAM_INTEGER then begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        p.return_size := sizeof(int32_t); { Minimum expected size }
        if p.data = nil then Exit(1);
        case p.data_size of
            sizeof(int32_t):
            begin
                Pint32_t(p.data)^ := val;
                Exit(1);
            end;
            sizeof(int64_t):
            begin
                p.return_size := sizeof(int64_t);
                Pint64_t(p.data)^ := val;
                Exit(1);
            end;
        end;
{$ENDIF}
        Exit(general_set_int(p, @val, sizeof(val)));
    end
    else
    if (p.data_type = OSSL_PARAM_UNSIGNED_INTEGER)  and  (val >= 0) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        p.return_size := sizeof(uint32_t); { Minimum expected size }
        if p.data = nil then Exit(1);
        case p.data_size of
          sizeof(uint32_t):
          begin
              Puint32_t(p.data)^ := uint32_t(val);
              Exit(1);
          end;
          sizeof(uint64_t):
          begin
              p.return_size := sizeof(uint64_t);
              Puint64_t(p.data)^ := uint64_t(val);
              Exit(1);
          end;
        end;
{$ENDIF}
        Exit(general_set_int(p, @val, sizeof(val)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        p.return_size := sizeof(double);
        if p.data = nil then Exit(1);
        case p.data_size of
          sizeof(double):
          begin
              shift := real_shift();
              if shift < 8 * sizeof(val) - 1  then
              begin
                  u32 := get_result(val < 0 , -val , val);
                  if u32  shr  shift  <> 0 then
                  begin
                      err_inexact;
                      Exit(0);
                  end;
              end;
              Pdouble(p.data)^ := (val);
              Exit(1);
          end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;

function OSSL_PARAM_set_int( p : POSSL_PARAM; val : integer):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(int)) of
    sizeof(int32_t):
        Exit(OSSL_PARAM_set_int32(p, val));
    sizeof(int64_t):
        Exit(OSSL_PARAM_set_int64(p, val));
    end;
{$ENDIF}
    Result := general_set_int(p, @val, sizeof(val));
end;

function get_ptr_internal(const p : POSSL_PARAM; val : PPointer; used_len : Psize_t; &type : uint32):integer;
begin
    if (val = nil)  or  (p = nil) then
    begin
        err_null_argument;
        Exit(0);
    end;
    if p.data_type <> &type then
    begin
        err_bad_type;
        Exit(0);
    end;
    if used_len <> nil then
       used_len^ := p.data_size;
    val^ := PPointer(p.data)^;
    Result := 1;
end;

function OSSL_PARAM_get_octet_ptr(const p : POSSL_PARAM; val : PPointer; used_len : Psize_t):integer;
begin
    Result := get_ptr_internal(p, val, used_len, OSSL_PARAM_OCTET_PTR);
end;

procedure err_too_small;
begin
    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_TOO_SMALL_BUFFER);
end;


function get_string_internal(const p : POSSL_PARAM; val : PPointer; max_len, used_len : Psize_t; _type : uint32):integer;
var
  sz,
  alloc_sz : size_t;
  q: PUTF8Char;
begin
    if ( (val = nil) and (used_len = nil))   or  (p = nil) then
    begin
        err_null_argument;
        Exit(0);
    end;
    if p.data_type <> _type then
    begin
        err_bad_type;
        Exit(0);
    end;
    sz := p.data_size;
    {
     * If the input size is 0, or the input string needs NUL byte
     * termination, allocate an extra byte.
     }
    alloc_sz := sz + 1 + int( (_type = OSSL_PARAM_UTF8_STRING)  or  (sz = 0) );
    //add by softwind 2022-09-02
    alloc_sz := alloc_sz * Char_Size;
    if used_len <> nil then
       used_len^ := sz;
    if p.data = nil then
    begin
        err_null_argument;
        Exit(0);
    end;
    if val = nil then Exit(1);
    if val^ = nil then
    begin
        q := OPENSSL_malloc(alloc_sz);
        if q = nil then
        begin
            ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
        val^ := q;
        max_len^ := alloc_sz;
    end;
    if max_len^ < sz then
    begin
        err_too_small;
        Exit(0);
    end;
    memcpy(val^, p.data, sz);
    //StrCopy(val, PUTF8Char(p.data));
    Result := 1;
end;

function OSSL_PARAM_get_utf8_string(const p : POSSL_PARAM; val : PPUTF8Char; max_len : size_t):integer;
var
    ret         : integer;
    data_length : size_t;
begin
    ret := get_string_internal(p, PPOINTER(val), @max_len, nil,
                                  OSSL_PARAM_UTF8_STRING);
    {
     * We try to ensure that the copied string is terminated with a
     * NUL byte.  That should be easy, just place a NUL byte at
     * |((char*)*val)[p.data_size]|.
     * Unfortunately, we have seen cases where |p.data_size| doesn't
     * correctly reflect the length of the string, and just happens
     * to be out of bounds according to |max_len|, so in that case, we
     * make the extra step of trying to find the true length of the
     * string that |p.data| points at, and use that as an index to
     * place the NUL byte in |*val|.
     }
    data_length := p.data_size;
    if ret = 0 then Exit(0);
    if data_length >= max_len then
       data_length := OPENSSL_strnlen(p.data, data_length);
    if data_length >= max_len then
    begin
        ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_NO_SPACE_FOR_TERMINATING_NULL);
        Exit( 0);            { No space for a terminating NUL byte }
    end;
    val^[data_length] := #0;
    Result := ret;
end;

procedure err_not_integer;
begin
    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_NOT_INTEGER_TYPE);
end;

function unsigned_from_unsigned(dest : Pointer; dest_len : size_t;const src : Pointer; src_len : size_t):integer;
begin
    Result := copy_integer(dest, dest_len, src, src_len, 0, 0);
end;

procedure err_unsigned_negative ;
begin
    ERR_raise(ERR_LIB_CRYPTO,
              CRYPTO_R_PARAM_UNSIGNED_INTEGER_NEGATIVE_VALUE_UNSUPPORTED);
end;

function unsigned_from_signed(dest : Pointer; dest_len : size_t;const src : Pointer; src_len : size_t):integer;
begin
    if is_negative(src, src_len)>0 then
    begin
        err_unsigned_negative;
        Exit(0);
    end;
    Result := copy_integer(dest, dest_len, src, src_len, 0, 0);
end;

function general_get_uint(const p : POSSL_PARAM; val : Pointer; val_size : size_t):integer;
begin
    if p.data_type = OSSL_PARAM_INTEGER then
       Exit(unsigned_from_signed(val, val_size, p.data, p.data_size));
    if p.data_type = OSSL_PARAM_UNSIGNED_INTEGER then
       Exit(unsigned_from_unsigned(val, val_size, p.data, p.data_size));
    err_not_integer;
    Result := 0;
end;

function OSSL_PARAM_get_uint32(const p : POSSL_PARAM; val : Puint32_t):integer;
var
  d : Double;
  u64 : uint64;
  i32 : integer;
  i64 : int64;
begin
    if (val = nil)  or  (p = nil) then
    begin
        err_null_argument;
        Exit(0);
    end;
    if p.data_type = OSSL_PARAM_UNSIGNED_INTEGER then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
            sizeof(uint32_t):
            begin
                val^ := Puint32_t(p.data)^;
                Exit(1);
            end;
            sizeof(uint64_t):
            begin
                u64 := Pint64_t(p.data)^;
                if u64 <= UINT32_MAX then
                begin
                    val^ := uint32_t(u64);
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
        end;
{$ENDIF}
        Exit(general_get_uint(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_INTEGER) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
            sizeof(uint32_t):
            begin
                i32 := Pint32_t(p.data)^;
                if i32 >= 0 then begin
                    val^ := i32;
                    Exit(1);
                end;
                err_unsigned_negative;
                Exit(0);
            end;
            sizeof(uint64_t):
            begin
                i64 := Pint64_t(p.data)^;
                if (i64 >= 0)  and  (i64 <= UINT32_MAX) then
                begin
                    val^ := uint32_t(i64);
                    Exit(1);
                end;
                if i64 < 0 then
                   err_unsigned_negative
                else
                    err_out_of_range;
                Exit(0);
            end;
        end;
{$ENDIF}
        Exit(general_get_uint(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        case p.data_size of
          sizeof(double):
          begin
              d := Pdouble (p.data)^;
              if (d >= 0)  and  (d <= UINT32_MAX)  and  (d = Round( d))then
              begin
                  val^ := Round(d);
                  Exit(1);
              end;
              err_inexact;
              Exit(0);
          end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;

function OSSL_PARAM_get_BN(const p : POSSL_PARAM; val : PPBIGNUM):integer;
var
  b : PBIGNUM;
begin
    b := nil;
    if (val = nil)  or  (p = nil) then
    begin
        err_null_argument;
        Exit(0);
    end;
    case p.data_type of
      OSSL_PARAM_UNSIGNED_INTEGER:
          b := BN_native2bn(p.data, int(p.data_size), val^);
          //break;
      OSSL_PARAM_INTEGER:
          b := BN_signed_native2bn(p.data, int(p.data_size), val^);
          //break;
      else
          err_bad_type;
          //break;
    end;
    if b = nil then
    begin
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    val^ := b;
    Result := 1;
end;

procedure err_bad_type ;
begin
    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_OF_INCOMPATIBLE_TYPE);
end;

procedure err_inexact ;
begin
    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_CANNOT_BE_REPRESENTED_EXACTLY);
end;

procedure err_null_argument ;
begin
    ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
end;

function OSSL_PARAM_get_int64(const p : POSSL_PARAM; val : Pint64_t):integer;
var
  d : Double;
  u64 : uint64;
begin
    if (val = nil)  or  (p = nil) then
    begin
        err_null_argument;
        Exit(0);
    end;
    if p.data_type = OSSL_PARAM_INTEGER then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
          sizeof(uint32_t):
          begin
              val^ := Pint32_t(p.data)^;
              Exit(1);
          end;
          sizeof(uint64_t):
          begin
              val^ := Pint64_t(p.data)^;
              Exit(1);
          end;
        end;
{$ENDIF}
        Exit(general_get_int(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_UNSIGNED_INTEGER) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
            sizeof(uint32_t):
            begin
                val^ := Pint32_t(p.data)^;
                Exit(1);
            end;
            sizeof(uint64_t):
            begin
                u64 := Pint64_t(p.data)^;
                if u64 <= INT64_MAX then
                begin
                    val^ := u64;
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
        end;
{$ENDIF}
        Exit(general_get_int(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        case p.data_size of
          sizeof(double):
          begin
              d := PDouble(p.data)^;
              if (d >= INT64_MIN)
                      {
                       * By subtracting 65535 (2^16-1 then we cancel the low order
                       * 15 bits of INT64_MAX to avoid using imprecise floating
                       * point values.
                       }
                       and  (d < (INT64_MAX - 65535) + 65536.0 )
                       and  (d = Round(d) ) then
              begin
                  val^ := Round(d);
                  Exit(1);
              end;
              err_inexact;
              Exit(0);
          end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;

procedure err_unsupported_real;
begin
    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_UNSUPPORTED_FLOATING_POINT_FORMAT);
end;

procedure err_out_of_range;
begin
    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION)
end;

function signed_from_unsigned(dest : Pointer; dest_len : size_t;const src : Pointer; src_len : size_t):integer;
begin
    Result := copy_integer(dest, dest_len, src, src_len, 0, 1);
end;

function is_negative(const number : Pointer; s : size_t):integer;
var
  n : PByte;
  ossl_is_endian: endian_st;
begin
    n := number;
    ossl_is_endian.one := 1;
    Result := $80 and (get_result(ossl_is_endian.little = 0, n[0] , n[s - 1]));
end;

function check_sign_bytes(const p : PByte; n : size_t; s : Byte):integer;
var
  i : size_t;
begin
    for i := 0 to n-1 do
        if p[i] <> s then Exit(0);
    Result := 1;
end;

function copy_integer(dest : PByte; dest_len : size_t;const src : PByte; src_len : size_t; pad : Byte; signed_int : integer):integer;
var
  n : size_t;
  ossl_is_endian: endian_st;
begin
   ossl_is_endian.one := 1;
   if ossl_is_endian.little = 0 then
    begin
        if src_len < dest_len then
        begin
            n := dest_len - src_len;
            memset(dest, pad, n);
            memcpy(dest + n, src, src_len);
        end
        else
        begin
            n := src_len - dest_len;
            if  (0>= check_sign_bytes(src, n, pad))   or   {
                     * Shortening a signed value must retain the correct sign.
                     * Avoiding this kind of thing: -253 = $ff03 . $03 = 3
                     }
                ( (signed_int>0)
                  and ( ((pad  xor  src[n]) and $80) <> 0 )
                ) then
            begin
                 ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION);
                Exit(0);
            end;
            memcpy(dest, src + n, dest_len);
        end;
    end
    else { IS_LITTLE_ENDIAN }
    begin
        if src_len < dest_len then
        begin
            n := dest_len - src_len;
            memset(dest + src_len, pad, n);
            memcpy(dest, src, src_len);
        end
        else
        begin
            n := src_len - dest_len;
            if  (0>= check_sign_bytes(src + dest_len, n, pad )) or{
                     * Shortening a signed value must retain the correct sign.
                     * Avoiding this kind of thing: 130 = $0082 . $82 = -126
                     }
                ( (signed_int>0)  and
                  ( ((pad  xor  src[dest_len - 1]) and $80) <> 0)
                ) then
            begin
                ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION);
                Exit(0);
            end;
            memcpy(dest, src, dest_len);
        end;
    end;
    Result := 1;
end;

function signed_from_signed(dest : Pointer; dest_len : size_t;const src : Pointer; src_len : size_t):integer;
begin
    Exit(copy_integer(dest, dest_len, src, src_len,
                      get_result(is_negative(src, src_len)>0 , $ff , 0), 1));
end;

function general_get_int(const p : POSSL_PARAM; val : Pointer; val_size : size_t):integer;
begin
    if p.data_type = OSSL_PARAM_INTEGER then
       Exit(signed_from_signed(val, val_size, p.data, p.data_size));
    if p.data_type = OSSL_PARAM_UNSIGNED_INTEGER then
       Exit(signed_from_unsigned(val, val_size, p.data, p.data_size));
    ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_NOT_INTEGER_TYPE);
    Result := 0;
end;

function OSSL_PARAM_get_int32(const p : POSSL_PARAM;val : Pint32_t):integer;
var
  d : Double;
  i64 : int64;
  u32 : uint32;
  u64 : uint64;
begin
    if (val = nil)  or  (p = nil) then
    begin
        //err_null_argument;
        ERR_raise(ERR_LIB_CRYPTO, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if p.data_type = OSSL_PARAM_INTEGER then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
            sizeof(int32_t):
            begin
                val^ := Pint32_t(p.data)^;
                Exit(1);
            end;
            sizeof(int64_t):
            begin
                i64 := Pint64_t (p.data)^;
                if (i64 >= INT32_MIN)  and  (i64 <= INT32_MAX) then
                begin
                    val^ := i64;
                    Exit(1);
                end;
                ERR_raise(ERR_LIB_CRYPTO, CRYPTO_R_PARAM_VALUE_TOO_LARGE_FOR_DESTINATION);
                Exit(0);
            end;
        end;
{$ENDIF}
        Exit(general_get_int(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_UNSIGNED_INTEGER) then
    begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
        case p.data_size of
            sizeof(uint32_t):
            begin
                u32 := Puint32_t(p.data)^;
                if u32 <= INT32_MAX then
                begin
                    val^ := u32;
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
            sizeof(uint64_t):
            begin
                u64 := Puint64_t(p.data)^;
                if u64 <= INT32_MAX then
                begin
                    val^ := u64;
                    Exit(1);
                end;
                err_out_of_range;
                Exit(0);
            end;
        end;
{$ENDIF}
        Exit(general_get_int(p, val, sizeof( val^)));
    end
    else
    if (p.data_type = OSSL_PARAM_REAL) then
    begin
        case p.data_size of
          sizeof(double):
          begin
              d := Pdouble (p.data)^;
              if (d >= INT32_MIN)  and  (d <= INT32_MAX)  and
                 (d = int32_t(Round(d)))  then
              begin
                  val^ := Round(d);
                  Exit(1);
              end;
              err_out_of_range;
              Exit(0);
          end;
        end;
        err_unsupported_real;
        Exit(0);
    end;
    err_bad_type;
    Result := 0;
end;


function OSSL_PARAM_get_int(const p : POSSL_PARAM;val : Pinteger):integer;
begin
{$IFNDEF OPENSSL_SMALL_FOOTPRINT}
    case (sizeof(int)) of
    sizeof(int32):
        Exit(OSSL_PARAM_get_int32(p, Pint32_t (val)));
    sizeof(Int64):
        Exit(OSSL_PARAM_get_int64(p, Pint64_t (val)));
    end;
{$ENDIF}
    Result := general_get_int(p, val, sizeof( val^));
end;

function OSSL_PARAM_locate(p : POSSL_PARAM;const key : PUTF8Char):POSSL_PARAM;
begin
    if (p <> nil)  and  (key <> nil) then
       while p.key <> nil do
       begin
          if strcmp(key, p.key) = 0   then
                Exit(p);
          Inc(p);
       end;
    Result := nil;
end;

function OSSL_PARAM_locate_const(const p : POSSL_PARAM; key : PUTF8Char):POSSL_PARAM;
begin
    Result := OSSL_PARAM_locate(p, key);
end;

function OSSL_PARAM_construct_octet_ptr(const key : PUTF8Char; buf : PPointer; bsize : size_t):TOSSL_PARAM;
begin
    Result := ossl_param_construct(key, OSSL_PARAM_OCTET_PTR, buf, bsize);
end;


function OSSL_PARAM_construct_octet_string(const key : PUTF8Char; buf : Pointer; bsize : size_t):TOSSL_PARAM;
begin
    Result := ossl_param_construct(key, OSSL_PARAM_OCTET_STRING, buf, bsize);
end;

function OSSL_PARAM_construct_utf8_ptr(const key : PUTF8Char; buf : PPUTF8Char; bsize : size_t):TOSSL_PARAM;
begin
    Result := ossl_param_construct(key, OSSL_PARAM_UTF8_PTR, buf, bsize);
end;


function OSSL_PARAM_construct_utf8_string(const key : PUTF8Char; buf : PUTF8Char; bsize : size_t):TOSSL_PARAM;
begin
    if (buf <> nil)  and  (bsize = 0) then
       bsize := Length(buf);
    Result := ossl_param_construct(key, OSSL_PARAM_UTF8_STRING, buf, bsize);
end;

function OSSL_PARAM_construct_uint(const key : PUTF8Char; buf : Puint32):TOSSL_PARAM;
begin
    Exit(ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf,  sizeof(uint32)));
end;

function OSSL_PARAM_construct_BN(const key : PUTF8Char; buf : PByte; bsize : size_t):TOSSL_PARAM;
begin
    Exit(ossl_param_construct(key, OSSL_PARAM_UNSIGNED_INTEGER, buf, bsize));
end;


function OSSL_PARAM_construct_end: TOSSL_PARAM;
var
  _end : TOSSL_PARAM;
begin
    _end := OSSL_PARAM_END;
    Result := _end;
end;

function ossl_param_construct(const key : PUTF8Char; data_type : uint32; data : Pointer; data_size : size_t):TOSSL_PARAM;
begin
    Result.key := key;
    Result.data_type := data_type;
    Result.data := data;
    Result.data_size := data_size;
    Result.return_size := OSSL_PARAM_UNMODIFIED;
end;

function OSSL_PARAM_construct_int(const key : PUTF8Char; buf : Pinteger):TOSSL_PARAM;
begin
    Result := ossl_param_construct(key, OSSL_PARAM_INTEGER, buf, sizeof(int));
end;

end.
