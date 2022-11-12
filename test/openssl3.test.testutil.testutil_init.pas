unit openssl3.test.testutil.testutil_init;

{$IFDEF FPC}
  {$MODE Delphi}
{$ENDIF}

interface
uses OpenSSL.api;

type
  tracedata_st = record
    bio : PBIO;
    ingroup : uint32;
  end;
  tracedata = tracedata_st;
  Ptracedata = ^tracedata;
  Pstack_st_tracedata = Pointer;

  {
function internal_trace_cb(const buf : PChar; cnt : size_t; category, cmd : integer; vdata : Pointer):size_t;
  procedure tracedata_free( data : Ptracedata);
  procedure cleanup_trace;
  procedure setup_trace_category( category : integer);
  procedure setup_trace(const str : PChar);
  }
  function global_init:integer;

var
  trace_data_stack : Pstack_st_tracedata;

implementation

{
function internal_trace_cb(const buf : PChar; cnt : size_t; category, cmd : integer; vdata : Pointer):size_t;
var
    ret        : integer;
    trace_data : Ptracedata;
    buffer     : array[0..255] of byte;
    tid        : CRYPTO_THREAD_ID;
begin
    ret := 0;
    trace_data := vdata;
    char buffer[256], *hex;
    case cmd of
    OSSL_TRACE_CTRL_BEGIN:
        trace_data.ingroup := 1;
        tid := CRYPTO_THREAD_get_current_id;
        hex := OPENSSL_buf2hexstr((const PByte )&tid, sizeof(tid));
        BIO_snprintf(buffer, sizeof(buffer), 'TRACE[%s]:%s: ',
                     hex, OSSL_trace_get_category_name(category));
        OPENSSL_free(hex);
        BIO_set_prefix(trace_data.bio, buffer);
        break;
    OSSL_TRACE_CTRL_WRITE:
        ret := BIO_write(trace_data.bio, buf, cnt);
        break;
    OSSL_TRACE_CTRL_END:
        trace_data.ingroup := 0;
        BIO_set_prefix(trace_data.bio, nil);
        break;
    end;
    Result := ret < 0 ? 0 : ret;
end;


procedure tracedata_free( data : Ptracedata);
begin
    BIO_free_all(data.bio);
    OPENSSL_free(data);
end;


procedure cleanup_trace;
begin
    sk_tracedata_pop_free(trace_data_stack, tracedata_free);
end;


procedure setup_trace_category( category : integer);
var
    channel    : PBIO;

    trace_data : Ptracedata;

    bio        : PBIO;
begin
    bio := nil;
    if OSSL_trace_enabled(category then )
        return;
    bio := BIO_new(BIO_f_prefix);
    channel := BIO_push(bio,
                       BIO_new_fp(stderr, BIO_NOCLOSE or BIO_FP_TEXT));
    trace_data := OPENSSL_zalloc(sizeof( *trace_data));
    if trace_data = nil
         or  bio = nil
         or  (trace_data.bio = channel then = nil
         or  OSSL_trace_set_callback(category, internal_trace_cb,
                                   trace_data) = 0
         or  sk_tracedata_push(trace_data_stack, trace_data) = 0) begin
        fprintf(stderr,
                'warning: unable to setup trace callback for category '%s'.\n',
                OSSL_trace_get_category_name(category));
        OSSL_trace_set_callback(category, nil, nil);
        BIO_free_all(channel);
    end;
end;


procedure setup_trace(const str : PChar);
var
  val,
  valp,
  item     : PChar;
  category : integer;
begin

    //  We add this handler as early as possible to ensure it's executed
    //  as late as possible, i.e. after the TRACE code has done its cleanup
    //  (which happens last in OPENSSL_cleanup).

    atexit(cleanup_trace);
    trace_data_stack := sk_tracedata_new_null;
    val := OPENSSL_strdup(str);
    if val <> nil then
    begin
        valp := val;
        for (valp = val; (item = strtok(valp, ',')) <> nil; valp = nil) begin
            category := OSSL_trace_get_category_num(item);
            if category = OSSL_TRACE_CATEGORY_ALL then begin
                while PreInc(category) < OSSL_TRACE_CATEGORY_NUM do
                    setup_trace_category(category);
                break;
            end
            else if (category > 0) begin then
                setup_trace_category(category);
            end
            else
            begin
                fprintf(stderr,
                        'warning: unknown trace category: '%s'.\n', item);
            end;
        end;
    end;
    OPENSSL_free(val);
end;
}

function global_init:integer;
begin
{$IFNDEF OPENSSL_NO_TRACE}
    //setup_trace(getenv('OPENSSL_TRACE'));
{$ENDIF}
    Result := 1;
end;

end.
