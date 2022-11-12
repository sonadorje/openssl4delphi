unit openssl3.crypto.core_algorithm;

interface
uses OpenSSL.Api;

type
  Tpre_func = function(p1: POSSL_PROVIDER; operation_id: Integer; data: Pointer; result1: PInteger): Integer;
  Talgorithm_fn = procedure(provider : POSSL_PROVIDER;const algo : POSSL_ALGORITHM; no_store : integer; data : Pointer);
  Tpost_func = function(p1: POSSL_PROVIDER; operation_id: Integer; no_store: Integer; data: Pointer; result1: PInteger): Integer;

procedure ossl_algorithm_do_all( libctx : POSSL_LIB_CTX; operation_id : integer; provider : POSSL_PROVIDER; pre : Tpre_func; fn : Talgorithm_fn; post : Tpost_func; data : Pointer);
function ossl_algorithm_get1_first_name(const algo : POSSL_ALGORITHM):PUTF8Char;
function algorithm_do_this( provider : POSSL_PROVIDER; cbdata : Pointer):integer;
function _OSSL_FUNC_keymgmt_new(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_new_fn;
function _OSSL_FUNC_keymgmt_gen_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_gen_init_fn;
function _OSSL_FUNC_keymgmt_gen_set_template(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_set_template_fn;
function _OSSL_FUNC_keymgmt_gen_set_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_set_params_fn;
function _OSSL_FUNC_keymgmt_gen_settable_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_settable_params_fn;
 function _OSSL_FUNC_keymgmt_gen(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_fn;
 function _OSSL_FUNC_keymgmt_gen_cleanup(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_cleanup_fn;
 function _OSSL_FUNC_keymgmt_free(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_free_fn;
 function _OSSL_FUNC_keymgmt_load(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_load_fn;
 function _OSSL_FUNC_keymgmt_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_get_params_fn;
 function _OSSL_FUNC_keymgmt_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_gettable_params_fn;
 function _OSSL_FUNC_keymgmt_set_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_set_params_fn;
 function _OSSL_FUNC_keymgmt_settable_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_settable_params_fn;
 function _OSSL_FUNC_keymgmt_query_operation_name(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_query_operation_name_fn;
 function _OSSL_FUNC_keymgmt_has(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_has_fn;
 function _OSSL_FUNC_keymgmt_dup(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_dup_fn;
 function _OSSL_FUNC_keymgmt_validate(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_validate_fn;
 function _OSSL_FUNC_keymgmt_match(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_match_fn;
 function _OSSL_FUNC_keymgmt_import(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_import_fn;
 function _OSSL_FUNC_keymgmt_import_types(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_import_types_fn;
 function _OSSL_FUNC_keymgmt_export(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_fn;
 function _OSSL_FUNC_keymgmt_export_types(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_types_fn;
 function _OSSL_FUNC_kem_newctx(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_newctx_fn;
 function _OSSL_FUNC_kem_encapsulate_init(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_encapsulate_init_fn;
 function _OSSL_FUNC_kem_encapsulate(const opf : POSSL_DISPATCH):TOSSL_FUNC_kem_encapsulate_fn;
 function _OSSL_FUNC_kem_decapsulate_init(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_decapsulate_init_fn;

  function _OSSL_FUNC_kem_decapsulate(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_decapsulate_fn;
  function _OSSL_FUNC_kem_freectx(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_freectx_fn;
  function _OSSL_FUNC_kem_dupctx(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_dupctx_fn;
  function _OSSL_FUNC_kem_get_ctx_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_get_ctx_params_fn;
  function _OSSL_FUNC_kem_gettable_ctx_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_gettable_ctx_params_fn;
  function _OSSL_FUNC_kem_set_ctx_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_set_ctx_params_fn;
  function _OSSL_FUNC_kem_settable_ctx_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_settable_ctx_params_fn;
  function _OSSL_FUNC_decoder_newctx(const opf : POSSL_DISPATCH): TOSSL_FUNC_decoder_newctx_fn;
  function _OSSL_FUNC_decoder_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_freectx_fn;
  function _OSSL_FUNC_decoder_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_get_params_fn;
  function _OSSL_FUNC_decoder_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_gettable_params_fn;
  function _OSSL_FUNC_decoder_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_set_ctx_params_fn;
  function _OSSL_FUNC_decoder_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_settable_ctx_params_fn;
  function _OSSL_FUNC_decoder_does_selection(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_does_selection_fn;
  function _OSSL_FUNC_decoder_decode(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_decode_fn;
  function _OSSL_FUNC_decoder_export_object(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_export_object_fn;

  function _OSSL_FUNC_encoder_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_newctx_fn;
  function _OSSL_FUNC_encoder_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_freectx_fn;
  function _OSSL_FUNC_encoder_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_get_params_fn;
  function _OSSL_FUNC_encoder_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_gettable_params_fn;
  function _OSSL_FUNC_encoder_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_set_ctx_params_fn;
  function _OSSL_FUNC_encoder_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_settable_ctx_params_fn;
  function _OSSL_FUNC_encoder_does_selection(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_does_selection_fn;
  function _OSSL_FUNC_encoder_encode(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_encode_fn;
  function _OSSL_FUNC_encoder_import_object(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_import_object_fn;
  function _OSSL_FUNC_encoder_free_object(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_free_object_fn;

implementation
uses
   openssl3.crypto.provider_core, openssl3.crypto.o_str, OpenSSL3.Err,
   OpenSSL3.common, openssl3.crypto.context;


function algorithm_do_this( provider : POSSL_PROVIDER; cbdata : Pointer):integer;
var
  _cbdata         : Palgorithm_data_st;
  no_store,
  first_operation,
  last_operation,
  cur_operation,
  ok              : integer;
  map,thismap     : POSSL_ALGORITHM;
  ret             : integer;
begin
    _cbdata := cbdata;
    no_store := 0;
    first_operation := 1;
    last_operation := OSSL_OP__HIGHEST;
    ok := 1;
    if _cbdata.operation_id <> 0 then
    begin
       last_operation := _cbdata.operation_id;
       first_operation := last_operation;
    end;
    cur_operation := first_operation;
    while  cur_operation <= last_operation do
    begin
        map := nil;
        { Do we fulfill pre-conditions? }
        if not Assigned(_cbdata.pre) then
        begin
            { If there is no pre-condition function, assume 'yes' }
            ret := 1;
        end
        else
        begin
          if  (0>= _cbdata.pre(provider, cur_operation, _cbdata.data, @ret)) then
              { Error, bail out! }
              Exit(0);
        end;
        { If pre-condition not fulfilled, go to the next operation }
        if  0>= ret then
        begin
           Inc(cur_operation);
           continue;
        end;

        map := ossl_provider_query_operation(provider, cur_operation, no_store);
        if map <> nil then
        begin
            thismap := map;
            while ( thismap.algorithm_names <> nil) do
            begin
            //core_fetch.ossl_method_construct_this
            {writeln('thismap.algorithm_names:'+ thismap.algorithm_names);
            if thismap.algorithm_names = 'RSA' then
              writeln('bug:'+ thismap.algorithm_names);
            }
              _cbdata.fn(provider, thismap, no_store, _cbdata.data);
              Inc(thismap);
            end;
        end;

        ossl_provider_unquery_operation(provider, cur_operation, map);
        { Do we fulfill post-conditions? }
        if not Assigned(_cbdata.post) then
        begin
            { If there is no post-condition function, assume 'yes' }
            ret := 1;
        end
        else
        begin   //core_fetch.ossl_method_construct_postcondition
            if  0>= _cbdata.post(provider, cur_operation, no_store, _cbdata.data, @ret)  then
                { Error, bail out! }
                Exit(0);
        end;
        { If post-condition not fulfilled, set general failure }
        if  0>= ret then
            ok := 0;

        Inc(cur_operation);
    end;
    Result := ok;
end;

function ossl_algorithm_get1_first_name(const algo : POSSL_ALGORITHM):PUTF8Char;
var
    first_name_end : PUTF8Char;
    first_name_len : size_t;
    ret            : PUTF8Char;
begin
    first_name_end := nil;
    first_name_len := 0;
    if algo.algorithm_names = nil then Exit(nil);
    first_name_end := strchr(algo.algorithm_names, ':');
    if first_name_end = nil then
       first_name_len := Length(algo.algorithm_names)
    else
       first_name_len := first_name_end - algo.algorithm_names;

    OPENSSL_strndup(ret, algo.algorithm_names, first_name_len);
    if ret = nil then
       ERR_raise(ERR_LIB_EVP, ERR_R_MALLOC_FAILURE);
    Result := ret;
end;

procedure ossl_algorithm_do_all( libctx : POSSL_LIB_CTX; operation_id : integer; provider : POSSL_PROVIDER; pre : Tpre_func; fn : Talgorithm_fn; post : Tpost_func; data : Pointer);
var
  cbdata : algorithm_data_st;
  libctx2 : POSSL_LIB_CTX;
begin
    {$IFNDEF FPC}
    cbdata := default(algorithm_data_st);
    {$ELSE}
     FillChar(cbdata, sizeof(cbdata), 0);
    {$ENDIF}
    cbdata.libctx := libctx;
    cbdata.operation_id := operation_id;
    cbdata.pre := pre;
    cbdata.fn := fn;
    cbdata.post := post;
    cbdata.data := data;
    if provider = nil then
    begin
        ossl_provider_doall_activated(libctx, algorithm_do_this, @cbdata);
    end
    else
    begin
        libctx2 := ossl_provider_libctx(provider);
        {
         * If a provider is given, its library context MUST match the library
         * context we're passed.  If this turns out not to be true, there is
         * a programming error in the functions up the call stack.
         }
        if  not ossl_assert(
             ossl_lib_ctx_get_concrete(libctx)= ossl_lib_ctx_get_concrete(libctx2))  then
            exit;
        cbdata.libctx := libctx2;
        algorithm_do_this(provider, @cbdata);
    end;
end;

function _OSSL_FUNC_encoder_newctx(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_newctx_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_newctx_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_freectx_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_freectx_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_get_params_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_get_params_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_gettable_params_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_gettable_params_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_set_ctx_params_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_set_ctx_params_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_settable_ctx_params_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_settable_ctx_params_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_does_selection(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_does_selection_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_does_selection_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_encode(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_encode_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_encode_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_import_object(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_import_object_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_import_object_fn *)opf.function);
end;


function _OSSL_FUNC_encoder_free_object(const opf : POSSL_DISPATCH):TOSSL_FUNC_encoder_free_object_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_encoder_free_object_fn *)opf.function);
end;

function _OSSL_FUNC_decoder_does_selection(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_does_selection_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_does_selection_fn *)opf.function);
end;


function _OSSL_FUNC_decoder_decode(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_decode_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_decode_fn *)opf.function);
end;


function _OSSL_FUNC_decoder_export_object(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_export_object_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_export_object_fn *)opf.function);
end;

function _OSSL_FUNC_decoder_settable_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_settable_ctx_params_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_settable_ctx_params_fn *)opf.function);
end;

function _OSSL_FUNC_decoder_freectx(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_freectx_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_freectx_fn *)opf.function);
end;


function _OSSL_FUNC_decoder_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_get_params_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_get_params_fn *)opf.function);
end;


function _OSSL_FUNC_decoder_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_gettable_params_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_gettable_params_fn *)opf.function);
end;


function _OSSL_FUNC_decoder_set_ctx_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_decoder_set_ctx_params_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_set_ctx_params_fn *)opf.function);
end;

function _OSSL_FUNC_decoder_newctx(const opf : POSSL_DISPATCH): TOSSL_FUNC_decoder_newctx_fn;
begin
   result := opf.method.Code; //((OSSL_FUNC_decoder_newctx_fn *)opf.function);
end;

function _OSSL_FUNC_kem_decapsulate_init(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_decapsulate_init_fn;
begin
   result := opf.method.Code; // (OSSL_FUNC_kem_decapsulate_init_fn *)opf.function;
end;


function _OSSL_FUNC_kem_decapsulate(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_decapsulate_fn;
begin
   result := opf.method.Code; // (OSSL_FUNC_kem_decapsulate_fn *)opf.function;
end;


function _OSSL_FUNC_kem_freectx(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_freectx_fn;
begin
   result := opf.method.Code; // (OSSL_FUNC_kem_freectx_fn *)opf.function;
end;


function _OSSL_FUNC_kem_dupctx(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_dupctx_fn;
begin
   result := opf.method.Code; // (OSSL_FUNC_kem_dupctx_fn *)opf.function;
end;


function _OSSL_FUNC_kem_get_ctx_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_get_ctx_params_fn;
begin
   result := opf.method.Code; // (OSSL_FUNC_kem_get_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_kem_gettable_ctx_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_gettable_ctx_params_fn;
begin
   result := opf.method.Code; // (OSSL_FUNC_kem_gettable_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_kem_set_ctx_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_set_ctx_params_fn;
begin
   result := opf.method.Code; // (OSSL_FUNC_kem_set_ctx_params_fn *)opf.function;
end;


function _OSSL_FUNC_kem_settable_ctx_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_settable_ctx_params_fn;
begin
   result := opf.method.Code; // (OSSL_FUNC_kem_settable_ctx_params_fn *)opf.function;
end;



function _OSSL_FUNC_kem_encapsulate(const opf : POSSL_DISPATCH):TOSSL_FUNC_kem_encapsulate_fn;
begin
    result :=  opf.method.Code; //(OSSL_FUNC_kem_encapsulate_fn *)opf.function);
end;



function _OSSL_FUNC_kem_encapsulate_init(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_encapsulate_init_fn;
begin
   result :=  opf.method.Code; // (OSSL_FUNC_kem_encapsulate_init_fn *)opf.function;
end;



function _OSSL_FUNC_kem_newctx(const opf : POSSL_DISPATCH): TOSSL_FUNC_kem_newctx_fn;
begin
   result :=  opf.method.Code; //(OSSL_FUNC_kem_newctx_fn *)opf->function;
end;


function _OSSL_FUNC_keymgmt_export_types(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_types_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_export_types_fn *)opf.function;
end;




function _OSSL_FUNC_keymgmt_export(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_export_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_export_fn *)opf.function;
end;



function _OSSL_FUNC_keymgmt_import_types(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_import_types_fn;
begin
  Result := opf.method.Code;// (OSSL_FUNC_keymgmt_import_types_fn *)opf.function;
end;


function _OSSL_FUNC_keymgmt_import(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_import_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_import_fn *)opf.function;
end;

function _OSSL_FUNC_keymgmt_match(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_match_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_match_fn *)opf.function;
end;


function _OSSL_FUNC_keymgmt_validate(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_validate_fn;
begin
    Result := opf.method.Code;//(OSSL_FUNC_keymgmt_validate_fn *)opf.function;
end;




function _OSSL_FUNC_keymgmt_dup(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_dup_fn;
begin
  Result := opf.method.Code;// (OSSL_FUNC_keymgmt_dup_fn *)opf.function;
end;

function _OSSL_FUNC_keymgmt_has(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_has_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_has_fn *)opf.function;
end;


function _OSSL_FUNC_keymgmt_query_operation_name(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_query_operation_name_fn;
begin
  Result := opf.method.Code;// (OSSL_FUNC_keymgmt_query_operation_name_fn *)opf.function;
end;




function _OSSL_FUNC_keymgmt_settable_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_settable_params_fn;
begin
  Result := opf.method.Code;// (OSSL_FUNC_keymgmt_settable_params_fn *)opf.function;
end;




function _OSSL_FUNC_keymgmt_set_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_set_params_fn;
begin
  Result := opf.method.Code;//  (OSSL_FUNC_keymgmt_set_params_fn *)opf.function;
end;



function _OSSL_FUNC_keymgmt_gettable_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_gettable_params_fn;
begin
  Result := opf.method.Code;// (OSSL_FUNC_keymgmt_gettable_params_fn *)opf.function;
end;





function _OSSL_FUNC_keymgmt_get_params(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_get_params_fn;
begin
  Result := opf.method.Code;// (OSSL_FUNC_keymgmt_get_params_fn *)opf.function;
end;




function _OSSL_FUNC_keymgmt_load(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_load_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_load_fn *)opf.function;
end;




function _OSSL_FUNC_keymgmt_free(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_free_fn;
begin
  Result := opf.method.Code;//(OSSL_FUNC_keymgmt_free_fn *)opf.function;
end;

function _OSSL_FUNC_keymgmt_gen_cleanup(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_cleanup_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_gen_cleanup_fn *)opf.function;
end;


function _OSSL_FUNC_keymgmt_gen(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_fn;
begin
  Result := opf.method.Code;// (OSSL_FUNC_keymgmt_gen_fn *)opf.function;
end;




function _OSSL_FUNC_keymgmt_gen_settable_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_settable_params_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_gen_settable_params_fn *)opf.function;
end;




function _OSSL_FUNC_keymgmt_gen_set_params(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_gen_set_params_fn;
begin
  Result := opf.method.Code;//  (OSSL_FUNC_keymgmt_gen_set_params_fn *)opf.function;
end;

function _OSSL_FUNC_keymgmt_gen_set_template(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_gen_set_template_fn;
begin
   Result := opf.method.Code;// (OSSL_FUNC_keymgmt_gen_set_template_fn *)opf.function;
end;

function _OSSL_FUNC_keymgmt_gen_init(const opf : POSSL_DISPATCH):TOSSL_FUNC_keymgmt_gen_init_fn;
begin
   Result := opf.method.Code;//(OSSL_FUNC_keymgmt_gen_init_fn *)opf.function;
end;

function _OSSL_FUNC_keymgmt_new(const opf : POSSL_DISPATCH): TOSSL_FUNC_keymgmt_new_fn;
begin
   RESULT := opf.method.Code //TOSSL_FUNC_keymgmt_new_fn(opf._function);
end;

end.
