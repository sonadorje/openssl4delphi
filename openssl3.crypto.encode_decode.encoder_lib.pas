unit openssl3.crypto.encode_decode.encoder_lib;

interface
uses OpenSSL.Api, SysUtils;

type
    encoder_process_data_st = record
        ctx                        : POSSL_ENCODER_CTX;
        bio                        : PBIO;
        current_encoder_inst_index,
        level                      : integer;
        next_encoder_inst          : POSSL_ENCODER_INSTANCE;
        count_output_structure     : integer;
        prev_encoder_inst          : POSSL_ENCODER_INSTANCE;
        running_output             : PByte;
        running_output_length      : size_t;
        data_type                  : PUTF8Char;
    end;
    Pencoder_process_data_st = ^encoder_process_data_st;

function OSSL_ENCODER_CTX_get_num_encoders( ctx : POSSL_ENCODER_CTX):integer;

function sk_OSSL_ENCODER_INSTANCE_num(const sk : Pstack_st_OSSL_ENCODER_INSTANCE):integer;
  function sk_OSSL_ENCODER_INSTANCE_value(const sk : Pstack_st_OSSL_ENCODER_INSTANCE; idx : integer):POSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_new( compare : sk_OSSL_ENCODER_INSTANCE_compfunc):Pstack_st_OSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_new_null:Pstack_st_OSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_new_reserve( compare : sk_OSSL_ENCODER_INSTANCE_compfunc; n : integer):Pstack_st_OSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_reserve( sk : Pstack_st_OSSL_ENCODER_INSTANCE; n : integer):integer;
  procedure sk_OSSL_ENCODER_INSTANCE_free( sk : Pstack_st_OSSL_ENCODER_INSTANCE);
  procedure sk_OSSL_ENCODER_INSTANCE_zero( sk : Pstack_st_OSSL_ENCODER_INSTANCE);
  function sk_OSSL_ENCODER_INSTANCE_delete( sk : Pstack_st_OSSL_ENCODER_INSTANCE; i : integer):POSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_delete_ptr( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):POSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_push( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):integer;
  function sk_OSSL_ENCODER_INSTANCE_unshift( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):integer;
  function sk_OSSL_ENCODER_INSTANCE_pop( sk : Pstack_st_OSSL_ENCODER_INSTANCE):POSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_shift( sk : Pstack_st_OSSL_ENCODER_INSTANCE):POSSL_ENCODER_INSTANCE;
  procedure sk_OSSL_ENCODER_INSTANCE_pop_free( sk : Pstack_st_OSSL_ENCODER_INSTANCE; freefunc : sk_OSSL_ENCODER_INSTANCE_freefunc);
  function sk_OSSL_ENCODER_INSTANCE_insert( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE; idx : integer):integer;
  function sk_OSSL_ENCODER_INSTANCE_set( sk : Pstack_st_OSSL_ENCODER_INSTANCE; idx : integer; ptr : POSSL_ENCODER_INSTANCE):POSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_find( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):integer;
  function sk_OSSL_ENCODER_INSTANCE_find_ex( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):integer;
  function sk_OSSL_ENCODER_INSTANCE_find_all( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE; pnum : PInteger):integer;
  procedure sk_OSSL_ENCODER_INSTANCE_sort( sk : Pstack_st_OSSL_ENCODER_INSTANCE);
  function sk_OSSL_ENCODER_INSTANCE_is_sorted(const sk : Pstack_st_OSSL_ENCODER_INSTANCE):integer;
  function sk_OSSL_ENCODER_INSTANCE_dup(const sk : Pstack_st_OSSL_ENCODER_INSTANCE):Pstack_st_OSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_deep_copy(const sk : Pstack_st_OSSL_ENCODER_INSTANCE; copyfunc : sk_OSSL_ENCODER_INSTANCE_copyfunc; freefunc : sk_OSSL_ENCODER_INSTANCE_freefunc):Pstack_st_OSSL_ENCODER_INSTANCE;
  function sk_OSSL_ENCODER_INSTANCE_set_cmp_func( sk : Pstack_st_OSSL_ENCODER_INSTANCE; compare : sk_OSSL_ENCODER_INSTANCE_compfunc):sk_OSSL_ENCODER_INSTANCE_compfunc;
  function OSSL_ENCODER_INSTANCE_get_encoder( encoder_inst : POSSL_ENCODER_INSTANCE):POSSL_ENCODER;
  function OSSL_ENCODER_INSTANCE_get_encoder_ctx( encoder_inst : POSSL_ENCODER_INSTANCE):Pointer;
   function OSSL_ENCODER_CTX_add_encoder( ctx : POSSL_ENCODER_CTX; encoder : POSSL_ENCODER):integer;
  function ossl_encoder_instance_new( encoder : POSSL_ENCODER; encoderctx : Pointer):POSSL_ENCODER_INSTANCE;
  procedure ossl_encoder_instance_free( encoder_inst : POSSL_ENCODER_INSTANCE);
  function ossl_encoder_ctx_add_encoder_inst( ctx : POSSL_ENCODER_CTX; ei : POSSL_ENCODER_INSTANCE):integer;
  function OSSL_ENCODER_CTX_set_construct(ctx : POSSL_ENCODER_CTX;construct : TOSSL_ENCODER_CONSTRUCT):integer;
  function OSSL_ENCODER_CTX_set_construct_data( ctx : POSSL_ENCODER_CTX; construct_data : Pointer):integer;
  function OSSL_ENCODER_CTX_set_cleanup(ctx : POSSL_ENCODER_CTX;cleanup : TOSSL_ENCODER_CLEANUP):integer;
  function OSSL_ENCODER_CTX_set_output_type(ctx : POSSL_ENCODER_CTX;const output_type : PUTF8Char):integer;
  function OSSL_ENCODER_CTX_set_output_structure(ctx : POSSL_ENCODER_CTX;const output_structure : PUTF8Char):integer;
  function OSSL_ENCODER_CTX_set_selection( ctx : POSSL_ENCODER_CTX; selection : integer):integer;
  function OSSL_ENCODER_CTX_add_extra(ctx : POSSL_ENCODER_CTX; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
  function OSSL_ENCODER_to_bio( ctx : POSSL_ENCODER_CTX; _out : PBIO):integer;
  function encoder_process( data : Pencoder_process_data_st):integer;
  function OSSL_ENCODER_INSTANCE_get_output_type( encoder_inst : POSSL_ENCODER_INSTANCE):PUTF8Char;
  function OSSL_ENCODER_INSTANCE_get_output_structure( encoder_inst : POSSL_ENCODER_INSTANCE):PUTF8Char;
function OSSL_ENCODER_to_data( ctx : POSSL_ENCODER_CTX; pdata : PPByte; pdata_len : Psize_t):integer;
function OSSL_ENCODER_to_fp( ctx : POSSL_ENCODER_CTX; fp : PFILE):integer;
function bio_from_file( fp : PFILE):PBIO;

implementation

uses openssl3.crypto.stack,           OpenSSL3.Err,
     openssl3.crypto.mem,             openssl3.crypto.provider_core,
     openssl3.crypto.params,          openssl3.crypto.bio.bio_lib,
     openssl3.crypto.passphrase,      openssl3.crypto.bio.bss_file,
     openssl3.crypto.bio.bss_mem,     openssl3.crypto.bio.ossl_core_bio,
     openssl3.crypto.property_query,  openssl3.crypto.bio.bio_print,
     OpenSSL3.common,                 openssl3.crypto.provider,
     openssl3.crypto.encode_decode.encoder_meth;

function bio_from_file( fp : PFILE):PBIO;
var
  b : PBIO;
begin
    b := BIO_new(BIO_s_file);
    if b = nil then  begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_BUF_LIB);
        Exit(nil);
    end;
    BIO_set_fp(b, fp, BIO_NOCLOSE);
    Result := b;
end;



function OSSL_ENCODER_to_fp( ctx : POSSL_ENCODER_CTX; fp : PFILE):integer;
var
  b : PBIO;
  ret : integer;
begin
    b := bio_from_file(fp);
    ret := 0;
    if b <> nil then
       ret := OSSL_ENCODER_to_bio(ctx, b);
    BIO_free(b);
    Result := ret;
end;

function OSSL_ENCODER_to_data( ctx : POSSL_ENCODER_CTX; pdata : PPByte; pdata_len : Psize_t):integer;
var
  _out : PBIO;
  buf : PBUF_MEM;
  ret : integer;
begin
    buf := nil;
    ret := 0;
    if pdata_len = nil then begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    _out := BIO_new(BIO_s_mem);
    if (_out <> nil)
         and  (OSSL_ENCODER_to_bio(ctx, _out) > 0)  and  (BIO_get_mem_ptr(_out, @buf) > 0) then
    begin
        ret := 1; { Hope for the best. A too small buffer will clear this }
        if (pdata <> nil)  and  (pdata^ <> nil) then
        begin
            if pdata_len^ < buf.length then
                {
                 * It's tempting to do |*pdata_len = size_t(buf.length|
                 * However, it's believed to be confusing more than helpful,
                 * so we don't.
                 }
                ret := 0
            else
                pdata_len^  := pdata_len^ - buf.length;
        end
        else
        begin
            { The buffer with the right size is already allocated for us }
            pdata_len^ := size_t(buf.length);
        end;
        if ret > 0 then
        begin
            if pdata <> nil then
            begin
                if pdata^ <> nil then
                begin
                    memcpy( pdata^, buf.data, buf.length);
                    pdata^  := pdata^ + buf.length;
                end
                else
                begin
                    { In this case, we steal the data from BIO_s_mem }
                    pdata^ := PByte(buf.data);
                    buf.data := nil;
                end;
            end;
        end;
    end;
    BIO_free(_out);
    Result := ret;
end;

function OSSL_ENCODER_INSTANCE_get_output_structure( encoder_inst : POSSL_ENCODER_INSTANCE):PUTF8Char;
begin
    if encoder_inst = nil then Exit(nil);
    Result := encoder_inst.output_structure;
end;

function OSSL_ENCODER_INSTANCE_get_output_type( encoder_inst : POSSL_ENCODER_INSTANCE):PUTF8Char;
begin
    if encoder_inst = nil then Exit(nil);
    Result := encoder_inst.output_type;
end;

function encoder_process( data : Pencoder_process_data_st):integer;
var
    current_encoder_inst     : POSSL_ENCODER_INSTANCE;
    current_encoder          : POSSL_ENCODER;
    current_encoder_ctx      : POSSL_ENCODER_CTX;
    allocated_out            : PBIO;
    original_data            : Pointer;
    _abstract                 : array[0..9] of TOSSL_PARAM;
    current_abstract         : POSSL_PARAM;

    i,  ok, top              : integer;
    next_encoder             : POSSL_ENCODER;
    current_output_type,
    current_output_structure : PUTF8Char;
    new_data                 : encoder_process_data_st;
    abstract_p               : POSSL_PARAM;
    prev_output_structure    : PUTF8Char;
    cbio                     : POSSL_CORE_BIO;
    current_out,trc_out      : PBIO;
    buf                      : PBUF_MEM;
    label _break;
begin
    current_encoder_inst := nil;
    current_encoder := nil;
    current_encoder_ctx := nil;
    allocated_out := nil;
    original_data := nil;
    current_abstract := nil;
    ok := -1;
    top := 0;
    if data.next_encoder_inst = nil then
    begin
        { First iteration, where we prepare for what is to come }
        data.count_output_structure :=
               get_result(data.ctx.output_structure = nil , -1 , 0);
        top := 1;
    end;
    i := data.current_encoder_inst_index;
    while PostDec(i) > 0 do
    begin
        next_encoder := nil;
        if 0>= top then
           next_encoder := OSSL_ENCODER_INSTANCE_get_encoder(data.next_encoder_inst);
        current_encoder_inst := sk_OSSL_ENCODER_INSTANCE_value(data.ctx.encoder_insts, i);
        current_encoder := OSSL_ENCODER_INSTANCE_get_encoder(current_encoder_inst);
        current_encoder_ctx := OSSL_ENCODER_INSTANCE_get_encoder_ctx(current_encoder_inst);
        current_output_type := OSSL_ENCODER_INSTANCE_get_output_type(current_encoder_inst);
        current_output_structure := OSSL_ENCODER_INSTANCE_get_output_structure(current_encoder_inst);
        memset(@new_data, 0, sizeof(new_data));
        new_data.ctx := data.ctx;
        new_data.current_encoder_inst_index := i;
        new_data.next_encoder_inst := current_encoder_inst;
        new_data.count_output_structure := data.count_output_structure;
        new_data.level := data.level + 1;
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       ' [%d] (ctx %p) Considering encoder instance %p (encoder %p)\n' ,
                       [data.level, Pointer( data.ctx),
                       Pointer( current_encoder_inst), Pointer( current_encoder)]);
        end;

        {
         * If this is the top call, we check if the output type of the current
         * encoder matches the desired output type.
         * If this isn't the top call, i.e. this is deeper in the recursion,
         * we instead check if the output type of the current encoder matches
         * the name of the next encoder (the one found by the parent call).
         }
        if top > 0 then
        begin
            if (data.ctx.output_type <> nil)    and
               (strcasecmp(current_output_type, data.ctx.output_type) <> 0) then
            begin
                if Boolean(0) then
                begin
                    BIO_printf(trc_out,
                               ' [%d]    Skipping because current encoder output type (%s) <> desired output type (%s)\n' ,
                               [data.level,
                               current_output_type, data.ctx.output_type]);
                end;

                continue;
            end;
        end
        else
        begin
            if 0>= OSSL_ENCODER_is_a(next_encoder, current_output_type) then
            begin
                if Boolean(0) then
                begin
                    BIO_printf(trc_out,
                               ' [%d]    Skipping because current encoder output type (%s) <> name of encoder %p\n' ,
                               [data.level,
                               current_output_type, Pointer( next_encoder)]);
                end;

                continue;
            end;
        end;
        {
         * If the caller and the current encoder specify an output structure,
         * Check if they match.  If they do, count the match, otherwise skip
         * the current encoder.
         }
        if (data.ctx.output_structure <> nil)
             and  (current_output_structure <> nil) then
        begin
            if (strcasecmp(data.ctx.output_structure,
                           current_output_structure) <> 0) then
            begin
                if Boolean(0) then
                begin
                    BIO_printf(trc_out,
                               ' [%d]    Skipping because current encoder output structure (%s) <> ctx output structure (%s)\n' ,
                               [data.level,
                               current_output_structure,
                               data.ctx.output_structure]);
                end;

                continue;
            end;
            Inc(data.count_output_structure);
        end;
        {
         * Recurse to process the encoder implementations before the current
         * one.
         }
        ok := encoder_process(@new_data);
        data.prev_encoder_inst := new_data.prev_encoder_inst;
        data.running_output := new_data.running_output;
        data.running_output_length := new_data.running_output_length;
        {
         * ok = -1     means that the recursion call above gave no further
         *              encoders, and that the one we're currently at should
         *              be tried.
         * ok = 0      means that something failed in the recursion call
         *              above, making the result unsuitable for a chain.
         *              In this case, we simply continue to try finding a
         *              suitable encoder at this recursion level.
         * ok = 1      means that the recursion call was successful, and we
         *              try to use the result at this recursion level.
         }
        if ok <> 0 then break;
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       ' [%d]    Skipping because recursion level %d failed\n' ,
                       [data.level, new_data.level]);
        end;

    end;
    {
     * If |i < 0|, we didn't find any useful encoder in this recursion, so
     * we do the rest of the process only if |i >= 0|.
     }
    if i < 0 then
    begin
        ok := -1;
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       ' [%d] (ctx %p) No suitable encoder found\n' ,
                       [data.level, Pointer( data.ctx)]);
        end;

    end
    else
    begin
        { Preparations }
        case ok of
            0:
               goto _break;
            -1:
            begin
                {
                 * We have reached the beginning of the encoder instance sequence,
                 * so we prepare the object to be encoded.
                 }
                {
                 * |data.count_output_structure| is one of these values:
                 *
                 * -1       There is no desired output structure
                 *  0       There is a desired output structure, and it wasn't
                 *          matched by any of the encoder instances that were
                 *          considered
                 * >0       There is a desired output structure, and at least one
                 *          of the encoder instances matched it
                 }
                if data.count_output_structure = 0 then
                   Exit(0);
                original_data := data.ctx.construct(current_encoder_inst,
                                         data.ctx.construct_data);
                { Also set the data type, using the encoder implementation name }
                data.data_type := OSSL_ENCODER_get0_name(current_encoder);
                { Assume that the constructor recorded an error }
                if original_data <> nil then
                   ok := 1
                else
                    ok := 0;
            end;
            1:
            begin
                if not ossl_assert(data.running_output <> nil) then
                begin
                    ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR);
                    ok := 0;
                    goto _break;
                end;
                begin
                    {
                     * Create an object abstraction from the latest output, which
                     * was stolen from the previous round.
                     }
                    abstract_p := @_abstract;
                    prev_output_structure :=
                        OSSL_ENCODER_INSTANCE_get_output_structure(data.prev_encoder_inst);
                    PostInc(abstract_p)^ :=
                        OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
                                                         PUTF8Char(data.data_type), 0);
                    if prev_output_structure <> nil then
                       PostInc(abstract_p)^ :=
                            OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                                             PUTF8Char(  prev_output_structure),
                                                             0);
                    PostInc(abstract_p)^ :=
                        OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
                                                          data.running_output,
                                                          data.running_output_length);
                    abstract_p^ := OSSL_PARAM_construct_end();
                    current_abstract := @_abstract;
                end;
            end;
        end;
_break:
        { Calling the encoder implementation }
        if ok > 0 then
        begin
            cbio := nil;
            current_out := nil;
            {
             * If we're at the last encoder instance to use, we're setting up
             * final output.  Otherwise, set up an intermediary memory output.
             }
            if top>0 then
               current_out := data.bio
            else
            begin
              allocated_out := BIO_new(BIO_s_mem);
              current_out := allocated_out;
              if (current_out  = nil) then
                 ok := 0;     { Assume BIO_new() recorded an error }
            end;
            if ok > 0 then
            begin
               cbio := ossl_core_bio_new_from_bio(current_out);
               ok   := int(cbio  <> nil);
            end;
            if ok>0 then
            begin
                ok := current_encoder.encode(current_encoder_ctx, cbio,
                                             original_data, current_abstract,
                                             data.ctx.selection,
                                             ossl_pw_passphrase_callback_enc,
                                             @data.ctx.pwdata);
                if Boolean(0) then
                begin
                    BIO_printf(trc_out,
                               ' [%d] (ctx %p) Running encoder instance %p => %d\n' ,
                               [data.level, Pointer( data.ctx),
                               Pointer( current_encoder_inst), ok]);
                end;

            end;
            ossl_core_bio_free(cbio);
            data.prev_encoder_inst := current_encoder_inst;
        end;
    end;
    { Cleanup and collecting the result }
    OPENSSL_free(data.running_output);
    data.running_output := nil;
    {
     * Steal the output from the BIO_s_mem, if we did allocate one.
     * That'll be the data for an object abstraction in the next round.
     }
    if allocated_out <> nil then
    begin
        BIO_get_mem_ptr(allocated_out, @buf);
        data.running_output := PByte( buf.data);
        data.running_output_length := buf.length;
        memset(buf, 0, sizeof( buf^));
    end;
    BIO_free(allocated_out);
    if original_data <> nil then
       data.ctx.cleanup(data.ctx.construct_data);
    Result := ok;
end;

function OSSL_ENCODER_to_bio( ctx : POSSL_ENCODER_CTX; _out : PBIO):integer;
var
  data : encoder_process_data_st;
begin
    memset(@data, 0, sizeof(data));
    data.ctx := ctx;
    data.bio := _out;
    data.current_encoder_inst_index := OSSL_ENCODER_CTX_get_num_encoders(ctx);
    if data.current_encoder_inst_index = 0 then
    begin
        ERR_raise_data(ERR_LIB_OSSL_ENCODER, OSSL_ENCODER_R_ENCODER_NOT_FOUND,
                       ' No encoders were found. For standard encoders you need '+
                       ' at least one of the default or base providers '+
                       ' available. Did you forget to load them?' );
        Exit(0);
    end;
    Result := Int(encoder_process(@data) > 0);
end;




function OSSL_ENCODER_CTX_add_extra(ctx : POSSL_ENCODER_CTX; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
begin
    Result := 1;
end;

function OSSL_ENCODER_CTX_set_selection( ctx : POSSL_ENCODER_CTX; selection : integer):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if not ossl_assert(selection <> 0) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_INVALID_ARGUMENT);
        Exit(0);
    end;
    ctx.selection := selection;
    Result := 1;
end;


function OSSL_ENCODER_CTX_set_output_structure(ctx : POSSL_ENCODER_CTX;const output_structure : PUTF8Char):integer;
begin
    if (not ossl_assert(ctx <> nil))  or  (not ossl_assert(output_structure <> nil)) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx.output_structure := output_structure;
    Result := 1;
end;




function OSSL_ENCODER_CTX_set_output_type(ctx : POSSL_ENCODER_CTX;const output_type : PUTF8Char):integer;
begin
    if (not ossl_assert(ctx <> nil))  or  (not ossl_assert(output_type <> nil)) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx.output_type := output_type;
    Result := 1;
end;



function OSSL_ENCODER_CTX_set_cleanup(ctx : POSSL_ENCODER_CTX;cleanup : TOSSL_ENCODER_CLEANUP):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx.cleanup := cleanup;
    Result := 1;
end;




function OSSL_ENCODER_CTX_set_construct_data( ctx : POSSL_ENCODER_CTX; construct_data : Pointer):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx.construct_data := construct_data;
    Result := 1;
end;



function OSSL_ENCODER_CTX_set_construct(ctx : POSSL_ENCODER_CTX;construct : TOSSL_ENCODER_CONSTRUCT):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx.construct := construct;
    Result := 1;
end;


function ossl_encoder_ctx_add_encoder_inst( ctx : POSSL_ENCODER_CTX; ei : POSSL_ENCODER_INSTANCE):integer;
var
  ok : integer;
  trc_out: PBIO;
begin
    ctx.encoder_insts := sk_OSSL_ENCODER_INSTANCE_new_null();
    if (ctx.encoder_insts = nil)
         and  (ctx.encoder_insts = nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    ok := int(sk_OSSL_ENCODER_INSTANCE_push(ctx.encoder_insts, ei) > 0);
    if ok>0 then
    begin
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       ' (ctx %p) Added encoder instance %p (encoder %p):'#10+
                       '     %s with %s'#10 ,
                       [Pointer( ctx), Pointer( ei), Pointer( ei.encoder),
                       OSSL_ENCODER_get0_name(ei.encoder),
                       OSSL_ENCODER_get0_properties(ei.encoder)]);
        end;

    end;
    Result := ok;
end;

procedure ossl_encoder_instance_free( encoder_inst : POSSL_ENCODER_INSTANCE);
begin
    if encoder_inst <> nil then
    begin
        if encoder_inst.encoder <> nil then
            encoder_inst.encoder.freectx(encoder_inst.encoderctx);
        encoder_inst.encoderctx := nil;
        OSSL_ENCODER_free(encoder_inst.encoder);
        encoder_inst.encoder := nil;
        OPENSSL_free(encoder_inst);
    end;
end;






function ossl_encoder_instance_new( encoder : POSSL_ENCODER; encoderctx : Pointer):POSSL_ENCODER_INSTANCE;
var
    encoder_inst : POSSL_ENCODER_INSTANCE;
    prov         : POSSL_PROVIDER;
    libctx       : POSSL_LIB_CTX;
    props        : POSSL_PROPERTY_LIST;
    prop         : POSSL_PROPERTY_DEFINITION;
    label _err;
begin
    encoder_inst := nil;
    if not ossl_assert(encoder <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
     encoder_inst := OPENSSL_zalloc(sizeof(encoder_inst^));
    if encoder_inst = nil then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if 0>= OSSL_ENCODER_up_ref(encoder) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    prov := OSSL_ENCODER_get0_provider(encoder);
    libctx := ossl_provider_libctx(prov);
    props := ossl_encoder_parsed_properties(encoder);
    if props = nil then
    begin
        ERR_raise_data(ERR_LIB_OSSL_DECODER, ERR_R_INVALID_PROPERTY_DEFINITION,
                     Format(' there are no property definitions with encoder %s' ,
                             [OSSL_ENCODER_get0_name(encoder)]));
        goto _err ;
    end;
    { The ' output'  property is mandatory }
    prop := ossl_property_find_property(props, libctx, ' output' );
    encoder_inst.output_type := ossl_property_get_string_value(libctx, prop);
    if encoder_inst.output_type = nil then
    begin
        ERR_raise_data(ERR_LIB_OSSL_DECODER, ERR_R_INVALID_PROPERTY_DEFINITION,
                    Format(' the mandatory ''output'' property is missing '+
                       ' for encoder %s (properties: %s)' ,
                       [OSSL_ENCODER_get0_name(encoder),
                       OSSL_ENCODER_get0_properties(encoder)]));
        goto _err ;
    end;
    { The ' structure'  property is optional }
    prop := ossl_property_find_property(props, libctx, ' structure' );
    if prop <> nil then
       encoder_inst.output_structure := ossl_property_get_string_value(libctx, prop);
    encoder_inst.encoder := encoder;
    encoder_inst.encoderctx := encoderctx;
    Exit(encoder_inst);
 _err:
    ossl_encoder_instance_free(encoder_inst);
    Result := nil;
end;



function OSSL_ENCODER_CTX_add_encoder( ctx : POSSL_ENCODER_CTX; encoder : POSSL_ENCODER):integer;
var
  encoder_inst : POSSL_ENCODER_INSTANCE;
  prov         : POSSL_PROVIDER;
  encoderctx,
  provctx      : Pointer;
  label _err;
begin
    encoder_inst := nil;
    prov := nil;
    encoderctx := nil;
    provctx := nil;
    if (not ossl_assert(ctx <> nil))  or  (not ossl_assert(encoder <> nil)) then
    begin
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    prov := OSSL_ENCODER_get0_provider(encoder);
    provctx := OSSL_PROVIDER_get0_provider_ctx(prov);
    encoderctx := encoder.newctx(provctx);
    encoder_inst := ossl_encoder_instance_new(encoder, encoderctx);
    if (encoderctx = nil) or  (encoder_inst = nil) then
        goto _err ;
    { Avoid double free of encoderctx on further errors }
    encoderctx := nil;
    if 0>= ossl_encoder_ctx_add_encoder_inst(ctx, encoder_inst) then
        goto _err ;
    Exit(1);
 _err:
    ossl_encoder_instance_free(encoder_inst);
    if encoderctx <> nil then encoder.freectx(encoderctx);
    Result := 0;
end;




function OSSL_ENCODER_INSTANCE_get_encoder_ctx( encoder_inst : POSSL_ENCODER_INSTANCE):Pointer;
begin
    if encoder_inst = nil then
       Exit(nil);
    Result := encoder_inst.encoderctx;
end;

function OSSL_ENCODER_INSTANCE_get_encoder( encoder_inst : POSSL_ENCODER_INSTANCE):POSSL_ENCODER;
begin
    if encoder_inst = nil then
       Exit(nil);
    Result := encoder_inst.encoder;
end;

function sk_OSSL_ENCODER_INSTANCE_num(const sk : Pstack_st_OSSL_ENCODER_INSTANCE):integer;
begin
 Exit(OPENSSL_sk_num(POPENSSL_STACK( sk)));
end;


function sk_OSSL_ENCODER_INSTANCE_value(const sk : Pstack_st_OSSL_ENCODER_INSTANCE; idx : integer):POSSL_ENCODER_INSTANCE;
begin
 Exit(POSSL_ENCODER_INSTANCE( OPENSSL_sk_value(POPENSSL_STACK( sk), idx)));
end;


function sk_OSSL_ENCODER_INSTANCE_new( compare : sk_OSSL_ENCODER_INSTANCE_compfunc):Pstack_st_OSSL_ENCODER_INSTANCE;
begin
 Exit(Pstack_st_OSSL_ENCODER_INSTANCE( OPENSSL_sk_new(OPENSSL_sk_compfunc(compare))));
end;


function sk_OSSL_ENCODER_INSTANCE_new_null:Pstack_st_OSSL_ENCODER_INSTANCE;
begin
 Exit(Pstack_st_OSSL_ENCODER_INSTANCE( OPENSSL_sk_new_null));
end;


function sk_OSSL_ENCODER_INSTANCE_new_reserve( compare : sk_OSSL_ENCODER_INSTANCE_compfunc; n : integer):Pstack_st_OSSL_ENCODER_INSTANCE;
begin
 Exit(Pstack_st_OSSL_ENCODER_INSTANCE( OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc(compare), n)));
end;


function sk_OSSL_ENCODER_INSTANCE_reserve( sk : Pstack_st_OSSL_ENCODER_INSTANCE; n : integer):integer;
begin
 Exit(OPENSSL_sk_reserve(POPENSSL_STACK( sk), n));
end;


procedure sk_OSSL_ENCODER_INSTANCE_free( sk : Pstack_st_OSSL_ENCODER_INSTANCE);
begin
 OPENSSL_sk_free(POPENSSL_STACK( sk));
end;


procedure sk_OSSL_ENCODER_INSTANCE_zero( sk : Pstack_st_OSSL_ENCODER_INSTANCE);
begin
 OPENSSL_sk_zero(POPENSSL_STACK( sk));
end;


function sk_OSSL_ENCODER_INSTANCE_delete( sk : Pstack_st_OSSL_ENCODER_INSTANCE; i : integer):POSSL_ENCODER_INSTANCE;
begin
 Exit(POSSL_ENCODER_INSTANCE( OPENSSL_sk_delete(POPENSSL_STACK( sk), i)));
end;


function sk_OSSL_ENCODER_INSTANCE_delete_ptr( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):POSSL_ENCODER_INSTANCE;
begin
 Exit(POSSL_ENCODER_INSTANCE( OPENSSL_sk_delete_ptr(POPENSSL_STACK( sk), Pointer( ptr))));
end;


function sk_OSSL_ENCODER_INSTANCE_push( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):integer;
begin
 Exit(OPENSSL_sk_push(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_OSSL_ENCODER_INSTANCE_unshift( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):integer;
begin
 Exit(OPENSSL_sk_unshift(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_OSSL_ENCODER_INSTANCE_pop( sk : Pstack_st_OSSL_ENCODER_INSTANCE):POSSL_ENCODER_INSTANCE;
begin
 Exit(POSSL_ENCODER_INSTANCE( OPENSSL_sk_pop(POPENSSL_STACK( sk))));
end;


function sk_OSSL_ENCODER_INSTANCE_shift( sk : Pstack_st_OSSL_ENCODER_INSTANCE):POSSL_ENCODER_INSTANCE;
begin
 Exit(POSSL_ENCODER_INSTANCE( OPENSSL_sk_shift(POPENSSL_STACK( sk))));
end;


procedure sk_OSSL_ENCODER_INSTANCE_pop_free( sk : Pstack_st_OSSL_ENCODER_INSTANCE; freefunc : sk_OSSL_ENCODER_INSTANCE_freefunc);
begin
 OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc));
end;


function sk_OSSL_ENCODER_INSTANCE_insert( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE; idx : integer):integer;
begin
 Exit(OPENSSL_sk_insert(POPENSSL_STACK( sk), Pointer( ptr), idx));
end;


function sk_OSSL_ENCODER_INSTANCE_set( sk : Pstack_st_OSSL_ENCODER_INSTANCE; idx : integer; ptr : POSSL_ENCODER_INSTANCE):POSSL_ENCODER_INSTANCE;
begin
 Exit(POSSL_ENCODER_INSTANCE( OPENSSL_sk_set(POPENSSL_STACK( sk), idx, Pointer( ptr))));
end;


function sk_OSSL_ENCODER_INSTANCE_find( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):integer;
begin
 Exit(OPENSSL_sk_find(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_OSSL_ENCODER_INSTANCE_find_ex( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE):integer;
begin
 Exit(OPENSSL_sk_find_ex(POPENSSL_STACK( sk), Pointer( ptr)));
end;


function sk_OSSL_ENCODER_INSTANCE_find_all( sk : Pstack_st_OSSL_ENCODER_INSTANCE; ptr : POSSL_ENCODER_INSTANCE; pnum : PInteger):integer;
begin
 Exit(OPENSSL_sk_find_all(POPENSSL_STACK( sk), Pointer( ptr), pnum));
end;


procedure sk_OSSL_ENCODER_INSTANCE_sort( sk : Pstack_st_OSSL_ENCODER_INSTANCE);
begin
 OPENSSL_sk_sort(POPENSSL_STACK( sk));
end;


function sk_OSSL_ENCODER_INSTANCE_is_sorted(const sk : Pstack_st_OSSL_ENCODER_INSTANCE):integer;
begin
 Exit(OPENSSL_sk_is_sorted(POPENSSL_STACK( sk)));
end;


function sk_OSSL_ENCODER_INSTANCE_dup(const sk : Pstack_st_OSSL_ENCODER_INSTANCE):Pstack_st_OSSL_ENCODER_INSTANCE;
begin
 Exit(Pstack_st_OSSL_ENCODER_INSTANCE( OPENSSL_sk_dup(POPENSSL_STACK( sk))));
end;


function sk_OSSL_ENCODER_INSTANCE_deep_copy(const sk : Pstack_st_OSSL_ENCODER_INSTANCE; copyfunc : sk_OSSL_ENCODER_INSTANCE_copyfunc; freefunc : sk_OSSL_ENCODER_INSTANCE_freefunc):Pstack_st_OSSL_ENCODER_INSTANCE;
begin
 Exit(Pstack_st_OSSL_ENCODER_INSTANCE( OPENSSL_sk_deep_copy(POPENSSL_STACK( sk),
               OPENSSL_sk_copyfunc(copyfunc), OPENSSL_sk_freefunc(freefunc))));
end;


function sk_OSSL_ENCODER_INSTANCE_set_cmp_func( sk : Pstack_st_OSSL_ENCODER_INSTANCE; compare : sk_OSSL_ENCODER_INSTANCE_compfunc):sk_OSSL_ENCODER_INSTANCE_compfunc;
begin
   Result := sk_OSSL_ENCODER_INSTANCE_compfunc(OPENSSL_sk_set_cmp_func(POPENSSL_STACK( sk),
                    OPENSSL_sk_compfunc(compare)));
end;



function OSSL_ENCODER_CTX_get_num_encoders( ctx : POSSL_ENCODER_CTX):integer;
begin
    if (ctx = nil)  or  (ctx.encoder_insts = nil) then Exit(0);
    Result := sk_OSSL_ENCODER_INSTANCE_num(ctx.encoder_insts);
end;


end.
