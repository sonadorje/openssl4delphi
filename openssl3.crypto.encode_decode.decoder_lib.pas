unit openssl3.crypto.encode_decode.decoder_lib;

interface
uses OpenSSL.Api, SysUtils;

type
  Ttype_check = ( IS_SAME = 0, IS_DIFFERENT = 1 );
  collect_extra_decoder_data_st = record
    ctx          : POSSL_DECODER_CTX;
    output_type  : PUTF8Char;
    type_check: Ttype_check;
    w_prev_start,
    w_prev_end,
    w_new_start,
    w_new_end    : size_t;
  end;
  Pcollect_extra_decoder_data_st = ^collect_extra_decoder_data_st;

  decoder_process_data_st = record
    ctx                          : POSSL_DECODER_CTX;
    bio                          : PBIO;
    current_decoder_inst_index,
    recursion                    : size_t;
    flag_next_level_called,
    flag_construct_called,
    flag_input_structure_checked : uint32;
  end;
  Pdecoder_process_data_st = ^decoder_process_data_st;

function OSSL_DECODER_INSTANCE_get_decoder( decoder_inst : POSSL_DECODER_INSTANCE):POSSL_DECODER;
function OSSL_DECODER_INSTANCE_get_decoder_ctx( decoder_inst : POSSL_DECODER_INSTANCE):Pointer;
function ossl_decoder_instance_new( decoder : POSSL_DECODER; decoderctx : Pointer):POSSL_DECODER_INSTANCE;
 procedure ossl_decoder_instance_free( decoder_inst : POSSL_DECODER_INSTANCE);
function ossl_decoder_ctx_add_decoder_inst( ctx : POSSL_DECODER_CTX; di : POSSL_DECODER_INSTANCE):integer;
function sk_OSSL_DECODER_INSTANCE_new_null:Pstack_st_OSSL_DECODER_INSTANCE;
function sk_OSSL_DECODER_INSTANCE_push( sk : Pstack_st_OSSL_DECODER_INSTANCE; ptr : POSSL_DECODER_INSTANCE):integer;
function OSSL_DECODER_CTX_get_num_decoders( ctx : POSSL_DECODER_CTX):integer;
 function sk_OSSL_DECODER_INSTANCE_num(const sk: Pstack_st_OSSL_DECODER_INSTANCE):integer;
 function OSSL_DECODER_CTX_set_construct( ctx : POSSL_DECODER_CTX; construct : TOSSL_DECODER_CONSTRUCT):integer;
 function OSSL_DECODER_CTX_set_construct_data( ctx : POSSL_DECODER_CTX; construct_data : Pointer):integer;
 function OSSL_DECODER_CTX_set_cleanup(ctx : POSSL_DECODER_CTX;cleanup : TOSSL_DECODER_CLEANUP):integer;
 function OSSL_DECODER_CTX_set_input_type(ctx : POSSL_DECODER_CTX;const input_type : PUTF8Char):integer;
 function OSSL_DECODER_CTX_set_input_structure(ctx : POSSL_DECODER_CTX;const input_structure : PUTF8Char):integer;
 function OSSL_DECODER_CTX_set_selection( ctx : POSSL_DECODER_CTX; selection : integer):integer;
 function OSSL_DECODER_CTX_add_extra(ctx : POSSL_DECODER_CTX; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
 function sk_OSSL_DECODER_new_null:Pstack_st_OSSL_DECODER;
 procedure collect_all_decoders( decoder : POSSL_DECODER; arg : Pointer);
 function sk_OSSL_DECODER_push( sk : Pstack_st_OSSL_DECODER; ptr : POSSL_DECODER):integer;
 function sk_OSSL_DECODER_num(const sk : Pstack_st_OSSL_DECODER):integer;
 function sk_OSSL_DECODER_INSTANCE_value(const sk : Pstack_st_OSSL_DECODER_INSTANCE; idx : integer):POSSL_DECODER_INSTANCE;
 function OSSL_DECODER_INSTANCE_get_input_type( decoder_inst : POSSL_DECODER_INSTANCE):PUTF8Char;
 procedure collect_extra_decoder( decoder : POSSL_DECODER; arg : Pointer);
 function sk_OSSL_DECODER_value(const sk : Pstack_st_OSSL_DECODER; idx : integer):POSSL_DECODER;
  procedure sk_OSSL_DECODER_pop_free( sk : Pstack_st_OSSL_DECODER; freefunc : sk_OSSL_DECODER_freefunc);
 procedure sk_OSSL_DECODER_INSTANCE_pop_free( sk : Pstack_st_OSSL_DECODER_INSTANCE; freefunc : sk_OSSL_DECODER_INSTANCE_freefunc);
 function OSSL_DECODER_from_data(ctx : POSSL_DECODER_CTX;const pdata : PPByte; pdata_len : Psize_t):integer;
 function OSSL_DECODER_from_bio( ctx : POSSL_DECODER_CTX; _in : PBIO):integer;
  function decoder_process(const params : POSSL_PARAM; arg : Pointer):integer;
 function OSSL_DECODER_INSTANCE_get_input_structure( decoder_inst : POSSL_DECODER_INSTANCE; was_set : PInteger):PUTF8Char;

implementation
uses OpenSSL3.Err, OpenSSL3.common, openssl3.crypto.mem,
     openssl3.crypto.encode_decode.decoder_meth,
     openssl3.crypto.bio.bio_lib, openssl3.crypto.bio.bf_readbuff,
     openssl3.crypto.bio.bio_print,  openssl3.crypto.provider,
     openssl3.crypto.stack, openssl3.crypto.bio.bss_mem,
     openssl3.crypto.passphrase, openssl3.crypto.params,
     openssl3.crypto.bio.ossl_core_bio,
     openssl3.providers.fips.fipsprov,
     openssl3.crypto.provider_core, openssl3.crypto.property_query;





function OSSL_DECODER_INSTANCE_get_input_structure( decoder_inst : POSSL_DECODER_INSTANCE; was_set : PInteger):PUTF8Char;
begin
    if decoder_inst = nil then
       Exit(nil);
    was_set^ := decoder_inst.flag_input_structure_was_set;
    Result := decoder_inst.input_structure;
end;

function decoder_process(const params : POSSL_PARAM; arg : Pointer):integer;
var
    data                 : Pdecoder_process_data_st;
    ctx                  : POSSL_DECODER_CTX;
    decoder_inst         : POSSL_DECODER_INSTANCE;
    decoder              : POSSL_DECODER;
    cbio                 : POSSL_CORE_BIO;
    bio                  : PBIO;
    loc                  : long;
    i                    : size_t;
    ok                   : integer;
    new_data             : decoder_process_data_st;
    data_type,
    data_structure       : PUTF8Char;
    p                    : POSSL_PARAM;
    trace_data_structure : PUTF8Char;
    rv                   : integer;
    new_decoder_inst     : POSSL_DECODER_INSTANCE;
    new_decoder          : POSSL_DECODER;
    new_decoderctx       : Pointer;
    new_input_type       : PUTF8Char;
    n_i_s_was_set        : integer;
    new_input_structure  : PUTF8Char;
    trc_out: PBIO;
    label _err, _end;
const
    LEVEL_STR: PUTF8Char = '>>>>>>>>>>>>>>>>';
    function LEVEL: PUTF8Char;
    begin
        if new_data.recursion < sizeof(LEVEL_STR) then
           Result :=  @LEVEL_STR[sizeof(LEVEL_STR) - new_data.recursion - 1]
        else
           Result := '...';
    end;


begin
    data := arg;
    ctx := data.ctx;
    decoder_inst := nil;
    decoder := nil;
    cbio := nil;
    bio := data.bio;
    ok := 0;
    { For recursions }
    data_type := nil;
    data_structure := nil;
    {
     * This is an indicator up the call stack that something was indeed
     * decoded, leading to a recursive call of this function.
     }
    data.flag_next_level_called := 1;
    new_data := default(decoder_process_data_st);
    new_data.ctx := data.ctx;
    new_data.recursion := data.recursion + 1;
    if params = nil then
    begin
        { First iteration, where we prepare for what is to come }
       if Boolean(0) then
       begin
            BIO_printf(trc_out, '(ctx %p) starting to walk the decoder chain\n',
                       [Pointer( new_data.ctx)]);
        end;

        data.current_decoder_inst_index := OSSL_DECODER_CTX_get_num_decoders(ctx);
        bio := data.bio;
    end
    else
    begin
        decoder_inst := sk_OSSL_DECODER_INSTANCE_value(ctx.decoder_insts,
                                           data.current_decoder_inst_index);
        decoder := OSSL_DECODER_INSTANCE_get_decoder(decoder_inst);
        data.flag_construct_called := 0;
        if Assigned(ctx.construct) then
        begin
            if Boolean(0) then
            begin
                BIO_printf(trc_out, '(ctx %p) %s Running constructor\n',
                           [Pointer( new_data.ctx), LEVEL]);
            end;

            rv := ctx.construct(decoder_inst, params, ctx.construct_data);
            if Boolean(0) then
            begin
                BIO_printf(trc_out,
                           '(ctx %p) %s Running constructor => %d\n',
                           [Pointer( new_data.ctx), LEVEL, rv]);
            end;

            data.flag_construct_called := 1;
            ok := int(rv > 0);
            if ok > 0 then
               goto _end ;
        end;
        { The constructor didn't return success }
        {
         * so we try to use the object we got and feed it to any next
         * decoder that will take it.  Object references are not
         * allowed for this.
         * If this data isn't present, decoding has failed.
         }
        p := OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA);
        if (p = nil)  or  (p.data_type <> OSSL_PARAM_OCTET_STRING) then
           goto _end ;
        new_data.bio := BIO_new_mem_buf(p.data, int (p.data_size));
        if new_data.bio = nil then
           goto _end ;
        bio := new_data.bio;
        { Get the data type if there is one }
        p := OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
        if (p <> nil)  and  (0>= OSSL_PARAM_get_utf8_string_ptr(p, @data_type)) then
            goto _end ;
        { Get the data structure if there is one }
        p := OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_STRUCTURE);
        if (p <> nil)  and  (0>= OSSL_PARAM_get_utf8_string_ptr(p, @data_structure)) then
            goto _end ;
        {
         * If the data structure is 'type-specific' and the data type is
         * given, we drop the data structure.  The reasoning is that the
         * data type is already enough to find the applicable next decoder,
         * so an additional 'type-specific' data structure is extraneous.
         *
         * Furthermore, if the OSSL_DECODER caller asked for a type specific
         * structure under another name, such as 'DH', we get a mismatch
         * if the data structure we just received is 'type-specific'.
         * There's only so much you can do without infusing this code with
         * too special knowledge.
         }
        trace_data_structure := data_structure;
        if (data_type <> nil)  and  (data_structure <> nil)
             and  (strcasecmp(data_structure, 'type-specific') = 0) then
            data_structure := nil;
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       '(ctx %p) %s incoming from previous decoder (%p):\n'+
                       '    data type: %s, data structure: %s%s\n',
                       [Pointer( new_data.ctx), LEVEL, Pointer( decoder),
                       data_type, trace_data_structure,
                      get_result(trace_data_structure = data_structure
                        , '' , ' (dropped)')]);
        end;

    end;
    {
     * If we have no more decoders to look through at this point,
     * we failed
     }
    if data.current_decoder_inst_index = 0 then
       goto _end ;
    loc := BIO_tell(bio);
    if loc < 0 then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_BIO_LIB);
        goto _end ;
    end;
    cbio := ossl_core_bio_new_from_bio(bio);
    if cbio =  nil then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        goto _end ;
    end;

    i := data.current_decoder_inst_index;
    while PostDec(i) > 0 do
    begin
        new_decoder_inst := sk_OSSL_DECODER_INSTANCE_value(ctx.decoder_insts, i);
        new_decoder := OSSL_DECODER_INSTANCE_get_decoder(new_decoder_inst);
        new_decoderctx := OSSL_DECODER_INSTANCE_get_decoder_ctx(new_decoder_inst);
        new_input_type := OSSL_DECODER_INSTANCE_get_input_type(new_decoder_inst);
        n_i_s_was_set := 0;
        new_input_structure := OSSL_DECODER_INSTANCE_get_input_structure(new_decoder_inst,
                                                      @n_i_s_was_set);
        if Boolean(0) then
        begin
            BIO_printf(trc_out, '(ctx %p) %s [%u] Considering decoder instance %p (decoder %p):\n'+
                       '    %s with %s\n',
                       [Pointer( new_data.ctx), LEVEL, uint32( i),
                       Pointer( new_decoder_inst), Pointer( new_decoder),
                       OSSL_DECODER_get0_name(new_decoder),
                       OSSL_DECODER_get0_properties(new_decoder)]);
        end;

        {
         * If |decoder| is nil, it means we've just started, and the caller
         * may have specified what it expects the initial input to be.  If
         * that's the case, we do this extra check.
         }
        if (decoder = nil)  and
           (ctx.start_input_type <> nil) and
           (strcasecmp(ctx.start_input_type, new_input_type) <> 0)  then
        begin
            if Boolean(0) then
            begin
                BIO_printf(trc_out,
                           '(ctx %p) %s [%u] the start input type ''%s'' doesn''t match the input type of the considered decoder, skipping...\n',
                           [Pointer( new_data.ctx), LEVEL, uint32( i),
                           ctx.start_input_type]);
            end;
            continue;
        end;
        {
         * If we have a previous decoder, we check that the input type
         * of the next to be used matches the type of this previous one.
         * |new_input_type| holds the value of the 'input-type' parameter
         * for the decoder we're currently considering.
         }
        if (decoder <> nil)  and  (0>= OSSL_DECODER_is_a(decoder, new_input_type)) then
        begin
            if Boolean(0) then
            begin
                BIO_printf(trc_out,
                           '(ctx %p) %s [%u] the input type doesn''t match the name of the previous decoder (%p), skipping...\n',
                           [Pointer( new_data.ctx), LEVEL, uint32( i),
                           Pointer( decoder)]);
            end;
            continue;
        end;
        {
         * If the previous decoder gave us a data type, we check to see
         * if that matches the decoder we're currently considering.
         }
        if (data_type <> nil)  and  (0>= OSSL_DECODER_is_a(new_decoder, data_type)) then
        begin
            if Boolean(0) then
            begin
                BIO_printf(trc_out,
                           '(ctx %p) %s [%u] the previous decoder''s data type doesn''t match the name of the considered decoder, skipping...\n',
                           [Pointer( new_data.ctx), LEVEL, uint32( i)]);
            end;

            continue;
        end;
        {
         * If the previous decoder gave us a data structure name, we check
         * to see that it matches the input data structure of the decoder
         * we're currently considering.
         }
        if (data_structure <> nil)   and
           ( (new_input_structure = nil) or  (strcasecmp(data_structure, new_input_structure) <> 0) ) then
        begin
            if Boolean(0) then
            begin
                BIO_printf(trc_out,
                  '(ctx %p) %s [%u] the previous decoder''s data structure doesn''t match the input structure of the considered decoder,skipping...\n',
                           [Pointer( new_data.ctx), LEVEL, uint32( i)]);
            end;

            continue;
        end;
        {
         * If the decoder we're currently considering specifies a structure,
         * and this check hasn't already been done earlier in this chain of
         * decoder_process() calls, check that it matches the user provided
         * input structure, if one is given.
         }
        if (0>= data.flag_input_structure_checked)
             and  (ctx.input_structure <> nil)
             and  (new_input_structure <> nil) then
        begin
            data.flag_input_structure_checked := 1;
            if strcasecmp(new_input_structure, ctx.input_structure) <> 0  then
            begin
                if Boolean(0) then
                begin
                    BIO_printf(trc_out,
                               '(ctx %p) %s [%u] the previous decoder''s data structure doesn''t match the input structure given by the user, skipping...\n',
                               [Pointer( new_data.ctx), LEVEL, uint32( i)]);
                end;

                continue;
            end;
        end;
        {
         * Checking the return value of BIO_reset() or BIO_seek() is unsafe.
         * Furthermore, BIO_reset() is unsafe to use if the source BIO happens
         * to be a BIO_s_mem(), because the earlier BIO_tell() gives us zero
         * no matter where we are in the underlying buffer we're reading from.
         *
         * So, we simply do a BIO_seek(), and use BIO_tell() that we're back
         * at the same position.  This is a best effort attempt, but BIO_seek()
         * and BIO_tell() should come as a pair...
         }
        BIO_seek(bio, loc);
        if BIO_tell(bio) <> loc  then
            goto _end ;
        { Recurse }
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       '(ctx %p) %s [%u] Running decoder instance %p\n',
                       [Pointer( new_data.ctx), LEVEL, uint32( i),
                       Pointer( new_decoder_inst)]);
        end;

        {
         * We only care about errors reported from decoder implementations
         * if it returns false (i.e. there was a fatal error).
         }
        ERR_set_mark();
        new_data.current_decoder_inst_index := i;
        new_data.flag_input_structure_checked := data.flag_input_structure_checked;

        writeln('function decoder_process i=', i);
        ok := new_decoder.decode(new_decoderctx, cbio,
                                 new_data.ctx.selection,
                                 decoder_process, @new_data,
                                 ossl_pw_passphrase_callback_dec,
                                 @new_data.ctx.pwdata);
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       '(ctx %p) %s [%u] Running decoder instance %p => %d'+
                       ' (recursed further: %s, construct called: %s)\n',
                       [Pointer( new_data.ctx), LEVEL, uint32( i),
                       Pointer( new_decoder_inst), ok,
                     get_result(new_data.flag_next_level_called > 0, 'yes' , 'no'),
                     get_result(new_data.flag_construct_called > 0, 'yes' , 'no')]);
        end;

        data.flag_construct_called := new_data.flag_construct_called;
        { Break on error or if we tried to construct an object already }
        if (0>= ok)  or  (data.flag_construct_called > 0) then
        begin
            ERR_clear_last_mark();
            break;
        end;
        ERR_pop_to_mark();
        {
         * Break if the decoder implementation that we called recursed, since
         * that indicates that it successfully decoded something.
         }
        if new_data.flag_next_level_called > 0 then
           break;
    end; //-->for i := data.current_decoder_inst_index

 _end:
    ossl_core_bio_free(cbio);
    BIO_free(new_data.bio);
    Result := ok;
end;

function OSSL_DECODER_from_bio( ctx : POSSL_DECODER_CTX; _in : PBIO):integer;
var
  data                  : decoder_process_data_st;
  ok                    : integer;
  new_bio               : PBIO;
  lasterr               : Cardinal;
  spaces,
  input_type_label,
  input_structure_label,
  comma, input_type,
  input_structure       : PUTF8Char;
begin
    ok := 0;
    new_bio := nil;
    if _in = nil then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    if OSSL_DECODER_CTX_get_num_decoders(ctx) = 0  then
    begin
        ERR_raise_data(ERR_LIB_OSSL_DECODER, OSSL_DECODER_R_DECODER_NOT_FOUND,
                     Format( 'No decoders were found. For standard decoders you need '+
                       'at least one of the default or base providers '+
                       'available. Did you forget to load them?',[]));
        Exit(0);
    end;
    lasterr := ERR_peek_last_error();
    if BIO_tell(_in) < 0  then
    begin
        new_bio := BIO_new(BIO_f_readbuffer);
        if new_bio = nil then
           Exit(0);
        _in := BIO_push(new_bio, _in);
    end;
    data := default(decoder_process_data_st);
    data.ctx := ctx;
    data.bio := _in;
    { Enable passphrase caching }
    ossl_pw_enable_passphrase_caching(@ctx.pwdata);
    ok := decoder_process(nil, @data);
    if 0>= data.flag_construct_called then
    begin
        spaces                := get_result( (ctx.start_input_type <> nil)  and  (ctx.input_structure <> nil), ' ' , '');
        input_type_label      := get_result( ctx.start_input_type <> nil , 'Input type: ' , '');
        input_structure_label := get_result( ctx.input_structure <> nil , 'Input structure: ' , '');
        comma                 := get_result( (ctx.start_input_type <> nil)  and  (ctx.input_structure <> nil), ', ' , '');
        input_type            := get_result( ctx.start_input_type <> nil , ctx.start_input_type , '');
        input_structure       := get_result( ctx.input_structure <> nil , ctx.input_structure , '');
        if (ERR_peek_last_error() = lasterr)  or  (ERR_peek_error() = 0) then
            { Prevent spurious decoding error but add at least something }
            ERR_raise_data(ERR_LIB_OSSL_DECODER, ERR_R_UNSUPPORTED,
                         Format('No supported data to decode. %s%s%s%s%s%s',
                           [spaces, input_type_label, input_type, comma,
                           input_structure_label, input_structure]));
        ok := 0;
    end;
    { Clear any internally cached passphrase }
    ossl_pw_clear_passphrase_cache(@ctx.pwdata);
    if new_bio <> nil then
    begin
        BIO_pop(new_bio);
        BIO_free(new_bio);
    end;
    Result := ok;
end;



function OSSL_DECODER_from_data(ctx : POSSL_DECODER_CTX;const pdata : PPByte; pdata_len : Psize_t):integer;
var
  membio : PBIO;
  ret : integer;
begin
    ret := 0;
    if (pdata = nil)  or  (pdata^ = nil)  or  (pdata_len = nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    membio := BIO_new_mem_buf( pdata^, Integer (pdata_len^));
    if OSSL_DECODER_from_bio(ctx, membio) > 0 then
    begin
        pdata_len^ := size_t(BIO_ctrl(membio,3,0, Pointer(pdata^))); // BIO_get_mem_data(membio, pdata));
        ret := 1;
    end;
    BIO_free(membio);
    Result := ret;
end;





procedure sk_OSSL_DECODER_INSTANCE_pop_free( sk : Pstack_st_OSSL_DECODER_INSTANCE; freefunc : sk_OSSL_DECODER_INSTANCE_freefunc);
begin
   OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc));
end;



procedure sk_OSSL_DECODER_pop_free( sk : Pstack_st_OSSL_DECODER; freefunc : sk_OSSL_DECODER_freefunc);
begin
    OPENSSL_sk_pop_free(POPENSSL_STACK( sk), OPENSSL_sk_freefunc(freefunc));
end;





function sk_OSSL_DECODER_value(const sk : Pstack_st_OSSL_DECODER; idx : integer):POSSL_DECODER;
begin
   Result := POSSL_DECODER(OPENSSL_sk_value(POPENSSL_STACK( sk), idx));
end;

procedure collect_extra_decoder( decoder : POSSL_DECODER; arg : Pointer);
var
  data       : Pcollect_extra_decoder_data_st;
  j          : size_t;
  prov       : POSSL_PROVIDER;
  provctx,
  decoderctx : Pointer;
  di,
  check_inst : POSSL_DECODER_INSTANCE;
  trc_out: PBIO;
begin
    data := arg;
    prov := OSSL_DECODER_get0_provider(decoder);
    provctx := OSSL_PROVIDER_get0_provider_ctx(prov);
    if OSSL_DECODER_is_a(decoder, data.output_type) > 0 then
    begin
        decoderctx := nil;
        di := nil;
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       '(ctx %p) [%d] Checking out decoder %p:\n'+
                       '    %s with %s\n',
                       [Pointer( data.ctx), Int(data.type_check), Pointer( decoder),
                       OSSL_DECODER_get0_name(decoder),
                       OSSL_DECODER_get0_properties(decoder)]);
        end;
        //OSSL_TRACE_END(DECODER);
        {
         * Check that we don't already have this decoder in our stack,
         * starting with the previous windows but also looking at what
         * we have added in the current window.
         }
        for j := data.w_prev_start to data.w_new_end-1 do
        begin
            check_inst := sk_OSSL_DECODER_INSTANCE_value(data.ctx.decoder_insts, j);
            if decoder.base.algodef = check_inst.decoder.base.algodef then
            begin
                { We found it, so don't do anything more }
                if Boolean(0) then
                begin
                    BIO_printf(trc_out,
                               '    REJECTED: already exists in the chain\n', []);
                end;
                //OSSL_TRACE_END(DECODER);
                exit;
            end;
        end;
        decoderctx := decoder.newctx(provctx);
        if decoderctx = nil then
            exit;
        di := ossl_decoder_instance_new(decoder, decoderctx);
        if di = nil then
        begin
            decoder.freectx(decoderctx);
            exit;
        end;
        case data.type_check of
        IS_SAME:
            { If it differs, this is not a decoder to add for now. }
            if 0>= OSSL_DECODER_is_a(decoder,
                                   OSSL_DECODER_INSTANCE_get_input_type(di)) then
            begin
                ossl_decoder_instance_free(di);
                if Boolean(0) then
                begin
                    BIO_printf(trc_out,
                               '    REJECTED: input type doesn''t match output type\n', []);
                end;
                // OSSL_TRACE_END(DECODER);
                exit;
            end;
            //break;
        IS_DIFFERENT:
            { If it's the same, this is not a decoder to add for now. }
            if OSSL_DECODER_is_a(decoder,
                                  OSSL_DECODER_INSTANCE_get_input_type(di))>0 then
            begin
                ossl_decoder_instance_free(di);
                if Boolean(0) then
                begin
                    BIO_printf(trc_out,
                               '    REJECTED: input type matches output type\n', []);
                end;
                //OSSL_TRACE_END(DECODER);
                exit;
            end;
            //break;
        end;
        {
         * Apart from keeping w_new_end up to date, We don't care about
         * errors here.  If it doesn't collect, then it doesn't...
         }
        if 0>= ossl_decoder_ctx_add_decoder_inst(data.ctx, di) then
        begin
            ossl_decoder_instance_free(di);
            exit;
        end;
        Inc(data.w_new_end);
    end;
end;

function OSSL_DECODER_INSTANCE_get_input_type( decoder_inst : POSSL_DECODER_INSTANCE):PUTF8Char;
begin
    if decoder_inst = nil then
       Exit(nil);
    Result := decoder_inst.input_type;
end;

function sk_OSSL_DECODER_INSTANCE_value(const sk : Pstack_st_OSSL_DECODER_INSTANCE; idx : integer):POSSL_DECODER_INSTANCE;
begin
    Exit(POSSL_DECODER_INSTANCE(OPENSSL_sk_value(POPENSSL_STACK( sk), idx)));
end;

function sk_OSSL_DECODER_num(const sk : Pstack_st_OSSL_DECODER):integer;
begin
   Exit(OPENSSL_sk_num(POPENSSL_STACK( sk)) );
end;




function sk_OSSL_DECODER_push( sk : Pstack_st_OSSL_DECODER; ptr : POSSL_DECODER):integer;
begin
   Exit(OPENSSL_sk_push(POPENSSL_STACK( sk), Pointer( ptr)) );
end;


procedure collect_all_decoders( decoder : POSSL_DECODER; arg : Pointer);
var
  skdecoders : Pstack_st_OSSL_DECODER;
begin
    skdecoders := arg;
    if OSSL_DECODER_up_ref(decoder) > 0 then
        sk_OSSL_DECODER_push(skdecoders, decoder);
end;




function sk_OSSL_DECODER_new_null:Pstack_st_OSSL_DECODER;
begin
   Result := Pstack_st_OSSL_DECODER(OPENSSL_sk_new_null);
end;




function OSSL_DECODER_CTX_add_extra(ctx : POSSL_DECODER_CTX; libctx : POSSL_LIB_CTX;const propq : PUTF8Char):integer;
var
  data         : collect_extra_decoder_data_st;
  depth,
  count,
  numdecoders  : size_t;
  k: int;
  skdecoders   : Pstack_st_OSSL_DECODER;
  i,
  j            : size_t;
  trc_out      : PBIO;
  decoder_inst : POSSL_DECODER_INSTANCE;
begin
    {
     * This function goes through existing decoder methods in
     * |ctx.decoder_insts|, and tries to fetch new decoders that produce
     * what the existing ones want as input, and push those newly fetched
     * decoders on top of the same stack.
     * Then it does the same again, but looping over the newly fetched
     * decoders, until there are no more decoders to be fetched, or
     * when we have done this 10 times.
     *
     * we do this with sliding windows on the stack by keeping track of indexes
     * and of the end.
     *
     * +----------------+
     * or   DER to RSA   or <--- w_prev_start
     * +----------------+
     * or   DER to DSA   or
     * +----------------+
     * or   DER to DH    or
     * +----------------+
     * or   PEM to DER   or <--- w_prev_end, w_new_start
     * +----------------+
     *                    <--- w_new_end
     }
    depth := 0;
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    {
     * If there is no stack of OSSL_DECODER_INSTANCE, we have nothing
     * more to add.  That's fine.
     }
    if ctx.decoder_insts = nil then
       Exit(1);
    if Boolean(0) then
    begin
        BIO_printf(trc_out, '(ctx %p) Looking for extra decoders\n',
                   [Pointer( ctx)]);
    end;
   // OSSL_TRACE_END(DECODER);
    skdecoders := sk_OSSL_DECODER_new_null();
    if skdecoders = nil then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    OSSL_DECODER_do_all_provided(libctx, collect_all_decoders, skdecoders);
    numdecoders := sk_OSSL_DECODER_num(skdecoders);
    memset(@data, 0, sizeof(data));
    data.ctx := ctx;
    data.w_prev_start := 0;
    data.w_prev_end := sk_OSSL_DECODER_INSTANCE_num(ctx.decoder_insts);
    repeat
        data.w_new_start := data.w_prev_end;
        data.w_new_end   := data.w_prev_end;
        {
         * Two iterations:
         * 0.  All decoders that have the same name as their input type.
         *     This allows for decoders that unwrap some data in a specific
         *     encoding, and pass the result on with the same encoding.
         * 1.  All decoders that a different name than their input type.
         }
        data.type_check := IS_SAME;
        while  data.type_check <= IS_DIFFERENT do
        begin
            for i := data.w_prev_start to data.w_prev_end-1 do
            begin
                decoder_inst := sk_OSSL_DECODER_INSTANCE_value(ctx.decoder_insts, i);
                data.output_type := OSSL_DECODER_INSTANCE_get_input_type(decoder_inst);
                for j := 0 to numdecoders-1 do
                begin
                    //writeln('decoder_lib.OSSL_DECODER_CTX_add_extra j=', j);
                    collect_extra_decoder(sk_OSSL_DECODER_value(skdecoders, j), @data);
                end;
            end;
            if data.type_check < IS_DIFFERENT then
               Inc(data.type_check)
            else
               Break;
        end;
        { How many were added in this iteration }
        count := data.w_new_end - data.w_new_start;
        { Slide the 'previous decoder' windows }
        data.w_prev_start := data.w_new_start;
        data.w_prev_end := data.w_new_end;
        Inc(depth);
    until not ( (count <> 0)  and  (depth <= 10) );

    sk_OSSL_DECODER_pop_free(skdecoders, OSSL_DECODER_free);
    Result := 1;
end;

function OSSL_DECODER_CTX_set_selection( ctx : POSSL_DECODER_CTX; selection : integer):integer;
begin
    if not ossl_assert(ctx <> nil ) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    {
     * 0 is a valid selection, and means that the caller leaves
     * it to code to discover what the selection is.
     }
    ctx.selection := selection;
    Result := 1;
end;




function OSSL_DECODER_CTX_set_input_structure(ctx : POSSL_DECODER_CTX;const input_structure : PUTF8Char):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    {
     * nil is a valid starting input structure, and means that the caller
     * leaves it to code to discover what the starting input structure is.
     }
    ctx.input_structure := input_structure;
    Result := 1;
end;




function OSSL_DECODER_CTX_set_input_type(ctx : POSSL_DECODER_CTX;const input_type : PUTF8Char):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    {
     * nil is a valid starting input type, and means that the caller leaves
     * it to code to discover what the starting input type is.
     }
    ctx.start_input_type := input_type;
    Result := 1;
end;

function OSSL_DECODER_CTX_set_cleanup(ctx : POSSL_DECODER_CTX;cleanup : TOSSL_DECODER_CLEANUP):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx.cleanup := cleanup;
    Result := 1;
end;


function OSSL_DECODER_CTX_set_construct_data( ctx : POSSL_DECODER_CTX; construct_data : Pointer):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx.construct_data := construct_data;
    Result := 1;
end;

function OSSL_DECODER_CTX_set_construct( ctx : POSSL_DECODER_CTX; construct : TOSSL_DECODER_CONSTRUCT):integer;
begin
    if not ossl_assert(ctx <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    ctx.construct := construct;
    Result := 1;
end;


function sk_OSSL_DECODER_INSTANCE_num(const sk: Pstack_st_OSSL_DECODER_INSTANCE):integer;
begin
   Result := OPENSSL_sk_num(POPENSSL_STACK( sk));
end;




function OSSL_DECODER_CTX_get_num_decoders( ctx : POSSL_DECODER_CTX):integer;
begin
    if (ctx = nil)  or  (ctx.decoder_insts = nil) then
       Exit(0);
    Result := sk_OSSL_DECODER_INSTANCE_num(ctx.decoder_insts);
end;




function sk_OSSL_DECODER_INSTANCE_push( sk : Pstack_st_OSSL_DECODER_INSTANCE; ptr : POSSL_DECODER_INSTANCE):integer;
begin
   Result := OPENSSL_sk_push(POPENSSL_STACK( sk), Pointer( ptr));
end;




function sk_OSSL_DECODER_INSTANCE_new_null:Pstack_st_OSSL_DECODER_INSTANCE;
begin
    Result := Pstack_st_OSSL_DECODER_INSTANCE(OPENSSL_sk_new_null);
end;




function ossl_decoder_ctx_add_decoder_inst( ctx : POSSL_DECODER_CTX; di : POSSL_DECODER_INSTANCE):integer;
var
  ok : integer;
  trc_out: PBIO;
begin

    if (ctx.decoder_insts = nil) then
    begin
       ctx.decoder_insts := sk_OSSL_DECODER_INSTANCE_new_null();
       if (ctx.decoder_insts = nil) then
        begin
            ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
            Exit(0);
        end;
    end;
    ok := int(sk_OSSL_DECODER_INSTANCE_push(ctx.decoder_insts, di) > 0);
    if ok > 0 then
    begin
        if Boolean(0) then
        begin
            BIO_printf(trc_out,
                       '(ctx %p) Added decoder instance %p for decoder %p'#10+
                       '    %s with %s'#10,
                       [Pointer( ctx), Pointer( di), Pointer( di.decoder),
                       OSSL_DECODER_get0_name(di.decoder),
                       OSSL_DECODER_get0_properties(di.decoder)]);
        end;
        // OSSL_TRACE_END(DECODER);
    end;
    Result := ok;
end;

procedure ossl_decoder_instance_free( decoder_inst : POSSL_DECODER_INSTANCE);
begin
    if decoder_inst <> nil then
    begin
        if decoder_inst.decoder <> nil then
            decoder_inst.decoder.freectx(decoder_inst.decoderctx);
        decoder_inst.decoderctx := nil;
        OSSL_DECODER_free(decoder_inst.decoder);
        decoder_inst.decoder := nil;
        OPENSSL_free(decoder_inst);
    end;
end;

function ossl_decoder_instance_new( decoder : POSSL_DECODER; decoderctx : Pointer):POSSL_DECODER_INSTANCE;
var
    decoder_inst : POSSL_DECODER_INSTANCE;
    prov         : POSSL_PROVIDER;
    libctx       : POSSL_LIB_CTX;
    props        : POSSL_PROPERTY_LIST;
    prop         : POSSL_PROPERTY_DEFINITION;
    label _err;
begin
    decoder_inst := nil;
    if not ossl_assert(decoder <> nil) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_PASSED_NULL_PARAMETER);
        Exit(0);
    end;
    decoder_inst := OPENSSL_zalloc(sizeof(decoder_inst^ ));
    if decoder_inst = nil then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        Exit(0);
    end;
    if 0>= OSSL_DECODER_up_ref(decoder) then
    begin
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_INTERNAL_ERROR);
        goto _err ;
    end;
    prov := OSSL_DECODER_get0_provider(decoder);
    libctx := ossl_provider_libctx(prov);
    props := ossl_decoder_parsed_properties(decoder);
    if props = nil then
    begin
        ERR_raise_data(ERR_LIB_OSSL_DECODER, ERR_R_INVALID_PROPERTY_DEFINITION,
                      Format( 'there are no property definitions with decoder %s',
                               [OSSL_DECODER_get0_name(decoder)]));
        goto _err ;
    end;
    { The 'input' property is mandatory }
    prop := ossl_property_find_property(props, libctx, 'input');
    decoder_inst.input_type := ossl_property_get_string_value(libctx, prop);
    if decoder_inst.input_type = nil then
    begin
        ERR_raise_data(ERR_LIB_OSSL_DECODER, ERR_R_INVALID_PROPERTY_DEFINITION,
                    Format('the mandatory ''input'' property is missing '+
                           'for decoder %s (properties: %s)',
                           [OSSL_DECODER_get0_name(decoder),
                           OSSL_DECODER_get0_properties(decoder)]));
        goto _err ;
    end;
    { The 'structure' property is optional }
    prop := ossl_property_find_property(props, libctx, 'structure');
    if prop <> nil then
    begin
        decoder_inst.input_structure := ossl_property_get_string_value(libctx, prop);
    end;
    decoder_inst.decoder := decoder;
    decoder_inst.decoderctx := decoderctx;
    Exit(decoder_inst);
 _err:
    ossl_decoder_instance_free(decoder_inst);
    Result := nil;
end;



function OSSL_DECODER_INSTANCE_get_decoder_ctx( decoder_inst : POSSL_DECODER_INSTANCE):Pointer;
begin
    if decoder_inst = nil then Exit(nil);
    Result := decoder_inst.decoderctx;
end;

function OSSL_DECODER_INSTANCE_get_decoder( decoder_inst : POSSL_DECODER_INSTANCE):POSSL_DECODER;
begin
    if decoder_inst = nil then
       Exit(nil);
    Result := decoder_inst.decoder;
end;


end.
