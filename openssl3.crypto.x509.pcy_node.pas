unit openssl3.crypto.x509.pcy_node;

interface
uses OpenSSL.Api;

function node_cmp(const a, b : PPX509_POLICY_NODE):integer;
  function ossl_policy_node_cmp_new:Pstack_st_X509_POLICY_NODE;
  function ossl_policy_tree_find_sk(nodes : Pstack_st_X509_POLICY_NODE;const id : PASN1_OBJECT):PX509_POLICY_NODE;
  function ossl_policy_level_find_node(const level : PX509_POLICY_LEVEL; parent : PX509_POLICY_NODE; id : PASN1_OBJECT):PX509_POLICY_NODE;
  function ossl_policy_level_add_node( level : PX509_POLICY_LEVEL; data : PX509_POLICY_DATA; parent : PX509_POLICY_NODE; tree : PX509_POLICY_TREE):PX509_POLICY_NODE;
  procedure ossl_policy_node_free( node : PX509_POLICY_NODE);
  function ossl_policy_node_match(const lvl : PX509_POLICY_LEVEL; node : PX509_POLICY_NODE; oid : PASN1_OBJECT):integer;
  function node_critical(node: PX509_POLICY_NODE): int;
  function node_data_critical(data: PX509_POLICY_DATA): int;

implementation
uses openssl3.crypto.objects.obj_lib, openssl3.crypto.x509v3, OpenSSL3.Err,
     openssl3.crypto.mem, openssl3.crypto.objects.obj_dat,
     openssl3.crypto.x509.pcy_cache, OpenSSL3.include.openssl.asn1;

function node_data_critical(data: PX509_POLICY_DATA): int;
begin
  Result := (data.flags and POLICY_DATA_FLAG_CRITICAL)
end;

function node_critical(node: PX509_POLICY_NODE): int;
begin
   Result := node_data_critical(node.data)
end;

function node_cmp(const a, b : PPX509_POLICY_NODE):integer;
begin
    Result := _OBJ_cmp((a^).data.valid_policy, (b^).data.valid_policy);
end;


function ossl_policy_node_cmp_new:Pstack_st_X509_POLICY_NODE;
begin
    Result := sk_X509_POLICY_NODE_new(node_cmp);
end;


function ossl_policy_tree_find_sk(nodes : Pstack_st_X509_POLICY_NODE;const id : PASN1_OBJECT):PX509_POLICY_NODE;
var
  n : TX509_POLICY_DATA;
  l : TX509_POLICY_NODE;
  idx : integer;
begin
    n.valid_policy := PASN1_OBJECT(id);
    l.data := @n;
    idx := sk_X509_POLICY_NODE_find(nodes, @l);
    Exit(sk_X509_POLICY_NODE_value(nodes, idx));
end;


function ossl_policy_level_find_node(const level : PX509_POLICY_LEVEL; parent : PX509_POLICY_NODE; id : PASN1_OBJECT):PX509_POLICY_NODE;
var
  node : PX509_POLICY_NODE;

  i : integer;
begin
    for i := 0 to sk_X509_POLICY_NODE_num(level.nodes)-1 do
    begin
        node := sk_X509_POLICY_NODE_value(level.nodes, i);
        if node.parent = parent then
        begin
            if 0>=_OBJ_cmp(node.data.valid_policy, id) then
                Exit(node);
        end;
    end;
    Result := nil;
end;


function ossl_policy_level_add_node( level : PX509_POLICY_LEVEL; data : PX509_POLICY_DATA; parent : PX509_POLICY_NODE; tree : PX509_POLICY_TREE):PX509_POLICY_NODE;
var
  node : PX509_POLICY_NODE;
  label _node_error;
begin
    node := OPENSSL_zalloc(sizeof( node^));
    if node = nil then begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(nil);
    end;
    node.data := data;
    node.parent := parent;
    if level <> nil then
    begin
        if OBJ_obj2nid(data.valid_policy) = NID_any_policy then
        begin
            if level.anyPolicy <> nil then
                goto _node_error;
            level.anyPolicy := node;
        end
        else
        begin
            if level.nodes = nil then
               level.nodes := ossl_policy_node_cmp_new;
            if level.nodes = nil then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto _node_error;
            end;
            if 0>=sk_X509_POLICY_NODE_push(level.nodes, node) then
            begin
                ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
                goto _node_error;
            end;
        end;
    end;
    if tree <> nil then
    begin
        if tree.extra_data = nil then
            tree.extra_data := sk_X509_POLICY_DATA_new_null;
        if tree.extra_data = nil then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _node_error;
        end;
        if 0>=sk_X509_POLICY_DATA_push(tree.extra_data, data) then
        begin
            ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
            goto _node_error;
        end;
    end;
    if parent <> nil then
       Inc(parent.nchild);
    Exit(node);
 _node_error:
    ossl_policy_node_free(node);
    Result := nil;
end;


procedure ossl_policy_node_free( node : PX509_POLICY_NODE);
begin
    OPENSSL_free(node);
end;


function ossl_policy_node_match(const lvl : PX509_POLICY_LEVEL; node : PX509_POLICY_NODE; oid : PASN1_OBJECT):integer;
var
    i          : integer;
    policy_oid : PASN1_OBJECT;
    x          : PX509_POLICY_DATA;
begin
   x := node.data;
    if (lvl.flags and X509_V_FLAG_INHIBIT_MAP > 0) or
       (0>=x.flags and POLICY_DATA_FLAG_MAP_MASK) then
       begin
        if 0>=_OBJ_cmp(x.valid_policy, oid) then
            Exit(1);
        Exit(0);
    end;
    for i := 0 to sk_ASN1_OBJECT_num(x.expected_policy_set)-1 do
    begin
        policy_oid := sk_ASN1_OBJECT_value(x.expected_policy_set, i);
        if 0>=_OBJ_cmp(policy_oid, oid) then
            Exit(1);
    end;
    Exit(0);
end;

end.
