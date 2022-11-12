unit openssl3.crypto.x509.pcy_tree;

interface
uses OpenSSL.Api;

const
   TREE_CALC_FAILURE = 0;
   TREE_CALC_OK_NOFREE = 1;
   TREE_CALC_OK_DOFREE = 2;

function X509_policy_check( ptree : PPX509_POLICY_TREE; pexplicit_policy : PInteger; certs: Pstack_st_X509; policy_oids : Pstack_st_ASN1_OBJECT; flags : uint32):integer;
 procedure X509_policy_tree_free( tree : PX509_POLICY_TREE);
procedure exnode_free( node : PX509_POLICY_NODE);
function tree_init( ptree : PPX509_POLICY_TREE; certs: Pstack_st_X509; flags : uint32):integer;
function tree_evaluate( tree : PX509_POLICY_TREE):integer;
function tree_link_nodes(curr : PX509_POLICY_LEVEL;const cache : PX509_POLICY_CACHE):integer;
function tree_link_matching_nodes( curr : PX509_POLICY_LEVEL; data : PX509_POLICY_DATA):integer;
function tree_link_any(curr : PX509_POLICY_LEVEL;const cache : PX509_POLICY_CACHE; tree : PX509_POLICY_TREE):integer;
function tree_link_unmatched(curr : PX509_POLICY_LEVEL;const cache : PX509_POLICY_CACHE; node : PX509_POLICY_NODE; tree : PX509_POLICY_TREE):integer;
function tree_add_unmatched(curr : PX509_POLICY_LEVEL;const cache : PX509_POLICY_CACHE; id : PASN1_OBJECT; node : PX509_POLICY_NODE; tree : PX509_POLICY_TREE):integer;
function tree_prune( tree : PX509_POLICY_TREE; curr : PX509_POLICY_LEVEL):integer;
function tree_calculate_authority_set( tree : PX509_POLICY_TREE; pnodes : PPstack_st_X509_POLICY_NODE):integer;
function tree_add_auth_node( pnodes : PPstack_st_X509_POLICY_NODE; pcy : PX509_POLICY_NODE):integer;
 function tree_calculate_user_set( tree : PX509_POLICY_TREE; policy_oids : Pstack_st_ASN1_OBJECT; auth_nodes : Pstack_st_X509_POLICY_NODE):integer;

implementation
uses openssl3.crypto.x509, OpenSSL3.crypto.x509.v3_purp,
     OpenSSL3.Err, openssl3.crypto.x509.pcy_data,
     openssl3.crypto.x509.pcy_lib,
     openssl3.crypto.x509.x_x509,  OpenSSL3.include.openssl.asn1,
     openssl3.crypto.objects.obj_dat,  openssl3.crypto.x509v3,
     openssl3.crypto.x509.pcy_node, OpenSSL3.crypto.x509.x509_set,
     openssl3.crypto.x509.pcy_cache, openssl3.crypto.mem;





function tree_calculate_user_set( tree : PX509_POLICY_TREE; policy_oids : Pstack_st_ASN1_OBJECT; auth_nodes : Pstack_st_X509_POLICY_NODE):integer;
var
    i         : integer;
    node      : PX509_POLICY_NODE;
    oid       : PASN1_OBJECT;
    anyPolicy : PX509_POLICY_NODE;
    extra     : PX509_POLICY_DATA;
begin
{$POINTERMATH ON}
    {
     * Check if anyPolicy present in authority constrained policy set: this
     * will happen if it is a leaf node.
     }
    if sk_ASN1_OBJECT_num(policy_oids) <= 0  then
        Exit(1);
    anyPolicy := tree.levels[tree.nlevel - 1].anyPolicy;
    for i := 0 to sk_ASN1_OBJECT_num(policy_oids)-1 do
    begin
        oid := sk_ASN1_OBJECT_value(policy_oids, i);
        if OBJ_obj2nid(oid) = NID_any_policy  then
        begin
            tree.flags  := tree.flags  or POLICY_FLAG_ANY_POLICY;
            Exit(1);
        end;
    end;
    for i := 0 to sk_ASN1_OBJECT_num(policy_oids)-1 do
    begin
        oid := sk_ASN1_OBJECT_value(policy_oids, i);
        node := ossl_policy_tree_find_sk(auth_nodes, oid);
        if nil = node then
        begin
            if nil =anyPolicy then
                continue;
            {
             * Create a new node with policy ID from user set and qualifiers
             * from anyPolicy.
             }
            extra := ossl_policy_data_new(nil, oid, node_critical(anyPolicy));
            if extra = nil then Exit(0);
            extra.qualifier_set := anyPolicy.data.qualifier_set;
            extra.flags := POLICY_DATA_FLAG_SHARED_QUALIFIERS or POLICY_DATA_FLAG_EXTRA_NODE;
            node := ossl_policy_level_add_node(nil, extra, anyPolicy.parent, tree);
        end;
        if nil =tree.user_policies then
        begin
            tree.user_policies := sk_X509_POLICY_NODE_new_null;
            if nil = tree.user_policies then Exit(1);
        end;
        if 0>=sk_X509_POLICY_NODE_push(tree.user_policies, node) then
            Exit(0);
    end;
    Result := 1;
{$POINTERMATH OFF}
end;

function tree_add_auth_node( pnodes : PPstack_st_X509_POLICY_NODE; pcy : PX509_POLICY_NODE):integer;
begin
    if pnodes^ = nil  then
    begin
        pnodes^ := ossl_policy_node_cmp_new();
        if pnodes^ = nil  then
           Exit(0);
    end;
    if sk_X509_POLICY_NODE_find(pnodes^, pcy) >= 0 then
        Exit(1);
    Result := Int(sk_X509_POLICY_NODE_push(pnodes^, pcy) <> 0);
end;

function tree_calculate_authority_set( tree : PX509_POLICY_TREE; pnodes : PPstack_st_X509_POLICY_NODE):integer;
var
  curr     : PX509_POLICY_LEVEL;
  node,
  anyptr   : PX509_POLICY_NODE;
  addnodes : PPstack_st_X509_POLICY_NODE;
  i,  j    : integer;
begin
{$POINTERMATH ON}
    curr := tree.levels + tree.nlevel - 1;
    { If last level contains anyPolicy set is anyPolicy }
    if curr.anyPolicy <> nil then
    begin
        if 0>=tree_add_auth_node(@tree.auth_policies, curr.anyPolicy) then
            Exit(TREE_CALC_FAILURE);
        addnodes := pnodes;
    end
    else
        { Add policies to authority set }
        addnodes := @tree.auth_policies;
    curr := tree.levels;
    for i := 1 to tree.nlevel-1 do
    begin
        {
         * If no anyPolicy node on this level it can't appear on lower
         * levels so end search.
         }
         anyptr := curr.anyPolicy;
        if anyptr = nil then
            break;
        Inc(curr);
        for j := 0 to sk_X509_POLICY_NODE_num(curr.nodes)-1 do
        begin
            node := sk_X509_POLICY_NODE_value(curr.nodes, j);
            if (node.parent = anyptr)  and  (0>=tree_add_auth_node(addnodes, node)) then
            begin
                if addnodes = pnodes then
                begin
                    sk_X509_POLICY_NODE_free( pnodes^);
                    pnodes^ := nil;
                end;
                Exit(TREE_CALC_FAILURE);
            end;
        end;
    end;
    if addnodes = pnodes then
       Exit(TREE_CALC_OK_DOFREE);
    pnodes^ := tree.auth_policies;
    Result := TREE_CALC_OK_NOFREE;
{$POINTERMATH OFF}
end;




function tree_prune( tree : PX509_POLICY_TREE; curr : PX509_POLICY_LEVEL):integer;
var
  nodes : Pstack_st_X509_POLICY_NODE;
  node : PX509_POLICY_NODE;
  i : integer;
begin
    nodes := curr.nodes;
    if curr.flags and X509_V_FLAG_INHIBIT_MAP > 0 then
    begin
        for i := sk_X509_POLICY_NODE_num(nodes) - 1 downto 0 do
        begin
            node := sk_X509_POLICY_NODE_value(nodes, i);
            { Delete any mapped data: see RFC3280 XXXX }
            if node.data.flags and POLICY_DATA_FLAG_MAP_MASK > 0 then
            begin
                Dec(node.parent.nchild);
                OPENSSL_free(node);
                sk_X509_POLICY_NODE_delete(nodes, i);
            end;
        end;
    end;
    while true do
    begin
        Dec(curr);
        nodes := curr.nodes;
        for i := sk_X509_POLICY_NODE_num(nodes) - 1 downto 0 do
        begin
            node := sk_X509_POLICY_NODE_value(nodes, i);
            if node.nchild = 0 then
            begin
                Dec(node.parent.nchild);
                OPENSSL_free(node);
                sk_X509_POLICY_NODE_delete(nodes, i);
            end;
        end;
        if (curr.anyPolicy <> nil)  and  (0>=curr.anyPolicy.nchild) then
        begin
            if curr.anyPolicy.parent <> nil then
               Dec( curr.anyPolicy.parent.nchild);
            OPENSSL_free(curr.anyPolicy);
            curr.anyPolicy := nil;
        end;
        if curr = tree.levels then
        begin
            { If we zapped anyPolicy at top then tree is empty }
            if nil =curr.anyPolicy then
                Exit(X509_PCY_TREE_EMPTY);
            break;
        end;
    end;
    Result := X509_PCY_TREE_VALID;
end;




function tree_add_unmatched(curr : PX509_POLICY_LEVEL;const cache : PX509_POLICY_CACHE; id : PASN1_OBJECT; node : PX509_POLICY_NODE; tree : PX509_POLICY_TREE):integer;
var
  data : PX509_POLICY_DATA;
begin
    if id = nil then
       id := node.data.valid_policy;
    {
     * Create a new node with qualifiers from anyPolicy and id from unmatched
     * node.
     }
     data := ossl_policy_data_new(nil, id, node_critical(node));
    if data = nil then
        Exit(0);
    { Curr may not have anyPolicy }
    data.qualifier_set := cache.anyPolicy.qualifier_set;
    data.flags  := data.flags  or POLICY_DATA_FLAG_SHARED_QUALIFIERS;
    if ossl_policy_level_add_node(curr, data, node, tree) = nil  then
    begin
        ossl_policy_data_free(data);
        Exit(0);
    end;
    Result := 1;
end;




function tree_link_unmatched(curr : PX509_POLICY_LEVEL;const cache : PX509_POLICY_CACHE; node : PX509_POLICY_NODE; tree : PX509_POLICY_TREE):integer;
var
  last : PX509_POLICY_LEVEL;
  i : integer;
  expset : Pstack_st_ASN1_OBJECT;
  oid : PASN1_OBJECT;
begin
{$POINTERMATH ON}
    last := curr - 1;
    if (last.flags and X509_V_FLAG_INHIBIT_MAP > 0) or
       (0>= node.data.flags and POLICY_DATA_FLAG_MAPPED) then
    begin
        { If no policy mapping: matched if one child present }
        if node.nchild > 0 then
            Exit(1);
        if 0>=tree_add_unmatched(curr, cache, nil, node, tree) then
            Exit(0);
        { Add it }
    end
    else
    begin
        { If mapping: matched if one child per expected policy set }
        expset := node.data.expected_policy_set;
        if node.nchild = sk_ASN1_OBJECT_num(expset) then
            Exit(1);
        { Locate unmatched nodes }
        for i := 0 to sk_ASN1_OBJECT_num(expset)-1 do
        begin
            oid := sk_ASN1_OBJECT_value(expset, i);
            if ossl_policy_level_find_node(curr, node, oid ) <> nil then
                continue;
            if 0>=tree_add_unmatched(curr, cache, oid, node, tree) then
                Exit(0);
        end;
    end;
    Result := 1;
{$POINTERMATH OFF}
end;

function tree_link_any(curr : PX509_POLICY_LEVEL;const cache : PX509_POLICY_CACHE; tree : PX509_POLICY_TREE):integer;
var
  i : integer;
  node : PX509_POLICY_NODE;
  last : PX509_POLICY_LEVEL;
begin
{$POINTERMATH ON}
    last := curr - 1;
    for i := 0 to sk_X509_POLICY_NODE_num(last.nodes)-1 do
    begin
        node := sk_X509_POLICY_NODE_value(last.nodes, i);
        if 0>=tree_link_unmatched(curr, cache, node, tree) then
            Exit(0);
    end;
    { Finally add link to anyPolicy }
    if (last.anyPolicy <> nil)  and
            (ossl_policy_level_add_node(curr, cache.anyPolicy,
                                       last.anyPolicy, nil) = nil) then
        Exit(0);
    Result := 1;
{$POINTERMATH OFF}
end;




function tree_link_matching_nodes( curr : PX509_POLICY_LEVEL; data : PX509_POLICY_DATA):integer;
var
  last : PX509_POLICY_LEVEL;
  i, matched : integer;
  node : PX509_POLICY_NODE;
begin
{$POINTERMATH ON}
    last := curr - 1;
    matched := 0;
    { Iterate through all in nodes linking matches }
    for i := 0 to sk_X509_POLICY_NODE_num(last.nodes)-1 do
    begin
        node := sk_X509_POLICY_NODE_value(last.nodes, i);
        if ossl_policy_node_match(last, node, data.valid_policy ) > 0 then
        begin
            if ossl_policy_level_add_node(curr, data, node, nil) = nil then
                Exit(0);
            matched := 1;
        end;
    end;
    if (0>=matched)  and  (last.anyPolicy <> nil) then
    begin
        if ossl_policy_level_add_node(curr, data, last.anyPolicy, nil) = nil then
            Exit(0);
    end;
    Result := 1;
{$POINTERMATH OFF}
end;

function tree_link_nodes(curr : PX509_POLICY_LEVEL;const cache : PX509_POLICY_CACHE):integer;
var
  i : integer;

  data : PX509_POLICY_DATA;
begin
    for i := 0 to sk_X509_POLICY_DATA_num(cache.data)-1 do
    begin
        data := sk_X509_POLICY_DATA_value(cache.data, i);
        { Look for matching nodes in previous level }
        if 0>=tree_link_matching_nodes(curr, data) then
            Exit(0);
    end;
    Result := 1;
end;




function tree_evaluate( tree : PX509_POLICY_TREE):integer;
var
  ret, i : integer;
  curr : PX509_POLICY_LEVEL;
  cache : PX509_POLICY_CACHE;
begin
{$POINTERMATH ON}
    curr := tree.levels + 1;
    for i := 1 to tree.nlevel-1 do
    begin
        cache := ossl_policy_cache_set(curr.cert);
        if 0>=tree_link_nodes(curr, cache ) then
            Exit(X509_PCY_TREE_INTERNAL);
        if (0>=curr.flags and X509_V_FLAG_INHIBIT_ANY) and
           (0>=tree_link_any(curr, cache, tree)) then
            Exit(X509_PCY_TREE_INTERNAL);
        //TREE_PRINT('before tree_prune', tree, curr);
        ret := tree_prune(tree, curr);
        if ret <> X509_PCY_TREE_VALID then
           Exit(ret);

        Inc(curr);
    end;
    Result := X509_PCY_TREE_VALID;
{$POINTERMATH OFF}
end;

procedure exnode_free( node : PX509_POLICY_NODE);
begin
    if (node.data <> nil) and  (node.data.flags and POLICY_DATA_FLAG_EXTRA_NODE > 0) then
        OPENSSL_free(node);
end;




procedure X509_policy_tree_free( tree : PX509_POLICY_TREE);
var
  curr : PX509_POLICY_LEVEL;

  i : integer;
begin
    if nil =tree then exit;
    sk_X509_POLICY_NODE_free(tree.auth_policies);
    sk_X509_POLICY_NODE_pop_free(tree.user_policies, exnode_free);
    i := 0; curr := tree.levels;
    while i < tree.nlevel do
    begin
        X509_free(curr.cert);
        sk_X509_POLICY_NODE_pop_free(curr.nodes, ossl_policy_node_free);
        ossl_policy_node_free(curr.anyPolicy);
        Inc(i); Inc(curr);
    end;
    sk_X509_POLICY_DATA_pop_free(tree.extra_data, ossl_policy_data_free);
    OPENSSL_free(tree.levels);
    OPENSSL_free(tree);
end;

function tree_init( ptree : PPX509_POLICY_TREE; certs: Pstack_st_X509; flags : uint32):integer;
var
    tree            : PX509_POLICY_TREE;
    level           : PX509_POLICY_LEVEL;
    cache           : PX509_POLICY_CACHE;
    data            : PX509_POLICY_DATA;
    ret,
    n,
    explicit_policy,
    any_skip,
    map_skip,
    i               : integer;
    x               : PX509;
    ex_flags        : uint32;
    label _bad_tree;
begin
    data := nil;
    ret := X509_PCY_TREE_VALID;
    n := sk_X509_num(certs) - 1;
    explicit_policy := get_result(flags and X509_V_FLAG_EXPLICIT_POLICY > 0 , 0 , n+1);
    any_skip := get_result(flags and X509_V_FLAG_INHIBIT_ANY > 0 , 0 , n+1);
    map_skip := get_result(flags and X509_V_FLAG_INHIBIT_MAP > 0 , 0 , n+1);
    ptree^ := nil;
    { Can't do anything with just a trust anchor }
    if n = 0 then
       Exit(X509_PCY_TREE_EMPTY);
    {
     * First setup the policy cache in all n non-TA certificates, this will be
     * used in X509_verify_cert which will invoke the verify callback for all
     * certificates with invalid policy extensions.
     }
    for i := n - 1 downto 0 do
    begin
        x := sk_X509_value(certs, i);
        { Call for side-effect of computing hash and caching extensions }
        X509_check_purpose(x, -1, 0);
        { If cache is nil, likely ENOMEM: return immediately }
        if ossl_policy_cache_set(x) = nil  then
            Exit(X509_PCY_TREE_INTERNAL);
    end;
    {
     * At this point check for invalid policies and required explicit policy.
     * Note that the explicit_policy counter is a count-down to zero, with the
     * requirement kicking in if and once it does that.  The counter is
     * decremented for every non-self-issued certificate in the path, but may
     * be further reduced by policy constraints in a non-leaf certificate.
     *
     * The ultimate policy set is the intersection of all the policies along
     * the path, if we hit a certificate with an empty policy set, and explicit
     * policy is required we're done.
     }
    i := n - 1;
    while (i >= 0)  and ( (explicit_policy > 0)  or  (ret and X509_PCY_TREE_EMPTY = 0) ) do

    begin
        x := sk_X509_value(certs, i);
        ex_flags := X509_get_extension_flags(x);
        { All the policies are already cached, we can return early }
        if ex_flags and EXFLAG_INVALID_POLICY > 0 then
           Exit(X509_PCY_TREE_INVALID);
        { Access the cache which we now know exists }
        cache := ossl_policy_cache_set(x);
        if (ret and X509_PCY_TREE_VALID > 0)  and  (cache.data = nil) then
            ret := X509_PCY_TREE_EMPTY;
        if explicit_policy > 0 then
        begin
            if 0>=(ex_flags and EXFLAG_SI) then
                Dec(explicit_policy);
            if (cache.explicit_skip >= 0) and  (cache.explicit_skip < explicit_policy) then
                explicit_policy := cache.explicit_skip;
        end;
        Dec(i);
    end;
    if explicit_policy = 0 then
       ret  := ret  or X509_PCY_TREE_EXPLICIT;
    if ret and X509_PCY_TREE_VALID = 0 then
        Exit(ret);
    { If we get this far initialize the tree }
    tree := OPENSSL_zalloc(sizeof(tree^));
    if tree = nil then
    begin
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(X509_PCY_TREE_INTERNAL);
    end;
    {
     * http://tools.ietf.org/html/rfc5280#section-6.1.2, figure 3.
     *
     * The top level is implicitly for the trust anchor with valid expected
     * policies of anyPolicy.  (RFC 5280 has the TA at depth 0 and the leaf at
     * depth n, we have the leaf at depth 0 and the TA at depth n).
     }
    tree.levels := OPENSSL_zalloc(sizeof(tree.levels^) *(n+1));
    if tree.levels = nil then
    begin
        OPENSSL_free(tree);
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        Exit(X509_PCY_TREE_INTERNAL);
    end;
    tree.nlevel := n+1;
    level := tree.levels;
    data := ossl_policy_data_new(nil, OBJ_nid2obj(NID_any_policy) , 0);
    if (data = nil) then
        goto _bad_tree;
    if ossl_policy_level_add_node(level, data, nil, tree) = nil  then
    begin
        ossl_policy_data_free(data);
        goto _bad_tree;
    end;
    {
     * In this pass initialize all the tree levels and whether anyPolicy and
     * policy mapping are inhibited at each level.
     }
    for i := n - 1 downto 0 do
    begin
        x := sk_X509_value(certs, i);
        ex_flags := X509_get_extension_flags(x);
        { Access the cache which we now know exists }
        cache := ossl_policy_cache_set(x);
        X509_up_ref(x);
        Inc(level);
        level.cert := x;
        if nil =cache.anyPolicy then
           level.flags  := level.flags  or X509_V_FLAG_INHIBIT_ANY;
        { Determine inhibit any and inhibit map flags }
        if any_skip = 0 then
        begin
            {
             * Any matching allowed only if certificate is self issued and not
             * the last in the chain.
             }
            if (0>=ex_flags and EXFLAG_SI)  or  (i = 0) then
                level.flags  := level.flags  or X509_V_FLAG_INHIBIT_ANY;
        end
        else
        begin
            if 0>=(ex_flags and EXFLAG_SI) then
                Dec(any_skip);
            if (cache.any_skip >= 0)  and  (cache.any_skip < any_skip) then
                any_skip := cache.any_skip;
        end;
        if map_skip = 0 then
           level.flags  := level.flags  or X509_V_FLAG_INHIBIT_MAP
        else
        begin
            if 0>=(ex_flags and EXFLAG_SI) then
                PostDec(map_skip);
            if (cache.map_skip >= 0) and  (cache.map_skip < map_skip) then
                map_skip := cache.map_skip;
        end;
    end;
    ptree^ := tree;
    Exit(ret);
 _bad_tree:
    X509_policy_tree_free(tree);
    Result := X509_PCY_TREE_INTERNAL;
end;



function X509_policy_check( ptree : PPX509_POLICY_TREE; pexplicit_policy : PInteger; certs: Pstack_st_X509 ; policy_oids : Pstack_st_ASN1_OBJECT; flags : uint32):integer;
var
  init_ret,
  ret,
  calc_ret   : integer;
  tree       : PX509_POLICY_TREE;
  nodes,
  auth_nodes : Pstack_st_X509_POLICY_NODE;
  label _error;
begin
    tree := nil;
    auth_nodes := nil;
    ptree^ := nil;
    pexplicit_policy^ := 0;
    init_ret := tree_init(@tree, certs, flags);
    if init_ret <= 0 then
       Exit(init_ret);
    if init_ret and X509_PCY_TREE_EXPLICIT = 0 then
    begin
        if init_ret and X509_PCY_TREE_EMPTY > 0 then
        begin
            X509_policy_tree_free(tree);
            Exit(X509_PCY_TREE_VALID);
        end;
    end
    else
    begin
        pexplicit_policy^ := 1;
        { Tree empty and requireExplicit True: Error }
        if init_ret and X509_PCY_TREE_EMPTY > 0 then
           Exit(X509_PCY_TREE_FAILURE);
    end;
    ret := tree_evaluate(tree);
    //TREE_PRINT('tree_evaluate', tree, nil);
    if ret <= 0 then goto _error;
    if ret = X509_PCY_TREE_EMPTY then
    begin
        X509_policy_tree_free(tree);
        if init_ret and X509_PCY_TREE_EXPLICIT > 0 then
           Exit(X509_PCY_TREE_FAILURE);
        Exit(X509_PCY_TREE_VALID);
    end;
    { Tree is not empty: continue }
    calc_ret := tree_calculate_authority_set(tree, @auth_nodes);
    if calc_ret = 0 then
        goto _error;
    ret := tree_calculate_user_set(tree, policy_oids, auth_nodes);
    if calc_ret = TREE_CALC_OK_DOFREE then
       sk_X509_POLICY_NODE_free(auth_nodes);
    if 0>=ret then
       goto _error;
    ptree^ := tree;
    if init_ret and X509_PCY_TREE_EXPLICIT > 0 then
    begin
        nodes := X509_policy_tree_get0_user_policies(tree);
        if sk_X509_POLICY_NODE_num(nodes) <= 0  then
            Exit(X509_PCY_TREE_FAILURE);
    end;
    Exit(X509_PCY_TREE_VALID);
 _error:
    X509_policy_tree_free(tree);
    Result := X509_PCY_TREE_INTERNAL;
end;



end.
