struct stack_st_OSSL_DECODER;
 typedef int (*sk_OSSL_DECODER_compfunc)(const OSSL_DECODER * const *a, const OSSL_DECODER *const *b);
 typedef void (*sk_OSSL_DECODER_freefunc)(OSSL_DECODER *a);
 typedef OSSL_DECODER * (*sk_OSSL_DECODER_copyfunc)(const OSSL_DECODER *a);
  
 
  
 struct stack_st_OSSL_DECODER *sk_OSSL_DECODER_new(sk_OSSL_DECODER_compfunc compare) 
{ return (struct stack_st_OSSL_DECODER *)OPENSSL_sk_new((OPENSSL_sk_compfunc)compare);
 }  
 
 
 struct stack_st_OSSL_DECODER *sk_OSSL_DECODER_new_reserve(sk_OSSL_DECODER_compfunc compare, int n) 
{ return (struct stack_st_OSSL_DECODER *)OPENSSL_sk_new_reserve((OPENSSL_sk_compfunc)compare, n);
 }  
 
 int sk_OSSL_DECODER_reserve(struct stack_st_OSSL_DECODER *sk, int n) 
{ return OPENSSL_sk_reserve((OPENSSL_STACK *)sk, n);
 }  
 
 void sk_OSSL_DECODER_free(struct stack_st_OSSL_DECODER *sk) 
{ OPENSSL_sk_free((OPENSSL_STACK *)sk);
 }  
 
 void sk_OSSL_DECODER_zero(struct stack_st_OSSL_DECODER *sk) 
{ OPENSSL_sk_zero((OPENSSL_STACK *)sk);
 }  
 
 OSSL_DECODER *sk_OSSL_DECODER_delete(struct stack_st_OSSL_DECODER *sk, int i) 
{ return (OSSL_DECODER *)OPENSSL_sk_delete((OPENSSL_STACK *)sk, i);
 }  
 
 OSSL_DECODER *sk_OSSL_DECODER_delete_ptr(struct stack_st_OSSL_DECODER *sk, OSSL_DECODER *ptr) 
{ return (OSSL_DECODER *)OPENSSL_sk_delete_ptr((OPENSSL_STACK *)sk, (const void *)ptr);
 }  
 
 
 
 int sk_OSSL_DECODER_unshift(struct stack_st_OSSL_DECODER *sk, OSSL_DECODER *ptr) 
{ return OPENSSL_sk_unshift((OPENSSL_STACK *)sk, (const void *)ptr);
 }  
 
 OSSL_DECODER *sk_OSSL_DECODER_pop(struct stack_st_OSSL_DECODER *sk) 
{ return (OSSL_DECODER *)OPENSSL_sk_pop((OPENSSL_STACK *)sk);
 }  
 
 OSSL_DECODER *sk_OSSL_DECODER_shift(struct stack_st_OSSL_DECODER *sk) 
{ return (OSSL_DECODER *)OPENSSL_sk_shift((OPENSSL_STACK *)sk);
 }  
 
 
 
 int sk_OSSL_DECODER_insert(struct stack_st_OSSL_DECODER *sk, OSSL_DECODER *ptr, int idx) 
{ return OPENSSL_sk_insert((OPENSSL_STACK *)sk, (const void *)ptr, idx);
 }  OSSL_DECODER *sk_OSSL_DECODER_set(struct stack_st_OSSL_DECODER *sk, int idx, OSSL_DECODER *ptr) 
{ return (OSSL_DECODER *)OPENSSL_sk_set((OPENSSL_STACK *)sk, idx, (const void *)ptr);
 }  int sk_OSSL_DECODER_find(struct stack_st_OSSL_DECODER *sk, OSSL_DECODER *ptr) 
{ return OPENSSL_sk_find((OPENSSL_STACK *)sk, (const void *)ptr);
 }  int sk_OSSL_DECODER_find_ex(struct stack_st_OSSL_DECODER *sk, OSSL_DECODER *ptr) 
{ return OPENSSL_sk_find_ex((OPENSSL_STACK *)sk, (const void *)ptr);
 }  int sk_OSSL_DECODER_find_all(struct stack_st_OSSL_DECODER *sk, OSSL_DECODER *ptr, int *pnum) 
{ return OPENSSL_sk_find_all((OPENSSL_STACK *)sk, (const void *)ptr, pnum);
 }  void sk_OSSL_DECODER_sort(struct stack_st_OSSL_DECODER *sk) 
{ OPENSSL_sk_sort((OPENSSL_STACK *)sk);
 }  int sk_OSSL_DECODER_is_sorted(const struct stack_st_OSSL_DECODER *sk) 
{ return OPENSSL_sk_is_sorted((const OPENSSL_STACK *)sk);
 }  struct stack_st_OSSL_DECODER * sk_OSSL_DECODER_dup(const struct stack_st_OSSL_DECODER *sk) 
{ return (struct stack_st_OSSL_DECODER *)OPENSSL_sk_dup((const OPENSSL_STACK *)sk);
 }  struct stack_st_OSSL_DECODER *sk_OSSL_DECODER_deep_copy(const struct stack_st_OSSL_DECODER *sk, sk_OSSL_DECODER_copyfunc copyfunc, sk_OSSL_DECODER_freefunc freefunc) 
{ return (struct stack_st_OSSL_DECODER *)OPENSSL_sk_deep_copy((const OPENSSL_STACK *)sk, (OPENSSL_sk_copyfunc)copyfunc, (OPENSSL_sk_freefunc)freefunc);
 }  sk_OSSL_DECODER_compfunc sk_OSSL_DECODER_set_cmp_func(struct stack_st_OSSL_DECODER *sk, sk_OSSL_DECODER_compfunc compare) 
{ return (sk_OSSL_DECODER_compfunc)OPENSSL_sk_set_cmp_func((OPENSSL_STACK *)sk, (OPENSSL_sk_compfunc)compare);
 }
