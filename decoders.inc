
#ifndef OPENSSL_NO_DH
DECODER_w_structure("DH", der, PrivateKeyInfo, dh, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DH", der, SubjectPublicKeyInfo, dh, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DH", der, type_specific_params, dh, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DH", der, DH, dh, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DHX", der, PrivateKeyInfo, dhx, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DHX", der, SubjectPublicKeyInfo, dhx, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DHX", der, type_specific_params, dhx, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DHX", der, DHX, dhx, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
#endif
#ifndef OPENSSL_NO_DSA
DECODER_w_structure("DSA", der, PrivateKeyInfo, dsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DSA", der, SubjectPublicKeyInfo, dsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DSA", der, type_specific, dsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DSA", der, DSA, dsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER("DSA", msblob, dsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER("DSA", pvk, dsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
#endif
#ifndef OPENSSL_NO_EC
DECODER_w_structure("EC", der, PrivateKeyInfo, ec, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("EC", der, SubjectPublicKeyInfo, ec, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("EC", der, type_specific_no_pub, ec, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("EC", der, EC, ec, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("ED25519", der, PrivateKeyInfo, ed25519, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("ED25519", der, SubjectPublicKeyInfo, ed25519, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("ED448", der, PrivateKeyInfo, ed448, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("ED448", der, SubjectPublicKeyInfo, ed448, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("X25519", der, PrivateKeyInfo, x25519, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("X25519", der, SubjectPublicKeyInfo, x25519, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("X448", der, PrivateKeyInfo, x448, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("X448", der, SubjectPublicKeyInfo, x448, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
# ifndef OPENSSL_NO_SM2
DECODER_w_structure("SM2", der, PrivateKeyInfo, sm2, no),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("SM2", der, SubjectPublicKeyInfo, sm2, no),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
# endif
#endif
DECODER_w_structure("RSA", der, PrivateKeyInfo, rsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("RSA", der, SubjectPublicKeyInfo, rsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("RSA", der, type_specific_keypair, rsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("RSA", der, RSA, rsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("RSA-PSS", der, PrivateKeyInfo, rsapss, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("RSA-PSS", der, SubjectPublicKeyInfo, rsapss, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER("RSA", msblob, rsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input';   
  _implementation:@ossl_##_input_to_##_output_decoder_functions 
),
DECODER("RSA", pvk, rsa, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input';   
  _implementation:@ossl_##_input_to_##_output_decoder_functions 
),

DECODER_w_structure("DER", der, SubjectPublicKeyInfo, der, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),
DECODER("DER", pem, der, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input';   
  _implementation:@ossl_##_input_to_##_output_decoder_functions 
),
DECODER_w_structure("DER", der, EncryptedPrivateKeyInfo, der, yes),
( algorithm_names: _name;                                                            
  property_definition: 'provider=default,fips= #_fips ,input= #_input ,structure=' + DECODER_STRUCTURE_##_structure;                     
  _implementation:@ossl_##_structure_##_input_to_##_output_decoder_functions 
),