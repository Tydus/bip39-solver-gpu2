

__kernel void int_to_address(
     ulong mnemonic_start_3,
     ulong mnemonic_start_2,
     ulong mnemonic_start_1,
     ulong mnemonic_start_0,
     __global uchar * target_mnemonic,
     __global uchar * found_mnemonic
) {
  ulong idx = get_global_id(0);

  ulong mnemonic_0 = mnemonic_start_0 + idx;
  ulong mnemonic_1 = mnemonic_start_1;
  ulong mnemonic_2 = mnemonic_start_2;
  ulong mnemonic_3 = mnemonic_start_3;

  uchar bytes[32];
  bytes[31] = (mnemonic_0      ) & 0xFF;
  bytes[30] = (mnemonic_0 >> 8 ) & 0xFF;
  bytes[29] = (mnemonic_0 >> 16) & 0xFF;
  bytes[28] = (mnemonic_0 >> 24) & 0xFF;
  bytes[27] = (mnemonic_0 >> 32) & 0xFF;
  bytes[26] = (mnemonic_0 >> 40) & 0xFF;
  bytes[25] = (mnemonic_0 >> 48) & 0xFF;
  bytes[24] = (mnemonic_0 >> 56) & 0xFF;
  
  bytes[23] = (mnemonic_1      ) & 0xFF;
  bytes[22] = (mnemonic_1 >> 8 ) & 0xFF;
  bytes[21] = (mnemonic_1 >> 16) & 0xFF;
  bytes[20] = (mnemonic_1 >> 24) & 0xFF;
  bytes[19] = (mnemonic_1 >> 32) & 0xFF;
  bytes[18] = (mnemonic_1 >> 40) & 0xFF;
  bytes[17] = (mnemonic_1 >> 48) & 0xFF;
  bytes[16] = (mnemonic_1 >> 56) & 0xFF;

  bytes[15] = (mnemonic_2      ) & 0xFF;
  bytes[14] = (mnemonic_2 >> 8 ) & 0xFF;
  bytes[13] = (mnemonic_2 >> 16) & 0xFF;
  bytes[12] = (mnemonic_2 >> 24) & 0xFF;
  bytes[11] = (mnemonic_2 >> 32) & 0xFF;
  bytes[10] = (mnemonic_2 >> 40) & 0xFF;
  bytes[9 ] = (mnemonic_2 >> 48) & 0xFF;
  bytes[8 ] = (mnemonic_2 >> 56) & 0xFF;
  
  bytes[7 ] = (mnemonic_3      ) & 0xFF;
  bytes[6 ] = (mnemonic_3 >> 8 ) & 0xFF;
  bytes[5 ] = (mnemonic_3 >> 16) & 0xFF;
  bytes[4 ] = (mnemonic_3 >> 24) & 0xFF;
  bytes[3 ] = (mnemonic_3 >> 32) & 0xFF;
  bytes[2 ] = (mnemonic_3 >> 40) & 0xFF;
  bytes[1 ] = (mnemonic_3 >> 48) & 0xFF;
  bytes[0 ] = (mnemonic_3 >> 56) & 0xFF;

  uchar mnemonic_hash[32];
  sha256(&bytes, 32, &mnemonic_hash);
  uchar checksum = mnemonic_hash[0];
  
  /* XXX: check alignment here!!! */
  ushort indices[24];
  indices[0 ] =  (mnemonic_3 >> 53) & 2047;
  indices[1 ] =  (mnemonic_3 >> 42) & 2047;
  indices[2 ] =  (mnemonic_3 >> 31) & 2047;
  indices[3 ] =  (mnemonic_3 >> 20) & 2047;
  indices[4 ] =  (mnemonic_3 >> 9 )  & 2047;
  indices[5 ] = ((mnemonic_3 & ((1 << 9)-1)) << 2) | ((mnemonic_2 >> 62) & 3);
  indices[6 ] =  (mnemonic_2 >> 51) & 2047;
  indices[7 ] =  (mnemonic_2 >> 40) & 2047;
  indices[8 ] =  (mnemonic_2 >> 29) & 2047;
  indices[9 ] =  (mnemonic_2 >> 18) & 2047;
  indices[10] =  (mnemonic_2 >> 7 ) & 2047;
  indices[11] = ((mnemonic_2 & ((1 << 7)-1)) << 4) | ((mnemonic_1 >> 60) & 15);

  indices[12] =  (mnemonic_1 >> 49) & 2047;
  indices[13] =  (mnemonic_1 >> 38) & 2047;
  indices[14] =  (mnemonic_1 >> 27) & 2047;
  indices[15] =  (mnemonic_1 >> 16) & 2047;
  indices[16] =  (mnemonic_1 >> 5 )  & 2047;
  indices[17] = ((mnemonic_1 & ((1 << 5)-1)) << 6) | ((mnemonic_0 >> 58) & 63);
  indices[18] =  (mnemonic_0 >> 47) & 2047;
  indices[19] =  (mnemonic_0 >> 36) & 2047;
  indices[20] =  (mnemonic_0 >> 25) & 2047;
  indices[21] =  (mnemonic_0 >> 14) & 2047;
  indices[22] =  (mnemonic_0 >> 3 ) & 2047;
  indices[23] = ((mnemonic_0 & ((1 << 3)-1)) << 8) | checksum;


  uchar mnemonic[360] = {0};
  uchar mnemonic_length = 23 +
    word_lengths[indices[0 ]] +
    word_lengths[indices[1 ]] +
    word_lengths[indices[2 ]] + 
    word_lengths[indices[3 ]] + 
    word_lengths[indices[4 ]] + 
    word_lengths[indices[5 ]] + 
    word_lengths[indices[6 ]] + 
    word_lengths[indices[7 ]] + 
    word_lengths[indices[8 ]] + 
    word_lengths[indices[9 ]] + 
    word_lengths[indices[10]] + 
    word_lengths[indices[11]] +
    word_lengths[indices[12]] +
    word_lengths[indices[13]] +
    word_lengths[indices[14]] + 
    word_lengths[indices[15]] + 
    word_lengths[indices[16]] + 
    word_lengths[indices[17]] + 
    word_lengths[indices[18]] + 
    word_lengths[indices[19]] + 
    word_lengths[indices[20]] + 
    word_lengths[indices[21]] + 
    word_lengths[indices[22]] + 
    word_lengths[indices[23]];

  int mnemonic_index = 0;
  
  for (int i=0; i < 24; i++) {
    int word_index = indices[i];
    int word_length = word_lengths[word_index];
    
    for(int j=0;j<word_length;j++) {
      mnemonic[mnemonic_index] = words[word_index][j];
      mnemonic_index++;
    }
    mnemonic[mnemonic_index] = 32;
    mnemonic_index++;
  }
  mnemonic[mnemonic_index - 1] = 0;
  mnemonic[mnemonic_index] = 0;

  /* if mnemonic length > 128 mnemonic = sha512(mnemonic)*/
  uchar mnemonic_tmp[128] = {0}, *mnemonic_result;
  if(mnemonic_length > 128) {
    sha512(&mnemonic, mnemonic_length, &mnemonic_tmp);
    mnemonic_result = mnemonic_tmp;
    mnemonic_length = 128;
  } else {
    mnemonic_result = mnemonic;
  }

  uchar ipad_key[128];
  uchar opad_key[128];
  for(int x=0;x<128;x++){
    ipad_key[x] = 0x36;
    opad_key[x] = 0x5c;
  }

  for(int x=0;x<mnemonic_length;x++){
    ipad_key[x] = ipad_key[x] ^ mnemonic_result[x];
    opad_key[x] = opad_key[x] ^ mnemonic_result[x];
  }

  uchar seed[64] = { 0 };
  uchar sha512_result[64] = { 0 };
  uchar key_previous_concat[256] = { 0 };
  uchar salt[12] = { 109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1 };
  for(int x=0;x<128;x++){
    key_previous_concat[x] = ipad_key[x];
  }
  for(int x=0;x<12;x++){
    key_previous_concat[x+128] = salt[x];
  }

  sha512(&key_previous_concat, 140, &sha512_result);
  copy_pad_previous(&opad_key, &sha512_result, &key_previous_concat);
  sha512(&key_previous_concat, 192, &sha512_result);
  xor_seed_with_round(&seed, &sha512_result);

  for(int x=1;x<2048;x++){
    copy_pad_previous(&ipad_key, &sha512_result, &key_previous_concat);
    sha512(&key_previous_concat, 192, &sha512_result);
    copy_pad_previous(&opad_key, &sha512_result, &key_previous_concat);
    sha512(&key_previous_concat, 192, &sha512_result);
    xor_seed_with_round(&seed, &sha512_result);
  }

  uchar network = BITCOIN_MAINNET;
  extended_private_key_t master_private;
  extended_public_key_t master_public;

  /* print_seed(seed); */

  new_master_from_seed(network, &seed, &master_private);
  public_from_private(&master_private, &master_public);

  uchar serialized_master_public[33];
  serialized_public_key(&master_public, &serialized_master_public);
  extended_private_key_t target_key;
  extended_public_key_t target_public_key;
  hardened_private_child_from_private(&master_private, &target_key, 44);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  public_from_private(&target_key, &target_public_key);

  uchar hash160_address[20] = {0};
  hash160_for_public_key(&target_public_key, &hash160_address);

  uchar target_address[20] = {0x75,0x9D,0x66,0x77,0x09,0x1E,0x97,0x3B,0x9E,0x9D,0x99,0xF1,0x9C,0x68,0xFB,0xF4,0x3E,0x3F,0x05};

  bool found_target = 1;
  for(int i=0;i<4;i++) {
    if(hash160_address[i] != target_address[i]){
      found_target = 0;
    }
  }

  if(found_target == 1) {
    printf("%s\n", mnemonic);
    //found_mnemonic[0] = 0x01;
    for(int i=0; i < mnemonic_index;i++) {
      target_mnemonic[i] = mnemonic[i];
    }
  }
}
