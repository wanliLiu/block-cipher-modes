/*
 * Block Cipher Modes of Operation
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 *
 */
/*
 * Advanced Encryption Standard
 * @author Dani Huertas
 * @email huertas.dani@gmail.com
 * @repo https://github.com/dhuertas/AES
 *
 * Based on the document FIPS PUB 197
 */
#include "aes.h"
#include "gmult.h"
#include "block-cipher.h"

/*
 * Addition in GF(2^8)
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
uint8_t gadd(uint8_t a, uint8_t b) {
  return a^b;
}

/*
 * Subtraction in GF(2^8)
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 */
uint8_t gsub(uint8_t a, uint8_t b) {
  return a^b;
}

/*
 * Addition of 4 byte words
 * m(x) = x4+1
 */
void coef_add(uint8_t a[], uint8_t b[], uint8_t d[]) {

  *(uint32_t *)d = *(uint32_t *)a ^ *(uint32_t *)b;
}

/*
 * Multiplication of 4 byte words
 * m(x) = x4+1
 */
void coef_mult(uint8_t *a, uint8_t *b, uint8_t *d) {

  d[0] = gmult(a[0],b[0])^gmult(a[3],b[1])^gmult(a[2],b[2])^gmult(a[1],b[3]);
  d[1] = gmult(a[1],b[0])^gmult(a[0],b[1])^gmult(a[3],b[2])^gmult(a[2],b[3]);
  d[2] = gmult(a[2],b[0])^gmult(a[1],b[1])^gmult(a[0],b[2])^gmult(a[3],b[3]);
  d[3] = gmult(a[3],b[0])^gmult(a[2],b[1])^gmult(a[1],b[2])^gmult(a[0],b[3]);
}

/*
 * Number of columns (32-bit words) comprising the State. For this 
 * standard, Nb = 4.
 */
static int Nb = 4;

/*
 * Number of 32-bit words comprising the Cipher Key. For this 
 * standard, Nk = 4, 6, or 8.
 */
static int Nk;

/*
 * Number of rounds, which is a function of  Nk  and  Nb (which is 
 * fixed). For this standard, Nr = 10, 12, or 14.
 */
static int Nr;

/*
 * S-box transformation table
 */
static uint8_t s_box[256] = {
  // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // a
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // b
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // c
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // d
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // e
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};// f

/*
 * Inverse S-box transformation table
 */
static uint8_t inv_s_box[256] = {
  // 0     1     2     3     4     5     6     7     8     9     a     b     c     d     e     f
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // a
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // b
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // c
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // d
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // e
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};// f


/*
 * Generates the round constant Rcon[i]
 */
static uint8_t R[] = {0x02, 0x00, 0x00, 0x00};
 
uint8_t * Rcon(uint8_t i) {
  
  if (i == 1) {
    R[0] = 0x01; // x^(1-1) = x^0 = 1
  } else if (i > 1) {
    R[0] = 0x02;
    i--;
    while (i-1 > 0) {
      R[0] = gmult(R[0], 0x02);
      i--;
    }
  }
  
  return R;
}

/*
 * Transformation in the Cipher and Inverse Cipher in which a Round 
 * Key is added to the State using an XOR operation. The length of a 
 * Round Key equals the size of the State (i.e., for Nb = 4, the Round 
 * Key length equals 128 bits/16 bytes).
 */
void add_round_key(uint8_t *state, uint8_t *w, uint8_t r) {
  
  uint8_t c;
  
  for (c = 0; c < Nb; c++) {
    state[Nb*0+c] = state[Nb*0+c]^w[4*Nb*r+4*c+0];   //debug, so it works for Nb !=4 
    state[Nb*1+c] = state[Nb*1+c]^w[4*Nb*r+4*c+1];
    state[Nb*2+c] = state[Nb*2+c]^w[4*Nb*r+4*c+2];
    state[Nb*3+c] = state[Nb*3+c]^w[4*Nb*r+4*c+3];  
  }
}

/*
 * Transformation in the Cipher that takes all of the columns of the 
 * State and mixes their data (independently of one another) to 
 * produce new columns.
 */
void mix_columns(uint8_t *state) {

  uint8_t a[] = {0x02, 0x01, 0x01, 0x03}; // a(x) = {02} + {01}x + {01}x2 + {03}x3
  uint8_t i, j, col[4], res[4];

  for (j = 0; j < Nb; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[Nb*i+j];
    }

    coef_mult(a, col, res);

    for (i = 0; i < 4; i++) {
      state[Nb*i+j] = res[i];
    }
  }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * MixColumns().
 */
void inv_mix_columns(uint8_t *state) {

  uint8_t a[] = {0x0e, 0x09, 0x0d, 0x0b}; // a(x) = {0e} + {09}x + {0d}x2 + {0b}x3
  uint8_t i, j, col[4], res[4];

  for (j = 0; j < Nb; j++) {
    for (i = 0; i < 4; i++) {
      col[i] = state[Nb*i+j];
    }

    coef_mult(a, col, res);

    for (i = 0; i < 4; i++) {
      state[Nb*i+j] = res[i];
    }
  }
}

/*
 * Transformation in the Cipher that processes the State by cyclically 
 * shifting the last three rows of the State by different offsets. 
 */
void shift_rows(uint8_t *state) {

  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    // shift(1,4)=1; shift(2,4)=2; shift(3,4)=3
    // shift(r, 4) = r;
    s = 0;
    while (s < i) {
      tmp = state[Nb*i+0];
      
      for (k = 1; k < Nb; k++) {
        state[Nb*i+k-1] = state[Nb*i+k];
      }

      state[Nb*i+Nb-1] = tmp;
      s++;
    }
  }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * ShiftRows().
 */
void inv_shift_rows(uint8_t *state) {

  uint8_t i, k, s, tmp;

  for (i = 1; i < 4; i++) {
    s = 0;
    while (s < i) {
      tmp = state[Nb*i+Nb-1];
      
      for (k = Nb-1; k > 0; k--) {
        state[Nb*i+k] = state[Nb*i+k-1];
      }

      state[Nb*i+0] = tmp;
      s++;
    }
  }
}

/*
 * Transformation in the Cipher that processes the State using a non­
 * linear byte substitution table (S-box) that operates on each of the 
 * State bytes independently. 
 */
void sub_bytes(uint8_t *state) {

  uint8_t i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[Nb*i+j] = s_box[16*((state[Nb*i+j] & 0xf0) >> 4) + (state[Nb*i+j] & 0x0f)];
    }
  }
}

/*
 * Transformation in the Inverse Cipher that is the inverse of 
 * SubBytes().
 */
void inv_sub_bytes(uint8_t *state) {

  uint8_t i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < Nb; j++) {
      state[Nb*i+j] = inv_s_box[16*((state[Nb*i+j] & 0xf0) >> 4) + (state[Nb*i+j] & 0x0f)];
    }
  }
}

/*
 * Function used in the Key Expansion routine that takes a four-byte 
 * input word and applies an S-box to each of the four bytes to 
 * produce an output word.
 */
void sub_word(uint8_t *w) {

  uint8_t i;

  for (i = 0; i < 4; i++) {
    w[i] = s_box[16*((w[i] & 0xf0) >> 4) + (w[i] & 0x0f)];
  }
}

/*
 * Function used in the Key Expansion routine that takes a four-byte 
 * word and performs a cyclic permutation. 
 */
void rot_word(uint8_t *w) {

  uint8_t tmp;

  tmp = w[0];
  w[0] = w[1];
  w[1] = w[2];
  w[2] = w[3];
  w[3] = tmp;
}

/*
 * Key Expansion
 */
void aes_key_expansion(uint8_t *key, uint8_t *w) {

  uint8_t tmp[4];
  uint8_t i;
  uint8_t len = Nb*(Nr+1);

  for (i = 0; i < Nk; i++) {
    memcpy(&w[4*i], &key[4*i], 4);
  }

  for (i = Nk; i < len; i++) {
    memcpy(tmp, &w[4*(i-1)], 4);

    if (i%Nk == 0) {

      rot_word(tmp);
      sub_word(tmp);
      coef_add(tmp, Rcon(i/Nk), tmp);

    } else if (Nk > 6 && i%Nk == 4) {

      sub_word(tmp);

    }

    w[4*i+0] = w[4*(i-Nk)+0]^tmp[0];
    w[4*i+1] = w[4*(i-Nk)+1]^tmp[1];
    w[4*i+2] = w[4*(i-Nk)+2]^tmp[2];
    w[4*i+3] = w[4*(i-Nk)+3]^tmp[3];
  }
}

/*
 * Initialize AES variables and allocate memory for expanded key
 */
uint8_t *aes_init(size_t key_size) {

    switch (key_size) {
    default:
    case 16: Nk = 4; Nr = 10; break;
    case 24: Nk = 6; Nr = 12; break;
    case 32: Nk = 8; Nr = 14; break;
  }

  return malloc(Nb*(Nr+1)*4);
}

/*
 * Transpose regular input array to State
 */
void transpose_in(uint8_t *in, uint8_t *s) {

  if (Nb == 4) {
    // Unrolled transposition for Nb == 4
    s[0] = in[0];  s[4] = in[1];  s[8]  = in[2];  s[12] = in[3];
    s[1] = in[4];  s[5] = in[5];  s[9]  = in[6];  s[13] = in[7];
    s[2] = in[8];  s[6] = in[9];  s[10] = in[10]; s[14] = in[11];
    s[3] = in[12]; s[7] = in[13]; s[11] = in[14]; s[15] = in[15];
  } else {  
    uint8_t i = 0, j = 0;
    for ( ; i < 4; i++) {
      for (j = 0; j < Nb; j++) {
        s[Nb*i+j] = in[i+4*j];
      }
    }
  }
}

/*
 * Transpose State back to regular output array
 */
void transpose_out(uint8_t *out, uint8_t *s) {

  if (Nb == 4) {
    // Unrolled transposition for Nb == 4
    out[0]  = s[0]; out[1]  = s[4]; out[2]  = s[8];  out[3]  = s[12];
    out[4]  = s[1]; out[5]  = s[5]; out[6]  = s[9];  out[7]  = s[13];
    out[8]  = s[2]; out[9]  = s[6]; out[10] = s[10]; out[11] = s[14];
    out[12] = s[3]; out[13] = s[7]; out[14] = s[11]; out[15] = s[15];
  } else {
    uint8_t i = 0, j = 0;
    for ( ; i < 4; i++) {
      for (j = 0; j < Nb; j++) {
        out[i+4*j] = s[Nb*i+j];
      }
    }
  }
}

/*
 * Performs the AES cipher operation
 */
void aes_cipher(uint8_t *in, uint8_t *out, uint8_t *w) {

  uint8_t state[4*Nb];
  uint8_t r;

  transpose_in(in, state);

  add_round_key(state, w, 0);

  for (r = 1; r < Nr; r++) {
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, w, r);
  }

  sub_bytes(state);
  shift_rows(state);
    // Using T-boxes:
  printf("\n");
  for (int i = 0; i < 16; i++){
    printf("%.2x", state[i]);
  }
  add_round_key(state, w, Nr);

  transpose_out(out, state);
}

/*
 * Performs the AES inverse cipher operation
 */
void aes_inv_cipher(uint8_t *in, uint8_t *out, uint8_t *w) {

  uint8_t state[4*Nb];
  uint8_t r;

  transpose_in(in, state);

  add_round_key(state, w, Nr);

  for (r = Nr-1; r >= 1; r--) {
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, w, r);
    inv_mix_columns(state);
  }

  inv_shift_rows(state);
  inv_sub_bytes(state);
  printf("\n");
  for (int i = 0; i < 16; i++){
    printf("%.2x", state[i]);
  }
  add_round_key(state, w, 0);

  transpose_out(out, state);
}

/*
 * Block cipher wrapper
 */
void aes(uint8_t direction, uint8_t *in, uint8_t *out, uint8_t *key, size_t key_size) {

  switch (direction) {

    case ENCRYPT:
      aes_cipher(in, out, key);
      break;

    case DECRYPT:
      aes_inv_cipher(in, out, key);
      break;
  }
}
