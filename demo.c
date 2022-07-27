#include "forkskinny64-cipher.h"
#include "forkskinny128-cipher.h"

#include <stdio.h>
#include <stdlib.h>

void print_block(uint8_t *block, unsigned int n) {
  for(unsigned int i=0; i<n; i++)
      printf("%02x", block[i]);
}

void demo_forkskinny_64_192() {
  uint8_t key[3*FORKSKINNY64_BLOCK_SIZE] = {0x29, 0xcd, 0xba, 0xab, 0xf2, 0xfb, 0xe3, 0x46, 0x7c, 0xc2, 0x54, 0xf8, 0x1b, 0xe8, 0xe7, 0x8d, 0x76, 0x5a, 0x2e, 0x63, 0x33, 0x9f, 0xc9, 0x9a};
  uint8_t message[FORKSKINNY64_BLOCK_SIZE] = {0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a, 0xec};

  // Pre-compute key schedule
  ForkSkinny64Key_t tk1, tk23;
  forkskinny_c_64_192_init_tk1(&tk1, key, FORKSKINNY64_MAX_ROUNDS);
  forkskinny_c_64_192_init_tk2_tk3(&tk23, key + FORKSKINNY64_BLOCK_SIZE, FORKSKINNY64_MAX_ROUNDS);

  // forward one leg
  uint8_t output_right_oneleg[FORKSKINNY64_BLOCK_SIZE];
  forkskinny_c_64_192_encrypt(&tk1, &tk23, NULL, output_right_oneleg, message);

  // forward both legs
  uint8_t output_left[FORKSKINNY64_BLOCK_SIZE];
  uint8_t output_right[FORKSKINNY64_BLOCK_SIZE];
  forkskinny_c_64_192_encrypt(&tk1, &tk23, output_left, output_right, message);

  // inverse one leg
  uint8_t inverse_message_oneleg[FORKSKINNY64_BLOCK_SIZE];
  forkskinny_c_64_192_decrypt(&tk1, &tk23, NULL, inverse_message_oneleg, output_right_oneleg);

  // inverse/output both legs
  uint8_t inverse_message[FORKSKINNY64_BLOCK_SIZE];
  uint8_t output_left2[FORKSKINNY64_BLOCK_SIZE];
  forkskinny_c_64_192_decrypt(&tk1, &tk23, output_left2, inverse_message, output_right);

  printf("Forkskinny-64-192 Forward s=0\n");
  printf("Tweakey: ");
  print_block(key, 3*FORKSKINNY64_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(message, FORKSKINNY64_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right_oneleg, FORKSKINNY64_BLOCK_SIZE);

  printf("\n\nForskinny-64-192 Forward s=b\n");
  printf("Tweakey: ");
  print_block(key, 3*FORKSKINNY64_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(message, FORKSKINNY64_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right, FORKSKINNY64_BLOCK_SIZE);
  printf("\nC1: ");
  print_block(output_left, FORKSKINNY64_BLOCK_SIZE);

  printf("\n\nForskinny-64-192 Inverse s=i\n");
  printf("Tweakey: ");
  print_block(key, 3*FORKSKINNY64_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right_oneleg, FORKSKINNY64_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(inverse_message_oneleg, FORKSKINNY64_BLOCK_SIZE);

  printf("\n\nForskinny-64-192 Inverse s=b\n");
  printf("Tweakey: ");
  print_block(key, 3*FORKSKINNY64_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right, FORKSKINNY64_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(inverse_message, FORKSKINNY64_BLOCK_SIZE);
  printf("\nC1: ");
  print_block(output_left2, FORKSKINNY64_BLOCK_SIZE);
  printf("\n");
}

void demo_forkskinny_128_256() {
  uint8_t key[2*FORKSKINNY128_BLOCK_SIZE] = {0x29, 0xcd, 0xba, 0xab, 0xf2, 0xfb, 0xe3, 0x46, 0x7c, 0xc2, 0x54, 0xf8, 0x1b, 0xe8, 0xe7, 0x8d, 0x76, 0x5a, 0x2e, 0x63, 0x33, 0x9f, 0xc9, 0x9a, 0x66, 0x32, 0x0d, 0xb7, 0x31, 0x58, 0x80, 0x01};
  uint8_t message[FORKSKINNY128_BLOCK_SIZE] = {0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a, 0xec, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  // Pre-compute key schedule
  ForkSkinny128Key_t tk1, tk2;
  forkskinny_c_128_256_init_tk1(&tk1, key, FORKSKINNY128_MAX_ROUNDS);
  forkskinny_c_128_256_init_tk2(&tk2, key + FORKSKINNY128_BLOCK_SIZE, FORKSKINNY128_MAX_ROUNDS);

  // forward one leg
  uint8_t output_right_oneleg[FORKSKINNY128_BLOCK_SIZE];
  forkskinny_c_128_256_encrypt(&tk1, &tk2, NULL, output_right_oneleg, message);

  // forward both legs
  uint8_t output_left[FORKSKINNY128_BLOCK_SIZE];
  uint8_t output_right[FORKSKINNY128_BLOCK_SIZE];
  forkskinny_c_128_256_encrypt(&tk1, &tk2, output_left, output_right, message);

  // inverse one leg
  uint8_t inverse_message_oneleg[FORKSKINNY128_BLOCK_SIZE];
  forkskinny_c_128_256_decrypt(&tk1, &tk2, NULL, inverse_message_oneleg, output_right_oneleg);

  // inverse/output both legs
  uint8_t inverse_message[FORKSKINNY128_BLOCK_SIZE];
  uint8_t output_left2[FORKSKINNY128_BLOCK_SIZE];
  forkskinny_c_128_256_decrypt(&tk1, &tk2, output_left2, inverse_message, output_right);

  printf("\nForkskinny-128-256 Forward s=0\n");
  printf("Tweakey: ");
  print_block(key, 2*FORKSKINNY128_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(message, FORKSKINNY128_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right_oneleg, FORKSKINNY128_BLOCK_SIZE);

  printf("\n\nForskinny-128-256 Forward s=b\n");
  printf("Tweakey: ");
  print_block(key, 2*FORKSKINNY128_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(message, FORKSKINNY128_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right, FORKSKINNY128_BLOCK_SIZE);
  printf("\nC1: ");
  print_block(output_left, FORKSKINNY128_BLOCK_SIZE);

  printf("\n\nForskinny-128-256 Inverse s=i\n");
  printf("Tweakey: ");
  print_block(key, 2*FORKSKINNY128_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right_oneleg, FORKSKINNY128_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(inverse_message_oneleg, FORKSKINNY128_BLOCK_SIZE);

  printf("\n\nForskinny-128-256 Inverse s=b\n");
  printf("Tweakey: ");
  print_block(key, 2*FORKSKINNY128_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right, FORKSKINNY128_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(inverse_message, FORKSKINNY128_BLOCK_SIZE);
  printf("\nC1: ");
  print_block(output_left2, FORKSKINNY128_BLOCK_SIZE);
  printf("\n");
}

void demo_forkskinny_128_384() {
  uint8_t key[3*FORKSKINNY128_BLOCK_SIZE] = {0x29, 0xcd, 0xba, 0xab, 0xf2, 0xfb, 0xe3, 0x46, 0x7c, 0xc2, 0x54, 0xf8, 0x1b, 0xe8, 0xe7, 0x8d, 0x76, 0x5a, 0x2e, 0x63, 0x33, 0x9f, 0xc9, 0x9a, 0x66, 0x32, 0x0d, 0xb7, 0x31, 0x58, 0x80, 0x01, 0x29, 0xcd, 0xba, 0xab, 0xf2, 0xfb, 0xe3, 0x46, 0x7c, 0xc2, 0x54, 0xf8, 0x1b, 0xe8, 0xe7, 0x8d};
  uint8_t message[FORKSKINNY128_BLOCK_SIZE] = {0x67, 0xc6, 0x69, 0x73, 0x51, 0xff, 0x4a, 0xec, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  // Pre-compute key schedule
  ForkSkinny128Key_t tk1, tk2, tk3;
  forkskinny_c_128_384_init_tk1(&tk1, key, FORKSKINNY128_MAX_ROUNDS);
  forkskinny_c_128_384_init_tk2(&tk2, key + FORKSKINNY128_BLOCK_SIZE, FORKSKINNY128_MAX_ROUNDS);
  forkskinny_c_128_384_init_tk3(&tk3, key + 2*FORKSKINNY128_BLOCK_SIZE, FORKSKINNY128_MAX_ROUNDS);

  // forward one leg
  uint8_t output_right_oneleg[FORKSKINNY128_BLOCK_SIZE];
  forkskinny_c_128_384_encrypt(&tk1, &tk2, &tk3, NULL, output_right_oneleg, message);

  // forward both legs
  uint8_t output_left[FORKSKINNY128_BLOCK_SIZE];
  uint8_t output_right[FORKSKINNY128_BLOCK_SIZE];
  forkskinny_c_128_384_encrypt(&tk1, &tk2, &tk3, output_left, output_right, message);

  // inverse one leg
  uint8_t inverse_message_oneleg[FORKSKINNY128_BLOCK_SIZE];
  forkskinny_c_128_384_decrypt(&tk1, &tk2, &tk3, NULL, inverse_message_oneleg, output_right_oneleg);

  // inverse/output both legs
  uint8_t inverse_message[FORKSKINNY128_BLOCK_SIZE];
  uint8_t output_left2[FORKSKINNY128_BLOCK_SIZE];
  forkskinny_c_128_384_decrypt(&tk1, &tk2, &tk3, output_left2, inverse_message, output_right);

  printf("\nForkskinny-128-384 Forward s=0\n");
  printf("Tweakey: ");
  print_block(key, 3*FORKSKINNY128_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(message, FORKSKINNY128_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right_oneleg, FORKSKINNY128_BLOCK_SIZE);

  printf("\n\nForskinny-128-384 Forward s=b\n");
  printf("Tweakey: ");
  print_block(key, 3*FORKSKINNY128_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(message, FORKSKINNY128_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right, FORKSKINNY128_BLOCK_SIZE);
  printf("\nC1: ");
  print_block(output_left, FORKSKINNY128_BLOCK_SIZE);

  printf("\n\nForskinny-128-384 Inverse s=i\n");
  printf("Tweakey: ");
  print_block(key, 3*FORKSKINNY128_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right_oneleg, FORKSKINNY128_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(inverse_message_oneleg, FORKSKINNY128_BLOCK_SIZE);

  printf("\n\nForskinny-128-384 Inverse s=b\n");
  printf("Tweakey: ");
  print_block(key, 3*FORKSKINNY128_BLOCK_SIZE);
  printf("\nC0: ");
  print_block(output_right, FORKSKINNY128_BLOCK_SIZE);
  printf("\nMessage: ");
  print_block(inverse_message, FORKSKINNY128_BLOCK_SIZE);
  printf("\nC1: ");
  print_block(output_left2, FORKSKINNY128_BLOCK_SIZE);
  printf("\n");
}

int main() {
  demo_forkskinny_64_192();

  demo_forkskinny_128_256();

  demo_forkskinny_128_384();
}
