#include "forkskinny128-cipher.h"
#include "forkskinny-internal.h"

#if SKINNY_64BIT

STATIC_INLINE uint64_t skinny128_LFSR2(uint64_t x)
{
    return ((x << 1) & 0xFEFEFEFEFEFEFEFEULL) ^
           (((x >> 7) ^ (x >> 5)) & 0x0101010101010101ULL);
}

STATIC_INLINE uint64_t skinny128_LFSR3(uint64_t x)
{
    return ((x >> 1) & 0x7F7F7F7F7F7F7F7FULL) ^
           (((x << 7) ^ (x << 1)) & 0x8080808080808080ULL);
}

#else

STATIC_INLINE uint32_t skinny128_LFSR2(uint32_t x)
{
    return ((x << 1) & 0xFEFEFEFEU) ^ (((x >> 7) ^ (x >> 5)) & 0x01010101U);
}

STATIC_INLINE uint32_t skinny128_LFSR3(uint32_t x)
{
    return ((x >> 1) & 0x7F7F7F7FU) ^ (((x << 7) ^ (x << 1)) & 0x80808080U);
}

#endif

STATIC_INLINE void skinny128_permute_tk(ForkSkinny128Cells_t *tk)
{
    /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */
#if SKINNY_64BIT && SKINNY_LITTLE_ENDIAN
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */
    uint64_t x = tk->lrow[1];
    uint64_t y;
    tk->lrow[1] = tk->lrow[0];
    y = x & 0xFF0000FF00FF00FFULL;
    tk->lrow[0] = (y << 16) | (y >> 48) |
                 ((x & 0x00000000FF000000ULL) << 32) |
                 ((x & 0x0000FF0000000000ULL) >> 16) |
                 ((x & 0x00FF00000000FF00ULL) >> 8);
#else
    uint32_t row2 = tk->row[2];
    uint32_t row3 = tk->row[3];
    tk->row[2] = tk->row[0];
    tk->row[3] = tk->row[1];
    row3 = (row3 << 16) | (row3 >> 16);
    tk->row[0] = ((row2 >>  8) & 0x000000FFU) |
                 ((row2 << 16) & 0x00FF0000U) |
                 ( row3        & 0xFF00FF00U);
    tk->row[1] = ((row2 >> 16) & 0x000000FFU) |
                  (row2        & 0xFF000000U) |
                 ((row3 <<  8) & 0x0000FF00U) |
                 ( row3        & 0x00FF0000U);
#endif
}

/* Initializes the key schedule with TK1 */
void forkskinny_c_128_256_init_tk1(ForkSkinny128Key_t *ks, const uint8_t *key, unsigned nb_rounds)
{
    ForkSkinny128Cells_t tk;
    unsigned index;

    /* Unpack the key and convert from little-endian to host-endian */
    tk.row[0] = READ_WORD32(key, 0);
    tk.row[1] = READ_WORD32(key, 4);
    tk.row[2] = READ_WORD32(key, 8);
    tk.row[3] = READ_WORD32(key, 12);

    /* Generate the key schedule words for all rounds */
    for (index = 0; index < nb_rounds; ++index) {
        /* Determine the subkey to use at this point in the key schedule */
        #if SKINNY_64BIT
          ks->schedule[index].lrow = tk.lrow[0];
        #else
          ks->schedule[index].row[0] = tk.row[0];
          ks->schedule[index].row[1] = tk.row[1];
        #endif
        /* Permute TK1 for the next round */
        skinny128_permute_tk(&tk);
    }
}

/* Initializes the key schedule with TK1 */
void forkskinny_c_128_384_init_tk1(ForkSkinny128Key_t *ks, const uint8_t *key, unsigned nb_rounds)
{
    ForkSkinny128Cells_t tk;
    unsigned index;

    /* Unpack the key and convert from little-endian to host-endian */
    tk.row[0] = READ_WORD32(key, 0);
    tk.row[1] = READ_WORD32(key, 4);
    tk.row[2] = READ_WORD32(key, 8);
    tk.row[3] = READ_WORD32(key, 12);

    /* Generate the key schedule words for all rounds */
    for (index = 0; index < nb_rounds; ++index) {
        /* Determine the subkey to use at this point in the key schedule */
        #if SKINNY_64BIT
          ks->schedule[index].lrow = tk.lrow[0];
        #else
          ks->schedule[index].row[0] = tk.row[0];
          ks->schedule[index].row[1] = tk.row[1];
        #endif
        /* Permute TK1 for the next round */
        skinny128_permute_tk(&tk);
    }
}

void forkskinny_c_128_256_init_tk2(ForkSkinny128Key_t *ks, const uint8_t *key, unsigned nb_rounds)
{
    ForkSkinny128Cells_t tk;
    unsigned index;

    /* Unpack the key and convert from little-endian to host-endian */
    tk.row[0] = READ_WORD32(key, 0);
    tk.row[1] = READ_WORD32(key, 4);
    tk.row[2] = READ_WORD32(key, 8);
    tk.row[3] = READ_WORD32(key, 12);

    /* Generate the key schedule words for all rounds */
    for (index = 0; index < nb_rounds; ++index) {
        /* Determine the subkey to use at this point in the key schedule */
        #if SKINNY_64BIT
          ks->schedule[index].lrow = tk.lrow[0];
        #else
          ks->schedule[index].row[0] = tk.row[0];
          ks->schedule[index].row[1] = tk.row[1];
        #endif

        /* XOR in the round constants for the first two rows.
           The round constants for the 3rd and 4th rows are
           fixed and will be applied during encrypt/decrypt */
        ks->schedule[index].row[0] ^= (RC[index] & 0x0F) ^ 0x00020000;
        ks->schedule[index].row[1] ^= (RC[index] >> 4);

        /* Permute TK2 for the next round */
        skinny128_permute_tk(&tk);

        /* Apply LFSR2 to the first two rows of TK2 */
        #if SKINNY_64BIT
          tk.lrow[0] = skinny128_LFSR2(tk.lrow[0]);
        #else
          tk.row[0] = skinny128_LFSR2(tk.row[0]);
          tk.row[1] = skinny128_LFSR2(tk.row[1]);
        #endif
    }
}

void forkskinny_c_128_384_init_tk2
    (ForkSkinny128Key_t *ks, const uint8_t *key, unsigned nb_rounds)
{
    ForkSkinny128Cells_t tk;
    unsigned index;
    // uint16_t word;

    /* Unpack the key and convert from little-endian to host-endian */
    tk.row[0] = READ_WORD32(key, 0);
    tk.row[1] = READ_WORD32(key, 4);
    tk.row[2] = READ_WORD32(key, 8);
    tk.row[3] = READ_WORD32(key, 12);

    /* Generate the key schedule words for all rounds */
    for (index = 0; index < nb_rounds; ++index) {
        /* Determine the subkey to use at this point in the key schedule */
        #if SKINNY_64BIT
          ks->schedule[index].lrow = tk.lrow[0];
        #else
          ks->schedule[index].row[0] = tk.row[0];
          ks->schedule[index].row[1] = tk.row[1];
        #endif
        /* Permute TK2 for the next round */
        skinny128_permute_tk(&tk);

        /* Apply LFSR2 to the first two rows of TK2 */
        #if SKINNY_64BIT
          tk.lrow[0] = skinny128_LFSR2(tk.lrow[0]);
        #else
          tk.row[0] = skinny128_LFSR2(tk.row[0]);
          tk.row[1] = skinny128_LFSR2(tk.row[1]);
        #endif
    }
}

void forkskinny_c_128_384_init_tk3(ForkSkinny128Key_t *ks, const uint8_t *key, unsigned nb_rounds)
{
    ForkSkinny128Cells_t tk;
    unsigned index;

    tk.row[0] = READ_WORD32(key, 0);
    tk.row[1] = READ_WORD32(key, 4);
    tk.row[2] = READ_WORD32(key, 8);
    tk.row[3] = READ_WORD32(key, 12);

    /* Generate the key schedule words for all rounds */
    for (index = 0; index < nb_rounds; ++index) {
        /* Determine the subkey to use at this point in the key schedule */
        #if SKINNY_64BIT
          ks->schedule[index].lrow = tk.lrow[0];
        #else
          ks->schedule[index].row[0] = tk.row[0];
          ks->schedule[index].row[1] = tk.row[1];
        #endif

        /* XOR in the round constants for the first two rows.
           The round constants for the 3rd and 4th rows are
           fixed and will be applied during encrypt/decrypt */
        ks->schedule[index].row[0] ^= (RC[index] & 0x0F) ^ 0x00020000;
        ks->schedule[index].row[1] ^= (RC[index] >> 4);

        /* Permute TK3 for the next round */
        skinny128_permute_tk(&tk);

        /* Apply LFSR3 to the first two rows of TK2 */
        #if SKINNY_64BIT
          tk.lrow[0] = skinny128_LFSR3(tk.lrow[0]);
        #else
          tk.row[0] = skinny128_LFSR3(tk.row[0]);
          tk.row[1] = skinny128_LFSR3(tk.row[1]);
        #endif
    }
}

STATIC_INLINE uint32_t skinny128_rotate_right(uint32_t x, unsigned count)
{
    /* Note: we are rotating the cells right, which actually moves
       the values up closer to the MSB.  That is, we do a left shift
       on the word to rotate the cells in the word right */
    return (x << count) | (x >> (32 - count));
}

#if SKINNY_64BIT

STATIC_INLINE uint64_t skinny128_sbox(uint64_t x)
{
    /* See 32-bit version below for a description of what is happening here */
    uint64_t y;
    x = ~x;
    x ^= (((x >> 2) & (x >> 3)) & 0x1111111111111111ULL);
    y  = (((x << 5) & (x << 1)) & 0x2020202020202020ULL);
    x ^= (((x << 5) & (x << 4)) & 0x4040404040404040ULL) ^ y;
    y  = (((x << 2) & (x << 1)) & 0x8080808080808080ULL);
    x ^= (((x >> 2) & (x << 1)) & 0x0202020202020202ULL) ^ y;
    y  = (((x >> 5) & (x << 1)) & 0x0404040404040404ULL);
    x ^= (((x >> 1) & (x >> 2)) & 0x0808080808080808ULL) ^ y;
    x = ~x;
    return ((x & 0x0808080808080808ULL) << 1) |
           ((x & 0x3232323232323232ULL) << 2) |
           ((x & 0x0101010101010101ULL) << 5) |
           ((x & 0x8080808080808080ULL) >> 6) |
           ((x & 0x4040404040404040ULL) >> 4) |
           ((x & 0x0404040404040404ULL) >> 2);
}

STATIC_INLINE uint64_t skinny128_inv_sbox(uint64_t x)
{
    /* See 32-bit version below for a description of what is happening here */
    uint64_t y;
    x = ~x;
    y  = (((x >> 1) & (x >> 3)) & 0x0101010101010101ULL);
    x ^= (((x >> 2) & (x >> 3)) & 0x1010101010101010ULL) ^ y;
    y  = (((x >> 6) & (x >> 1)) & 0x0202020202020202ULL);
    x ^= (((x >> 1) & (x >> 2)) & 0x0808080808080808ULL) ^ y;
    y  = (((x << 2) & (x << 1)) & 0x8080808080808080ULL);
    x ^= (((x >> 1) & (x << 2)) & 0x0404040404040404ULL) ^ y;
    y  = (((x << 5) & (x << 1)) & 0x2020202020202020ULL);
    x ^= (((x << 4) & (x << 5)) & 0x4040404040404040ULL) ^ y;
    x = ~x;
    return ((x & 0x0101010101010101ULL) << 2) |
           ((x & 0x0404040404040404ULL) << 4) |
           ((x & 0x0202020202020202ULL) << 6) |
           ((x & 0x2020202020202020ULL) >> 5) |
           ((x & 0xC8C8C8C8C8C8C8C8ULL) >> 2) |
           ((x & 0x1010101010101010ULL) >> 1);
}

#else

STATIC_INLINE uint32_t skinny128_sbox(uint32_t x)
{
    /* Original version from the specification is equivalent to:
     *
     * #define SBOX_MIX(x)
     *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
     * #define SBOX_SWAP(x)
     *     (((x) & 0xF9F9F9F9U) |
     *     (((x) >> 1) & 0x02020202U) |
     *     (((x) << 1) & 0x04040404U))
     * #define SBOX_PERMUTE(x)
     *     ((((x) & 0x01010101U) << 2) |
     *      (((x) & 0x06060606U) << 5) |
     *      (((x) & 0x20202020U) >> 5) |
     *      (((x) & 0xC8C8C8C8U) >> 2) |
     *      (((x) & 0x10101010U) >> 1))
     *
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * return SBOX_SWAP(x);
     *
     * However, we can mix the bits in their original positions and then
     * delay the SBOX_PERMUTE and SBOX_SWAP steps to be performed with one
     * final permuatation.  This reduces the number of shift operations.
     *
     * We can further reduce the number of NOT operations from 7 to 2
     * using the technique from https://github.com/kste/skinny_avx to
     * convert NOR-XOR operations into AND-XOR operations by converting
     * the S-box into its NOT-inverse.
     */
    uint32_t y;

    /* Mix the bits */
    x = ~x;
    x ^= (((x >> 2) & (x >> 3)) & 0x11111111U);
    y  = (((x << 5) & (x << 1)) & 0x20202020U);
    x ^= (((x << 5) & (x << 4)) & 0x40404040U) ^ y;
    y  = (((x << 2) & (x << 1)) & 0x80808080U);
    x ^= (((x >> 2) & (x << 1)) & 0x02020202U) ^ y;
    y  = (((x >> 5) & (x << 1)) & 0x04040404U);
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y;
    x = ~x;

    /* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [2 7 6 1 3 0 4 5] */
    return ((x & 0x08080808U) << 1) |
           ((x & 0x32323232U) << 2) |
           ((x & 0x01010101U) << 5) |
           ((x & 0x80808080U) >> 6) |
           ((x & 0x40404040U) >> 4) |
           ((x & 0x04040404U) >> 2);
}

STATIC_INLINE uint32_t skinny128_inv_sbox(uint32_t x)
{
    /* Original version from the specification is equivalent to:
     *
     * #define SBOX_MIX(x)
     *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
     * #define SBOX_SWAP(x)
     *     (((x) & 0xF9F9F9F9U) |
     *     (((x) >> 1) & 0x02020202U) |
     *     (((x) << 1) & 0x04040404U))
     * #define SBOX_PERMUTE_INV(x)
     *     ((((x) & 0x08080808U) << 1) |
     *      (((x) & 0x32323232U) << 2) |
     *      (((x) & 0x01010101U) << 5) |
     *      (((x) & 0xC0C0C0C0U) >> 5) |
     *      (((x) & 0x04040404U) >> 2))
     *
     * x = SBOX_SWAP(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * return SBOX_MIX(x);
     *
     * However, we can mix the bits in their original positions and then
     * delay the SBOX_PERMUTE_INV and SBOX_SWAP steps to be performed with one
     * final permuatation.  This reduces the number of shift operations.
     */
    uint32_t y;

    /* Mix the bits */
    x = ~x;
    y  = (((x >> 1) & (x >> 3)) & 0x01010101U);
    x ^= (((x >> 2) & (x >> 3)) & 0x10101010U) ^ y;
    y  = (((x >> 6) & (x >> 1)) & 0x02020202U);
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y;
    y  = (((x << 2) & (x << 1)) & 0x80808080U);
    x ^= (((x >> 1) & (x << 2)) & 0x04040404U) ^ y;
    y  = (((x << 5) & (x << 1)) & 0x20202020U);
    x ^= (((x << 4) & (x << 5)) & 0x40404040U) ^ y;
    x = ~x;

    /* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [5 3 0 4 6 7 2 1] */
    return ((x & 0x01010101U) << 2) |
           ((x & 0x04040404U) << 4) |
           ((x & 0x02020202U) << 6) |
           ((x & 0x20202020U) >> 5) |
           ((x & 0xC8C8C8C8U) >> 2) |
           ((x & 0x10101010U) >> 1);
}

#endif

static ForkSkinny128Cells_t forkskinny_128_encrypt_rounds
    (ForkSkinny128Cells_t state, const ForkSkinny128Key_t *ks1, const ForkSkinny128Key_t *ks2, unsigned from, unsigned to)
{
    const ForkSkinny128HalfCells_t *schedule1, *schedule2;
    unsigned index;
    uint32_t temp;


    /* Perform all encryption rounds */
    schedule1 = ks1->schedule + from;
    schedule2 = ks2->schedule + from;
    for (index = from; index < to; ++index, ++schedule1, ++schedule2) {
        /* Apply the S-box to all bytes in the state */
        #if SKINNY_64BIT
          state.lrow[0] = skinny128_sbox(state.lrow[0]);
          state.lrow[1] = skinny128_sbox(state.lrow[1]);
        #else
          state.row[0] = skinny128_sbox(state.row[0]);
          state.row[1] = skinny128_sbox(state.row[1]);
          state.row[2] = skinny128_sbox(state.row[2]);
          state.row[3] = skinny128_sbox(state.row[3]);
        #endif

        /* Apply the subkey for this round */
        #if SKINNY_64BIT
          state.lrow[0] ^= schedule1->lrow ^ schedule2->lrow;
          state.lrow[1] ^= 0x02;
        #else
          state.row[0] ^= schedule1->row[0] ^ schedule2->row[0];
          state.row[1] ^= schedule1->row[1] ^ schedule2->row[1];
          state.row[2] ^= 0x02;
        #endif

        /* Shift the rows */
        state.row[1] = skinny128_rotate_right(state.row[1], 8);
        state.row[2] = skinny128_rotate_right(state.row[2], 16);
        state.row[3] = skinny128_rotate_right(state.row[3], 24);

        /* Mix the columns */
        state.row[1] ^= state.row[2];
        state.row[2] ^= state.row[0];
        temp = state.row[3] ^ state.row[2];
        state.row[3] = state.row[2];
        state.row[2] = state.row[1];
        state.row[1] = state.row[0];
        state.row[0] = temp;
    }
    return state;
}

static ForkSkinny128Cells_t forkskinny_128_384_encrypt_rounds
    (ForkSkinny128Cells_t state, const ForkSkinny128Key_t *ks1, const ForkSkinny128Key_t *ks2, const ForkSkinny128Key_t *ks3, unsigned from, unsigned to)
{
    const ForkSkinny128HalfCells_t *schedule1, *schedule2, *schedule3;
    unsigned index;
    uint32_t temp;


    /* Perform all encryption rounds */
    schedule1 = ks1->schedule + from;
    schedule2 = ks2->schedule + from;
    schedule3 = ks3->schedule + from;
    for (index = from; index < to; ++index, ++schedule1, ++schedule2, ++schedule3) {
        /* Apply the S-box to all bytes in the state */
        #if SKINNY_64BIT
          state.lrow[0] = skinny128_sbox(state.lrow[0]);
          state.lrow[1] = skinny128_sbox(state.lrow[1]);
        #else
          state.row[0] = skinny128_sbox(state.row[0]);
          state.row[1] = skinny128_sbox(state.row[1]);
          state.row[2] = skinny128_sbox(state.row[2]);
          state.row[3] = skinny128_sbox(state.row[3]);
        #endif

        /* Apply the subkey for this round */
        #if SKINNY_64BIT
          state.lrow[0] ^= schedule1->lrow ^ schedule2->lrow ^ schedule3->lrow;
          state.lrow[1] ^= 0x02;
        #else
          state.row[0] ^= schedule1->row[0] ^ schedule2->row[0] ^ schedule3->row[0];
          state.row[1] ^= schedule1->row[1] ^ schedule2->row[1] ^ schedule3->row[1];
          state.row[2] ^= 0x02;
        #endif

        /* Shift the rows */
        state.row[1] = skinny128_rotate_right(state.row[1], 8);
        state.row[2] = skinny128_rotate_right(state.row[2], 16);
        state.row[3] = skinny128_rotate_right(state.row[3], 24);

        /* Mix the columns */
        state.row[1] ^= state.row[2];
        state.row[2] ^= state.row[0];
        temp = state.row[3] ^ state.row[2];
        state.row[3] = state.row[2];
        state.row[2] = state.row[1];
        state.row[1] = state.row[0];
        state.row[0] = temp;
    }
    return state;
}

void forkskinny_c_128_256_encrypt
      (const ForkSkinny128Key_t *tks1,
        const ForkSkinny128Key_t *tks2,
        uint8_t *output_left, uint8_t *output_right,
        const unsigned char *input)
{
    ForkSkinny128Cells_t state;

    /* Read the input buffer and convert little-endian to host-endian */
    state.row[0] = READ_WORD32(input, 0);
    state.row[1] = READ_WORD32(input, 4);
    state.row[2] = READ_WORD32(input, 8);
    state.row[3] = READ_WORD32(input, 12);

    /* Run all of the rounds before the forking point */
    state = forkskinny_128_encrypt_rounds(state, tks1, tks2, 0, FORKSKINNY_128_256_ROUNDS_BEFORE);

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* Generate the right output block */
        ForkSkinny128Cells_t output_state = forkskinny_128_encrypt_rounds
            (state, tks1, tks2, FORKSKINNY_128_256_ROUNDS_BEFORE,
             FORKSKINNY_128_256_ROUNDS_BEFORE +
             FORKSKINNY_128_256_ROUNDS_AFTER);

        /* Convert host-endian back into little-endian in the output buffer */
        WRITE_WORD32(output_right, 0, output_state.row[0]);
        WRITE_WORD32(output_right, 4, output_state.row[1]);
        WRITE_WORD32(output_right, 8, output_state.row[2]);
        WRITE_WORD32(output_right, 12, output_state.row[3]);
    }
    if (output_left) {
        /* Generate the left output block */
        #if SKINNY_64BIT
          state.lrow[0] ^= 0x8241201008040201U;
          state.lrow[1] ^= 0x8844a25128140a05U;
        #else
          state.row[0] ^= 0x08040201U; /* Branching constant */
          state.row[1] ^= 0x82412010U;
          state.row[2] ^= 0x28140a05U;
          state.row[3] ^= 0x8844a251U;
        #endif
        state = forkskinny_128_encrypt_rounds
            (state, tks1, tks2, FORKSKINNY_128_256_ROUNDS_BEFORE +
                     FORKSKINNY_128_256_ROUNDS_AFTER,
             FORKSKINNY_128_256_ROUNDS_BEFORE +
             FORKSKINNY_128_256_ROUNDS_AFTER * 2);
        /* Convert host-endian back into little-endian in the output buffer */
        WRITE_WORD32(output_left, 0, state.row[0]);
        WRITE_WORD32(output_left, 4, state.row[1]);
        WRITE_WORD32(output_left, 8, state.row[2]);
        WRITE_WORD32(output_left, 12, state.row[3]);
    } else {
        /* We only need the right output block */
        state = forkskinny_128_encrypt_rounds
            (state, tks1, tks2, FORKSKINNY_128_256_ROUNDS_BEFORE,
             FORKSKINNY_128_256_ROUNDS_BEFORE +
             FORKSKINNY_128_256_ROUNDS_AFTER);

             /* Convert host-endian back into little-endian in the output buffer */
             WRITE_WORD32(output_right, 0, state.row[0]);
             WRITE_WORD32(output_right, 4, state.row[1]);
             WRITE_WORD32(output_right, 8, state.row[2]);
             WRITE_WORD32(output_right, 12, state.row[3]);
    }
}

static ForkSkinny128Cells_t forkskinny_128_decrypt_rounds
    (ForkSkinny128Cells_t state, const ForkSkinny128Key_t *ks1, const ForkSkinny128Key_t *ks2, unsigned from, unsigned to)
{
    const ForkSkinny128HalfCells_t *schedule1, *schedule2;
    unsigned index;
    uint32_t temp;

    /* Perform all decryption rounds */
    schedule1 = &(ks1->schedule[from - 1]);
    schedule2 = &(ks2->schedule[from - 1]);
    for (index = from; index > to; --index, --schedule1, --schedule2) {
        /* Inverse mix of the columns */
        temp = state.row[3];
        state.row[3] = state.row[0];
        state.row[0] = state.row[1];
        state.row[1] = state.row[2];
        state.row[3] ^= temp;
        state.row[2] = temp ^ state.row[0];
        state.row[1] ^= state.row[2];

        /* Inverse shift of the rows */
        state.row[1] = skinny128_rotate_right(state.row[1], 24);
        state.row[2] = skinny128_rotate_right(state.row[2], 16);
        state.row[3] = skinny128_rotate_right(state.row[3], 8);

        /* Apply the subkey for this round */
        #if SKINNY_64BIT
          state.lrow[0] ^= schedule1->lrow ^ schedule2->lrow;
        #else
          state.row[0] ^= schedule1->row[0] ^ schedule2->row[0];
          state.row[1] ^= schedule1->row[1] ^ schedule2->row[1];
        #endif
        state.row[2] ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        #if SKINNY_64BIT
          state.lrow[0] = skinny128_inv_sbox(state.lrow[0]);
          state.lrow[1] = skinny128_inv_sbox(state.lrow[1]);
        #else
          state.row[0] = skinny128_inv_sbox(state.row[0]);
          state.row[1] = skinny128_inv_sbox(state.row[1]);
          state.row[2] = skinny128_inv_sbox(state.row[2]);
          state.row[3] = skinny128_inv_sbox(state.row[3]);
        #endif
    }
    return state;
}

static ForkSkinny128Cells_t forkskinny_128_384_decrypt_rounds
    (ForkSkinny128Cells_t state, const ForkSkinny128Key_t *ks1, const ForkSkinny128Key_t *ks2, const ForkSkinny128Key_t *ks3, unsigned from, unsigned to)
{
    const ForkSkinny128HalfCells_t *schedule1, *schedule2, *schedule3;
    unsigned index;
    uint32_t temp;

    /* Perform all decryption rounds */
    schedule1 = &(ks1->schedule[from - 1]);
    schedule2 = &(ks2->schedule[from - 1]);
    schedule3 = &(ks3->schedule[from - 1]);
    for (index = from; index > to; --index, --schedule1, --schedule2, --schedule3) {
        /* Inverse mix of the columns */
        temp = state.row[3];
        state.row[3] = state.row[0];
        state.row[0] = state.row[1];
        state.row[1] = state.row[2];
        state.row[3] ^= temp;
        state.row[2] = temp ^ state.row[0];
        state.row[1] ^= state.row[2];

        /* Inverse shift of the rows */
        state.row[1] = skinny128_rotate_right(state.row[1], 24);
        state.row[2] = skinny128_rotate_right(state.row[2], 16);
        state.row[3] = skinny128_rotate_right(state.row[3], 8);

        /* Apply the subkey for this round */
        #if SKINNY_64BIT
          state.lrow[0] ^= schedule1->lrow ^ schedule2->lrow ^ schedule3->lrow;
        #else
          state.row[0] ^= schedule1->row[0] ^ schedule2->row[0] ^ schedule3->row[0];
          state.row[1] ^= schedule1->row[1] ^ schedule2->row[1] ^ schedule3->row[1];
        #endif
        state.row[2] ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        #if SKINNY_64BIT
          state.lrow[0] = skinny128_inv_sbox(state.lrow[0]);
          state.lrow[1] = skinny128_inv_sbox(state.lrow[1]);
        #else
          state.row[0] = skinny128_inv_sbox(state.row[0]);
          state.row[1] = skinny128_inv_sbox(state.row[1]);
          state.row[2] = skinny128_inv_sbox(state.row[2]);
          state.row[3] = skinny128_inv_sbox(state.row[3]);
        #endif
    }
    return state;
}

void forkskinny_c_128_256_decrypt
     (const ForkSkinny128Key_t *tks1,
       const ForkSkinny128Key_t *tks2,
       uint8_t *output_left, uint8_t *output_right,
       const uint8_t *input_right)
{
    ForkSkinny128Cells_t state;

    /* Read the input buffer and convert little-endian to host-endian */
    state.row[0] = READ_WORD32(input_right, 0);
    state.row[1] = READ_WORD32(input_right, 4);
    state.row[2] = READ_WORD32(input_right, 8);
    state.row[3] = READ_WORD32(input_right, 12);

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    state = forkskinny_128_decrypt_rounds
        (state, tks1, tks2, FORKSKINNY_128_256_ROUNDS_BEFORE +
                 FORKSKINNY_128_256_ROUNDS_AFTER,
         FORKSKINNY_128_256_ROUNDS_BEFORE);

    if(output_left) {
      ForkSkinny128Cells_t fstate = state;

      /* Add the branching constant */
      #if SKINNY_64BIT
        fstate.lrow[0] ^= 0x8241201008040201U;
        fstate.lrow[1] ^= 0x8844a25128140a05U;
      #else
        fstate.row[0] ^= 0x08040201U; /* Branching constant */
        fstate.row[1] ^= 0x82412010U;
        fstate.row[2] ^= 0x28140a05U;
        fstate.row[3] ^= 0x8844a251U;
      #endif

      /* Generate the left output block after another "before" rounds */
      fstate = forkskinny_128_encrypt_rounds
          (fstate, tks1, tks2, FORKSKINNY_128_256_ROUNDS_BEFORE +
            FORKSKINNY_128_256_ROUNDS_AFTER,
            FORKSKINNY_128_256_ROUNDS_BEFORE + 2*FORKSKINNY_128_256_ROUNDS_AFTER);
      /* Convert host-endian back into little-endian in the output buffer */
      WRITE_WORD32(output_left, 0, fstate.row[0]);
      WRITE_WORD32(output_left, 4, fstate.row[1]);
      WRITE_WORD32(output_left, 8, fstate.row[2]);
      WRITE_WORD32(output_left, 12, fstate.row[3]);
    }

    /* Generate the right output block by going backward "before"
     * rounds from the forking point */
    state = forkskinny_128_decrypt_rounds
        (state, tks1, tks2, FORKSKINNY_128_256_ROUNDS_BEFORE, 0);
    /* Convert host-endian back into little-endian in the output buffer */
    WRITE_WORD32(output_right, 0, state.row[0]);
    WRITE_WORD32(output_right, 4, state.row[1]);
    WRITE_WORD32(output_right, 8, state.row[2]);
    WRITE_WORD32(output_right, 12, state.row[3]);
}

void forkskinny_c_128_384_encrypt
      (const ForkSkinny128Key_t *tks1,
        const ForkSkinny128Key_t *tks2,
        const ForkSkinny128Key_t *tks3,
        uint8_t *output_left, uint8_t *output_right,
        const unsigned char *input)
{
    ForkSkinny128Cells_t state;

    /* Read the input buffer and convert little-endian to host-endian */
    state.row[0] = READ_WORD32(input, 0);
    state.row[1] = READ_WORD32(input, 4);
    state.row[2] = READ_WORD32(input, 8);
    state.row[3] = READ_WORD32(input, 12);

    /* Run all of the rounds before the forking point */
    state = forkskinny_128_384_encrypt_rounds(state, tks1, tks2, tks3, 0, FORKSKINNY_128_384_ROUNDS_BEFORE);

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* Generate the right output block */
        ForkSkinny128Cells_t output_state = forkskinny_128_384_encrypt_rounds
            (state, tks1, tks2, tks3, FORKSKINNY_128_384_ROUNDS_BEFORE,
             FORKSKINNY_128_384_ROUNDS_BEFORE +
             FORKSKINNY_128_384_ROUNDS_AFTER);

        /* Convert host-endian back into little-endian in the output buffer */
        WRITE_WORD32(output_right, 0, output_state.row[0]);
        WRITE_WORD32(output_right, 4, output_state.row[1]);
        WRITE_WORD32(output_right, 8, output_state.row[2]);
        WRITE_WORD32(output_right, 12, output_state.row[3]);
    }
    if (output_left) {
        /* Generate the left output block */
        #if SKINNY_64BIT
          state.lrow[0] ^= 0x8241201008040201U;
          state.lrow[1] ^= 0x8844a25128140a05U;
        #else
          state.row[0] ^= 0x08040201U; /* Branching constant */
          state.row[1] ^= 0x82412010U;
          state.row[2] ^= 0x28140a05U;
          state.row[3] ^= 0x8844a251U;
        #endif
        state = forkskinny_128_384_encrypt_rounds
            (state, tks1, tks2, tks3, FORKSKINNY_128_384_ROUNDS_BEFORE +
                     FORKSKINNY_128_384_ROUNDS_AFTER,
             FORKSKINNY_128_384_ROUNDS_BEFORE +
             FORKSKINNY_128_384_ROUNDS_AFTER * 2);
        /* Convert host-endian back into little-endian in the output buffer */
        WRITE_WORD32(output_left, 0, state.row[0]);
        WRITE_WORD32(output_left, 4, state.row[1]);
        WRITE_WORD32(output_left, 8, state.row[2]);
        WRITE_WORD32(output_left, 12, state.row[3]);
    } else {
        /* We only need the right output block */
        state = forkskinny_128_384_encrypt_rounds
            (state, tks1, tks2, tks3, FORKSKINNY_128_384_ROUNDS_BEFORE,
             FORKSKINNY_128_384_ROUNDS_BEFORE +
             FORKSKINNY_128_384_ROUNDS_AFTER);

        /* Convert host-endian back into little-endian in the output buffer */
        WRITE_WORD32(output_right, 0, state.row[0]);
        WRITE_WORD32(output_right, 4, state.row[1]);
        WRITE_WORD32(output_right, 8, state.row[2]);
        WRITE_WORD32(output_right, 12, state.row[3]);
    }
}

void forkskinny_c_128_384_decrypt
     (const ForkSkinny128Key_t *tks1,
       const ForkSkinny128Key_t *tks2,
       const ForkSkinny128Key_t *tks3,
       uint8_t *output_left, uint8_t *output_right,
       const uint8_t *input_right)
{
    ForkSkinny128Cells_t state;

    /* Read the input buffer and convert little-endian to host-endian */
    state.row[0] = READ_WORD32(input_right, 0);
    state.row[1] = READ_WORD32(input_right, 4);
    state.row[2] = READ_WORD32(input_right, 8);
    state.row[3] = READ_WORD32(input_right, 12);

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    state = forkskinny_128_384_decrypt_rounds
        (state, tks1, tks2, tks3, FORKSKINNY_128_384_ROUNDS_BEFORE +
                 FORKSKINNY_128_384_ROUNDS_AFTER,
         FORKSKINNY_128_384_ROUNDS_BEFORE);

    if(output_left) {
      ForkSkinny128Cells_t fstate = state;
      /* Add the branching constant */
      #if SKINNY_64BIT
        fstate.lrow[0] ^= 0x8241201008040201U;
        fstate.lrow[1] ^= 0x8844a25128140a05U;
      #else
        fstate.row[0] ^= 0x08040201U; /* Branching constant */
        fstate.row[1] ^= 0x82412010U;
        fstate.row[2] ^= 0x28140a05U;
        fstate.row[3] ^= 0x8844a251U;
      #endif

      /* Generate the left output block after another "before" rounds */
      fstate = forkskinny_128_384_encrypt_rounds
          (fstate, tks1, tks2, tks3, FORKSKINNY_128_384_ROUNDS_BEFORE +
            FORKSKINNY_128_384_ROUNDS_AFTER,
            FORKSKINNY_128_384_ROUNDS_BEFORE + 2*FORKSKINNY_128_384_ROUNDS_AFTER);
      /* Convert host-endian back into little-endian in the output buffer */
      WRITE_WORD32(output_left, 0, fstate.row[0]);
      WRITE_WORD32(output_left, 4, fstate.row[1]);
      WRITE_WORD32(output_left, 8, fstate.row[2]);
      WRITE_WORD32(output_left, 12, fstate.row[3]);
    }

    /* Generate the right output block by going backward "before"
     * rounds from the forking point */
    state = forkskinny_128_384_decrypt_rounds
        (state, tks1, tks2, tks3, FORKSKINNY_128_384_ROUNDS_BEFORE, 0);
    /* Convert host-endian back into little-endian in the output buffer */
    WRITE_WORD32(output_right, 0, state.row[0]);
    WRITE_WORD32(output_right, 4, state.row[1]);
    WRITE_WORD32(output_right, 8, state.row[2]);
    WRITE_WORD32(output_right, 12, state.row[3]);
}