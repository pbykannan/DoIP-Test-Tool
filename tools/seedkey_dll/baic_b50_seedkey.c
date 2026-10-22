/*
 * 北汽 B50（136-4G / 136-5G）TBOX 0x27 安全访问 Seed&Key DLL
 *
 * 算法：《UDS安全访问认证方案 v2.0》（与 DoIP-Test 的 baic-df-token 一致）
 *   1) 27 01 / 27 11 -> ECU 返回 16 字节 Seed
 *   2) Tester 生成 16 字节随机派生因子 DF
 *   3) SK    = AES-128-CMAC(Key, DF)
 *   4) Token = AES-128-CMAC(SK, Seed)
 *   5) 27 02 / 27 12 上传 32 字节 DF || Token
 *   Level 0x01/0x02 用 UDS 因子（L1），0x11/0x12 用 BOOT 因子（L3）。
 *
 * 导出接口（Vector CANoe/CANdela 标准，TSMaster / eFlash 等可直接加载）：
 *   GenerateKeyEx / GenerateKeyExOpt（__cdecl，与 Vector KeyGenAlgoInterfaceEx.h 一致）
 */

#include <windows.h>
#include <bcrypt.h>
#include <string.h>

#define KGRE_Ok 0
#define KGRE_BufferToSmall 1
#define KGRE_SecurityLevelInvalid 2
#define KGRE_VariantInvalid 3
#define KGRE_UnspecifiedError 4

#define B50_SEED_LEN 16u
#define B50_KEY_LEN 32u

static const unsigned char kKeyLevel1[16] = {
    0xF6, 0x6E, 0xF1, 0xDE, 0x91, 0xB9, 0x87, 0x09,
    0x6F, 0xEF, 0x02, 0xAF, 0xE2, 0x30, 0x7F, 0xC6};
static const unsigned char kKeyLevel3[16] = {
    0x98, 0x48, 0xBF, 0xCD, 0x81, 0x7E, 0x43, 0x44,
    0x93, 0x12, 0x03, 0x9E, 0xA7, 0x03, 0xDB, 0x79};

/* ---------------- AES-128（仅加密） ---------------- */

static const unsigned char kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static unsigned char xtime(unsigned char x)
{
    return (unsigned char)((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

static void aes128_expand_key(const unsigned char key[16], unsigned char rk[176])
{
    static const unsigned char rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
    unsigned int i;
    memcpy(rk, key, 16);
    for (i = 16; i < 176; i += 4) {
        unsigned char t[4];
        t[0] = rk[i - 4];
        t[1] = rk[i - 3];
        t[2] = rk[i - 2];
        t[3] = rk[i - 1];
        if (i % 16 == 0) {
            unsigned char tmp = t[0];
            t[0] = (unsigned char)(kSbox[t[1]] ^ rcon[i / 16 - 1]);
            t[1] = kSbox[t[2]];
            t[2] = kSbox[t[3]];
            t[3] = kSbox[tmp];
        }
        rk[i + 0] = (unsigned char)(rk[i - 16] ^ t[0]);
        rk[i + 1] = (unsigned char)(rk[i - 15] ^ t[1]);
        rk[i + 2] = (unsigned char)(rk[i - 14] ^ t[2]);
        rk[i + 3] = (unsigned char)(rk[i - 13] ^ t[3]);
    }
}

static void aes128_encrypt_block(const unsigned char rk[176], const unsigned char in[16], unsigned char out[16])
{
    unsigned char s[16];
    unsigned int round, i, c;

    for (i = 0; i < 16; i++)
        s[i] = (unsigned char)(in[i] ^ rk[i]);

    for (round = 1; round <= 10; round++) {
        unsigned char t[16];
        /* SubBytes + ShiftRows；状态按列存放：s[row + 4*col] */
        for (c = 0; c < 4; c++) {
            unsigned int r;
            for (r = 0; r < 4; r++)
                t[r + 4 * c] = kSbox[s[r + 4 * ((c + r) & 3)]];
        }
        if (round != 10) {
            for (c = 0; c < 4; c++) {
                unsigned char a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
                unsigned char all = (unsigned char)(a0 ^ a1 ^ a2 ^ a3);
                t[4 * c + 0] = (unsigned char)(a0 ^ all ^ xtime((unsigned char)(a0 ^ a1)));
                t[4 * c + 1] = (unsigned char)(a1 ^ all ^ xtime((unsigned char)(a1 ^ a2)));
                t[4 * c + 2] = (unsigned char)(a2 ^ all ^ xtime((unsigned char)(a2 ^ a3)));
                t[4 * c + 3] = (unsigned char)(a3 ^ all ^ xtime((unsigned char)(a3 ^ a0)));
            }
        }
        for (i = 0; i < 16; i++)
            s[i] = (unsigned char)(t[i] ^ rk[16 * round + i]);
    }
    memcpy(out, s, 16);
}

/* ---------------- AES-128-CMAC（RFC 4493） ---------------- */

static void cmac_shift_subkey(const unsigned char in[16], unsigned char out[16])
{
    unsigned int i;
    unsigned char msb = (unsigned char)(in[0] & 0x80);
    for (i = 0; i < 15; i++)
        out[i] = (unsigned char)((in[i] << 1) | (in[i + 1] >> 7));
    out[15] = (unsigned char)(in[15] << 1);
    if (msb)
        out[15] ^= 0x87;
}

static void aes128_cmac(const unsigned char key[16], const unsigned char *msg, unsigned int len, unsigned char mac[16])
{
    unsigned char rk[176], l[16], k1[16], k2[16], x[16], last[16];
    unsigned int n, i, j;
    int complete;

    aes128_expand_key(key, rk);
    memset(x, 0, 16);
    aes128_encrypt_block(rk, x, l);
    cmac_shift_subkey(l, k1);
    cmac_shift_subkey(k1, k2);

    n = (len + 15) / 16;
    if (n == 0) {
        n = 1;
        complete = 0;
    } else {
        complete = (len % 16) == 0;
    }

    if (complete) {
        for (j = 0; j < 16; j++)
            last[j] = (unsigned char)(msg[16 * (n - 1) + j] ^ k1[j]);
    } else {
        unsigned int rem = len - 16 * (n - 1);
        memset(last, 0, 16);
        memcpy(last, msg + 16 * (n - 1), rem);
        last[rem] = 0x80;
        for (j = 0; j < 16; j++)
            last[j] ^= k2[j];
    }

    for (i = 0; i + 1 < n; i++) {
        for (j = 0; j < 16; j++)
            x[j] ^= msg[16 * i + j];
        aes128_encrypt_block(rk, x, x);
    }
    for (j = 0; j < 16; j++)
        x[j] ^= last[j];
    aes128_encrypt_block(rk, x, mac);

    SecureZeroMemory(rk, sizeof(rk));
    SecureZeroMemory(l, sizeof(l));
    SecureZeroMemory(k1, sizeof(k1));
    SecureZeroMemory(k2, sizeof(k2));
}

/* ---------------- B50 Seed&Key ---------------- */

static const unsigned char *select_key(unsigned int level)
{
    switch (level) {
    case 0x01:
    case 0x02:
        return kKeyLevel1;
    case 0x11:
    case 0x12:
        return kKeyLevel3;
    default:
        return NULL;
    }
}

static int compute_key(const unsigned char *seed, unsigned int seed_len, unsigned int level,
                       const unsigned char *df_in, unsigned char *key_out,
                       unsigned int key_max, unsigned int *key_len)
{
    const unsigned char *master;
    unsigned char df[16], sk[16];

    if (key_len)
        *key_len = 0;
    if (seed == NULL || key_out == NULL || key_len == NULL)
        return KGRE_UnspecifiedError;
    master = select_key(level);
    if (master == NULL)
        return KGRE_SecurityLevelInvalid;
    if (seed_len != B50_SEED_LEN)
        return KGRE_UnspecifiedError;
    if (key_max < B50_KEY_LEN)
        return KGRE_BufferToSmall;

    if (df_in != NULL) {
        memcpy(df, df_in, 16);
    } else if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, df, sizeof(df), BCRYPT_USE_SYSTEM_PREFERRED_RNG))) {
        return KGRE_UnspecifiedError;
    }

    aes128_cmac(master, df, 16, sk);
    memcpy(key_out, df, 16);
    aes128_cmac(sk, seed, B50_SEED_LEN, key_out + 16);
    *key_len = B50_KEY_LEN;

    SecureZeroMemory(sk, sizeof(sk));
    SecureZeroMemory(df, sizeof(df));
    return KGRE_Ok;
}

int __cdecl GenerateKeyEx(const unsigned char *ipSeedArray, unsigned int iSeedArraySize,
                          const unsigned int iSecurityLevel, const char *ipVariant,
                          unsigned char *iopKeyArray, unsigned int iMaxKeyArraySize,
                          unsigned int *oActualKeyArraySize)
{
    (void)ipVariant;
    return compute_key(ipSeedArray, iSeedArraySize, iSecurityLevel, NULL,
                       iopKeyArray, iMaxKeyArraySize, oActualKeyArraySize);
}

int __cdecl GenerateKeyExOpt(const unsigned char *ipSeedArray, unsigned int iSeedArraySize,
                             const unsigned int iSecurityLevel, const char *ipVariant,
                             const char *ipOptions, unsigned char *iopKeyArray,
                             unsigned int iMaxKeyArraySize, unsigned int *oActualKeyArraySize)
{
    (void)ipVariant;
    (void)ipOptions;
    return compute_key(ipSeedArray, iSeedArraySize, iSecurityLevel, NULL,
                       iopKeyArray, iMaxKeyArraySize, oActualKeyArraySize);
}

/* 固定 DF 的确定性版本，仅用于离线比对/自测（不被上位机调用）。 */
int __cdecl B50_ComputeKeyWithDF(const unsigned char *ipSeedArray, unsigned int iSeedArraySize,
                                 unsigned int iSecurityLevel, const unsigned char *ipDF16,
                                 unsigned char *iopKeyArray, unsigned int iMaxKeyArraySize,
                                 unsigned int *oActualKeyArraySize)
{
    if (ipDF16 == NULL)
        return KGRE_UnspecifiedError;
    return compute_key(ipSeedArray, iSeedArraySize, iSecurityLevel, ipDF16,
                       iopKeyArray, iMaxKeyArraySize, oActualKeyArraySize);
}

/* 通用 AES-128-CMAC，供自测比对 RFC 4493 向量。 */
void __cdecl B50_AesCmac(const unsigned char *key16, const unsigned char *msg, unsigned int len, unsigned char *mac16)
{
    aes128_cmac(key16, msg, len, mac16);
}
