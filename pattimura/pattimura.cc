//=======================================================================
// Copyright abeinoe 2015.
// Distributed under the MIT License.
// (See accompanying file LICENSE or copy at
//  http://opensource.org/licenses/MIT)
//=======================================================================

#include <string.h>

#include "pattimura.h"
#include "utils.h"

void PATTIMURA_Encrypt(PATTIMURA_Context *ctx, const unsigned char *in, unsigned char *out);
void PATTIMURA_Decrypt(PATTIMURA_Context *ctx, const unsigned char *in, unsigned char *out);
short PATTIMURA_InitTable(PATTIMURA_Context *ctx, const unsigned char *cipherKey, short keyBits, const unsigned char *userBox);
void PATTIMURA_InverseTable(unsigned char *tw);

short PATTIMURA_Open(PATTIMURA_Context *ctx, const unsigned char *cipherKey, short keyBits, unsigned char mode, const unsigned char *userBox)
{
    short ret;

    if(!ctx)
        return 1;

    memset(ctx, 0, sizeof(PATTIMURA_Context));

    if((mode <= PATTIMURA_FREE) || (mode >= PATTIMURA_MODES))
        return 1;

    ctx->mode = mode;

    if(checkBox(userBox)){
        return 1;
    }

    ret = PATTIMURA_InitTable(ctx, cipherKey, keyBits, userBox);
    if((ret == 0) && ((ctx->mode == PATTIMURA_CBC_DEC) || (ctx->mode == PATTIMURA_ECB_DEC)))
        PATTIMURA_InverseTable(ctx->tw);

    return ret;
}


short PATTIMURA_InitOFB_CBC_CTR(PATTIMURA_Context *ctx, const unsigned char *iv)
{
    if(!ctx)
        return 1;
    if((ctx->mode != PATTIMURA_OFB) && (ctx->mode != PATTIMURA_CBC_ENC) && (ctx->mode != PATTIMURA_CBC_DEC) && (ctx->mode != PATTIMURA_CTR))
        return 1;

    memcpy(ctx->InitialVector, iv, PATTIMURA_IVBYTES);
    return 0;
}


short PATTIMURA_EncryptDecript(PATTIMURA_Context *ctx, unsigned char *out, unsigned char *in, short nblocks)
{
    short i, j, cb;
    unsigned char tmp[PATTIMURA_BLOCKBYTES];

    if(!ctx)
        return 1;

    if(ctx->mode == PATTIMURA_CTR)
    {
        for(i=0; i < nblocks; i++)
        {
            PATTIMURA_Encrypt(ctx, ctx->InitialVector, out);
            for(j=0; j < PATTIMURA_BLOCKBYTES; j++)
                out[j] = *in++ ^ out[j];
            out += PATTIMURA_BLOCKBYTES;

            i = 15;
            do {
                ctx->InitialVector[i]++;
                cb = ctx->InitialVector[i] == 0;
            } while(i-- && cb);
        }
        return 0;
    } else if(ctx->mode == PATTIMURA_OFB)
    {
        for(i=0; i < nblocks; i++)
        {
            PATTIMURA_Encrypt(ctx, ctx->InitialVector, ctx->InitialVector);
            for(j=0; j < PATTIMURA_BLOCKBYTES; j++)
                *out++ = *in++ ^ ctx->InitialVector[j];
        }
        return 0;
    } else if(ctx->mode == PATTIMURA_ECB_ENC)
    {
        for(i=0; i < nblocks; i++)
        {
            PATTIMURA_Encrypt(ctx, in, out);
            in += PATTIMURA_BLOCKBYTES;
            out += PATTIMURA_BLOCKBYTES;
        }
        return 0;
    } else if(ctx->mode == PATTIMURA_ECB_DEC)
    {
        for(i=0; i < nblocks; i++)
        {
            PATTIMURA_Decrypt(ctx, in, out);
            in += PATTIMURA_BLOCKBYTES;
            out += PATTIMURA_BLOCKBYTES;
        }
        return 0;
    } else if(ctx->mode == PATTIMURA_CBC_ENC)
    {
        for(i=0; i < nblocks; i++)
        {
            for(j=0; j < PATTIMURA_BLOCKBYTES; j++)
                tmp[j] = in[j] ^ ctx->InitialVector[j];
            PATTIMURA_Encrypt(ctx, tmp, out);
            for(j=0; j < PATTIMURA_BLOCKBYTES; j++)
                ctx->InitialVector[j] = out[j];
            in += PATTIMURA_BLOCKBYTES;
            out += PATTIMURA_BLOCKBYTES;
        }
        return 0;
    } else if(ctx->mode == PATTIMURA_CBC_DEC)
    {
        for(i=0; i < nblocks; i++)
        {
            PATTIMURA_Decrypt(ctx, in, out);
            for(j=0; j< PATTIMURA_BLOCKBYTES; j++)
            {
                out[j] ^= ctx->InitialVector[j];
                ctx->InitialVector[j] = in[j];
            }
            in += PATTIMURA_BLOCKBYTES;
            out += PATTIMURA_BLOCKBYTES;
        }
        return 0;
    }
    return 1;
}

void PATTIMURA_Encrypt(PATTIMURA_Context *ctx, const unsigned char *in, unsigned char *out)
{
    out[0] = ctx->tw[in[0]];
    out[1] = ctx->tw[in[1]];
    out[2] = ctx->tw[in[2]];
    out[3] = ctx->tw[in[3]];
    out[4] = ctx->tw[in[4]];
    out[5] = ctx->tw[in[5]];
    out[6] = ctx->tw[in[6]];
    out[7] = ctx->tw[in[7]];
    out[8] = ctx->tw[in[8]];
    out[9] = ctx->tw[in[9]];
    out[10] = ctx->tw[in[10]];
    out[11] = ctx->tw[in[11]];
    out[12] = ctx->tw[in[12]];
    out[13] = ctx->tw[in[13]];
    out[14] = ctx->tw[in[14]];
    out[15] = ctx->tw[in[15]];

    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[0])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[1])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[2])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[3])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[4])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[5])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[6])];
    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[7])];

    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[8])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[9])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[10])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[11])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[12])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[13])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[14])];
    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[15])];

    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[16])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[17])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[18])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[19])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[20])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[21])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[22])];
    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[23])];

    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[24])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[25])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[26])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[27])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[28])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[29])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[30])];
    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[31])];

    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[32])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[33])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[34])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[35])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[36])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[37])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[38])];
    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[39])];

    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[40])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[41])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[42])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[43])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[44])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[45])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[46])];
    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[47])];

    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[48])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[49])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[50])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[51])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[52])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[53])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[54])];
    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[55])];

    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[56])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[57])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[58])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[59])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[60])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[61])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[62])];
    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[63])];

    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[64])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[65])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[66])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[67])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[68])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[69])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[70])];
    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[71])];

    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[72])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[73])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[74])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[75])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[76])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[77])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[78])];
    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[79])];

    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[80])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[81])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[82])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[83])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[84])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[85])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[86])];
    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[87])];

    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[88])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[89])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[90])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[91])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[92])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[93])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[94])];
    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[95])];

    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[96])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[97])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[98])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[99])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[100])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[101])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[102])];
    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[103])];

    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[104])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[105])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[106])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[107])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[108])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[109])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[110])];
    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[111])];

    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[112])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[113])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[114])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[115])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[116])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[117])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[118])];
    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[119])];

    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[120])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[121])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[122])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[123])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[124])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[125])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[126])];
    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[127])];

    out[0] = ctx->tw[out[0]];
    out[1] = ctx->tw[out[1]];
    out[2] = ctx->tw[out[2]];
    out[3] = ctx->tw[out[3]];
    out[4] = ctx->tw[out[4]];
    out[5] = ctx->tw[out[5]];
    out[6] = ctx->tw[out[6]];
    out[7] = ctx->tw[out[7]];
    out[8] = ctx->tw[out[8]];
    out[9] = ctx->tw[out[9]];
    out[10] = ctx->tw[out[10]];
    out[11] = ctx->tw[out[11]];
    out[12] = ctx->tw[out[12]];
    out[13] = ctx->tw[out[13]];
    out[14] = ctx->tw[out[14]];
    out[15] = ctx->tw[out[15]];
}


void PATTIMURA_Decrypt(PATTIMURA_Context *ctx, const unsigned char *in, unsigned char *out)
{
    out[0] = ctx->tw[in[0]];
    out[1] = ctx->tw[in[1]];
    out[2] = ctx->tw[in[2]];
    out[3] = ctx->tw[in[3]];
    out[4] = ctx->tw[in[4]];
    out[5] = ctx->tw[in[5]];
    out[6] = ctx->tw[in[6]];
    out[7] = ctx->tw[in[7]];
    out[8] = ctx->tw[in[8]];
    out[9] = ctx->tw[in[9]];
    out[10] = ctx->tw[in[10]];
    out[11] = ctx->tw[in[11]];
    out[12] = ctx->tw[in[12]];
    out[13] = ctx->tw[in[13]];
    out[14] = ctx->tw[in[14]];
    out[15] = ctx->tw[in[15]];

    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[127])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[126])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[125])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[124])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[123])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[122])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[121])];
    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[120])];

    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[119])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[118])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[117])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[116])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[115])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[114])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[113])];
    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[112])];

    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[111])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[110])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[109])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[108])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[107])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[106])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[105])];
    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[104])];

    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[103])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[102])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[101])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[100])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[99])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[98])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[97])];
    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[96])];

    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[95])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[94])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[93])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[92])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[91])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[90])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[89])];
    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[88])];

    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[87])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[86])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[85])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[84])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[83])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[82])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[81])];
    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[80])];

    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[79])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[78])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[77])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[76])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[75])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[74])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[73])];
    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[72])];

    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[71])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[70])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[69])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[68])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[67])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[66])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[65])];
    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[64])];

    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[63])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[62])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[61])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[60])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[59])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[58])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[57])];
    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[56])];

    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[55])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[54])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[53])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[52])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[51])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[50])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[49])];
    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[48])];

    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[47])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[46])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[45])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[44])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[43])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[42])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[41])];
    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[40])];

    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[39])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[38])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[37])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[36])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[35])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[34])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[33])];
    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[32])];

    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[31])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[30])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[29])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[28])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[27])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[26])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[25])];
    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[24])];

    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[23])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[22])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[21])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[20])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[19])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[18])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[17])];
    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[16])];

    out[11] ^= ctx->ty[(ctx->tx[out[15]] + ctx->tx[out[2]]  + ctx->ty[15])];
    out[10] ^= ctx->ty[(ctx->tx[out[14]] + ctx->tx[out[1]]  + ctx->ty[14])];
    out[9]  ^= ctx->ty[(ctx->tx[out[13]] + ctx->tx[out[0]]  + ctx->ty[13])];
    out[8]  ^= ctx->ty[(ctx->tx[out[12]] + ctx->tx[out[3]]  + ctx->ty[12])];
    out[7]  ^= ctx->ty[(ctx->tx[out[3]]  + ctx->tx[out[14]] + ctx->ty[11])];
    out[6]  ^= ctx->ty[(ctx->tx[out[2]]  + ctx->tx[out[13]] + ctx->ty[10])];
    out[5]  ^= ctx->ty[(ctx->tx[out[1]]  + ctx->tx[out[12]] + ctx->ty[9])];
    out[4]  ^= ctx->ty[(ctx->tx[out[0]]  + ctx->tx[out[15]] + ctx->ty[8])];

    out[15] ^= ctx->ty[(ctx->tx[out[11]] + ctx->tx[out[6]]  + ctx->ty[7])];
    out[14] ^= ctx->ty[(ctx->tx[out[10]] + ctx->tx[out[5]]  + ctx->ty[6])];
    out[13] ^= ctx->ty[(ctx->tx[out[9]]  + ctx->tx[out[4]]  + ctx->ty[5])];
    out[12] ^= ctx->ty[(ctx->tx[out[8]]  + ctx->tx[out[7]]  + ctx->ty[4])];
    out[3]  ^= ctx->ty[(ctx->tx[out[7]]  + ctx->tx[out[10]] + ctx->ty[3])];
    out[2]  ^= ctx->ty[(ctx->tx[out[6]]  + ctx->tx[out[9]]  + ctx->ty[2])];
    out[1]  ^= ctx->ty[(ctx->tx[out[5]]  + ctx->tx[out[8]]  + ctx->ty[1])];
    out[0]  ^= ctx->ty[(ctx->tx[out[4]]  + ctx->tx[out[11]] + ctx->ty[0])];

    out[0] = ctx->tw[out[0]];
    out[1] = ctx->tw[out[1]];
    out[2] = ctx->tw[out[2]];
    out[3] = ctx->tw[out[3]];
    out[4] = ctx->tw[out[4]];
    out[5] = ctx->tw[out[5]];
    out[6] = ctx->tw[out[6]];
    out[7] = ctx->tw[out[7]];
    out[8] = ctx->tw[out[8]];
    out[9] = ctx->tw[out[9]];
    out[10] = ctx->tw[out[10]];
    out[11] = ctx->tw[out[11]];
    out[12] = ctx->tw[out[12]];
    out[13] = ctx->tw[out[13]];
    out[14] = ctx->tw[out[14]];
    out[15] = ctx->tw[out[15]];
}

short PATTIMURA_InitTable(PATTIMURA_Context *ctx, const unsigned char *cipherKey, short keyBits, const unsigned char *userBox)
{
    unsigned char tz[259], swp;
    short i;

    for(i=0; i < 256; i++){
        ctx->tw[i] = ctx->tx[i] = ctx->ty[i] = (unsigned char) i;
    }

    if(keyBits == 128){
        memcpy(tz, cipherKey, 16);
        for(i=16; i < 256; i++){
            tz[i] = (((tz[i-4] ^ tz[i-3]) + tz[i-2]) ^ tz[i-1]) + 0xAB;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->tw[i];
            ctx->tw[i] = ctx->tw[tz[i]];
            ctx->tw[tz[i]] = swp;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->tx[i];
            ctx->tx[i] = ctx->tx[tz[i]];
            ctx->tx[tz[i]] = swp;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->ty[i];
            ctx->ty[i] = ctx->ty[tz[i]];
            ctx->ty[tz[i]] = swp;
        }

        return 0;
    } else if(keyBits == 192){
        memcpy(tz, cipherKey, 24);
        for(i=24; i < 256; i++){
            tz[i] = (((tz[i-4] ^ tz[i-3]) + tz[i-2]) ^ tz[i-1]) + 0xAB;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->tw[i];
            ctx->tw[i] = ctx->tw[tz[i]];
            ctx->tw[tz[i]] = swp;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->tx[i];
            ctx->tx[i] = ctx->tx[tz[i]];
            ctx->tx[tz[i]] = swp;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->ty[i];
            ctx->ty[i] = ctx->ty[tz[i]];
            ctx->ty[tz[i]] = swp;
        }

        return 0;
    } else if(keyBits == 256){
        memcpy(tz, cipherKey, 32);
        for(i=32; i < 256; i++){
            tz[i] = (((tz[i-4] ^ tz[i-3]) + tz[i-2]) ^ tz[i-1]) + 0xAB;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->tw[i];
            ctx->tw[i] = ctx->tw[tz[i]];
            ctx->tw[tz[i]] = swp;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->tx[i];
            ctx->tx[i] = ctx->tx[tz[i]];
            ctx->tx[tz[i]] = swp;
        }

        tz[256] = tz[0];
        tz[257] = tz[1];
        tz[258] = tz[2];

        for(i=255; i>=0; i--){
            tz[i] = (((userBox[tz[i]] ^ userBox[tz[i+1]]) + userBox[tz[i+2]]) ^ userBox[tz[i+3]]) + 0xAB;
        }

        for(i=0; i < 256; i++){
            swp = ctx->ty[i];
            ctx->ty[i] = ctx->ty[tz[i]];
            ctx->ty[tz[i]] = swp;
        }

        return 0;
    }
    return 1;
}

void PATTIMURA_InverseTable(unsigned char *tw)
{
    unsigned char tmp[256];
    short i;

    memcpy(tmp, tw, 256);

    for(i=0; i < 256; i++){
        tw[tmp[i]] = (unsigned char) i;
    }
}
