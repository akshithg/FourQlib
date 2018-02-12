#include "FourQ_internal.h"
#include "FourQ_params.h"
#include "../random/random.h"
#include "../sha512/sha512.h"
#include <malloc.h>
#include <string.h>

// bpv_n and bpv_k are the bpv generator params
// k subsets over n random numbers alpha_i
#define BPV_n 1024
#define BPV_k 16

// Algo: (x, g^x) for Schnorr
//
// A) Preprocessing step:
// Generate bpv_n random integers alpha_i
// Compute beta_i = g ^ alpha_i
// Store both in a table
//
// B) When a pair (x, g^x) is needed:
// Randomly select S subset [1, bpv_n] and |S| = bpv_k
// x = Sum_(i in S) of alpha_i mod ord(g) (THIS CAN BE PARALLELIZED)
//     if x = 0 stop and start again
// g^x = Product_(i in S) of beta_i (THIS CAN BE PARALLELIZED)
// return (x, g^x)

ECCRYPTO_STATUS BPVOnline(const unsigned char *SecretKey, const unsigned char *PublicKey, unsigned char *lastSecret, unsigned char *lastPublic)
{
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN; // initially no error
    digit_t *S = (digit_t *)(lastSecret); //
    unsigned char *index; // bpv_n random numbers
    unsigned char secretTemp[32], publicTemp[64]; //
    unsigned char secretTemp2[32]; //
    int k; // loop variable

    //point_t Temp;
    point_t Added; //
    point_extproj_t AddedExtproj; //
    point_extproj_t TempExtproj; //
    point_extproj_precomp_t TempExtprojPre; //

    // Precomputation
    // Generate bpv_n random numbers and put it in index
    Status = RandomBytesFunction(index, BPV_n);
    if (Status != ECCRYPTO_SUCCESS)
    {
        goto cleanup;
    }

    // obtain (x, g^x)
    // A i=0
    index[0] = BPV_n * index[0] / 256; //
    memmove(secretTemp, SecretKey + 32 * index[0], 32);
    memmove(publicTemp, PublicKey + 64 * index[0], 64);

    // B i=0
    point_setup((point_affine *)publicTemp, AddedExtproj);

    // A i=1
    index[1] = BPV_n * index[1] / 256;
    memmove(secretTemp2, SecretKey + 32 * index[1], 32);
    memmove(publicTemp, PublicKey + 64 * index[1], 64);

    // B i=1
    point_setup((point_affine *)publicTemp, TempExtproj);
    R1_to_R3(TempExtproj, TempExtprojPre);
    eccadd(TempExtprojPre, AddedExtproj);
    add_mod_order((digit_t *)secretTemp, (digit_t *)secretTemp2, S);

    for (k = 0; k < BPV_k - 2; k++)
    {
        // A i=2 to bpv_k
        index[k + 2] = BPV_n * index[k + 2] / 256;
        memmove(secretTemp, SecretKey + 32 * index[k + 2], 32);
        memmove(publicTemp, PublicKey + 64 * index[k + 2], 64);

        // B i=2 to bpv_k
        point_setup((point_affine *)publicTemp, TempExtproj);
        R1_to_R3(TempExtproj, TempExtprojPre);
        eccadd(TempExtprojPre, AddedExtproj);
        add_mod_order((digit_t *)secretTemp, S, S);
    }

    //eccnorm(AddedExtproj, (point_affine*)lastPublic);
    eccnorm(AddedExtproj, Added);
    encode(Added, lastPublic);

    return ECCRYPTO_SUCCESS;

cleanup:
    return Status;
}

ECCRYPTO_STATUS BPVSchnorr_Sign(const unsigned char *AllSecretKey, const unsigned char *AllPublicKey, const unsigned char *SecretKey, const unsigned char *PublicKey, const unsigned char *Message, const unsigned int SizeMessage, unsigned char *Signature)
{
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
    unsigned char k[32], r[32], h[64], *temp = NULL;
    digit_t *H = (digit_t *)h;
    digit_t *S = (digit_t *)(Signature + 32);

    BPVOnline(AllSecretKey, AllPublicKey, k, r);

    temp = (unsigned char *)calloc(1, SizeMessage + 32);
    if (temp == NULL)
    {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }

    memmove(temp, r, 32);
    memmove(temp + 32, Message, SizeMessage);

    if (CryptoHashFunction(temp, SizeMessage + 32, h) != 0)
    {
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }

    modulo_order(H, H);
    memmove(Signature, h, 32);

    to_Montgomery((digit_t *)SecretKey, S); // Converting to Montgomery representation
    to_Montgomery(H, H);                    // Converting to Montgomery representation
    Montgomery_multiply_mod_order(S, H, S);
    from_Montgomery(S, S); // Converting back to standard representation
    subtract_mod_order((digit_t *)r, S, S);
    Status = ECCRYPTO_SUCCESS;

    return Status;

cleanup:
    return Status;
}

ECCRYPTO_STATUS BPVSchnorr_Verify(const unsigned char *PublicKey, const unsigned char *Message, const unsigned int SizeMessage, const unsigned char *Signature, unsigned int *valid)
{
    ECCRYPTO_STATUS Status = ECCRYPTO_ERROR_UNKNOWN;
    point_t A;
    unsigned char *temp, h[64], r[32];
    digit_t *H = (digit_t *)h;
    unsigned int i;

    *valid = false;

    temp = (unsigned char *)calloc(1, SizeMessage + 32);
    if (temp == NULL)
    {
        Status = ECCRYPTO_ERROR_NO_MEMORY;
        goto cleanup;
    }

    Status = decode(PublicKey, A); // Also verifies that A is on the curve. If it is not, it fails
    if (Status != ECCRYPTO_SUCCESS)
    {
        goto cleanup;
    }

    memmove(r, Signature, 32);

    Status = ecc_mul_double((digit_t *)(Signature + 32), A, (digit_t *)r, A);
    if (Status != ECCRYPTO_SUCCESS)
    {
        goto cleanup;
    }

    encode(A, r);

    memmove(temp, r, 32);
    memmove(temp + 32, Message, SizeMessage);

    if (CryptoHashFunction(temp, SizeMessage + 32, h) != 0)
    {
        Status = ECCRYPTO_ERROR;
        goto cleanup;
    }
    modulo_order(H, H);

    for (i = 0; i < NWORDS_ORDER; i++)
    {
        if (((digit_t *)h)[i] != ((digit_t *)Signature)[i])
        {
            goto cleanup;
        }
    }
    *valid = true;

    return Status;
cleanup:
    return Status;
}
