/*
 * hotp.h
 *
 * Created: 10.05.2023 10:38:09
 */

#ifndef HOTP_H
#define HOTP_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
// #include <math.h>

#define OUTPUTLENGHT 20
#define BLOCKSIZE 64

/* We want exact 32bits; uint_fast32_t sometimes assign a type larger than 32bits */
#define SHA1_WORD uint32_t

SHA1_WORD sha1_f(uint8_t t, SHA1_WORD B, SHA1_WORD C, SHA1_WORD D)
{
  if (t <= 19)
  {
    return (B & C) | ((~B) & D);
  }
  else if (t <= 39)
  {
    return B ^ C ^ D;
  }
  else if (t <= 59)
  {
    return (B & C) | (B & D) | (C & D);
  }
  else if (t <= 79)
  {
    return B ^ C ^ D;
  }

  exit(1); // impossible case
}

SHA1_WORD sha1_K(uint8_t t)
{
  if (t <= 19)
  {
    return 0x5A827999;
  }
  else if (t <= 39)
  {
    return 0x6ED9EBA1;
  }
  else if (t <= 59)
  {
    return 0x8F1BBCDC;
  }
  else
  {
    return 0xCA62C1D6;
  }

  exit(2); // impossible case
}

SHA1_WORD sha1_Sn(SHA1_WORD X, uint8_t n)
{
  return (X << n) | (X >> (32 - n));
}

// return copy of array that is padded
uint8_t *sha1_pad(const void *msg, size_t size, size_t *newSize)
{
  if (!msg)
  {
    return 0;
  }

  size_t toPad = 64 - (size % 64);
  if (toPad < 9)
  { // spillover
    toPad += 64;
  }

  uint8_t *newArr = (uint8_t *)malloc(size + toPad);
  memcpy(newArr, msg, size);
  newArr[size] = 0x80;
  memset(newArr + size + 1, 0x00, toPad - 8); // -8 for 2 words at the back

  /*
   * This code relies too much on the endianess of the system, so we won't be using it
   * uint64_t* ref = (uint64_t*) (newArr + size + toPad - 8);
   * ref = size * 8;
   */

  const uint64_t sizeInBits = size * 8;
  const uint8_t ptr = size + toPad - 8;
  newArr[ptr] = sizeInBits >> 56;
  newArr[ptr + 1] = sizeInBits >> 48;
  newArr[ptr + 2] = sizeInBits >> 40;
  newArr[ptr + 3] = sizeInBits >> 32;
  newArr[ptr + 4] = sizeInBits >> 24;
  newArr[ptr + 5] = sizeInBits >> 16;
  newArr[ptr + 6] = sizeInBits >> 8;
  newArr[ptr + 7] = sizeInBits;

  if (newSize)
  {
    *newSize = size + toPad;
  }

  return newArr;
}

uint8_t *sha1(const void *msg, size_t size)
{
  SHA1_WORD MASK = 0x0000000F;
  SHA1_WORD h0 = 0x67452301;
  SHA1_WORD h1 = 0xefcdab89;
  SHA1_WORD h2 = 0x98badcfe;
  SHA1_WORD h3 = 0x10325476;
  SHA1_WORD h4 = 0xc3d2e1f0;

  size_t messageSize = 0;
  uint8_t *message = sha1_pad(msg, size, &messageSize);
  for (int i = 0; i < messageSize; i += 64)
  {
    int t = 0;
    uint8_t *block = message + i;
    SHA1_WORD W[80];

    for (t = 0; t < 16; t++)
    {
      W[t] = block[t * 4] << 24;
      W[t] |= block[t * 4 + 1] << 16;
      W[t] |= block[t * 4 + 2] << 8;
      W[t] |= block[t * 4 + 3];
    }

    SHA1_WORD A = h0;
    SHA1_WORD B = h1;
    SHA1_WORD C = h2;
    SHA1_WORD D = h3;
    SHA1_WORD E = h4;
    SHA1_WORD TEMP;

    for (t = 0; t < 80; t++)
    {
      int s = t & MASK;
      if (t >= 16)
      {
        W[s] = sha1_Sn(W[(s + 13) & MASK] ^ W[(s + 8) & MASK] ^ W[(s + 2) & MASK] ^ W[s], 1);
      }

      TEMP = sha1_Sn(A, 5) + sha1_f(t, B, C, D) + E + W[s] + sha1_K(t);

      E = D;
      D = C;
      C = sha1_Sn(B, 30);
      B = A;
      A = TEMP;
    }

    h0 += A;
    h1 += B;
    h2 += C;
    h3 += D;
    h4 += E;
  }

  free(message);

  uint8_t *retVal = (uint8_t *)malloc(20);
  SHA1_WORD *retValView = (SHA1_WORD *)retVal;
  retValView[0] = h0;
  retValView[1] = h1;
  retValView[2] = h2;
  retValView[3] = h3;
  retValView[4] = h4;

  for (int i = 0; i < 5; i++)
  {
    SHA1_WORD temp = retValView[i];
    retVal[i * 4] = temp >> 24;
    retVal[i * 4 + 1] = temp >> 16;
    retVal[i * 4 + 2] = temp >> 8;
    retVal[i * 4 + 3] = temp;
  }

  return retVal;
}

uint8_t *hmac_pad(uint8_t *input, size_t size, size_t blockSize)
{
  uint8_t *retVal = (uint8_t *)malloc(blockSize);
  memcpy(retVal, input, size);
  memset(retVal + size, 0x00, blockSize - size);

  return retVal;
}

uint8_t *hmac(const void *msg, size_t size, const void *K, size_t keySize, size_t blockSize, size_t outputLength)
{
  uint8_t *workingKey = (uint8_t *)K;

  if (keySize > blockSize)
  {
    uint8_t *temp = sha1(K, keySize);
    workingKey = hmac_pad(temp, outputLength, blockSize);
    free(temp);
  }
  else
  {
    workingKey = hmac_pad(workingKey, keySize, blockSize);
  }

  uint8_t *intermediate1 = (uint8_t *)malloc(blockSize);
  uint8_t *intermediate2 = (uint8_t *)malloc(blockSize);
  for (int i = 0; i < blockSize; i++)
  {
    intermediate1[i] = workingKey[i] ^ 0x36;
    intermediate2[i] = workingKey[i] ^ 0x5c;
  }

  uint8_t *intermediate3 = (uint8_t *)malloc(blockSize + size);
  memcpy(intermediate3, intermediate1, blockSize);
  memcpy(intermediate3 + blockSize, msg, size);

  uint8_t *intermediate4 = sha1(intermediate3, blockSize + size);
  uint8_t *intermediate5 = (uint8_t *)malloc(blockSize + outputLength);
  memcpy(intermediate5, intermediate2, blockSize);
  memcpy(intermediate5 + blockSize, intermediate4, outputLength);

  uint8_t *result = sha1(intermediate5, blockSize + outputLength);
  free(intermediate1);
  free(intermediate2);
  free(intermediate3);
  free(intermediate4);
  free(intermediate5);
  free(workingKey);

  return result;
}

uint32_t hotp_DT(const uint8_t *data, size_t len)
{
  uint8_t offset = data[len - 1] & 0x0f;
  uint32_t p = (data[offset] & 0x7f) << 24 | data[offset + 1] << 16 | data[offset + 2] << 8 | data[offset + 3];

  return p;
}

uint32_t hotp(uint8_t digits, char *secret, size_t secretSize, uint64_t hCounter)
{

  uint8_t counter[8];
  counter[0] = hCounter >> 56;
  counter[1] = hCounter >> 48;
  counter[2] = hCounter >> 40;
  counter[3] = hCounter >> 32;
  counter[4] = hCounter >> 24;
  counter[5] = hCounter >> 16;
  counter[6] = hCounter >> 8;
  counter[7] = hCounter;

  uint8_t *hs = hmac(counter, sizeof(counter), secret, secretSize, BLOCKSIZE, OUTPUTLENGHT);

  uint32_t Snum = hotp_DT(hs, OUTPUTLENGHT);
  free(hs);

  // return Snum % (uint32_t)pow(10.0, digits);
  if(digits == 6) {
	return Snum % (uint32_t)1000000.0;
  } else {	
	return Snum % (uint32_t)100000000.0; //8 digits
  }
}

#endif
