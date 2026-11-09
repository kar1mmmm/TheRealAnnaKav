#include "sha.h"
#include <errno.h>

const u32t H2[64] = { 
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2  
};


unsigned char * Greg_bitLOC(unsigned char * Sinput, int len, u64t Tot){
      //fix: 55 bytes of data + 0x80 + 8 bytes length still fit in one block,
      //so only 56..64 bytes need an extra length block (was len > 54)
      if(len > 55){
            unsigned char * gBIT = calloc(64, 1); 
            for (int i = 0 ; i < len; i++){
                  gBIT[i] = Sinput[i];
            }

            if (len == 64) return gBIT;

            else {
                  int end = 64 - len;
                  gBIT[64 - end] = 0x80;
                  return gBIT;
            }
      }

      else if (len == 0){
            unsigned char * gBIT = calloc(64, 1); 
            u64t bitLen = Tot * 8;
            gBIT[56] = (bitLen >> 56) & 0xFF;
            gBIT[57] = (bitLen >> 48) & 0xFF;
            gBIT[58] = (bitLen >> 40) & 0xFF;
            gBIT[59] = (bitLen >> 32) & 0xFF;
            gBIT[60] = (bitLen >> 24) & 0xFF;
            gBIT[61] = (bitLen >> 16) & 0xFF;
            gBIT[62] = (bitLen >> 8)  & 0xFF;
            gBIT[63] = (bitLen)       & 0xFF; 

            return gBIT;
      }


      unsigned char * gBIT= calloc(64, 1); 
      gBIT[len] = 0x80 ;

      for (int i = 0; i < len; i++){
            gBIT[i] = Sinput[i];
      }

      u64t bitLen = Tot * 8;
      gBIT[56] = (bitLen >> 56) & 0xFF;
      gBIT[57] = (bitLen >> 48) & 0xFF;
      gBIT[58] = (bitLen >> 40) & 0xFF;
      gBIT[59] = (bitLen >> 32) & 0xFF;
      gBIT[60] = (bitLen >> 24) & 0xFF;
      gBIT[61] = (bitLen >> 16) & 0xFF;
      gBIT[62] = (bitLen >> 8)  & 0xFF;
      gBIT[63] = (bitLen)       & 0xFF; 

      return gBIT;
}

u32t *wordCOME(unsigned char *gBIT){
      u32t *word = malloc(64 * sizeof(u32t));
      
      for (int i = 0 ; i < 16; i++){
            word[i] = (u32t) gBIT[i*4]   << 24 |
                      (u32t) gBIT[i*4+1] << 16 |
                      (u32t) gBIT[i*4+2] << 8  |
                      (u32t) gBIT[i*4+3];
      }

      for (int i = 16; i < 64; i++){
            word[i] = Sigma1(word[i-2]) + word[i-7] + Sigma0(word[i-15]) + word[i-16];
      }

      return word;
}

u32t * sha256(unsigned char * hasi, size_t len, u64t fs){

      u32t * H = malloc(8 * sizeof(u32t));
      H[0] = 0x6a09e667;
      H[1] = 0xbb67ae85;
      H[2] = 0x3c6ef372;
      H[3] = 0xa54ff53a;
      H[4] = 0x510e527f;
      H[5] = 0x9b05688c;
      H[6] = 0x1f83d9ab;
      H[7] = 0x5be0cd19;

      unsigned char * gBITmain = Greg_bitLOC(hasi, len, fs);
      u32t *actualwordTS = wordCOME(gBITmain);

      u32t a,b,c,d,e,f,g,j;
      a = H[0];
      b = H[1];
      c = H[2];
      d = H[3];
      e = H[4];
      f = H[5];
      g = H[6];
      j = H[7];

      for (int i = 0 ; i < 64; i++){
            u32t T1 = j + smallSig1(e) + GCH(e, f, g) + H2[i] + actualwordTS[i];
            u32t T2 = smallSig0(a) + MAAAYOR(a, b, c);
            j = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
      }

      H[0] += a;
      H[1] += b;
      H[2] += c;
      H[3] += d;
      H[4] += e;
      H[5] += f;
      H[6] += g;
      H[7] += j;

      free(gBITmain);
      free(actualwordTS);
      return H;
}

u32t * MultiSha (unsigned char * hasi, u32t * H, size_t len, u64t fs){
      unsigned char * gBITmain = Greg_bitLOC(hasi, len, fs);
      u32t *actualwordTS = wordCOME(gBITmain);

      u32t a,b,c,d,e,f,g,j;
      a = H[0];
      b = H[1];
      c = H[2];
      d = H[3];
      e = H[4];
      f = H[5];
      g = H[6];
      j = H[7];

      for (int i = 0 ; i < 64; i++){
            u32t T1 = j + smallSig1(e) + GCH(e, f, g) + H2[i] + actualwordTS[i];
            u32t T2 = smallSig0(a) + MAAAYOR(a, b, c);
            j = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
      }

      H[0] += a;
      H[1] += b;
      H[2] += c;
      H[3] += d;
      H[4] += e;
      H[5] += f;
      H[6] += g;
      H[7] += j;

      free(gBITmain);
      free(actualwordTS);
      return H;
}


//read() may return less than asked even before EOF, so keep reading until
//we got `want` bytes, hit EOF, or a real error happens.
static ssize_t readFull(int Pp, unsigned char *buf, size_t want){
      size_t got = 0;
      while (got < want){
            ssize_t n = read(Pp, buf + got, want - got);
            if (n == 0) break;            //EOF
            if (n < 0){
                  if (errno == EINTR) continue;
                  return -1;
            }
            got += (size_t)n;
      }
      return (ssize_t)got;
}

//feed one full 64 byte block to the compression function
static u32t * shaBlock(unsigned char *block, u32t *H){
      if (H == NULL) return sha256(block, 64, 0);   //first block -> init H
      return MultiSha(block, H, 64, 0);
}

//Streaming SHA-256 over an open file descriptor.
//Fix for v0.1.4: the old version skipped the final padding block when the
//file size was a multiple of 64, or when the last chunk was 55..63 bytes.
//Now padding (0x80 + 64-bit big endian length) is always appended at the end
//and the length comes from the bytes actually read, not st_size.
static u32t * shaFromFd(int Pp){
      unsigned char block[128];
      u32t *H = NULL;
      u64t total = 0;
      ssize_t n;

      for (;;){
            n = readFull(Pp, block, 64);
            if (n < 0){
                  free(H);
                  return NULL;
            }
            total += (u64t)n;
            if (n < 64) break;            //remaining tail (0..63 bytes)
            H = shaBlock(block, H);
      }

      //padding: 0x80, zeros, then length -> 1 block if tail <= 55, else 2 blocks
      size_t padLen = (n <= 55) ? 64 : 128;
      memset(block + n, 0, sizeof(block) - (size_t)n);
      block[n] = 0x80;

      u64t bitLen = total * 8;
      for (int i = 0; i < 8; i++){
            block[padLen - 1 - i] = (unsigned char)(bitLen >> (8 * i));
      }

      for (size_t off = 0; off < padLen; off += 64){
            H = shaBlock(block + off, H);
      }

      return H;
}

u32t * HashAfile(char * path){
      int Pp = open(path, O_RDONLY);
      if (Pp == -1){
            printf("Can't open the file\t\t This error from Hash a file function\n");
            return NULL;
      }

      u32t * H = shaFromFd(Pp);
      close(Pp);
      return H;
}

u32t * HashAfileByFp(int Pp, struct stat *file ){
      if (file != NULL) fstat(Pp, file);
      return shaFromFd(Pp);
}
