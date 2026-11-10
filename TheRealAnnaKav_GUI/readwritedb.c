#include <stdio.h>
#include "headerUndUtil/sha.h"
#include <stdint.h>

typedef uint32_t u32t;

int main(int argc, char *argv[]){
      if (argc < 3){
            fprintf(stderr, "Usage: %s <input_file> <output_db_file>\n", argv[0]);
            return 1;
      }

      u32t HforDB[8];
      u32t * H = HashAfile(argv[1]);
      if (H == NULL){
            fprintf(stderr, "Error: failed to hash file %s\n", argv[1]);
            return 1;
      }

      for (int i = 0 ; i < 8 ; i++){
            HforDB[i] = H[i];
            printf("%08x", HforDB[i]);
      }
      printf("\n");

      FILE *binWRITE = fopen(argv[2], "wb");
      if (binWRITE == NULL){
            perror("Error opening output file");
            free(H);
            return 1;
      }

      fwrite(HforDB, sizeof(u32t), 8, binWRITE);
      fclose(binWRITE);
      free(H);

      return 0;
}
