#include "headerUndUtil/sha.h"


int main(){
      annaInitPaths(); //resolve db/, log.bin, scan root before any chdir()
      if (hmload() == -1){
            return 1;
      }
      for (int j = 0 ; j < SL; j++){
            if (hashtable[j] != NULL){
                  printf("%d | sha of %s  = " , j, hashtable[j]->name);
                  for (int i = 0; i < 8; i++ ){
                        printf("%08x", hashtable[j]->sha[i]);
                  }
            }

            else{
                  printf("%d | UNALLOCATED", j);
            }
            printf("\n");
      }
      WAFPrev();
      startWalking();
      Checkpoint();
      return 0;
}
