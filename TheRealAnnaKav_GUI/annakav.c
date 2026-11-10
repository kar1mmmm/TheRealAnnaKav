#include "headerUndUtil/sha.h"


int main(){
      annaInitPaths(); //resolve db/, log.bin, quarantine/, scan root before any chdir()
      if (hmload() == -1){
            return 1;
      }
      for (uint j = 0 ; j < hmCapacity; j++){
            if (hashtable[j] != NULL){
                  printf("%u | sha of %s  = " , j, hashtable[j]->name);
                  for (int i = 0; i < 8; i++ ){
                        printf("%08x", hashtable[j]->sha[i]);
                  }
            }
            else{
                  printf("%u | UNALLOCATED", j);
            }
            printf("\n");
      }
      WAFPrev();
      startWalking();
      Checkpoint();
      return 0;
}
