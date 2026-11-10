#include "sha.h"
#include <dirent.h>
#include <string.h>

// v0.1.5: Dynamic Hashmap with automatic 2x resizing at 70% load factor
hashed **hashtable = NULL;
uint hmCapacity = SL;
uint hmCount = 0;

uint Ihash(u32t * sha){
      uint hashval = 0;
      for (int i = 0; i < 8; i++){
            hashval += (sha[i] * 3);
      }
      return hashval;
}

static void initHmTable(uint cap){
      if (hashtable == NULL){
            hmCapacity = cap > 0 ? cap : SL;
            hashtable = calloc(hmCapacity, sizeof(hashed *));
            hmCount = 0;
      }
}

static void resizeHm(uint newCap){
      hashed **oldTable = hashtable;
      uint oldCap = hmCapacity;

      hashtable = calloc(newCap, sizeof(hashed *));
      if (hashtable == NULL){
            hashtable = oldTable;
            return;
      }
      hmCapacity = newCap;
      hmCount = 0;

      for (uint i = 0; i < oldCap; i++){
            if (oldTable[i] != NULL){
                  uint idx = Ihash(oldTable[i]->sha) % hmCapacity;
                  while (hashtable[idx] != NULL){
                        idx = (idx + 1) % hmCapacity;
                  }
                  hashtable[idx] = oldTable[i];
                  hmCount++;
            }
      }
      free(oldTable);
      printf("[Hashmap] Resized capacity %u -> %u\n", oldCap, hmCapacity);
}


void insertToHm(u32t * sha, char *name){
      initHmTable(SL);

      // Resize 2x before load factor exceeds 70%
      if ((hmCount + 1) * 10 >= hmCapacity * 7){
            resizeHm(hmCapacity * 2);
      }

      hashed * data = malloc(sizeof(hashed));
      if (data == NULL) return;
      uint index, counter;
      index = Ihash(sha) % hmCapacity;
      counter = 0;
      data->name = strdup(name);

      for (int i = 0 ; i < 8 ; i++){
            data->sha[i] = sha[i];
      }

      check:

      if (counter == hmCapacity){
            printf("ALERT:HASHMAP IS FULL\n");
            free(data->name);
            free(data);
            goto end;
      }
      if (hashtable[index] != NULL){
            index += 1;
            if (index >= hmCapacity){
                  index = 0;
            }
            counter += 1;
            goto check;
      }

      hashtable[index] = data;
      hmCount++;

      end: ; //empty statement: a label right before '}' is an error before C23
}

hashed * get(u32t * sha){
      if (hashtable == NULL || hmCapacity == 0) return NULL;
      hashed * target = NULL;
      uint t = Ihash(sha) % hmCapacity;
      uint count = 0;
      //verify (stop early if we hit an empty slot during linear probing)
      while(count < hmCapacity && hashtable[t] != NULL){
            int x = 0;
            for (int i = 0; i < 8; i++ ){
                  if(sha[i] != hashtable[t]->sha[i]){
                        break;
                  }
                  else{
                        x++;
                  }
            }

            if (x == 8){
                  target = hashtable[t];
                  return target;
            }
            t = (t + 1) % hmCapacity;
            count++;
      }

      //no HM doesn't contain the item
      return NULL;
}

int hmload(){
      u32t shafile[8];

      // Reset table if reloading
      if (hashtable != NULL){
            for (uint j = 0; j < hmCapacity; j++){
                  if (hashtable[j] != NULL){
                        free(hashtable[j]->name);
                        free(hashtable[j]);
                  }
            }
            free(hashtable);
            hashtable = NULL;
      }
      initHmTable(SL);

      DIR *dir;
      struct dirent *entry;
      const char *db = annaDbDir(); //configurable, see chprelated.c (ANNAKAV_DB)
      dir = opendir(db);
      if (dir == NULL){
            fprintf(stderr, "hmload: can't open db directory %s: ", db);
            perror(NULL);
            return -1;
      }
      if (chdir(db) == -1){
            perror("hmload: chdir to db directory failed");
            closedir(dir);
            return -1;
      }

      while((entry = readdir(dir)) != NULL){
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0){
                  continue;
            }


            int Fp = open(entry->d_name, O_RDONLY);
            if (Fp == -1 ){
                  printf("ERROR: can't open %s\n", entry->d_name);
                  continue;
            }

            //fix: read exactly 8 words (32 bytes).
            unsigned char *dst = (unsigned char *)shafile;
            size_t got = 0;
            while (got < sizeof(shafile)){
                  ssize_t n = read(Fp, dst + got, sizeof(shafile) - got);
                  if (n <= 0) break;
                  got += (size_t)n;
            }

            if (got != sizeof(shafile)){
                  printf("WARNING: %s is not a valid 32 byte signature, skipped\n", entry->d_name);
                  close(Fp);
                  continue;
            }

            insertToHm(shafile, entry->d_name);
            close(Fp);
      }

      closedir(dir);
      return 0;
}
