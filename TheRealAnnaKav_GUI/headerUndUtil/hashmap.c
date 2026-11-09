#include "sha.h"
#include <dirent.h>
#include <string.h>
hashed *hashtable[SL];
//This index hashing value is a homework for me 
//It wasn't the most effective one 
//Effective In context of what?
//i don't know
uint Ihash(u32t * sha){
      uint hashval = 0;
      for (int i = 0; i < 8; i++){
            hashval += (sha[i] * 3);
      }
      return hashval;
}


void insertToHm(u32t * sha, char *name){
      hashed * data = malloc(sizeof(hashed));
      uint index,counter;
      index = Ihash(sha) % SL;
      counter = 0;
      data->name = strdup(name);

      for (int i = 0 ; i < 8 ; i++){
            data->sha[i] = sha[i];
      }

      check:

      if (counter == SL){
            printf("ALERT:HASHMAP IS FULL\n");
            free(data->name);
            free(data);
            goto end;
      }
      if (hashtable[index] != NULL){
            index+= 1;
            if (index >= SL){
                  index = 0;
            }
            counter += 1;
            goto check;
      }

      hashtable[index] = data;

      end: ; //empty statement: a label right before '}' is an error before C23
}

hashed * get(u32t * sha){
      hashed * target = NULL; //was malloc'd then overwritten -> leaked on every lookup
      uint t = Ihash(sha) % SL;
      uint count = 0;
      //verify
      while(count < SL ){
            if (hashtable[t] != NULL){
                  int x =0;
                  for (int i = 0; i < 8; i++ ){
                        if(sha[i] != hashtable[t]->sha[i]){
                              break;
                        }
                        else{
                              x++;
                        }
                  }

                  if (x==8){
                        target = hashtable[t];
                        return target;
                  }
            }
            t++;

            if (t >= SL) t = 0;
            count++;
      }

      //no HM doesn't contain the item
      return NULL;
}

//named this main function to hmload later
//At the end of any coding session, i think it's a must for me to recap what've i done. (2026-10-15)
int hmload(){
      u32t shafile[8];
      u32t new[8];

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

      while(entry = readdir(dir)){
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0){
                  continue;
            }


            int Fp = open(entry->d_name, O_RDONLY);
            if (Fp == -1 ){
                  printf("ERROR: can't open %s\n", entry->d_name);
                  continue;
            }

            //fix: read exactly 8 words (32 bytes). The old loop kept reading
            //until EOF and wrote past shafile[7] for files bigger than 32 bytes.
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

      /*
      hashed * data = get(new);
      if (data != NULL){
            for (int i = 0 ; i < 8; i++){
                  printf("%08x", data->sha[i]);
            }
            printf("\n");
      }

      else{
            printf("Item doesn't exist in hashmap\n");
      }
      */
      closedir(dir);
      return 0;
}
