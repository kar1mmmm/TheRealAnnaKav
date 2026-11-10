#include "sha.h"
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <stdlib.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static time_t activeCheckpoint = 0;

// v0.1.5: Quarantine detected malware (strip execute bits and move to quarantine/)
int quarantineFile(const char *filepath, const char *sigName){
      const char *qdir = annaQuarantineDir();
      mkdir(qdir, 0700);

      const char *base = strrchr(filepath, '/');
      base = (base != NULL) ? base + 1 : filepath;

      char dest[PATH_MAX];
      snprintf(dest, sizeof(dest), "%s/%ld_%s.quarantined", qdir, (long)time(NULL), base);

      chmod(filepath, 0000);
      if (rename(filepath, dest) == 0){
            printf("[QUARANTINE] %s (matched %s) -> %s\n", filepath, sigName, dest);
            return 0;
      }
      perror("[QUARANTINE] rename failed");
      return -1;
}

int dfsWalker(char *path){
      DIR *dir;
      struct dirent *entry;
      dir = opendir(path);

      if (dir == NULL){
            printf("can't open %s\n", path);
            return -1;
      }

      if (chdir(path) == -1){
            closedir(dir);
            return -1;
      }

      while((entry = readdir(dir)) != NULL){
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0){
                  continue;
            }

            struct stat file;
            if (lstat(entry->d_name, &file) == -1){
                  continue;
            }

            if (S_ISDIR(file.st_mode)){
                  printf("folder name : %s\n", entry->d_name);
                  dfsWalker(entry->d_name);
            }
            else if (S_ISREG(file.st_mode)){
                  printf("file name : %s\n", entry->d_name);
                  int isExec = (file.st_mode & S_IEXEC) || (file.st_mode & S_IXGRP) || (file.st_mode & S_IXOTH);
                  // v0.1.5: Incremental scan using readCheckpoint()
                  int isNewer = (activeCheckpoint <= 0) || (file.st_mtime > activeCheckpoint);

                  if (isExec && isNewer){
                        u32t * H = HashAfile(entry->d_name);
                        if (H != NULL){
                              hashed * check = get(H);
                              if (check != NULL){
                                    printf("There is something here\n");
                                    printf("file %s is a %s\n", entry->d_name, check->name);
                                    if (getenv("ANNAKAV_AUTO_QUARANTINE") != NULL){
                                          quarantineFile(entry->d_name, check->name);
                                    }
                              }
                        }
                        free(H);
                  }
                  else if (!isExec){
                        printf("%s is not executable\n", entry->d_name);
                  }
                  else{
                        printf("%s unchanged since checkpoint (%ld), skipped\n", entry->d_name, (long)activeCheckpoint);
                  }
            }
      }

      chdir("../");

      if (closedir(dir) == -1){
            printf("Can't close\n");
            return -1;
      }
      return 0;
}


void startWalking(){
      activeCheckpoint = readCheckpoint();
      if (activeCheckpoint > 0){
            printf("[Checkpoint] Incremental scan enabled (last scan epoch: %ld)\n", (long)activeCheckpoint);
      }
      const char *root = annaScanRoot(); //configurable (ANNAKAV_SCAN_ROOT, default $HOME)
      if (chdir(root) == -1){
            fprintf(stderr, "startWalking: can't chdir to %s: ", root);
            perror(NULL);
            return;
      }
      dfsWalker("./");
}

static int askYesNo(){
      char buf[16];
      if (fgets(buf, sizeof(buf), stdin) == NULL) return 0;
      return toupper((unsigned char)buf[0]) == 'Y';
}

void WAFPrev(){
      struct stat cred;
      printf("Checking /etc/passwd permission\n");
      if (stat("/etc/passwd", &cred) == -1){
            perror("WAFPrev: cannot stat /etc/passwd");
      }
      else if (cred.st_mode & (S_IWOTH | S_IWGRP)){
            printf("ALERT: regular user able to write /etc/passwd, would you like change this? (Y/n) ");
            if (askYesNo()){
                  chmod("/etc/passwd", S_IWUSR | S_IRUSR | S_IROTH | S_IRGRP);
                  printf("/etc/passwd permission changed\n");
            }
            else{
                  printf("Do it yourself then scum\n");
            }
      }
      else{
            printf("/etc/passwd permission complying the rule\n");
      }

      printf("Checking /etc/shadow permission\n");
      if (stat("/etc/shadow", &cred) == -1){
            perror("WAFPrev: cannot stat /etc/shadow");
      }
      else if (cred.st_mode & (S_IWOTH | S_IROTH | S_IRGRP | S_IWGRP)){
            printf("ALERT: The /etc/shadow permission is weak, would you like to change it? (Y/n) ");
            if (askYesNo()){
                  chmod("/etc/shadow", S_IWUSR | S_IRUSR);
                  printf("/etc/shadow permission changed\n");
            }
            else{
                  printf("Do it yourself then scum\n");
            }
      }
      else{
            printf("/etc/shadow permission complying the rule\n");
      }
}
