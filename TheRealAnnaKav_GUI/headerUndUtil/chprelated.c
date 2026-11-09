#include <time.h>
#include <limits.h>
#include "./sha.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

//Path configuration (v0.1.4 fix: no more hardcoded /home/draco/... paths)
//Every path is resolved ONCE to an absolute path, before anything calls chdir(),
//so hmload()/dfsWalker() changing the cwd can't break them anymore.
//
//  ANNAKAV_DB         -> signature folder   (default: <start dir>/db/)
//  ANNAKAV_LOG        -> checkpoint file    (default: <start dir>/log.bin)
//  ANNAKAV_SCAN_ROOT  -> folder to walk     (default: $HOME, or / if unset)
static char dbDir[PATH_MAX];
static char logPath[PATH_MAX];
static char scanRoot[PATH_MAX];
static int pathsReady = 0;

static void pickPath(char *dst, const char *envName, const char *base, const char *suffix){
      const char *env = getenv(envName);
      if (env != NULL && env[0] != '\0'){
            snprintf(dst, PATH_MAX, "%s", env);
      }
      else{
            snprintf(dst, PATH_MAX, "%s/%s", base, suffix);
      }
}

void annaInitPaths(){
      if (pathsReady) return;

      char cwd[PATH_MAX];
      if (getcwd(cwd, sizeof(cwd)) == NULL){
            perror("annaInitPaths: getcwd failed, using \".\"");
            snprintf(cwd, sizeof(cwd), ".");
      }

      pickPath(dbDir, "ANNAKAV_DB", cwd, "db/");
      pickPath(logPath, "ANNAKAV_LOG", cwd, "log.bin");

      const char *root = getenv("ANNAKAV_SCAN_ROOT");
      if (root == NULL || root[0] == '\0') root = getenv("HOME");
      if (root == NULL || root[0] == '\0') root = "/";
      snprintf(scanRoot, sizeof(scanRoot), "%s", root);

      pathsReady = 1;
}

const char * annaDbDir(){
      annaInitPaths();
      return dbDir;
}

const char * annaLogPath(){
      annaInitPaths();
      return logPath;
}

const char * annaScanRoot(){
      annaInitPaths();
      return scanRoot;
}

void Checkpoint(){
      time_t local = time(NULL);
      //fix: O_CREAT needs a mode argument, and O_TRUNC so old data is overwritten
      int Fp = open(annaLogPath(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (Fp == -1) {
            perror("An error encountered while trying to open the file from checkpoint func");
            return;
      }
      if (write(Fp, &local, sizeof(local)) != (ssize_t)sizeof(local)){
            perror("Checkpoint: failed to write log.bin");
      }
      close(Fp);
}

time_t readCheckpoint(){
      time_t readloc = 0;
      //fix: read from the same file Checkpoint() writes to
      int Fp = open(annaLogPath(), O_RDONLY);
      if (Fp == -1) {
            perror("An error encountered while trying to open the file from reading function");
            return 0;
      }
      if (read(Fp, &readloc, sizeof(time_t)) != (ssize_t)sizeof(time_t)){
            readloc = 0;   //empty / corrupted log.bin -> treat as "never scanned"
      }
      close(Fp);
      return readloc;
}
