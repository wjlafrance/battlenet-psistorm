#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
typedef int (*CR)(const char*, const char*, const char*, const char*, unsigned long*, unsigned long*, char*);
static int hexval(char c){return c>='0'&&c<='9'?c-'0':(c|32)-'a'+10;}
int main(int argc,char**argv){
  if(argc<6){fprintf(stderr,"usage: %s lib file1 file2 file3 valuestring_hex\n",argv[0]);return 2;}
  void*h=dlopen(argv[1],RTLD_NOW); if(!h){fprintf(stderr,"dlopen: %s\n",dlerror());return 3;}
  CR f=(CR)dlsym(h,"CheckRevision"); if(!f){fprintf(stderr,"dlsym: %s\n",dlerror());return 4;}
  char vs[512]; memset(vs,0,sizeof vs); size_t n=strlen(argv[5])/2; for(size_t i=0;i<n;i++) vs[i]=(char)(hexval(argv[5][2*i])<<4|hexval(argv[5][2*i+1]));
  unsigned long ver=0xdeadbeef, chk=0xdeadbeef; char info[1024]; memset(info,0,sizeof info);
  int r=f(argv[2],argv[3],argv[4],vs,&ver,&chk,info);
  printf("ret=%d version=%08lx checksum=%08lx info=",r,ver&0xffffffffUL,chk&0xffffffffUL);
  for(size_t i=0;i<strlen(info);i++) printf("%02x",(unsigned char)info[i]);
  printf("\n"); return 0;}
