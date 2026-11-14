#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <omp.h>

#define ROTL(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define F(x,y,z) (((x)&(y))|(~(x)&(z)))
#define G(x,y,z) (((x)&(z))|((y)&~(z)))
#define H(x,y,z) ((x)^(y)^(z))
#define I(x,y,z) ((y)^((x)|~(z)))
#define STEP(f,a,b,c,d,x,s,ac){a+=f(b,c,d)+x+ac;a=ROTL(a,s);a+=b;}
static inline void md5block(const uint32_t M[16], uint8_t out[16]){
  uint32_t a=0x67452301,b=0xefcdab89,c=0x98badcfe,d=0x10325476;
  STEP(F,a,b,c,d,M[0],7,0xd76aa478)STEP(F,d,a,b,c,M[1],12,0xe8c7b756)STEP(F,c,d,a,b,M[2],17,0x242070db)STEP(F,b,c,d,a,M[3],22,0xc1bdceee)
  STEP(F,a,b,c,d,M[4],7,0xf57c0faf)STEP(F,d,a,b,c,M[5],12,0x4787c62a)STEP(F,c,d,a,b,M[6],17,0xa8304613)STEP(F,b,c,d,a,M[7],22,0xfd469501)
  STEP(F,a,b,c,d,M[8],7,0x698098d8)STEP(F,d,a,b,c,M[9],12,0x8b44f7af)STEP(F,c,d,a,b,M[10],17,0xffff5bb1)STEP(F,b,c,d,a,M[11],22,0x895cd7be)
  STEP(F,a,b,c,d,M[12],7,0x6b901122)STEP(F,d,a,b,c,M[13],12,0xfd987193)STEP(F,c,d,a,b,M[14],17,0xa679438e)STEP(F,b,c,d,a,M[15],22,0x49b40821)
  STEP(G,a,b,c,d,M[1],5,0xf61e2562)STEP(G,d,a,b,c,M[6],9,0xc040b340)STEP(G,c,d,a,b,M[11],14,0x265e5a51)STEP(G,b,c,d,a,M[0],20,0xe9b6c7aa)
  STEP(G,a,b,c,d,M[5],5,0xd62f105d)STEP(G,d,a,b,c,M[10],9,0x02441453)STEP(G,c,d,a,b,M[15],14,0xd8a1e681)STEP(G,b,c,d,a,M[4],20,0xe7d3fbc8)
  STEP(G,a,b,c,d,M[9],5,0x21e1cde6)STEP(G,d,a,b,c,M[14],9,0xc33707d6)STEP(G,c,d,a,b,M[3],14,0xf4d50d87)STEP(G,b,c,d,a,M[8],20,0x455a14ed)
  STEP(G,a,b,c,d,M[13],5,0xa9e3e905)STEP(G,d,a,b,c,M[2],9,0xfcefa3f8)STEP(G,c,d,a,b,M[7],14,0x676f02d9)STEP(G,b,c,d,a,M[12],20,0x8d2a4c8a)
  STEP(H,a,b,c,d,M[5],4,0xfffa3942)STEP(H,d,a,b,c,M[8],11,0x8771f681)STEP(H,c,d,a,b,M[11],16,0x6d9d6122)STEP(H,b,c,d,a,M[14],23,0xfde5380c)
  STEP(H,a,b,c,d,M[1],4,0xa4beea44)STEP(H,d,a,b,c,M[4],11,0x4bdecfa9)STEP(H,c,d,a,b,M[7],16,0xf6bb4b60)STEP(H,b,c,d,a,M[10],23,0xbebfbc70)
  STEP(H,a,b,c,d,M[13],4,0x289b7ec6)STEP(H,d,a,b,c,M[0],11,0xeaa127fa)STEP(H,c,d,a,b,M[3],16,0xd4ef3085)STEP(H,b,c,d,a,M[6],23,0x04881d05)
  STEP(H,a,b,c,d,M[9],4,0xd9d4d039)STEP(H,d,a,b,c,M[12],11,0xe6db99e5)STEP(H,c,d,a,b,M[15],16,0x1fa27cf8)STEP(H,b,c,d,a,M[2],23,0xc4ac5665)
  STEP(I,a,b,c,d,M[0],6,0xf4292244)STEP(I,d,a,b,c,M[7],10,0x432aff97)STEP(I,c,d,a,b,M[14],15,0xab9423a7)STEP(I,b,c,d,a,M[5],21,0xfc93a039)
  STEP(I,a,b,c,d,M[12],6,0x655b59c3)STEP(I,d,a,b,c,M[3],10,0x8f0ccc92)STEP(I,c,d,a,b,M[10],15,0xffeff47d)STEP(I,b,c,d,a,M[1],21,0x85845dd1)
  STEP(I,a,b,c,d,M[8],6,0x6fa87e4f)STEP(I,d,a,b,c,M[15],10,0xfe2ce6e0)STEP(I,c,d,a,b,M[6],15,0xa3014314)STEP(I,b,c,d,a,M[13],21,0x4e0811a1)
  STEP(I,a,b,c,d,M[4],6,0xf7537e82)STEP(I,d,a,b,c,M[11],10,0xbd3af235)STEP(I,c,d,a,b,M[2],15,0x2ad7d2bb)STEP(I,b,c,d,a,M[9],21,0xeb86d391)
  uint32_t st[4];
  st[0]=0x67452301u+a; st[1]=0xefcdab89u+b; st[2]=0x98badcfeu+c; st[3]=0x10325476u+d;
  memcpy(out,st,16);
}

#define MAXT 4096
static int NT;
static int T_G[MAXT];
static uint32_t T_V[MAXT];
static int T_M[MAXT];          // bitmask of fixed bytes
static uint32_t T_KEY[MAXT];   // little-endian value of 4 bytes (for full)

static const char *sufs[4]={"GpLaMjEW","pVOjnnmk","RGiledp6","Mvcezxls"};
static const int offs[4]={8,2,7,1};
static uint32_t M1[4], M2[4];

static volatile uint32_t foundPre[MAXT];
static volatile int foundFlag[MAXT];

int main(int argc,char**argv){
  FILE*f=fopen("/tmp/opencode/targets.txt","r");
  char b[4][8];
  while(fscanf(f,"%d %7s %7s %7s %7s",&T_G[NT],b[0],b[1],b[2],b[3])==5){
    uint32_t v=0; int m=0; uint32_t key=0;
    for(int j=0;j<4;j++){
      if(strcmp(b[j],"??")==0){ /*wild*/ m|=1<<j; }
      else { unsigned x; sscanf(b[j],"%x",&x); v|=((uint32_t)(x&0xff))<<(8*j); key|=((uint32_t)(x&0xff))<<(8*j); }
    }
    T_V[NT]=v; T_M[NT]=m; T_KEY[NT]=key; foundFlag[NT]=0; foundPre[NT]=0xffffffffu; NT++;
  }
  fclose(f);
  fprintf(stderr,"NT=%d\n",NT);
  for(int g=0;g<4;g++){ const unsigned char*s=(const unsigned char*)sufs[g];
    M1[g]=s[0]|(s[1]<<8)|(s[2]<<16)|((uint32_t)s[3]<<24);
    M2[g]=s[4]|(s[5]<<8)|(s[6]<<16)|((uint32_t)s[7]<<24); }

  for(int g=0;g<4;g++){
    // build this group's target indices
    int idxs[MAXT]; int n=0;
    for(int i=0;i<NT;i++) if(T_G[i]==g) idxs[n++]=i;
    // hash table for full masks (T_M==0)
    int H=8192; while(H<4*n+16)H<<=1;
    uint32_t *keys=malloc(sizeof(uint32_t)*H);
    int *vals=malloc(sizeof(int)*H);
    for(int i=0;i<H;i++){keys[i]=0xffffffffu;vals[i]=-1;}
    int nfull=0;
    for(int t=0;t<n;t++){ int i=idxs[t]; if(T_M[i]!=0) continue; nfull++;
      uint32_t k=T_KEY[i];
      int h=(k*2654435761u)&(H-1);
      while(keys[h]!=0xffffffffu) h=(h+1)&(H-1);
      keys[h]=k; vals[h]=i; }
    // partial list
    int pidxs[MAXT]; int np=0;
    for(int t=0;t<n;t++){ int i=idxs[t]; if(T_M[i]!=0) pidxs[np++]=i; }
    fprintf(stderr,"group %d: n=%d full=%d partial=%d\n",g,n,nfull,np);
    #pragma omp parallel
    {
      #pragma omp for schedule(static)
      for(int a=1;a<256;a++){ if(a==10)continue;
        for(int b=1;b<256;b++){ if(b==10)continue;
          for(int c=1;c<256;c++){ if(c==10)continue;
            for(int d=1;d<256;d++){ if(d==10)continue;
              uint32_t M[16]={0};
              M[0]=((uint32_t)a)|((uint32_t)b<<8)|((uint32_t)c<<16)|((uint32_t)d<<24);
              M[1]=M1[g]; M[2]=M2[g]; M[3]=0x00000080u; M[14]=0x60;
              uint8_t out[16]; md5block(M,out);
              int o=offs[g];
              uint32_t dg=out[o]|(out[o+1]<<8)|(out[o+2]<<16)|((uint32_t)out[o+3]<<24);
              // full lookup
              if(nfull){
                int h=(dg*2654435761u)&(H-1);
                while(keys[h]!=0xffffffffu){
                  if(keys[h]==dg){ int ti=vals[h];
                    if(!foundFlag[ti]){ foundFlag[ti]=1; foundPre[ti]=M[0];
                      #pragma omp critical
                      { printf("F %d %08x\n",ti,M[0]); fflush(stdout); }
                    }
                    break; }
                  h=(h+1)&(H-1);
                }
              }
              // partial
              for(int t=0;t<np;t++){ int ti=pidxs[t]; if(foundFlag[ti]) continue;
                int mm=T_M[ti]; uint32_t vv=T_V[ti]; int ok=1;
                for(int j=0;j<4;j++) if(!((mm>>j)&1)){ if(out[o+j]!=((vv>>(8*j))&0xff)){ok=0;break;} }
                if(ok){ foundFlag[ti]=1; foundPre[ti]=M[0];
                  #pragma omp critical
                  { printf("F %d %08x\n",ti,M[0]); fflush(stdout); }
                }
              }
            }
          }
        }
      }
    }
    free(keys); free(vals);
  }
  fprintf(stderr,"done\n");
  return 0;
}
