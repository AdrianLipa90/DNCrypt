#include <stdint.h>
#include <stddef.h>
#include <omp.h>
static const uint32_t K[64]={
0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u};
static const uint32_t IV[8]={0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
static inline uint32_t rr(uint32_t x,int n){return (x>>n)|(x<<(32-n));}
static inline uint32_t s0(uint32_t x){return rr(x,7)^rr(x,18)^(x>>3);}static inline uint32_t s1(uint32_t x){return rr(x,17)^rr(x,19)^(x>>10);}static inline uint32_t S0(uint32_t x){return rr(x,2)^rr(x,13)^rr(x,22);}static inline uint32_t S1(uint32_t x){return rr(x,6)^rr(x,11)^rr(x,25);}static inline uint32_t ch(uint32_t x,uint32_t y,uint32_t z){return (x&y)^((~x)&z);}static inline uint32_t maj(uint32_t x,uint32_t y,uint32_t z){return (x&y)^(x&z)^(y&z);}static inline uint32_t bswap(uint32_t x){return __builtin_bswap32(x);}
#define L 16
static inline void comp(const uint32_t in[8][L],uint32_t w[64][L],uint32_t out[8][L]){
 for(int t=16;t<64;t++){
  #pragma GCC ivdep
  for(int j=0;j<L;j++) w[t][j]=w[t-16][j]+s0(w[t-15][j])+w[t-7][j]+s1(w[t-2][j]);
 }
 uint32_t a[L],b[L],c[L],d[L],e[L],f[L],g[L],h[L];
 #pragma GCC ivdep
 for(int j=0;j<L;j++){a[j]=in[0][j];b[j]=in[1][j];c[j]=in[2][j];d[j]=in[3][j];e[j]=in[4][j];f[j]=in[5][j];g[j]=in[6][j];h[j]=in[7][j];}
 for(int t=0;t<64;t++){
  #pragma GCC ivdep
  for(int j=0;j<L;j++){uint32_t t1=h[j]+S1(e[j])+ch(e[j],f[j],g[j])+K[t]+w[t][j];uint32_t t2=S0(a[j])+maj(a[j],b[j],c[j]);h[j]=g[j];g[j]=f[j];f[j]=e[j];e[j]=d[j]+t1;d[j]=c[j];c[j]=b[j];b[j]=a[j];a[j]=t1+t2;}
 }
 #pragma GCC ivdep
 for(int j=0;j<L;j++){out[0][j]=in[0][j]+a[j];out[1][j]=in[1][j]+b[j];out[2][j]=in[2][j]+c[j];out[3][j]=in[3][j]+d[j];out[4][j]=in[4][j]+e[j];out[5][j]=in[5][j]+f[j];out[6][j]=in[6][j]+g[j];out[7][j]=in[7][j]+h[j];}
}
__attribute__((visibility("default"))) void sha256d_vec16_hi64(const uint32_t midstate[8],const uint32_t tail[3],uint32_t start,uint32_t count,uint64_t *out){
 uint32_t in[8][L] __attribute__((aligned(64))), iv[8][L] __attribute__((aligned(64))), w[64][L] __attribute__((aligned(64))), z[64][L] __attribute__((aligned(64))), o1[8][L] __attribute__((aligned(64))),o2[8][L] __attribute__((aligned(64)));
 for(int q=0;q<8;q++)for(int j=0;j<L;j++){in[q][j]=midstate[q];iv[q][j]=IV[q];}
 uint32_t i=0;
 while(i<count){uint32_t rem=count-i; if(rem>L)rem=L;
  for(int j=0;j<L;j++){w[0][j]=tail[0];w[1][j]=tail[1];w[2][j]=tail[2];w[3][j]=bswap(start+i+(uint32_t)j);w[4][j]=0x80000000u;for(int q=5;q<15;q++)w[q][j]=0;w[15][j]=640;}
  comp(in,w,o1);
  for(int j=0;j<L;j++){for(int q=0;q<8;q++)z[q][j]=o1[q][j];z[8][j]=0x80000000u;for(int q=9;q<15;q++)z[q][j]=0;z[15][j]=256;}
  comp(iv,z,o2);
  for(uint32_t j=0;j<rem;j++)out[i+j]=(uint64_t)bswap(o2[6][j])|((uint64_t)bswap(o2[7][j])<<32);
  i+=rem;
 }
}

__attribute__((visibility("default"))) void sha256d_vec16_hi64_omp(const uint32_t midstate[8],const uint32_t tail[3],uint32_t start,uint32_t count,uint64_t *out,int threads){
 if(threads<1) threads=1;
 uint64_t groups=((uint64_t)count+L-1)/L;
 #pragma omp parallel num_threads(threads)
 {
  uint32_t in[8][L] __attribute__((aligned(64))), iv[8][L] __attribute__((aligned(64))), w[64][L] __attribute__((aligned(64))), z[64][L] __attribute__((aligned(64))), o1[8][L] __attribute__((aligned(64))),o2[8][L] __attribute__((aligned(64)));
  for(int q=0;q<8;q++)for(int j=0;j<L;j++){in[q][j]=midstate[q];iv[q][j]=IV[q];}
  #pragma omp for schedule(static)
  for(uint64_t gg=0;gg<groups;gg++){
   uint64_t i64=gg*L; uint32_t i=(uint32_t)i64; uint32_t rem=(uint32_t)(((uint64_t)count-i64)>L?L:((uint64_t)count-i64));
   for(int j=0;j<L;j++){w[0][j]=tail[0];w[1][j]=tail[1];w[2][j]=tail[2];w[3][j]=bswap(start+i+(uint32_t)j);w[4][j]=0x80000000u;for(int q=5;q<15;q++)w[q][j]=0;w[15][j]=640;}
   comp(in,w,o1);
   for(int j=0;j<L;j++){for(int q=0;q<8;q++)z[q][j]=o1[q][j];z[8][j]=0x80000000u;for(int q=9;q<15;q++)z[q][j]=0;z[15][j]=256;}
   comp(iv,z,o2);
   for(uint32_t j=0;j<rem;j++)out[i+j]=(uint64_t)bswap(o2[6][j])|((uint64_t)bswap(o2[7][j])<<32);
  }
 }
}

static inline void comp_ring(const uint32_t in[8][L],uint32_t w[16][L],uint32_t out[8][L]){
 uint32_t a[L],b[L],c[L],d[L],e[L],f[L],g[L],h[L];
 #pragma GCC ivdep
 for(int j=0;j<L;j++){a[j]=in[0][j];b[j]=in[1][j];c[j]=in[2][j];d[j]=in[3][j];e[j]=in[4][j];f[j]=in[5][j];g[j]=in[6][j];h[j]=in[7][j];}
 for(int t=0;t<64;t++){
   int k=t&15;
   if(t>=16){int k15=(t-15)&15,k7=(t-7)&15,k2=(t-2)&15;
     #pragma GCC ivdep
     for(int j=0;j<L;j++) w[k][j]=w[k][j]+s0(w[k15][j])+w[k7][j]+s1(w[k2][j]);
   }
   #pragma GCC ivdep
   for(int j=0;j<L;j++){uint32_t t1=h[j]+S1(e[j])+ch(e[j],f[j],g[j])+K[t]+w[k][j];uint32_t t2=S0(a[j])+maj(a[j],b[j],c[j]);h[j]=g[j];g[j]=f[j];f[j]=e[j];e[j]=d[j]+t1;d[j]=c[j];c[j]=b[j];b[j]=a[j];a[j]=t1+t2;}
 }
 #pragma GCC ivdep
 for(int j=0;j<L;j++){out[0][j]=in[0][j]+a[j];out[1][j]=in[1][j]+b[j];out[2][j]=in[2][j]+c[j];out[3][j]=in[3][j]+d[j];out[4][j]=in[4][j]+e[j];out[5][j]=in[5][j]+f[j];out[6][j]=in[6][j]+g[j];out[7][j]=in[7][j]+h[j];}
}

__attribute__((visibility("default"))) void sha256d_vec16_hi64_ring_omp(const uint32_t midstate[8],const uint32_t tail[3],uint32_t start,uint32_t count,uint64_t *out,int threads){
 if(threads<1) threads=1; uint64_t groups=((uint64_t)count+L-1)/L;
 #pragma omp parallel num_threads(threads)
 {
  uint32_t in[8][L] __attribute__((aligned(64))),ivv[8][L] __attribute__((aligned(64))),w[16][L] __attribute__((aligned(64))),z[16][L] __attribute__((aligned(64))),o1[8][L] __attribute__((aligned(64))),o2[8][L] __attribute__((aligned(64)));
  for(int q=0;q<8;q++)for(int j=0;j<L;j++){in[q][j]=midstate[q];ivv[q][j]=IV[q];}
  #pragma omp for schedule(static)
  for(uint64_t gg=0;gg<groups;gg++){
   uint64_t i64=gg*L; uint32_t i=(uint32_t)i64; uint32_t rem=(uint32_t)(((uint64_t)count-i64)>L?L:((uint64_t)count-i64));
   for(int j=0;j<L;j++){w[0][j]=tail[0];w[1][j]=tail[1];w[2][j]=tail[2];w[3][j]=bswap(start+i+(uint32_t)j);w[4][j]=0x80000000u;for(int q=5;q<15;q++)w[q][j]=0;w[15][j]=640;}
   comp_ring(in,w,o1);
   for(int j=0;j<L;j++){for(int q=0;q<8;q++)z[q][j]=o1[q][j];z[8][j]=0x80000000u;for(int q=9;q<15;q++)z[q][j]=0;z[15][j]=256;}
   comp_ring(ivv,z,o2);
   for(uint32_t j=0;j<rem;j++)out[i+j]=(uint64_t)bswap(o2[6][j])|((uint64_t)bswap(o2[7][j])<<32);
  }
 }
}

__attribute__((visibility("default"))) uint32_t sha256d_vec16_scan_ring_omp(const uint32_t midstate[8],const uint32_t tail[3],uint32_t start,uint32_t count,uint64_t target_hi,uint32_t *candidates,uint32_t cap,int threads){
 if(threads<1)threads=1; uint64_t groups=((uint64_t)count+L-1)/L; uint32_t found=0;
 #pragma omp parallel num_threads(threads)
 {
  uint32_t in[8][L] __attribute__((aligned(64))),ivv[8][L] __attribute__((aligned(64))),w[16][L] __attribute__((aligned(64))),z[16][L] __attribute__((aligned(64))),o1[8][L] __attribute__((aligned(64))),o2[8][L] __attribute__((aligned(64)));
  for(int q=0;q<8;q++)for(int j=0;j<L;j++){in[q][j]=midstate[q];ivv[q][j]=IV[q];}
  #pragma omp for schedule(static)
  for(uint64_t gg=0;gg<groups;gg++){
   uint64_t i64=gg*L; uint32_t i=(uint32_t)i64; uint32_t rem=(uint32_t)(((uint64_t)count-i64)>L?L:((uint64_t)count-i64));
   for(int j=0;j<L;j++){w[0][j]=tail[0];w[1][j]=tail[1];w[2][j]=tail[2];w[3][j]=bswap(start+i+(uint32_t)j);w[4][j]=0x80000000u;for(int q=5;q<15;q++)w[q][j]=0;w[15][j]=640;}
   comp_ring(in,w,o1);
   for(int j=0;j<L;j++){for(int q=0;q<8;q++)z[q][j]=o1[q][j];z[8][j]=0x80000000u;for(int q=9;q<15;q++)z[q][j]=0;z[15][j]=256;}
   comp_ring(ivv,z,o2);
   for(uint32_t j=0;j<rem;j++){
    uint64_t hv=(uint64_t)bswap(o2[6][j])|((uint64_t)bswap(o2[7][j])<<32);
    if(hv<=target_hi){uint32_t slot;
      #pragma omp atomic capture
      slot=found++;
      if(slot<cap)candidates[slot]=start+i+j;
    }
   }
  }
 }
 return found;
}

static inline void comp_ring_split(const uint32_t in[8][L],uint32_t w[16][L],uint32_t out[8][L]){
 uint32_t a[L],b[L],c[L],d[L],e[L],f[L],g[L],h[L];
 #pragma GCC ivdep
 for(int j=0;j<L;j++){a[j]=in[0][j];b[j]=in[1][j];c[j]=in[2][j];d[j]=in[3][j];e[j]=in[4][j];f[j]=in[5][j];g[j]=in[6][j];h[j]=in[7][j];}
 #pragma GCC unroll 16
 for(int t=0;t<16;t++){
   #pragma GCC ivdep
   for(int j=0;j<L;j++){uint32_t t1=h[j]+S1(e[j])+ch(e[j],f[j],g[j])+K[t]+w[t][j];uint32_t t2=S0(a[j])+maj(a[j],b[j],c[j]);h[j]=g[j];g[j]=f[j];f[j]=e[j];e[j]=d[j]+t1;d[j]=c[j];c[j]=b[j];b[j]=a[j];a[j]=t1+t2;}
 }
 #pragma GCC unroll 48
 for(int t=16;t<64;t++){
   int k=t&15,k15=(t-15)&15,k7=(t-7)&15,k2=(t-2)&15;
   #pragma GCC ivdep
   for(int j=0;j<L;j++) w[k][j]=w[k][j]+s0(w[k15][j])+w[k7][j]+s1(w[k2][j]);
   #pragma GCC ivdep
   for(int j=0;j<L;j++){uint32_t t1=h[j]+S1(e[j])+ch(e[j],f[j],g[j])+K[t]+w[k][j];uint32_t t2=S0(a[j])+maj(a[j],b[j],c[j]);h[j]=g[j];g[j]=f[j];f[j]=e[j];e[j]=d[j]+t1;d[j]=c[j];c[j]=b[j];b[j]=a[j];a[j]=t1+t2;}
 }
 #pragma GCC ivdep
 for(int j=0;j<L;j++){out[0][j]=in[0][j]+a[j];out[1][j]=in[1][j]+b[j];out[2][j]=in[2][j]+c[j];out[3][j]=in[3][j]+d[j];out[4][j]=in[4][j]+e[j];out[5][j]=in[5][j]+f[j];out[6][j]=in[6][j]+g[j];out[7][j]=in[7][j]+h[j];}
}
__attribute__((visibility("default"))) uint32_t sha256d_vec_scan_split_omp(const uint32_t midstate[8],const uint32_t tail[3],uint32_t start,uint32_t count,uint64_t target_hi,uint32_t *candidates,uint32_t cap,int threads){
 if(threads<1)threads=1; uint64_t groups=((uint64_t)count+L-1)/L; uint32_t found=0;
 #pragma omp parallel num_threads(threads)
 {
  uint32_t in[8][L] __attribute__((aligned(64))),ivv[8][L] __attribute__((aligned(64))),w[16][L] __attribute__((aligned(64))),z[16][L] __attribute__((aligned(64))),o1[8][L] __attribute__((aligned(64))),o2[8][L] __attribute__((aligned(64)));
  for(int q=0;q<8;q++)for(int j=0;j<L;j++){in[q][j]=midstate[q];ivv[q][j]=IV[q];}
  #pragma omp for schedule(static)
  for(uint64_t gg=0;gg<groups;gg++){
   uint64_t i64=gg*L; uint32_t i=(uint32_t)i64; uint32_t rem=(uint32_t)(((uint64_t)count-i64)>L?L:((uint64_t)count-i64));
   for(int j=0;j<L;j++){w[0][j]=tail[0];w[1][j]=tail[1];w[2][j]=tail[2];w[3][j]=bswap(start+i+(uint32_t)j);w[4][j]=0x80000000u;for(int q=5;q<15;q++)w[q][j]=0;w[15][j]=640;}
   comp_ring_split(in,w,o1);
   for(int j=0;j<L;j++){for(int q=0;q<8;q++)z[q][j]=o1[q][j];z[8][j]=0x80000000u;for(int q=9;q<15;q++)z[q][j]=0;z[15][j]=256;}
   comp_ring_split(ivv,z,o2);
   for(uint32_t j=0;j<rem;j++){uint64_t hv=(uint64_t)bswap(o2[6][j])|((uint64_t)bswap(o2[7][j])<<32);if(hv<=target_hi){uint32_t slot;
      #pragma omp atomic capture
      slot=found++;
      if(slot<cap)candidates[slot]=start+i+j;}}
  }
 }
 return found;
}

static inline void precompute_first3(const uint32_t mid[8], const uint32_t tail[3], uint32_t pre[8], uint32_t *w16, uint32_t *w17){
 uint32_t a=mid[0],b=mid[1],c=mid[2],d=mid[3],e=mid[4],f=mid[5],g=mid[6],h=mid[7];
 for(int t=0;t<3;t++){uint32_t wt=tail[t];uint32_t t1=h+S1(e)+ch(e,f,g)+K[t]+wt;uint32_t t2=S0(a)+maj(a,b,c);h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
 pre[0]=a;pre[1]=b;pre[2]=c;pre[3]=d;pre[4]=e;pre[5]=f;pre[6]=g;pre[7]=h;
 *w16=tail[0]+s0(tail[1])+0u+s1(0u);
 *w17=tail[1]+s0(tail[2])+0u+s1(640u);
}
static inline void comp_first_special(const uint32_t mid[8][L], const uint32_t pre[8][L], uint32_t w[16][L], uint32_t w16fix, uint32_t w17fix, uint32_t out[8][L]){
 uint32_t a[L],b[L],c[L],d[L],e[L],f[L],g[L],h[L];
 #pragma GCC ivdep
 for(int j=0;j<L;j++){a[j]=pre[0][j];b[j]=pre[1][j];c[j]=pre[2][j];d[j]=pre[3][j];e[j]=pre[4][j];f[j]=pre[5][j];g[j]=pre[6][j];h[j]=pre[7][j];}
 #pragma GCC unroll 13
 for(int t=3;t<16;t++){
   #pragma GCC ivdep
   for(int j=0;j<L;j++){uint32_t t1=h[j]+S1(e[j])+ch(e[j],f[j],g[j])+K[t]+w[t][j];uint32_t t2=S0(a[j])+maj(a[j],b[j],c[j]);h[j]=g[j];g[j]=f[j];f[j]=e[j];e[j]=d[j]+t1;d[j]=c[j];c[j]=b[j];b[j]=a[j];a[j]=t1+t2;}
 }
 #pragma GCC ivdep
 for(int j=0;j<L;j++) w[0][j]=w16fix;
 {int t=16;
  #pragma GCC ivdep
  for(int j=0;j<L;j++){uint32_t t1=h[j]+S1(e[j])+ch(e[j],f[j],g[j])+K[t]+w[0][j];uint32_t t2=S0(a[j])+maj(a[j],b[j],c[j]);h[j]=g[j];g[j]=f[j];f[j]=e[j];e[j]=d[j]+t1;d[j]=c[j];c[j]=b[j];b[j]=a[j];a[j]=t1+t2;}}
 #pragma GCC ivdep
 for(int j=0;j<L;j++) w[1][j]=w17fix;
 {int t=17;
  #pragma GCC ivdep
  for(int j=0;j<L;j++){uint32_t t1=h[j]+S1(e[j])+ch(e[j],f[j],g[j])+K[t]+w[1][j];uint32_t t2=S0(a[j])+maj(a[j],b[j],c[j]);h[j]=g[j];g[j]=f[j];f[j]=e[j];e[j]=d[j]+t1;d[j]=c[j];c[j]=b[j];b[j]=a[j];a[j]=t1+t2;}}
 #pragma GCC unroll 46
 for(int t=18;t<64;t++){
   int k=t&15,k15=(t-15)&15,k7=(t-7)&15,k2=(t-2)&15;
   #pragma GCC ivdep
   for(int j=0;j<L;j++) w[k][j]=w[k][j]+s0(w[k15][j])+w[k7][j]+s1(w[k2][j]);
   #pragma GCC ivdep
   for(int j=0;j<L;j++){uint32_t t1=h[j]+S1(e[j])+ch(e[j],f[j],g[j])+K[t]+w[k][j];uint32_t t2=S0(a[j])+maj(a[j],b[j],c[j]);h[j]=g[j];g[j]=f[j];f[j]=e[j];e[j]=d[j]+t1;d[j]=c[j];c[j]=b[j];b[j]=a[j];a[j]=t1+t2;}
 }
 #pragma GCC ivdep
 for(int j=0;j<L;j++){out[0][j]=mid[0][j]+a[j];out[1][j]=mid[1][j]+b[j];out[2][j]=mid[2][j]+c[j];out[3][j]=mid[3][j]+d[j];out[4][j]=mid[4][j]+e[j];out[5][j]=mid[5][j]+f[j];out[6][j]=mid[6][j]+g[j];out[7][j]=mid[7][j]+h[j];}
}
__attribute__((visibility("default"))) uint32_t sha256d_vec_scan_special_omp(const uint32_t midstate[8],const uint32_t tail[3],uint32_t start,uint32_t count,uint64_t target_hi,uint32_t *candidates,uint32_t cap,int threads){
 if(threads<1)threads=1; uint64_t groups=((uint64_t)count+L-1)/L; uint32_t found=0; uint32_t preS[8],wf16,wf17;precompute_first3(midstate,tail,preS,&wf16,&wf17);
 #pragma omp parallel num_threads(threads)
 {
  uint32_t in[8][L] __attribute__((aligned(64))),pre[8][L] __attribute__((aligned(64))),ivv[8][L] __attribute__((aligned(64))),w[16][L] __attribute__((aligned(64))),z[16][L] __attribute__((aligned(64))),o1[8][L] __attribute__((aligned(64))),o2[8][L] __attribute__((aligned(64)));
  for(int q=0;q<8;q++)for(int j=0;j<L;j++){in[q][j]=midstate[q];pre[q][j]=preS[q];ivv[q][j]=IV[q];}
  #pragma omp for schedule(static)
  for(uint64_t gg=0;gg<groups;gg++){
   uint64_t i64=gg*L; uint32_t i=(uint32_t)i64; uint32_t rem=(uint32_t)(((uint64_t)count-i64)>L?L:((uint64_t)count-i64));
   for(int j=0;j<L;j++){w[0][j]=tail[0];w[1][j]=tail[1];w[2][j]=tail[2];w[3][j]=bswap(start+i+(uint32_t)j);w[4][j]=0x80000000u;for(int q=5;q<15;q++)w[q][j]=0;w[15][j]=640;}
   comp_first_special(in,pre,w,wf16,wf17,o1);
   for(int j=0;j<L;j++){for(int q=0;q<8;q++)z[q][j]=o1[q][j];z[8][j]=0x80000000u;for(int q=9;q<15;q++)z[q][j]=0;z[15][j]=256;}
   comp_ring_split(ivv,z,o2);
   for(uint32_t j=0;j<rem;j++){uint64_t hv=(uint64_t)bswap(o2[6][j])|((uint64_t)bswap(o2[7][j])<<32);if(hv<=target_hi){uint32_t slot;
      #pragma omp atomic capture
      slot=found++;
      if(slot<cap)candidates[slot]=start+i+j;}}
  }
 }
 return found;
}
