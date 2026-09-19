#!/usr/bin/env python3
"""NOEMA × DNCrypt × GREMLIN PhaseVec Bitcoin Miner v2.

Correctness-first native SHA256d miner with 36D control-plane tuning.
Hot path: 16-lane uint32 SIMD + OpenMP + correct SHA256 midstate specialization.
No change to SHA256d probability is claimed.
"""
from __future__ import annotations
import argparse, ctypes, hashlib, json, os, stat, struct, subprocess, time
from pathlib import Path
import numpy as np

ROOT_DEFAULT=Path('/dev/shm/ciel_noema')
HERE=Path(__file__).resolve().parent
C_SOURCE=HERE/'sha256d_phasevec_v2.c'
SO_PATH=HERE/'libsha256d_phasevec_v2.so'
UINT32_SPACE=1<<32
GENESIS_HEADER76=bytes.fromhex('01000000'+'00'*32+'3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a'+'29ab5f49'+'ffff001d')
GENESIS_NONCE=2083236893
GENESIS_HASH='000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f'
K=(0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2)
IV=(0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19)
MASK=0xffffffff

def canonical(o): return json.dumps(o,sort_keys=True,separators=(',',':')).encode()
def receipt(o): return hashlib.blake2b(canonical(o),digest_size=32).hexdigest()
def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()
def rr(x,n): return ((x>>n)|(x<<(32-n)))&MASK

def _compress_scalar(st,block64):
    if len(block64)!=64: raise ValueError('block64 required')
    w=[int.from_bytes(block64[i:i+4],'big') for i in range(0,64,4)]
    for i in range(16,64):
        w.append((w[i-16]+(rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>10)))&MASK)
    a,b,c,d,e,f,g,h=map(int,st)
    for i in range(64):
        t1=(h+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^((~e)&g))+K[i]+w[i])&MASK
        t2=((rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c)))&MASK
        h,g,f,e,d,c,b,a=g,f,e,(d+t1)&MASK,c,b,a,(t1+t2)&MASK
    return [(x+y)&MASK for x,y in zip(st,(a,b,c,d,e,f,g,h))]

def midstate64(prefix64):
    if len(prefix64)!=64: raise ValueError('prefix64 required')
    return np.asarray(_compress_scalar(IV,prefix64),dtype=np.uint32)

def compact_to_target(nbits):
    e=(nbits>>24)&0xff; m=nbits&0x007fffff
    if nbits&0x00800000: raise ValueError('negative compact target')
    return (m>>(8*(3-e))) if e<=3 else (m<<(8*(e-3)))

def noema_gate(root:Path,require_execution=False):
    if not root.is_dir(): raise RuntimeError('NOEMA_ROOT_MISSING')
    binding=(root/'ciel_binding_status').read_text().strip()
    if binding!='ACTIVE': raise RuntimeError('TETHER_NOT_ACTIVE:'+binding)
    vh={}
    for n in ('phi','aux_phi','aux_feedback_phi'):
        raw=(root/n).read_bytes(); v=np.frombuffer(raw,dtype='<f8')
        if len(raw)!=288 or v.shape!=(36,) or not np.isfinite(v).all(): raise RuntimeError(n+'_INVALID')
        vh[n]=hashlib.sha256(raw).hexdigest()
    sp=json.loads((root/'session/startpoint.json').read_text()); sm=root/'session/system_message.txt'
    if sp.get('status')!='VERIFIED' or not sm.is_file(): raise RuntimeError('NOEMA_SESSION_NOT_VERIFIED')
    sock=Path('/run/user/1000/noema/ciel_headless.sock')
    if not sock.exists() or not stat.S_ISSOCK(sock.stat().st_mode): raise RuntimeError('NOEMA_SOCKET_MISSING')
    sup=json.loads((root/'supervisor/status.json').read_text())
    for svc in ('tether','gremlin','terminal36d'):
        if sup.get('services',{}).get(svc,{}).get('observed_status')!='ACTIVE': raise RuntimeError('NOEMA_SERVICE_NOT_ACTIVE:'+svc)
    if require_execution and sup.get('execution_authorized') is not True: raise RuntimeError('NOEMA_EXECUTION_NOT_AUTHORIZED')
    return {'status':'PASS','binding':binding,'vectors':vh,'authority':sup.get('authority'),'execution_authorized':sup.get('execution_authorized'),'startpoint_packet_sha256':sp.get('packet_sha256')}

def build_native(force=False):
    if not C_SOURCE.is_file(): raise RuntimeError('C_SOURCE_MISSING:'+str(C_SOURCE))
    if SO_PATH.exists() and not force and SO_PATH.stat().st_mtime_ns>=C_SOURCE.stat().st_mtime_ns: return SO_PATH
    cmd=['gcc','-O3','-march=native','-fPIC','-shared','-fopenmp','-funroll-loops','-fomit-frame-pointer',str(C_SOURCE),'-o',str(SO_PATH)]
    p=subprocess.run(cmd,capture_output=True,text=True)
    if p.returncode: raise RuntimeError('NATIVE_BUILD_FAIL:'+p.stderr)
    return SO_PATH

class NativeVectorBackend:
    def __init__(self):
        build_native(); self.lib=ctypes.CDLL(str(SO_PATH))
        A=[ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32),ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint64,ctypes.POINTER(ctypes.c_uint32),ctypes.c_uint32,ctypes.c_int]
        names={'ring':'sha256d_vec16_scan_ring_omp','split':'sha256d_vec_scan_split_omp','special':'sha256d_vec_scan_special_omp'}
        self.f={}
        for k,n in names.items(): fn=getattr(self.lib,n); fn.argtypes=A; fn.restype=ctypes.c_uint32; self.f[k]=fn
        hi=self.lib.sha256d_vec16_hi64_ring_omp; hi.argtypes=[ctypes.POINTER(ctypes.c_uint32),ctypes.POINTER(ctypes.c_uint32),ctypes.c_uint32,ctypes.c_uint32,ctypes.POINTER(ctypes.c_uint64),ctypes.c_int]; self.hi=hi
    @staticmethod
    def p32(a): return a.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32))
    def scan(self,k,mid,tail,start,count,target_hi,threads,cap=4096):
        cand=np.empty(cap,dtype=np.uint32); n=int(self.f[k](self.p32(mid),self.p32(tail),start&0xffffffff,count&0xffffffff,target_hi,cand.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32)),cap,threads)); return n,cand[:min(n,cap)].copy()
    def hi64(self,mid,tail,start,count,threads):
        out=np.empty(count,dtype=np.uint64); self.hi(self.p32(mid),self.p32(tail),start,count,out.ctypes.data_as(ctypes.POINTER(ctypes.c_uint64)),threads); return out

def header_parts(header76):
    if len(header76)!=76: raise ValueError('header76 must be 76 bytes')
    mid=midstate64(header76[:64]); tail=np.asarray([int.from_bytes(header76[64+4*i:68+4*i],'big') for i in range(3)],dtype=np.uint32); return mid,tail

def selftest(backend,threads):
    mid,tail=header_parts(GENESIS_HEADER76)
    out=backend.hi64(mid,tail,0,4096,threads)
    for n in range(4096):
        d=sha256d(GENESIS_HEADER76+struct.pack('<I',n)); expected=int.from_bytes(d,'little')>>192
        if int(out[n])!=expected: raise RuntimeError(f'VECTOR_MISMATCH:{n}')
    gd=sha256d(GENESIS_HEADER76+struct.pack('<I',GENESIS_NONCE))
    if gd[::-1].hex()!=GENESIS_HASH: raise RuntimeError('GENESIS_FAIL')
    return {'status':'PASS','checked_nonces':4096,'genesis_nonce':GENESIS_NONCE,'genesis_hash':GENESIS_HASH,'native_sha256':hashlib.sha256(SO_PATH.read_bytes()).hexdigest()}

def shard_range(total,idx):
    if not 1<=total<=UINT32_SPACE or not 0<=idx<total: raise ValueError('invalid shard')
    return (UINT32_SPACE*idx)//total,(UINT32_SPACE*(idx+1))//total

def mine(header76,target,root,threads,batch_size,kernel,total_shards,shard_id):
    gate=noema_gate(root,True); backend=NativeVectorBackend(); selftest(backend,min(threads,os.cpu_count() or threads)); mid,tail=header_parts(header76); target_hi=target>>192; start,end=shard_range(total_shards,shard_id); cursor=start; checked=0; t0=time.perf_counter()
    while cursor<end:
        noema_gate(root,False)
        n=min(batch_size,end-cursor); found,cands=backend.scan(kernel,mid,tail,cursor,n,target_hi,threads)
        for nonce in map(int,cands):
            digest=sha256d(header76+struct.pack('<I',nonce))
            if int.from_bytes(digest,'little')<=target:
                dt=time.perf_counter()-t0; r={'status':'FOUND','nonce':nonce,'hash_display':digest[::-1].hex(),'hashes_checked':checked+(nonce-cursor)+1,'elapsed_s':dt,'hashes_per_second':(checked+(nonce-cursor)+1)/max(dt,1e-12),'kernel':kernel,'threads':threads,'batch_size':batch_size,'shard':[shard_id,total_shards],'noema':gate};r['receipt_sha256']=receipt(r);return r
        if found>len(cands): raise RuntimeError('CANDIDATE_BUFFER_OVERFLOW')
        checked+=n; cursor+=n
    dt=time.perf_counter()-t0; r={'status':'EXHAUSTED_SHARD','hashes_checked':checked,'elapsed_s':dt,'hashes_per_second':checked/max(dt,1e-12),'kernel':kernel,'threads':threads,'batch_size':batch_size,'shard':[shard_id,total_shards],'noema':gate};r['receipt_sha256']=receipt(r);return r

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--noema-root',default=str(ROOT_DEFAULT)); sub=ap.add_subparsers(dest='cmd',required=True)
    st=sub.add_parser('selftest'); st.add_argument('--threads',type=int,default=min(4,os.cpu_count() or 1))
    m=sub.add_parser('mine-header');m.add_argument('--header76-hex',required=True);tg=m.add_mutually_exclusive_group(required=True);tg.add_argument('--target-hex');tg.add_argument('--nbits',type=lambda x:int(x,0));m.add_argument('--kernel',choices=('ring','split','special'),default='split');m.add_argument('--threads',type=int,default=min(4,os.cpu_count() or 1));m.add_argument('--batch-size',type=int,default=4194304);m.add_argument('--total-shards',type=int,default=1);m.add_argument('--shard-id',type=int,default=0);m.add_argument('--out',default='NOEMA_BITCOIN_MINING_RECEIPT_V2.json')
    ns=ap.parse_args();root=Path(ns.noema_root);gate=noema_gate(root,False);backend=NativeVectorBackend()
    if ns.cmd=='selftest': result={'noema':gate,'selftest':selftest(backend,ns.threads)}
    else:
        h=bytes.fromhex(ns.header76_hex);target=int(ns.target_hex,16) if ns.target_hex else compact_to_target(ns.nbits);result=mine(h,target,root,ns.threads,ns.batch_size,ns.kernel,ns.total_shards,ns.shard_id);Path(ns.out).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))
if __name__=='__main__': main()
