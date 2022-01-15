from asyncio.windows_events import NULL
import hashlib as hb
from datetime import datetime

g1,g2,g3 = 0
pkO=0
prover_secret_key=0
class Signature:
    def __init__(self, t, B):
        self.t = t
        self.B = B

class Beta:
    def __init__(self, msg, pk):
        self.msg = msg
        self.pk = pk
class Att_Token:
    def __init__(self, H, cl, vl, t, signo) -> None:
        self.H = H
        self.cl = cl
        self.vl = vl
        self.t = t
        self.signo = signo

def or_vector(H):
    if H.count() == 1:
        return H[0]
    else:
        return H[H.count()-1] | or_vector(H.pop())

def Sign(m,M):
    if m == M:
        return Signature(pow(hb.sha3_256(m),self.private_key),[])
    else:
        return Signature(pow(hb.sha3_256(m),self.private_key),[Beta(m,self.public_key)])

def Verify(apk, S, msg, sign):
    apkm = apk / (multiply_vect(S) * multiply_vect(extract_public_keys(sign.B)))
    if bilinear_map(sign.t, g2) == bilinear_map(hb.sha3_256(msg),apkm) * multiply_bilinear_maps(sign.B):
        return sign.B
    else:
        return NULL


def VerifyChallenge(token):
    print("verification of the challenge started")
    hg = hb.sha256(or_vector(token.H))
    if (datetime.now() > datetime.strptime(token.t,"%H:%M:%S")):
         print("invalid time for the request")
         return 0
    else:
         if not (Verify(pkO,[],or_vector(list([hg,token.cl,token.vl,token.t])),token.signo)):
              print("invalid signature for the request")
              return 0
    return 1




