from asyncio.windows_events import NULL
import hashlib as hb
from datetime import datetime
from stat import SF_APPEND
import numpy as np

g1 = 0
g2 = 0
g3 = 0
pkO=0
prover_secret_key=0
class Signature:
    def __init__(self, t, B):
        self.t = t
        self.B = B
class AttestationCounter:
    def __init__(self, status = "free", v = 0) -> None:
        self.status = status
        self.v = v

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

def multiply_vect(V):
    if V.count() == 1:
        return V[0]
    else:
        return V[V.count()-1] * multiply_vect (V.pop())

def publicKeyAggregation(pkList):
    return multiply_vect(pkList)

def Sign(m,M):
    if m == M:
        return Signature(pow(hb.sha3_256(m),self.private_key),list)
    else:
        return Signature(pow(hb.sha3_256(m),self.private_key),list(Beta(m,self.public_key)))

def getGoodConfigs():       #Crea array di interi random per simulare software config di 10 dispositivi
    softConfig = np.random.randint(1000000000000000000000000000000000000000,
                            10000000000000000000000000000000000000000,20)
    return softConfig   #Salvare questo array nel main per usare funzione getSoftConfig( softConfig ) 

def aggregateSignature(sig1, sig2):
    return Signature(sig1.t * sig2.t, sig1.B.append(sig2.B))

def getSoftConfig(softConfig, legit):      #ritorna un elemento cauale di softConfig se legit == 1
    if legit==1:                           #altrimenti ritorna elemento non in softConfig 
        return softConfig[np.random.randint(0,20)]
    else:
        return(10000000000000000000000000000000000000001) 

def createCounterList():    #crea lista di 10 AttestationCounter tutti free e con counter 0   
    counterList = []
    for i in range(10):
        c = AttestationCounter()
        counterList.append(c)
    return counterList



def getFreeCounter(counterList):        #cerca nella lista di AttestationCounter uno free, setta status a busy e incrementa v di 1
    for i in range(counterList.length):
        if counterList[i].status == "free":
            counterList[i].status = "busy"
            counterList[i].v +=1
            return counterList[i].status, counterList[i].v
    return NULL




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


