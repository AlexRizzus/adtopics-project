from asyncio.windows_events import NULL
import hashlib as hb
from datetime import datetime
import math
import random as rand
from stat import SF_APPEND
import numpy as np
import sympy as sp

g1 = 0
g2 = 0
gt = 0
pkO = 0
p = 0
prover_secret_key=0

def InitializeCryptoSystem():
    p = sp.randprime(100000000000,1000000000000000000)
    g1 = rand.randrange(100000000000,1000000000000000000)
    g2 = rand.randrange(100000000000,1000000000000000000)
    gt = rand.randrange(100000000000,1000000000000000000)

def generateKeys():
    self.privateKey = rand.randrange(0,p)
    self.publicKey = g2 ** self.privateKey

def H(msg):
    x = hb.sha256(msg)
    return g1**x

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

def computeBilinearMap(term1, term2):
    x = findExponent(term1, g1)
    y = findExponent(term2, g2)
    return gt**(x*y)

def findExponent(result, base):
    c = 2
    while base**c <= result :
        if base**c == result:
            return c
    return 0
def publicKeyAggregation(pkList):
    return multiply_vect(pkList)

def Sign(m,M):
    if m == M:
        return Signature(pow(H(m),self.private_key),list)
    else:
        return Signature(pow(H(m),self.private_key),list(Beta(m,self.public_key)))

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

def multiplyBilinearMaps(list):
    result = 1 
    for i in list:
        result= result * computeBilinearMap(H(i.msg),i.pk)
    return result

def extractPublicKeys(list):
    result = {}
    for i in list:
        result.append(i.pk)
    return result

def Verify(apk, S, msg, sign):
    apkm = apk / (multiply_vect(S) * multiply_vect(extractPublicKeys(sign.B)))
    if computeBilinearMap(sign.t, g2) == computeBilinearMap(H(msg),apkm) * multiplyBilinearMaps(sign.B):
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


