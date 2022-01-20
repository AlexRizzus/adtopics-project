from asyncio.windows_events import NULL
import hashlib as hb
import datetime as dt
import math
import random as rand
from stat import SF_APPEND
import numpy as np
import sympy as sp
from util import *

# general class Node
class Node:
    privateKey = 0
    publicKey = 0
    nonce = randomBinaryFixedLength(20)
    tokenExpirytime =  dt.datetime.now() + 300 

    def generateKeys(self):
        self.privateKey = rand.randrange(1,p)
        self.publicKey = pow(g2,self.privateKey)
        pklist.append(self.publicKey)
    
    def Sign(self,m,M):
        if m == M:
            return Signature(pow(H(m),self.privateKey),list())
        else:
            return Signature(pow(H(m),self.privateKey),list(Beta(m,self.publicKey)))

    def getGoodConfigs():       #Crea array di interi random per simulare software config di 10 dispositivi
        softConfig = np.random.randint(1000000000000000000000000000000000000000,
                            10000000000000000000000000000000000000000,20)
        return softConfig   #Salvare questo array nel main per usare funzione getSoftConfig( softConfig )

    def Verify(apk, S, msg, sign):
        apkm = apk // (multiply_vect(S) * multiply_vect(extractPublicKeys(sign.B)))
        if computeBilinearMap(sign.t, g2) == computeBilinearMap(H(msg),apkm) * multiplyBilinearMaps(sign.B):
            return sign.B
        else:
            return NULL

    def VerifyChallenge(self,token):
        print("verification of the challenge started")
        hg = hb.sha256(or_vector(token.H))
        if (dt.now() > dt.strptime(token.t,"%H:%M:%S")):
             print("invalid time for the request")
             return 0
        else:
             if not (self.Verify(pklist[0],[],or_vector(list([hg,token.cl,token.vl,token.t])),token.signo)):
                  print("invalid signature for the request")
                  return 0
        return 1
    def aggregateSignature(sig1, sig2):
        return Signature(sig1.t * sig2.t, sig1.B.append(sig2.B))

    def getSoftConfig(softConfig, legit):      #ritorna un elemento cauale di softConfig se legit == 1
        if legit==1:                           #altrimenti ritorna elemento non in softConfig 
            return softConfig[np.random.randint(0,20)]
        else:
            return(10000000000000000000000000000000000000001)

    def getFreeCounter(counterList):        #cerca nella lista di AttestationCounter uno free, setta status a busy e incrementa v di 1
        for i in range(counterList.length):
            if counterList[i].status == "free":
                counterList[i].status = "busy"
                counterList[i].v +=1
                return counterList[i].status, counterList[i].v
        return NULL
# Child class from node: Owner
