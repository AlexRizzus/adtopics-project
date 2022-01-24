from asyncio.windows_events import NULL
import hashlib as hb
import datetime as dt
import math
import random as rand
from stat import SF_APPEND
import numpy as np
import rsa
import sympy as sp
from util import *

# general class Node
class Node:
    privateKey = 0
    publicKey = 0
    nonce = randomBinaryFixedLength(8)
    tokenExpirytime =  dt.datetime.now() + dt.timedelta(0,300) 
    tokenMem = {}
    # generates public and private key for itself
    def generateKeys(self):
        self.privateKey = rand.randrange(1,p)
        self.publicKey = pow(g2,self.privateKey, p)
        pklist.append(self.publicKey)
    # signs a message m depending on the fact that it's the same as the default message M or not
    def Sign(self,m,M):
        if m == M:
            return Signature(pow(H(m),self.privateKey, p),list())
        else:
            return Signature(pow(H(m),self.privateKey, p),list([Beta(m,self.publicKey)]))

    def getGoodConfigs(self):       #Crea array di interi random per simulare software config di 10 dispositivi
        softConfig = np.random.randint(1000, 10000, 20)
        return list(softConfig)   #Salvare questo array nel main per usare funzione getSoftConfig( softConfig )
    # verifies a given signature by computing the bilinear maps
    def Verify(self, apk, S, msg, sign):
        apkm = apk // (multiply_vect(S) * multiply_vect(extractPublicKeys(sign.B)))
        if computeBilinearMap(sign.t, g2) == computeBilinearMap(H(msg),apkm) * multiplyBilinearMaps(sign.B):
            return sign.B
        else:
            return NULL
    # verifies the challenge given by the verifier
    def VerifyChallenge(self,token):
        print("verification of the challenge started")
        hg = hb.sha256(or_vector(list(token.H)))
        if (int((dt.datetime.now() - dt.datetime(1970,1,1)).total_seconds()) < token.t):
             print("invalid time for the request")
             return 0
        else:
             if not (self.Verify(pklist[0],[],or_vector(list([hg,token.cl,token.vl,token.t])),token.signo)):
                  print("invalid signature for the request")
                  return 0
        return 1
    # aggregates two normal/aggregated signatures
    def aggregateSignature(self, sig1, sig2):
        return Signature(sig1.t * sig2.t, sig1.B + sig2.B)
        

    def getSoftConfig(self, softConfig, legit):      #ritorna un elemento cauale di softConfig se legit == 1
        if legit==1:                           #altrimenti ritorna elemento non in softConfig 
            return hb.sha256(softConfig[np.random.randint(0,20)])
        else:
            return hb.sha256(str(10001).encode('utf-8'))

    def getFreeCounter(self,counterList):        #cerca nella lista di AttestationCounter uno free, setta status a busy e incrementa v di 1
        for i in range(len(counterList)):
            if counterList[i].status == "free":
                counterList[i].status = "busy"
                counterList[i].v +=1
                return i, counterList[i].v
        return NULL
    
# Child classes from node: 
class Owner(Node):
    # handles the verification request by generating a token T
    def handleRequest(self, signv, expTime, noncev, counterList):
        if self.Verify(pklist[1],[],self.nonce | expTime.seconds, signv) != NULL:
            cl, vl = self.getFreeCounter(counterList)
            H = self.getGoodConfigs()
            hg = hb.sha256(or_vector(list(H)))
            expirancySeconds = int((dt.datetime.now() + expTime - dt.datetime(1970,1,1)).total_seconds())
            ownerSignature1 = self.Sign(int(hg.hexdigest(),16) | cl | vl | expirancySeconds, int(hg.hexdigest(),16) | cl | vl | expirancySeconds)
            T = Att_Token(H,cl,vl,expirancySeconds,ownerSignature1)
            encToken = T
            ownerSignature2 = self.Sign(noncev | multiply_vect(list(pklist)), noncev | multiply_vect(list(pklist)))
        else:
            print("error during the authorization of the request by the owner")
        return encToken,ownerSignature2

class Verifier(Node):
    tokenMem = []
    # stores the token after checking the owner's signature
    def storeToken(self, signo2, apk, T):
        if self.Verify(pklist[0],[], self.nonce | apk, signo2) != NULL:
            if self.Verify(pklist[0],[], int(hb.sha256(or_vector(list(T.H))).hexdigest(),16) | T.cl | T.vl | T.t, T.signo) != NULL:
                self.tokenMem = [T, apk]
            else:
                print("ERROR STORING THE TOKEN")