from asyncio.windows_events import NULL
import hashlib as hb
import datetime as dt
import math
import random as rand
from stat import SF_APPEND
import numpy as np
import rsa
import sympy as sp
import util
from util import *
from nodes import *

util.p, util.g1, util.g2, util.gt = initializeCrytoSystem()
counterList = createCounterList()
owner = Owner()
owner.generateKeys()
verifier = Verifier()
verifier.generateKeys()
aggregator = Node()
aggregator.generateKeys()
prover_number = int(input())
provers = []
for i in range(prover_number):
    provers.append(Node())
    provers[i].generateKeys()
apk = multiply_vect(list(pklist))
expTime = dt.timedelta(0,300)


verifierRequestToOwner = verifier.Sign((verifier.nonce | expTime.seconds) , (verifier.nonce | expTime.seconds))

T, ownerSignature2 = owner.handleRequest(verifierRequestToOwner,expTime,verifier.nonce,counterList)
#verifier stores the token after checking the owner's signature
verifier.storeToken(ownerSignature2, apk, T)

verifierNonce = randomBinaryFixedLength(8)
cha = Challenge(verifierNonce, verifier.tokenMem[0])

#Aggregator
aggregator.VerifyChallenge(T)
alpha1 = Signature(1,list())

#Prover
for prover in provers:
    prover.VerifyChallenge(cha.T)
    hi = prover.getSoftConfig(cha.T.H, np.random.choice(np.arange(0, 2), p=[0.8, 0.2]))
    hg = hb.sha256(or_vector(list(cha.T.H)))

    M= int(hg.hexdigest(),16)|cha.N|cha.T.cl|cha.T.vl

    for i in range(len(cha.T.H)):
        if hi == cha.T.H[i]:
            hi = hg
   
    m= int(hi.hexdigest(),16)|cha.N|cha.T.cl|cha.T.vl
    alphai = prover.Sign(m, M)


#back to the Aggregator
    alpha1 = verifier.aggregateSignature(alpha1, alphai)


#back to the verifier

M = int(hg.hexdigest(),16)|cha.N|cha.T.cl|cha.T.vl
B = verifier.Verify(apk, [owner.publicKey, verifier.publicKey, aggregator.publicKey], M, alpha1)
if B == []:
    r = 1
else:
    if B == NULL:
        r = 2
    else:
        r = 0
if r == 1:
    print("the system can be trusted")
else:
    if r == 0:
        print("these nodes cannot be trusted")
    else:
        print("incompatibility error with the signature")
    for i in B:
        print(i.pk)
    print("list of all nodes pk:")
    for i in pklist:
        print(i)