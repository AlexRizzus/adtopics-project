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
from nodes import *


owner = Owner()
owner.generateKeys()
verifier = Verifier()
verifier.generateKeys()
apk = multiply_vect(pklist)
expTime = dt.timedelta(0,300)

verifierRequestToOwner = verifier.Sign(verifier.nonce , verifier.nonce | expTime.seconds())

T, ownerSignature2 = owner.handleRequest(verifierRequestToOwner,expTime,verifier.nonce)
#verifier stores the token after checking the owner's signature
verifier.storeToken(ownerSignature2, apk, T, expTime)

verifierNonce = randomBinaryFixedLength(20)
Cha = Challenge(verifierNonce, verifier.tokenMem[0])

#Aggregator
aggregator = Node()
aggregator.generateKeys()
aggregator.VerifyChallenge(T)
alpha1 = Signature(1,{})

#Prover
prover = Node()
prover.generateKeys()
prover.VerifyChallenge(Cha.T)
hi = prover.getSoftConfig(H, 1)
hg = hb.sha256(or_vector(Cha.T.H))

M= hg|Cha.N|Cha.T.cl|Cha.T.vl

for i in range(len(H)):
    if hi == H[i]:
        hi = hg
   
m= hi|Cha.N|Cha.T.cl|Cha.T.vl
alphai = prover.Sign(m, M)


#back to the Aggregator
alpha1 = verifier.aggregateSignature(alpha1, alphai)


#back to the verifier

M = hg|Cha.N|Cha.T.cl|Cha.T.vl
B = Verify(apk, [], M, alpha1)
if B == NULL:
    r = 1
else:
    r = 0

