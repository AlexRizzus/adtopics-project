from asyncio.windows_events import NULL
import hashlib as hb
from datetime import datetime
import math
import random as rand
from stat import SF_APPEND
import numpy as np
import sympy as sp
from util import *
from nodes import *


owner = Node()
owner.generateKeys()
verifier = Node()
verifier.generateKeys()
verifierRequestToOwner = verifier.Sign(verifier.nonce , verifier.nonce)



owner.generateKeys()
print(g2)
print(owner.privateKey)
#print(owner.publicKey)
signature = owner.Sign(12,12)
print(signature)
print(Verify(pklist[owner.id], {}, 12, signature))



verifierNonce = randomBinaryFixedLength(20)
Cha = Challenge(verifierNonce, T)

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

