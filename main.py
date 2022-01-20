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

#Aggregator
aggregator = Node()
aggregator.generateKeys()
aggregator.VerifyChallenge(T)
aggregatorSignature = Signature(0,0)

#Prover
prover = Node()
prover.generateKeys()
prover.VerifyChallenge(T)
hi = prover.getSoftConfig(H, 1)
hg = hb.sha256(or_vector(T.H))
for i in range(len(H)):
    if hi == H[i]:
        hi = hg
   

prover.Sign()