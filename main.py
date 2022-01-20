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

verifier = Node()
verifierRequestToOwner = verifier.Sign(verifier.nonce , verifier.nonce)
owner = Node()

owner.generateKeys()
print(g2)
print(owner.privateKey)
#print(owner.publicKey)
signature = owner.Sign(12,12)
print(signature)
print(Verify(owner.publicKey, {}, 12, signature))