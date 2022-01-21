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