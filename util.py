from asyncio.windows_events import NULL
import hashlib as hb
import random as rand
from stat import SF_APPEND
from util import *
from sympy import primerange

def randomBinaryFixedLength(length):
    string = str()
    for i in range(length):
        string = string + str(rand.randint(0,1))
    return int(string,2)

gt = randomBinaryFixedLength(8)
g2 = randomBinaryFixedLength(8)
g1 = randomBinaryFixedLength(8)
p = primerange(1000,10000)
pklist = {}

def H(msg):
    x = hb.sha256(bin(msg).encode('utf-8'))
    result = g1**(int(x.hexdigest(),16) % int(p))
    return result


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

class Challenge:
    def __init__(self, N, T) -> None:
        self.N = N
        self.T = T

def or_vector(H):
    if H.count() == 1:
        return H[0]
    else:
        return H[H.count()-1] | or_vector(H.pop())

def multiply_vect(V):
    if len(V) == 0:
        return 1
    else:
        return V[len(V)-1] * multiply_vect (V.pop())

def computeBilinearMap(term1, term2):
    print("term1 " + str(term1))
    x = findExponent(term1, g1)
    y = findExponent(term2, g2)
    print(x)
    print(y)
    return gt**(x*y)

def findExponent(result, base):
    c = 1
    while base**c <= result :
        # print(c)
        if base**c == result:
            return c
        c= c+1
    return 0

def publicKeyAggregation(pkList):
    return multiply_vect(pkList)



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

def createCounterList():    #crea lista di 10 AttestationCounter tutti free e con counter 0   
    counterList = []
    for i in range(10):
        c = AttestationCounter()
        counterList.append(c)
    return counterList

