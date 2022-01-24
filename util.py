from asyncio.windows_events import NULL
import hashlib as hb
from operator import mod
import random as rand
from stat import SF_APPEND
from cv2 import log

import sympy
from util import *
from sympy import randprime

def randomBinaryFixedLength(length):
    string = str()
    for i in range(length):
        string = string + str(rand.randint(0,1))
    return int(string,2)

gt = 13
g2 = 10
g1 = 5
p = 72130926498893822734492001005677631332746356118879806659093994416564121503313
pklist = []


def initializeCrytoSystem():
    # p = randprime(int(str('1')+str('0') * 255,2),int(str('1') * 256,2))
    p = 72130926498893822734492001005677631332746356118879806659093994416564121503313
    # factors = sympy.primefactors(p-1)
    factors = [2, 3, 31, 663720899, 4666254422144569, 550768670793363408056383, 9472708845023994873315671]
    generators = []
    tempNumber = 2
    isGen = 1
    while len(generators) < 3:
        for i in factors:
            if pow(tempNumber, (p-1)//i, p) == 1:
                isGen = 0
                break
        if isGen:
            generators.append(tempNumber)
        tempNumber += 1
        isGen = 1
    return p, generators[0], generators[1], generators[2]

def H(msg):
    x = hb.sha256(bin(msg).encode('utf-8'))
    # check if this is right !!!
    result = mod(int(x.hexdigest(),16),p)
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
    if len(H) == 1:
        return H[0]
    else:
        return H.pop() | or_vector(H)

def multiply_vect(V):
    if len(V) == 0:
        return 1
    else:
        
        return V.pop() * multiply_vect (V)

def computeBilinearMap(term1, term2):
    x = findExponent(term1, g1)
    y = findExponent(term2, g2)
    return pow(gt, (x*y) % p, p)

def findExponent(result, base):
    c = 1
    while c < p:
        # print(c)
        if pow(base,c,p) == result:
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
    result = []
    for i in list:
        result.append(i.pk)
    return result

def createCounterList():    #crea lista di 10 AttestationCounter tutti free e con counter 0   
    counterList = []
    for i in range(10):
        c = AttestationCounter()
        counterList.append(c)
    return counterList

