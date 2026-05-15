# compute a**m mod n
def moduloExp(a, m, n):
     # convert m into binary

     binaryOfm = bin(m)
     binaryOfm = binaryOfm[2:len(binaryOfm)]
     
     d = 1
     k = len(binaryOfm) - 1
     L = range(k,-1,-1)   #L= [k, k-1,...,0]

     # binaryOfm is a string

     # binaryOfm[0]  = b_k; binaryOfm[1]  = b_{k-1}; binaryOfm[2]  = b_{k-2}

     # binaryOfm[k-i] = b_i

     for i in L:
          d = d*d%n
          b_i = binaryOfm[k-i]
          if b_i != '0':
               d = (d*a)%n
     return d

#print(moduloExp(60115587, 20001955, 60115687)) # 60115587**20001955%60115687

#print(moduloExp(60, 20, 6011)) # 60**20%6011 = 5926

def  EuclidGCD(a,b):
     c, d = a, b
     while True:
          if c == 0:
               return d
          if d ==0:
               return c
          if c > d:
               c = c%d
          else: # d >= c
               d = d%c

def rsaKeyGen(nOfBits=128):
     ### Step 1: genering two primes p, q
     import primeGenerator
     p = primeGenerator.generatePrime(int(nOfBits/2))
     q = primeGenerator.generatePrime(int(nOfBits/2))

     ##
     ### Step 2: compute n= p x q
     ##
     n = p*q

     ##
     ### Step 3:
     ##
     phi_n = (p-1)*(q-1)

     import secrets
     
     while True:
          e = secrets.randbelow(phi_n - 1) + 1
          if EuclidGCD(e,phi_n) == 1:
               break
     ##
     ##
     PU = (e, n)
     ### Step 4:
     ##
     
     ##for d in range(1, phi_n):
     ##     if d*e%phi_n == 1:
     ##          break
     ##
     ##PR = (d,n)

     import mulInverseByExtendedEuclidean
     d = mulInverseByExtendedEuclidean.mulInverse(e, phi_n)
     PR = (d, n)
     
     return (PR, PU)


#myPR, myPU = rsaKeyGen(2028)
#print("my PU = ", myPU)
#print("my PR = ", myPR)


# sample key pair

PU = (28954921, 70405183)
PR = (3839497, 70405183)


# block encryption algorithm
def encryptBlock(M, K):
     e, n = K
     C = moduloExp(M, e, n)
     # C = M**e%n
     # C = pow(M, e, n)
     return C


#print(encryptBlock(614677, PU)) # we want to see 31868457

# block decryption algorithm
def decryptBlock(C, K):
     d, n = K
     M = moduloExp(C, d, n)
     return M

#print(decryptBlock(31868457, PR)) # we want to see 614677


# multi-block encryption

def encryptBlocks(Ms, K):
     # list comprehension
     return [encryptBlock(M, K) for M in Ms]


# multi-block decryption
def decryptBlocks(Cs, K):
     return [decryptBlock(C, K) for C in Cs]

# bit string encryption algorithm

s = '01110011'
i = '01101001'
t = '01110100'
siit = s + i + i + t

def encryptBitString(plainBitSeq, K):
     import math
     e, n  = K
     
     blockSize = math.floor(math.log2(n))
   
     Ms = []
     i = 0
     while i<len(plainBitSeq):
          Ms.append(plainBitSeq[i:i+blockSize])
          i = i + blockSize
          
     # perform padding for the last block, which is Ms[len(Ms)-1]
     # print(Ms)

     lM = Ms[len(Ms)-1]
     lM = lM  + "1" + "0"*(blockSize-len(lM)-1)
     Ms[len(Ms)-1] = lM
     #print('binary blocks =', Ms)
     Ms = [int(M,2)  for M in Ms]
     #print('block values =', Ms)

     Cs = encryptBlocks(Ms, K)

     #print('encrypted block values =', Cs)
     
     CsInBinary =  ["0"*(blockSize+1-len(bin(C)[2:])) + bin(C)[2:] for C in Cs]

     #print('encrypted binary values =', CsInBinary)
     
     cipheredBitSeq = ""
     for CInBinary in CsInBinary:
          cipheredBitSeq = cipheredBitSeq +    CInBinary  

     #print(cipheredBitSeq)

     return cipheredBitSeq


# test

#PR = (77, 143)
#PU = (53, 143)
#print(siit)
#print(encryptBitString(siit, PR))


# bit string decryption algorithm

def descryptBitString(cipheredBitSeq, K):
     import math
     d, n  = K   
     blockSize = math.floor(math.log2(n))+1
     Cs = []
     i = 0
     while i<len(cipheredBitSeq):
          Cs.append(cipheredBitSeq[i:i+blockSize])
          i = i + blockSize
  
     Cs = [int(C,2) for C in Cs]
     
     Ms = decryptBlocks(Cs, K)
   

     Ms = ["0"*(blockSize-1-len(bin(M)[2:])) + bin(M)[2:] for M in Ms]
     plainBitSeq = "".join(Ms)
     # remove the padded bits
     p = len(plainBitSeq)-1
    
     while True:
          if plainBitSeq[p]=="0":
               p = p - 1
          else:
               break
     return plainBitSeq[0:p]


# for textual data
def encryptText(text, K):
     bitString  = "".join(["0"*(8-len(bin(b)[2:])) + bin(b)[2:] for b in text.encode("utf-8")])
     return encryptBitString(bitString,K)

def descryptText(ciphertext, K):
     plainBitString = descryptBitString(ciphertext,K)
     plaintext = ""
     i = 0
     while i < len(plainBitString):
          plaintext =  plaintext + chr(int(plainBitString[i:i+8],2))
          i = i + 8
     return plaintext


