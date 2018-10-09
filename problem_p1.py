import json
import sys, os, itertools

sys.path.append(os.path.abspath(os.path.join('..')))
from playcrypt.primitives import *
from playcrypt.tools import *
from playcrypt.ideal.block_cipher import *

"""
Problem 1 [100 points]
Let E be a blockcipher  E:{0, 1}^k x {0, 1}^n --> {0, 1}^n
and E_I be its inverse.
Define F: {0, 1}^k+n x {0, 1}^n --> {0, 1}^n as shown below.

Notes:
Sizes in comments are bits, sizes in code are in bytes (bits / 8).
In the code K1\in{0,1}^k and K2,M\in{0,1}^n
"""
 
def F(K, M):
    """
    Blockcipher F constructed from blockcipher E.

    :param K: blockcipher key
    :param M: plaintext message
    :return: ciphertext
    """
    K1 = K[:k_bytes]
    K2 = K[k_bytes:]

    C = E(K1, xor_strings(M,K2))
    return C

"""
(a) [50 points] Give a 1-query adversary A1 that has advantage
                Adv^kr_F(A1) = 1 and running time O(T_E + k + n).
"""

def A1(fn):
    #key_guess = fn('\x00' * (n_bytes + k_bytes))
    key_guess = fn(E_I)
    #key_check = F(key_guess, "01110")
    print key_guess
    print type(key_guess)
    """
    key = fn('0010')
    for i,j in zip(K1, K2):
        if E(M) == C:
            return key
    """
    """
    You must fill in this method. This is the adversary that the problem is
    asking for.

    :param fn: This is the oracle supplied by GameKR, you can call this
    oracle to get an "encryption" of the data you pass into it.
    :return: return the a string that represents a key guess.
    """
    return key_guess
    #pass

"""
(b) [50 points] Give a 3-query adversary A3 that has advantage Adv^kr_F(A3) = 1
                and running time O(2^k * (T_E + k + n)).
"""

def A3(fn):

    """
    You must fill in this method. This is the adversary that the problem is
    asking for.

    :param fn: This is the oracle supplied by GameKR, you can call this
    oracle to get an "encryption" of the data you pass into it.
    :return: return the a string that represents a key guess.
    """

    pass

from playcrypt.games.game_kr import GameKR
from playcrypt.simulator.kr_sim import KRSim

if __name__ == '__main__':
    warning = False
    f = open("student_info.json", 'r')
    student_info = json.loads(f.read())
    f.close()
    for a in student_info:
        print "%s: %s" % (a, student_info[a])
        if a == "TODO" or student_info[a] == "TODO":
            warning = True
    if warning:
        print "Wrong personal information. Please fill in file student_info.json."

    # Arbitrary choices of k, n.
    k = 128
    n = 64
    # Block & key size in bytes.
    k_bytes = k/8
    n_bytes = n/8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g1 = GameKR(1, F, k_bytes+n_bytes, n_bytes)
    s1 = KRSim(g1, A1)
    print "The advantage of your adversary A1 is approximately " + str(s1.compute_advantage(20))
"""
    # Smaller choices of k, n.
    k = 8
    n = 64
    k_bytes = k/8
    n_bytes = n/8
    EE = BlockCipher(k_bytes, n_bytes)
    E = EE.encrypt
    E_I = EE.decrypt
    g3 = GameKR(3, F, k_bytes+n_bytes, n_bytes)
    s3 = KRSim(g3, A3)
    print "The advantage of your adversary A3 is approximately " + str(s3.compute_advantage(20))
    """
