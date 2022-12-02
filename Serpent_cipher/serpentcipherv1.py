# -*- coding: utf-8 -*-


import string
import sys
import getopt
import re


"""### Basic Operations

#### Format conversion
"""

# converts integer to bitstring having minimum length = minlen. 
# If length of obtained string < milen, 0s appended at the end
def bitstring(n, minlen=1):
    if minlen < 1:
        print("ValueError: a bitstring must have at least 1 char")
    if int(n) < 0:
        print("ValueError: bitstring representation undefined for neg numbers")
    result = str(bin(int(n)))[2:]
    '''while n > 0:
        if n & 1:
            result = result + "1"
        else:
            result = result + "0"
        n = n >> 1'''
    if len(result) < minlen:
        result = "0" * (minlen - len(result)) + result 
    return result


# reversing a string
def reverseString(s):
    newstr = ""
    l = list(s)
    l.reverse()
    for i in l:
      newstr += i
    return newstr


# splitting 128 bit string into 4 32 bit strings for bitslice format
def quadSplit(b128):
    if len(b128) != 128:
        print("ValueError: must be 128 bits long, not " + len(b128))
    result = []
    for i in range(4):
        result.append(b128[(i*32):(i+1)*32])
    return result

# concatinating 4 32 bit words into 128 bit string
def quadJoin(l4x32):
    if len(l4x32) != 4:
        print("ValueError: need a list of 4 bitstrings, not " + len(l4x32))
    return l4x32[0] + l4x32[1] + l4x32[2] + l4x32[3]

bitstring(1, 4)

"""#### XOR"""

# XOR of two binary strings of equal length
def binaryXor(n1, n2):
    if len(n1) != len(n2):
        print("ValueError: can't xor bitstrings of different lengths ({} and {})".format(len(n1), len(n2)))
    result = ""
    for i in range(len(n1)):
        if n1[i] == n2[i]:
            result = result + "0"
        else:
            result = result + "1"
    return result

# XOR of arbitrary number of bitstrings of equal length
def xor(*args):
    if args == []:
        print("ValueError: at least one argument needed")
    result = args[0]
    for arg in args[1:]:
        result = binaryXor(result, arg)
    return result

"""#### Logical Operations"""

# rotating bitstring left x = x1||x2, x <<< len(x1) = x2 || x1 
def rotateLeft(input, places):
    p = places % len(input)
    return input[-p:] + input[:-p]

# rotating bitstring right x = x1||x2, x >>> len(x2) = x2 || x1 
def rotateRight(input, places):
    return rotateLeft(input, -places)

# shifting bitstring left x << 2 = 00 || x[:2]
def shiftLeft(input, p):
    if abs(p) >= len(input):
        # Everything gets shifted out anyway
        return "0" * len(input)
    if p < 0:
        # Shift right instead
        return  input[-p:] + "0" * len(input[:-p])
    elif p == 0:
        return input
    else: # p > 0, normal case
        return "0" * len(input[-p:]) + input[:-p]

# shifting bitstring right x >> 2 = x[2:] || 0
def shiftRight(input, p):
    return shiftLeft(input, -p)

# returns length of key string
def keyLengthInBitsOf(k):
    return len(k) * 4

"""### Data Tables

#### S-boxes
"""

# all 8 S-boxes in one table
SBoxDecimalTable = [
	[3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12], # S0
	[15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4], # S1
	[8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2], # S2
	[0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14], # S3
	[1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13], # S4
	[15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1], # S5
	[7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0], # S6
	[1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6], # S7
    ] 

# S-boxes as dictionaries and inverse S-boxes 
# SboxBitString has x and S-box[x] as bit strings. Therefore list of 8 dictionaries
SBoxBitstring = []
# SBoxBitstringInverse has x and Sinv[x] as bit strings. Therefore, list of 8 dictionaries
SBoxBitstringInverse = []
for line in SBoxDecimalTable:
    dict = {}
    inverseDict = {}
    for i in range(len(line)):
        index = bitstring(i, 4)
        value = bitstring(line[i], 4)
        dict[index] = value
        inverseDict[value] = index
    SBoxBitstring.append(dict)
    SBoxBitstringInverse.append(inverseDict)

'print(SBoxBitstring)'

"""#### Permutations"""

# shows which value comes to which position. 
# Having value v(say, 32) at position p (say, 1) means that the output bit at position p(1) comes from the input bit at position v (32).

# Table for initial permutation
IPTable = [
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
    ]

# Table for final permutation
FPTable = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
 ]

"""#### Linear Transformation"""

# the linear transformation table consists of 128 lists that consist the position of elements in input block that need to be xored in order to get corresponding element of output block.
# NON-BITSLICE MODE

# table for linear transformation used while encryption
LTTable = [
    [16, 52, 56, 70, 83, 94, 105],
    [72, 114, 125],
    [2, 9, 15, 30, 76, 84, 126],
    [36, 90, 103],
    [20, 56, 60, 74, 87, 98, 109],
    [1, 76, 118],
    [2, 6, 13, 19, 34, 80, 88],
    [40, 94, 107],
    [24, 60, 64, 78, 91, 102, 113],
    [5, 80, 122],
    [6, 10, 17, 23, 38, 84, 92],
    [44, 98, 111],
    [28, 64, 68, 82, 95, 106, 117],
    [9, 84, 126],
    [10, 14, 21, 27, 42, 88, 96],
    [48, 102, 115],
    [32, 68, 72, 86, 99, 110, 121],
    [2, 13, 88],
    [14, 18, 25, 31, 46, 92, 100],
    [52, 106, 119],
    [36, 72, 76, 90, 103, 114, 125],
    [6, 17, 92],
    [18, 22, 29, 35, 50, 96, 104],
    [56, 110, 123],
    [1, 40, 76, 80, 94, 107, 118],
    [10, 21, 96],
    [22, 26, 33, 39, 54, 100, 108],
    [60, 114, 127],
    [5, 44, 80, 84, 98, 111, 122],
    [14, 25, 100],
    [26, 30, 37, 43, 58, 104, 112],
    [3, 118],
    [9, 48, 84, 88, 102, 115, 126],
    [18, 29, 104],
    [30, 34, 41, 47, 62, 108, 116],
    [7, 122],
    [2, 13, 52, 88, 92, 106, 119],
    [22, 33, 108],
    [34, 38, 45, 51, 66, 112, 120],
    [11, 126],
    [6, 17, 56, 92, 96, 110, 123],
    [26, 37, 112],
    [38, 42, 49, 55, 70, 116, 124],
    [2, 15, 76],
    [10, 21, 60, 96, 100, 114, 127],
    [30, 41, 116],
    [0, 42, 46, 53, 59, 74, 120],
    [6, 19, 80],
    [3, 14, 25, 100, 104, 118],
    [34, 45, 120],
    [4, 46, 50, 57, 63, 78, 124],
    [10, 23, 84],
    [7, 18, 29, 104, 108, 122],
    [38, 49, 124],
    [0, 8, 50, 54, 61, 67, 82],
    [14, 27, 88],
    [11, 22, 33, 108, 112, 126],
    [0, 42, 53],
    [4, 12, 54, 58, 65, 71, 86],
    [18, 31, 92],
    [2, 15, 26, 37, 76, 112, 116],
    [4, 46, 57],
    [8, 16, 58, 62, 69, 75, 90],
    [22, 35, 96],
    [6, 19, 30, 41, 80, 116, 120],
    [8, 50, 61],
    [12, 20, 62, 66, 73, 79, 94],
    [26, 39, 100],
    [10, 23, 34, 45, 84, 120, 124],
    [12, 54, 65],
    [16, 24, 66, 70, 77, 83, 98],
    [30, 43, 104],
    [0, 14, 27, 38, 49, 88, 124],
    [16, 58, 69],
    [20, 28, 70, 74, 81, 87, 102],
    [34, 47, 108],
    [0, 4, 18, 31, 42, 53, 92],
    [20, 62, 73],
    [24, 32, 74, 78, 85, 91, 106],
    [38, 51, 112],
    [4, 8, 22, 35, 46, 57, 96],
    [24, 66, 77],
    [28, 36, 78, 82, 89, 95, 110],
    [42, 55, 116],
    [8, 12, 26, 39, 50, 61, 100],
    [28, 70, 81],
    [32, 40, 82, 86, 93, 99, 114],
    [46, 59, 120],
    [12, 16, 30, 43, 54, 65, 104],
    [32, 74, 85],
    [36, 90, 103, 118],
    [50, 63, 124],
    [16, 20, 34, 47, 58, 69, 108],
    [36, 78, 89],
    [40, 94, 107, 122],
    [0, 54, 67],
    [20, 24, 38, 51, 62, 73, 112],
    [40, 82, 93],
    [44, 98, 111, 126],
    [4, 58, 71],
    [24, 28, 42, 55, 66, 77, 116],
    [44, 86, 97],
    [2, 48, 102, 115],
    [8, 62, 75],
    [28, 32, 46, 59, 70, 81, 120],
    [48, 90, 101],
    [6, 52, 106, 119],
    [12, 66, 79],
    [32, 36, 50, 63, 74, 85, 124],
    [52, 94, 105],
    [10, 56, 110, 123],
    [16, 70, 83],
    [0, 36, 40, 54, 67, 78, 89],
    [56, 98, 109],
    [14, 60, 114, 127],
    [20, 74, 87],
    [4, 40, 44, 58, 71, 82, 93],
    [60, 102, 113],
    [3, 18, 72, 114, 118, 125],
    [24, 78, 91],
    [8, 44, 48, 62, 75, 86, 97],
    [64, 106, 117],
    [1, 7, 22, 76, 118, 122],
    [28, 82, 95],
    [12, 48, 52, 66, 79, 90, 101],
    [68, 110, 121],
    [5, 11, 26, 80, 122, 126],
    [32, 86, 99],
    ]

# Table for linear transformation while decryption
LTTableInverse = [
    [53, 55, 72],
    [1, 5, 20, 90],
    [15, 102],
    [3, 31, 90],
    [57, 59, 76],
    [5, 9, 24, 94],
    [19, 106],
    [7, 35, 94],
    [61, 63, 80],
    [9, 13, 28, 98],
    [23, 110],
    [11, 39, 98],
    [65, 67, 84],
    [13, 17, 32, 102],
    [27, 114],
    [1, 3, 15, 20, 43, 102],
    [69, 71, 88],
    [17, 21, 36, 106],
    [1, 31, 118],
    [5, 7, 19, 24, 47, 106],
    [73, 75, 92],
    [21, 25, 40, 110],
    [5, 35, 122],
    [9, 11, 23, 28, 51, 110],
    [77, 79, 96],
    [25, 29, 44, 114],
    [9, 39, 126],
    [13, 15, 27, 32, 55, 114],
    [81, 83, 100],
    [1, 29, 33, 48, 118],
    [2, 13, 43],
    [1, 17, 19, 31, 36, 59, 118],
    [85, 87, 104],
    [5, 33, 37, 52, 122],
    [6, 17, 47],
    [5, 21, 23, 35, 40, 63, 122],
    [89, 91, 108],
    [9, 37, 41, 56, 126],
    [10, 21, 51],
    [9, 25, 27, 39, 44, 67, 126],
    [93, 95, 112],
    [2, 13, 41, 45, 60],
    [14, 25, 55],
    [2, 13, 29, 31, 43, 48, 71],
    [97, 99, 116],
    [6, 17, 45, 49, 64],
    [18, 29, 59],
    [6, 17, 33, 35, 47, 52, 75],
    [101, 103, 120],
    [10, 21, 49, 53, 68],
    [22, 33, 63],
    [10, 21, 37, 39, 51, 56, 79],
    [105, 107, 124],
    [14, 25, 53, 57, 72],
    [26, 37, 67],
    [14, 25, 41, 43, 55, 60, 83],
    [0, 109, 111],
    [18, 29, 57, 61, 76],
    [30, 41, 71],
    [18, 29, 45, 47, 59, 64, 87],
    [4, 113, 115],
    [22, 33, 61, 65, 80],
    [34, 45, 75],
    [22, 33, 49, 51, 63, 68, 91],
    [8, 117, 119],
    [26, 37, 65, 69, 84],
    [38, 49, 79],
    [26, 37, 53, 55, 67, 72, 95],
    [12, 121, 123],
    [30, 41, 69, 73, 88],
    [42, 53, 83],
    [30, 41, 57, 59, 71, 76, 99],
    [16, 125, 127],
    [34, 45, 73, 77, 92],
    [46, 57, 87],
    [34, 45, 61, 63, 75, 80, 103],
    [1, 3, 20],
    [38, 49, 77, 81, 96],
    [50, 61, 91],
    [38, 49, 65, 67, 79, 84, 107],
    [5, 7, 24],
    [42, 53, 81, 85, 100],
    [54, 65, 95],
    [42, 53, 69, 71, 83, 88, 111],
    [9, 11, 28],
    [46, 57, 85, 89, 104],
    [58, 69, 99],
    [46, 57, 73, 75, 87, 92, 115],
    [13, 15, 32],
    [50, 61, 89, 93, 108],
    [62, 73, 103],
    [50, 61, 77, 79, 91, 96, 119],
    [17, 19, 36],
    [54, 65, 93, 97, 112],
    [66, 77, 107],
    [54, 65, 81, 83, 95, 100, 123],
    [21, 23, 40],
    [58, 69, 97, 101, 116],
    [70, 81, 111],
    [58, 69, 85, 87, 99, 104, 127],
    [25, 27, 44],
    [62, 73, 101, 105, 120],
    [74, 85, 115],
    [3, 62, 73, 89, 91, 103, 108],
    [29, 31, 48],
    [66, 77, 105, 109, 124],
    [78, 89, 119],
    [7, 66, 77, 93, 95, 107, 112],
    [33, 35, 52],
    [0, 70, 81, 109, 113],
    [82, 93, 123],
    [11, 70, 81, 97, 99, 111, 116],
    [37, 39, 56],
    [4, 74, 85, 113, 117],
    [86, 97, 127],
    [15, 74, 85, 101, 103, 115, 120],
    [41, 43, 60],
    [8, 78, 89, 117, 121],
    [3, 90],
    [19, 78, 89, 105, 107, 119, 124],
    [45, 47, 64],
    [12, 82, 93, 121, 125],
    [7, 94],
    [0, 23, 82, 93, 109, 111, 123],
    [49, 51, 68],
    [1, 16, 86, 97, 125],
    [11, 98],
    [4, 27, 86, 97, 113, 115, 127],
]

"""#### Constants"""

# Fractional part of Golden Ratio
phi = 0x9e3779b9

# Number of rounds
r = 32

"""### Functions

#### Substitution step
"""

# S-box and S-box inverse
# substitution according to provided box number
def S(box, input):
    return SBoxBitstring[box%8][input]
    
# inverse substitution according to provided block number
def SInverse(box, output):
    return SBoxBitstringInverse[box%8][output]


# Substituting each character in 128 bit string according to box number provided 
# substitution
def SHat(box, input):
    result = ""
    for i in range(32):
        result = result + S(box, input[4*i:4*(i+1)])
    return result

# inverse substitution
def SHatInverse(box, output):
    result = ""
    for i in range(32):
        result = result + SInverse(box, output[4*i:4*(i+1)])
    return result


# Substituting each character of 4 32 bit words taken as list
# substitution
def SBitslice(box, words):
    result = ["", "", "", ""]
    for i in range(32):
        quad = S(box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result

# inverse substitution
def SBitsliceInverse(box, words):
    result = ["", "", "", ""]
    for i in range(32): 
        quad = SInverse(
            box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result

"""#### Permutation step"""

# USing specified permutation table (IP or LP) as specified to perform permutation on 128 bit string
def applyPermutation(permutationTable, input):
    if len(input) != len(permutationTable):
        print("ValueError: input size {} doesn't match perm table size {}".format(len(input), len(permutationTable)))
    result = ""
    for i in range(len(permutationTable)):
        result = result + input[permutationTable[i]]
    return result

# Initial permutation
def IP(input):
    """Apply the Initial Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""
    return applyPermutation(IPTable, input)

# Inverse initial permutation or final permutation
def IPInverse(output):
    return FP(output)

# Final permutation
def FP(input):
    return applyPermutation(FPTable, input)

# Inverse final permutation or initial permutation
def FPInverse(output):
    """Apply the Final Permutation in reverse."""
    return IP(output)

"""#### Linear transformation step"""

# Using table to perform linear transformation on 128 bit string and returning 128 bit output
# linear transformation
def LT(input):
    if len(input) != 128:
        print("ValueError: input to LT is not 128 bit long")
    result = ""
    for i in range(len(LTTable)):
        outputBit = "0"
        for j in LTTable[i]:
            outputBit = xor(outputBit, input[j])
        result = result + outputBit
    return result
    
# inverse linear transformation
def LTInverse(output):
    if len(output) != 128:
        print("ValueError: input to inverse LT is not 128 bit long")
    result = ""
    for i in range(len(LTTableInverse)):
        inputBit = "0"
        for j in LTTableInverse[i]:
            inputBit = xor(inputBit, output[j])
        result = result + inputBit
    return result


# Using the linear transformation equation to the 4 32 bit input words, least significant word's bitstring taken first
# linear transformation
def LTBitslice(X):
    X[0] = rotateLeft(X[0], 13)
    X[2] = rotateLeft(X[2], 3)
    X[1] = xor(X[1], X[0], X[2])
    X[3] = xor(X[3], X[2], shiftLeft(X[0], 3))
    X[1] = rotateLeft(X[1], 1)
    X[3] = rotateLeft(X[3], 7)
    X[0] = xor(X[0], X[1], X[3])
    X[2] = xor(X[2], X[3], shiftLeft(X[1], 7))
    X[0] = rotateLeft(X[0], 5)
    X[2] = rotateLeft(X[2], 22)
    return X

# inverse linear transformation
def LTBitsliceInverse(X):
    X[2] = rotateRight(X[2], 22)
    X[0] = rotateRight(X[0], 5)
    X[2] = xor(X[2], X[3], shiftLeft(X[1], 7))
    X[0] = xor(X[0], X[1], X[3])
    X[3] = rotateRight(X[3], 7)
    X[1] = rotateRight(X[1], 1)
    X[3] = xor(X[3], X[2], shiftLeft(X[0], 3))
    X[1] = xor(X[1], X[0], X[2])
    X[2] = rotateRight(X[2], 3)
    X[0] = rotateRight(X[0], 13)
    return X

"""### Round"""

# Each round takes a 128 bit string and applies the round operations on it in the given order: 
# round key mixing, substitution and linear transformation (addition key mixing in case of last round)
# r = 32 rounds
# one round during encryption
def R(i, BHati, KHat):
    # adding round key
    xored = xor(BHati, KHat[i])
    # Passing through sbox
    SHati = SHat(i, xored)
    # Last step of round depending on which rounkd it is
    # for every round except last, linear transformation applied
    if 0 <= i <= r-2:
        BHatiPlus1 = LT(SHati)
    # in case of last round, round key added
    elif i == r-1:
        BHatiPlus1 = xor(SHati, KHat[r])
    else:
        print("ValueError: round {} is out of 0..{} range".format(i, r-1))
    # returning input for the next round except in case of last round
    return BHatiPlus1

# Each round takes a 128 bit string and applies the round operation on it in the given order:
# inverse linear transformation (additional key mixing in case of first decryption round = inverse of last encryption round), inverse substitution, key mixing
# r = 32 rounds
# one round during decryption
def RInverse(i, BHatiPlus1, KHat): 
    # inverse linear transformation
    if 0 <= i <= r-2:
        SHati = LTInverse(BHatiPlus1)
    # in case of inverse of last encryption round
    elif i == r-1:
        SHati = xor(BHatiPlus1, KHat[r])
    else:
        print("ValueError: round {} is out of 0..{} range".format(i, r-1))
    # inverse substitution
    xored = SHatInverse(i, SHati)
    # key mixing
    BHati = xor(xored, KHat[i])
    # returns input for previous round
    return BHati


# Bitslice version (input and output are both lists of 4 32-bit bitstrings)
def RBitslice(i, Bi, K):
    # Key mixing
    xored = xor (Bi, K[i])
    # Substitution
    Si = SBitslice(i, quadSplit(xored))
    # Linear Transformation
    if i == r-1:
        # In the last round, replaced by an additional key mixing
        BiPlus1 = xor(quadJoin(Si), K[r])
    else:
        BiPlus1 = quadJoin(LTBitslice(Si))
    # BIPlus1 is a 128-bit bitstring
    return BiPlus1

# Bitslice version (input and output are both lists of 4 32-bit bitstrings)
def RBitsliceInverse(i, BiPlus1, K):
    # Linear Transformation
    if i == r-1:
        # In the last round, replaced by an additional key mixing
        Si = quadSplit(xor(BiPlus1, K[r]))
    else:
        Si = LTBitsliceInverse(quadSplit(BiPlus1))
    # S Boxes
    xored = SBitsliceInverse(i, Si)
    # Key mixing
    Bi = xor (quadJoin(xored), K[i])
    return Bi

"""### Keyscheduling"""

def makeSubkeys(userKey):
    # We write the key as 8 32-bit words w-8 ... w-1
    # w-8 is the least significant word
    w = {}
    for i in range(-8, 0):
        w[i] = userKey[(i+8)*32:(i+9)*32]


    # We expand these to a prekey w0 ... w131 with the affine recurrence
    for i in range(132):
        w[i] = rotateLeft(
            xor(w[i-8], w[i-5], w[i-3], w[i-1], bitstring(phi, 32), bitstring(i,32)), 11)


    # The round keys are now calculated from the prekeys using the S-boxes
    # in bitslice mode. Each k[i] is a 32-bit bitstring.
    k = {}
    for i in range(r+1):
        whichS = (r + 3 - i) % r
        k[0+4*i] = ""
        k[1+4*i] = ""
        k[2+4*i] = ""
        k[3+4*i] = ""
        for j in range(32): # for every bit in the k and w words
            # ENOTE: w0 and k0 are the least significant words, w99 and k99
            # the most.
            input = w[0+4*i][j] + w[1+4*i][j] + w[2+4*i][j] + w[3+4*i][j]
            output = S(whichS, input)
            for l in range(4):
                k[l+4*i] = k[l+4*i] + output[l]

    # We then renumber the 32 bit values k_j as 128 bit subkeys K_i.
    K = []
    for i in range(33):
        # ENOTE: k4i is the least significant word, k4i+3 the most.
        K.append(k[4*i] + k[4*i+1] + k[4*i+2] + k[4*i+3])

    # We now apply IP to the round key in order to place the key bits in
    # the correct column
    KHat = []
    for i in range(33):
        KHat.append(IP(K[i]))
        #O.show("Ki", K[i], "(i=%2d) Ki" % i)
        #O.show("KHati", KHat[i], "(i=%2d) KHati" % i)

    return w, K, KHat


def makeLongKey(k):
    """Take a key k in bitstring format. Return the long version of that
    key."""

    l = len(k)
    if l % 32 != 0 or l < 64 or l > 256:
        print("ValueError: Invalid key length {} bits)".format(l))
    
    if l == 256:
        return k
    else:
        return k + "1" + "0"*(256 -l -1)

'''key = "6E3272357538782F413F4428472B4B6250645367566B59703373367639792442"
bitkey = bitstring(int(key, 16), 256)
print(bitkey)
subkeys = makeSubkeys(bitkey)
hexkey = hex(int(bitkey, 2))[2:].upper()
print(hexkey == key)'''

"""### Encryption"""

# input : 128-bit string of plaintext and 256-bit string of key in bits
# outputs 128 bit string of ciphertext in bits
def encrypt(plainText, userKey):   
    # Key scheduling to get sub keys for each round
    w, K, KHat = makeSubkeys(userKey)
    # Initial permutation
    BHat = IP(plainText) 
    # 32 rounds
    for i in range(r):
        BHat = R(i, BHat, KHat) # Produce BHat_i+1 from BHat_i
    # BHat is now _32 i.e. _r
    # Final permutation
    C = FP(BHat)
    # Ciphertext
    return C

# Bitslice version 
def encryptBitslice(plainText, userKey):
    K, KHat = makeSubkeys(userKey)
    B = plainText 
    for i in range(r):
        B = RBitslice(i, B, K) 
    return B

'''message = "28472B4B6250655368566D5971337436"
bitmg = bin(int(message, 16))
print(bitmg)
encrypted = encrypt(bitmg, bitkey)
print(encrypted)
print(hex(int(encrypted, 2))[2:].upper())'''

"""### Decryption"""

# input : 128-bit string of ciphertext and 256-bit string of key in bits
# outputs 128-bit string of plaintext in bits
def decrypt(cipherText, userKey):
    # key scheduling to get subkeys for all rounds
    w, K, KHat = makeSubkeys(userKey)
    # Inverse of final permutation => initial permutation
    BHat = FPInverse(cipherText) # BHat_r at this stage
    # Inverse rounds
    for i in range(r-1, -1, -1): # from r-1 down to 0 included
        BHat = RInverse(i, BHat, KHat)
    # Inverse of initial permutation => final permutation
    plainText = IPInverse(BHat)
    # returns plaintext
    return plainText
    
# Bitslice version
def decryptBitslice(cipherText, userKey):
    K, KHat = makeSubkeys(userKey)
    B = cipherText 
    for i in range(r-1, -1, -1):
        B = RBitsliceInverse(i, B, K) 
    return B

'''message_new = "BD01C3AEE094B0EBC061F398B802F254"
bitmg_new = bin(int(message_new, 16))
decrypted_new = decrypt(encrypted, bitkey)
hexdec_new = str(hex(int(decrypted_new, 2)))[2:].upper()
print(hexdec_new)
print(decrypted_new)

"""Checking whether decrypted ciphertext matches plaintext"""

print(hexdec_new == message)'''

"""### To-Use"""

'''process = int(input("Would you like to perform encryption or decryption (1:encryption / 2:decryption)? "))
all = []

def Process(process):
  text = input("Please enter 128 bit text in hexadecimal format: ")
  bittext = bitstring(int("0x"+text, 16), 128)
  key = input("Please enter 256 bit key in hexadecimal format: ")
  bitkey = bitstring(int("0x"+key, 16), 256)
  if process == 1:
      encrypted = encrypt(bittext, bitkey)
      hexenc = str(hex(int(encrypted, 2)))[2:]
      print("\n\ngiven plaintext: {}\nciphertext: {}\n\n".format(text, hexenc.upper()))
      all.append(encrypted)
      all.append(hexenc)
  elif process == 2:
      decrypted = decrypt(bittext, bitkey) 
      hexdec = str(hex(int(decrypted, 2)))[2:] 
      print("\n\ngiven ciphertext: {}\nplaintext: {}\n\n".format(text, hexdec.upper()))
      all.append(decrypted)
      all.append(hexdec)
  else:
      print("\n\nPlease enter a valid choice.\n\n")
  cont = input("Do you want to continue (Y:yes / N:no)? ")
  if cont == "Y":
      pn = int(input("\n\nWould you like to perform encryption or decryption (1:encryption / 2:decryption)? "))
      Process(pn)
  return all

info = Process(process)'''


asciiInvDict = {"0":0}
for i in range(65, 91):
  asciiInvDict[chr(i)] = i

asciiDict = {"0": 0}
for i in range(65, 91):
  asciiDict[i] = chr(i)

def str2bitstring(name):
  name = name.upper()
  if len(name) < 32:
    name = "0"*(2*(32-len(name))) + name
  name_new = ""
  for letter in name:
    name_new += str(asciiInvDict[letter])
  bittext = bin(int(name_new, 16))[2:]
  if len(bittext) < 128:
    bittext = "0"*(128-len(bittext)) + bittext
  return bittext

def bitstring2str(hexstr):
  bittext = hex(int(hexstr, 2))[2:]
  hextext = ""
  for i in range(0, len(bittext), 2):
    hextext += asciiDict[int(bittext[i:i+2])]
  return hextext.lower()

def list_enc(name_list, key):
  bitkey = bin(int(key, 16))[2:]
  if len(bitkey) < 256:
    bitkey = "0"*(256-len(bitkey)) + bitkey
  encrypted_names = []
  for i in range(len(name_list)):
    name = name_list[i].upper()
    bitname = str2bitstring(name)
    encrypted = encrypt(bitname, bitkey)
    hexen = hex(int(encrypted, 2))[2:]
    encrypted_names.append(hexen)
  return encrypted_names

def list_dec(enc_list, key):
  bitkey = bin(int(key, 16))[2:]
  if len(bitkey) < 256:
    bitkey = "0"*(256-len(bitkey)) + bitkey
  decrypted_names = []
  for i in range(len(enc_list)):
    enc_name = bin(int(enc_list[i], 16))[2:]
    if len(enc_name)<128:
      enc_name = "0"*(128-len(enc_name))+enc_name
    decrypted = decrypt(enc_name, bitkey)
    hexde = bitstring2str(decrypted)
    decrypted_names.append(hexde)
  return decrypted_names