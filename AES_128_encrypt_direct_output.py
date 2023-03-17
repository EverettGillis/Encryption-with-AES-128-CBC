# AES v.01/27/2022

import math
import numpy as np
import sys


###################################### <<< INPUTS >>> ######################################


bitlength = 128 #128, 192, 256
mode = 'encrypt' #encrypt, decrypt

##PLAINTEXT = '00112233445566778899aabbccddeeff' # NIST test I
##KEY = '000102030405060708090a0b0c0d0e0f'

##PLAINTEXT = '3243f6a8885a308d313198a2e0370734' # NIST test II
##KEY = '2b7e151628aed2a6abf7158809cf4f3c'

##PLAINTEXT = 'd92233498ac75012fb9f6236bc9761ee' # Rand test I
##KEY = '3d24038f3de17b9faf063f04fbf39ffc'

##PLAINTEXT = 'b40521450a07ac14bf82d8f22c83e133' # Rand test II
##KEY = '566f10aee1b7f808c76048f58059ada3'

##PLAINTEXT = 'fad2afb142b327854d3f1082ee51bfe4' # Rand test III
##KEY = '8bc3d92b722e49570b7d0961d15a72fb'


####################################### <<< INIT >>> #######################################


Nk = 0 #key length
Nb = 4 #constant block size
Nr = 0 #number of rounds

roundnumber = 1

if bitlength == 128:
    Nk = 4
    Nr = 10
elif bitlength == 192:
    Nk = 6
    Nr = 12
elif bitlength == 256:
    Nk = 8
    Nr = 14
else:
    print('Bit length error!')
    

###################################### <<< STATE >>> ######################################


class State:

    def Flatten(array):
        array = np.reshape(array, (1,4*Nk), 'F')
        output = []
        array = array.flatten()
        for value in array:
            output.append(str(value))
        output = ''.join(output)
        return output

    def Format(hextext, n, order):
        
        hex_list = []
        hext_evens = []
        hext_odds = []

        for i in range(0, len(hextext)):
            if i % 2 == 0:
                hext_evens.append(hextext[i])
            else:
                hext_odds.append(hextext[i])

        for i in range(0, int(len(hextext)/2)):
            hex_list.append(''.join(hext_evens[i]+hext_odds[i]))

        hex_array = np.array([hex_list])
        hex_array = np.reshape(hex_array,(n,4), order)
        return hex_array


#################################### <<< FUNCTIONS >>> ####################################


class SubBytes:
    
    def Transform(array):
        
        sbox = np.array([
            '63','7c','77','7b','f2','6b','6f','c5','30','01','67','2b','fe','d7','ab','76',
            'ca','82','c9','7d','fa','59','47','f0','ad','d4','a2','af','9c','a4','72','c0',
            'b7','fd','93','26','36','3f','f7','cc','34','a5','e5','f1','71','d8','31','15',
            '04','c7','23','c3','18','96','05','9a','07','12','80','e2','eb','27','b2','75',
            '09','83','2c','1a','1b','6e','5a','a0','52','3b','d6','b3','29','e3','2f','84',
            '53','d1','00','ed','20','fc','b1','5b','6a','cb','be','39','4a','4c','58','cf',
            'd0','ef','aa','fb','43','4d','33','85','45','f9','02','7f','50','3c','9f','a8',
            '51','a3','40','8f','92','9d','38','f5','bc','b6','da','21','10','ff','f3','d2',
            'cd','0c','13','ec','5f','97','44','17','c4','a7','7e','3d','64','5d','19','73',
            '60','81','4f','dc','22','2a','90','88','46','ee','b8','14','de','5e','0b','db',
            'e0','32','3a','0a','49','06','24','5c','c2','d3','ac','62','91','95','e4','79',
            'e7','c8','37','6d','8d','d5','4e','a9','6c','56','f4','ea','65','7a','ae','08',
            'ba','78','25','2e','1c','a6','b4','c6','e8','dd','74','1f','4b','bd','8b','8a',
            '70','3e','b5','66','48','03','f6','0e','61','35','57','b9','86','c1','1d','9e',
            'e1','f8','98','11','69','d9','8e','94','9b','1e','87','e9','ce','55','28','df',
            '8c','a1','89','0d','bf','e6','42','68','41','99','2d','0f','b0','54','bb','16',
        ])

        sbox = np.reshape(sbox, (16, 16))

        s_dict = {
            'a': '10',
            'b': '11',
            'c': '12',
            'd': '13',
            'e': '14',
            'f': '15',
            }

        output = np.array([])
        sbox_coordinates = []
        for h in array:
            for j in h:
                for i in j:
                    try:
                        float(i)
                    except:
                        i = s_dict[i]
                    sbox_coordinates.append(int(i))
                    if len(sbox_coordinates) == 2:
                        output = np.append(output,(sbox[sbox_coordinates[0]][sbox_coordinates[1]]))
                        sbox_coordinates = []
        output = np.reshape(output, (4, Nk))
        return output


class ShiftRows:
    
    def Transform(array):
        output = np.array([])
        output = np.append(output, [array[0], np.roll(array[1],-1), np.roll(array[2],-2), np.roll(array[3],-3)])
        output = np.reshape(output, (4, Nk))
        return output


class MixColumns:

    def Multiply(a, b): #Multiply modulo two hex vals in GF2^8
        binary_byte = "{0:b}".format(int(b, 16))

        partial_products = []
        for bit in str(binary_byte):
            if bit == '1':
                partial_products.append(int(hex(int(str('0x' + a), 16)), 16)*int(hex(2**(len(binary_byte)-1)), 16))
            binary_byte = binary_byte[1:]

        output = 0
        while len(partial_products) > 0:
            output = output ^ partial_products[0]
            partial_products = partial_products[1:]
            
        #GF(2^8) mod
        dividend = output
        divisor = 283
        rem = 2

        if dividend > 255:
            while dividend > -1:
                divisor = 283
                divisor = divisor << len('{0:b}'.format(int(dividend), 10))-len('{0:b}'.format(int(divisor), 10))
                rem = dividend ^ divisor
                dividend = rem
                if 283 > rem:
                    dividend = -2
        elif dividend <= 255:
            rem = dividend
        elif divisor == dividend:
            rem = 0
        output = '{0:b}'.format(int(rem), 10)
        return output


    def Transform(array):

        output = array

        mix_box = np.array([
            '02','03','01','01',
            '01','02','03','01',
            '01','01','02','03',
            '03','01','01','02'
            ])
        mix_box = np.reshape(mix_box, (4, 4))

        output = np.array([])
        for j in range(0,4):
            for i in range(0,Nk):
                matrix_attribute = 0
                for h in range(0,Nk):
                    term = MixColumns.Multiply(str(mix_box[i,h]), str(array[h,j]))
                    matrix_attribute = matrix_attribute ^ int(term,2)
                matrix_attribute = hex(matrix_attribute).split('x')[-1]
                while len(matrix_attribute) < 2:
                    matrix_attribute = '0' + matrix_attribute
                output = np.append(output, matrix_attribute)
        output = np.reshape(output, (4,Nk), 'F')
        return output

class RoundKey:
    
    def init_k_sch(key):
        global k_sch
        k_sch = np.array([])
        k_sch = np.append(k_sch, key)
        k_sch = np.reshape(k_sch, (int((k_sch.size)/4),4), 'F')
        return k_sch

    def append_k_sch(key):
        global k_sch
        k_sch = np.append(k_sch, key)
        k_sch = np.reshape(k_sch, (int((k_sch.size)/4),4), 'C')
        return k_sch

    def XOR(state, roundkey):
        output = np.array([])
        for i in range(0,4):
            for j in range(0,4):
                factor_a = int(('0x'+ state[i][j]), 16)
                factor_b = int(('0x'+ roundkey[i][j]), 16)
                product_c = str(hex(factor_a ^ factor_b)).replace('0x', '')
                if len(product_c) < 2:
                    product_c = '0' + product_c
                output = np.append(output, product_c)
        output = output.reshape(4, Nk)
        return output

class KeyExpansion:
    
    def RotWord(word):
        output = np.array([])
        output = np.append(output, np.roll(word,-1))
        output = np.reshape(output, (1,4))
        return output

    def SubWord(word):
        for i in range(0, 3*Nk):
            word = np.append(word, '00')
        word = word.reshape(4,Nk)
        word = SubBytes.Transform(word)
        output = word[0]
        return output

    def Rcon(key):
        n = '01'
        for j in range(1,roundnumber):
            rcon_word = np.array([])
            rcon_word = np.append(rcon_word, n)
            for h in range(0,3):
                rcon_word = np.append(rcon_word, '00')
            rcon_word = np.reshape(rcon_word, (1,4))
            n = MixColumns.Multiply(n,'02')
            n = hex(int(n,2))[2:]
            if len(n)== 1:
                n = '0' + str(n)
        output = KeyExpansion.XOR(rcon_word, key)
        return output

    def XOR(word_a, word_b):
        output = np.array([])
        for j in range(0,len(word_a[0])):
            term = int(hex(int(str('0x' + word_a[0][j]), 16)), 16) ^ int(hex(int(str('0x' + word_b[j]), 16)), 16)
            term = hex(term)[2:]
            if len(term)== 1:
                term = '0' + term
            output = np.append(output, term)
        return output

    def Expand(key):
        global roundnumber
        roundnumber += 1
        word = KeyExpansion.RotWord(key[:,Nk-1])
        word = KeyExpansion.SubWord(word)
        word = np.array([KeyExpansion.Rcon(word)])
        word = KeyExpansion.XOR(word, key[:,(len(key)-Nk)])
        RoundKey.append_k_sch(word)
        for i in range(0, Nk-1):
            word = KeyExpansion.XOR(np.array([word]), k_sch[(len(k_sch)-Nk)])
            RoundKey.append_k_sch(word)
        output = np.array([])
        for i in range(0, Nk):
            output = np.append(output, k_sch[len(k_sch)-Nk+i])
        output = np.reshape(output, (4,Nk), 'F')
        return output


#################################### <<< CALL ORDER >>> ####################################

# main
def main(PLAINTEXT, KEY, misc_arg):
    process_container = []

    #init (input round)
    state = State.Format(PLAINTEXT, Nk, 'F')
    if misc_arg == 'print_methods':
##        print('PLAINTEXT:\t       ', State.Flatten(state))
##        process_container.append(str('PLAINTEXT:\t       ' + str(State.Flatten(state))))
        pass

    key = State.Format(KEY, Nk, 'F')
    if misc_arg == 'print_methods':
##        print('KEY:\t\t       ', State.Flatten(key))
##        process_container.append(str('KEY:\t\t       ' + str(State.Flatten(key))))
        pass

    k_sch = RoundKey.init_k_sch(key)

    if misc_arg == 'print_methods':
##        print('\nCYPHER (ENCRYPT):')
        process_container.append('CYPHER (ENCRYPT):')

    RN = ' 0'
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].input\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].input\t\t' + State.Flatten(state)))
##        print('round[' + RN + '].k_sch\t\t' + State.Flatten(key))
        process_container.append(str('round[' + RN + '].k_sch\t\t' + State.Flatten(key)))

    #rounds (roundnumber = 1 to roundnumber = Nr-1)
    for x in range(0, Nr-1):
        if len(str(roundnumber)) < 2:
            RN = ' ' + str(roundnumber)
            k_RN = ' ' + str(roundnumber - 1)
        elif len(str(roundnumber)) == 2:
            RN = str(roundnumber)
            k_RN = str(roundnumber - 1)
            
        state = RoundKey.XOR(state, key)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].start\t\t' + State.Flatten(state))
            process_container.append(str('round[' + RN + '].start\t\t' + State.Flatten(state)))

        state = SubBytes.Transform(state)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].s_box\t\t' + State.Flatten(state))
            process_container.append(str('round[' + RN + '].s_box\t\t' + State.Flatten(state)))

        state = ShiftRows.Transform(state)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].s_row\t\t' + State.Flatten(state))
            process_container.append(str('round[' + RN + '].s_row\t\t' + State.Flatten(state)))

        state = MixColumns.Transform(state)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].m_col\t\t' + State.Flatten(state))
            process_container.append(str('round[' + RN + '].m_col\t\t' + State.Flatten(state)))

        key = KeyExpansion.Expand(key)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].k_sch\t\t' + State.Flatten(key))
            process_container.append(str('round[' + RN + '].k_sch\t\t' + State.Flatten(key)))

    #final round (roundnumber = Nr)
        if len(str(roundnumber)) < 2:
            RN = ' ' + str(roundnumber)
            k_RN = ' ' + str(roundnumber - 1)
        elif len(str(roundnumber)) == 2:
            RN = str(roundnumber)
            k_RN = str(roundnumber - 1)
    state = RoundKey.XOR(state, key)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].start\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].start\t\t' + State.Flatten(state)))

    state = SubBytes.Transform(state)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].s_box\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].s_box\t\t' + State.Flatten(state)))

    state = ShiftRows.Transform(state)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].s_row\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].s_row\t\t' + State.Flatten(state)))

    key = KeyExpansion.Expand(key)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].k_sch\t\t' + State.Flatten(key))
        process_container.append(str('round[' + RN + '].k_sch\t\t' + State.Flatten(key)))

    state = RoundKey.XOR(state, key)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].output\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].output\t' + State.Flatten(state)))

##    print(process_container)

    print(str(process_container) + '$$$'+str([State.Flatten(state), State.Flatten(key)]))

    return# [process_container, State.Flatten(state), State.Flatten(key)]

# call main
if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3]) # state, key, misc_arg
##main(PLAINTEXT, KEY, 'print_methods')


