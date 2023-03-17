# AES v.08/29/2021

import math
import numpy as np
import sys

###################################### <<< INPUTS >>> ######################################

bitlength = 128 #128, 192, 256
mode = 'decrypt' #encrypt, decrypt

PLAINTEXT = '69c4e0d86a7b0430d8cdb78070b4c55a' # NIST test I
KEY = '13111d7fe3944a17f307a78b4d2b30c5'

##PLAINTEXT = '3925841d02dc09fbdc118597196a0b32' # NIST test II
##KEY = 'd014f9a8c9ee2589e13f0cc8b6630ca6'

##PLAINTEXT = 'c9257a2a309e9b4f36fed74129012eab' # Rand test I
##KEY = '44fea5e7fe1421ddf9744bfc4bedb93a'

##PLAINTEXT = '6cd76f9814a692f17f73a8644f4eaaa7' # Rand test II
##KEY = '77168b964a932daeaac409869f44650a'

##PLAINTEXT = '320ef384b15182d524c86415278f6b16' # Rand test III
##KEY = '5f93c14632aeea583d1eb938b78275ed'

##PLAINTEXT = '8a22f2878bf7fc042332c8dc67a7f380'
##KEY = 'ce71b451a5ac3afeecd6df5a29211136'


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
        output = []
        array = np.reshape(array, (1,4*Nk), 'F')
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


################################### <<< FUNCTIONS_INV >>> ###################################

class SubBytes:
    def Transform(array):
        
        sbox = np.array([
            '52','09','6a','d5','30','36','a5','38','bf','40','a3','9e','81','f3','d7','fb',
            '7c','e3','39','82','9b','2f','ff','87','34','8e','43','44','c4','de','e9','cb',
            '54','7b','94','32','a6','c2','23','3d','ee','4c','95','0b','42','fa','c3','4e',
            '08','2e','a1','66','28','d9','24','b2','76','5b','a2','49','6d','8b','d1','25',
            '72','f8','f6','64','86','68','98','16','d4','a4','5c','cc','5d','65','b6','92',
            '6c','70','48','50','fd','ed','b9','da','5e','15','46','57','a7','8d','9d','84',
            '90','d8','ab','00','8c','bc','d3','0a','f7','e4','58','05','b8','b3','45','06',
            'd0','2c','1e','8f','ca','3f','0f','02','c1','af','bd','03','01','13','8a','6b',
            '3a','91','11','41','4f','67','dc','ea','97','f2','cf','ce','f0','b4','e6','73',
            '96','ac','74','22','e7','ad','35','85','e2','f9','37','e8','1c','75','df','6e',
            '47','f1','1a','71','1d','29','c5','89','6f','b7','62','0e','aa','18','be','1b',
            'fc','56','3e','4b','c6','d2','79','20','9a','db','c0','fe','78','cd','5a','f4',
            '1f','dd','a8','33','88','07','c7','31','b1','12','10','59','27','80','ec','5f',
            '60','51','7f','a9','19','b5','4a','0d','2d','e5','7a','9f','93','c9','9c','ef',
            'a0','e0','3b','4d','ae','2a','f5','b0','c8','eb','bb','3c','83','53','99','61',
            '17','2b','04','7e','ba','77','d6','26','e1','69','14','63','55','21','0c','7d',
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

class InvSubBytes:
    def Transform(array):

        inv_sbox = np.array([
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


        inv_sbox = np.reshape(inv_sbox, (16, 16))

        s_dict = {
            'a': '10',
            'b': '11',
            'c': '12',
            'd': '13',
            'e': '14',
            'f': '15',
            }

        output = np.array([])
        inv_sbox_coordinates = []
        for h in array:
            for j in h:
                for i in j:
                    try:
                        float(i)
                    except:
                        i = s_dict[i]
                    inv_sbox_coordinates.append(int(i))
                    if len(inv_sbox_coordinates) == 2:
                        output = np.append(output,(inv_sbox[inv_sbox_coordinates[0]][inv_sbox_coordinates[1]]))
                        inv_sbox_coordinates = []
        output = np.reshape(output, (4, Nk))
        return output


class InvShiftRows:
    def Transform(array):
        output = np.array([])
        output = np.append(output, [array[0], np.roll(array[1],1), np.roll(array[2],2), np.roll(array[3],3)])
        output = np.reshape(output, (4, Nk))
        return output


class InvMixColumns:

    def Multiply(a, b): #Multiply modulo two hex vals in GF2^8

##        ###########
##        a = '09'
##        b = '3d'
##        ###########
            
        binary_byte = '{0:b}'.format(int(b, 16))

        # multiply polynomials a, b
        byte_a = [] # init lists
        byte_b = []
        
        for bit in '{0:b}'.format(int(a, 16)): # populate lists
            byte_a.append(int(bit))
        byte_a.reverse() # reverse lists for following function. Form x^0 + x^1 + ... + x^n
        for bit in '{0:b}'.format(int(b, 16)):
            byte_b.append(int(bit))
        byte_b.reverse()

        product = [0]*(len(byte_a)+len(byte_b)-1)
        for i in range(len(byte_a)):
            for j in range(len(byte_b)):
                product[i+j] += byte_a[i]*byte_b[j]
        #product.reverse() # un-reverse list such that form is x^n + ... + x^1 + x^0

        product = [0 if x==2 else x for x in product] # modulo 2
        product = [1 if x>1 else x for x in product] # turn higher odd numbers into 1

        # divide product by m(x)
        remainder = []
        quotient = []
        dividend = []
        power = 0
        for bit in product:
            if bit == 1:
                dividend.append(power)
            power += 1
        divisor = [0,1,3,4,8] # the magic polynomial

            # loop here
        for i in range(0, len(divisor)): # problem here: if dividend=0, program tries to index an empty list!
            
            # 1: try stop if divisor > remainder. Else, continue.
            try:
                if divisor[-1] > dividend[-1]:
                    pass
                    
                else:
            # 2: find GCD, generate part of the quotient
                    quotient_part = dividend[-1] - divisor[-1]
                    quotient.append(quotient_part)
                    
            # 3: calculate new dividend from divisor multiplied by quotient part
                    divisor_times_quotient_part = [x+quotient[-1] for x in divisor]
                    
            # 4, 5: subtract (XOR) new dividend from old dividend. Calculates remainder
                    for power in dividend:
                        if power not in divisor_times_quotient_part:
                            remainder.append(power)
                    for power in divisor_times_quotient_part:
                        if power not in dividend:
                            remainder.append(power)
                    remainder.sort()

            # 6: dividend becomes remainder here
                    dividend = remainder
                    
            # 7: reset remainder
                    remainder = []
                    
            except IndexError: # if dividend == [] (zero)
                pass

        # 1: check if divisor > remainder
        # 2: find GCD from divisor and dividend
        # 3: calc new dividend
        # 4: subtract
        # 5: calculate remainder
        # 6: dividend becomes remainder
        # 7: reset remainder

        # convert powers to binary
        output = [0,0,0,0,0,0,0,0]
        for power in dividend:
            output[power] = 1

        output.reverse()
        output = ''.join([str(x) if x>-1 else x for x in output])
        #output = hex(int(output, 2))[2:]
        output = int(output, 2)
##        output = '{0:b}'.format(int(output, 2), 2)
##        print(output)
##        output = int(output, 10)
####        print(output)

        # decimal -> hex
        #output = '{0:b}'.format(int(output), 10)

        return output


    def Transform(array):

        output = array

        mix_box = np.array([
            '0e','0b','0d','09',
            '09','0e','0b','0d',
            '0d','09','0e','0b',
            '0b','0d','09','0e'
            ])
        
        mix_box = np.reshape(mix_box, (4, 4))

        output = np.array([])
        for j in range(0,4):
            for i in range(0,Nk):
                matrix_attribute = 0
                for h in range(0,Nk):
                    term = InvMixColumns.Multiply(str(mix_box[i,h]), str(array[h,j]))
####
##                    print(mix_box[i,h] + ' • ' + array[h,j] + ' = ' + term + '\t(' + hex(int(term,2)).split('x')[-1] + ')')
##                    print(mix_box[i,h] + ' • ' + array[h,j] + ' = ' + str(term) + '\t(' + hex(term).split('x')[-1] + ')')
####
                    #matrix_attribute = matrix_attribute ^ int(term,2)
                    matrix_attribute = matrix_attribute ^ term
                matrix_attribute = hex(matrix_attribute).split('x')[-1]
                while len(matrix_attribute) < 2:
                    matrix_attribute = '0' + matrix_attribute
##                print('Result:', matrix_attribute, '\n')
                output = np.append(output, matrix_attribute)
        output = np.reshape(output, (4,Nk), 'F')
        return output

class InvRoundKey:
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

class InvRoundKey:
    def init_k_sch(key):
        global k_sch
        k_sch = np.array([])
        k_sch = np.append(k_sch, key)
        k_sch = np.reshape(k_sch, (int((k_sch.size)/4),4), 'F')
        #k_sch = np.reshape(k_sch, (int(k_sch.size/4/Nk), 4*Nk), 'F')
        return k_sch

    def append_k_sch(key):
        global k_sch
        k_sch = np.append(k_sch, key)
        k_sch = np.reshape(k_sch, (int((k_sch.size)/4),4), 'C')
        #k_sch = np.reshape(k_sch, (int(k_sch.size/4/Nk), 4*Nk), 'F')
##        print('K_SCH:\n', k_sch)
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

class InvKeyExpansion:
    def RotWord(word):
        output = np.array([])
        output = np.append(output, np.roll(word,-1))
        output = np.reshape(output, (1,4))
        return output

    def SubWord(word):
        for i in range(0, 3*Nk):
            word = np.append(word, '00')
        word = word.reshape(4,Nk)
        word = InvSubBytes.Transform(word)
        output = word[0]
        return output

    def Rcon(key):
        n = '01'
        for j in range(1,(Nr - roundnumber + 3)):
            rcon_word = np.array([])
            rcon_word = np.append(rcon_word, n)
            for h in range(0,3):
                rcon_word = np.append(rcon_word, '00')
            rcon_word = np.reshape(rcon_word, (1,4))
            n = InvMixColumns.Multiply(n,'02')
            n = hex(n)[2:]
            if len(n)== 1:
                n = '0' + str(n)
##        print('Roundnumber:', roundnumber, '\n'
##                  'Rcon:', rcon_word)
        output = InvKeyExpansion.XOR(rcon_word, key)
        return output

    def XOR(word_a, word_b):# ATTENTION! word_a must be 2D (e.g. [['12' '23' 5f' 14']]) and word_b must be 1D (e.g. ['12' '23' 5f' 14'])
        output = np.array([])
        for j in range(0,len(word_a[0])):
            term = int(hex(int(str('0x' + word_a[0][j]), 16)), 16) ^ int(hex(int(str('0x' + word_b[j]), 16)), 16)
            term = hex(term)[2:]
            if len(term)== 1:
                term = '0' + term
            output = np.append(output, term)
##        print(word_a, 'XOR', word_b, '=', output)
        return output

    def Expand(key): #XOR current word with XOR after Rcon
        global roundnumber
        roundnumber += 1
        output = np.array([])

        for p in range(1, 5):
            if Nk-p == 0:
                temp = InvKeyExpansion.XOR(key[:, Nk-1].reshape(1,4), key[:, Nk-2])
                
                #RotWord
                temp = InvKeyExpansion.RotWord(temp)
##                print('After RotWord:\t\t\t', temp)

                #SubWord
                temp = InvKeyExpansion.SubWord(temp)
##                print('After SubWord:\t\t\t', temp)

                #XOR with Rcon
                temp = InvKeyExpansion.Rcon(temp)
##                print('After XOR with Rcon:\t\t', temp)

                #XOR temp with k_sch[Nk-4]
                temp = InvKeyExpansion.XOR(np.array([temp]), k_sch[len(k_sch)-4]) # formerly k_sch[Nk-4]
##                print('After XOR with k_sch[Nk-4]:\t', temp)
                
            else:
                temp = InvKeyExpansion.XOR(key[:, Nk-p].reshape(1,4), key[:, Nk-p-1])
            output = np.append(output, temp)

        #update key schedule
        output = np.reshape(output, (4,Nk), 'C')
        output = np.flip(output, 0)
        InvRoundKey.append_k_sch(output)
        
        #package output
        output = np.swapaxes(output, 0, 1)
        
        return output

################################## <<< INV CALL ORDER >>> ##################################

# main
def main(PLAINTEXT, KEY, misc_arg):
    process_container = []
    
    #init (input round)
        
    state = State.Format(PLAINTEXT, Nk, 'F')
    ##print('PLAINTEXT:\t       ', State.Flatten(state.reshape(4,4,order='C'))) # PROBLEM HERE: need to arrange array in C or F such that array is flattened into correct order
    if misc_arg == 'print_methods':
##        print('PLAINTEXT:\t       ', State.Flatten(state))
##        process_container.append(str('PLAINTEXT:\t       ', State.Flatten(state)))
        pass
    key = State.Format(KEY, Nk, 'F')
    if misc_arg == 'print_methods':
##        print('KEY:\t\t       ', State.Flatten(key))
##        process_container.append(str('KEY:\t\t       ', State.Flatten(key)))
        pass

    k_sch = InvRoundKey.init_k_sch(key)

    if misc_arg == 'print_methods':
##        print('\nINVERSE CYPHER (DECRYPT):')
        process_container.append('INVERSE CYPHER (DECRYPT):')

    RN = ' 0'
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].iinput\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].iinput\t' + State.Flatten(state)))
##        print('round[' + RN + '].ik_sch\t\t' + State.Flatten(key))
        process_container.append(str('round[' + RN + '].ik_sch\t' + State.Flatten(key)))

    RN = ' 1'
    state = InvRoundKey.XOR(state, key)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].istart\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].istart\t' + State.Flatten(state)))
    state = InvShiftRows.Transform(state)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].is_row\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].is_row\t' + State.Flatten(state)))
    state = SubBytes.Transform(state)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].is_box\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].is_box\t' + State.Flatten(state)))
    #rounds (0, Nr-1)


    #fwd order: 1)roundkey.xor, 2)sbytes.trans, 3)srows.trans, 4)mixcol.trans, 5)keyexp.exp
    #rev order: 1)keyexp.exp , 2)mixcol.trans, 3)srows.trans, 4)sbytes.trans, 5)roundkey.xor



    for x in range(0, 9):

        key = InvKeyExpansion.Expand(key)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].ik_sch\t\t' + State.Flatten(key))
            process_container.append(str('round[' + RN + '].ik_sch\t' + State.Flatten(key)))
        
        state = InvRoundKey.XOR(state, key)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].ik_add\t\t' + State.Flatten(state))
            process_container.append(str('round[' + RN + '].ik_add\t' + State.Flatten(state)))

        if len(str(roundnumber)) < 2:
            RN = ' ' + str(roundnumber)
            k_RN = ' ' + str(roundnumber - 1)
        elif len(str(roundnumber)) == 2:
            RN = str(roundnumber)
            k_RN = str(roundnumber - 1)

        state = InvMixColumns.Transform(state)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].istart\t\t' + State.Flatten(state))
            process_container.append(str('round[' + RN + '].istart\t' + State.Flatten(state)))

        state = InvShiftRows.Transform(state)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].is_row\t\t' + State.Flatten(state))
            process_container.append(str('round[' + RN + '].is_row\t' + State.Flatten(state)))

        state = SubBytes.Transform(state)
        if misc_arg == 'print_methods':
##            print('round[' + RN + '].is_box\t\t' + State.Flatten(state))
            process_container.append(str('round[' + RN + '].is_box\t' + State.Flatten(state)))

        if len(str(roundnumber)) < 2:
            RN = ' ' + str(roundnumber)
            k_RN = ' ' + str(roundnumber - 1)
        elif len(str(roundnumber)) == 2:
            RN = str(roundnumber)
            k_RN = str(roundnumber - 1)




    #final round (roundnumber = Nr)

    key = InvKeyExpansion.Expand(key)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].ik_sch\t\t' + State.Flatten(key))
        process_container.append(str('round[' + RN + '].ik_sch\t' + State.Flatten(key)))

    state = InvRoundKey.XOR(state, key)
    if misc_arg == 'print_methods':
##        print('round[' + RN + '].ioutput\t\t' + State.Flatten(state))
        process_container.append(str('round[' + RN + '].ioutput\t' + State.Flatten(state)))

    print(str(process_container) + '$$$'+str([State.Flatten(state), State.Flatten(key)]))
        
    return# [State.Flatten(state), State.Flatten(key)]

##main('320ef384b15182d524c86415278f6b16', '5f93c14632aeea583d1eb938b78275ed', 'print_methods')

##subprocess.check_output([sys.executable, "AES_128_encrypt_direct_output.py", '320ef384b15182d524c86415278f6b16', '5f93c14632aeea583d1eb938b78275ed', 'print_methods'])
# call main
if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2], sys.argv[3]) # state, key, misc_arg


#main(PLAINTEXT, KEY, '')
















