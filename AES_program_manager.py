# AES program manager (main)

from tkinter import *
import tkinter as tk
import tkinter.font as tkFont

import sys
import subprocess
import ast

import math
import random

# call AES functions

##misc_arg = ''
##misc_arg = 'print_methods'

class AES128: # need to change what functions take as inputs
    def order_encrypt(state, key, misc_arg):

        cipher_out = subprocess.check_output([sys.executable, "AES_128_encrypt_direct_output.py", state, key, misc_arg]).decode(sys.stdout.encoding)
##        print('CIPHER OUT:', cipher_out)

        if misc_arg == 'print_methods':
            process_container = cipher_out.split('$$$')[-2]
            process_container = ast.literal_eval(process_container)
            for i in range(0, len(process_container)):
                print(process_container[i])

        encrypted_tuple = cipher_out.split('$$$')[-1]
        encrypted_tuple = ast.literal_eval(encrypted_tuple)
        if misc_arg == 'print_methods':
            print('\t\t\t\t\t\t\t\t' + str(encrypted_tuple[0]) + '\t' + str(encrypted_tuple[1]))
##        print(encrypted_tuple)

        #encrypted_tuple = encrypt(state, key)
        #encrypted_tuple = ['320ef384b15182d524c86415278f6b16', '5f93c14632aeea583d1eb938b78275ed'] # state, key

        return encrypted_tuple


    def order_decrypt(state, key, misc_arg):

        decipher_out = subprocess.check_output([sys.executable, "AES_128_decrypt_direct_output.py", state, key, misc_arg]).decode(sys.stdout.encoding)

        if misc_arg == 'print_methods':
            process_container = decipher_out.split('$$$')[-2]
            process_container = ast.literal_eval(process_container)
            for i in range(0, len(process_container)):
                print(process_container[i])

        decrypted_tuple = decipher_out.split('$$$')[-1]
        decrypted_tuple = ast.literal_eval(decrypted_tuple)
        
        if misc_arg == 'print_methods':
            print('\t\t\t\t\t\t\t\t' + str(decrypted_tuple[0]) + '\t' + str(decrypted_tuple[1]))

        #decrypted_tuple = decrypt(state, key)
        #decrypted_tuple = ['320ef384b15182d524c86415278f6b16', '5f93c14632aeea583d1eb938b78275ed'] # state, key
        
        return decrypted_tuple


#                                       <<< INPUT >>>
def init(mode, misc_arg, PLAINTEXT, IV, CIPHERTEXT, KEY):
    #mode = 'decrypt' # 'encrypt'/'decrypt'


    if mode == 'encrypt':

        #PLAINTEXT = "I'm serious! He's won three Piston Cups!" # plaintext of any length
        #IV = '01234567890123' # plaintext up to 16 characters/32 bits long

        #                                     <<< ENCRYPT MODE >>>

        # [ENCRYPT MODE] convert utf-8 PLAINTEXT and IV to hex

        PLAINTEXT = PLAINTEXT.encode('utf-8').hex()
        IV = IV.encode('utf-8').hex()


        # [ENCRYPT MODE] pad PLAINTEXT and IV

        while len(PLAINTEXT)%32 != 0:
            PLAINTEXT += '00'
##        print('Hex formatted plaintext:', PLAINTEXT)

        while len(IV)%32 != 0:
            IV += '00'
##        print('IV:', IV)


        # [ENCRYPT MODE] check that init vector is 32 bits

        if len(IV) != 32:
            print('Invalid initialization vector length.')


        # [ENCRYPT MODE] split and parse block data

        blockchain = [] # states
        register = [IV] # keys

        encyptmode_ciphertext = [] # encrypted text from encrypt mode
        encryptmode_accesskey = [] # final access key from encrypt mode

        for i in range(1, 1+int(len(PLAINTEXT)/32)): # chunks data
            #print(PLAINTEXT[(32*i)-32:(32*i)])
            blockchain.append(PLAINTEXT[(32*i)-32:(32*i)])

        if misc_arg == 'print_methods':
            print('    OPERATION\t\t\t     VALUE\t\t\t\t    BLOCKCHAIN\t\t\t\t     REGISTER')
        for i in range(0, len(blockchain)): # parses data into encrypt function
            encrypt_tuple = AES128.order_encrypt(blockchain[i], register[i], misc_arg)
            # encrypt_tuple[0] == output state; encrypt_tuple[1] == output key
            encyptmode_ciphertext.append(encrypt_tuple[0])
            register.append(encrypt_tuple[1])

        # encryption outputs
        encyptmode_ciphertext = ''.join(encyptmode_ciphertext)
        encryptmode_accesskey = register[-1]

##        print('BLOCKCHAIN:', encyptmode_ciphertext)
##        print('REGISTER:', encryptmode_accesskey)
        return [encyptmode_ciphertext, encryptmode_accesskey]
        
            
    elif mode == 'decrypt':
        #CIPHERTEXT = '8a22f2878bf7fc042332c8dc67a7f38084cc789383ec7ee5ff8d9b2c5976829eed6464febf2ed25863b3b5bc4cc3ea31' # may be of any length
        #KEY = '745fcac365b2199e765f02b173737567' # may be up to 32 bits long


        #                                     <<< DECRYPT MODE >>>


        # [DECRYPT MODE] check that access key is 32 bits

        if len(KEY) != 32:
            print('Invalid access key length.')


        # [DECRYPT MODE] split and parse block data

        blockchain = [] # states
        register = [KEY] # keys

        decryptmode_plaintext = [] # plaintext from decrypt mode
        decryptmode_IV = [] # IV from decrypt mode

        for i in range(1, 1+int(len(CIPHERTEXT)/32)): # chunks data
            blockchain.append(CIPHERTEXT[(32*i)-32:(32*i)])
        blockchain.reverse()

        if misc_arg == 'print_methods':
            print('    OPERATION\t\t\t     VALUE\t\t\t\t    BLOCKCHAIN\t\t\t\t     REGISTER')
##        print(blockchain)
        for i in range(0, len(blockchain)): # parses data into encrypt function
            decrypt_tuple = AES128.order_decrypt(blockchain[i], register[i], misc_arg)
            # encrypt_tuple[0] == output state; encrypt_tuple[1] == output key
            decryptmode_plaintext.append(decrypt_tuple[0])
            register.append(decrypt_tuple[1])

        # encryption outputs
        decryptmode_plaintext.reverse()
        decryptmode_plaintext = ''.join(decryptmode_plaintext)
        decryptmode_IV = register[-1]

##        print('BLOCKCHAIN:', decryptmode_plaintext)
##        print('REGISTER:', decryptmode_IV)


        # [DECRYPT MODE] convert hex ciphertext and IV to utf-8

        PLAINTEXT = bytes.fromhex(decryptmode_plaintext).decode('latin-1') # may have to change this back to utf-8, but that encoding was raising a UnicodeDecodeError
##        print('PLAINTEXT:', PLAINTEXT)
        KEY = bytes.fromhex(decryptmode_IV).decode('latin-1') # see note about plaintext encoding above
##        print('KEY:', KEY)
        return [PLAINTEXT, KEY]
    

def RNG(password_length): # needs work. Check for undefined variables.

    #character pools
##    lowers_list = ['a', 'b', 'c', 'd', 'e', 'f']
##    numbers_list = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    lowers_list = ['a', 'b', 'c', 'd', 'e', 'f', 'g',
                   'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                   'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

    uppers_list = ['A', 'B', 'C', 'D', 'E', 'F', 'G',
                   'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                   'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']

    numbers_list = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

    symbols_list = ['!', '"', '#', '$', '%', '&', "'", '(', ')', '*',
                    '+', ',', '-', '.', '/', ':', ';', '<', '=', '>',
                    '?', '@', '[', "", ']', '^', '_', '`', '{', '|',
                    '}', '~']

    #character pool list
    char_pool = []

    char_pool = char_pool + lowers_list
    char_pool = char_pool + uppers_list
    char_pool = char_pool + numbers_list
    char_pool = char_pool + symbols_list


    #password
    password = ''

    #password specs to meet
    spec_lowers = [0]
    spec_uppers = [0]
    spec_numbers = [0]
    spec_symbols = [0]

    
    while password_length >= 4:

        #make a preliminary password
        for i in range(0, password_length):
            
            random_number = random.randint(1, len(char_pool))
            
            password = password + str(char_pool[random_number-1])

        #watch the computer try to find a good solution!
##        print(password)

        for character in password:
            
            if character in lowers_list:
                spec_lowers.append(1)

            if character in uppers_list:
                spec_uppers.append(1)

            if character in numbers_list:
                spec_numbers.append(1)

            if character in symbols_list:
                spec_symbols.append(1)

        #final check...
        if sum(spec_lowers) >= 1 and sum(spec_uppers) >= 1 and sum(spec_numbers) >= 1 and sum(spec_symbols) >= 1:
##            print('Done!\n')
            break

        else:
            password = ''
            pass


    if password_length < 4:
        
        for i in range(0, password_length):
            
            random_number = random.randint(1, len(char_pool))
            
            password = password + str(char_pool[random_number-1])

##        print(password)
    return password


class App:
    def __init__(self, root):
        #setting title
        root.title("AES-128 CBC")
        #setting window size
        width=600
        height=500
        screenwidth = root.winfo_screenwidth()
        screenheight = root.winfo_screenheight()
        alignstr = '%dx%d+%d+%d' % (width, height, (screenwidth - width) / 2, (screenheight - height) / 2)
        root.geometry(alignstr)
        root.resizable(width=False, height=False)

        title_label=tk.Label(root)
        ft = tkFont.Font(family='Times',size=28)
        title_label["font"] = ft
        title_label["fg"] = "#333333"
        title_label["justify"] = "center"
        title_label["text"] = "AES-128 CBC"
        title_label.place(x=0,y=0,width=599,height=194)

        encrypt_button=tk.Button(root)
        encrypt_button["bg"] = "#e9e9ed"
        encrypt_button["cursor"] = "watch"
        ft = tkFont.Font(family='Times',size=18)
        encrypt_button["font"] = ft
        encrypt_button["fg"] = "#000000"
        encrypt_button["justify"] = "center"
        encrypt_button["text"] = "ENCRYPT"
        encrypt_button.place(x=90,y=310,width=140,height=50)
        encrypt_button["command"] = self.encrypt_button_command

        decrypt_button=tk.Button(root)
        decrypt_button["bg"] = "#e9e9ed"
        ft = tkFont.Font(family='Times',size=18)
        decrypt_button["font"] = ft
        decrypt_button["fg"] = "#000000"
        decrypt_button["justify"] = "center"
        decrypt_button["text"] = "DECRYPT"
        decrypt_button.place(x=370,y=310,width=140,height=50)
        decrypt_button["command"] = self.decrypt_button_command

        author_label=tk.Label(root)
        ft = tkFont.Font(family='Times',size=10)
        author_label["font"] = ft
        author_label["fg"] = "#333333"
        author_label["justify"] = "center"
        author_label["text"] = "Everett Gillis 2023"
        author_label.place(x=0,y=470,width=116,height=30)
        
        text_label=tk.Label(root)
        ft = tkFont.Font(family='Times',size=13)
        text_label["font"] = ft
        text_label["fg"] = "#333333"
        text_label["justify"] = "right"
        text_label["text"] = "TEXT:"
        text_label.place(x=0,y=190,width=80,height=32)

        key_label=tk.Label(root)
        ft = tkFont.Font(family='Times',size=13)
        key_label["font"] = ft
        key_label["fg"] = "#333333"
        key_label["justify"] = "right"
        key_label["text"] = "KEY:"
        key_label.place(x=0,y=250,width=80,height=32)

        rand_button=tk.Button(root)
        rand_button["bg"] = "#e9e9ed"
        ft = tkFont.Font(family='Times',size=10)
        rand_button["font"] = ft
        rand_button["fg"] = "#000000"
        rand_button["justify"] = "center"
        rand_button["text"] = "RAND"
        rand_button.place(x=510,y=253,width=70,height=25)
        rand_button["command"] = self.rand_button_command

        text_out_label=tk.Label(root)
        ft = tkFont.Font(family='Times',size=13)
        text_out_label["font"] = ft
        text_out_label["fg"] = "#333333"
        text_out_label["justify"] = "right"
        text_out_label["text"] = "TEXT OUT:"
        text_out_label.place(x=0,y=380,width=80,height=32)

        key_out_label=tk.Label(root)
        ft = tkFont.Font(family='Times',size=13)
        key_out_label["font"] = ft
        key_out_label["fg"] = "#333333"
        key_out_label["justify"] = "right"
        key_out_label["text"] = "KEY OUT:"
        key_out_label.place(x=0,y=430,width=80,height=32)
        
    def rand_button_command(self):
##        print("command")
##        print('RANDOM PASS:', RNG(16))
        key_box_label.delete(0, "end") # delete all the text in the entry
        key_box_label.insert(0, str(RNG(16))) #insert random input password
        key_box_label.config(fg = 'black')

    def encrypt_button_command(self): # init(mode, misc_arg, PLAINTEXT, IV, CIPHERTEXT, KEY):
##        print("command")
        mode = 'encrypt'
        #misc_arg = 'print_methods'
        misc_arg = misc_arg_entry.get()
        PLAINTEXT = text_box_message.get()
        IV = key_box_label.get()
        CIPHERTEXT = ''
        KEY = ''
        encryptedoutput = init(mode, misc_arg, PLAINTEXT, IV, CIPHERTEXT, KEY)
        text_out_box_label.delete(0, "end") # delete all the text in the entry
        text_out_box_label.insert(0, str(encryptedoutput[0]))
        key_out_box_label.delete(0, "end") # delete all the text in the entry
        key_out_box_label.insert(0, str(encryptedoutput[1]))

    def decrypt_button_command(self):
##        print("command")
        mode = 'decrypt'
        #misc_arg = 'print_methods'
        misc_arg = misc_arg_entry.get()
        PLAINTEXT = ''
        IV = ''
        CIPHERTEXT = text_box_message.get()
        KEY = key_box_label.get()

        decryptedoutput = init(mode, misc_arg, PLAINTEXT, IV, CIPHERTEXT, KEY)
        text_out_box_label.delete(0, "end") # delete all the text in the entry
        text_out_box_label.insert(0, str(decryptedoutput[0]))
        key_out_box_label.delete(0, "end") # delete all the text in the entry
        key_out_box_label.insert(0, str(decryptedoutput[1]))

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)

    user_text = ''
                  
    text_box_message=tk.Entry(root, textvariable=user_text)
    text_box_message["borderwidth"] = "1px"
    ft = tkFont.Font(family='Times',size=10)
    text_box_message["font"] = ft
    text_box_message["fg"] = "#333333"
    text_box_message["justify"] = "left"
    text_box_message["text"] = "Encrypt plaintext or decrypt hexadecimal text."
    text_box_message.place(x=90,y=190,width=490,height=32)


    user_key = ''

    key_box_label=tk.Entry(root, textvariable=user_key)
    key_box_label["borderwidth"] = "1px"
    ft = tkFont.Font(family='Times',size=10)
    key_box_label["font"] = ft
    key_box_label["fg"] = "#333333"
    key_box_label["justify"] = "left"
    key_box_label["text"] = "Hexadecimal initialization vector (IV) or <17 char access key."
    key_box_label.place(x=90,y=250,width=405,height=32)

    # sneaky way to store variable
    misc_arg_entry=tk.Entry(root)
    misc_arg_entry["text"] = ''

    # show steps button control misc_arg function
    def showsteps_button_command():
        if cb.get() == 1:
##            print('on')
            misc_arg_entry.delete(0, 'end')
            misc_arg_entry.insert(0, 'print_methods')
            #misc_arg = 'print_methods'
        elif cb.get() == 0:
##            print('off')
            misc_arg_entry.delete(0, 'end')
            misc_arg_entry.insert(0, '')
            #misc_arg = ''

    cb = IntVar()

    showsteps_button=tk.Checkbutton(root)
    ft = tkFont.Font(family='Times',size=10)
    showsteps_button["font"] = ft
    showsteps_button["fg"] = "#333333"
    showsteps_button["justify"] = "center"
    showsteps_button["text"] = "Show steps"
    showsteps_button["relief"] = "flat"
    showsteps_button.place(x=250,y=314,width=100,height=42)
    showsteps_button["variable"] = cb
    showsteps_button["offvalue"] = 0
    showsteps_button["onvalue"] = 1
    showsteps_button["command"] = showsteps_button_command

    # temp text in main text box: minor functions
    def on_entry_click_text(event):
    # function that gets called whenever entry is clicked
        if text_box_message.get() == 'Encrypt plaintext or decrypt hexadecimal text.':
           text_box_message.delete(0, "end") # delete all the text in the entry
           text_box_message.insert(0, '') #Insert blank for user input
           text_box_message.config(fg = 'black')
    def on_focusout_text(event):
        if text_box_message.get() == '':
            text_box_message.insert(0, 'Encrypt plaintext or decrypt hexadecimal text.')
            text_box_message.config(fg = 'grey')
    
    text_box_message.insert(0, 'Encrypt plaintext or decrypt hexadecimal text.')
    text_box_message.bind('<FocusIn>', on_entry_click_text)
    text_box_message.bind('<FocusOut>', on_focusout_text)
    text_box_message.config(fg = 'grey')

    # temp text in key box: minor functions
    def on_entry_click_key(event):
    # function that gets called whenever entry is clicked
        if key_box_label.get() == 'Hexadecimal initialization vector (IV) or <17 char access key.':
           key_box_label.delete(0, "end") # delete all the text in the entry
           key_box_label.insert(0, '') #Insert blank for user input
           key_box_label.config(fg = 'black')
    def on_focusout_key(event):
        if key_box_label.get() == '':
            key_box_label.insert(0, 'Hexadecimal initialization vector (IV) or <17 char access key.')
            key_box_label.config(fg = 'grey')
    
    key_box_label.insert(0, 'Hexadecimal initialization vector (IV) or <17 char access key.')
    key_box_label.bind('<FocusIn>', on_entry_click_key)
    key_box_label.bind('<FocusOut>', on_focusout_key)
    key_box_label.config(fg = 'grey')


    user_text_out = ''
    text_out_box_label=tk.Entry(root, textvariable=user_text_out)
    ft = tkFont.Font(family='Times',size=10)
    text_out_box_label["font"] = ft
    text_out_box_label["fg"] = "#333333"
    text_out_box_label["justify"] = "left"
    text_out_box_label["text"] = "Resultant text here."
    text_out_box_label.place(x=90,y=380,width=490,height=32)

    user_key_out = ''
    key_out_box_label=tk.Entry(root, textvariable=user_key_out)
    ft = tkFont.Font(family='Times',size=10)
    key_out_box_label["font"] = ft
    key_out_box_label["fg"] = "#333333"
    key_out_box_label["justify"] = "left"
    key_out_box_label["text"] = "Resultant access key or IV here."
    key_out_box_label.place(x=90,y=430,width=490,height=32)

              
    root.mainloop()
