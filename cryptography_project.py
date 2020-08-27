###################################################
#caeser
def CaesarEn(plaintext,key):
    ciphertext=""
    for ch in plaintext:
        if ch.isalpha():
            shiftedalpha=ord(ch)+key
            if shiftedalpha> ord('Z' and 'z'):
                shiftedalpha -=26
            encryptedalpha=chr(shiftedalpha)
            ciphertext+=encryptedalpha
   # print("your ciphertext is :",ciphertext )
    return ciphertext
   
def CaesarDec(ciphertext,key):
    plaintext="" 
    for ch in ciphertext:
        if ch.isalpha():
            shiftedalpha=ord(ch)-key
            if shiftedalpha < ord('a' and 'A'):
               shiftedalpha +=26
               
            Decryptedalpha=chr(shiftedalpha)
            plaintext+=Decryptedalpha
     #print("your plaintext is :",plaintext )
    return plaintext
    
def caser():
    print("_caesercipher_encryption_")
    mytext=input("plz entre plaintext without spaces : ")
    key=int(input("enter your key :"))
    cryptstr=CaesarEn(mytext,key)
    print("The text after Encryption is:\n" + cryptstr,"\n")

    print("_caesercipher_decryption_")
    mytext=input("plz entre ciphertext without spaces : ")
    key=int(input("enter your key :"))
    decryptstr=CaesarDec(mytext,key)
    print("The text after Decryption is:"+decryptstr)
##############################################################
#mono
alphabets="abcdefghijklmnopqrstuvwxyz"
key=      "eyfqwdtcrjbganxoilzmpshkvu"
plaintext="item"

def enccrtpt():
    indexvals=[alphabets.index(char.lower()) for char in plaintext]
    return ''.join(key[indexkey] for indexkey in indexvals)

def decrypt():
    indexvals=[key.index(char) for char in ciphertext]
    return ''.join(alphabets[indexkey] for indexkey in indexvals)


ciphertext=enccrtpt()

def mono():
    print("_monocipher_encryption_")
    ciphertext=enccrtpt()
    print("Encryption message is:"+ ciphertext ,"\n")
    
    print("_monocipher_decryption_")
    originalMes=decrypt()
    print("Decryption message is:"+ originalMes)

############################################################
 #Vigenere Cipher 
def vigenere():
    print("_vigenerecipher_encryption_")
    plaintext=input("plz entre plaintext without spaces :")
    plaintext=plaintext.replace(" ", "")                                      # remove space in the message
    plaintext = ''.join([ch for ch in plaintext if not ch.isdigit()])         #remove any didgit from the message
    key=input("Enter Your key letter with same length as text: ")
    key=key.replace(" ", "")                                                    # remove space in the key
    key = ''.join([ch for ch in key if not ch.isdigit()])                      #remove any didgit from the key
    EncryptMessage=vigenereEnc(plaintext,key)
    print("Your Encryption Message :" + EncryptMessage,"\n" ) 
    
    print("_veginerecipher_decryption_")
    plaintext=input("plz entre ciphertext without spaces :")
    ciphertext=plaintext.replace(" ", "")                                      # remove space in the message
    plaintext = ''.join([ch for ch in plaintext if not ch.isdigit()])         #remove any didgit from the message
    key=input("Enter Your key letter with same length as text: ")
    key=key.replace(" ", "")                                                    # remove space in the key
    key = ''.join([ch for ch in key if not ch.isdigit()])                      #remove any didgit from the key
    DecrypMessage=vigenereDec(ciphertext,key)
    print("The original Message is: " + DecrypMessage)

#make plaintext and key with same length
def generateKey(plaintext,key):
    
    if len(plaintext)==len(key):
        return key
    else:
        for i in range(len(plaintext)-len(key)):
            key+=key[i % len(key)]
            
    return key


alphabets="abcdefghijklmnopqrstuvwxyz" 
key=generateKey(plaintext,key)


#Encryption Function
def vigenereEnc(plaintext,key):
    ciphertext=""
    C_Index=""
    
    plainindex=[alphabets.index(char.lower()) for char in plaintext]
    keyindex=[alphabets.index(char.lower()) for char in key]
    
    for i in range(len(plaintext)):
       C_Index=(plainindex[i]+keyindex[i])%26
       ciphertext+=alphabets[C_Index]
       
    return ciphertext    
    

#Decryption Function
def vigenereDec(ciphertext,key):
     plaintext=""
     P_Index=""
     
     cipherindex=[alphabets.index(char.lower()) for char in ciphertext]
     keyindex=[alphabets.index(char.lower()) for char in key]
     
     for i in range(len(ciphertext)):
         P_Index=(cipherindex[i]-keyindex[i]+26)%26
         plaintext+=alphabets[P_Index]
         
     return plaintext
         
 ####################################################
#affine
def affinecipher_encryption():
    print("_affinecipher_encryption_")
    p = input("Enter message: ")
    p = p.replace(" ", "").upper()
    ciphertxt=""
    a = int(input("enter the value of a : "))
    b = int(input("enter the value of b : "))
    for t in p :
        ci=((a*(ord(t))-ord('A')+b)%26)+ord('A')
        ciphertxt+=chr(ci)
    print(ciphertxt,"\n")

def affinecipher_decryption():
    print("_affinecipher_decryption_")
    ci = input("Enter message: ")
    ci = ci.replace(" ", "").upper()
    ptxt=""
    a = int(input("enter the value of a : "))
    b = int(input("enter the value of b : "))
    x=1
    while(x*a % 26 != 1) :
        x=x+1
    a=x
    print (x)
    for t in ci :
        pi=((a*(ord(t) - ord('A') - b)) % 26) + ord('A')
        ptxt+=chr(pi)
    print(ptxt)
    
    
def affine():
    affinecipher_encryption()
    affinecipher_decryption()    

#################################################
#hillcipher    
import sys
import numpy as np


def hillcipher_encryption():
    print("_hillcipher_encryption_")
    msg = input("Enter message: ").upper()
    msg = msg.replace(" ", "")

    # if message length is odd number, append 0 at the end
    len_chk = 0
    if len(msg) % 2 != 0:
        msg += "0"
        len_chk = 1

    # msg to matrices
    row = 2
    col = int(len(msg)/2)
    msg2d = np.zeros((row, col), dtype=int)

    itr1 = 0
    itr2 = 0
    for i in range(len(msg)):
        if i % 2 == 0:
            msg2d[0][itr1] = int(ord(msg[i])-65)
            itr1 += 1
        else:
            msg2d[1][itr2] = int(ord(msg[i])-65)
            itr2 += 1
    # for

    key = input("Enter 4 letter Key String: ").upper()
    key = key.replace(" ", "")

    # key to 2x2
    key2d = np.zeros((2, 2), dtype=int)
    itr3 = 0
    for i in range(2):
        for j in range(2):
            key2d[i][j] = ord(key[itr3])-65
            itr3 += 1

    # checking validity of the key
    # finding determinant
    deter = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
    deter = deter % 26

    # finding multiplicative inverse
    mul_inv = -1
    for i in range(26):
        temp_inv = deter * i
        if temp_inv % 26 == 1: 
            mul_inv = i
            break
        else:
            continue
    # for

    if mul_inv == -1:
        print("Invalid key")
        sys.exit()
    # if

    encryp_text = ""
    itr_count = int(len(msg)/2)
    if len_chk == 0:
        for i in range(itr_count):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            encryp_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            encryp_text += chr((temp2 % 26) + 65)
        # for
    else:
        for i in range(itr_count-1):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            encryp_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            encryp_text += chr((temp2 % 26) + 65)
        # for
    # if else

    print("Encrypted Text: {} \n".format(encryp_text))


def hillcipher_decryption():
    print("_hillcipher_decryption_")
    msg = input("Enter message: ").upper()
    msg = msg.replace(" ", "")

    # if message length is odd number, append 0 at the end
    len_chk = 0
    if len(msg) % 2 != 0:
        msg += "0"
        len_chk = 1

    # msg to matrices
    row = 2
    col = int(len(msg) / 2)
    msg2d = np.zeros((row, col), dtype=int)

    itr1 = 0
    itr2 = 0
    for i in range(len(msg)):
        if i % 2 == 0:
            msg2d[0][itr1] = int(ord(msg[i]) - 65)
            itr1 += 1
        else:
            msg2d[1][itr2] = int(ord(msg[i]) - 65)
            itr2 += 1
    # for

    key = input("Enter 4 letter Key String: ").upper()
    key = key.replace(" ", "")

    # key to 2x2
    key2d = np.zeros((2, 2), dtype=int)
    itr3 = 0
    for i in range(2):
        for j in range(2):
            key2d[i][j] = ord(key[itr3]) - 65
            itr3 += 1
    # for

    # finding determinant
    deter = key2d[0][0] * key2d[1][1] - key2d[0][1] * key2d[1][0]
    deter = deter % 26

    # finding multiplicative inverse
    mul_inv = -1
    for i in range(26):
        temp_inv = deter * i
        if temp_inv % 26 == 1:
            mul_inv = i
            break
        else:
            continue
    # for

    # adjugate matrix
    # swapping
    key2d[0][0], key2d[1][1] = key2d[1][1], key2d[0][0]

    # changing signs
    key2d[0][1] *= -1
    key2d[1][0] *= -1

    key2d[0][1] = key2d[0][1] % 26
    key2d[1][0] = key2d[1][0] % 26

    # multiplying multiplicative inverse with adjugate matrix
    for i in range(2):
        for j in range(2):
            key2d[i][j] *= mul_inv

    # modulo
    for i in range(2):
        for j in range(2):
            key2d[i][j] = key2d[i][j] % 26

    # cipher to plain
    decryp_text = ""
    itr_count = int(len(msg) / 2)
    if len_chk == 0:
        for i in range(itr_count):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            decryp_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            decryp_text += chr((temp2 % 26) + 65)
            # for
    else:
        for i in range(itr_count - 1):
            temp1 = msg2d[0][i] * key2d[0][0] + msg2d[1][i] * key2d[0][1]
            decryp_text += chr((temp1 % 26) + 65)
            temp2 = msg2d[0][i] * key2d[1][0] + msg2d[1][i] * key2d[1][1]
            decryp_text += chr((temp2 % 26) + 65)
            # for
    # if else

    print("Decrypted Text: {}".format(decryp_text))

def hill():
    hillcipher_encryption()
    hillcipher_decryption()
    
################################################
"""
def main():
    choice = int(input("1. CAESERCIPHER\n2. MONOCIPHER\n3. VIGENERECIPHER\n4. AFFINECIPHER\n5. HILLCIPHER\nChoose(1,2,3,4,5): "))
    if choice == 1:
        print("---caesercipher---")
        caser()
    elif choice == 2:
        print("---monocipher---")
        mono()   
    elif choice == 3:
        print("---vigenerecipher---")
        vigenere()
    elif choice == 4:
        print("---affinecipher---")
        affine()
    elif choice == 5:
        print("---hillcipher---")
        hill()

    else:
        print("Invalid Choice")

if __name__ == "__main__":
    main() """
##############################################

def  default1():
    print("\n$$$invalid choise please entre number (1-6)$$$")     

print("##### Hi this is smiple cryptocraphyapp #####")
print("      ##################################")
print("        #############################")
print("          ######################## ")
print("           ### Create By M_K_M ###\n")
print("1- caesercipher \n")
print("2- monocipher \n")
print("3- vigenerecipher \n")
print("4- affinecipher \n")
print("5- hillcipher ")
choise=eval(input(" - please choose the operation you want to perform :  ",))
print("\n")

my_switch={1:caser ,2:mono ,3:vigenere ,4:affine ,5:hill }
my_switch.get(choise ,default1)()