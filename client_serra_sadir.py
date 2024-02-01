import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve,Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json
import os

API_URL = 'http://harpoon1.sabanciuniv.edu:9999'

stuID = 28201

E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b


X="0x1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9"
Y="0xce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff"

#Server's Identitiy public key
IKey_Ser = Point(int("0x1d42d0b0e55ccba0dd86df9f32f44c4efd7cbcdbbb7f36fd38b2ca680ab126e9",base=16),int("0xce091928fa3738dc18f529bf269ade830eeb78672244fd2bdfbadcb26c4894ff",base=16),E)

#Key generation
def Key_Gen():
    k = Random.new().read(int(math.log(n,2)))
    k = int.from_bytes(k, byteorder='big')%n       
    sA = k
    QA = sA*P
    return sA, QA


sA, QA = Key_Gen()
print("sA", sA, "QA", QA)
# Signature generation
def Sig_Gen(m, sA):
    k = Random.new().read(int(math.log(n,2))) #1. k←Zn,(i.e.,kisarandomintegerin[1,n−2]).
    k = int.from_bytes(k, byteorder='big')%n  
    R = k*P #3. R=k·P
    r = R.x % n  # 3. r = R.x (mod n), where R.x is the x coordinate of R
    r_con_m = r.to_bytes((math.ceil(r.bit_length()/8)), byteorder='big') + m.to_bytes((math.ceil(m.bit_length()/8)), byteorder='big') #(r||m)
    h = SHA3_256.new(r_con_m) #h = SHA3 256(r||m) 
    h = int.from_bytes(h.digest(), byteorder='big') % n # 4.h = SHA3 256(r||m) (mod n) -> converted into integer from hexadecimal
    s = (k - sA*h) % n #5. s=(k−sA·h) (modn)
    return h,s #signature tuple


message = stuID



def Sig_Ver(m, h,s, QA):
    V = s*P + h*QA  #1. V = sP + hQA
    v = V.x % n    #2. v = V.x (mod n), where V.x is x coordinate of V

    v_con_m = v.to_bytes((math.ceil(v.bit_length()/8)), byteorder='big') + m.to_bytes((math.ceil(m.bit_length()/8)), byteorder='big')
    h_ver = SHA3_256.new(v_con_m)
    #3. h′ = SHA3 256(v||m) (mod n)
    h_ver = int.from_bytes(h_ver.digest(), byteorder='big') % n #converted into integer from hexadecimal

    if h_ver == h:
        return True  #4. Accept the signature only if h = h′
    else:
        return False #5. Reject it otherwise.



def IKRegReq(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json = mes)		
    print(response.json())


def IKRegVerify(code):
    mes = {'ID':stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json = mes)
    if((response.ok) == False): raise Exception(response.json())
    else:
        print(response.json())
        f = open('Identity_Key.txt', 'w')
        f.write("IK.Prv: "+str(IKey_Pr)+"\n"+"IK.Pub.x: "+str(IKey_Pub.x)+"\n"+"IK.Pub.y: "+str(IKey_Pub.y))
        f.close()

def SPKReg(h,s,x,y):
    mes = {'ID':stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json = mes)
    print(response.json())			

def OTKReg(keyID,x,y,hmac):
    mes = {'ID':stuID, 'KEYID': keyID, 'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True

def ResetSPK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


def ResetOTK(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json = mes)		
    if((response.ok) == False): print(response.json())



#send message to server -> format is {‘ID’: stuID, ‘H’: h, ‘S’: s, ‘IKPUB.X’: ikpub.x, ‘IKPUB.Y’: ikpub.y}

def FuncIKRegVer(stuID):
    IKey_Pr , IKey_Pub = Key_Gen()
    
    print("Private key:", IKey_Pr, "Public Key:", IKey_Pub)
    h , s = Sig_Gen(stuID,IKey_Pr)  
    print("h:",h,"s:",s)
    print("Verification:", Sig_Ver(stuID, h, s,IKey_Pub))
    return h, s, IKey_Pr , IKey_Pub

def ResetIK(rcode):
    mes = {'ID':stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json = mes)		
    print(response.json())
    if((response.ok) == False): return False
    else: return True


#rcode = int(input("Rcode: "))
#ResetIK(rcode)
#h,s, IKey_Pr , IKey_Pub = FuncIKRegVer(stuID)

IKey_Pr = 74602409118232834545905679695941466375799101996578107476656577050221529187044
IKey_Pub = Point(int("0xcc4f0b749a7e9e12f4178096b3a0c06df49031cdf68e4fd416b27b83757b7b7e",base=16),int("0x20bc5ff0d7bd76dc03a9d718edebb006fbd7babe035228aa32e8f4785530bc5d",base=16),E)

h = 32581452727248454477264259906283509510116364155119567945655119314618651807516
s = 90596246987349403939163722849372843852783745958857874242518852637621074431326

IKRegReq(h,s,IKey_Pub.x,IKey_Pub.y)

#code = int(input("Code: "))

IKRegVerify(184093)

print("Signature of my ID number is:")
print("h: ", h)
print("s: ", s)


print("+++++++++++++++++++++++++++++++++++++++++++++")

def FuncSPK():
    print("Generating SPK...")
    SKey_Pr, SKey_Pub = Key_Gen() 
    SKey_x = SKey_Pub.x
    SKey_y = SKey_Pub.y 
    print("Private SPK:", SKey_Pr, " \n Public SPK.x: ", SKey_Pub.x, "Public SPK.y: ", SKey_Pub.y)
    print("Convert SPK.x and SPK.y to bytes in order to sign them then concatenate them")
    #concatenate (SPKA.Pub.x || SPKA.Pub.y)
    x_con_y = SKey_x.to_bytes((math.ceil(SKey_x.bit_length()/8)), byteorder='big') + SKey_y.to_bytes((math.ceil(SKey_y.bit_length()/8)), byteorder='big')
    x_con_y = int.from_bytes(x_con_y, byteorder="big")
    spk_h, spk_s = Sig_Gen(x_con_y, IKey_Pr) #sign the public key part of the signed pre-key, SPKA.Pub using your identity key IKA 
    print("Signature of SPK is: \n h=", spk_h, "\n s= ",spk_s)
    print("Verification:" , Sig_Ver(x_con_y, spk_h, spk_s, IKey_Pub))
    return spk_h, spk_s, SKey_x, SKey_y, SKey_Pr

spk_h, spk_s, SKey_x, SKey_y, SKey_Pr = FuncSPK()
#print("spk_h", spk_h, "spk_s", spk_s, " spk pr", SKey_Pr, "skey x y", SKey_x, SKey_y,)
print("Sending SPK and the signatures to the server via SPKReg() function in json format...")


SPKReg(spk_h,spk_s,SKey_x,SKey_y)

SKey_Ser = IKey_Ser

def HMAC_Gen(SKey_Pr, SKey_Ser):

    T = SKey_Pr*SKey_Ser
    #U = {b’TheHMACKeyToSuccess’ ∥ T.y ∥ T.x}
    U = "TheHMACKeyToSuccess".encode()  + T.y.to_bytes((math.ceil(T.y.bit_length()/8)), byteorder='big') +  T.x.to_bytes((math.ceil(T.x.bit_length()/8)), byteorder='big')
    Khmac = SHA3_256.new().update(U).digest()
    print(Khmac)
    print("++++++++++++++++++++")
    return  Khmac #• KHMAC = SHA3 256(U)

ResetOTK(h,s)

def FuncOTK(SKey_Pr, SKey_Ser):
    HMACKey = HMAC_Gen(SKey_Pr, SKey_Ser) #T = SPK A.Pri · IK S.Pub (Diffie-Hellman with SPK of the client and the IK of the server)
    print("Creating HMAC key (Diffie Hellman)", HMACKey)
    HMACKeys = []
    OTKeys = []
    print("+++++++++++++++++++")
    print("Creating OTKs starting from index 1...")
    for i in range(1,11): #you must generate 10 one-time public and private key pairs     
        OKey_Pr, OKey_Pub = Key_Gen() 
        OKey_Pubx = OKey_Pub.x
        OKey_Puby = OKey_Pub.y
        x_con_y =  OKey_Pubx.to_bytes((math.ceil(OKey_Pubx.bit_length()/8)), byteorder='big') + OKey_Puby.to_bytes((math.ceil(OKey_Puby.bit_length()/8)), byteorder='big')
        Hmac = HMAC.new(key=HMACKey,msg=x_con_y,digestmod=SHA256).hexdigest()

        OTKReg(i,OKey_Pub.x,OKey_Pub.y,Hmac)
        print(i,"th key is generated", "\n", "Private part =",OKey_Pr, "\n","Public (x coordinate)=",OKey_Pub.x,"\n", "Public (y coordinate)=",OKey_Pub.y )
        HMACKeys.append(Hmac)
        print()
        OTKeys.append((OKey_Pr,OKey_Pub.x,OKey_Pub.y))
    return HMACKeys, OTKeys
HMACKeys = []
OTKeys = []
HMACKeys, OTKeys = FuncOTK(SKey_Pr, IKey_Ser)

print("OTK keys were generated successfully!")
j = 0
for i in OTKeys:
    print(j,i)
    j+=1

#----------------------------------------------------------PHASE 2 -------------------------------------------------------------------

stuID = 28201
stuIDB = 28201

def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m

def Setup():
    E = Curve.get_curve('secp256k1')
    return E



#server's Identitiy public key
IKey_Ser = Point(13235124847535533099468356850397783155412919701096209585248805345836420638441, 93192522080143207888898588123297137412359674872998361245305696362578896786687, E)

############## The new functions of phase 2 ###############
def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1,n-1)
    QA = sA*P
    return sA, QA

def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1, n-2)
    R = k*P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes((r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    s = (k - sA*h) % n
    return h, s

def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P + h*QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes((v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big')%n
    if h_ == h:
        return True
    else:
        return False

#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsg"), json = mes)		
    print(response.json())

#Get your messages. server will send 1 message from your inbox
def ReqMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json = mes)	
    print(response.json())	
    if((response.ok) == True): 
        res = response.json()
        return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["IK.X"], res["IK.Y"], res["EK.X"], res["EK.Y"]

#Get the list of the deleted messages' ids.
def ReqDelMsg(h,s):
    mes = {'ID':stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json = mes)      
    print(response.json())      
    if((response.ok) == True): 
        res = response.json()
        return res["MSGID"]

#If you decrypted the message, send back the plaintext for checking
def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA':stuID, 'IDB':stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json = mes)		
    print(response.json())

def Session_Key_Gen(Spka_pr, IKB_pub,EKB_pub,IKA_pr,OTKA_pr):
    #A refers to the receiver and B refers to the sender
    T1 = Spka_pr * IKB_pub  #T1 = IKB.Pub·SPKA.Pri   
    T2 = EKB_pub * IKA_pr   #T2 = EKB.Pub·IKA.Pri   
    T3 = EKB_pub * Spka_pr  #T3 = EKB.Pub·SPKA.Pri   
    T4 = EKB_pub * OTKA_pr  #T4 = EKB.Pub·OTKA.Pri
    #U={T1.x∥T1.y∥T2.x∥T2.y∥T3.x∥T3.y∥T4.x∥T4.y∥b’WhatsUpDoc’}
    U = T1.x.to_bytes((math.ceil(T1.x.bit_length()/8)), byteorder='big') + T1.y.to_bytes((math.ceil(T1.y.bit_length()/8)), byteorder='big') + T2.x.to_bytes((math.ceil(T2.x.bit_length()/8)), byteorder='big') + T2.y.to_bytes((math.ceil(T2.y.bit_length()/8)), byteorder='big')+ T3.x.to_bytes((math.ceil(T3.x.bit_length()/8)), byteorder='big') + T3.y.to_bytes((math.ceil(T3.y.bit_length()/8)), byteorder='big')+T4.x.to_bytes((math.ceil(T4.x.bit_length()/8)), byteorder='big') + T4.y.to_bytes((math.ceil(T4.y.bit_length()/8)), byteorder='big') + "WhatsUpDoc".encode()  
    Ks = SHA3_256.new(U)    #KS = SHA3 256(U)
    return Ks

def Key_Deriv(Key_KDF):
    #KENC = SHA3 256(KKDF ∥ b’JustKeepSwimming’)
    Kenc = SHA3_256.new(Key_KDF.digest() + b'JustKeepSwimming')
    #KHMAC = SHA3 256(KKDF ∥ KENC ∥ b’HakunaMatata’)
    Khmac = SHA3_256.new(Key_KDF.digest() + Kenc.digest() + b'HakunaMatata')
    #KKDF.Next = SHA3 256(KENC ∥ KHMAC ∥ b’OhanaMeansFamily’)
    Knext = SHA3_256.new(Kenc.digest() + Khmac.digest() + b'OhanaMeansFamily')
    return Kenc, Khmac, Knext


Knext = None
h,s = Sig_Gen(stuID, IKey_Pr)
Spka_pr = SKey_Pr
IKA_pr = IKey_Pr


#Pseudo-client will send you 5 messages to your inbox via server when you call this function
def PseudoSendMsgPH3(h,s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())

# Send a message to client idB
def SendMsg(idA, idB, otkID, msgid, msg, ikx, iky, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(otkID), "MSGID": msgid, "MSG": msg, "IK.X": ikx, "IK.Y": iky, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())    


# Receive KeyBundle of the client stuIDB
def reqKeyBundle(stuID, stuIDB, h, s):
    key_bundle_msg = {'IDA': stuID, 'IDB':stuIDB, 'S': s, 'H': h}
    print("Requesting party B's Key Bundle ...")
    response = requests.get('{}/{}'.format(API_URL, "ReqKeyBundle"), json=key_bundle_msg)
    print(response.json()) 
    if((response.ok) == True):
        print(response.json()) 
        res = response.json()
        return res['KEYID'], res['IK.X'], res['IK.Y'], res['SPK.X'], res['SPK.Y'], res['SPK.H'], res['SPK.s'], res['OTK.X'], res['OTK.Y']
        
    else:
        return -1, 0, 0, 0, 0, 0, 0, 0, 0


#Status control. Returns #of messages and remained OTKs
def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']

def FuncSPK( spkbx, spkby):
    SKey_x = spkbx
    SKey_y = spkby
    #concatenate (SPKA.Pub.x || SPKA.Pub.y)
    x_con_y = SKey_x.to_bytes((math.ceil(SKey_x.bit_length()/8)), byteorder='big') + SKey_y.to_bytes((math.ceil(SKey_y.bit_length()/8)), byteorder='big')
    x_con_y = int.from_bytes(x_con_y, byteorder="big")
    spk_h, spk_s = Sig_Gen(x_con_y, IKey_Pr) #sign the public key part of the signed pre-key, SPKA.Pub using your identity key IKA 
    return Sig_Ver(x_con_y, spk_h, spk_s, IKey_Pub)

def FuncOTK3(SKey_Pr, SKey_Ser):
    HMACKey = HMAC_Gen(SKey_Pr, SKey_Ser) #T = SPK A.Pri · IK S.Pub (Diffie-Hellman with SPK of the client and the IK of the server)
    HMACKeys = []
    OTKeys = []
    for i in range(1,11): #you must generate 10 one-time public and private key pairs     
        OKey_Pr, OKey_Pub = Key_Gen() 
        OKey_Pubx = OKey_Pub.x
        OKey_Puby = OKey_Pub.y
        x_con_y =  OKey_Pubx.to_bytes((math.ceil(OKey_Pubx.bit_length()/8)), byteorder='big') + OKey_Puby.to_bytes((math.ceil(OKey_Puby.bit_length()/8)), byteorder='big')
        Hmac = HMAC.new(key=HMACKey,msg=x_con_y,digestmod=SHA256).hexdigest()
        OTKReg(i,OKey_Pub.x,OKey_Pub.y,Hmac)
        HMACKeys.append(Hmac)
        print()
        OTKeys.append((OKey_Pr))
    return HMACKeys, OTKeys

################################# IMPLEMENTATION OF PHASE 3 ######################################
#Note that the signature (H, s) is generated for the concatenated form of the public signed pre-key (SPKA.Pub.x ∥ SPKA.Pub.y).


'''ResetOTK(h,s)
HMAC_Key = HMAC_Gen(SKey_Pr,IKey_Ser)
OTKeys,HMACKeys = FuncOTK(SKey_Pr,SKey_Ser)'''
PseudoSendMsgPH3(h,s)

unread_mes,otk_left, status = Status(stuID,h,s)


messages = []
for i in range(1,unread_mes+1):
    print()
    print("Message",i)
    m = ReqMsg(h,s)
    IDB = m[0]
    print("OTK ID :", str(m[1]))
 
    print("I got this from client", IDB)
    OTKA_pr = OTKeys[m[1]-1][0]
    mID = m[2]

    print("Converting message to bytes to decrypt it...")
    print("Converted message is:")
    message = m[3].to_bytes((math.ceil(m[3].bit_length()/8)), byteorder='big')  
    print(message)
    print()
    ikbx = m[4]
    ikby = m[5]
    IKB_pub = Point(ikbx, ikby, E)

    ekbx = m[6]
    ekby = m[7]

    EKB_pub = Point(ekbx, ekby,E)
    if i==1:
        ks = Session_Key_Gen(Spka_pr, IKB_pub,EKB_pub,IKA_pr,OTKA_pr)
    else:
        ks = Knext

    print("Generating the key Ks, Kenc, & Khmac and then the HMAC value ..")
    Kenc, Khmac, Knext = Key_Deriv(ks)

    ctext = message[8:-32]

    mac = HMAC.new(key=Khmac.digest(), msg=ctext, digestmod=SHA256).digest()
    print("hmac is:", mac)
    #print(" MAC LENGTH", len(mac))
    mac_m = message[len(message)-32:]
    print("Message mac:" ,mac_m)

    if mac_m == mac:
        print("Hmac value is verified")
        nonce = message[:8]

        cipher = AES.new(Kenc.digest(), AES.MODE_CTR, nonce=nonce)
        ptext = cipher.decrypt(ctext)
        plaintext = ptext.decode('latin1')
        print("The collected plaintext:  ", plaintext)
        messages.append(plaintext)
        Checker(stuID, IDB, mID, plaintext)
    else:
        print("INVALIDHMAC")

    unread_mes,otk_left, status = Status(stuID,h,s)
    if otk_left == 0:
        FuncOTK3(SKey_Pr, SKey_Ser)
        Checker(stuID, IDB, mID, plaintext)


print("Signing The stuIDB of party B with my private IK")

print("Requesting the deleted messages: ")
'''
h,s = Sig_Gen(28201,IKey_Pr)
deleted = ReqDelMsg(h,s)

print("These messages are deleted: ")
if len(deleted) > 1:
    for i in deleted:
        print("Message:", i , messages[i])

print()
print()

for i in messages:
    print("Message:", i , messages[i])

'''
stuIDB = 28201
for mID in range(len(messages)):
    message = messages[mID]
    if message !=  "":
        hA, sA = Sig_Gen(stuIDB, IKey_Pr)
        otk_id , ikx, iky, spkx, spky, spkb_h, spkb_s, otkx, otky = reqKeyBundle(stuID, stuIDB, hA, sA)

        SPK_pub = Point(spkx,spky,E)
        OTK_Pub = Point(otkx,otky,E)
        IK_pub = Point(ikx,iky,E)

        print("Verifying the server's SPK...")
        print( "Is SPK verified? ",FuncSPK( spkx, spky) )

        if(FuncSPK( spkx, spky)):
            print("The other party's OTK public key is acquired from the server ... \nRequesting messages from the pseudo-client...")
            EK_pr, EK_pub = Key_Gen()

            if mID == 0:
                ks = ks = Session_Key_Gen(SPK_pub, IKey_Pr,EK_pr,IK_pub,OTK_Pub)
            else:
                ks = knext
            Kenc , Khmac , knext =  Key_Deriv(ks)
            
            ctext = messages[mID]
            nonce = os.urandom(8)
            ctext = ctext.encode()

            ctext = AES.new(Kenc.digest(), AES.MODE_CTR, nonce = nonce).encrypt(ctext)
            hmac = HMAC.new(key=Khmac.digest(), msg=ctext, digestmod=SHA256).digest()
            encoded = nonce + ctext + hmac
            encoded = int.from_bytes(encoded, byteorder= 'big')
        
            SendMsg(stuID, stuIDB, otk_id, mID, encoded, ikx, iky,EK_pub.x,EK_pub.y)
            h,s = Sig_Gen(stuID,IKey_Pr)



unread_mes,otk_left, status = Status(stuID,h,s)

for m in messages:
    print("Message:", m)

'''
for mID in range(len(messages)):
    message = messages[mID]
    if message !=  "":
        hA, sA = Sig_Gen(stuIDB, IKey_Pr)
        otk_id , ikx, iky, spkx, spky, spkb_h, spkb_s, otkx, otky = reqKeyBundle(stuID, stuIDB, hA, sA)
        SPK_pub = Point(spkx,spky,E)
        OTK_Pub = Point(otkx,otky,E)
        IK_pub = Point(ikx,iky,E)
        print("Verifying the server's SPK...")
        print( "Is SPK verified? ",FuncSPK( spkx, spky) )

        if(FuncSPK( spkx, spky)):
            print("The other party's OTK public key is acquired from the server ... \nRequesting messages from the pseudo-client...")
            EK_pr, EK_pub = Key_Gen()

            if ks == None:
                ks = ks = Session_Key_Gen(SPK_pub, IKey_Pr,EK_pr,IK_pub,OTK_Pub)
            else:
                ks = knext
            Kenc , Khmac , knext =  Key_Deriv(ks)
            aes_key = Kenc.digest()[:16]
            ctext = messages[mID]
            nonce = os.urandom(8)
            ctext = ctext.encode()

            ctext = AES.new(Kenc, AES.MODE_CTR, nonce = nonce).encrypt(ctext)
            hmac = HMAC.new(key=Khmac, msg=ctext, digestmod=SHA256).digest()
            encoded = nonce + ctext + hmac
            encoded = int.from_bytes(encoded, byteorder= 'big')
            SendMsg(stuID,stuIDB,otk_id,mID,encoded,EK_pub.x,EK_pub.y)
            h,s = Sig_Gen(stuID,IKey_Pr)

messages = []
for i in range(1,unread_mes+1):
    print()
    print("Message",i)
    m = ReqMsg(h,s)
    IDB = m[0]

    if IDB == stuID:
        print("I got this from client", IDB)
        OTKA_pr = OTKeys[m[2]-1][0]
        mID = m[3]

        print("Converting message to bytes to decrypt it...")
        print("Converted message is:")
        message = m[4].to_bytes((math.ceil(m[4].bit_length()/8)), byteorder='big')  
        print(message)
        print()
        ikbx = m[5]
        ikby = m[6]
        IKB_pub = Point(ikbx, ikby, E)
    
        ekbx = m[7]
        ekby = m[8]

        EKB_pub = Point(ekbx, ekby,E)
    else:
        print("I got this from client", IDB)
        OTKA_pr = OTKeys[m[1]-1][0]
        mID = m[2]

        print("Converting message to bytes to decrypt it...")
        print("Converted message is:")
        message = m[3].to_bytes((math.ceil(m[3].bit_length()/8)), byteorder='big')  
        print(message)
        print()
        ikbx = m[4]
        ikby = m[5]
        IKB_pub = Point(ikbx, ikby, E)

        ekbx = m[6]
        ekby = m[7]

        EKB_pub = Point(ekbx, ekby,E)
    if i==1:
        ks = Session_Key_Gen(Spka_pr, IKB_pub,EKB_pub,IKA_pr,OTKA_pr)
    else:
        ks = Knext

    print("Generating the key Ks, Kenc, & Khmac and then the HMAC value ..")
    Kenc, Khmac, Knext = Key_Deriv(ks)

    ctext = message[8:-32]

    mac = HMAC.new(key=Khmac.digest(), msg=ctext, digestmod=SHA256).digest()
    print("hmac is:", mac)
    #print(" MAC LENGTH", len(mac))
    mac_m = message[len(message)-32:]
 

    if mac_m == mac:
        print("Hmac value is verified")
        nonce = message[:8]

        cipher = AES.new(Kenc.digest(), AES.MODE_CTR, nonce=nonce)
        ptext = cipher.decrypt(ctext)
        plaintext = ptext.decode('latin1')
        print("The collected plaintext:  ", plaintext)
        messages.append(plaintext)
        Checker(stuID, IDB, mID, plaintext)
    else:
        print("INVALIDHMAC")

    unread_mes,otk_left, status = Status(stuID,h,s)
    if otk_left == 0:
        FuncOTK3(SKey_Pr, SKey_Ser)

'''