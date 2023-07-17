# import hashlib
# from cryptography.hazmat.primitives.asymmetric import rsa,dsa
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
# from cryptography.hazmat.primitives import padding
 
# def generatersa():
 
#     private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
  
# ) 
#     publicKey = private_key
#     return publicKey,private_key

# # print("private key",generatersa)

# def RSAEncrypt(publicKey,private_key):
# from cryptography.hazmat.primitives.asymmetric import rsa, dsa
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
# from cryptography.hazmat.primitives import padding

# text = "blockchain"

# def generateRSAKeyPair():
#     privateKey = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
#     )
#     publicKey = privateKey.public_key()
#     return privateKey, publicKey


# def RSAEncrypt(publicKey, text):
#     cipherText = publicKey.encrypt(text, padding=PKCS1v15())
#     return cipherText


# def RSADecrypt(privateKey, cipherText):
#     plainText = privateKey.decrypt(cipherText, padding=PKCS1v15())
#     return plainText


# def generateDSAKeyPair():
#     privateKey = dsa.generate_private_key(key_size=1024)
#     publicKey = privateKey.public_key()
#     return privateKey, publicKey


# def DSASign(privateKey, message):
#     signature = privateKey.sign(
#         message,
#         algorithm=hashes.SHA256()
#     )
#     return signature

# def DSAVerify(publicKey, message, signature):
#     try:
#         publicKey.verify(
#             signature,
#             message,
#             hashes.SHA256()
#         )
#         return True
#     except :
#         return False

# def main():
#     RSAprivateKey, RSApublicKey = generateRSAKeyPair()
#     message = "Message for RSA algorithm"
#     plainText = message.encode()
#     cipherText = RSAEncrypt(RSApublicKey, plainText)
#     decryptedText = RSADecrypt(RSAprivateKey, cipherText)

#     print("RSA Public Key:", RSApublicKey)
#     print("RSA Private Key:", RSAprivateKey)
#     print("Plain Text:", plainText.decode())
#     print("Cipher Text:", cipherText)
#     print("Decrypted Text:", decryptedText)


# DSAPrivateKey, DSAPublicKey = generateDSAKeyPair()
# message = b"Message for DSA algorithm"
# signature = DSASign(DSAPrivateKey, message)
# verified = DSAVerify(DSAPublicKey, message, signature)

# print("DSA Public Key:", DSAPublicKey)
# print("DSA Private Key:", DSAPrivateKey)
# print("Message:", message)
# print("Signature:", signature)
# print("Verified:", verified)

# # Calling the main function
# main()
    

    # fifth task
# from cryptography.hazmat.primitives.asymmetric import rsa, dsa
# from cryptography.hazmat.primitives import serialization, hashes
# from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
# from cryptography.hazmat.primitives import padding
# from cryptography.hazmat.primitives.asymmetric import ec

# from cryptography.hazmat.primitives import hashes
# text = "blockchain"
# def generateECDSAKeyPair():
#     privateKey = ec.generate_private_key(ec.SECP256K1())
#     publicKey = privateKey.public_key()
#     return privateKey, publicKey

# def ECDSASign(privateKey, message):
#     signature = privateKey.sign(
#         message,
#         ec.ECDSA(hashes.SHA256())
#     )
#     return signature

# def ECDSAVerify(publicKey, message, signature):
#     try:
#         publicKey.verify(
#             signature,
#             message,
#             ec.ECDSA(hashes.SHA256())
#         )
#         return True
#     except:
#         return False

# def main():
#     ECDSAPrivateKey, ECDSAPublicKey = generateECDSAKeyPair()
#     message = "Message for ECDSA algorithm"
#     signature = ECDSASign(ECDSAPrivateKey, message)
#     verified = ECDSAVerify(ECDSAPublicKey, message, signature)

#     print("ECDSA:")
#     print("ECDSA Public Key:", ECDSAPublicKey)
#     print("ECDSA Private Key:", ECDSAPrivateKey)
#     print("Message:", message.decode())
#     print("Signature:", signature)
#     print("Verification:", verified)

# # Calling the main function
# main()

    
    # test 6
# from cryptography.hazmat.primitives.asymmetric import ec
# from cryptography.hazmat.primitives import  hashes
# import hashlib
# import random

# randomNumbers = random.randint(1, 1000000)

# def generateTxid():
#  str(randomNumbers)
#  stringToHash = hashlib.sha256(randomNumbers.encode()).hexdigest()
#  print(stringToHash)

# def generateInput():
#   prevTxid = generateTxid()
#   prevOutputIndex = random.randint(0, 5)
#   return prevTxid,prevOutputIndex

# def generateOutput():
#   randomNumbers2 = random.randint(1, 100)
#   str(randomNumbers2)
#   recipientAddress=  'recipient_address_' + randomNumbers2
#   random_number = random.uniform(0.001, 1.0)
#   rounded_number = round(random_number, 8)
#   amount = rounded_number
#   return recipientAddress, amount

# def generateTransactionFee():
#  random_number = random.uniform(0.0001,  0.001)
#  rounded_number = round(random_number, 8)
#  print(rounded_number)

  
# def generateRandomTransaction():
#   txid = generateTxid()
#   inputPrevTxid, inputPrevOutputIndex = generateInput()
#   outputRecipientAddress, outputAmount = generateOutput()
#   transactionFee = generateTransactionFee()

#   return txid, inputPrevTxid, inputPrevOutputIndex,outputRecipientAddress, outputAmount,transactionFee
# def concatenateString(txid, inputPrevTxid,
# inputPrevOutputIndex, outputRecipientAddress,
# outputAmount, transactionFee):
#  transactionData =  str(txid + inputPrevTxid + inputPrevOutputIndex + outputRecipientAddress + outputAmount + transactionFee)
#  return transactionData

# def generateECDSAKeyPair():
  
#   ECDSAPrivateKey = ec.generate_private_key(ec.SECP256K1())
#   ECDSAPublicKey = ECDSAPrivateKey
#   return ECDSAPublicKey

# def ECDSASign(privateKey, message):
#   message = "the message is for signature"
#   signature = privateKey.sign(message,ec.ECDSA(hashes.SHA256()))
#   return signature

# def ECDSAVerify(publicKey, message,signature):
#       try:
#         publicKey.verify(
#             signature,
#             message,
#             ec.ECDSA(hashes.SHA256())
#         )
#         return True
#       except:
#         return False
# def  main():
#  txid, inputPrevTxid, inputPrevOutputIndex,outputRecipientAddress, outputAmount,transactionFee = generateRandomTransaction()
#  transactionDataAsMessage =concatenateString(txid, inputPrevTxid,inputPrevOutputIndex, outputRecipientAddress,outputAmount, transactionFee).encode()
#  transactionDataAsMessageSHA256Hashed = hashlib.sha256(transactionDataAsMessage).hexdigest()
#  ECDSAPrivateKey, ECDSAPublicKey = generateECDSAKeyPair()
#  signature = ECDSASign(ECDSAPrivateKey,transactionDataAsMessageSHA256Hashed)
#  verified = ECDSAVerify(ECDSAPublicKey,transactionDataAsMessageSHA256Hashed,signature)

#  print(ECDSAPublicKey)
#  print(ECDSAPrivateKey)
#  print(transactionDataAsMessageSHA256Hashed,transactionDataAsMessageSHA256Hashed)
#  print(signature)
#  print(verified)
# # call main function 
# main()

import random
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes

def generateTxid():
    random_integer = random.randint(1, 1000000)
    hash_object = hashlib.sha256(str(random_integer).encode())
    return hash_object.hexdigest()


def generateInput():
    prevTxid = generateTxid()
    prevOutputIndex = random.randint(0, 5)
    return prevTxid, prevOutputIndex


def generateOutput():
    recipientAddress = 'recipient_address_' + str(random.randint(1, 100))
    amount = round(random.uniform(0.001, 1.0), 8)
    return recipientAddress, amount


def generateTransactionFee():
    return round(random.uniform(0.0001, 0.001), 8)


def generateRandomTransaction():
    txid = generateTxid()
    inputPrevTxid, inputPrevOutputIndex = generateInput()
    outputRecipientAddress, outputAmount = generateOutput()
    transactionFee = generateTransactionFee()
    return txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee


def concatenateString(txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee):
    transactionData = str(txid) + str(inputPrevTxid) + str(inputPrevOutputIndex) + str(outputRecipientAddress) + str(outputAmount) + str(transactionFee)
    return transactionData.encode()


def generateECDSAKeyPair():
    private_key = ec.generate_private_key(ec.SECP256K1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key


def ECDSASign(privateKey, message):
    signature = privateKey.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def ECDSAVerify(publicKey, message, signature):
    try:
        publicKey.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except:
        return False


def main():
    txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee = generateRandomTransaction()
    transactionData = concatenateString(txid, inputPrevTxid, inputPrevOutputIndex, outputRecipientAddress, outputAmount, transactionFee)
    transactionDataSHA256Hashed = hashlib.sha256(transactionData).digest()
    ECDSAPrivateKey, ECDSAPublicKey = generateECDSAKeyPair()
    signature = ECDSASign(ECDSAPrivateKey, transactionDataSHA256Hashed)
    verified = ECDSAVerify(ECDSAPublicKey, transactionDataSHA256Hashed, signature)

    print("ECDSA:")
    print("ECDSA Public Key:", ECDSAPublicKey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    print("ECDSA Private Key:", ECDSAPrivateKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()).decode())
    print("transactionDataSHA256Hashed:", transactionDataSHA256Hashed.hex())
    print("Signature:", signature.hex())
    print("Verification:", verified)

main()

