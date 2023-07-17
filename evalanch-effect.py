import hashlib
fileHashString = 'c27783392976304d9ec296c6cf318f4145e780d02b78c679347e93408553a59c'
file = open('Lab5-6-2023.pdf', 'rb')
binaryData = file.read()

sha__256 = hashlib.sha256(binaryData).hexdigest()

if fileHashString == sha__256:
    print('hash matches')
else:
    print('hash not matches')

#  Effect avalanche

textFile = open('text.txt', 'rb')
fileOneBinary = file.read()
fileOneHash = hashlib.sha256(fileOneBinary).hexdigest()

print('hash before changing', fileOneHash)

textfileChange = open('textcopy.txt', 'rb')
fileTwoBinary = textfileChange.read()
fileTwoHash = hashlib.sha256(fileTwoBinary).hexdigest()
print('hash after changing', fileTwoHash)

if fileTwoHash == fileOneHash:
    print('hash of both files match')
else:
    print('hash of both files donot match')

# last task 

messageOne = open('message1.bin', 'rb')
messageOneBinary = messageOne.read()
messageTwo = open('message2.bin', 'rb')
messageTwoBinary = messageTwo.read()
print('')
print('hashing message with md5')
print(hashlib.md5(messageOneBinary).hexdigest())
print(hashlib.md5(messageTwoBinary).hexdigest())
print('')
print('hashing message with sha1')
print(hashlib.sha1(messageOneBinary).hexdigest())
print(hashlib.sha1(messageTwoBinary).hexdigest())
