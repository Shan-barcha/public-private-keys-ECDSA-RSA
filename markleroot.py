# firstHash= "1d0ada7a906e529d19fb2aca66911eaaee84ff4c7c6b685f019cd79c2deec5ff"
# secondHash =" 40791afdc85ba029dc28348174e5bd5070dd664a421234f7a935a62d43f7852f"
# thirdHash ="c43194ab05fca649152ea3b92c49eacee99902badd7ea503e3315d49a83781ba"
# forthHas ="b349939cb094a89e4cf720b895df300c0d5c7b3f0f3a237bc026cad42637fb61"

# concateA ="1d0ada7a906e529d19fb2aca66911eaaee84ff4c7c6b685f019cd79c2deec5ff40791afdc85ba029dc28348174e5bd5070dd664a421234f7a935a62d43f7852f"
# concateB ="c43194ab05fca649152ea3b92c49eacee99902badd7ea503e3315d49a83781bab349939cb094a89e4cf720b895df300c0d5c7b3f0f3a237bc026cad42637fb61"

# import hashlib

# def calculate_block_hash(data):
#     # """Calculates the hash of a data block."""
#     return hashlib.sha256(data.encode()).hexdigest()

# def calculate_nodal_hash(left_hash, right_hash):
#     # """Calculates the hash of a nodal (parent) node."""
#     combined = left_hash + right_hash
#     return hashlib.sha256(combined.encode()).hexdigest()

# def construct_merkle_tree(data):
#     # """Constructs a Merkle tree given a list of data."""
#     if len(data) == 1:
#         return {
#             'data': data[0],
#             'hash': calculate_block_hash(data[0]),
#             'left_child': None,
#             'right_child': None
#         }
    
#     nodes = []
#     for i in range(0, len(data), 2):
#         left_child = construct_merkle_tree(data[i])
#         if i+1 < len(data):
#             right_child = construct_merkle_tree(data[i+1])
#         else:
#             right_child = left_child
        
#         nodal_hash = calculate_nodal_hash(left_child['hash'], right_child['hash'])
#         node = {
#             'hash': nodal_hash,
#             'left_child': left_child,
#             'right_child': right_child
#         }
#         nodes.append(node)
    
#     return nodes[0]

# def calculate_merkle_root(merkle_tree):
#     # """Calculates the Merkle root given a Merkle tree."""
#     if isinstance(merkle_tree, dict):
#         return merkle_tree['hash']
    
#     left_hash = calculate_merkle_root(merkle_tree[0])
#     right_hash = calculate_merkle_root(merkle_tree[-1])
#     return calculate_nodal_hash(left_hash, right_hash)

# # Step a: Random strings
# random_strings = [
#     "abc",
#     "def",
#     "123",
#     "xyz",
#     "hello",
#     "world",
#     "open",
#     "ai"
# ]

# # Step b: Construct Merkle tree
# merkle_tree = construct_merkle_tree(random_strings)

# # Step c: Calculate Merkle root
# merkle_root = calculate_merkle_root(merkle_tree)

# # Print Merkle root
# print("Merkle Root:", merkle_root)


# import hashlib

# str1 = "abc"
# hash1 = hashlib.sha256(str1.encode()).hexdigest()
# # print(hash1)

# str2 = "def"
# hash2 = hashlib.sha256(str2.encode()).hexdigest()
# # print(hash2)

# str3 = "ghi"
# hash3 = hashlib.sha256(str3.encode()).hexdigest()
# # print(hash3)

# str4 = "jkl"
# hash4 = hashlib.sha256(str4.encode()).hexdigest()
# # print(hash4)

# str5 = "mno"
# hash5 = hashlib.sha256(str5.encode()).hexdigest()
# # print(hash5)

# str6 = "pqr"
# hash6 = hashlib.sha256(str6.encode()).hexdigest()
# # print(hash6)

# str7 = "stu"
# hash7 = hashlib.sha256(str7.encode()).hexdigest()
# # print(hash7)


# str8 = "xyz"
# hash8 = hashlib.sha256(str8.encode()).hexdigest()
# # print(hash8)


# childnode1 = hash1 + hash2
# childHash = hashlib.sha256(childnode1.encode()).hexdigest()
# print(childHash)

# childnode2 = hash3 + hash4
# childHash2 = hashlib.sha256(childnode2.encode()).hexdigest()
# print(childHash2)


# childnode3 = hash5 + hash6
# childHash3 = hashlib.sha256(childnode3.encode()).hexdigest()
# print(childHash3)

# childnode4 = hash7 + hash8
# childHash4 = hashlib.sha256(childnode4.encode()).hexdigest()
# print(childHash4)

# # combination of child nodes

# firstChild = childHash + childHash2
# childHash5 = hashlib.sha256(firstChild.encode()).hexdigest()
# print("childHash5:",childHash5)

# secondChild = childHash3 + childHash4
# childHash6 = hashlib.sha256(secondChild.encode()).hexdigest()
# print("childHash6:",childHash6)
# # # finding root 
# root = firstChild + secondChild
# rootTree = hashlib.sha256(root.encode()).hexdigest()
# print("root hash :", rootTree)

# 3rd question dfghjkllkjhgffghjk
import hashlib
file = open('Lab5-6-2023.pdf', 'rb')
fileOneBinary = file.read()
blocksize = len(fileOneBinary)//8
datablocks = [fileOneBinary[i:i+blocksize]for i in range(0,len(fileOneBinary),blocksize)]

hashGenerator = hashlib.sha256(datablocks.encode()).hexdigest()
print("jhgdjsdgjsdcsdh:",hashGenerator)
import hashlib

file = open('lacture_file.pptx', "rb")
content = file.read()

listOfHashes = []
listOfTwoShes = []
listOfFourShes = []
rootHash = ""


blockSize = len(content) // 8
dataBlocks = [content[i:i + blockSize] for i in range(0, len(content), blockSize)]
# print("hello there ugsdglsdgclsda",dataBlocks)


for x in range(len(dataBlocks)):
    stringToHash = hashlib.sha256(dataBlocks[x]).hexdigest()
    listOfHashes.append(stringToHash)

# Concatenating two hashes and finding the heash of the concatenated string and storing into array
for x in range(0, 8, 2):
    stringToHash = listOfHashes[x] + listOfHashes[x + 1]
    stringToHash = hashlib.sha256(stringToHash.encode()).hexdigest()
    listOfTwoShes.append(stringToHash)
blockSize
for x in range(0, 4, 2):
    stringToHash = listOfTwoShes[x] + listOfTwoShes[x + 1]
    stringToHash = hashlib.sha256(stringToHash.encode()).hexdigest()
    listOfFourShes.append(stringToHash)

for x in range(0, 2, 2):
    rootHash = listOfFourShes[x] + listOfFourShes[x + 1]
    stringToHash = hashlib.sha256(stringToHash.encode()).hexdigest()
    rootHash = stringToHash

print(f"List of Hashes: {listOfHashes}")
print(f"List of Two Shes: {listOfTwoShes}")
print(f"List of Four Shes: {listOfFourShes}")
print("\n")
print(f"Root Hash: {rootHash}")

# task four
import hashlib

def markleRoot(file_path):
    file = open("lacture_file.pptx", "rb")
    content = file.read()

    listOfHashes = []
    # listOfTwoShes = []
    # listOfFourShes = []
    rootHash = ""

    blockSize = len(content) // 512
    dataBlocks = [content[i:i + blockSize] for i in range(0, len(content), blockSize)]
    print("blocksixe",len(dataBlocks))
    for x in range(len(dataBlocks)):
        stringToHash = hashlib.sha256(dataBlocks[x]).hexdigest()
        listOfHashes.append(stringToHash)

    while len(listOfHashes) > 1:
        storedHashes = []
        for x in range(0, len(listOfHashes), 2):
            if x + 1 < len(listOfHashes):
                stringToHash = listOfHashes[x] + listOfHashes[x + 1]
            else:
                stringToHash = listOfHashes[x] + listOfHashes[x]
            stringToHash = hashlib.sha256(stringToHash.encode()).hexdigest()
            storedHashes.append(stringToHash)
        listOfHashes = storedHashes

    rootHash = listOfHashes[0]

    return rootHash

file_path = 'lecture_file.pptx'
root_hash = markleRoot(file_path)
print(f"Root Hash: {root_hash}")