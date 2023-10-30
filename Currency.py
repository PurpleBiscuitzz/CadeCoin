import hashlib
import time

import rsa
import binascii
import sys
import os.path


# gets the hash of a file; from https://stackoverflow.com/a/44873382
def hashFile(filename):
    h = hashlib.sha256()
    with open(filename, 'rb', buffering=0) as f:
        for b in iter(lambda : f.read(128*1024), b''):
            h.update(b)
    return h.hexdigest()


# given an array of bytes, return a hex reprenstation of it
def bytesToString(data):
    return binascii.hexlify(data)


# given a hex reprensetation, convert it to an array of bytes
def stringToBytes(hexstr):
    return binascii.a2b_hex(hexstr)


# Load the wallet keys from a filename
def loadWallet(filename):
    with open(filename, mode='rb') as file:
        keydata = file.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata)
    pubkey = rsa.PublicKey.load_pkcs1(keydata)
    return pubkey, privkey


# save the wallet to a file
def saveWallet(pubkey, privkey, filename):
    # Save the keys to a key format (outputs bytes)
    pubkeyBytes = pubkey.save_pkcs1(format='PEM')
    privkeyBytes = privkey.save_pkcs1(format='PEM')
    # Convert those bytes to strings to write to a file (gibberish, but a string...)
    pubkeyString = pubkeyBytes.decode('ascii')
    privkeyString = privkeyBytes.decode('ascii')
    # Write both keys to the wallet file
    with open(filename, 'w') as file:
        file.write(pubkeyString)
        file.write(privkeyString)
    return


def getGenesis():
    f = open("block_0.txt", "w")
    f.truncate(0)
    f.write("The Gods envy us. They envy us because we're mortal, because any moment might be our last."
            " Everything is more beautiful because we're doomed. You will never be lovelier than you are now.")
    f.close()
    print("genesis block has been created in block_0.txt")
    return


def computeTag(filename):
    (pubkey, privkey) = loadWallet(filename)
    pubkeyBytes = pubkey.save_pkcs1(format='PEM')
    pubkeyString = pubkeyBytes.decode('ascii')
    hash = hashlib.sha256(pubkeyString.encode())
    return hash.hexdigest()[0:16]


def generateWallet(file):
    (pubkey, privkey) = rsa.newkeys(1024)
    saveWallet(pubkey, privkey, file)
    print("Wallet created in " + file + " with tag " + str(computeTag(file)))
    return


def transferFunds(Stag, Dtag, amount, filename):
    if Stag != "Caden":
        myf = Stag
        Stag = computeTag(Stag)

    f = open(filename, "w")
    f.write(Stag + '\n')
    f.write(Dtag + '\n')
    f.write(amount + '\n')

    time.ctime()
    curtime = time.strftime('%c')
    f.write(curtime + '\n')
    if Stag == "Caden":
        f.write('Caden')
    else:
        f.close()
        filehash = hashFile(filename).encode()

        (pubkey, privkey) = loadWallet(myf)
        signature = rsa.sign(filehash, privkey, 'SHA-256')
        f = open(filename, 'a')
        f.write(signature.hex())
    if Stag == 'Caden':
        print("Funded wallet " + Dtag + " with " + str(amount) + " CadeCoins on " + curtime)
    f.close()
    return curtime


def checkBalance(tag):
    filename = 'block_1.txt'
    balance = 0
    filenum = 2

    while os.path.isfile(filename):
        with open(filename, 'r') as file:
            for line in file:
                if line != "" and "hash: " not in line and "nonce: " not in line:
                    parts = line.split(" ")
                    if parts[0] == tag:
                        balance -= int(parts[2])
                    if parts[4] == tag:
                        balance += int(parts[2])
        filename = filename[:6] + str(filenum) + filename[6+len(str(filenum)):]
        filenum += 1

    if os.path.isfile('mempool.txt'):
        with open('mempool.txt', 'r') as file:
            for line in file:
                if line != "":
                    parts = line.split(" ")
                    if parts[0] == tag:
                        balance -= int(parts[2])
                    if parts[4] == tag:
                        balance += int(parts[2])

    return balance
arguments = len(sys.argv)-1

def verify(wallet, trans):
    f = open(trans, "r")
    Stag = f.readline()
    Dtag = f.readline()
    amount = f.readline()
    time = f.readline()
    key = f.readline()
    f.close()
    if (Stag.strip() == "Caden"):
        f = open("mempool.txt", "a")
        f.write(Stag.strip() + " transferred " + amount.strip() + " to " + Dtag.strip() + " on " + time.strip() + "\n")
        print(Stag.strip() + " transferred " + amount.strip() + " to " + Dtag.strip() + " on " + time.strip())
        f.close()
        return True
    if checkBalance(Stag.strip()) <= 0:
        print("Transaction Invalid in file " + trans + " because of a balance issue")
        return False
    newf = open("verify.txt", "w")
    newf.write(Stag)
    newf.write(Dtag)
    newf.write(amount)
    newf.write(time)
    newf.close()
    (pubkey, privkey) = loadWallet(wallet)
    signature = rsa.sign(hashFile("verify.txt").encode(), privkey, 'SHA-256')
    if signature.hex() != key:
        print("Transaction Invalid in file " + trans + " because of a signature issue")
        return False

    f = open("mempool.txt", "a")
    f.write(Stag.strip() + " transferred " + amount.strip() + " to " + Dtag.strip() + " on " + time.strip() + "\n")
    print(Stag.strip() + " transferred " + amount.strip() + " to " + Dtag.strip() + " on " + time.strip())
    f.close()
    return True

def mine(level):
    filename = "block_1.txt"
    oldblock = "block_0.txt"
    filenum = 2

    while os.path.isfile(filename):
        oldblock = filename
        filename = filename[:6] + str(filenum) + filename[6 + len(str(filenum)):]
        filenum += 1

    hash = hashFile(oldblock)
    f = open(filename, "w")
    mem = open("mempool.txt", "r")
    f.write("hash: " + hash + "\n")
    for line in mem:
        f.write(line)
    mem.close()
    open("mempool.txt", "w").close()
    f.close()

    case = False
    counter = 0
    target = ""
    for i in range(0, int(level)):
        target = target + "0"
    f = open(filename, "r")
    insides = f.read()
    f.close()
    while not case:
        t = open("test.txt", "w")
        t.write(insides)
        t.write("nonce: " + str(counter))
        t.close()
        if hashFile("test.txt")[0:int(level)] == target:
            case = True
            f = open(filename, "a")
            f.write("nonce: " + str(counter))
        counter += 1

def validate():
    filename = "block_1.txt"
    oldblock = "block_0.txt"
    filenum = 2

    while os.path.isfile(filename):
        f = open(filename, "r")
        myhash = f.readline().strip()
        myhash = myhash[6:]
        if hashFile(oldblock) != myhash:
            return False
        oldblock = filename
        filename = filename[:6] + str(filenum) + filename[6 + len(str(filenum)):]
        filenum += 1

    return True
if arguments > 0:
    if sys.argv[1] == "name":
        print("CadeCoin")
    if sys.argv[1] == "genesis":
        getGenesis()
    if sys.argv[1] == 'generate':
        generateWallet(sys.argv[2])
    if sys.argv[1] == 'address':
        print(computeTag(sys.argv[2]))
    if sys.argv[1] == 'fund':
        transferFunds('Caden', sys.argv[2], sys.argv[3], sys.argv[4])
    if sys.argv[1] == 'transfer':
        time = transferFunds(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        print("Transferred " + str(sys.argv[4]) + " from " + sys.argv[2] + " to " + sys.argv[3] + " and the statement to "
              + sys.argv[5] + " on " + time)
    if sys.argv[1] == 'balance':
        print(checkBalance(sys.argv[2]))
    if sys.argv[1] == "verify":
        verify(sys.argv[2], sys.argv[3])
    if sys.argv[1] == 'mine':
        mine(sys.argv[2])
    if sys.argv[1] == 'validate':
        print(validate())
