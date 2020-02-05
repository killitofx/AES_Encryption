import sys
#AES CFB
import hashlib
import base64
from Crypto.Cipher import AES

key = 'hellocmd'

def pkcs7padding(text):
    bs = AES.block_size
    ####tips：utf-8编码时，英文占1个byte，而中文占3个byte####
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    padding_size = length if (bytes_length == length) else bytes_length
    ####################################################
    padding = bs - padding_size % bs
    padding_text = chr(padding) * padding    # tips：chr(padding)看与其它语言的约定，有的会使用'\0'
    return text + padding_text

def pkcs7padding_tobytes(text):
    return bytes(pkcs7padding(text), encoding='utf-8')

def get_aes_cfb(the_string):
    key_bytes = pkcs7padding_tobytes(key)
    iv = key_bytes
    aes = AES.new(key_bytes, AES.MODE_CFB, iv)                              # 初始化加密器，key,iv使用同一个
    encrypt_aes = iv + aes.encrypt(the_string.encode())                     # 进行aes加密
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8') # 用base64转成字符串形式
    return encrypted_text


def back_aes_cfb(the_string):
    key_bytes = pkcs7padding_tobytes(key)
    iv = key_bytes
    aes = AES.new(key_bytes, AES.MODE_CFB, iv)                                 # 初始化加密器，key,iv使用同一个
    decrypted_base64 = base64.decodebytes(the_string.encode(encoding='utf-8')) # 逆向解密base64成bytes
    decrypted_text = str(aes.decrypt(decrypted_base64[16:]), encoding='utf-8') # 执行解密密并转码返回str
    return decrypted_text


flag = 0

if '-k' in sys.argv:
    key_index = sys.argv.index('-k') + 1
    key = (sys.argv[key_index])


if '-o' in sys.argv:
    key_index = sys.argv.index('-o') + 1
    out_data = (sys.argv[key_index])
    flag = 1
    try:
        print(back_aes_cfb(str(out_data)))
    except:
        print("无法解密")


if '-i' in sys.argv:
    key_index = sys.argv.index('-i') + 1
    out_data = (sys.argv[key_index])
    flag = 1
    try:
        print(get_aes_cfb(str(out_data)).replace('\n',''))
    except:
        print("无法加密")

if flag == 0:
    m = """ 
    使用方法：
    加密： xx.exe -o 需要加密的内容
    解密： xx.exe -i 加密字符串

    使用特定密钥加密：
    加密： xx.exe -o 需要加密的内容 -k 密钥
    解密： xx.exe -i 加密字符串 -k 密钥
    """
    print(m)
    input()