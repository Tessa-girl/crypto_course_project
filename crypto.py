import sys
import os

# ==================== 工具函数 ====================

def read_file(path):
    """读取文件内容"""
    try:
        with open(path, 'rb') as f:
            return f.read()
    except Exception as e:
        print(f"错误: 读取文件失败! {e}")
        return None


def write_file(path, data):
    """写入文件内容"""
    try:
        with open(path, 'wb') as f:
            f.write(data)
        print(f"[工具] 写入文件 '{path}', 大小: {len(data)} 字节")
    except Exception as e:
        print(f"错误: 写入文件失败! {e}")


def to_hex(data):
    """字节转十六进制字符串"""
    result = ""
    for byte in data:
        hex_str = hex(byte)[2:]
        if len(hex_str) == 1:
            hex_str = "0" + hex_str
        result += hex_str
    return result


def from_hex(hex_str):
    """十六进制字符串转字节"""
    if len(hex_str) % 2 != 0:
        raise ValueError("十六进制字符串长度必须是偶数")
    
    result = []
    for i in range(0, len(hex_str), 2):
        hex_byte = hex_str[i:i+2]
        byte_val = int(hex_byte, 16)
        result.append(byte_val)
    
    return bytes(result)


def pkcs7_pad(data, block_size):
    """PKCS#7填充"""
    pad_len = block_size - (len(data) % block_size)
    padded = bytearray(data)
    for i in range(pad_len):
        padded.append(pad_len)
    return bytes(padded)


def pkcs7_unpad(data):
    """去除PKCS#7填充"""
    if len(data) == 0:
        raise ValueError("数据为空!")
    
    pad_len = data[-1]
    if pad_len < 1 or pad_len > len(data):
        raise ValueError("填充格式不正确!")
    
    return data[:-pad_len]


# ==================== DES算法实现 ====================

IP_TABLE = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7]
IP_INV_TABLE = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25]
E_TABLE = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1]
P_TABLE = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25]
PC1_TABLE = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4]
PC2_TABLE = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32]
SHIFT_SCHEDULE = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

S_BOXES = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]]
]


def bytes_to_bits(data):
    """字节转二进制字符串"""
    bits = ""
    for byte in data:
        for i in range(7, -1, -1):
            if (byte >> i) & 1:
                bits += "1"
            else:
                bits += "0"
    return bits


def bits_to_bytes(bit_str):
    """二进制字符串转字节"""
    result = []
    for i in range(0, len(bit_str), 8):
        eight_bits = bit_str[i:i+8]
        byte_val = 0
        for j in range(8):
            if eight_bits[j] == '1':
                byte_val += (1 << (7 - j))
        result.append(byte_val)
    return bytes(result)


def rearrange_bits(bits, table):
    """按表格重排位"""
    result = ""
    for pos in table:
        result += bits[pos - 1]
    return result


def left_rotate(bits, n):
    """循环左移"""
    return bits[n:] + bits[:n]


def xor_bits(bits1, bits2):
    """异或操作"""
    result = ""
    for i in range(len(bits1)):
        if bits1[i] != bits2[i]:
            result += "1"
        else:
            result += "0"
    return result


def generate_des_subkeys(key):
    """生成DES子密钥"""
    key_bits = bytes_to_bits(key)
    key_56 = rearrange_bits(key_bits, PC1_TABLE)
    C = key_56[:28]
    D = key_56[28:]
    
    subkeys = []
    for i in range(16):
        shift = SHIFT_SCHEDULE[i]
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        combined = C + D
        subkey = rearrange_bits(combined, PC2_TABLE)
        subkeys.append(subkey)
    
    return subkeys


def des_feistel(right, subkey):
    """DES的F函数"""
    expanded = rearrange_bits(right, E_TABLE)
    xored = xor_bits(expanded, subkey)
    
    sbox_out = ""
    for i in range(8):
        six_bits = xored[i*6:(i+1)*6]
        row = int(six_bits[0] + six_bits[5], 2)
        col = int(six_bits[1:5], 2)
        val = S_BOXES[i][row][col]
        
        val_bits = ""
        for p in [8, 4, 2, 1]:
            if val >= p:
                val_bits += "1"
                val -= p
            else:
                val_bits += "0"
        sbox_out += val_bits
    
    return rearrange_bits(sbox_out, P_TABLE)


def des_process_block(block, subkeys, encrypt=True):
    """DES单块加解密"""
    bits = bytes_to_bits(block)
    bits = rearrange_bits(bits, IP_TABLE)
    
    L = bits[:32]
    R = bits[32:]
    
    keys = subkeys if encrypt else subkeys[::-1]
    
    for i in range(16):
        old_R = R
        f_result = des_feistel(R, keys[i])
        R = xor_bits(L, f_result)
        L = old_R
    
    combined = R + L
    final_bits = rearrange_bits(combined, IP_INV_TABLE)
    return bits_to_bytes(final_bits)


class SimpleDES:
    """DES算法类"""
    def __init__(self, key):
        if len(key) != 8:
            raise ValueError("DES密钥必须是8字节!")
        self.subkeys = generate_des_subkeys(key)
    
    def encrypt_block(self, plaintext):
        return des_process_block(plaintext, self.subkeys, True)
    
    def decrypt_block(self, ciphertext):
        return des_process_block(ciphertext, self.subkeys, False)


# ==================== AES算法实现 ====================

S_BOX = [0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16]

INV_S_BOX = [0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d]

RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def gf_multiply(a, b):
    """GF(2^8)乘法"""
    result = 0
    for i in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xFF
        if high_bit:
            a ^= 0x1B
        b >>= 1
    return result


def bytes_to_matrix(data):
    """字节转4x4矩阵"""
    state = [[0]*4 for _ in range(4)]
    for c in range(4):
        for r in range(4):
            state[r][c] = data[r + c*4]
    return state


def matrix_to_bytes(state):
    """矩阵转字节"""
    result = []
    for c in range(4):
        for r in range(4):
            result.append(state[r][c])
    return bytes(result)


def aes_sub_bytes(state, inverse=False):
    """字节代换"""
    box = INV_S_BOX if inverse else S_BOX
    for r in range(4):
        for c in range(4):
            state[r][c] = box[state[r][c]]
    return state


def aes_shift_rows(state, inverse=False):
    """行移位"""
    for r in range(4):
        if r == 0:
            continue
        
        row = state[r][:]
        if inverse:
            # 右移
            shift = r
            for c in range(4):
                state[r][c] = row[(c - shift) % 4]
        else:
            # 左移
            shift = r
            for c in range(4):
                state[r][c] = row[(c + shift) % 4]
    return state


def aes_mix_columns(state, inverse=False):
    """列混合"""
    for c in range(4):
        col = [state[r][c] for r in range(4)]
        
        if inverse:
            new_col = [
                gf_multiply(0x0E,col[0]) ^ gf_multiply(0x0B,col[1]) ^ gf_multiply(0x0D,col[2]) ^ gf_multiply(0x09,col[3]),
                gf_multiply(0x09,col[0]) ^ gf_multiply(0x0E,col[1]) ^ gf_multiply(0x0B,col[2]) ^ gf_multiply(0x0D,col[3]),
                gf_multiply(0x0D,col[0]) ^ gf_multiply(0x09,col[1]) ^ gf_multiply(0x0E,col[2]) ^ gf_multiply(0x0B,col[3]),
                gf_multiply(0x0B,col[0]) ^ gf_multiply(0x0D,col[1]) ^ gf_multiply(0x09,col[2]) ^ gf_multiply(0x0E,col[3])
            ]
        else:
            new_col = [
                gf_multiply(0x02,col[0]) ^ gf_multiply(0x03,col[1]) ^ col[2] ^ col[3],
                col[0] ^ gf_multiply(0x02,col[1]) ^ gf_multiply(0x03,col[2]) ^ col[3],
                col[0] ^ col[1] ^ gf_multiply(0x02,col[2]) ^ gf_multiply(0x03,col[3]),
                gf_multiply(0x03,col[0]) ^ col[1] ^ col[2] ^ gf_multiply(0x02,col[3])
            ]
        
        for r in range(4):
            state[r][c] = new_col[r]
    return state


def aes_add_round_key(state, round_key):
    """轮密钥加"""
    for r in range(4):
        for c in range(4):
            state[r][c] ^= round_key[r][c]
    return state


def aes_expand_key(key):
    """AES密钥扩展"""
    round_keys = [bytes_to_matrix(key)]
    
    for rnd in range(1, 11):
        prev = round_keys[-1]
        new_key = [[0]*4 for _ in range(4)]
        
        temp = [prev[r][3] for r in range(4)]
        
        # RotWord
        first = temp[0]
        for i in range(3):
            temp[i] = temp[i+1]
        temp[3] = first
        
        # SubWord
        for i in range(4):
            temp[i] = S_BOX[temp[i]]
        
        # XOR with RCON
        temp[0] ^= RCON[rnd-1]
        
        # First column
        for r in range(4):
            new_key[r][0] = prev[r][0] ^ temp[r]
        
        # Remaining columns
        for c in range(1, 4):
            for r in range(4):
                new_key[r][c] = new_key[r][c-1] ^ prev[r][c]
        
        round_keys.append(new_key)
    
    return round_keys


def aes_encrypt_block(plaintext, round_keys):
    """AES加密单块"""
    state = bytes_to_matrix(plaintext)
    state = aes_add_round_key(state, round_keys[0])
    
    for rnd in range(1, 10):
        state = aes_sub_bytes(state)
        state = aes_shift_rows(state)
        state = aes_mix_columns(state)
        state = aes_add_round_key(state, round_keys[rnd])
    
    state = aes_sub_bytes(state)
    state = aes_shift_rows(state)
    state = aes_add_round_key(state, round_keys[10])
    
    return matrix_to_bytes(state)


def aes_decrypt_block(ciphertext, round_keys):
    """AES解密单块"""
    state = bytes_to_matrix(ciphertext)
    state = aes_add_round_key(state, round_keys[10])
    
    for rnd in range(9, 0, -1):
        state = aes_shift_rows(state, inverse=True)
        state = aes_sub_bytes(state, inverse=True)
        state = aes_add_round_key(state, round_keys[rnd])
        state = aes_mix_columns(state, inverse=True)
    
    state = aes_shift_rows(state, inverse=True)
    state = aes_sub_bytes(state, inverse=True)
    state = aes_add_round_key(state, round_keys[0])
    
    return matrix_to_bytes(state)


class SimpleAES:
    """AES算法类"""
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("AES密钥必须是16字节!")
        self.round_keys = aes_expand_key(key)
    
    def encrypt_block(self, plaintext):
        return aes_encrypt_block(plaintext, self.round_keys)
    
    def decrypt_block(self, ciphertext):
        return aes_decrypt_block(ciphertext, self.round_keys)


# ==================== ECB模式 ====================

class ECB_Mode:
    """ECB工作模式"""
    def __init__(self, cipher):
        self.cipher = cipher
        self.block_size = 8 if isinstance(cipher, SimpleDES) else 16
    
    def encrypt(self, plaintext):
        """ECB加密"""
        padded = pkcs7_pad(plaintext, self.block_size)
        cipher_text = bytearray()
        
        num_blocks = len(padded) // self.block_size
        for i in range(num_blocks):
            block = padded[i*self.block_size:(i+1)*self.block_size]
            encrypted_block = self.cipher.encrypt_block(block)
            cipher_text.extend(encrypted_block)
        
        return bytes(cipher_text)
    
    def decrypt(self, ciphertext):
        """ECB解密"""
        plain_text = bytearray()
        
        num_blocks = len(ciphertext) // self.block_size
        for i in range(num_blocks):
            block = ciphertext[i*self.block_size:(i+1)*self.block_size]
            decrypted_block = self.cipher.decrypt_block(block)
            plain_text.extend(decrypted_block)
        
        return pkcs7_unpad(bytes(plain_text))


# ==================== 交互式界面 ====================

def interactive_mode():
    """交互模式"""
    print("\n" + "=" * 60)
    print("  密码学加密工具 - ECB模式")
    print("=" * 60)
    
    # 选择操作
    print("\n请选择操作:")
    print("  1. 加密文件")
    print("  2. 解密文件")
    choice = input("\n请输入选项 (1/2): ").strip()
    
    if choice not in ['1', '2']:
        print("错误: 无效选项!")
        return
    
    is_encrypt = (choice == '1')
    
    # 选择算法
    print("\n请选择加密算法:")
    print("  1. DES (8字节密钥)")
    print("  2. AES-128 (16字节密钥)")
    algo_choice = input("\n请输入选项 (1/2): ").strip()
    
    if algo_choice == '1':
        algo_name = "DES"
        key_size = 8
    elif algo_choice == '2':
        algo_name = "AES-128"
        key_size = 16
    else:
        print("错误: 无效选项!")
        return
    
    # 输入密钥
    print(f"\n请输入{key_size}字节的密钥:")
    key_input = input("密钥: ").strip()
    
    if len(key_input) != key_size:
        print(f"错误: 密钥长度必须是{key_size}字节! (当前{len(key_input)}字节)")
        return
    
    key_bytes = key_input.encode('utf-8')
    
    # 输入文件路径
    if is_encrypt:
        print("\n请输入要加密的文件路径:")
        input_file = input("输入文件路径: ").strip()
        
        if not os.path.exists(input_file):
            print(f"错误: 文件 '{input_file}' 不存在!")
            return
        
        print("\n请输入输出文件路径(将保存十六进制格式的密文):")
        output_file = input("输出文件路径: ").strip()
        
        file_desc = "明文文件"
    else:
        print("\n请输入要解密的文件路径(十六进制格式的密文文件):")
        input_file = input("输入文件路径: ").strip()
        
        if not os.path.exists(input_file):
            print(f"错误: 文件 '{input_file}' 不存在!")
            return
        
        print("\n请输入输出文件路径(将保存解密后的明文):")
        output_file = input("输出文件路径: ").strip()
        
        file_desc = "密文文件"
    
    # 执行加解密
    print(f"\n开始{'加密' if is_encrypt else '解密'}...")
    print(f"算法: {algo_name}")
    print(f"输入文件: {input_file} ({file_desc})")
    print(f"输出文件: {output_file}")
    print("-" * 60)
    
    try:
        if algo_name == "DES":
            cipher = SimpleDES(key_bytes)
        else:
            cipher = SimpleAES(key_bytes)
        
        mode = ECB_Mode(cipher)
        
        if is_encrypt:
            plain_data = read_file(input_file)
            if plain_data is None:
                return
            
            cipher_data = mode.encrypt(plain_data)
            cipher_hex = to_hex(cipher_data)
            write_file(output_file, cipher_hex.encode('utf-8'))
            
            print(f"\n✓ 加密成功!")
            print(f"  密文已保存到: {output_file}")
            print(f"  密文长度: {len(cipher_hex)} 字符(十六进制)")
        else:
            hex_data = read_file(input_file)
            if hex_data is None:
                return
            
            try:
                cipher_data = from_hex(hex_data.decode('utf-8'))
            except Exception as e:
                print(f"错误: 密文文件格式不正确! {e}")
                return
            
            plain_data = mode.decrypt(cipher_data)
            if plain_data is None:
                print("错误: 解密失败!")
                return
            
            write_file(output_file, plain_data)
            
            print(f"\n✓ 解密成功!")
            print(f"  明文已保存到: {output_file}")
            print(f"  明文长度: {len(plain_data)} 字节")
    
    except Exception as e:
        print(f"\n错误: 操作失败! {e}")


def main():
    """主函数"""
    print("     DES和AES密码算法演示".center(60))
    print("     工作模式:ECB".center(60))
    interactive_mode()


if __name__ == "__main__":
    main()