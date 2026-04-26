"""
DES加密算法实现 - 基于FIPS PUB 46-3标准
包含:初始置换、Feistel网络、S/P盒替换、密钥扩展等完整流程
"""

# ==================== DES标准置换表 ====================

# 初始置换表 IP (64位重排)
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# 表2逆初始置换表 IP^-1
IP_INV_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# 表3扩展表 E（32位 -> 48位）
E_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# 表4：S盒
S_BOXES = [
    # S1 盒
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2 盒
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3 盒
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4 盒
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5 盒
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6 盒
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7 盒
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8 盒
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# 表5：P盒置换表（32位 -> 32位）
P_TABLE = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

# ==================== 密钥处理表格 ====================

# PC-1 置换表
PC1_TABLE = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

# PC-2 置换表
PC2_TABLE = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# 左移位数表
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# ==================== 基础位操作工具 ====================

def bytes_to_bits(data):
    """字节数组转二进制字符串"""
    bits = ""
    for byte in data:
        # 逐个检查每个位
        for i in range(7, -1, -1):
            if (byte >> i) & 1:
                bits += "1"
            else:
                bits += "0"
    return bits


def bits_to_bytes(bit_str):
    """二进制字符串转字节数组"""
    if len(bit_str) % 8 != 0:
        raise ValueError("二进制字符串长度必须是8的倍数")
    
    result = []
    # 每次取8位转换为一个字节
    for i in range(0, len(bit_str), 8):
        eight_bits = bit_str[i:i+8]
        byte_val = 0
        # 从左到右计算每一位的值
        for j in range(8):
            if eight_bits[j] == '1':
                byte_val += (1 << (7 - j))
        result.append(byte_val)
    
    return bytes(result)


def rearrange_bits(bits, table):
    """按表格重新排列位串"""
    result = ""
    for pos in table:
        result += bits[pos - 1]
    return result


def left_rotate(bits, n):
    """循环左移n位"""
    return bits[n:] + bits[:n]


def xor_bits(bits1, bits2):
    """两个等长二进制字符串异或"""
    if len(bits1) != len(bits2):
        raise ValueError("异或操作需要等长的位串!")
    
    result = ""
    for i in range(len(bits1)):
        if bits1[i] != bits2[i]:
            result += "1"
        else:
            result += "0"
    return result


# ==================== DES核心算法函数 ====================

def generate_subkeys(master_key):
    """从主密钥生成16轮子密钥"""
    print("\n生成16个子密钥...")
    
    # 将密钥转为二进制位串
    key_bits = bytes_to_bits(master_key)
    
    # PC-1置换：64位变成56位
    key_56bits = rearrange_bits(key_bits, PC1_TABLE)
    
    # 分成左右两半，各28位
    C = key_56bits[:28]
    D = key_56bits[28:]
    
    subkeys = []
    # 进行16轮处理
    for round_idx in range(16):
        # 根据移位表进行循环左移
        shift = SHIFT_SCHEDULE[round_idx]
        C = left_rotate(C, shift)
        D = left_rotate(D, shift)
        
        # 合并后做PC-2置换，得到48位子密钥
        combined = C + D
        subkey = rearrange_bits(combined, PC2_TABLE)
        subkeys.append(subkey)
    
    print(f"完成!共生成{len(subkeys)}个子密钥")
    return subkeys


def feistel_function(right_half, subkey):
    """DES的F函数:32位右半部分 + 48位子密钥 -> 32位输出"""
    # 第一步：E扩展，32位变成48位
    expanded = rearrange_bits(right_half, E_TABLE)
    
    # 第二步：与子密钥异或
    xored = xor_bits(expanded, subkey)
    
    # 第三步：S盒替换，48位变回32位
    sbox_output = ""
    for i in range(8):
        # 每次取6位
        six_bits = xored[i*6:(i+1)*6]
        
        # 第1位和第6位决定行号
        row_str = six_bits[0] + six_bits[5]
        row = int(row_str, 2)
        
        # 中间4位决定列号
        col_str = six_bits[1:5]
        col = int(col_str, 2)
        
        # 查S盒得到值
        val = S_BOXES[i][row][col]
        
        # 将值转为4位二进制
        val_bits = ""
        for p in [8, 4, 2, 1]:
            if val >= p:
                val_bits += "1"
                val -= p
            else:
                val_bits += "0"
        
        sbox_output += val_bits
    
    # 第四步：P盒置换
    result = rearrange_bits(sbox_output, P_TABLE)
    return result


def des_encrypt_decrypt(block, subkeys, encrypt=True):
    """DES单块加解密核心逻辑"""
    # 将数据块转为二进制
    bits = bytes_to_bits(block)
    
    # 初始置换IP
    bits = rearrange_bits(bits, IP_TABLE)
    
    # 分成左右两半，各32位
    L = bits[:32]
    R = bits[32:]
    
    # 如果是解密，子密钥要反序使用
    if encrypt:
        keys = subkeys
    else:
        keys = []
        for i in range(len(subkeys) - 1, -1, -1):
            keys.append(subkeys[i])
    
    # 进行16轮Feistel网络处理
    for i in range(16):
        old_R = R
        
        # 计算F函数
        f_result = feistel_function(R, keys[i])
        
        # 新的R = L异或F的结果
        R = xor_bits(L, f_result)
        
        # 新的L = 原来的R
        L = old_R
    
    # 最后一轮后要交换左右部分
    combined = R + L
    
    # 逆初始置换
    final_bits = rearrange_bits(combined, IP_INV_TABLE)
    
    # 转回字节
    result = bits_to_bytes(final_bits)
    return result


class SimpleDES:
    """DES加密算法类 - 支持单块加解密"""
    
    def __init__(self, key):
        if len(key) != 8:
            raise ValueError("DES密钥必须是8字节!")
        
        print(f"[DES初始化] 密钥: {key.hex()}")
        self.subkeys = generate_subkeys(key)
        print("[DES初始化] 完成\n")
    
    def encrypt_block(self, plaintext):
        """加密单个8字节数据块"""
        if len(plaintext) != 8:
            raise ValueError("DES数据块必须为8字节!")
        return des_encrypt_decrypt(plaintext, self.subkeys, encrypt=True)
    
    def decrypt_block(self, ciphertext):
        """解密单个8字节数据块"""
        if len(ciphertext) != 8:
            raise ValueError("DES数据块必须为8字节!")
        return des_encrypt_decrypt(ciphertext, self.subkeys, encrypt=False)
