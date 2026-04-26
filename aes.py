"""
AES-128加密算法实现 - 基于SPN结构
包含:字节代换、行移位、列混合、轮密钥加等完整流程
"""

# ==================== AES标准常量表 ====================

# S盒
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# 逆S盒
INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# 轮常数
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

# ==================== GF(2^8)有限域运算 ====================

def gf_multiply(a, b):
    """GF(2^8)有限域乘法"""
    result = 0
    
    # 逐位处理b的每一位
    for i in range(8):
        # 如果b的当前最低位是1，就把a加到结果中（异或）
        if b & 1:
            result = result ^ a
        
        # 检查a的最高位是否为1
        high_bit = a & 0x80
        
        # a左移一位
        a = a << 1
        # 保持a在0-255范围内
        if a > 255:
            a = a - 256
        
        # 如果最高位原来是1，需要异或0x1B来模约简
        if high_bit:
            a = a ^ 0x1B
        
        # b右移一位，处理下一位
        b = b >> 1
    
    return result

# ==================== 状态矩阵转换 ====================

def bytes_to_matrix(data):
    """16字节转4x4状态矩阵(按列填充)"""
    # 创建4x4的矩阵，初始值为0
    state = [[0, 0, 0, 0],
             [0, 0, 0, 0],
             [0, 0, 0, 0],
             [0, 0, 0, 0]]
    
    # 按列填充：第0列填data[0-3]，第1列填data[4-7]...
    for c in range(4):
        for r in range(4):
            index = r + c * 4
            state[r][c] = data[index]
    
    return state


def matrix_to_bytes(state):
    """4x4状态矩阵转16字节(按列读取)"""
    result = []
    
    # 按列读取：先读第0列的4个字节，再读第1列...
    for c in range(4):
        for r in range(4):
            result.append(state[r][c])
    
    return bytes(result)

# ==================== AES四轮操作 ====================

def substitute_bytes(state, inverse=False):
    """字节替换(SubBytes/InvSubBytes)"""
    # 选择使用哪个替换表
    if inverse:
        box = INV_S_BOX
    else:
        box = S_BOX
    
    # 遍历状态矩阵的每个字节
    for r in range(4):
        for c in range(4):
            old_val = state[r][c]
            new_val = box[old_val]
            state[r][c] = new_val
    
    return state


def shift_rows(state, inverse=False):
    """行移位(ShiftRows/InvShiftRows)"""
    for r in range(4):
        # 复制当前行
        original_row = []
        for c in range(4):
            original_row.append(state[r][c])
        
        if inverse:
            # 解密：循环右移r位
            if r == 0:
                # 第0行不移位
                pass
            elif r == 1:
                # 第1行右移1位
                state[r][0] = original_row[3]
                state[r][1] = original_row[0]
                state[r][2] = original_row[1]
                state[r][3] = original_row[2]
            elif r == 2:
                # 第2行右移2位
                state[r][0] = original_row[2]
                state[r][1] = original_row[3]
                state[r][2] = original_row[0]
                state[r][3] = original_row[1]
            elif r == 3:
                # 第3行右移3位
                state[r][0] = original_row[1]
                state[r][1] = original_row[2]
                state[r][2] = original_row[3]
                state[r][3] = original_row[0]
        else:
            # 加密：循环左移r位
            if r == 0:
                # 第0行不移位
                pass
            elif r == 1:
                # 第1行左移1位
                state[r][0] = original_row[1]
                state[r][1] = original_row[2]
                state[r][2] = original_row[3]
                state[r][3] = original_row[0]
            elif r == 2:
                # 第2行左移2位
                state[r][0] = original_row[2]
                state[r][1] = original_row[3]
                state[r][2] = original_row[0]
                state[r][3] = original_row[1]
            elif r == 3:
                # 第3行左移3位
                state[r][0] = original_row[3]
                state[r][1] = original_row[0]
                state[r][2] = original_row[1]
                state[r][3] = original_row[2]
    
    return state


def mix_columns(state, inverse=False):
    """列混合(MixColumns/InvMixColumns)"""
    for c in range(4):
        # 取出当前列的4个字节
        c0 = state[0][c]
        c1 = state[1][c]
        c2 = state[2][c]
        c3 = state[3][c]
        
        if inverse:
            # 逆列混合（解密时用）
            new_c0 = gf_multiply(0x0E, c0) ^ gf_multiply(0x0B, c1) ^ gf_multiply(0x0D, c2) ^ gf_multiply(0x09, c3)
            new_c1 = gf_multiply(0x09, c0) ^ gf_multiply(0x0E, c1) ^ gf_multiply(0x0B, c2) ^ gf_multiply(0x0D, c3)
            new_c2 = gf_multiply(0x0D, c0) ^ gf_multiply(0x09, c1) ^ gf_multiply(0x0E, c2) ^ gf_multiply(0x0B, c3)
            new_c3 = gf_multiply(0x0B, c0) ^ gf_multiply(0x0D, c1) ^ gf_multiply(0x09, c2) ^ gf_multiply(0x0E, c3)
        else:
            # 正向列混合（加密时用）
            new_c0 = gf_multiply(0x02, c0) ^ gf_multiply(0x03, c1) ^ c2 ^ c3
            new_c1 = c0 ^ gf_multiply(0x02, c1) ^ gf_multiply(0x03, c2) ^ c3
            new_c2 = c0 ^ c1 ^ gf_multiply(0x02, c2) ^ gf_multiply(0x03, c3)
            new_c3 = gf_multiply(0x03, c0) ^ c1 ^ c2 ^ gf_multiply(0x02, c3)
        
        # 将计算结果写回状态矩阵
        state[0][c] = new_c0
        state[1][c] = new_c1
        state[2][c] = new_c2
        state[3][c] = new_c3
    
    return state


def add_round_key(state, round_key):
    """轮密钥加(AddRoundKey)"""
    for r in range(4):
        for c in range(4):
            # 状态与轮密钥对应位置异或
            state[r][c] = state[r][c] ^ round_key[r][c]
    return state

# ==================== 密钥扩展 ====================

def expand_key(master_key):
    """AES-128密钥扩展:16字节主密钥->11个轮密钥"""
    print("\n【AES密钥扩展】生成11个轮密钥...")
    
    # 将主密钥转为4x4矩阵，作为第0个轮密钥
    round_keys = [bytes_to_matrix(master_key)]
    
    # 生成后续的10个轮密钥
    for rnd in range(1, 11):
        # 获取上一个轮密钥
        prev = round_keys[-1]
        
        # 创建新的轮密钥矩阵
        new_key = [[0, 0, 0, 0],
                   [0, 0, 0, 0],
                   [0, 0, 0, 0],
                   [0, 0, 0, 0]]
        
        # 第一步：取上一轮密钥的最后一列
        temp = []
        for r in range(4):
            temp.append(prev[r][3])
        
        # 第二步：循环上移一位（RotWord）
        first_byte = temp[0]
        temp[0] = temp[1]
        temp[1] = temp[2]
        temp[2] = temp[3]
        temp[3] = first_byte
        
        # 第三步：S盒替换（SubWord）
        for i in range(4):
            temp[i] = S_BOX[temp[i]]
        
        # 第四步：第一个字节异或轮常数
        temp[0] = temp[0] ^ RCON[rnd - 1]
        
        # 第五步：计算新密钥的第一列
        for r in range(4):
            new_key[r][0] = prev[r][0] ^ temp[r]
        
        # 第六步：计算剩余的三列（每列 = 前一列异或上一轮密钥的对应列）
        for c in range(1, 4):
            for r in range(4):
                new_key[r][c] = new_key[r][c-1] ^ prev[r][c]
        
        # 将新轮密钥加入列表
        round_keys.append(new_key)
    
    print(f"【AES密钥扩展】完成!共{len(round_keys)}个轮密钥")
    return round_keys


# ==================== AES加解密核心流程 ====================

def aes_encrypt_block(plaintext, round_keys):
    """AES加密单个16字节块"""
    state = bytes_to_matrix(plaintext)
    
    # 初始轮密钥加
    state = add_round_key(state, round_keys[0])
    
    # 第1-9轮:SubBytes->ShiftRows->MixColumns->AddRoundKey
    for rnd in range(1, 10):
        state = substitute_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[rnd])
    
    # 第10轮(最后一轮):无MixColumns
    state = substitute_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return matrix_to_bytes(state)


def aes_decrypt_block(ciphertext, round_keys):
    """AES解密单个16字节块"""
    state = bytes_to_matrix(ciphertext)
    
    # 初始轮密钥加(使用最后一个轮密钥)
    state = add_round_key(state, round_keys[10])
    
    # 第9-1轮逆操作:InvShiftRows->InvSubBytes->AddRoundKey->InvMixColumns
    for rnd in range(9, 0, -1):
        state = shift_rows(state, inverse=True)
        state = substitute_bytes(state, inverse=True)
        state = add_round_key(state, round_keys[rnd])
        state = mix_columns(state, inverse=True)
    
    # 最后一轮逆操作
    state = shift_rows(state, inverse=True)
    state = substitute_bytes(state, inverse=True)
    state = add_round_key(state, round_keys[0])
    
    return matrix_to_bytes(state)


class SimpleAES:
    """AES-128加密算法类 - 支持单块加解密"""
    
    def __init__(self, key):
        if len(key) != 16:
            raise ValueError("AES-128密钥必须是16字节!")
        
        print(f"【AES初始化】密钥: {key.hex()}")
        self.round_keys = expand_key(key)
        print("【AES初始化】完成\n")
    
    def encrypt_block(self, plaintext):
        """加密单个16字节数据块"""
        if len(plaintext) != 16:
            raise ValueError("AES数据块必须为16字节!")
        return aes_encrypt_block(plaintext, self.round_keys)
    
    def decrypt_block(self, ciphertext):
        """解密单个16字节数据块"""
        if len(ciphertext) != 16:
            raise ValueError("AES数据块必须为16字节!")
        return aes_decrypt_block(ciphertext, self.round_keys)
