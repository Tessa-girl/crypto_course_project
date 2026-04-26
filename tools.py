"""
工具函数模块 - 处理字节转换、文件读写和填充操作
"""

def read_file(filepath):
    """读取文件为字节数据"""
    try:
        with open(filepath, 'rb') as f:
            data = f.read()
        print(f"[工具] 读取文件 '{filepath}', 大小: {len(data)} 字节")
        return data
    except FileNotFoundError:
        print(f"[错误] 文件 '{filepath}' 不存在!")
        return None


def write_file(filepath, data):
    """将字节数据写入文件"""
    with open(filepath, 'wb') as f:
        f.write(data)
    print(f"[工具] 写入文件 '{filepath}', 大小: {len(data)} 字节")


def str_to_bytes(text):
    """字符串转字节(UTF-8编码)"""
    return text.encode('utf-8')


def bytes_to_str(data):
    """字节转字符串(UTF-8解码)"""
    try:
        return data.decode('utf-8')
    except Exception:
        print("【错误】 无法解码为UTF-8,可能密钥错误!")
        return None


def to_hex(data):
    """字节转十六进制字符串"""
    return data.hex()


def from_hex(hex_str):
    """十六进制字符串转字节"""
    return bytes.fromhex(hex_str)


# ==================== PKCS#7 填充/去填充 ====================

def add_padding(data, block_size):
    """添加填充:使数据长度为block_size的整数倍"""
    data_len = len(data)
    remainder = data_len % block_size
    
    # 计算需要填充多少字节
    if remainder == 0:
        # 如果正好是整数倍，需要填充一整个块
        pad_len = block_size
    else:
        pad_len = block_size - remainder
    
    # 创建填充字节（每个字节的值都是pad_len）
    padding = bytes([pad_len] * pad_len)
    
    # 将填充附加到原数据后面
    result = data + padding
    return result


def remove_padding(padded_data, block_size):
    """移除填充"""
    if len(padded_data) == 0:
        return padded_data
    
    # 获取最后一个字节的值，这就是填充长度
    pad_len = padded_data[-1]
    
    # 安全检查：填充长度不能为0，也不能超过块大小
    if pad_len > block_size or pad_len == 0:
        print(f"【警告】 填充长度{pad_len}异常(块大小{block_size}),可能密钥错误!")
        return padded_data
    
    # 验证填充是否正确：检查最后pad_len个字节是否都等于pad_len
    expected = bytes([pad_len] * pad_len)
    actual = padded_data[-pad_len:]
    
    if actual != expected:
        print(f"【警告】 填充格式不正确")
        return padded_data
    
    # 移除最后的填充部分
    result = padded_data[:-pad_len]
    return result
