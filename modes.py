"""
ECB工作模式实现 - 电子密码本模式
支持自动填充和多块迭代加解密
"""

from tools import add_padding, remove_padding


class ECB_Mode:
    """ECB模式封装类 - 将块密码扩展到任意长度数据"""
    
    def __init__(self, cipher):
        """初始化ECB模式
        
        Args:
            cipher: 块密码算法实例(SimpleDES或SimpleAES)
        """
        self.cipher = cipher
        
        # 根据算法类型确定块大小
        algo_name = cipher.__class__.__name__
        if algo_name == 'SimpleDES':
            self.block_size = 8
            self.algo_name = "DES"
        elif algo_name == 'SimpleAES':
            self.block_size = 16
            self.algo_name = "AES-128"
        else:
            raise ValueError(f"不支持的算法: {algo_name}")
        
        print(f"【ECB模式】算法:{self.algo_name}, 块大小:{self.block_size}字节")
    
    def encrypt(self, plaintext):
        """ECB加密任意长度数据
        
        流程:填充->分块->逐块加密
        """
        print(f"\n【ECB加密】开始 - 原始数据:{len(plaintext)}字节")
        
        # 添加填充
        padded = add_padding(plaintext, self.block_size)
        num_blocks = len(padded) // self.block_size
        print(f"【ECB加密】分为{num_blocks}个块")
        
        # 逐块加密
        ciphertext = bytearray()
        for i in range(num_blocks):
            block = padded[i*self.block_size:(i+1)*self.block_size]
            encrypted_block = self.cipher.encrypt_block(block)
            ciphertext.extend(encrypted_block)
            
            # 显示进度(只显示前后几块)
            if i < 3 or i >= num_blocks - 2:
                print(f"【ECB加密】  块{i+1}/{num_blocks}")
            elif i == 3 and num_blocks > 8:
                print(f"【ECB加密】  ...省略...")
        
        print(f"【ECB加密】完成 - 密文:{len(ciphertext)}字节")
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext):
        """ECB解密
        
        流程:分块->逐块解密->去填充
        """
        print(f"\n【ECB解密】开始 - 密文:{len(ciphertext)}字节")
        
        # 检查密文长度
        if len(ciphertext) % self.block_size != 0:
            print(f"【ECB解密】错误!密文长度不是{self.block_size}的倍数")
            return None
        
        num_blocks = len(ciphertext) // self.block_size
        print(f"【ECB解密】共{num_blocks}个块")
        
        # 逐块解密
        decrypted_padded = bytearray()
        for i in range(num_blocks):
            block = ciphertext[i*self.block_size:(i+1)*self.block_size]
            decrypted_block = self.cipher.decrypt_block(block)
            decrypted_padded.extend(decrypted_block)
            
            # 显示进度
            if i < 3 or i >= num_blocks - 2:
                print(f"【ECB解密】  块{i+1}/{num_blocks}")
            elif i == 3 and num_blocks > 8:
                print(f"【ECB解密】  ...省略...")
        
        # 移除填充
        plaintext = remove_padding(bytes(decrypted_padded), self.block_size)
        print(f"【ECB解密】完成 - 明文:{len(plaintext)}字节")
        return plaintext


if __name__ == "__main__":
    print("ECB模式模块测试 - 请运行main.py进行完整测试")