"""
主程序 - DES和AES加密算法演示(ECB模式)
展示完整加解密流程并生成测试文件
"""

from tools import (
    read_file, write_file,
    str_to_bytes, bytes_to_str,
    to_hex, from_hex
)
from des import SimpleDES
from aes import SimpleAES
from modes import ECB_Mode

def print_separator(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def print_section(title):
    print("\n" + "-" * 50)
    print(f"  {title}")
    print("-" * 50)

def test_des_ecb():
    """测试DES-ECB对文本的加解密"""
    print_separator("第一部分:DES-ECB算法测试")
    
    # 1.准备密钥
    print_section("1:准备DES密钥")
    key = b'mykey123'
    print(f"密钥原文: {key.decode('ascii')}")
    print(f"密钥(十六进制): {key.hex()}")
    
    # 2.初始化DES和ECB模式
    print_section("2:初始化DES和ECB模式")
    des_cipher = SimpleDES(key)
    des_mode = ECB_Mode(des_cipher)
    
    # 3.准备测试文本
    print_section("3:准备测试文本")
    original_text = """Constant dripping wears away a stone. 水滴石穿，绳锯木断。
Brevity is the soul of wit. 言简意赅，智慧的精髓。
：，。！？；："”''
life is not waiting for the storm to pass, but learning to dance in the rain. 人生不是等待暴风雨过去，而是学会在雨中跳舞。EOF"""
    
    print("原始文本:")
    print("-" * 40)
    print(original_text)
    print("-" * 40)
    print(f"字符数:{len(original_text)}, 字节数待转换")
    
    plain_bytes = str_to_bytes(original_text)
    print(f"转换后字节数:{len(plain_bytes)}")
    
    # 保存原始明文
    write_file("des_ecb_plain.txt", plain_bytes)
    print("原始明文已保存到:des_ecb_plain.txt")
    
    # 4.加密
    print_section("4:DES-ECB加密")
    cipher_bytes = des_mode.encrypt(plain_bytes)
    cipher_hex = to_hex(cipher_bytes)
    print(f"\n密文(十六进制前80字符):\n{cipher_hex[:80]}...")
    
    # 保存密文
    write_file("des_ecb_cipher.txt", cipher_hex.encode('utf-8'))
    print("密文已保存到:des_ecb_cipher.txt")
    
    # 5.解密
    print_section("5:DES-ECB解密")
    print("从文件读取密文...")
    cipher_hex_read = read_file("des_ecb_cipher.txt").decode('utf-8')
    cipher_bytes_read = from_hex(cipher_hex_read)
    
    decrypted_bytes = des_mode.decrypt(cipher_bytes_read)
    decrypted_text = bytes_to_str(decrypted_bytes)
    
    print("\n解密后的文本:")
    print("-" * 40)
    print(decrypted_text)
    print("-" * 40)
    
    # 保存解密结果
    write_file("des_ecb_decrypted.txt", decrypted_bytes)
    print("解密明文已保存到:des_ecb_decrypted.txt")
    
    # 6.验证
    print_section("6:验证结果")
    if original_text == decrypted_text:
        print("✓ DES-ECB加解密成功!")
        print("  原文与解密文本完全一致")
    else:
        print("✗ DES-ECB加解密失败!")
        print(f"  原文长度:{len(original_text)}字符")
        print(f"  解密长度:{len(decrypted_text) if decrypted_text else 0}字符")


def test_aes_ecb():
    """测试AES-ECB对文件的加解密"""
    print_separator("第二部分:AES-128-ECB算法测试")
    
    # 1.准备密钥
    print_section("1:准备AES-128密钥")
    key = b'0123456789abcdef'
    print(f"密钥原文: {key.decode('ascii')}")
    print(f"密钥(十六进制): {key.hex()}")
    
    # 2.初始化AES和ECB模式
    print_section("2:初始化AES和ECB模式")
    aes_cipher = SimpleAES(key)
    aes_mode = ECB_Mode(aes_cipher)
    
    # 3.准备测试内容
    print_section("3:准备测试文件")
    test_content = """====================================
【文件信息】
加密算法：AES-128
工作模式：ECB (Electronic Codebook Mode)

【中文测试】
从"绿树村边合，青山郭外斜"的景致到"采菊东篱下，悠然见南山"的惬意，
乡土中国向来不缺少美的元素。这个春天，万千乡村在"美"中苏醒。

【English Test】
Through education and student initiatives, cross-cultural exchange deepens China-Central Asia ties 
while fostering mutual understanding and long-term people-to-people connections.

【混合测试】
在景德镇瓷器还能是什么？
Today, ceramic art has transcended its functional origins to become 
a vital form of contemporary expression.
：！@#$%^&*()_+-=[]{}|;':",./<>?
0123456789

【重复内容测试】
AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH
AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH
AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH

========================================"""
    
    print("测试内容预览:")
    print("-" * 50)
    print(test_content[:500] + "...")
    print("-" * 50)
    print(f"总长度:{len(test_content)}字符")
    
    plain_bytes = str_to_bytes(test_content)
    print(f"转换后字节数:{len(plain_bytes)}")
    
    # 保存原始文件
    write_file("aes_ecb_plain.txt", plain_bytes)
    print("原始文件已保存到:aes_ecb_plain.txt")
    
    # 4.加密
    print_section("4:AES-ECB加密")
    file_bytes = read_file("aes_ecb_plain.txt")
    cipher_bytes = aes_mode.encrypt(file_bytes)
    
    cipher_hex = to_hex(cipher_bytes)
    write_file("aes_ecb_cipher.txt", cipher_hex.encode('utf-8'))
    print("密文已保存到:aes_ecb_cipher.txt")
    print(f"密文长度:{len(cipher_hex)}字符")
    print(f"密文前80字符:{cipher_hex[:80]}...")
    
    # 5.解密
    print_section("5:AES-ECB解密")
    print("从文件读取密文...")
    cipher_hex_read = read_file("aes_ecb_cipher.txt").decode('utf-8')
    cipher_bytes_read = from_hex(cipher_hex_read)
    
    decrypted_bytes = aes_mode.decrypt(cipher_bytes_read)
    write_file("aes_ecb_decrypted.txt", decrypted_bytes)
    print("解密文件已保存到:aes_ecb_decrypted.txt")
    
    decrypted_text = bytes_to_str(decrypted_bytes)
    print("\n解密内容预览(前500字符):")
    print("-" * 50)
    print(decrypted_text[:500] + "...")
    print("-" * 50)
    
    # 6.验证
    print_section("6:验证结果")
    if test_content == decrypted_text:
        print("✓ AES-ECB文件加解密成功!")
        print("  文件内容完全一致")
        print("  可打开'aes_ecb_decrypted.txt'查看完整内容")
    else:
        print("✗ AES-ECB文件加解密失败!")
        print(f"  原文长度:{len(test_content)}字符")
        print(f"  解密长度:{len(decrypted_text)}字符")
        
        # 查找第一个差异位置
        min_len = min(len(test_content), len(decrypted_text))
        for i in range(min_len):
            if test_content[i] != decrypted_text[i]:
                print(f"  首个差异位置:第{i}字符")
                print(f"    原文:'{test_content[i]}' (ASCII:{ord(test_content[i])})")
                print(f"    解密:'{decrypted_text[i]}' (ASCII:{ord(decrypted_text[i])})")
                break
        else:
            if len(test_content) != len(decrypted_text):
                print(f"  前{min_len}字符相同,但长度不同")


def main():
    print("     DES和AES密码算法演示".center(60))
    print("     工作模式:ECB (Electronic Codebook Mode)".center(60))
    
    # 运行测试
    test_des_ecb()
    test_aes_ecb()
    
    # 总结
    print_separator("程序运行完毕")
    print("\n生成的文件相关说明:")
    print("  【DES-ECB相关文件】")
    print("    - des_ecb_plain.txt       (DES原始明文)")
    print("    - des_ecb_cipher.txt      (DES密文-十六进制)")
    print("    - des_ecb_decrypted.txt   (DES解密明文)")
    print("\n  【AES-ECB相关文件】")
    print("    - aes_ecb_plain.txt       (AES原始明文)")
    print("    - aes_ecb_cipher.txt      (AES密文-十六进制)")
    print("    - aes_ecb_decrypted.txt   (AES解密明文)")

if __name__ == "__main__":
    main()