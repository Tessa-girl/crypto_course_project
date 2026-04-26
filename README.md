# 密码学算法演示项目

## 📖 项目简介

这是一个用于学习密码学原理的 Python 项目，实现了两种经典的对称加密算法：
- **DES** (Data Encryption Standard) - 数据加密标准
- **AES-128** (Advanced Encryption Standard) - 高级加密标准

项目使用 **ECB** (Electronic Codebook Mode) 工作模式，支持任意长度的中英文文本加密和解密。

> ⚠️ **重要提示**：本项目仅用于学习和理解密码算法的工作原理。ECB 模式在实际应用中安全性较弱，不建议在生产环境中使用。

---

## 🚀 快速开始

### 环境要求

- Python 3.6 或更高版本
- 无需安装任何第三方库（纯 Python 实现）

### 运行程序

在项目根目录下执行以下命令：

```bash
python main.py
```

程序将自动执行以下操作：
1. 运行简单的 DES 加密演示
2. 测试 DES-ECB 对文本的完整加解密流程
3. 测试 AES-128-ECB 对文件的完整加解密流程
4. 验证加解密的正确性
5. 生成相关的测试文件

---

## 📁 项目结构

```
crypto_project/
├── main.py          # 主程序入口，包含完整的测试用例
├── des.py           # DES 算法实现
├── aes.py           # AES-128 算法实现
├── modes.py         # ECB 工作模式实现
├── tools.py         # 工具函数（字节转换、填充处理等）
└── README.md        # 本说明文档
```

### 生成的测试文件

运行 `main.py` 后，会生成以下文件：

**DES-ECB 相关文件：**
- `des_ecb_plain.txt` - DES 原始明文文件
- `des_ecb_cipher.txt` - DES 加密后的密文（十六进制格式）
- `des_ecb_decrypted.txt` - DES 解密后的明文

**AES-ECB 相关文件：**
- `aes_ecb_plain.txt` - AES 原始明文文件
- `aes_ecb_cipher.txt` - AES 加密后的密文（十六进制格式）
- `aes_ecb_decrypted.txt` - AES 解密后的明文

---

## 🔧 核心功能模块

### 1. DES 算法 (`des.py`)

实现了完整的 DES 加密算法，包括：
- 初始置换 (IP) 和逆初始置换 (IP⁻¹)
- 密钥扩展（生成 16 个子密钥）
- Feistel 网络结构
- S 盒替换
- P 盒置换
- F 函数

**使用方法：**
```python
from des import SimpleDES

# 创建 DES 实例（密钥必须是 8 字节）
key = b'mykey123'
des = SimpleDES(key)

# 加密单个 8 字节数据块
cipher_block = des.encrypt_block(b'12345678')

# 解密单个 8 字节数据块
plain_block = des.decrypt_block(cipher_block)
```

### 2. AES-128 算法 (`aes.py`)

实现了完整的 AES-128 加密算法，包括：
- 字节代换 (SubBytes) 和逆字节代换
- 行移位 (ShiftRows) 和逆行移位
- 列混合 (MixColumns) 和逆列混合
- 轮密钥加 (AddRoundKey)
- 密钥扩展（生成 11 个轮密钥）
- GF(2⁸) 有限域乘法

**使用方法：**
```python
from aes import SimpleAES

# 创建 AES 实例（密钥必须是 16 字节）
key = b'0123456789abcdef'
aes = SimpleAES(key)

# 加密单个 16 字节数据块
cipher_block = aes.encrypt_block(b'0123456789abcdef')

# 解密单个 16 字节数据块
plain_block = aes.decrypt_block(cipher_block)
```

### 3. ECB 工作模式 (`modes.py`)

实现了电子密码本 (ECB) 模式，支持：
- 自动 PKCS#7 填充
- 逐块加密/解密
- 适用于任意长度的数据

**使用方法：**
```python
from des import SimpleDES
from modes import ECB_Mode

# 创建加密器
des = SimpleDES(b'mykey123')
ecb_mode = ECB_Mode(des)

# 加密任意长度的数据
cipher_data = ecb_mode.encrypt(b'Hello, World! 你好世界！')

# 解密
plain_data = ecb_mode.decrypt(cipher_data)
```

### 4. 工具函数 (`tools.py`)

提供了常用的辅助功能：
- 字节与字符串的相互转换
- 字节与十六进制字符串的相互转换
- 文件读写操作
- PKCS#7 填充和去填充

---

## 📊 程序输出示例

运行 `python main.py` 后，你将看到类似以下的输出：

```
██████████████████████████████████████████████████████████████████████
█                                                                    █
█                 DES 和 AES 密码算法演示程序（ECB模式）               █
█                                                                    █
█                 功能：支持任意长度中英文文本的加密和解密              █
█                 工作模式：ECB (Electronic Codebook Mode)            █
█                                                                    █
██████████████████████████████████████████████████████████████████████

======================================================================
  第一部分：简单演示
======================================================================

原文: 密码学很有趣！Cryptography is fun!
密钥: 12345678
模式: ECB
密文(十六进制): a3f2b8c9d1e4...
解密结果: 密码学很有趣！Cryptography is fun!
✓ 简单演示成功！

... (更多详细的测试输出) ...

✓ DES-ECB 加解密成功！
✓ AES-ECB 文件加解密成功！
```

---

## ✅ 验证加解密结果

运行程序后，可以通过以下方式验证：

1. **对比文件内容**
   ```bash
   # Windows
   fc des_ecb_plain.txt des_ecb_decrypted.txt
   fc aes_ecb_plain.txt aes_ecb_decrypted.txt
   
   # Linux/Mac
   diff des_ecb_plain.txt des_ecb_decrypted.txt
   diff aes_ecb_plain.txt aes_ecb_decrypted.txt
   ```

2. **手动检查**
   - 打开 `*_plain.txt` 查看原始内容
   - 打开 `*_cipher.txt` 查看密文（十六进制乱码）
   - 打开 `*_decrypted.txt` 查看解密后的内容
   - 确认 `plain` 和 `decrypted` 文件内容完全一致

---

## 🎓 学习要点

### DES 算法特点
- **密钥长度**：64 位（实际有效 56 位，8 位用于奇偶校验）
- **块大小**：64 位（8 字节）
- **轮数**：16 轮
- **结构**：Feistel 网络

### AES-128 算法特点
- **密钥长度**：128 位（16 字节）
- **块大小**：128 位（16 字节）
- **轮数**：10 轮
- **结构**：SPN (Substitution-Permutation Network)

### ECB 模式特点
- ✅ 实现简单，易于理解
- ✅ 可以并行加密/解密
- ❌ 相同的明文块产生相同的密文块（安全性弱）
- ❌ 不适合加密有规律的数据

---

## ⚠️ 安全警告

1. **ECB 模式不安全**：相同的明文块会产生相同的密文块，容易受到模式分析攻击
2. **仅用于学习**：本项目旨在帮助理解密码算法原理，不应在生产环境中使用
3. **实际应用建议**：
   - 使用更安全的模式（如 CBC、CTR、GCM）
   - 使用经过审计的加密库（如 Python 的 `cryptography` 库）
   - 妥善管理密钥

---

## 📝 代码说明

### 关键算法实现

**DES 加密流程：**
```
明文 → IP置换 → 16轮Feistel变换 → IP⁻¹置换 → 密文
```

**AES 加密流程：**
```
明文 → AddRoundKey → 9轮(SubBytes+ShiftRows+MixColumns+AddRoundKey) 
     → 最后一轮(SubBytes+ShiftRows+AddRoundKey) → 密文
```

### PKCS#7 填充

当数据长度不是块大小的整数倍时，使用 PKCS#7 填充：
- 填充字节值 = 需要填充的字节数
- 例如：需要填充 3 字节，则添加 `0x03 0x03 0x03`
- 如果正好是整数倍，则添加一整块填充

---

## 🤝 贡献

欢迎提出问题和改进建议！如果你发现代码中的错误或有任何优化建议，请随时反馈。

---

## 📄 许可证

本项目仅供学习和研究使用。

---

## 📚 参考资料

- FIPS PUB 46-3: Data Encryption Standard (DES)
- FIPS PUB 197: Advanced Encryption Standard (AES)
- 《应用密码学手册》- Alfred J. Menezes 等

---

**祝你学习愉快！🎉**
