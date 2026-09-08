#!/usr/bin/env python3
"""
网易易盾 DEX 加密/解密工具
============================
对网易易盾(NetEase Yidun)保护的 classes.dex 文件进行加密和解密。

算法原理:
  - 条件XOR加密（跳过零字节和等于密钥的字节）
  - 每1024字节(0x400)更换一次密钥，共4个块 = 4096字节(0x1000)
  - 仅加密前4096字节，其余为明文

密钥派生（来自 .ntp.dex）:
  - 偏移0:   密钥递增量 = 2
  - 偏移4:   基础密钥字节 = 0x4e ('N'，密钥字符串首字节)
  - 偏移8:   密钥加数 = 3
  - 初始密钥 = (基础字节 + 加数) & 0xff = (0x4e + 3) = 0x51
  - 密钥[i] = (初始密钥 + i * 递增量) & 0xff
  - 密钥序列: 0x51, 0x53, 0x55, 0x57

验证机制:
  - Adler32 校验和（偏移0x08）: 校验通过
  - SHA-1 签名（偏移0x0C）: 校验通过
  - DEX 魔数: "dex\\n038\\x00"（DEX版本38）

用法:
  解密: python3 dex_crypto_tool.py decrypt <加密的dex路径> <输出路径> [<ntp_dex路径>]
  加密: python3 dex_crypto_tool.py encrypt <明文dex路径> <输出路径> [<ntp_dex路径>]

示例:
  解密: python3 dex_crypto_tool.py decrypt .unzip/classes.dex classes_decrypted.dex .ntp.dex
  加密: python3 dex_crypto_tool.py encrypt classes_decrypted.dex classes_encrypted.dex .ntp.dex
"""
import struct
import zlib
import hashlib
import sys
import os

# ============================================================
# 常量定义
# ============================================================

DEX_MAGIC = b'dex\n038\x00'          # DEX文件魔数（版本38）
HEADER_SIZE = 0x70                    # DEX头部大小
ENCRYPTED_REGION_SIZE = 0x1000        # 加密区域大小（4096字节）
BLOCK_SIZE = 0x400                    # 每个密钥块大小（1024字节）
NUM_BLOCKS = 4                        # 密钥块数量

# 默认密钥序列（当没有.ntp.dex文件时使用）
DEFAULT_KEYS = [0x51, 0x53, 0x55, 0x57]

# ============================================================
# 核心算法：条件XOR
# ============================================================

def 条件XOR(数据, 密钥):
    """条件XOR运算：跳过零字节和等于密钥的字节。

    对每个字节b和密钥k：
      - 如果 b == 0:   保持不变（跳过）
      - 如果 b == k:   保持不变（跳过）
      - 否则:          b = b XOR k

    由于XOR的对称性，此函数同时用于加密和解密。
    """
    结果 = bytearray(len(数据))
    for i, b in enumerate(数据):
        if b == 0 or b == 密钥:
            结果[i] = b       # 跳过，保持原样
        else:
            结果[i] = b ^ 密钥 # XOR运算
    return bytes(结果)


def 派生密钥(ntp数据):
    """从 .ntp.dex 文件内容派生XOR密钥序列。

    .ntp.dex 文件结构：
      偏移 0-3:   密钥递增量 (uint32 小端序)
      偏移 4-7:   基础密钥字节 (密钥字符串首字节, uint32 小端序)
      偏移 8-11:  密钥加数 (uint32 小端序)
      偏移 12+:   密钥字符串 + libminecraftpe.so 引用

    返回: 密钥列表，如 [0x51, 0x53, 0x55, 0x57]
    """
    递增量 = struct.unpack('<I', ntp数据[0:4])[0]
    基础字节 = struct.unpack('<I', ntp数据[4:8])[0] & 0xff
    加数 = struct.unpack('<I', ntp数据[8:12])[0]

    初始密钥 = (基础字节 + 加数) & 0xff

    密钥列表 = [(初始密钥 + i * 递增量) & 0xff for i in range(NUM_BLOCKS)]
    return 密钥列表


def 生成ntp文件(递增量=2, 基础字节=0x4e, 加数=3, 密钥字符串=b"Njl90NRIQLJHWHs9nGN44pxJthHWwHue", so引用=b"libminecraftpe.so"):
    """生成 .ntp.dex 密钥文件。

    参数:
      递增量:     密钥递增步长（默认2）
      基础字节:   密钥派生基础字节（默认0x4e = 'N'）
      加数:       密钥加数（默认3）
      密钥字符串: 32字节密钥字符串
      so引用:    引用的SO库名

    返回: .ntp.dex 文件内容（bytes）
    """
    数据 = bytearray()
    数据.extend(struct.pack('<I', 递增量))      # 偏移0: 递增量
    数据.extend(struct.pack('<I', 基础字节))     # 偏移4: 基础字节
    数据.extend(struct.pack('<I', 加数))        # 偏移8: 加数
    数据.extend(密钥字符串)                      # 偏移12: 密钥字符串
    数据.extend(so引用)                          # SO引用
    数据.extend(b'\x00' * (4 - len(so引用) % 4) if len(so引用) % 4 else b'')  # 对齐
    return bytes(数据)

# ============================================================
# DEX 校验函数
# ============================================================

def 校验DEX(dex数据, 详细=False):
    """校验DEX文件的完整性和有效性。

    检查项:
      1. 魔数 (dex\\n038\\x00)
      2. Adler32 校验和
      3. SHA-1 签名
      4. 文件大小字段
      5. DEX头部各区域结构

    返回: (是否通过, 校验信息字典)
    """
    信息 = {}

    # 1. 魔数检查
    魔数 = dex数据[:8]
    信息['魔数'] = 魔数
    魔数通过 = 魔数 == DEX_MAGIC

    # 2. Adler32 校验和
    存储校验和 = struct.unpack('<I', dex数据[0x08:0x0c])[0]
    计算校验和 = zlib.adler32(dex数据[0x0c:])
    信息['adler32_存储'] = 存储校验和
    信息['adler32_计算'] = 计算校验和
    校验和通过 = 存储校验和 == 计算校验和

    # 3. SHA-1 签名
    存储sha1 = dex数据[0x0c:0x20]
    计算sha1 = hashlib.sha1(dex数据[0x20:]).digest()
    信息['sha1_存储'] = 存储sha1.hex()
    信息['sha1_计算'] = 计算sha1.hex()
    sha1通过 = 存储sha1 == 计算sha1

    # 4. 文件大小
    文件大小 = struct.unpack('<I', dex数据[0x20:0x24])[0]
    信息['文件大小字段'] = 文件大小
    信息['实际大小'] = len(dex数据)
    大小通过 = 文件大小 == len(dex数据)

    # 5. 头部大小
    头部大小 = struct.unpack('<I', dex数据[0x24:0x28])[0]
    信息['头部大小'] = 头部大小

    # 6. 端序标记
    端序标记 = struct.unpack('<I', dex数据[0x28:0x2c])[0]
    信息['端序标记'] = 端序标记

    # 7. DEX 结构区域
    信息['string_ids'] = {
        '数量': struct.unpack('<I', dex数据[0x38:0x3c])[0],
        '偏移': struct.unpack('<I', dex数据[0x3c:0x40])[0]
    }
    信息['type_ids'] = {
        '数量': struct.unpack('<I', dex数据[0x40:0x44])[0],
        '偏移': struct.unpack('<I', dex数据[0x44:0x48])[0]
    }
    信息['proto_ids'] = {
        '数量': struct.unpack('<I', dex数据[0x48:0x4c])[0],
        '偏移': struct.unpack('<I', dex数据[0x4c:0x50])[0]
    }
    信息['field_ids'] = {
        '数量': struct.unpack('<I', dex数据[0x50:0x54])[0],
        '偏移': struct.unpack('<I', dex数据[0x54:0x58])[0]
    }
    信息['method_ids'] = {
        '数量': struct.unpack('<I', dex数据[0x58:0x5c])[0],
        '偏移': struct.unpack('<I', dex数据[0x5c:0x60])[0]
    }
    信息['class_defs'] = {
        '数量': struct.unpack('<I', dex数据[0x60:0x64])[0],
        '偏移': struct.unpack('<I', dex数据[0x64:0x68])[0]
    }
    信息['data'] = {
        '大小': struct.unpack('<I', dex数据[0x68:0x6c])[0],
        '偏移': struct.unpack('<I', dex数据[0x6c:0x70])[0]
    }
    信息['map_off'] = struct.unpack('<I', dex数据[0x34:0x38])[0]

    全部通过 = 魔数通过 and 校验和通过 and sha1通过 and 大小通过
    信息['全部通过'] = 全部通过

    if 详细:
        print(f"\n{'='*50}")
        print(f"DEX 文件校验")
        print(f"{'='*50}")
        print(f"  魔数:       {魔数} {'✓' if 魔数通过 else '✗ 失败'}")
        print(f"  文件大小:   {文件大小} {'✓' if 大小通过 else '✗ 失败'} (实际: {len(dex数据)})")
        print(f"  头部大小:   0x{头部大小:x}")
        print(f"  端序标记:   0x{端序标记:08x}")
        print(f"  Adler32:    0x{存储校验和:08x} vs 0x{计算校验和:08x} {'✓' if 校验和通过 else '✗ 失败'}")
        print(f"  SHA-1:      {存储sha1.hex()}")
        print(f"        vs    {计算sha1.hex()} {'✓' if sha1通过 else '✗ 失败'}")
        print(f"  ─────────────────────────────────")
        print(f"  string_ids:  数量={信息['string_ids']['数量']}, 偏移=0x{信息['string_ids']['偏移']:x}")
        print(f"  type_ids:    数量={信息['type_ids']['数量']}, 偏移=0x{信息['type_ids']['偏移']:x}")
        print(f"  proto_ids:   数量={信息['proto_ids']['数量']}, 偏移=0x{信息['proto_ids']['偏移']:x}")
        print(f"  field_ids:   数量={信息['field_ids']['数量']}, 偏移=0x{信息['field_ids']['偏移']:x}")
        print(f"  method_ids:  数量={信息['method_ids']['数量']}, 偏移=0x{信息['method_ids']['偏移']:x}")
        print(f"  class_defs:  数量={信息['class_defs']['数量']}, 偏移=0x{信息['class_defs']['偏移']:x}")
        print(f"  data:        大小={信息['data']['大小']}, 偏移=0x{信息['data']['偏移']:x}")
        print(f"  map_off:     0x{信息['map_off']:x}")
        print(f"{'='*50}")

    return 全部通过, 信息

# ============================================================
# 加密/解密核心函数
# ============================================================

def 处理DEX(输入路径, 输出路径, ntp路径=None, 模式="解密"):
    """对DEX文件进行加密或解密处理。

    由于条件XOR的对称性，加密和解密使用相同的运算逻辑。
    区别仅在于：加密时输入为明文DEX，解密时输入为加密DEX。

    参数:
      输入路径: 输入DEX文件路径
      输出路径: 输出DEX文件路径
      ntp路径:  .ntp.dex密钥文件路径（可选）
      模式:     "加密" 或 "解密"

    返回: True表示成功，False表示失败
    """
    # 读取输入文件
    with open(输入路径, "rb") as f:
        dex数据 = f.read()

    print(f"\n{'━'*60}")
    print(f"  网易易盾 DEX {模式}工具")
    print(f"{'━'*60}")
    print(f"  输入文件: {输入路径}")
    print(f"  输出文件: {输出路径}")
    print(f"  文件大小: {len(dex数据):,} 字节 (0x{len(dex数据):x})")

    # 派生密钥
    if ntp路径 and os.path.exists(ntp路径):
        with open(ntp路径, "rb") as f:
            ntp数据 = f.read()

        密钥列表 = 派生密钥(ntp数据)
        递增量 = struct.unpack('<I', ntp数据[0:4])[0]
        基础字节 = struct.unpack('<I', ntp数据[4:8])[0] & 0xff
        加数 = struct.unpack('<I', ntp数据[8:12])[0]

        print(f"\n  密钥派生（来源: {ntp路径}）:")
        print(f"    递增量:   {递增量}")
        print(f"    基础字节: 0x{基础字节:02x} ('{chr(基础字节)}')")
        print(f"    加数:     {加数}")
        print(f"    初始密钥: 0x{(基础字节 + 加数) & 0xff:02x}")
    else:
        密钥列表 = DEFAULT_KEYS
        print(f"\n  使用默认密钥序列: {', '.join([hex(k) for k in 密钥列表])}")

    print(f"  密钥序列: {', '.join([f'0x{k:02x}' for k in 密钥列表])}")
    print(f"  块大小:   {BLOCK_SIZE} 字节 (0x{BLOCK_SIZE:x})")
    print(f"  块数量:   {NUM_BLOCKS}")
    print(f"  加密区域: 0x0000 - 0x{ENCRYPTED_REGION_SIZE:x} ({ENCRYPTED_REGION_SIZE} 字节)")

    # 对前4096字节执行条件XOR处理
    处理结果 = bytearray()

    for 块索引 in range(NUM_BLOCKS):
        起始 = 块索引 * BLOCK_SIZE
        结束 = 起始 + BLOCK_SIZE
        块数据 = dex数据[起始:结束]
        处理块 = 条件XOR(块数据, 密钥列表[块索引])
        处理结果.extend(处理块)

        # 统计本块处理情况
        零字节数 = sum(1 for b in 块数据 if b == 0)
        等于密钥数 = sum(1 for b in 块数据 if b == 密钥列表[块索引])
        实际处理数 = BLOCK_SIZE - 零字节数 - 等于密钥数
        print(f"    块{块索引} (0x{起始:03x}-0x{结束-1:03x}): 密钥=0x{密钥列表[块索引]:02x} "
              f"零字节={零字节数} 等于密钥={等于密钥数} 实际XOR={实际处理数}")

    # 追加明文区域（4096字节之后的部分不变）
    处理结果.extend(dex数据[ENCRYPTED_REGION_SIZE:])
    处理结果 = bytes(处理结果)

    print(f"\n  输出大小: {len(处理结果):,} 字节 (0x{len(处理结果):x})")

    # 校验
    if 模式 == "解密":
        通过, 信息 = 校验DEX(处理结果, 详细=True)
        if 通过:
            print(f"\n  ★ {模式}成功！校验全部通过 ✓")
        else:
            print(f"\n  ✗ {模式}失败！校验未通过")
            print(f"    魔数: {处理结果[:8]}")
            return False
    else:
        # 加密模式：验证解密后能恢复原始数据
        验证结果 = bytearray()
        for 块索引 in range(NUM_BLOCKS):
            起始 = 块索引 * BLOCK_SIZE
            结束 = 起始 + BLOCK_SIZE
            块数据 = 处理结果[起始:结束]
            验证块 = 条件XOR(块数据, 密钥列表[块索引])
            验证结果.extend(验证块)
        验证结果.extend(处理结果[ENCRYPTED_REGION_SIZE:])

        if 验证结果 == dex数据:
            print(f"\n  ★ {模式}成功！往返验证通过 ✓")
            通过, 信息 = 校验DEX(dex数据, 详细=True)
            if 通过:
                print(f"  原始DEX校验: 全部通过 ✓")
            else:
                print(f"  警告: 原始DEX校验未通过（不影响加密）")
        else:
            print(f"\n  ✗ {模式}失败！往返验证未通过")
            return False

    # 写入输出文件
    with open(输出路径, "wb") as f:
        f.write(处理结果)
    print(f"\n  已保存到: {输出路径}")

    return True


def 解密DEX(加密路径, 输出路径, ntp路径=None):
    """解密网易易盾保护的DEX文件。

    将加密的classes.dex还原为可被Android加载的标准DEX文件。
    """
    return 处理DEX(加密路径, 输出路径, ntp路径, 模式="解密")


def 加密DEX(明文路径, 输出路径, ntp路径=None):
    """加密DEX文件（网易易盾格式）。

    将标准DEX文件加密为网易易盾保护格式。
    仅加密前4096字节，其余保持明文。

    注意：加密后的DEX无法被Android直接加载，
    需要通过易盾的解密流程才能还原。
    """
    return 处理DEX(明文路径, 输出路径, ntp路径, 模式="加密")

# ============================================================
# 生成 .ntp.dex 密钥文件
# ============================================================

def 生成ntp(输出路径, 递增量=2, 基础字节=0x4e, 加数=3,
           密钥字符串=b"Njl90NRIQLJHWHs9nGN44pxJthHWwHue",
           so引用=b"libminecraftpe.so"):
    """生成 .ntp.dex 密钥文件。

    可用于自定义密钥参数，生成新的密钥文件。

    参数:
      输出路径:    .ntp.dex 输出文件路径
      递增量:      密钥递增步长（默认2）
      基础字节:    密钥派生基础字节（默认0x4e = 'N'）
      加数:        密钥加数（默认3）
      密钥字符串:  32字节密钥字符串
      so引用:     引用的SO库名
    """
    ntp数据 = 生成ntp文件(递增量, 基础字节, 加数, 密钥字符串, so引用)

    初始密钥 = (基础字节 + 加数) & 0xff
    密钥列表 = [(初始密钥 + i * 递增量) & 0xff for i in range(NUM_BLOCKS)]

    print(f"\n{'━'*60}")
    print(f"  生成 .ntp.dex 密钥文件")
    print(f"{'━'*60}")
    print(f"  输出路径:   {输出路径}")
    print(f"  递增量:     {递增量}")
    print(f"  基础字节:   0x{基础字节:02x} ('{chr(基础字节)}')")
    print(f"  加数:       {加数}")
    print(f"  初始密钥:   0x{初始密钥:02x}")
    print(f"  密钥序列:   {', '.join([f'0x{k:02x}' for k in 密钥列表])}")
    print(f"  密钥字符串: {密钥字符串.decode('ascii', errors='replace')}")
    print(f"  SO引用:    {so引用.decode('ascii', errors='replace')}")
    print(f"  文件大小:   {len(ntp数据)} 字节")

    with open(输出路径, "wb") as f:
        f.write(ntp数据)
    print(f"\n  ★ 密钥文件生成成功！已保存到: {输出路径}")
    return True

# ============================================================
# 命令行界面
# ============================================================

def 打印帮助():
    """打印使用帮助。"""
    print("""
╔══════════════════════════════════════════════════════════╗
║          网易易盾 DEX 加密/解密工具                       ║
╚══════════════════════════════════════════════════════════╝

用法:
  python3 dex_crypto_tool.py <命令> [参数]

命令:
  decrypt  解密DEX文件（加密DEX → 明文DEX）
  encrypt  加密DEX文件（明文DEX → 加密DEX）
  genkey   生成 .ntp.dex 密钥文件
  verify   校验DEX文件完整性
  help     显示此帮助信息

解密命令:
  python3 dex_crypto_tool.py decrypt <加密dex> <输出dex> [<ntp.dex>]

  示例:
    python3 dex_crypto_tool.py decrypt .unzip/classes.dex output.dex .ntp.dex
    python3 dex_crypto_tool.py decrypt encrypted.dex decrypted.dex

加密命令:
  python3 dex_crypto_tool.py encrypt <明文dex> <输出dex> [<ntp.dex>]

  示例:
    python3 dex_crypto_tool.py encrypt classes.dex encrypted.dex .ntp.dex
    python3 dex_crypto_tool.py encrypt original.dex protected.dex

生成密钥命令:
  python3 dex_crypto_tool.py genkey <输出路径> [选项]

  选项:
    --increment <值>    密钥递增量（默认: 2）
    --base <值>         基础密钥字节（默认: 0x4e）
    --addend <值>       密钥加数（默认: 3）
    --keystr <字符串>   32字节密钥字符串
    --soref <字符串>    SO库引用名

  示例:
    python3 dex_crypto_tool.py genkey .ntp.dex
    python3 dex_crypto_tool.py genkey custom.ntp.dex --increment 4 --base 0x41

校验命令:
  python3 dex_crypto_tool.py verify <dex文件>

算法说明:
  ┌─────────────────────────────────────────────────────┐
  │ 加密区域: DEX前4096字节（4个1024字节块）            │
  │ 明文区域: 4096字节之后全部为明文                     │
  │                                                     │
  │ 条件XOR:                                             │
  │   if (byte == 0 || byte == key):  保持不变           │
  │   else:                           byte ^= key       │
  │                                                     │
  │ 密钥序列: 0x51, 0x53, 0x55, 0x57                    │
  │   初始密钥 = (基础字节 + 加数) & 0xFF               │
  │   密钥[i] = (初始密钥 + i × 递增量) & 0xFF          │
  └─────────────────────────────────────────────────────┘
""")


def 解析整数参数(值, 默认值):
    """解析整数参数（支持十进制和十六进制）。"""
    try:
        if 值.lower().startswith('0x'):
            return int(值, 16)
        return int(值)
    except ValueError:
        print(f"  警告: 无法解析 '{值}'，使用默认值 {默认值}")
        return 默认值


def 主函数():
    """命令行入口函数。"""
    if len(sys.argv) < 2:
        打印帮助()
        sys.exit(1)

    命令 = sys.argv[1].lower()
    参数 = sys.argv[2:]

    if 命令 == "decrypt" or 命令 == "解密":
        if len(参数) < 2:
            print("用法: python3 dex_crypto_tool.py decrypt <加密dex> <输出dex> [<ntp.dex>]")
            sys.exit(1)
        加密路径 = 参数[0]
        输出路径 = 参数[1]
        ntp路径 = 参数[2] if len(参数) > 2 else None
        成功 = 解密DEX(加密路径, 输出路径, ntp路径)
        sys.exit(0 if 成功 else 1)

    elif 命令 == "encrypt" or 命令 == "加密":
        if len(参数) < 2:
            print("用法: python3 dex_crypto_tool.py encrypt <明文dex> <输出dex> [<ntp.dex>]")
            sys.exit(1)
        明文路径 = 参数[0]
        输出路径 = 参数[1]
        ntp路径 = 参数[2] if len(参数) > 2 else None
        成功 = 加密DEX(明文路径, 输出路径, ntp路径)
        sys.exit(0 if 成功 else 1)

    elif 命令 == "genkey" or 命令 == "生成密钥":
        if len(参数) < 1:
            print("用法: python3 dex_crypto_tool.py genkey <输出路径> [选项]")
            sys.exit(1)
        输出路径 = 参数[0]
        递增量 = 2
        基础字节 = 0x4e
        加数 = 3
        密钥字符串 = b"Njl90NRIQLJHWHs9nGN44pxJthHWwHue"
        so引用 = b"libminecraftpe.so"

        i = 1
        while i < len(参数):
            if 参数[i] == "--increment" and i + 1 < len(参数):
                递增量 = 解析整数参数(参数[i+1], 递增量)
                i += 2
            elif 参数[i] == "--base" and i + 1 < len(参数):
                基础字节 = 解析整数参数(参数[i+1], 基础字节) & 0xff
                i += 2
            elif 参数[i] == "--addend" and i + 1 < len(参数):
                加数 = 解析整数参数(参数[i+1], 加数)
                i += 2
            elif 参数[i] == "--keystr" and i + 1 < len(参数):
                密钥字符串 = 参数[i+1].encode('ascii')
                i += 2
            elif 参数[i] == "--soref" and i + 1 < len(参数):
                so引用 = 参数[i+1].encode('ascii')
                i += 2
            else:
                i += 1

        生成ntp(输出路径, 递增量, 基础字节, 加数, 密钥字符串, so引用)

    elif 命令 == "verify" or 命令 == "校验":
        if len(参数) < 1:
            print("用法: python3 dex_crypto_tool.py verify <dex文件>")
            sys.exit(1)
        with open(参数[0], "rb") as f:
            dex数据 = f.read()
        通过, 信息 = 校验DEX(dex数据, 详细=True)
        sys.exit(0 if 通过 else 1)

    elif 命令 == "help" or 命令 == "帮助" or 命令 == "-h" or 命令 == "--help":
        打印帮助()

    else:
        print(f"未知命令: {命令}")
        打印帮助()
        sys.exit(1)


if __name__ == "__main__":
    主函数()
