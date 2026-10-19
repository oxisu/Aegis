#!/usr/bin/env python3
"""生成 Aegis 的图标（盾牌，靛蓝→青渐变）。

⚠ 为什么用脚本生成而不是放一张位图进来：
   图标是**唯一一个每次构建都会被重写**的资源（tauri-build 要拿
   `icons/icon.ico` 生成 Windows 资源文件）。用脚本生成意味着想改配色时
   改的是**参数**，而不是去翻图形软件重画一遍——配置项和产物对得上。

用法：python make_icon.py   （产出落在同目录）
"""

import os
from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))

# 与 ui/src/styles/main.css 的 --accent / --accent-secondary 一致
ACCENT = (108, 140, 255)
ACCENT2 = (0, 212, 200)
SIZE = 512

# 盾形轮廓（归一化）：顶宽底尖，收腰在 0.52
SHIELD = [
    (0.50, 0.04),
    (0.91, 0.17),
    (0.91, 0.50),
    (0.50, 0.96),
    (0.09, 0.50),
    (0.09, 0.17),
]


def shield_points(size: int, inset: float = 0.0):
    """把归一化盾形缩放到像素坐标。

    ⚠ 不提供"以中心缩放"的挖空用法：盾形不对称（底尖、顶平），
    中心缩放会让内轮廓的顶点下陷，画出来是心形不是盾。
    描边一律用 ``outline + width``。
    """
    return [(x * size, y * size) for x, y in SHIELD]


def gradient(size: int) -> Image.Image:
    """左上（靛蓝）→ 右下（青）的线性渐变。"""
    g = Image.new("RGB", (size, size))
    px = g.load()
    for y in range(size):
        for x in range(size):
            t = (x + y) / (2 * size - 2)
            px[x, y] = (
                int(ACCENT[0] + (ACCENT2[0] - ACCENT[0]) * t),
                int(ACCENT[1] + (ACCENT2[1] - ACCENT[1]) * t),
                int(ACCENT[2] + (ACCENT2[2] - ACCENT[2]) * t),
            )
    return g


def render(size: int) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    # 1) 渐变只铺在盾形 mask 里
    mask = Image.new("L", (size, size), 0)
    ImageDraw.Draw(mask).polygon(shield_points(size), fill=255)
    img.paste(gradient(size), (0, 0), mask)

    # 2) 白描边画在渐变上面。宽度随尺寸缩放，16px 时也能看清一圈白边
    ImageDraw.Draw(img).polygon(
        shield_points(size), outline=(255, 255, 255, 255), width=max(2, size // 32)
    )
    return img


def main() -> None:
    base = render(SIZE)
    base.save(os.path.join(HERE, "icon.png"))

    # Windows 资源文件要 .ico，且要含多档尺寸（16 用于任务栏/标题栏）
    base.save(
        os.path.join(HERE, "icon.ico"),
        sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)],
    )

    for s in (32, 128, 256):
        base.resize((s, s), Image.LANCZOS).save(os.path.join(HERE, f"{s}x{s}.png"))
    base.resize((256, 256), Image.LANCZOS).save(os.path.join(HERE, "128x128@2x.png"))

    # MSIX / 应用商店要的那一套方形磁贴尺寸
    for name, s in (
        ("Square30x30Logo.png", 30),
        ("Square44x44Logo.png", 44),
        ("Square71x71Logo.png", 71),
        ("Square89x89Logo.png", 89),
        ("Square107x107Logo.png", 107),
        ("Square142x142Logo.png", 142),
        ("Square150x150Logo.png", 150),
        ("Square284x284Logo.png", 284),
        ("Square310x310Logo.png", 310),
        ("StoreLogo.png", 50),
    ):
        base.resize((s, s), Image.LANCZOS).save(os.path.join(HERE, name))

    print("图标已生成于", HERE)


if __name__ == "__main__":
    main()
