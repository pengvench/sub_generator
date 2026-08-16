# -*- coding: utf-8 -*-
"""Генерация иконки SubGenerator.ico."""
from PIL import Image, ImageDraw, ImageFont

SIZE = 256
ICON_PATH = "icon.ico"


def make_icon() -> None:
    img = Image.new("RGBA", (SIZE, SIZE), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Тёмно-синий скруглённый фон
    radius = 48
    draw.rounded_rectangle(
        [8, 8, SIZE - 8, SIZE - 8],
        radius=radius,
        fill=(30, 41, 59, 255),  # slate-800
    )

    # Градиентная рамка (имитация) — светлая линия
    draw.rounded_rectangle(
        [16, 16, SIZE - 16, SIZE - 16],
        radius=radius - 8,
        outline=(56, 189, 248, 255),  # sky-400
        width=6,
    )

    # Буква "S"
    try:
        font = ImageFont.truetype("arialbd.ttf", 150)
    except OSError:
        font = ImageFont.load_default()

    text = "S"
    bbox = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (SIZE - tw) // 2 - bbox[0]
    y = (SIZE - th) // 2 - bbox[1] + 8

    # Тень буквы
    draw.text((x + 4, y + 4), text, font=font, fill=(14, 165, 233, 255))
    # Основная буква
    draw.text((x, y), text, font=font, fill=(224, 242, 254, 255))

    # Сохранить в нескольких размерах для .ico
    img.save(ICON_PATH, format="ICO", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"Иконка сохранена: {ICON_PATH}")


if __name__ == "__main__":
    make_icon()
