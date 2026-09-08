"""Generate README screenshots from captured CLI output."""

import re
from PIL import Image, ImageDraw, ImageFont


def render_terminal(text, accent_lines=None, title=None):
    accent_lines = accent_lines or []
    bg = (30, 30, 30)
    fg = (240, 240, 240)
    accent = (97, 214, 117)
    cyan = (78, 201, 176)
    green = (98, 214, 117)

    font_size = 15
    line_height = 22
    padding = 24

    try:
        font = ImageFont.truetype("DejaVuSansMono.ttf", font_size)
    except Exception:
        try:
            font = ImageFont.truetype("consola.ttf", font_size)
        except Exception:
            font = ImageFont.load_default()

    draw = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    lines = text.splitlines()

    # Prevent looping prompts or runaway output from creating huge images.
    display_lines = []
    max_width = 0
    for line in lines:
        display_line = line if len(line) <= 200 else line[:200]
        display_lines.append(display_line)
        bbox = draw.textbbox((0, 0), display_line, font=font)
        max_width = max(max_width, bbox[2] - bbox[0])

    width = max_width + padding * 2
    height = len(display_lines) * line_height + padding * 2

    title_font = font
    if title:
        try:
            title_font = ImageFont.truetype("DejaVuSansMono-Bold.ttf", font_size)
        except Exception:
            title_font = font
        bbox = draw.textbbox((0, 0), title, font=title_font)
        width = max(width, bbox[2] - bbox[0] + padding * 2)
        height += line_height + 8

    img = Image.new("RGB", (width, height), bg)
    draw = ImageDraw.Draw(img)

    y = padding
    if title:
        draw.text((padding, y), title, fill=cyan, font=title_font)
        y += line_height + 8

    for i, line in enumerate(display_lines):
        color = fg
        if i in accent_lines:
            color = accent
        elif line.startswith("INFO") or line.startswith("✅"):
            color = cyan
        elif line.startswith("#") or "HSCAN" in line or "COMPLETED" in line:
            color = green
        elif "Error" in line or "HONEYPOT" in line:
            color = (241, 76, 76)
        elif "Valid" in line or "Success" in line:
            color = green
        draw.text((padding, y), line, fill=color, font=font)
        y += line_height

    return img


def main():
    with open("scripts/.capture_banner.txt", encoding="utf-8") as f:
        banner_text = f.read()

    with open("scripts/.capture_help.txt", encoding="utf-8") as f:
        help_text = f.read()
        help_text = re.sub(r"Usage of .*hscan:", "Usage of ./hscan:", help_text)

    with open("scripts/.capture_summary.txt", encoding="utf-8") as f:
        summary_text = f.read()

    import os
    os.makedirs("assets", exist_ok=True)

    render_terminal(
        "\n".join(banner_text.splitlines()[:7]),
        title="$ ./hscan",
    ).save("assets/screenshot_banner.png")

    render_terminal(help_text, title="$ ./hscan -h").save("assets/screenshot_help.png")

    render_terminal(
        "\n".join(summary_text.splitlines()[-30:]),
        title="$ ./hscan targets.txt",
    ).save("assets/screenshot_summary.png")

    print("saved assets/screenshot_banner.png")
    print("saved assets/screenshot_help.png")
    print("saved assets/screenshot_summary.png")


if __name__ == "__main__":
    main()
