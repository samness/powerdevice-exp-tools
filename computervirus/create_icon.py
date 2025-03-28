from PIL import Image, ImageDraw, ImageFont
import os
import subprocess

def create_icon():
    # 创建一个 1024x1024 的图像
    size = 1024
    image = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)
    
    # 绘制一个圆形背景
    margin = size // 10
    draw.ellipse([margin, margin, size-margin, size-margin], 
                 fill=(41, 128, 185, 255))
    
    # 绘制一个简单的 PLC 图标
    # 绘制矩形
    rect_margin = size // 4
    draw.rectangle([rect_margin, rect_margin, size-rect_margin, size-rect_margin], 
                  fill=(255, 255, 255, 255))
    
    # 绘制连接线
    line_width = size // 20
    draw.line([rect_margin, size//2, size-rect_margin, size//2], 
              fill=(41, 128, 185, 255), width=line_width)
    
    # 保存为 PNG
    image.save('app.png')
    
    # 创建 iconset 目录
    if os.path.exists('icon.iconset'):
        subprocess.run(['rm', '-rf', 'icon.iconset'])
    os.makedirs('icon.iconset')
    
    # 生成不同尺寸的图标
    sizes = [16, 32, 64, 128, 256, 512, 1024]
    
    for s in sizes:
        resized = image.resize((s, s), Image.Resampling.LANCZOS)
        resized.save(f'icon.iconset/icon_{s}x{s}.png')
        if s <= 512:
            resized.save(f'icon.iconset/icon_{s//2}x{s//2}@2x.png')
    
    # 转换为 ICNS
    subprocess.run(['iconutil', '-c', 'icns', 'icon.iconset'])
    
    # 重命名生成的 icns 文件
    if os.path.exists('icon.icns'):
        if os.path.exists('app.icns'):
            os.remove('app.icns')
        os.rename('icon.icns', 'app.icns')
    
    print("Icon created successfully!")

if __name__ == '__main__':
    create_icon() 