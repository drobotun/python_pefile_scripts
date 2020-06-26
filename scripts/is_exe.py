"""
Скрипт, определяющий наличие признаков PE-файла.

Ищет в файле сигнатуры "MZ" и "PE", а также анализируя поле 'magic' из Otional
header, определяет тип PE-файла (PE32 или PE64).

Пример использования:

    python is_exe.py d:/file.exe
"""

import sys

__BUFFER_SIZE = 1000
try:
    file_path = sys.argv[1]
    with open(file_path, 'rb') as file:
        buffer = file.read(__BUFFER_SIZE)
except IndexError:
    print('Не указан файл.')
    sys.exit(0)
except FileNotFoundError:
    print('Не удается найти указанный файл:', sys.argv[1])
    sys.exit(0)
e_ifanew = int.from_bytes(buffer[0x3c:0x40], byteorder='little')
mz_signature = buffer[0x0:0x2]
pe_signature = buffer[e_ifanew:e_ifanew + 0x4]
magic = buffer[e_ifanew + 0x18:e_ifanew + 0x1a]
if mz_signature == b'MZ' and pe_signature == b'PE\x00\x00':
    if magic == b'\x0b\x01':
        print('Файл', sys.argv[1], 'является исполнимым PE32 файлом Windows.')
    elif magic == b'\x0b\x02':
        print('Файл', sys.argv[1], 'является исполнимым PE64 файлом Windows.')
    elif magic == b'\x07\x01':
        print('Файл', sys.argv[1], 'является ROM-образом.')
else:
    print('Файл', sys.argv[1],'не является PE файлом Windows.')
