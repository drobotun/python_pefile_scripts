"""
Скрипт, выводящий информацию о дате и времени компиляции PE-файла.

Пример использования:

    python get_compilations_time.py d:/file.exe
"""

import sys
import time
import pefile

try:
    file_path = sys.argv[1]
except IndexError:
    print('Не указан файл.')
    sys.exit(0)
try:
    pe = pefile.PE(file_path)
except FileNotFoundError:
    print('Не удается найти указанный файл:', sys.argv[1])
    sys.exit(0)
except pefile.PEFormatError:
    print('Файл', sys.argv[1], 'не является PE файлом Windows.')
    sys.exit(0)
print('Дата и время компиляции:', time.strftime('%d-%m-%Y %H:%M:%S', time.gmtime(pe.FILE_HEADER.TimeDateStamp)))
