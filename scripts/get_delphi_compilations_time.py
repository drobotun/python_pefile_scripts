"""
Скрипт, выводящий информацию о дате и времени компиляции PE-файла.

Скрипт определяет дату и время компиляции PE-файлов, скомпилированных
компилятором Delphi, на основе времени и создания секции .rsrc.

Пример использования:

    python get_delphi_compilations_time.py d:/file.exe
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
time_stamp_dos = 0
if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
    time_stamp_dos = pe.DIRECTORY_ENTRY_RESOURCE.struct.TimeDateStamp
if time_stamp_dos != 0:
    day = time_stamp_dos >> 16 & 0x1f
    month = time_stamp_dos >> 21 & 0x7
    year = (time_stamp_dos >>  25 & 0xff) + 1980
    second = (time_stamp_dos & 0x1f) * 2
    minute = time_stamp_dos >> 5 & 0x3f
    hour = time_stamp_dos >> 11 & 0x1f
    print('Дата и время компиляции: {}-{}-{} {:02d}:{:02d}:{:02d}'.format(day, month, year, hour, minute, second))
else:
    print('Метка времени создания секции .rsrc отсутствует')
