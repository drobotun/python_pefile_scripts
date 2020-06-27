"""
Скрипт, выводящий информацию о дате и времени компиляции PE-файла.

Скрипт определяет дату и время компиляции PE-файлов с включенной в них
отладочной информацией, скомпилированных компилятором Visual Studio, на основе
времени и создания таблицы Debug Directory.

Пример использования:

    python get_debug_compilations_time.py d:/file.exe
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
time_stamp = 0
if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
    time_stamp = pe.DIRECTORY_ENTRY_DEBUG[0].struct.TimeDateStamp
if time_stamp != 0:
    print('Дата и время компиляции:', time.strftime('%d-%m-%Y %H:%M:%S', time.gmtime(time_stamp)))
else:
    print('Метка времени создания Debug Directory отсутствует')