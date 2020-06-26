"""
Скрипт, выводящий информацию о таблице импорта PE-файла.

Для каждой подключаемой dll-библиотеки выводит имя библиотеки и перечень
импортируемых функций. Также выводит значение imphash.

Пример использования:

    python get_import_info.py d:/file.exe
"""

import sys
import pefile

try:
    file_path = sys.argv[1]
except IndexError:
    print('Не указан файл.')
    sys.exit(0)
except FileNotFoundError:
    print('Не удается найти указанный файл:', sys.argv[1])
    sys.exit(0)
try:
    pe = pefile.PE(file_path)
except pefile.PEFormatError:
    print('Файл', sys.argv[1], 'не является PE файлом Windows.')
    sys.exit(0)
if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
    for dll_entry in pe.DIRECTORY_ENTRY_IMPORT:
        print(dll_entry.dll.decode('utf-8'))
        for api_entry in dll_entry.imports:
            print('\t' + api_entry.name.decode('utf-8'))
    print('Imphash = ', pe.get_imphash())
else:
    print('Файл', sys.argv[1], 'не содержит секцию импорта.')
