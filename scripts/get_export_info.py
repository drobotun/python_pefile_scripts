"""
Скрипт, выводящий информацию о таблице экспорта PE-файла.

Для каждой экспортируемой функции выводит имя функции и ее RVA. Также выводит
общее количество экспортируемых функций.

Пример использования:

    python get_export_info.py d:/file.exe
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
print('Библиотека:', pe.DIRECTORY_ENTRY_EXPORT.name.decode('utf-8'))
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for export_entry in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        print('\t' + export_entry.name.decode('utf-8'))
        print('\t\tОрдинал:', str(hex(export_entry.ordinal)))
        print('\t\tRVA функции:', str(hex(export_entry.address)))
else:
    print('Файл', sys.argv[1], 'не содержит секцию экспорта.')
print('Всего экспортируется', len(pe.DIRECTORY_ENTRY_EXPORT.symbols), 'функций.')
