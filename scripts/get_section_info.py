"""
Скрипт, выводящий информацию о секциях PE-файла.

Для каждой, содержащейся в файле, секции выводит:
    - имя секции;
    - значение атрибута 'Characteristics';
    - md5-хэш секции;
    - значение энтропии секции.

Пример использования:

    python get_section_info.py d:/file.exe
"""

import sys
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
for section_entry in pe.sections:
    print(section_entry.Name.decode('utf-8'))
    print('\tCharacteristics:', hex(section_entry.Characteristics))
    print('\tMD5 хэш секции:', section_entry.get_hash_md5())
    print('\tЭнтропия секции:', section_entry.get_entropy())
