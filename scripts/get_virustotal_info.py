"""
Скрипт, отправляющий хэш-сумму файла для проверки на VirusTotal.

Для работы необходим ключ доступа к API сервиса VirusTotal. Ключ можно получить
после регистрации на VirusTotal. Для корректной работы скрипта ключ необходимо
прописать в переменную среды VT_API_KEY. В качестве параметра скрипту передается
md5, sha1 или sha256 хэш файла, который необходимо отправить.

Пример использования:

    python get_virustotal_info.py 44d88612fea8a8f36de82e1278abb02f
"""

import sys
import os
import requests

if 'VT_API_KEY' in os.environ:
    vt_api_key = os.environ['VT_API_KEY']
else:
    print('Не задан ключ доступа к API VirusTotal.')
    sys.exit(0)
api_url = 'https://www.virustotal.com/vtapi/v2/file/report'
try:
    params = dict(apikey=vt_api_key, resource=str(sys.argv[1]))
except IndexError:
    print('Неверные аргументы.')
    sys.exit(0)
response = requests.get(api_url, params=params)
if response.status_code == 200:
    result=response.json()
    if result['response_code'] == 1:
        print('Обнаружено:', result['positives'], '/', result['total'])
        print('Результаты сканирования:')
        for key in result['scans']:
            print('\t' + key, '==>', result['scans'][key]['result'])
    elif result['response_code'] == -2:
        print('Запрашиваемый объект находится в очереди на анализ.')
    elif result['response_code'] == 0:
        print('Запрашиваемый объект отсутствует в базе VirusTotal.')
    else:
        print('Ошибка ответа VirusTotal.')
elif response.status_code == 204:
    print('Превышено максимально допустимое количество запросов.')
elif response.status_code == 400:
    print('Неверный формат запроса.')
elif response.status_code == 403:
    print('Неверный ключ доступа к API VirusTotal.')
else:
    print('Ошибка ответа VirusTotal.')
