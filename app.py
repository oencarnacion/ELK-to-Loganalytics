#!/usr/bin/env python3
from elasticsearch import Elasticsearch
from datetime import datetime, timedelta
import json
import requests
import hashlib
import hmac
import base64


# Configurar el cliente Elasticsearch con las credenciales
es = Elasticsearch(
    ['https://<URL>:9200'],
    http_auth=('USERNAME', 'PASSWORD!'),
    verify_certs=False
)

# Calcular la fecha y hora hace una hora
hora_anterior = datetime.utcnow() - timedelta(hours=24)

# Consulta para buscar documentos con http_status_code 403 generados en la última hora
fecha_actual = datetime.now().strftime("%Y.%m.%d")
nombre_indice = f"reblaze-{fecha_actual}"
resultado = es.search(index=nombre_indice, body={
    "query": {
        "bool": {
            "must": [
                { "match": { "http_status_code.keyword": "403" } }
            ],
            "filter": {
                "range": {
                    "@timestamp": {
                        "gte": hora_anterior.isoformat(),
                        "lte": "now"
                    }
                }
            }
        }
    }
})

# Imprimir los resultados
for hit in resultado['hits']['hits']:
    source = hit['_source']
    print(f"client_ip: {source['client_ip']}, error_message: {source['error_message']}, timestamp: {source['timestamp']}, country: {source['country']}, Full URL: {source['Full URL']}")

# Configurar el cliente de Log Analytics con las credenciales
workspace_id = "WORKSPACEID"
shared_key = "SHAREKEY"
log_type = "LOGTYPENAME"

# Crear una instancia de LogAnalyticsDataCollector
# Crear una lista de registros en formato JSON
json_records = []
for hit in resultado['hits']['hits']:
    source = hit['_source']
    json_records.append({
        'client_ip': source['client_ip'],
        'error_message': source['error_message'],
        'timestamp': source['timestamp'],
        'country': source['country'],
        'Full URL': source['Full URL']
    })

# Convertir los registros en una cadena JSON
json_data = json.dumps(json_records)

# Calcular la fecha y hora actual en formato ISO 8601
datestring = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')


# Generar la firma de autorización
content_length = len(json_data)
string_to_sign = bytes('POST\n{}\napplication/json\nx-ms-date:{}\n/api/logs'.format(content_length, datestring), encoding='utf-8')
signature = base64.b64encode(hmac.new(base64.b64decode(shared_key), string_to_sign, digestmod=hashlib.sha256).digest()).decode()

# print(json_data)
# Imprimir la cadena de firma
# print("Cadena de firma: {}".format(string_to_sign))

# Imprimir la firma de autorización
# print("Firma de autorización: {}".format(signature))

# Configurar los encabezados de la solicitud
headers = {
    'Content-Type': 'application/json',
    'Authorization': 'SharedKey {}:{}'.format(workspace_id, signature),
    'Log-Type': log_type,
    'x-ms-date': datestring,
    'time-generated-field': 'timestamp'
}

# Enviar los registros a Log Analytics
response = requests.post('https://{}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01'.format(workspace_id), data=json_data, headers=headers)
print(response.content.decode())

# Comprobar si la solicitud de envío se completó correctamente
if response.status_code == 200:
    print('Registros enviados correctamente a Log Analytics')
else:
    print('Error al enviar registros a Log Analytics')
