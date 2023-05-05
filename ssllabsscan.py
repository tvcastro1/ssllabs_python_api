#!/usr/bin/env python
import pandas as pd
import requests
import time
import sys
import logging

API = 'https://api.ssllabs.com/api/v3/'


def request_api(path, payload={}):

    url = API + path

    try:
        response = requests.get(url, params=payload)
    except requests.exception.RequestException:
        logging.exception('Request failed.')
        sys.exit(1)

    data = response.json()
    return data


def results_from_cache(host, publish='off', startNew='off', fromCache='on', all='done'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'startNew': startNew,
                'fromCache': fromCache,
                'all': all
              }
    data = request_api(path, payload)
    return data


def new_scan(host, publish='off', startNew='on', all='done', ignoreMismatch='on'):
    path = 'analyze'
    payload = {
                'host': host,
                'publish': publish,
                'startNew': startNew,
                'all': all,
                'ignoreMismatch': ignoreMismatch
              }
    results = request_api(path, payload)

    payload.pop('startNew')

    while results['status'] != 'READY' and results['status'] != 'ERROR':
        time.sleep(30)
        results = request_api(path, payload)

    return results

def extract_protocols_and_cipher_suites(results):
    extracted_tls_and_cipher_results = {}
    extracted_tls_and_cipher_results['host'] = results['host']
    for key,value in results['endpoints'][0].items():
        if key in ('ipAddress', 'grade'):
            extracted_tls_and_cipher_results[key] = value
        elif key == 'details':
            extracted_tls_and_cipher_results['tls'] = value['protocols']
            tls_versions = [protocol['version'] for protocol in extracted_tls_and_cipher_results['tls']]
            extracted_tls_and_cipher_results['tls'] = tls_versions

            extracted_tls_and_cipher_results['ciphers'] = value['suites']
            cipher_no = 1
            for value in extracted_tls_and_cipher_results['ciphers']:
                for cipher in value['list']:
                    extracted_tls_and_cipher_results[f'cipher_{cipher_no}'] = [cipher['name']]
                    if cipher.get('q') == 1:
                        extracted_tls_and_cipher_results[f'cipher_{cipher_no}'].append('cifra fraca')
                    elif cipher.get('q') == 0:
                        extracted_tls_and_cipher_results[f'cipher_{cipher_no}'].append('cifra insegura')
                    elif cipher.get('q') == None:
                        extracted_tls_and_cipher_results[f'cipher_{cipher_no}'].append('cifra forte ou boa')
                    cipher_no += 1 
            del extracted_tls_and_cipher_results['ciphers']   
    return extracted_tls_and_cipher_results
def extract_certs_info(results):
    pass
results_no_treatment = results_from_cache('site')
print(extract_protocols_and_cipher_suites(results_no_treatment))
