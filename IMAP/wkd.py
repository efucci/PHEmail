import requests
#TO-DO:
#
#https request with verify function!
#
#
#
ROOT_PATH = 'http://127.0.0.1:8000/users/'

#download key from WKD
def get_key(user):

    try:
        key_filename = '../myWKD/cert.key'
        cert_filename = '../myWKD/cert.crt'
        path = ROOT_PATH + user
        response = requests.get(path)
        #response = requests.get(path, cert=(cert_filename,key_filename))
        response.raise_for_status()
    except requests.exceptions.HTTPError as http_err:
        raise ValueError(f'HTTP error occurred: {http_err}')  # Python 3.6
    except Exception as err:
        raise ValueError(f'Other error occurred: {err}')  # Python 3.6
    else:
        jtext = response.json()
        return jtext['public_key']

