import requests, pem
#TO-DO:
#
#https request with verify function!
#
#
#
ROOT_PATH = 'http://127.0.0.1:8000/users/'

#download key from WKD
def get_keys(user,key):

    try:
        key_filename = './myWKD/cert.key'
        cert_filename = './myWKD/cert.crt'
        path = ROOT_PATH + user
        response = requests.get(path)
        #response = requests.get(path, cert=(cert_filename,key_filename))
        #print("response",response)
        response.raise_for_status()
    except requests.exceptions.HTTPError as http_err:
        raise ValueError(f'HTTP error occurred: {http_err}')  # Python 3.6
    except Exception as err:
        raise ValueError(f'Other error occurred: {err}')  # Python 3.6
    else:
        jtext = response.json()
        print(jtext)
        return jtext[key]

#upload key to WKD
def put_keys(user, fullname, public, encrypt):
    try:
        data = {'username':user,'fullname':fullname,'public_key':public,'encrypt_key':encrypt}
        path = ROOT_PATH
        print(data)
        response=requests.post(path, data=data)
        response.raise_for_status()

    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')  # Python 3.6
    except Exception as err:
        print(f'Other error occurred: {err}')  # Python 3.6


'''
#download key from WKD
try:
    ekey=get_keys('fuele95@gmail.com','encrypt_key')

    print(ekey,'\n')
except Exception as e:
    print(e)

#upload key to WKD
try:
    user='author@example.com'
    pkey = pem.parse_file(user + "/pk.pem")
    ekey = pem.parse_file(user+"/ek.pem")
    put_keys(user,'Author test',pkey.pop(),ekey.pop())
except Exception as e:
    print(e)
'''