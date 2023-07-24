import json
import requests
import time
import hmac
import hashlib
import base64
import urllib.parse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


url_lists = [
    {
        'url': "https://10.10.10.150/prometheus",
        'host': 'home.liamlea.local'
    },
    {
        'url': "https://10.10.10.150/alertmanager",
        'host': "home.liamlea.local"
    }
    ]

def alert_dingtalk(webhook, key, failed_urls):
    timestamp = str(round(time.time() * 1000))
    secret = key
    secret_enc = secret.encode('utf-8')
    string_to_sign = '{}\n{}'.format(timestamp, secret)
    string_to_sign_enc = string_to_sign.encode('utf-8')
    hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    headers = {'Content-Type': 'application/json'}
    data = {
        'msgtype': 'text',
        'text': {
            'content': '以下url检测失败:\n\r' + '\n\r'.join(failed_urls)
        }
    }
    url="%s&timestamp=%s&sign=%s" %(webhook, timestamp, sign)
    response = requests.post(url,headers=headers,data=json.dumps(data))

def alert(failed_urls):
    alert_dingtalk("https://oapi.dingtalk.com/robot/send?access_token=09935dc01b6beccc3e485abcf7c8f4a74114630fd38a8db126efb612a46c3633",
                   "SEC2f054a2c5f2cda5801a3d25ead7c1b741b03f6638bf4a7980c6e05aa8746c13a",
                   failed_urls)

def url_probe(url_lists):
    failed_urls = []
    for url in url_lists:
        headers = {
            "Host": url['host']
        }

        try:
            response = requests.get(url['url'],headers=headers, verify=False)
            if response.status_code != 200:
                failed_urls.append(url['url'])
        except Exception:
            failed_urls.append(url['url'])
    if failed_urls:
        alert(failed_urls)

url_probe(url_lists)