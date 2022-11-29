import json
import re
from xml.dom.minidom import parseString

from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.clickjacking import xframe_options_sameorigin
from shodan import Shodan
import requests
# Create your views here.

from JetbrainsServerFinder import settings


@xframe_options_sameorigin
def index(request):
    return render(request, 'index.html')


def getserverlist(request):
    try:
        api = Shodan(settings.APIKEY)
        result = api.search('Location: https://account.jetbrains.com/fls-auth')
        url = "{protocol}://{ip}:{port}"
        resp = {"total": 0, "data": []}
        id = 1
        for server in result["matches"]:
            if "account.jetbrains.com" in server["data"]:
                protocol = "http"
                if "ssl" in server:
                    protocol = "https"
                '''print(url.format(
                    protocol=protocol,
                    ip=server["ip_str"],
                    port=server["port"],
                    position=translator.translate(str(server["location"]["country_name"]))
                ))'''
                address = url.format(
                    protocol=protocol,
                    ip=server["ip_str"],
                    port=server["port"])
                if checkvalid(address):
                    resp["data"].append(dict(id=id, address=address,
                                             location=server["location"]["country_name"],
                                             status='存活验证 √ 激活验证 √'))
                    id += 1
        resp.update({'total': len(resp['data'])})
        resp["code"] = 0
        return HttpResponse(json.dumps(resp), content_type='application/json')
    except Exception as error:
        return HttpResponse(json.dumps({'code': 1}), content_type='application/json')


def checkvalid(host):
    try:
        pattern = re.compile(r'http[s]?://')
        protocol = re.findall(pattern, host)[0]
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0',
            'Host': host.replace(protocol, '')
        }
        alive_url = "/rpc/ping.action?salt=1669702326321"
        active_url = "/rpc/obtainTicket.action?" \
                     "machineId=cc696c3f-d41e-45b6-9d12-59e6d2250171&" \
                     "productCode=49c202d4-ac56-452b-bb84-735056242fb3&" \
                     "salt=1669702326321&" \
                     "userName=FuckYou&" \
                     "hostName=DESKTOP-FuckYou"
        # first of all check alive
        alive_resp_xml = parseString(requests.get(host + alive_url, headers=headers, timeout=5, verify=False).content)
        alive_code = alive_resp_xml.getElementsByTagName('responseCode')[0].firstChild.data
        if alive_code == 'OK':
            # second check active
            active_resp_xml = parseString(
                requests.get(host + active_url, headers=headers, timeout=5, verify=False).content)
            active_code = active_resp_xml.getElementsByTagName('responseCode')[0].firstChild.data
            if active_code == 'OK':
                active_ticket = active_resp_xml.getElementsByTagName('ticketProperties')[0].firstChild.data
                print("[√]{} --- {}".format(host, active_ticket))
                return True
            active_message = active_resp_xml.getElementsByTagName('message')[0].firstChild.data
            print("[!]{} --- {}".format(host, active_message))
        return False
    except Exception as error:
        print("[x]{} --- {}".format(host, error))
        return False
