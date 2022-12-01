import json
import queue
import re
import threading
import uuid
from xml.dom.minidom import parseString

import requests
from django.http import HttpResponse
from django.shortcuts import render
from django.views.decorators.clickjacking import xframe_options_sameorigin
from shodan import Shodan

from JetbrainsServerFinder import settings


# Create your views here.


class Mythread(threading.Thread):
    def __init__(self, name, q):
        threading.Thread.__init__(self)
        self.name = name
        self.q = q

    def run(self):
        print("Start thread: " + self.name)
        find_server(self.name, self.q)
        print("Exit thread: " + self.name)


@xframe_options_sameorigin
def index(request):
    return render(request, 'index.html')


exit_flag = 0
queue_lock = threading.Lock()
work_queue = queue.Queue()
resp = {}


def getserverlist(request):
    try:
        server_list = []
        global exit_flag, resp
        exit_flag = 0
        resp = {"total": 0, "data": []}
        api = Shodan(settings.APIKEY)
        result = api.search('Location: https://account.jetbrains.com/fls-auth')
        url = "{protocol}://{ip}:{port}"
        for server in result["matches"]:
            if "account.jetbrains.com" in server["data"]:
                protocol = "http"
                if "ssl" in server:
                    protocol = "https"
                address = url.format(
                    protocol=protocol,
                    ip=server["ip_str"],
                    port=server["port"])
                server_list.append([address, server["location"]["country_name"]])
        work_queue.maxsize = len(server_list)
        threads = []
        # 创建新线程
        for active_server in server_list:
            thread = Mythread(active_server, work_queue)
            thread.start()
            threads.append(thread)
        # 填充队列
        queue_lock.acquire()
        for s in server_list:
            work_queue.put(s)
        queue_lock.release()
        # 等待队列清空
        while not work_queue.empty():
            pass
        # 通知线程是时候退出
        exit_flag = 1
        # 等待所有线程完成
        for t in threads:
            t.join()
        print("Exit main thread")
        resp.update({'total': len(resp['data'])})
        resp.update({'code': 0})
        print(resp)
        return HttpResponse(json.dumps(resp), content_type='application/json')
    except Exception as error:
        return HttpResponse(json.dumps({'code': 1}), content_type='application/json')


def find_server(thread_name, q):
    global exit_flag, queue_lock, work_queue, resp
    while not exit_flag:
        queue_lock.acquire()
        if not work_queue.empty():
            data = q.get()
            queue_lock.release()
            print("%s processing %s" % (thread_name, data))
            if checkvalid(data[0]):
                resp["data"].append(dict(id=str(uuid.uuid4()), address=data[0],
                                         location=data[1],
                                         status='存活验证 √ 激活验证 √'))
        else:
            queue_lock.release()
        # time.sleep(1)


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
