# -*- coding:utf-8 -*-
import threading
import socket
import traceback
import time
import base64
import re
import random
import Tkinter
import tkMessageBox
import serial
import serial.tools.list_ports
import json
import icon
import os
import signal
import common
import threadmonitor
import subprocess

lock = 0
gui  = None
monitor = None
gwstatic = {"rxnb":0,"rxok":0,"rxfw":0,"udptx":0,"udptxack":0,"udprx":0,"udprxack":0,"dwnb":0, "txok":0}


def hton2(s):
    r  = (s>>8)&0xff
    r += (s&0xff)<<8

    return r

def hton4(s):
    r  = hton2(s >> 16) & 0xffff
    r += hton2(s & 0xffff) << 16

    return r

def hton8(s):
    r  = hton4(s >> 32) & 0xffffffff
    r += hton4(s & 0xffffffff) << 32

    return r

def rbf2(b):
    return (b[1]<<8)+b[0]

def rbf4(b):
    return (rbf2(b[2:])<<16)+rbf2(b)

def rbf8(b):
    return (rbf4(b[4:])<<32)+rbf4(b)

def wbf2(i):
    b = []

    i = int(i)

    b.append(i&255)
    i>>=8
    b.append(i&255)

    return b

def wbf4(i):
    b = []
    b.extend(wbf2(i))
    i>>=16
    b.extend(wbf2(i))

    return b

def wbf8(i):
    b = []
    b.extend(wbf4(i))
    i >>= 32
    b.extend(wbf4(i))

    return b

def datr2sfbw(datr):
    ret = []
    res = re.findall(r"SF(.+?)BW(.+?)K", datr)

    if len(res)==0 or len(res[0])<2:
        return [0, 0]

    # ret.append(int(res[0][0])|0x40) #IQ invert
    ret.append(int(res[0][0]))
    ret.append((int(res[0][1])/125)>>1)

    return ret

def codr4str(str):
    res = re.findall(r"4/(.+?)", str)

    if len(res)==0 or len(res[0])<1:
        return 0

    res = int(res[0][0])

    if res <= 5:
        return 0

    return res-5

def PktSizeRx(p):
    return p[21]+22

def PktSizeTx(p):
    return p[24]+25

def Pkt2Json(p):
    j = {}

    j["tmst"] = int(p["time"])*1e3
    j["time"] = time.ctime(time.time())
    j["chan"] = 0
    j["rfch"] = 0
    j["freq"] = int(p["freq"])
    j["stat"] = 1
    j["modu"] = "LORA"
    j["datar"] = "SF"+p["sf"]+"BW125K"
    j["codr"] = "4/5"
    j["lsnr"] = float(p["snr"])
    j["rssi"] = int(float(p["rssi"]))
    j["size"] = len(p["data"])
    p = p["data"]
    p = [chr(x) for x in p]
    p = ''.join(p)
    j["data"] = base64.b64encode(p)

    return j

def Pkt4Json1(j):
    p = []

    if j["imme"]==True:
        p.append(1)
    else:
        p.append(0)

    p.extend(wbf4(hton4(j["tmst"]/1000)))
    # if j["ncrc"]==True:
    #     p.append(1)
    # else:
    #     p.append(0)
    p.extend(wbf4(hton4(j["freq"])))
    # p.append(j["rfch"])
    # p.append(j["powe"])
    #
    # if j["modu"]=="LORA":
    #     p.append(1)
    # else:
    #     p.append(0)

    p.extend(datr2sfbw(j["datar"]))
    p.append(j["powe"])
    # p.append(codr4str(j["codr"]))
    # p.append(j["fdev"])

    # if j["ipol"]==True:
    #     p.append(1)
    # else:
    #     p.append(0)

    # p.extend(wbf2(j["prea"]))
    # p.append(j["size"])

    data = j["data"]
    data = base64.b64decode(data)
    data = [ord(x) for x in data]

    p.extend(data)

    return p

def Pkt4Json(j):
    p = []

    if j["imme"]==True:
        p.append(1)
    else:
        p.append(0)

    p.extend(wbf8(j["tmst"]))
    if j["ncrc"]==True:
        p.append(1)
    else:
        p.append(0)
    p.extend(wbf4(j["freq"]))
    p.append(j["rfch"])
    p.append(j["powe"])

    if j["modu"]=="LORA":
        p.append(1)
    else:
        p.append(0)

    p.extend(datr2sfbw(j["datar"]))
    p.append(codr4str(j["codr"]))
    p.append(j["fdev"])

    if j["ipol"]==False:
        p.append(0)
    else:
        p.append(1)

    p.extend(wbf2(j["prea"]))
    p.append(j["size"])

    data = j["data"]
    data = base64.b64decode(data)
    data = [ord(x) for x in data]

    p.extend(data)

    return p

def getCfg():
    fp = open("config.json", "r+")

    try:
        c = json.load(fp)
    except BaseException:
        traceback.print_exc()
        return None

    print c

    fp.close()

    return c

def log(msg):
    global gui

    gui.log(msg)

def GetValidUart(uartlist):
    valid = []
    command = [0xff, 0, 0]

    for name in uartlist:
        try:
            u =serial.Serial(name, 115200, timeout=1)
            common.UartSend(u, command)
            ack = common.UartRecv(u, 4096)
            ack = [ord(x) for x in ack]
            if len(ack)!=3:
                continue
            if ack[0]!=command[0] or ack[1]!=command[1] or ack[2]!=command[2]:
                continue
            valid.append(name)
            # u.close()
            common.UartClose(u)
        except BaseException, e:
            print repr(e)
            continue

    return valid

def UartCfgGw(uart, freq, sf):
    req  = [255, 1]

    data = []
    data.append(1) #lora
    data.append(0) #ncrc
    data.extend(wbf4(freq))
    data.append(0)#bw
    data.append(sf) #sf
    data.append(0) #codr
    data.append(0)
    data.append(0)
    data.append(0)
    data.append(0x34)#syncword
    data.extend(wbf2(8))

    req.extend(wbf2(len(data)))
    req.extend(data)
    # req.extend(wbf2(0))
    try:
        print req
        common.UartSend(uart, req)
        ack = common.UartRecv(uart, 4096)
        ack = [ord(x) for x in ack]
        print ack

        if ack==None or len(ack)<=0:
            return False
    except BaseException:
        traceback.print_exc()
        return False

    return True

def UartCtrlGw(uart, ctrl):
    req = [255, 4, ctrl]
    try:
        print req
        common.UartSend(uart, req)
        ack = common.UartRecv(uart, 1024)
        ack = [ord(x) for x in ack]
        print ack

        if ack==None or len(ack)<=3:
            return False

    except BaseException:
        traceback.print_exc()
        return False

    return True

def UartSendTest(u, freq, sf, data):
    command = [255, 2, 1]
    command.extend(wbf8(0))
    command.append(1)
    command.extend(wbf4(freq))
    command.append(0)
    command.append(6)
    command.append(1)
    command.append(sf)
    command.append(0)
    command.append(0)
    command.append(0)
    command.append(0)
    command.extend(wbf2(8))
    command.append(len(data))
    command.extend(data)
    u.write(command)

def UartSendSync(uart, freq, data):
    req = [0xff, 7]
    req.append(freq >> 24)
    req.append((freq >> 16)&0xff)
    req.append((freq >> 8) & 0xff)
    req.append((freq >> 0) & 0xff)
    req.extend(data)

    UartClearRx(uart)
    common.UartSend(uart, req)

    # return True
    trys = 0
    while trys < 5:
        try:
            ack = common.UartRecv(uart, 3)
        except BaseException:
            continue

        ack = [ord(x) for x in ack]
        if len(ack)<3:
            continue
        if ack[0] == 0xff and ack[1] == 7 and ack[2] == 0:
            print "uart send sync success"
            return True
        trys+=1

    return False

def UartReadPkts(uart):
    req = [255, 3, 0, 0, 0, 0]

    pkts = []

    try:
        print req
        common.UartSend(uart, req)
        res = common.UartRecv(uart, 4096)
        res = [ord(x) for x in res]
        print res

        if res==None or len(res)<=0 or res[0]!=255 or res[1]!=3:
            return None

        res = res[4:]

        while len(res)>22 and len(res)>=PktSizeRx(res):
            plen = PktSizeRx(res)
            pkts.append(res[0:plen])
            res = res[plen:]

        return pkts
    except BaseException:
        traceback.print_exc()
        return None

def GetGwStateJson():
    j = {}
    j["time"] = time.strftime('%Y-%m-%d %H:%M:%S ',time.localtime(time.time()))+"GMT"
    j["lati"] = 31.9414024565
    j["long"] = 118.8275251181
    j["alti"] = 20
    j["rxnb"] = gwstatic["rxnb"]
    j["rxok"] = gwstatic["rxok"]
    j["rxfw"] = gwstatic["rxfw"]
    if gwstatic["udprxack"]+gwstatic["udptxack"]==0:
        j["ackr"] = 100.0
    else:
        j["ackr"] = int(float(gwstatic["udprxack"]+gwstatic["udptxack"])*100/
                        float(gwstatic["udprxack"]+gwstatic["udptxack"]))
    j["dwnb"] = gwstatic["dwnb"]
    j["txnb"] = gwstatic["txok"]

    return j

def UdpSendState(udp, serv):
    jpkt = {}

    msg = [1]
    rnd = random.uniform(0, 0xffff)
    msg.extend(wbf2(rnd))
    msg.append(0)
    msg.extend(wbf8(hton8(1)))

    jpkt["stat"] = GetGwStateJson()

    jary = json.dumps(jpkt)
    jary = [ord(x) for x in jary]
    msg.extend(jary)

    msg = [chr(x) for x in msg]
    msg = ''.join(msg)
    log(msg[12:])

    try:
        udp.sendto(msg, serv)
    except BaseException:
        tkMessageBox.showerror(u"Warning", u"UDP Send Failed")
        return

    global gwstatic
    gwstatic["udptx"] += 1
    try:
        udp.recvfrom(4096)
    except BaseException:
        return
    gwstatic["udptxack"] += 1

def UdpSendPkt(udp, serv, pkts):
    jary = []
    jpkt = {}

    msg = [1]
    rnd = random.uniform(0, 0xffff)
    msg.extend(wbf2(rnd))
    msg.append(0)
    msg.extend(wbf8(hton8(1)))

    for p in pkts:
        j = Pkt2Json(p)
        jary.append(j)

    jpkt["stat"]  = GetGwStateJson()
    jpkt["rxpkt"] = jary

    jary = json.dumps(jpkt)
    jary = [ord(x) for x in jary]
    msg.extend(jary)

    msg = [chr(x) for x in msg]
    msg=''.join(msg)
    log(msg[12:])

    try:
        udp.sendto(msg, serv)
    except BaseException:
        tkMessageBox.showerror(u"Warning", u"UDP Send Failed")
        return

    global gwstatic
    gwstatic["udptx"] += 1
    try:
        udp.recvfrom(4096)
    except BaseException:
        return
    gwstatic["udptxack"] += 1
    gwstatic["rxfw"] += len(pkts)

def UartClearRx(u):
    ret = common.UartRecv(u, 4096)
    ret = [ord(x) for x in ret]
    while len(ret)>0:
        if ret[0]!=0xff:
            ret = ret[1:]
            continue

        if ret[1]==5:
            gwstatic["txok"] += 1
        ret = ret[3:]


def UdpRecvPkt1(udp, serv, uart):
    msg = [1]
    rnd = random.uniform(0, 0xffff)
    msg.extend(wbf2(rnd))
    msg.append(2)
    msg.extend(wbf8(hton8(1)))

    msg=[chr(x) for x in msg]
    msg=''.join(msg)

    try:
        udp.sendto(msg, serv)
    except BaseException:
        return

    gwstatic["udprx"] += 1
    res = None
    try:
        res = udp.recvfrom(4096)
    except BaseException:
        res = None
        return

    if res == None or len(res)<1:
        return

    gwstatic["udprxack"] += 1
    res = res[0]

    if len(res)<=4:
        return

    msg   = res[4:]
    msg   = ''.join(msg)
    log(msg)
    msg   = json.loads(msg)
    jpkts = msg['txpkt']
    msg   = []

    if len(jpkts)<1:
        return

    for p in jpkts:
        p1 = Pkt4Json1(p)

        if len(p1)<=11:
            continue

        req = [255, 2]
        req.extend(p1)

        log("send to radio")
        print req
        UartSendSync(uart, req)
        time.sleep(0.01)

    return

def UdpRecvPkt(udp, serv, uart):
    msg = [1]
    rnd = random.uniform(0, 0xffff)
    msg.extend(wbf2(rnd))
    msg.append(2)
    msg.extend(wbf8(hton8(1)))

    msg=[chr(x) for x in msg]
    msg=''.join(msg)

    try:
        udp.sendto(msg, serv)
    except BaseException:
        return

    res = []
    try:
        res = udp.recvfrom(4096)
        res = res[0]

        if len(res)<=4:
            return

        msg   = res[4:]
        msg   = ''.join(msg)
        log(msg)
        msg   = json.loads(msg)
        jpkts = msg['txpkt']
        msg   = []

        if len(jpkts)<1:
            return

        gwstatic["dwnb"] += len(jpkts)

        for p in jpkts:
            p1 = Pkt4Json(p)

            if len(p1)<26 or len(p1)!=PktSizeTx(p1):
                continue

            msg.extend(p1)

        if len(msg)<1:
            return

        req = [255, 2]
        req.extend(msg)
        print req
        UartClearRx(uart)
        common.UartSend(uart, req)

    except BaseException:
        # traceback.print_exc()
        print "udp recv timeout"

    return

class SDRInterface():
    def __init__(self, uart, freqs):
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.settimeout(1)
        self.serv = ("127.0.0.1",1234)
        self.udp.bind(("", 2345))
        self.uart = uart
        self.freqlist = freqs
        self.sync_diff = {}
        self.sync_param = {}
        self.prev_syncdata = {}
        self.need_sync = {}
        self.sync_failed_counter = None

    def close(self):
        self.udp.close()

    def checkcrc(self, data):
        crc2  = data[5]<<8
        crc2 += data[6]
        crc1  = common.CRC16(data,5)

        if crc1 == crc2:
            return True

        print "crc error"
        return False

    def handleSyncData(self, d):
        if "data" not in d or len(d["data"])!=8:
            return False

        print "handle sync data:"+d["freq"]

        f0 = self.freqlist[0]
        data = d["data"]
        freq = int(d["freq"])
        if data[0] != 0xff or self.checkcrc(data[1:])==False:
            return True

        if data[1] != self.freqlist.index(freq):
            print "交调信号"
            return True

        data = data[2:]

        t = data[3] << 24
        t += data[2] << 16
        t += data[1] << 8
        t += data[0]
        d['sendtime'] = t

        #重复数据
        if t == self.prev_syncdata[freq]['sendtime']:
            return True

        t2 = float(d['time'])*1e3*self.sync_param[freq][0]-self.sync_param[freq][1]-36
        print "freq:"+str(freq)+" real time:"+str(t)+" recv time:"+str(t2)+" diff:"+str(t2-t)

        # 频点0用于校准
        if freq != f0:
            self.sync_diff[freq]+=t2-t
            self.need_sync[freq] = False
            return True

        diff1 = t - self.prev_syncdata[freq]['sendtime']
        diff2 = (float(d['time'])-float(self.prev_syncdata[freq]['time']))*1e3
        rate = abs(diff1/diff2)

        self.sync_param[freq][0] = rate
        self.sync_param[freq][1] = float(d['time'])*1e3*rate-d['sendtime']-36

        if abs(t2-t)>60:
            self.prev_syncdata[freq] = d

        for f in self.freqlist:
            if f==f0:
                continue
            self.sync_param[f][0] = rate
            self.sync_param[f][1] = self.sync_param[f0][1]+self.sync_diff[f]

        print "rate:"+str(rate)+" offset:"+str(self.sync_param[f0][1])

        global monitor
        monitor.resetCounter(self.sync_failed_counter)
        return True

    def readData(self):
        datalist = []

        # self.udp.settimeout(0.01)
        # while True:
        #     try:
        #         acks, addr = self.udp.recvfrom(4096)
        #     except BaseException:
        #         break

        self.udp.settimeout(0.1)

        while True:
            try:
                acks,addr = self.udp.recvfrom(1024)
                if len(acks)<=10:
                    continue
            except BaseException:
                break

            acks.replace("\n", "")
            acks = acks.split(";")

            for ack in acks:
                res = {}
                if "time:" not in ack:
                    continue
                if "freq:" not in ack:
                    continue
                if "data:" not in ack:
                    continue
                if "rssi:" not in ack:
                    continue

                ack = ack.split(",")
                for a in ack:
                    if ":" in a:
                        key_value = a.split(":")
                        if len(key_value)<=1:
                            continue
                        key = key_value[0].strip()
                        res[key] = key_value[1]
                try:
                    data = res["data"]
                    data = data.split(" ")
                    data = [x.strip() for x in data]
                    data1 = []
                    for d in data:
                        if len(d)>0:
                            data1.append(int(d, 16))
                    res["data"] = data1
                except BaseException:
                    print "sdr data invalid"
                    continue

                datalist.append(res)

        return datalist

    def getSyncDataList(self, dlist):
        datalist = {}

        for fi in range(len(self.freqlist)):
            freq = self.freqlist[fi]
            trys = 0
            while trys<10:
                trys += 1
                if UartSendSync(self.uart, freq, [fi])==True:
                    time.sleep(1.5)
                    datas = self.readData()
                    if len(datas)==0:
                        continue
                    for d in datas:
                        if int(d["freq"])!=freq:
                            continue
                        data = d["data"]
                        if len(data)!=8 or data[0] != 0xff or self.checkcrc(data[1:])==False:
                            continue
                        if data[1] != fi:
                            print "交调信号"
                        data = data[2:]
                        t = data[3] << 24
                        t += data[2] << 16
                        t += data[1] << 8
                        t += data[0] << 0
                        d['sendtime'] = t
                        if dlist!=None and t == dlist[freq]['sendtime']:
                            continue
                        datalist[freq] = d
                if freq in datalist:
                    break

            if trys>=10:
                tkMessageBox.showerror(u"出错", "发送同步失败，请检查串口")
                return None

        return datalist

    def sync(self):
        # UartCtrlGw(self.uart, 0)
        print "sync"
        time_diff = 0
        time_rate = 0
        datalist1 = self.getSyncDataList(None)
        if datalist1 == None:
            return False
        time.sleep(20)
        datalist2 = self.getSyncDataList(datalist1)
        if datalist2 == None:
            return False

        f0 = self.freqlist[0]
        self.sync_diff[f0] = {0}

        for freq in self.freqlist:
            diff1 = datalist2[freq]["sendtime"] - datalist1[freq]["sendtime"]
            diff = float(datalist2[freq]["time"])*1e3 - float(datalist1[freq]["time"])*1e3

            time_rate = abs(diff1 / diff)
            time_diff = float(datalist1[freq]["time"]) * 1e3 * time_rate - datalist1[freq]["sendtime"] - 36
            self.prev_syncdata[freq] = datalist2[freq]
            self.sync_param[freq] = [time_rate, time_diff]
            t1 = datalist2[freq]["sendtime"]
            t2 = float(datalist2[freq]["time"])*1e3*time_rate-time_diff

            if f0 != freq:
                self.sync_diff[freq] = (float(datalist2[freq]["time"])-float(datalist2[f0]["time"]))*1e3-(datalist2[freq]["sendtime"]-datalist2[f0]["sendtime"])

            print "t1:"+str(t1)+" t2:"+str(t2)
        return True

    def clear(self):
        print "clear"
        while True:
            datas = self.readData()
            if datas == None or len(datas) <= 0:
                break

    def readTest(self):
        datas = []
        while(len(datas)<=0):
            if UartSendSync(self.uart, 470100000, [0]) == True:
                time.sleep(0.5)
                datas = self.readData()

        for d in datas:
            data = d["data"]
            if len(data) != 7 or data[0]!=0xff or self.checkcrc(data[1:])==False:
                continue
            data = data[1:]
            t1 = float(d["time"])*1e3
            t1 *= self.sync_param[470100000][0]
            t1 -= self.sync_param[470100000][1]
            t2 = data[3]<<24
            t2 += data[2]<<16
            t2 += data[1]<<8
            t2 += data[0]
            print "real time:"+str(t2)+" recv time:"+str(t1)+" diff:"+str(t1-t2)

    def readSyncData(self):
        datalist1 = []
        datalist = self.readData()
        if len(datalist)<=0:
            return datalist1

        for d in datalist:
            if self.handleSyncData(d)==True:
                continue
            t = float(d["time"])*1e3
            f = int(d["freq"])
            t *= self.sync_param[f][0]
            t -= self.sync_param[f][1]
            d["time"] = t
            datalist1.append(d)
            if f!=self.freqlist[0]:
                self.need_sync[f] = True

        return datalist1

class LoraReceiver():
    def __init__(self, freqs):
        self.freqlist = freqs
        self.process = None

    def start(self):
        command = u"lorareceive.exe -f "
        command += str(self.freqlist[0])
        for freq in self.freqlist:
            if self.freqlist.index(freq)==0:
                continue
            command += ","+str(freq)
        self.process = subprocess.Popen(command, shell=True)
        trys = 0
        ret = 0
        while trys<20:
            trys+=1
            ret = os.system('tasklist | find "lorareceive.exe"')
            if ret == 0:
                return True

        if ret !=0:
            return False

    def stop(self):
        count = 10
        while self.alive():
            if count>=10:
                os.system('TASKKILL /F /IM lorareceive.exe"')
                count = 0
            time.sleep(0.1)
            count += 1

    def alive(self):
        ret = os.system('tasklist | find "lorareceive.exe"')
        if ret == 0:
            return True
        else:
            return False

class ThreadSync(threading.Thread):
    def __init__(self, u, fl, sdr):
        threading.Thread.__init__(self)
        self.uart = u
        self.freqlist = fl
        self.sdr = sdr
        self.done = False
        self.pauseed = False

    def stop(self):
        if self.done == True:
            return
        self.running = True
        self.done=True
        trys = 0
        while self.running == True and trys < 30:
            trys += 1
            time.sleep(0.1)

    def pause(self):
        self.pauseed = True

    def contin(self):
        self.pauseed = False

    def sendNeedSync(self):
        for f in self.freqlist:
            if self.sdr.need_sync.has_key(f) and self.sdr.need_sync[f] == True:
                UartSendSync(self.uart, f, [self.freqlist.index(f)])
                return True

        return False

    def run(self):
        # self.sdr.sync()
        fi = 0
        count = 0

        while self.done==False:
            time.sleep(2)
            if self.pauseed==True:
                continue
            count += 1
            if self.sendNeedSync():
                continue
            if count>=10:
                UartSendSync(self.uart, self.freqlist[fi], [fi])
                global monitor
                monitor.addCount(self.sdr.sync_failed_counter)
                count=0

        self.running = False

class ThreadUplink(threading.Thread):
    def __init__(self, a, u, sdr):
        threading.Thread.__init__(self)

        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.udp.bind(a)
        self.serv = a
        self.uart = u
        self.udp.settimeout(10)
        self.sdr = sdr
        self.done = False
        self.pauseed = False

    def stop(self):
        if self.done == True:
            return
        self.running = True
        self.done = True
        trys = 0
        while self.running==True and trys<30:
            trys+=1
            time.sleep(0.1)

    def pause(self):
        self.pauseed = True

    def contin(self):
        self.pauseed = False

    def run(self):
        statictime = time.time()

        while self.done==False:
            if self.pauseed:
                time.sleep(1)
                continue
            datas = self.sdr.readSyncData()
            if len(datas)<=0:
                time.sleep(0.1)
                if time.time()-statictime>300:
                    UdpSendState(self.udp,self.serv)
                    statictime = time.time()
                continue
            # print "send data to cloud"
            UdpSendPkt(self.udp, self.serv, datas)
            # print "send to cloud end"
            global gwstatic
            gwstatic["rxok"] += len(datas)
            gwstatic["rxnb"] += len(datas)
            statictime = time.time()

        self.running = False
        self.udp.close()

class ThreadDnlink(threading.Thread):
    def __init__(self, a, u):
        threading.Thread.__init__(self)

        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # self.udp.bind(a)
        self.serv = a
        self.udp.settimeout(10)

        self.uart=u
        self.done=False
        self.pauseed = False

    def stop(self):
        if self.done == True:
            return
        self.running = True
        self.done=True
        trys = 0
        while self.running == True and trys < 30:
            trys += 1
            time.sleep(0.1)

    def pause(self):
        self.pauseed = True

    def contin(self):
        self.pauseed = False

    def run(self):
        # UartCtrlGw(self.uart, 1)
        while(self.done==False):
            if self.pauseed:
                time.sleep(1)
                continue
            UdpRecvPkt(self.udp, self.serv, self.uart)
            UartClearRx(self.uart)
            time.sleep(0.5)

        self.udp.close()
        self.running = False

class GwUI():
    def __init__(self):
        top  = Tkinter.Tk()
        top.title("LoRaWAN Gateway")
        tmp = open("tmp.ico", "wb+")
        tmp.write(base64.b64decode(icon.img))
        tmp.close()
        top.iconbitmap("tmp.ico")
        os.remove("tmp.ico")

        labl_str_serv = Tkinter.StringVar()
        labl_str_port = Tkinter.StringVar()
        labl_str_freq = Tkinter.StringVar()
        labl_str_log  = Tkinter.StringVar()
        self.labl_str_btn1 = Tkinter.StringVar()
        self.labl_str_btn2 = Tkinter.StringVar()

        entr_str_serv = Tkinter.StringVar()
        entr_str_port = Tkinter.StringVar()
        entr_str_freq = Tkinter.StringVar()
        entr_str_freq.set("470100000,470300000")

        labl_str_serv.set(u'NS地址：')
        labl_str_port.set(u'NS端口：')
        labl_str_freq.set(u'频率表：')
        labl_str_log.set(u'日 志：')
        self.labl_str_btn1.set(u'开 始')
        self.labl_str_btn2.set(u'清 除')

        labl_serv = Tkinter.Label(top, textvariable=labl_str_serv, width=10, justify='left')
        self.entr_serv = Tkinter.Entry(top, textvariable=entr_str_serv, width=18)
        labl_port = Tkinter.Label(top, textvariable=labl_str_port, width=10, justify='left')
        self.entr_port = Tkinter.Entry(top, textvariable=entr_str_port, width=18)
        labl_freq = Tkinter.Label(top, textvariable=labl_str_freq)
        self.entr_freq = Tkinter.Text(top, width=40, height=3)
        labl_log  = Tkinter.Label(top, textvariable=labl_str_log)
        self.text_log  = Tkinter.Text(top, width=95, height=30)
        self.btn_start = Tkinter.Button(top, textvariable=self.labl_str_btn1, height=2, width=10, command=self.btnstart)
        self.btn_clear = Tkinter.Button(top, textvariable=self.labl_str_btn2, height=2, width=10, command=self.btnclear)

        labl_serv.grid(row=0, column=0)
        self.entr_serv.grid(row=0, column=1)
        labl_port.grid(row=1, column=0)
        self.entr_port.grid(row=1, column=1)
        labl_freq.grid(row=0, column=2)
        self.entr_freq.grid(row=0, column=3, rowspan=2, columnspan=2)
        labl_log.grid(row=2, column=0)
        self.text_log.grid(row=3, column=0, columnspan=8)
        self.btn_start.grid(row=0, column=6, rowspan=2)
        self.btn_clear.grid(row=0, column=7, rowspan=2)

        conf = getCfg()

        if conf!=None:
            try:
                entr_str_serv.set(conf['serv'])
            except BaseException:
                entr_str_serv.set("127.0.0.1")
                print "no server"
            try:
                entr_str_port.set(conf['port'])
            except BaseException:
                entr_str_port.set(u"6000")
                print "no port"
            try:
                if len(conf['freqlist'])<1:
                    self.entr_freq.insert(Tkinter.END, u"470100000,470300000")
                else:
                    freqs = str(conf['freqlist'][0])
                    for i in range(len(conf['freqlist'])):
                        if i==0:
                            continue
                        freqs += ","+str(conf['freqlist'][i])
                    self.entr_freq.insert(Tkinter.END, freqs)
            except BaseException:
                self.entr_freq.insert(Tkinter.END, u"470100000,470300000")
                print "no freq list"

        self.start = False
        self.text_log_rows = []
        self.top = top
        self.monitors = []
        self.monitors.append(monitor.registerCounter(0, 0, 10, self.restart))
        return

    def Start(self):
        self.top.mainloop()
        return

    def startThreads(self):
        addr = (self.serv, self.port)
        self.threads = []
        self.threads.append(ThreadUplink(addr, self.uart, self.sdr))
        self.threads.append(ThreadDnlink(addr, self.uart))
        self.threads.append(ThreadSync(self.uart, self.freqs, self.sdr))

        for th in self.threads:
            th.start()
        return

    def pauseThreads(self):
        for th in self.threads:
            th.pause()
        return

    def continueThreads(self, uart):
        for th in self.threads:
            th.uart = uart
            th.contin()
        return

    def stopThreads(self):
        for th in self.threads:
            th.stop()
        return

    def restart(self):
        self.log(u"重启")
        # 暂停所有线程
        self.pauseThreads()
        # self.uart.close()
        common.UartClose(self.uart)
        self.lora.stop()

        if self.lora.start() != True:
            tkMessageBox.showerror(u"错误", u"请插入RTLSDR设备")
            return
        try:
            self.uart = serial.Serial(self.uartname, 115200, timeout=0.5)
        except BaseException:
            traceback.print_exc()
            self.uart = None

        if self.uart == None:
            tkMessageBox.showerror(u"c出错", u"打开串口失败")
            return

        self.log(u"正在同步...")
        self.sdr.clear()
        UartCtrlGw(self.uart, 0)
        time.sleep(15)
        self.sdr.uart = self.uart
        self.sdr.sync()
        self.log(u"同步完成!")

        #所有线程继续运行
        self.continueThreads(self.uart)

    def closeAll(self):
        # self.uart.close()
        common.UartClose(self.uart)
        self.sdr.close()

    def btnstart(self):
        # uart = self.list_uart.get(self.list_uart.curselection(), 1)
        # serv = self.entr_serv.get()

        if self.start==False:
            uarts = getSeirals()
            if len(uarts) <= 0:
                tkMessageBox.showerror(u"出错", u"请插入至少1个有效的发送模块")
                return
            uart = GetValidUart(uarts)
            if len(uart) <= 0:
                tkMessageBox.showerror(u"出错", u"请插入至少1个有效的发送模块")
                return
            uart = uart[0]
            self.serv = self.entr_serv.get()
            self.port = self.entr_port.get()

            if self.serv==None or self.serv=="" or self.port=="" or int(self.port)<=0:
                tkMessageBox.showerror(u"出错", u"请输入NS地址")
                return

            self.log(u"NS地址:"+self.serv+":"+self.port)
            self.log(u"串口号:"+uart)

            self.port     = int(self.port)
            self.uartname = uart

            try:
                self.uart = serial.Serial(uart, 115200, timeout=0.5)
            except BaseException:
                traceback.print_exc()
                self.uart=None

            if self.uart == None:
                tkMessageBox.showerror(u"c出错", u"打开串口失败")
                return

            freqs = self.entr_freq.get("0.0", Tkinter.END)
            print "freqlist:"+freqs
            freqs = freqs.split(",")
            if len(freqs)<=0:
                tkMessageBox.showerror(u"c出错", u"请输入至少1个有效频率")
                # self.uart.close()
                common.UartClose(self.uart)
                return

            freqs = [int(x) for x in freqs]
            if max(freqs)>=min(freqs)+2e6:
                tkMessageBox.showerror(u"c出错", u"输入的频段超出带宽范围")
                # self.uart.close()
                common.UartClose(self.uart)
                return
            if len(freqs)>10:
                tkMessageBox.showerror(u"c出错", u"最多支持10个频点")
                # self.uart.close()
                common.UartClose(self.uart)
                return

            #保存参数到配置文件中
            config = {}
            config['port'] = self.port
            config['serv'] = self.serv
            config['freqlist'] = freqs
            f = open("config.json", "w+")
            f.write(json.dumps(config))
            f.close()
            self.lora = LoraReceiver(freqs)
            self.lora.stop()
            if self.lora.start()!=True:
                tkMessageBox.showerror(u"错误", u"不能发现lorareceive.exe")
                # self.uart.close()
                common.UartClose(self.uart)
                return

            time.sleep(15)
            if self.lora.alive() != True:
                tkMessageBox.showerror(u"错误", u"请插入RTLSDR设备")
                # self.uart.close()
                common.UartClose(self.uart)
                return
            self.sdr = SDRInterface(self.uart, freqs)
            global monitor
            self.sdr.sync_failed_counter = self.monitors[0]
            monitor.resetCounter(self.sdr.sync_failed_counter)
            self.freqs = freqs
            self.log(u"正在同步...")
            self.sdr.clear()
            UartCtrlGw(self.uart, 0)
            self.sdr.sync()
            self.log(u"同步完成!")
            # print param
            self.startThreads()
            self.start=True
            self.labl_str_btn1.set(u"停止")
            global gwstatic
            gwstatic = {"rxnb": 0, "rxok": 0, "rxfw": 0, "udptx": 0, "udptxack": 0, "udprx": 0, "udprxack": 0,
                        "dwnb": 0, "txok": 0}

            return

        self.labl_str_btn1.set(u"正在停止...")
        UartCtrlGw(self.uart, 1)
        self.stopThreads()
        self.sdr.close()
        # self.uart.close()
        common.UartClose(self.uart)
        self.lora.stop()
        self.labl_str_btn1.set(u"开始")
        self.start=False

    def btnclear(self):
        self.text_log.delete(0.0, Tkinter.END)
        self.text_log_rows = []

    def log(self, msg):
        self.text_log_rows.append(msg)

        if len(self.text_log_rows)>30:
            self.text_log_rows = self.text_log_rows[1:]

        str = ""
        for m in self.text_log_rows:
            str+=m+"\n"

        self.text_log.delete(0.0, Tkinter.END)
        self.text_log.insert(Tkinter.END, str)

        return

def getSeirals():
    list1 = serial.tools.list_ports.comports()
    list2 = []

    print len(list1)

    for s in list1:
        print s[0]
        list2.append(s[0])

    return list2

def Start():
    global gui
    global monitor

    monitor = threadmonitor.ThreadMonitor()
    monitor.start()
    gui = GwUI()
    gui.Start()

Start()

# import lora_receive_nogui
# lora = lora_receive_nogui.SDR([470100000])
# ret = lora.HasDevice()
# print ret
# if ret:
#     sdr = LoraReceiver([470100000])
#     sdr.start()
#     time.sleep(20)

# sdr = LoraReceiver([470100000])
# sdr.start()
# time.sleep(20)
# sdr.stop()
# time.sleep(1)
# sdr.start()
# time.sleep(20)
# uartlist = getSeirals()
# # print "valid uart:"
# name = GetValidUart(uartlist)
# uart = serial.Serial(name[0], 115200, timeout=1)
# # sdr = lora.SDR([470100000, 470300000])
# # sdr.Start()
# i=0
# # time.sleep(10)
# while True:
#     # UartSendTest(uart, 470300000, 12, [0xff,i,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20])
#     # time.sleep(3)
#     UartSendTest(uart, 470300000, 12, [0xff, i, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
#     i+=1
#     i%=256
#     time.sleep(3)

# sdr.clear()
# if sdr.sync()==True:
#     while True:
#         # sdr.readTest()
#         for freq in [470100000, 470300000]:
#             UartSendSync(uart, freq)
#             time.sleep(0.5)
#         time.sleep(3)
#         sdr.readSyncData()
#         time.sleep(2)
# j = 0
# while j<17:
#     if j<1:
#         test = 0
#     else:
#         test = 1<<(j-1)
#     data = []
#     for i in range(28):
#         # data.append(random.uniform(0, 256))
#         data.append(0)
#     data[0] = j
#     j+=1
#     data.append(test&0xff)
#     data.append((test>>8)&0xff)
#     data = [int(x) for x in data]
#     command = [0xff,2,1,0,0,0,0, 0x1c, 0x05, 0x28, 0x20, 0x09, 0x06]
#     command.extend(data)
#
#     ok = False
#     for i in range(1):
#         sdr.clear()
#         uart.write(command)
#         time.sleep(2)
#         recvdatas = sdr.readData()
#         if recvdatas == None:
#             continue
#
#         for d in recvdatas:
#             err = 0
#             if "data" not in d:
#                 continue
#             print "send:"
#             print data
#             print "recv:"
#             print d["data"]
#
#             for a in data:
#                 if a not in d["data"]:
#                     if i>0 and ok == True:
#                         raw_input("press any key")
#                         exit(0)
#                     else:
#                         err+=1
#                         break
#
#             if err==0:
#                 ok = True
#             time.sleep(2)