# -*- coding:utf-8 -*-
import threading
import time

class ThreadMonitor(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.counters = []

    def registerCounter(self, init, min, max, opt):
        self.counters.append([init, init, min, max, opt])
        return len(self.counters)-1

    def addCount(self, counter):
        self.counters[counter][0]+=1
        return

    def subCount(self, counter):
        self.counters[counter][0] -= 1
        return

    def resetCounter(self, counter):
        self.counters[counter][0] = self.counters[counter][1]
        return

    def run(self):
        while(True):
            time.sleep(1)
            i = 0
            for counter in self.counters:
                if counter[0] < counter[2] or counter[0] > counter[3]:
                    self.resetCounter(i)
                    #执行注册的操作
                    counter[4]()
                i+=1