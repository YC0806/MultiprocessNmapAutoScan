import nmap
import time
import os
import csv
from multiprocessing import Pool,Lock,cpu_count
from subprocess import run, PIPE
import logging



logging.basicConfig(level=logging.INFO,
                format='%(asctime)s: %(levelname)-8s %(message)s',
                datefmt='%H:%M:%S')


def connect_check(mode=0): # mode 0:阻塞等待网络恢复 mode 1:返回网络状态
    while True:
        r = run('ping 8.8.8.8',
                stdout=PIPE,
                stderr=PIPE,
                stdin=PIPE,
                shell=True)
        if r.returncode:
            if mode == 1:
                return 0
            logging.warning('网络异常,重试中')
        else:
            return 1
        time.sleep(30)


def init_lock(l):
    global lock
    lock = l


def single_scan(task):
    target,port_chunk,output_file = task
    connect_check()
    t_start = time.time()
    logging.info("{0}开始扫描,进程号为{1}".format(target,os.getpid()))
    
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target,ports=port_chunk,arguments="-sT -T3",timeout=600)

        if connect_check(1) == 0:
            logging.warning("{0}出现异常:网络中断".format(target))
            return 1

        if len(nm.all_hosts()) == 0:
            logging.info("{0}已关闭".format(target))
            return 1

        else:
            _data = []
            for host in nm.all_hosts():
                for protocol in nm[host].all_protocols():
                    for item in nm[host][protocol].items():
                        _data.append([host,"up",protocol,item[0],item[1]["state"],item[1]["name"]])


            lock.acquire()
            with open(output_file,mode='a',newline='',encoding='utf8') as cfa:
                wf = csv.writer(cfa)
                for i in _data:
                    print(i)
                    wf.writerow(i)
            lock.release()

            t_stop = time.time()
            logging.info("{0}扫描完毕，耗时{1}s".format(target,round(t_stop-t_start,2)))
            return 0
    
    except nmap.PortScannerTimeout:
        print("\a")
        logging.warning("{0}超时异常".format(target))
        return 2

    except Exception as ex:
        print("\a")
        logging.warning("{0}出现异常：{1} {2}".format(target,type(ex),ex))
        return 1
        

def alive_scan(target):
    connect_check()
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target,arguments="-sP")

        if connect_check(1) == 0:
            logging.warning("{0}出现异常:网络中断".format(target))
            return 1

        if len(nm.all_hosts()) == 0:
            logging.info("{0}确认关闭".format(target))
            return 0
        else:
            logging.info("{0}确认开启".format(target))
            return 1

    except Exception as ex:
        print("\a")
        logging.warning("{0}出现异常:{1} {2}".format(target,type(ex),ex))
        return 1


    # scan_dict = scan_result['scan']
    # while host not in scan_dict:
    #     time.sleep(1)
    # if "osmatch" in scan_dict[host]: 
    #     for item in scan_dict[host]["osmatch"]:
    #         os_insert(host=host,os=item["name"],accuracy=item["accuracy"],sid=self.sid)
    #         print("{0}({1})".format(item["name"],item["accuracy"]))
    # if "tcp" in scan_dict[host]:
    #     for item in scan_dict[host]["tcp"].items():
    #         port_insert(host=host,port=item[0],protocol="tcp",state=item[1]["state"],name=item[1]["name"],sid=self.sid)
    #         print("{0}/tcp {1} {2}".format(item[0], item[1]["state"], item[1]["name"]))
    # if "udp" in scan_dict[host]:
    #     for item in scan_dict[host]["udp"].items():
    #         port_insert(host=host,port=item[0],protocol="udp",state=item[1]["state"],name=item[1]["name"],sid=self.sid)
    #         print("{0}/udp {1} {2}".format(item[0], item[1]["state"], item[1]["name"]))
    

   
if __name__=="__main__":
    
    f = open("target.txt","r")
    _targets = f.readlines()
    f.close()

    targets = []
    for t in _targets:
        t = t.replace("\n","")
        if len(t) > 0:
            targets.append(t)

    output_file= "scandata_"+time.strftime("%Y%m%d%H%M%S")+".csv"
    f = open(output_file,"w")
    f.close()

    port_chunks = ["0-10000","10001-20000","20001-30000","30001-40000","40001-50000","50001-60000","60001-65535"]
    # port_chunks = ["10001-20000"]
    # port_chunks = ["0-100","101-200","201-300","301-400"]

    cpu_num = cpu_count()
    print("CPU_NUM:",cpu_num)

    retry_num = 2
    i = 0
    slow_list = []
    down_list = []
    _targets = []

    while(i < retry_num):
        i += 1
        logging.info("第{0}轮存活扫描开始".format(i))

        pool = Pool(processes=cpu_num)
        res = pool.map(func=alive_scan, iterable=targets)
        pool.close()
        pool.join()

        for flag,target in zip(res,targets):
            if flag == 1:
                _targets.append(target)

        logging.info("第{0}轮存活扫描完成, 共{1}个目标, 其中{2}个目标存活".format(i, len(targets), sum(res)))
        continue

    _targets = list(set(_targets))
    for target in targets:
        if target not in _targets:
            down_list.append(target)
    targets = _targets


    for port_chunk in port_chunks:
        _targets = list(targets)

        i = 0 
        while(len(_targets) != 0):
            i += 1
            tasks = []
            for target in _targets: # 分段扫描
                tasks.append((target,port_chunk,output_file))

            logging.info("{0} 第{1}轮扫描开始".format(port_chunk, i))
            l = Lock()
            pool = Pool(processes=cpu_num, initializer=init_lock, initargs=(l, ))
            res = pool.map(func=single_scan, iterable=tasks)

            
            pool.close()
            pool.join()
            print("\a")
            print(res)

            
            _temp = []

            for flag,target in zip(res,_targets):
                if flag == 2:
                    slow_list.append(target)
                if flag == 1:
                    _temp.append(target)
            
            _targets = []

            retry_num = 3
            j = 0
            while(j < retry_num):
                j += 1
                logging.info("第{0}轮扫描 第{1}轮核对开始".format(i,j))

                pool = Pool(processes=cpu_num)
                res = pool.map(func=alive_scan, iterable=_temp)

                pool.close()
                pool.join()
                print(res)

                for flag,target in zip(res,_temp):
                    if flag == 1:
                        _targets.append(target)

                logging.info("第{0}轮扫描 第{1}轮核对完成".format(i,j))
                continue

            _targets = list(set(_targets))
            for target in _temp:
                if target not in _targets:
                    down_list.append(target)
            logging.info("{0} 第{1}轮扫描完成".format(port_chunk, i))
            
        logging.info("端口{0}扫描完成 共{1}轮扫描".format(port_chunk, i))

    _data = []
    down_list = list(set(down_list))
    for target in down_list:
        _data.append([target,"down"])

    slow_list = list(set(slow_list))
    for target in slow_list:
        _data.append([target,"slow"])

    with open(output_file,mode='a',newline='',encoding='utf8') as cfa:
        wf = csv.writer(cfa)
        for i in _data:
            print(i)
            wf.writerow(i)
    


    

    # while True:
    #     if a.ready() and q.empty():
    #         break
    #     else:
    #         _data = q.get()
    #         with open(r'scan_res.csv',mode='a',newline='',encoding='utf8') as cfa:
    #             wf = csv.writer(cfa)
    #             for i in _data:
    #                 print(i)
    #                 wf.writerow(i)
    # for t in targets:
    #     pool.apply_async(func=single_scan, args=(q,t),callback=callback_func) 
    # q.close()



    
    