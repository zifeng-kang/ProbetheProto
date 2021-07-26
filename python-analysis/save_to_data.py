import os
import json
from match_configs import CONFIG

def my_file_read(ff):
    ff.seek(0, 0)
    content = ff.read()
    return content

def my_file_write(ff, content):
    ff.seek(0, 0)
    ff.write(content)

def save_to_data(joint_matches, f1, f2, file1, file2):
    # Assume that if there is already something in the file, the variable in the file does not contain any website that is in sitevarc or sitevarm!
    sitevarc=None
    sitevarm=None
    for element in joint_matches:
        #if there is nothing in the file cookie_storage_modify_extension/data1.js
        if sitevarc==None:
            if element[0]=='Cookie':
                site=element[2]
                sitevarc={
                    site: {
                        'Cookie':[],
                        'localStorage':{},
                        'sessionStorage':{},
                    }
                }
                sitevarc[site]['Cookie'].append(element[1])
            elif element[0]=='Storage':
                site=element[2]
                sitevarc={
                    site: {
                        'Cookie':[],
                        'localStorage':{},
                        'sessionStorage':{},
                    }
                }
                key=list(element[1].keys())
                value=list(element[1].values())
                if element[4]==1:
                    sitevarc[site]['localStorage'][key[0]]=value[0]
                elif element[4]==-1:
                    sitevarc[site]['sessionStorage'][key[0]]=value[0]
        #if there is something in the file cookie_storage_modify_extension/data1.js, retrieve it
        else:
            if element[0]=='Cookie':
                site=element[2]
                sitevarc = check_dupc(sitevarc,site,element[1])
            elif element[0]=='Storage':
                    site=element[2]
                    if element[4]=='1':
                        sitevarc=check_dupLS(sitevarc,site,element[1])
                    elif element[4]=='-1':
                        sitevarc=check_dupSS(sitevarc,site,element[1])
        #if there is nothing in the file postMessage_extension/data1.js
        if sitevarm==None:
            if element[0]=='Message':
                    site=element[2]
                    sitevarm={
                        site:[]
                    }
                    sitevarm[site].append([element[4],element[3],element[1]]) 
                    # Origin, Receiver, Msg_str
        #if there is something in the file postMessage_extension/data1.js
        else:
            if element[0]=='Message':
                    site=element[2]
                    sitevarm[site].append([element[4],element[3],element[1]])
                    # Origin, Receiver, Msg_str
    if sitevarc:
        if not my_file_read(f1):
        # if os.stat(file1).st_size == 0:
            my_file_write(f1, 'var data_to_change = %s;' % json.dumps(sitevarc))
            # f1.write('var data_to_change = %s;' % json.dumps(sitevarc))
        else:
            # f1.seek(0, 0)
            # json1_str = f1.read()
            json1_str = my_file_read(f1)
            json1_str=json1_str.replace('var data_to_change =','')
            json1_str=json1_str.rstrip(';')
            json1_data = json.loads(json1_str)
            for i in sitevarc.keys():
                json1_data[i]=(sitevarc[i])
            # f1.seek(0, 0)
            # f1.write('var data_to_change = %s;' % json.dumps(json1_data))
            my_file_write(f1, 'var data_to_change = %s;' % json.dumps(json1_data))
            f1.truncate()
            # f1.seek(0, 0)
    if sitevarm:
        if not my_file_read(f2):
        # if os.stat(file2).st_size == 0:
            # f2.write('var data_to_change = %s;' % json.dumps(sitevarm))
            my_file_write(f2, 'var data_to_change = %s;' % json.dumps(sitevarm))
        else:
            # f2.seek(0, 0)
            # json1_str = f2.read()
            json1_str = my_file_read(f2)
            json1_str=json1_str.replace('var data_to_change =','')
            json1_str=json1_str.rstrip(';')
            json1_data = json.loads(json1_str)
            for i in sitevarm.keys():
                json1_data[i]=(sitevarm[i])
            # f2.seek(0, 0)
            # f2.write('var data_to_change = %s;' % json.dumps(json1_data))
            my_file_write(f2, 'var data_to_change = %s;' % json.dumps(json1_data))
            f2.truncate()
            # f2.seek(0, 0)
    return


def check_dupc(var,site,value):
    obj=var[site]['Cookie']
    o=[]
    for i in obj:
        o.append(i.split('=')[0])
    if value.split('=')[0] in o:
        return var
    else:
        var[site]['Cookie'].append(value)
        return var

def check_dupLS(var,site,value):
    obj=var[site]['localStorage']
    o=list(obj.keys())
    if value.keys() in o:
        return var
    else:
        key=list(value.keys())
        value=list(value.values())
        var[site]['localStorage'][key[0]]=value[0]
        return var

def check_dupSS(var,site,value):
    obj=var[site]['sessionStorage']
    o=list(obj.keys())
    if value.keys() in o:
        return var
    else:
        key=list(value.keys())
        value=list(value.values())
        var[site]['sessionStorage'][key[0]]=value[0]
        return var





if __name__ == "__main__":
    # old_joint_matches=[['Cookie','1:1','www.qwe.com','www.qwe','1'],
    #                 ['Cookie','1:2','www.qwe.com','www.qwe','1'],
    #                 ['Cookie','1:3','www.qwe.com','www.qwe','-1'],
    #                 ['Cookie','1:4','www.qwe.com','www.qwe','-1'],
    #                 ['Cookie','1:5','www.qwe.com','www.qwe','1'],
    #                 ['Cookie','1:5','www.qwe.com','www.qwe','1'],
    #                 ['Storage','1:1','www.qwe.com','www.qwe','1'],
    #                 ['Storage','2:2','www.qwe.com','www.qwe','1'],
    #                 ['Storage','3:3','www.qwe.com','www.qwe','-1'],
    #                 ['Message','4:4','www.qwe.com','www.qwe','google.com']]
    joint_matches=[['Cookie','__proto__=testk:testv','www.qwe.com','www.qwe','1'],
                    ['Cookie','__proto__=111','www.qwe.com','www.qwe','1'],
                    ['Cookie','1=3','www.qwe.com','www.qwe','-1'],
                    ['Cookie','1=5','www.qwe.com','www.qwe','1'],
                    ['Cookie','1=5','www.qwe.com','www.qwe','1'],
                    ['Storage',{'testk':'testv'},'www.qwe.com','www.qwe','1'],
                    ['Storage',{'testk':'111'},'www.qwe.com','www.qwe','1'],
                    ['Storage',{'testk':'111'},'www.qwe.com','www.qwe','-1'],
                    ['Storage',{'testk':'testv'},'www.qwe.com','www.qwe','-1'],
                    ['Message',"{\"du\":\"gws\",\"zf\":27}",'www.qwe.com','www.qwe','google.com']]
    joint_matches2 = [['Cookie', "__proto__=Cookie_testk%3DCookie_testv%26VISIT%255FDATE%3D2021%252F05%252F26", "hmv.co.jp", "hmv.co.jp", '0'], 
                        ['Cookie', "__proto__=LANG%3Dja%26VISIT%255FDATE%3D2021%252F05%252F26", "hmv.co.jp", "hmv.co.jp", '0'], 
                        ['Message',"{\"du\":\"gws\",\"zf\":27}",'hmv.co.jp','hmv.co.jp','google.com']]
    # 
    file1="/home/zfk/Documents/process-cookies/taintchrome/cookie_storage_modify_extension/data1.js"
    file2="/home/zfk/Documents/process-cookies/taintchrome/postMessage_extension/data1.js"
    # file1 = CONFIG.storage_data_file
    # file2 = CONFIG.message_data_file
    open(file1, 'a').close()
    open(file2, 'a').close()
    with open(file1, 'r+') as f1, open(file2, 'r+') as f2:
        save_to_data(joint_matches,f1,f2, file1, file2)
        save_to_data(joint_matches2,f1,f2, file1, file2)
