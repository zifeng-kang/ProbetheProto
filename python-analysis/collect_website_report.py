import os
import glob
import mmap
import all_vul_websites
from selenium import webdriver
import json
import time
from selenium.webdriver.firefox.options import Options as FirefoxOptions

#decode results in /home/zfk/Documents/sanchecker/src/vul_to_url_websites_pattern1_0to600kplus.txt
def getdecode():
    with open('/home/zfk/Documents/sanchecker/src/vul_to_url_websites_pattern1_0to600kplus.txt','r') as f, open('/home/zfk/Documents/sanchecker/src/vul_to_url_websites_cleaned_0to600kplus.txt','w') as f2:
        Lines = f.readlines()
        for l in Lines:
            l=l.split(',')[1]
            l=l.replace('.','_', 1)
            l=l.replace('\n','')
            os.chdir("/home/zfk/Documents/sanchecker/check_pp_pattern1_0to600kplus_crawl")
            max = 0 #float('-inf')
            mf = None
            for file in glob.glob(l+"_*"):
                # if not add '_', will mix e.g. 'docusign_com.au' and 'docusign_com'
                if max<=os.path.getsize(file):
                    max=os.path.getsize(file)
                    mf = file
            if mf:
                f2.write(mf+'\n')
            else:
                print('Alert! {} has no matches'.format(l))
                #print(mf)
            
#search for valie key strings
def search():
    array=[]
    nosink=[]
    os.chdir('/home/zfk/Documents/sanchecker/record_new_check_pp_pattern1_0to600kplus_crawl')
    for file in glob.glob("*"):
        with open(file,'r') as f:
            r=f.readlines()
            for num, line in enumerate(r, 1):
                if 'sinkType = prototype' in line:
                    if '(content = "testv", isOneByte = true) ] ),' in r[num-3]:
                        z=file.split('_')
                        name='.'.join(z[1:len(z)-3])
                        if 'segments = [' in r[num-4]:
                            #print(r[num-5])
                            if 'targetString = (' in r[num-5]:
                                s=r[num+1]
                                start=s.index('1:')
                                end=s.index('] [')
                                t=s[start+3:end].split('[')
                                functName=t[0].replace(' ','')
                                st=t[1].split(':')
                                if len(st)==3:
                                    jsName=st[0]+st[1].replace(' ','')
                                else:
                                    jsName=st[0].replace(' ','')
                                lineNum=st[len(st)-1].replace(' ','')
                                temp=[name,functName,jsName,lineNum]
                                if "--------- s o u r c e   c o d e ---------" in s:
                                    start=s.index('--------- s o u r c e   c o d e ---------')
                                    try:
                                        end=s.index('-------',start+42,len(s)-1)
                                        temp.append(s[start+43:end])
                                    except:
                                        temp.append(s[start+43:len(s)-1])
                                array.append(temp)
                                break
                elif num==len(r):
                    nosink.append(file)
                    break
    with open('/home/zfk/Documents/sanchecker/src/website_reports_vul_0to600kplus.txt','w') as out:
        for i in array:
            out.write(' | '.join(i)+'\n')
    with open('/home/zfk/Documents/sanchecker/src/website_reports_vul_0to600kplus_no_sink.txt','w') as out:
        for i in nosink:
            out.write(i+'\n')
                    
                
def is_slice_in_list(s,l):
    len_s = len(s) #so we don't recompute length of s on every iteration
    return any(s in l[i:len_s+i] for i in range(len(l) - len_s+1))

def add_to_flowstocheck():
    with open('/home/zfk/Documents/sanchecker/src/0626_flows_to_check.log','r') as f:
        d=f.readlines() 
    with open('/home/zfk/Documents/sanchecker/src/website_reports_vul_0to600kplus.txt','r') as f:
        data=f.readlines()
        l=[]
        for i in data:
            for j in d:
                try:
                    f1=j.split('www.')[1]
                    f1=f1.split('/')[0]
                    f2=i.split('|')[0]
                    if f1==f2.replace(' ',''):
                        i=i+"\n\t"+j.replace('URL is:  ','')
                except:
                    pass
            l.append(i)
    with open('/home/zfk/Documents/sanchecker/src/flowstocheck.txt','w') as f:
        for i in l:
            f.write(i+'\n')


def gettop1mfile():
    with open('/home/zfk/Documents/sanchecker/src/vul_to_url_websites_cleaned_0to1mkplus.txt','w') as f2:
        os.chdir("/home/zfk/Documents/sanchecker/record_check_pp_pattern1_0to1m_crawl")
        l=[]
        for file in glob.glob("*"):
            t=file.split('_')
            te=t[1]+"_"+t[2]
            l.append(te)
        l=set(l)
        l=list(l)
        for i in l:
            max = 0 #float('-inf')
            mf = None
            for file in glob.glob("*"+i+"_*"):
                # if not add '_', will mix e.g. 'docusign_com.au' and 'docusign_com'
                if max<=os.path.getsize(file):
                    max=os.path.getsize(file)
                    mf = file
            if mf:
                print("good")
                f2.write(mf+'\n')
            


def search1mil():
    array=[]
    nosink=[]
    l=[]
    with open('/home/zfk/Documents/sanchecker/src/vul_to_url_websites_cleaned_0to1mkplus.txt','r') as f1:
        l=f1.readlines()

    for file in l:
        t=file.replace('\n','')
        os.chdir('/home/zfk/Documents/sanchecker/record_check_pp_pattern1_0to1m_crawl')
        with open(t,'r') as f:
            r=f.readlines()
            for num, line in enumerate(r, 1):
                if 'sinkType = prototype' in line:
                    if '(content = "testv", isOneByte = true) ] ),' in r[num-3]:
                        z=file.split('_')
                        name='.'.join(z[1:len(z)-3])
                        if 'segments = [' in r[num-4]:
                            #print(r[num-5])
                            if 'targetString = (' in r[num-5]:
                                try:
                                    s=r[num+1]
                                    start=s.index('1:')
                                    end=s.index('] [')
                                    t=s[start+3:end].split('[')
                                    functName=t[0].replace(' ','')
                                    st=t[1].split(':')
                                    if len(st)==3:
                                        jsName=st[0]+st[1].replace(' ','')
                                    else:
                                        jsName=st[0].replace(' ','')
                                    lineNum=st[len(st)-1].replace(' ','')
                                    temp=[name,functName,jsName,lineNum]
                                    if "--------- s o u r c e   c o d e ---------" in s:
                                        start=s.index('--------- s o u r c e   c o d e ---------')
                                        try:
                                            end=s.index('-------',start+42,len(s)-1)
                                            temp.append(s[start+43:end])
                                        except:
                                            temp.append(s[start+43:len(s)-1])
                                    array.append(temp)
                                    break
                                except:
                                    pass
                elif num==len(r):
                    nosink.append(file)
                    break
    with open('/home/zfk/Documents/sanchecker/src/website_reports_vul_0to1mplus.txt','w') as out:
        for i in array:
            out.write(' | '.join(i)+'\n')
    with open('/home/zfk/Documents/sanchecker/src/website_reports_vul_0to1mplus_no_sink.txt','w') as out:
        for i in nosink:
            out.write(i+'\n')


def getcategory():
    v=all_vul_websites.vul_sites.values()
    l=[]
    for i in v:
        l=l+i
    d=dict()
    for i in l:
        options = FirefoxOptions();
        options.add_argument("--headless")
        with webdriver.Firefox(executable_path='/home/zfk/Documents/sanchecker/src/geckodriver',options=options) as driver:
            print('https://sitereview.bluecoat.com/#/lookup-result/'+i)
            driver.get('https://sitereview.bluecoat.com/#/lookup-result/'+i)
            time.sleep(3)
            elem = driver.find_elements_by_xpath("//*[@class='clickable-category']")
            if len(elem) > 0:
                te=elem[0].text
                if te in d:
                    d[te]=d[te]+1
                else:
                    d[te]=1
            
    with open('categories.json','w') as f:
        json.dump(d,f)

if __name__ == "__main__":
    # getdecode()
    getcategory()
