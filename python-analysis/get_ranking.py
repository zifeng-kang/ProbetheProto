import os
import numpy as np


def func1():
    with open('/media/data1/zfk/Documents/sanchecker/src/tranco_3Z3L.csv','r') as f1, open('/home/zfk/Documents/sanchecker/src/website_reports_vul_0to600kplus.txt','r') as f2, open('top_30_vul_websites.txt','w') as f3, open('wp-content_sites.txt','w') as f4:
        l1=f1.readlines()
        l2=f2.readlines()
        list=[]
        col=[]
        for i in l1:
            list.append(i.split(',')[1].replace('\n',''))
            #print(i.split(',')[1])
        for i in l2:
            if 'wp-' in i:
                f4.write(i)
            site=i.split('|')[0].replace(' ','')
            ranking=list.index(site)
            col.append([ranking,site])
        
        col=np.array(col)
        col =col[col[:, 0].astype(np.int).argsort()]
        for num, i in enumerate(col, 1):
            if num==100:
                break
            for j in l2:
                site=j.split('|')[0].replace(' ','')
                if site==i[1]:
                    f3.write(j)
                    break


def func2():
    with open('wp-content_sites.txt','r') as f:
        l=f.readlines()
        col=[]
        for i in l:
            li=i.split('/')
            if 'wp-content' in li:
                col.append(li[li.index('wp-content')+1]+'/'+li[li.index('wp-content')+2])
        col=set(col)
        col=list(col)
        print(col)











if __name__ == "__main__":
    func2()