import os, codecs
from pprint import pprint
# import numpy as np
import matplotlib.pyplot as plt

def key_generator(query_max:int, query_interval:int, unit='k'):
    key_list = [(max(1, query_interval*i), min(query_max, query_interval*(i+1))) for i in range(int(query_max/query_interval))]
    return [str(each[0]) + '~' + str(each[1]) + 'k' for each in key_list]

def count_popular_top_rankings(db_file:str, read_file:str, write_file:str, query_max:int, query_interval:int, mode="url"):
    db_dict = {}
    # db_list = [[] for i in range(int(query_max/query_interval))]
    result_list = [0 for i in range(int(query_max/query_interval))]
    query_list = []
    with open(read_file, 'r') as f1:
        read_contents = f1.read()
        for idx, line in enumerate(read_contents.split('\n')):
            query_list.append(line.split(',')[-1])

    with open(db_file, 'r') as f0:
        db_contents = f0.read()
        for idx, line in enumerate(db_contents.split('\n')[:query_max*1000+1]):
            site = line.split(',')[-1]
            if site in query_list:
                kk = int(idx / (query_interval * 1000))
                result_list[kk] += 1

    print(sum(result_list))
    pprint(result_list)

    bb = [0 for i in range(len(result_list))]
    cc = [0 for i in range(len(result_list))]
    plt.hist((result_list, bb, cc))
    plt.xlabel('Top ranking / 20k sites')
    plt.ylabel('Counts')
    plt.savefig(write_file)
    

if __name__ == "__main__":
    write_root_path = "/home/zfk/Documents/sanchecker/src/"
    read_root_path = "/home/zfk/Documents/sanchecker/src/"

    write_file = '3hist.png'
    read_file = "vul_to_url_websites_pattern1_0to200k.txt"
    db_file = "tranco_3Z3L.csv"
    count_popular_top_rankings(os.path.join(read_root_path, db_file), \
        os.path.join(read_root_path, read_file), \
        os.path.join(write_root_path, write_file), \
        200, 20)