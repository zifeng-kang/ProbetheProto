from storage_match_utils import traverse_object
from match_configs import CONFIG
from try_match import read_and_match, get_replacement
from generate_exploits import dict_element_refactor
import all_vul_websites
from pprint import pprint
from urllib.parse import urlparse, unquote_plus
import json, ast, os, glob, codecs, re


def test_traverse_object():
    object_aa = {
        'aa': {
            'bb': {
                'cc': {
                    'dd': 'ee'
                }, 
                'key1': {
                    'key2': 'value'
                }
            }
        }, 
        '1':1
    }
    target = 'key1'
    found_object, is_found = traverse_object(object_aa, target)
    print(is_found)
    found_object[get_replacement('key1', 'Message')] = {get_replacement('key2', 'Message'): get_replacement('value', 'Message')}
    found_object["constructor"] = {"prototype": {get_replacement('key2', 'Message'): get_replacement('value', 'Message')}}
    pprint(object_aa)
    print(json.dumps(object_aa))

def find_string_in_file(stem=CONFIG.stem, file_name_pattern='.py', target_str='vul_to_url_websites_pattern1_0to600kplus'):
    for file_name in os.listdir(stem):
        if file_name_pattern in file_name and os.stat(os.path.join(stem, file_name)).st_size != 0:
            with open(os.path.join(stem, file_name), 'r') as f:
                content = f.read()
                if target_str in content:
                    print(file_name)

def refactor_stat_log_file(fpath:str, site_set_idx=3):
    with open(fpath, 'r') as f:
        contents = f.read()
        dictionary = ast.literal_eval(contents)
    # pprint(dict_element_refactor(dictionary))

    # url_search_list = dictionary['UnknownTaintError:12']['UnknownTaintError:12']['UnknownTaintError:12'][-1]
    # url_list = dictionary['Url']['Url']['Url'][-1]
    vul_list = []
    with open('vul_to_url_websites_pattern1_0to600kplus.txt', 'r') as f:
        for line in f.read().split('\n'):
            site = line.split(',')[-1]
            vul_list.append(site)
    # url_vul_list = [each for each in url_list if each in vul_list]
    # fp_list = [each for each in url_list if each not in vul_list]
    # with open('url_0to600kplus_fp.txt', 'w') as out:
    #     out.write('\n'.join(fp_list) + '\n')
    # fn_list = [each for each in vul_list if each not in url_list]
    # with open('url_0to600kplus_fn.txt', 'w') as out:
    #     out.write('\n'.join(fn_list) + '\n')
    # print(len(url_list), len(url_vul_list), len(fp_list))

    site_list_regroup_set = set()
    for key1_type in dictionary.keys():
        for key2_type in dictionary[key1_type].keys():
            for value_type in dictionary[key1_type][key2_type].keys():
                site_set = dictionary[key1_type][key2_type][value_type][site_set_idx]
                # site_list = [each for each in vul_list if each in site_set]
                site_list = [each for each in site_set if each not in vul_list]
                site_list_regroup_set = site_list_regroup_set.union(site_list)
                if site_list:
                    print((key1_type, key2_type, value_type), len(site_list), site_list)
    print(len(vul_list), len(site_list_regroup_set), [each for each in vul_list if each not in site_list_regroup_set])
    with open(os.path.join(CONFIG.stem, '42_websites_url_src_to_pp_again_0to600kplus.txt'), 'w') as ff:
        websites_to_pp = '\n'.join([str(idx+1)+','+each for idx,each in zip(range(len(site_list_regroup_set)),site_list_regroup_set)])
        ff.write(websites_to_pp)

def read_from_storage_data_js(fpath, write_path):
    import json
    with open(fpath, 'r') as fp:
        json1_str = fp.read()
        json1_str=json1_str.replace('var data_to_change =','')
        json1_str=json1_str.rstrip(';')
        json1_data = json.loads(json1_str)
        website_list = list(json1_data.keys())
    websites_to_pp = '\n'.join([str(idx+1)+','+each for idx,each in zip(range(len(website_list)),website_list)])
    with open(write_path, 'w') as fw:
        fw.write(websites_to_pp)
    print('len(website_list): ', len(website_list))

def split_same_diff_msg_origin(fpath):
    with open(fpath, 'r') as fp:
        contents = fp.read()
        msg_dict = ast.literal_eval(contents[len('var data_to_change = '):-1])
    count_dict = {}
    for kk, vv in msg_dict.items():
        msg_origin = vv[0][0]
        if msg_origin not in count_dict.keys():
            count_dict[msg_origin] = []
        count_dict[msg_origin].append(kk)
    pprint(count_dict)

def refactor_msg_data(receiver_path, origin_and_message_write_path, origin_write_path):
    origin_refactor_dict = {
        'https://fast.wistia.net': 'https://auth.wistia.com/session/new?app=wistia', 
        'http://fast.wistia.net': 'https://auth.wistia.com/session/new?app=wistia'
    }
    with open(receiver_path, 'r') as fr:
        contents = fr.read()
        msg_dict = ast.literal_eval(contents[len('var data_to_change = '):-1])
    new_dict, origin_set = {}, set()
    for receiver, msg_info in msg_dict.items():
        for origin, receive_url, msg_str in msg_info:
            # replace the origin name with the 'real' origin name
            if origin in origin_refactor_dict.keys():
                origin = origin_refactor_dict[origin]
            elif 'wistia' in origin:
                print('Weird origin '+origin)
            elif '/' not in origin.replace('https://', '').replace('http://', ''):
                origin = origin + '/'

            origin_set.add(origin)
            if origin not in new_dict.keys():
                new_dict[origin] = {}
                # <receiver>:  {'url': [<receiver_url>], 'message': [<msg_str>]} * n 
            if receiver not in new_dict[origin].keys():
                new_dict[origin][receiver] = {'url':[], 'message':[]}
            receive_url = receive_url.split('/?')[0].rstrip('/') # + '/?__proto__[testk]=testv&__proto__.testk=testv&constructor[prototype][testk]=testv'
            if receive_url not in new_dict[origin][receiver]['url']:
                new_dict[origin][receiver]['url'].append(receive_url)
            if len(new_dict[origin][receiver]['message']) <= 10 and msg_str not in new_dict[origin][receiver]['message']:
                new_dict[origin][receiver]['message'].append(msg_str)

    max_length_dict = {}
    for k1, v1 in new_dict.items():
        temp_list = []
        for k2, v2 in v1.items():
            temp_list.append(len(v2['url'])*(10 + len(v2['message'])*2))
        max_length_dict[k1] = sum(temp_list) #max(temp_list)
    print(max_length_dict)
    print(max(max_length_dict.values()), min(max_length_dict.values()), sum(max_length_dict.values())/float(len(max_length_dict.values())))
    with open(origin_and_message_write_path, 'w') as fo:
        fo.write('var data_to_change = ' + str(new_dict))
    with open(origin_write_path, 'w') as fw:
        fw.write('\n'.join([str(idx+1)+','+each[0]+','+str(60+each[1]) for idx,each in zip(range(len(max_length_dict)),max_length_dict.items())]))
        # the number 6 should change according to new-content.js in postMessage extension

def check_consequence(mode='URL'):
    sinktype_pattern = re.compile('sinkType = (.*),')
    content_pattern = re.compile('content = "(.*)",')
    consq = {'All':0}
    consq_sub = {'All':0}
    prev_pos = 0
    check_site_list = all_vul_websites.URL_vul_sites if mode=='URL' else all_vul_websites.vul_sites[mode]
    # os.chdir('/home/zfk/temp/cookie') #Documents/sanchecker/record_new_check_pp_pattern1_0to600kplus_crawl')
    os.chdir('/home/zfk/Documents/sanchecker/record_check_pp_pattern1_0to1m_crawl')
    vul_website = set()
    for fpath in glob.glob("*"):
        if "record_" in fpath:
            with codecs.open(fpath, mode='r') as ff:
                cont = ff.readlines()
                z = fpath.split('_')
                site = '.'.join(z[1:len(z)-3])
                if site not in check_site_list:
                    continue
                for num, line in enumerate(cont, 1):
                    if 'targetString = (' in line:
                        prev_pos = num
                    elif 'sinkType = ' in line and 'sinkType = prototype' not in line:
                        contents_to_search = ''.join(cont[prev_pos + 1 : num - 3])
                        content_result = content_pattern.finditer(contents_to_search)
                        if content_result:
                            content = ''.join([m.groups()[0] for m in content_result])
                            
                            sinktype_result = sinktype_pattern.search(line)
                            if sinktype_result:
                                sinkType = sinktype_result[1]
                            else:
                                raise ValueError('{} Cannot find sinkType! Line {} {}'.format(site, num, line))
                                continue
                            judge, consequence, sinkType = judge_if_valid(content, sinkType, mode=mode)
                            if judge:
                                # found
                                assert len(consequence) and len(sinkType)
                                
                                if sinkType not in consq.keys():
                                    consq[sinkType] = [[], 0, set()]
                                consq[sinkType][1] += 1
                                consq[sinkType][2].add(site)
                                # consq[sinkType][0].append('{} {} {}'.format(site, num, content))
                                consq['All'] += 1

                                if consequence not in consq_sub.keys():
                                    consq_sub[consequence] = [0, set(), []]
                                consq_sub[consequence][0] += 1
                                consq_sub[consequence][1].add(site)
                                consq_sub[consequence][2].append('{} {} {}'.format(site, num, content))
                                consq_sub['All'] += 1

                                vul_website.add(site)
                        else:
                            raise ValueError('{} Cannot find content! Line {} {}'.format(site, num-3, cont[ num - 3]))
                            continue

    for kk,vv in consq.items():
        if kk != 'All':
            consq[kk][2] = len(vv[2])
    for kk,vv in consq_sub.items():
        if kk != 'All':
            consq_sub[kk][1] = len(vv[1])

    # pprint(consq)
    with open('/home/zfk/Documents/sanchecker/src/0719_consequence_url_0to1m.log', 'w') as f1: #0614_consequence_cookie.log, 0609_consequence_0to600kplus.log
        pprint(consq, f1)
        pprint(consq_sub, f1)
    print(len(vul_website), vul_website)

consq_dict = {
        'anchorSrcSink': 'query', 
        'cookie': 'cookie', 
        'html': 'xss', 
        'javascript': 'xss', 
        'iframeSrcSink': 'query',
        'imgSrcSink': 'query',
        'scriptSrcUrlSink': 'query'
}
k_v_dict = {
    'URL': 'testk=testv', 
    'Message': 'Message_testk=Message_testv', 
    'Cookie': 'Cookie_testk=Cookie_testv'
}
blacklist = ('__proto__[testk]=testv&__proto__.testk=testv&constructor[prototype][testk]=testv&__proto___testk=testv&' + \
    '__proto__[testk]&__proto__.testk&constructor[prototype][testk]&__proto___testk').split('&')
                        
def judge_if_valid(content, sinkType, mode='URL'):
    
    temp_content = content
    counter = 0
    while '%' in temp_content and counter < 10:
        temp_content = unquote_plus(temp_content)
        counter += 1
    for each in blacklist:
        temp_content = temp_content.replace(each, '')
    # if (not ('testk' in temp_content or 'testv' in temp_content or 'loginStatus' in temp_content)): # or any([each for each in blacklist if each in temp_content]): 
    if not ('testk' in temp_content and 'testv' in temp_content):
        return False, '', ''
    
    if sinkType not in consq_dict.keys():
        consq_dict[sinkType] = sinkType
    consequence = consq_dict[sinkType]
    k_v_str = k_v_dict[mode]
    if consequence == 'query':
        if '%' in content:
            content = temp_content #unquote_plus(unquote_plus(content))
        outs = urlparse(content)
        if not outs.path:
            # raise ValueError('{} is not query!'.format(content))
            print(('ValueError {} is not query!'.format(content)))
        q_list = outs.query.split('&')
        if mode == 'Cookie':
            if k_v_str in q_list or 'loginStatus=login' in q_list:
                return True, consequence, sinkType
            else:
                return False, consequence, sinkType
        else:
            if k_v_str in q_list:
                return True, consequence, sinkType
            else:
                return False, consequence, sinkType
    elif consequence == 'xss':
        # TODO: generate exploit strings

        # Not perfect criterion: '%', an indicator of encoding
        if '%' in content or all(each in content for each in ("'", '&#39;')) or all(each in content for each in ('"', '&quot;')):
            return False, '', sinkType
        # Currently, cases are rare, so simply return True
        # counter = 0
        # while '%' in temp_content and counter < 10:
        #     temp_content = temp_content.encode('utf-8').decode('unicode_escape')
        #     counter += 1
        return True, consequence, sinkType
    elif consequence == 'cookie':
        # judge direct or indirect manipulation
        if k_v_str in content.replace(' ', '').split(';'):
            return True, 'direct-cookie', sinkType
        else:
            if '%' in content:
                content = temp_content # unquote_plus(unquote_plus(content))
            
            if mode == 'Cookie':
                pattern = r"[^a-zA-Z]Cookie_testk[^a-zA-Z]+Cookie_testv[^a-zA-Z]"
            elif mode == 'Message':
                pattern = r"[^a-zA-Z]Message_testk[^a-zA-Z]+Message_testv[^a-zA-Z]"
            else:
                pattern = r"[^a-zA-Z]testk[^a-zA-Z]+testv[^a-zA-Z]"
            judge = re.search(pattern, content) #.groups()
            # if judge:
            #     judge = not re.search(pattern, content)
            return not not judge, 'indirect-cookie', sinkType
    else:
        # TODO: other types
        # if '__proto__[testk]' not in temp_content:
        #     return True, consequence, sinkType
        # else:
        #     return False, consequence, sinkType
        print(sinkType, temp_content)
        return True, consequence, sinkType

allow_no_load_time_set = set()

def get_show_time(fpath, time_write_file, recrawl_write_file, mode='add'):
    load_time_dict = {}
    site_to_recrawl = set()
    for each_file in os.listdir(os.path.join(CONFIG.stem, fpath)):
        if 'log_file' in each_file:
            with open(os.path.join(CONFIG.stem, fpath, each_file), 'r') as fr:
                site = each_file.replace('_log_file', '').replace('_', '.', 1)
                for line in fr.readlines():
                    # if 'Codes for showing loading time in' in line:
                    matchs = re.search(r'Loading time for (.*) is: (.*)", source:', line)
                    if matchs:
                        load_time = int(matchs.group(2))
                        load_time_dict[site] = load_time
                        break
                else:
                    if mode == 'add':
                        allow_no_load_time_set.add(site)
                    elif mode == 'check' and site not in allow_no_load_time_set:
                        site_to_recrawl.add(site)
    if mode == 'add':
        print(fpath, len(allow_no_load_time_set))
    else:
        print(fpath, len(site_to_recrawl))
    with open(os.path.join(CONFIG.stem, time_write_file), 'w') as fw:
        fw.write(str(load_time_dict))
    if mode == 'check':
        with open(os.path.join(CONFIG.stem, recrawl_write_file), 'w') as fwr:
            for idx, each_line in zip(range(1, len(site_to_recrawl)+1), site_to_recrawl):
                fwr.write(str(idx)+','+each_line+'\n')

def get_rankings_from_site_list(write_file):
    from all_vul_websites import vul_sites
    write_list = set()
    with open(os.path.join(CONFIG.stem, 'tranco_3Z3L.csv'), 'r') as fr:
        for line in fr.readlines():
            rank, site = line.split(',')
            site = site.rstrip('\n')
            for source_type, vul_site_list in vul_sites.items():
                if site in vul_site_list:
                    log_file_name = site.replace('.', '_', 1) + '_log_file'
                    write_list.add(log_file_name + '==>' + rank + '\n')
                    # for key, value_set in vul_rankings.items():
                    #     if key in source_type:
                    #         vul_rankings[key].add(rank)
    with open(os.path.join(CONFIG.stem, write_file), 'w') as fw:
        for each in write_list:
            fw.write(each)

def generate_appendix(cols=3):
    from consequence_url_0to1m import detail_conseq
    from all_vul_websites import vul_sites
    output_str = ''
    scanned_site_set = set()
    conseq_site_dict = {}
    it = 0

    # pre-process detail_conseq
    for each_key, each_val in detail_conseq.items():
        if 'cookie' in each_key:
            target_type = 'Cookie-M'
        elif 'query' in each_key:
            target_type = 'URL-M'
        elif 'xss' in each_key:
            target_type = 'XSS'
        else:
            continue
        for detail in each_val[-1]:
            matchs = re.search(r'^(.*?) \d', detail)
            site = matchs.group(1)
            if site not in conseq_site_dict.keys():
                conseq_site_dict[site] = set()
            conseq_site_dict[site].add(target_type)

    site_list = sorted([each for each_list in vul_sites.values() for each in each_list])
    # for site_list in vul_sites.values():
    for each_site in site_list:
        if each_site in scanned_site_set:
            continue
        it += 1
        output_str += each_site + ' & '
        
        scanned_site_set.add(each_site)
        if each_site in conseq_site_dict.keys():
            each_conseq = ', '.join(conseq_site_dict[each_site])
        else:
            each_conseq = '-'
        terminator = ' \\\\\n' if it % cols == 0 else ' & '
        output_str += each_conseq + terminator

    print(output_str)
    print(it)

def find_missing_file(fpath, txt_file):
    prefix = "record_"
    files_to_check = []
    with open(txt_file, 'r') as f:
        content = f.read()
        for each in content.split('\n'):
            files_to_check.append(prefix + each)

    for each in os.listdir(fpath):
        if prefix not in each:
            continue
        if each in files_to_check:
            files_to_check.remove(each)
        else:
            print(each)

    print(files_to_check)

if __name__ == "__main__":
    # test_traverse_object()
    # check_consequence()
    generate_appendix()
    # get_rankings_from_site_list('logfile_to_rankings_0to1m.txt')
    # get_show_time('show_load_time_legacy_chrome_1k_logs', 'load-time-legacy-chrome-1k.py', '', mode='add')
    # get_show_time('show_load_time_ppchrome_key1key2_1k_logs', 'load-time-ppchrome-1k.py', 'recrawl-ppchrome-1k.txt', mode='check')
    # get_show_time('show_load_time_ndss18_1k_logs', 'load-time-ndss18-1k.py', 'recrawl-ndss18-1k.txt', mode='check')
    # find_string_in_file()
    # split_same_diff_msg_origin('/home/zfk/Documents/process-cookies/taintchrome/postMessage_extension/message_data.js')
    # read_from_storage_data_js('/home/zfk/Documents/process-cookies/taintchrome/cookie_storage_modify_extension/storage_data_new.js', \
    #     '/home/zfk/Documents/sanchecker/src/websites_to_pp_cookie_storage_0to1m.txt')
    # refactor_msg_data("/home/zfk/Documents/process-cookies/taintchrome/postMessage_extension/message_receiver_data.js", \
    #     "/home/zfk/Documents/process-cookies/taintchrome/postMessage_extension/msg-origin-data-new.js", 
    #     "/home/zfk/Documents/sanchecker/src/msg_origin_to_crawl.txt")
    # refactor_stat_log_file('/home/zfk/Documents/sanchecker/src/0623_proto_count_flow_0to600kplus.py')
    # find_missing_file('/home/zfk/Documents/sanchecker/record_new_check_pp_pattern1_0to600kplus_crawl', '/home/zfk/Documents/sanchecker/src/vul_to_url_websites_cleaned_0to600kplus.txt')
#     temp='''
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "325px"
# HTMLIFrameElement __proto__ c"Message_testk" "347px"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "407px"
# HTMLIFrameElement __proto__ c"Message_testk" "325px"
# HTMLIFrameElement __proto__ c"Message_testk" "347px"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "365px"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "357px"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
# HTMLIFrameElement __proto__ c"Message_testk" "Message_testv"
# HTMLDivElement __proto__ c"Message_testk" "Message_testv"
#     '''
#     print(temp.count('__proto__'), temp.count('HTMLDivElement'), temp.count('HTMLIFrameElement'))
    