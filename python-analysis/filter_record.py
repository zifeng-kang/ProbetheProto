from tqdm import tqdm
from fuzzywuzzy import fuzz, process
import subprocess

Sources = ['url', 'untainted', 'cookie', 'urlHostname', 'urlOrigin', 'storage', 'urlPathname', 'message', 'windowname', 'referrer', 'urlSearch']
Sink_type = ['anchorSrcSink', 'scriptSrcUrlSink', 'imgSrcSink', 'cookie', 'iframeSrcSink', 'javascript', 'html']
target_sink = ['html', 'javascript']
target_source = ['url', 'urlHostname', 'urlOrigin', 'urlPathname', 'urlSearch', 'urlHost', 'urlHash']


def Read_record():
    count = 0
    stage = 0
    content_list = []
    total_content_list = []
    sink_func = ''
    sinkType = ''
    msgid_content = {}
    sinkType_list = []
    taintSource_flag = False
    Sink_type_flag = False
    taintSource = []
    f = open('../crawl/record_all_helpshift_com')
    lines = f.readlines()
    for (index, line) in enumerate(lines):
        line = line.strip().replace('\"', '"').replace("\'", "'").replace("\\\'", "'").replace('\\\"', '"')
        # start
        if line == '( message = (':
            stage = 0.5
            taintSource_flag = False
            Sink_type_flag = False
            taintSource = []
        # taintSource
        if stage == 0.5 and 'taintSource = (' in line:
            stage = 0.6
        if stage == 0.6 and 'type = ' in line:
            start_index = line.index('type = ')
            end_index = 0
            if 'encoding' in line:
                end_index = line.index('encoding')-2
            else:
                end_index = line.rindex(',')
            label = line[start_index+len('type = '):end_index]
            if label in target_source:
                taintSource_flag = True
                if label not in taintSource:
                    taintSource.append(label)
        # next stage
        if stage == 0.6 and 'targetString =' in line:
            stage = 1
        # append content
        if stage == 1 and 'content = ' in line:
            start_index = line.find('content = ')
            end_index = line.rfind('\",')
            content = str(line[start_index+len('content = ')+1:end_index])
            content_list.append(content)
        # judge js type
        # if stage == 1 and 'sinkType = javascript' in line:
        if stage == 1 and 'sinkType = ' in line:
            stage = 2
            count = count + 1
            start_index = line.index('=')
            end_index = line.rindex(',')
            sinkType = line[start_index+2:end_index]
            if sinkType not in Sink_type:
                Sink_type.append(sinkType)
            sinkType_list.append(line[start_index+2:])
            if sinkType in target_sink:
                Sink_type_flag = True
        # find sink type
        if stage == 2 and 'stackTrace = ' in line:
            if '0: builtin exit frame: ' in line:
                stage = 3
                start_index = line.find('0: builtin exit frame: ')
                end_index = line.find('1:')
                sink_func = line[start_index + len('0: builtin exit frame: '):end_index]
                sink_func = sink_func.strip()
            if '0: builtin exit frame: ' not in line:
                sink_func = 'unknown'
                stage = 3

        if (stage == 3 and 'messageId = ' in line) and (taintSource_flag == True) and (Sink_type_flag == True):
            start_index = line.find('messageId = ')
            end_index = line.rfind('\",')
            msgid = int(line[start_index+len('messageId = '):end_index])
            #print('message id: ', msgid)
            msgid_content[msgid] = ["".join(content_list), sinkType, sink_func, taintSource]
            total_content_list.append("".join(content_list))
        # end
        if line == 'contextId = (':
            stage = 0
            content_list = []

    return msgid_content, count, total_content_list, sinkType_list

def output(data):
    index = 0
    with open('../crawl/find_proper_record_all_helpshift_com.txt', 'w+') as fp:
        # msgid_content[msgid] = ["".join(content_list), sinkType, sink_func, taintSource]
        for key, value in results.items():
            # print(value[0])
            fp.write('# '+str(index))
            fp.write('\n')
            fp.write('message id:')
            fp.write('\n')
            fp.write(str(key))
            fp.write('\n')
            fp.write('sinkType: ')
            fp.write('\n')
            fp.write(str(value[1]))
            fp.write('\n')
            fp.write("taintSource: ")
            fp.write('\n')
            fp.write(str(value[3]))
            fp.write('\n')
            fp.write("sink function: ")
            fp.write('\n')
            fp.write(str(value[2]))
            fp.write('\n')
            fp.write('content: ')
            fp.write('\n')
            fp.write(str(value[0]))
            fp.write('\n')
            fp.write('\n')
            index = index + 1

if __name__ == '__main__':
    try:
        cmd = 'rm find_proper_record.txt'
        subprocess.run(cmd.split(' '), check=True)
    except Exception as e:
        pass
    # global count
    results, contend_count, all_content, sinkType_list = Read_record()
    #print('All content: ')
    #for index, cont in enumerate(all_content):
     #   print(index, ": ", cont)

    output(results)

    print('All content length: ', len(all_content))
    #find_eachinfo(results)
    #print('count: ')
    print(Sources)
    print(Sink_type)



