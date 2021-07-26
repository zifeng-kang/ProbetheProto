
class CONFIG:
    debug = False
    # debug = True
    generating_exploits = False
    write_to_txt_files = False
    statistic_mode = '__proto__'

    stem = "/home/zfk/Documents/sanchecker/src/"
    recursive_pp_log_dir = "recursive_pp_key1key2_0to600kplus_logs" #"recursive_pp_pattern1_0to600kplus_logs"
    # recursive_pp_log_dir = "recursive_pp_pattern1_0to600kplus_logs"
    # recursive_pp_log_dir = "recursive_pp_key1key2_600kto1m_logs"
    # check_pp_log_dir = "check_pp_pattern1_0to200k_logs"
    check_pp_log_dir = "check_pp_pattern1_0to600kplus_logs" 
    check_pp_log_dir_2 = "check_pp_pattern1_600kto1m_logs"
    # check_pp_log_dir = "postMessage_flows_0to1m_logs"
    # check_pp_log_dir = "modify_cookie_pp_0to1m_logs"
    check_cookie_message_log_dir = "real_vul_cookie_message_0to600kplus_logs"
    website_set_txt = "website_set_pp_0to600kplus.txt"
    large_file_read_lines_limit = 20000000

    count_flow_log_file = {
        'key1key2': '0705_key1key2_count_flow_600kto1m.py', 
        'proto': '0716_proto_count_object_san_flows_0to1m.py', #'0714_proto_count_flow_cookie_storage_0to1m.py', #'0714_proto_count_flow_message_0to1m.py', 
        'cookie': '0630_cookie_count_flow_0to600kplus.py'
    }

    if_make_storage_data_js_empty = False
    if_make_message_data_js_empty = False
    # storage_log_relative_path = "cookie_log_0to600kplus_logs"
    storage_log_relative_path = "cookie_log_600kto1m_logs"
    # storage_data_file = "/home/zfk/Documents/process-cookies/taintchrome/cookie_storage_modify_extension/storage_data.js"
    storage_data_file = "/home/zfk/Documents/process-cookies/taintchrome/cookie_storage_modify_extension/storage_data_new.js"
    # message_log_relative_path = "message_log_0to600kplus_logs"
    message_log_relative_path = "message_log_600kto1m_logs"
    # message_data_file = "/home/zfk/Documents/process-cookies/taintchrome/postMessage_extension/message_data.js"
    message_data_file = "/home/zfk/Documents/process-cookies/taintchrome/postMessage_extension/message_receiver_data.js"

    if not generating_exploits:
        if_make_storage_data_js_empty = False
        if_make_message_data_js_empty = False
    else:
        write_to_txt_files = False
    
    ppExploitFOUND_str = "ppExploitFOUND"
    objTainted_str = "ObjTaintedDueToTaintKey!"
    objTainted_terminate_line_startswith = " KeyTaintType"
    ppfound_str = 'ppFOUND!'
    prototype_addr_str = ' - prototype = '
    STORAGE_LOGGING_STR = "LOGGING:"
    MESSAGE_LOGGING_STR = "Received message: "
    MESSAGE_ORIGIN_START_STR = ' Received from: '
    MESSAGE_RECEIVER_STR = ' Receiver: '
    # MESSAGE_ISOBJECT_STR = ' IsObject? '

    OBJ_PROTO_PROP = '''
   #__defineGetter__: 0x358f9ea0e871 <JS Function __defineGetter__ (SharedFunctionInfo 0x2c4854d84649)> (data constant)
   #__defineSetter__: 0x358f9ea0e8b9 <JS Function __defineSetter__ (SharedFunctionInfo 0x2c4854d84759)> (data constant)
   #hasOwnProperty: 0x358f9ea089b1 <JS Function hasOwnProperty (SharedFunctionInfo 0x2c4854d84869)> (data constant)
   #__lookupGetter__: 0x358f9ea0e901 <JS Function __lookupGetter__ (SharedFunctionInfo 0x2c4854d84969)> (data constant)
   #__lookupSetter__: 0x358f9ea0e949 <JS Function __lookupSetter__ (SharedFunctionInfo 0x2c4854d84a79)> (data constant)
   #propertyIsEnumerable: 0x358f9ea0e991 <JS Function propertyIsEnumerable (SharedFunctionInfo 0x2c4854d84b89)> (data constant)
   #constructor: 0x358f9ea04831 <JS Function Object (SharedFunctionInfo 0x2c4854d45cc9)> (data constant)
   #toString: 0x358f9ea089f9 <JS Function toString (SharedFunctionInfo 0x2c4854d8ea41)> (data constant)
   #toLocaleString: 0x358f9ea0e9d9 <JS Function toLocaleString (SharedFunctionInfo 0x2c4854d44ee9)> (data constant)
   #valueOf: 0x358f9ea0ea21 <JS Function valueOf (SharedFunctionInfo 0x2c4854d44fe1)> (data constant)
   #isPrototypeOf: 0x358f9ea0ea69 <JS Function isPrototypeOf (SharedFunctionInfo 0x2c4854d45099)> (data constant)
   #__proto__: 0x358f9ea0eab1 <AccessorPair> (accessor constant)'''
    OBJ_PROTO_PROP = [each.split(':')[0] for each in OBJ_PROTO_PROP.split('\n') if each]

    check_other_prototype = True
    OTHER_PROTOTYPE = ['HTMLDivElement', 'HTMLIFrameElement']

    key1 = {'check': ["__proto__", "prototype"], 'origin': "KEY1"} #"constructor", 
    key2 = {'check': ["testk", "Cookie_testk", "Message_testk"], 'origin': "KEY2"}
    value = {'check': ["testv", "Cookie_testv", "Message_testv"], 'origin': "VALUE0"}

    TaintType = ['Cookie',
    'Message',
    'MultipleTaints',
    'Referrer',
    'Storage',
    'UnknownTaintError:11', # URL pathname
    'UnknownTaintError:12', # URL search
    'UnknownTaintError:5', # URL hash
    'UnknownTaintError:7', # URL host
    'UnknownTaintError:8', # URL hostname
    'UnknownTaintError:9', # URL origin
    'UnknownTaintError:6', # URL protocol
    'UnknownTaintError:10', # URL port
    'Url',
    'UnknownTaintError:13', # DOM
    'UnknownTaintError:17', # Network
    'UnknownTaintError:19', # Message origin
    'WindowName']

    priority_taintType = ['URL',
    'URL search',
    'URL hash', 
    'Cookie',
    'Message',
    'Referrer',
    'Storage',
    'URL pathname', 
    'URL host', 
    'URL hostname', 
    'URL origin', 
    'URL protocol', 
    'URL port', 
    'window.name',
    'Multiple',
    'DOM', 
    'Network',
    'Message origin'
    ]

    refactor_dict = {
    'UnknownTaintError:11': 'URL pathname', # URL pathname
    'UnknownTaintError:12': 'URL search', # URL search
    'UnknownTaintError:5': 'URL hash', # URL hash
    'UnknownTaintError:7': 'URL host', # URL host
    'UnknownTaintError:8': 'URL hostname', # URL hostname
    'UnknownTaintError:9': 'URL origin', # URL origin
    'UnknownTaintError:6': 'URL protocol', # URL protocol
    'UnknownTaintError:10': 'URL port', # URL port
    'UnknownTaintError:13': 'DOM', 
    'UnknownTaintError:17': 'Network',
    'UnknownTaintError:19': 'Message origin', 
    'Cookie': 'Cookie',
    'Message': 'Message',
    'MultipleTaints': 'Multiple',
    'Referrer': 'Referrer',
    'Storage': 'Storage',
    'Url': 'URL',
    'WindowName': 'window.name', 
    'ObjTaintedDueToTaintKey!': 'Message' # Unexpected case
    }

    query_string_type_list = ['Url', 'UnknownTaintError:12',  'Referrer']#, 'UnknownTaintError:5']

    storage_number_dict = {
        -1: 'Cookie', 
        0: 'sessionStorage', 
        1: 'localStorage'
    }

    sanitizer_dict = {
        'key1': {
            'Cookie': ['utag_main'], 
            'Message': []
        }, 
        'key2': {
            'Cookie': [], 
            'Message': []
        }, 
        'value': {
            'Cookie': [], 
            'Message': []
        }
    }

    types_with_sanitizer = ['Cookie', 'Message']

    log_file_blacklist = ['userwise_io_log_file', 'tgw_com_log_file', 'shopbetreiber-blog_de_log_file']
    
    temp_target_sites = [each.replace('.','_',1)+'_log_file' for each in \
        "elancontrolsystems.com, octoperf.com, uconnectlabs.com, sixthman.net, rockettheme.com".split(', ') ]
    # [
        
    #     'tgw.com' #, 
    #     # 'benarnews.org', 
    #     # 'porzellantreff.de',
    #     # 'alliai.com',
    #     # 'yankeecandle.co.uk',
    #     # 'andor.com'
    # ]]