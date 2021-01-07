import os
import glob
import yaml
import __main__

GADGET_FOLDER = os.path.join(os.path.dirname(__file__), 'gadgets')

MAJOR = 0
MINOR = 1
PATCH = 0
VERSION = '{0}.{1}.{2}'.format(MAJOR, MINOR, PATCH)

AUTHOR = 'Daniel Uroz'
EMAIL = 'duroz@unizar.es'

TOOL_NAME = os.path.basename(os.path.realpath(__main__.__file__))

HEADER = '\
                          .d8888b.  \n\
                         d88P  Y88b \n\
                              .d88P \n\
888d888 .d88b.  88888b.      8888"  \n\
888P"  d88""88b 888 "88b      "Y8b. \n\
888    888  888 888  888 888    888 \n\
888    Y88..88P 888 d88P Y88b  d88P \n\
888     "Y88P"  88888P"   "Y8888P"  \n\
                888                 \n\
                888                 \n\
                888\n\
\n\
                A tool of RME-DisCo Research Group at University of Zaragoza\
'

def show_version():
    print(HEADER)
    print()
    print('Version: {0} v{1}'.format(TOOL_NAME, VERSION))
    print('Author:  {0} <{1}>'.format(AUTHOR, EMAIL))

def format_gadget(gad):
    #return '[{0} @ {1:#x}]: {2}'.format(os.path.basename(gad['file']), gad['vaddr'], gad['gadget'])
    return '[{0} @ {1:#x}]: {2}'.format(gad['file'], gad['vaddr'], gad['gadget'])

def format_op_gadget(gad):
    ret = format_gadget(gad)

    str_values = ''
    values = gad['values']

    for value in values:
        for key in value.keys():
            str_values += '{0} = {1}'.format(key, hex(value[key]))

        ret = '{0} ({1})'.format(ret, str_values)

    return ret

def format_op_ropchain(op):
    ret = op['data']
    ret += ' ['

    if op['dst']:
        ret += '{0}: {1}'.format(op['dst'], op[op['dst']])
    if op['src']:
        ret += ', {0}: {1}'.format(op['src'], op[op['src']])

    ret += ']'

    return ret

def get_ops():
    ret = {}

    files = get_op_files()

    for file in files:
        # Merge dicts
        ret = {**ret, **read_yaml(file)}

    return ret

def get_op_files():
    return [file for file in glob.glob(os.path.join(GADGET_FOLDER, '**', '*.yaml'), recursive=True) if os.path.isfile(file)]

def read_yaml(file):
    with open(file, 'r') as f:        
        return yaml.safe_load(f.read())

def delete_duplicate_gadgets(gadgets):
    '''
    Deletes all duplicated gadgets

    @param gadgets: a list of gadgets

    @returns a gadgets list without repeated elements
    '''
    gadgets_content_set = set()
    unique_gadgets = []

    for gadget in gadgets:
        gad = gadget['gadget']
        if gad in gadgets_content_set:
            continue
        gadgets_content_set.add(gad)
        unique_gadgets += [gadget]

    return unique_gadgets

def is_x64_qword_reg(reg):
    return reg in ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

def promote_x64_qword_reg(reg):
    to_change = {
        'eax': 'rax',
        'ecx': 'rcx',
        'edx': 'rdx',
        'ebx': 'rbx',
        'esp': 'rsp',
        'ebp': 'rbp',
        'esi': 'rsi',
        'edi': 'rdi'
    }

    try:
        return to_change[reg]
    except KeyError:
        return reg
