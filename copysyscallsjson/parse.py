import json
import os
import sys

def parse_json(json_file):
    with open(json_file, 'r') as f:
        data = json.load(f)
    return data


json_file = sys.argv[1]
data = parse_json(json_file)
data = data['syscalls']
for key in data:
    i = 0;
    print("{",key['number'],", \"", key['name'],'", ',len(key['signature']),', {', end='', sep='')
    for arg in key['signature']:
        # print('"', end='')
        line = arg.split()
        argname = line[-1]
        line.pop(-1)
        if "*" in argname:
            line.insert(1,"*")
        arg = ' '.join(line)
        i += 1
        print(arg, end='')
        
        if i < len(key['signature']):
            print(', ', end='')
    print('}}, \\') 
    # print('\n') 