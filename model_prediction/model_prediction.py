import json
import os
import copy
import sys

# get the midlevel files
def get_model_prediction_from_sol(dir, suffix):
    res = []
    for root, directory, files in os.walk(dir):
        for filename in files:
            name, suf = os.path.splitext(filename)
            if suf == suffix:
                find = os.path.join(root, filename)
                if filename.startswith('test') or filename.startswith('0x'):
                    # "slither test30.sol --print  model-prediction-reen > 111.json"
                    os.system("slither " + find + ' --print  model-prediction-dele > ./slither_save_dele/' + filename.replace('.sol', '.json'))   
                    os.system("slither " + find + ' --print   model-prediction-reen > ./slither_save_reen/' + filename.replace('.sol', '.json'))
                    os.system("slither " + find + ' --print  model-prediction-tx > ./slither_save_tx/' + filename.replace('.sol', '.json'))         
    return res

def compile_all_sol(dir, suffix):
    res = []
    compile_template = "solc --combined-json abi,bin,bin-runtime,srcmap,srcmap-runtime,ast contracts/e2.sol > contracts/e2.sol.json"
    for root, directory, files in os.walk(dir):
        for filename in files:
            name, suf = os.path.splitext(filename)
            if suf == suffix:
                # find = os.path.join('./contracts', filename)
                get_compile_command = compile_template.replace('e2.sol', filename)
                os.system(get_compile_command)
                # res.append(find)
    return res



def static_process_phase():
    get_model_prediction_from_sol("./contracts", '.sol')
    compile_all_sol("./contracts", '.sol')
