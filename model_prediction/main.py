import json
import os
import copy
import sys

template_external_call = "fuzzer --file ./new2501.sol.json --source ./new2501.sol --name Participant --function processPayment -p 111 " \
                         "--externalcall EasySmartolution_processPayment  --assets assets/ --duration 240 --mode 0 " \
                         "--reporter 0 --attacker ReentrancyAttacker\n "
template_internal_call = "fuzzer --file ./new2501.sol.json --source ./new2501.sol --name Participant --function " \
                         "processPayment -p 111 --internalcall addParticipant --assets assets/ --duration 120 --mode 0 --reporter 0 --attacker ReentrancyAttacker \n"


def generate_ex_command(ex_result, file,fileName):
    ex_result.sort()
    for res in ex_result:
        sc = res[0]
        tstr = '111'
        if sc <= 1:
            tstr = '100'
        elif sc <= 10:
            tstr = '010'
        else:
            tstr = '001'
        contractName = res[1]
        functionName = res[2]
        externalCall = res[3]
        command = template_external_call.replace('./new2501.sol', fileName).replace('--name Participant',
                                                                                    '--name ' + contractName).replace(
            '--function processPayment', '--function ' + functionName).replace('EasySmartolution_processPayment',
                                                                               externalCall[0] + '_' + externalCall[
                                                                                   1]).replace('-p 111', '-p ' + tstr)
        # print(command)
        file.write(command)


def generate_in_command(in_result, file,fileName):
    for res in in_result:
        contractName = res[0]
        functionName = res[1]
        internalCalls = res[2]
        tmpstr = ''
        for iter in internalCalls:
            tmpstr = iter + '+' + tmpstr
        if tmpstr == '':
            tmpstr = 'NONE'
        else:
            tmpstr = tmpstr[:-1]

        command = template_internal_call.replace('./new2501.sol', fileName).replace('--name Participant', \
                                                                                    '--name ' + contractName).replace( \
            '--function processPayment', '--function ' + functionName). \
            replace('--internalcall addParticipant', '--internalcall ' + tmpstr)

        # print(command)
        file.write(command)


def generate_commands(file_name, file):
    with open(file_name, 'r') as f:
        fileName = './contracts/' + file_name.split('/')[-1].replace('.json','.sol')
        try:
            data_json = json.load(f)
        except BaseException:
            # print("Parse Json error: " + file_name)
            return

        ex_result = []
        in_result = []
        for key in data_json:
            contractName = key
            for item in data_json[key]:
                functionName = item
                if data_json[key][item]["model_predict"]:
                    # print(data_json[key][item]["func_priority"])
                    internalCalls = []
                    externalCalls = []
                    scores = []
                    pfun = data_json[key][item]['func_priority']
                    scores.append(pfun)
                    for iitem in data_json[key][item]["callers"]:
                        if iitem['type'] != 'undefined':
                            continue
                            # print (iitem['type'])
                            # pcall = (iitem['priority'])
                        elif iitem['type'] == 'internal':
                            internalCalls.append(iitem['function'])
                        elif iitem['type'] == 'external':
                            externalContract = iitem['contract']
                            tmp = [externalContract, iitem['function']]
                            externalCalls.append(tmp)
                            scores.append(iitem['priority'])

                    if len(externalCalls) > 0:
                        for i in range(0, len(scores) - 1):
                            tmpres = [scores[i], contractName, functionName, externalCalls[i]]
                            ex_result.append(tmpres)
                    in_result.append([contractName, functionName, internalCalls])
        f.close()
        generate_ex_command(ex_result, file, fileName)
        generate_in_command(in_result, file, fileName)


def traverse(dir, file):
    res = []
    for root, directory, files in os.walk(dir):
        for filename in files:
            name, suf = os.path.splitext(filename)
            if suf == '.json':
                find = os.path.join(root, filename)
                if True or filename.startswith('test') or filename.startswith('0x'):
                    generate_commands(find, file)
    return res


def generate_all_commands():
    file = open('fuzzing_script', 'w')
    traverse('./slither_save_dele', file)
    traverse('./slither_save_reen', file)
    traverse('./slither_save_tx', file)


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
                    os.system(
                        "slither " + find + ' --print  model-prediction-dele > ./slither_save_dele/' + filename.replace(
                            '.sol', '.json'))
                    os.system(
                        "slither " + find + ' --print   model-prediction-reen > ./slither_save_reen/' + filename.replace(
                            '.sol', '.json'))
                    os.system(
                        "slither " + find + ' --print  model-prediction-tx > ./slither_save_tx/' + filename.replace(
                            '.sol', '.json'))
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


def run():
    static_process_phase()
    generate_all_commands()


run()
