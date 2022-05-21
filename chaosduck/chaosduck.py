import sys, os, shlex, time, csv, shutil, traceback, random, argparse, multiprocessing.pool
from elftools.elf.elffile import ELFFile
from elftools.common.exceptions import ELFError
from capstone import *
from capstone.x86 import *
from pathlib import Path
from subprocess import Popen,PIPE,TimeoutExpired
from multiprocessing import Pool
from functools import partial
import numpy as np
import pandas as pd

sys.path.insert(1, 'swifitool') # use swifitool folder for file exports

from faults_inject import ExecConfig
from faults.jbe import JBE
from faults.jmp import JMP
from faults.z1b import Z1B
from faults.z1w import Z1W
from faults.nop import NOP
from faults.flp import FLP

class NoDaemonProcess(multiprocessing.Process):
    # make 'daemon' attribute always return False
    def _get_daemon(self):
        return False
    def _set_daemon(self, value):
        pass
    daemon = property(_get_daemon, _set_daemon)

class MyPool(multiprocessing.pool.Pool):
    Process = NoDaemonProcess


def create_temperature_readings():
    file_object = open('temp_readings.txt', 'w')
    for num in range(0,200000):
        temp = random.randint(-30, 100)
        file_object.write(str(temp) + "\n")
    file_object.close()

def create_light_readings():
    file_object = open('light_readings.txt', 'w')
    for num in range(0,16):
        temp = random.randint(-900, 2250)
        file_object.write(str(temp) + "\n")
    file_object.close()

def extract_x86_instructions(infile):
    print("Disassembling the binary and parsing instructions...\n");
    infile = open(infile, 'rb')
    # ELFFile looks for magic number, if there's none, ELFError is raised
    try:
        elffile = ELFFile(infile)
        parsing = False
        startAddress = 65535
        endAddress = 0
        # all jump instr supported by Intel x86 CPU
        supjumps = ['jne','je','jbe','jae','jb','jo','jmp','ja','jle','js','jc',
        'jcxz','jecxz','jrcxz','jg','jge','jl','jle','jna','jnae','jnbe','jnc',
        'jng','jnge','jnl','jnle','jno','jnp','jns','jnz','jp','jpe','jpo','jz']
        jumps = []  # array for jmp instructions
        cmpsmovs = []   # array for cmp and mov instructions
        allinstr = []   # all instructions' addresses and their size in bytes
        for section in elffile.iter_sections():
            ops = section.data()
            addr = section['sh_addr']
            name = section.name
            md = Cs(CS_ARCH_X86, CS_MODE_32)
            md.detail = True
            # print("%x\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
            # print("%x:\t%s\t%s\t" %(i.address, i.mnemonic, i.op_str) +
              # ' '.join(format(x, '02x') for x in i.bytes)) # with bytes
            # below code finds and parses only certain elf sections
            # this is consistent with "objdump -S binary" command output
            if name == ".rodata": parsing = False
            elif name == ".init" or parsing:
                parsing = True
                for i in md.disasm(ops, addr):
                    # determine the heap range
                    if i.address < startAddress: startAddress=i.address
                    if i.address > endAddress: endAddress=i.address
                    allinstr.append({'addr':i.address, 'size':i.size})
                    # print("%x\t%s\t%s\t%d" %(i.address, i.mnemonic, i.op_str, i.size))
                    # determine the instruction type and parse accordingly
                    if i.mnemonic in supjumps:  # select only jump instructions
                        if len(i.op_str)==6: # process only simple jumps e.g 0x3eef
                            # print("%x\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
                            type = i.mnemonic
                            jumpfrom = hex(i.address) # 0xdead
                            jumpto = i.op_str   # 0xbeef
                            jump = {'type':type, 'from':jumpfrom, 'to':jumpto}
                            jumps.append(jump)
                    # zero static compare values and static variables
                    elif i.mnemonic == 'cmp' or i.mnemonic =='mov':  # select cmp or mov instructions
                        # print("%x:\t%s\t%s\t%d" %(i.address, i.mnemonic, i.op_str, i.size))
                        lastoperand = i.operands[len(i.operands)-1]
                        operands = i.op_str.split()
                        value = operands[len(operands)-1]
                        # ignore comparisons with zero and values stored in registers
                        if value!='0' and ']' not in value and lastoperand.type!=X86_OP_REG:
                            # print("%x:\t%s\t%s\t%d" %(i.address, i.mnemonic, i.op_str, i.size))
                            size = 0
                            loc = 0
                            if len(value)<=4:   # '0x' + 1 byte i.e. max 255
                                size = 1
                                if 'byte' in operands:
                                    loc = hex(i.address + (i.size - 1))
                                elif 'word' in operands:
                                    loc = hex(i.address + (i.size - 2)) # 2 bytes
                                elif 'dword' in operands:
                                    loc = hex(i.address + (i.size - 4)) # 4 bytes
                            elif len(value)<=6: # '0x' + 2 bytes i.e. uint16_t
                                size = 2
                                if 'word' in operands:
                                    loc = hex(i.address + (i.size - 2)) # 2 bytes
                                elif 'dword' in operands:
                                    loc = hex(i.address + (i.size - 4)) # 4 bytes
                            elif len(value)<=10: # '0x' + 4 bytes i.e. uint32_t or int
                                size = 4
                                if 'dword' in operands:
                                    loc = hex(i.address + (i.size - 4)) # 4 bytes
                            if loc!=0:
                                cmpsmovs.append({'type':i.mnemonic,'size':size,'loc':loc})
        return allinstr, jumps, cmpsmovs
    except ELFError:
        logging.info("%s is invalid elf file" % elffile)

def extract_arm_instructions(infile):
    print("Disassembling the binary and parsing instructions...\n");
    infile = open(infile, 'rb')
    # ELFFile looks for magic number, if there's none, ELFError is raised
    try:
        elffile = ELFFile(infile)
        parsing = False
        startAddress = 65535
        endAddress = 0
        # all ARM branch instructions
        branch_instr = ['b', 'beq', 'bne', 'bcs', 'bhs', 'bcc', 'blo', 'bmi','bpl',
        'bvs', 'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'bl', 'bleq',
        'bllt', 'blx', 'bx', 'bxeq', 'bxne', 'bxcs', 'bxcc', 'bxhi', 'bxls',
        'bxgt', 'bxle']
        jumps = []  # array for jmp instructions
        cmpsmovs = []   # array for cmp and mov instructions
        allinstr = []   # all instructions' addresses and their size in bytes
        for section in elffile.iter_sections():
            ops = section.data()
            addr = section['sh_addr']   # section start address
            offset = section['sh_offset']
            file_offset = addr - offset
            name = section.name
            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
            # below code finds and parses only certain elf sections
            # this is consistent with "objdump -S binary" command output
            if name == ".rodata": parsing = False
            elif name == ".init" or parsing:
                parsing = True
                for i in md.disasm(ops, addr):
                    # determine the heap range
                    if i.address < startAddress: startAddress=i.address
                    if i.address > endAddress: endAddress=i.address
                    allinstr.append({'addr':i.address-file_offset, 'size':i.size})
                    # determine the instruction type and parse accordingly
                    if i.mnemonic in branch_instr:  # select only branch instructions
                        if len(i.op_str)>4: # process proper jump addresses and ignore registers
                            type = i.mnemonic
                            jumpfrom = hex(i.address-file_offset)
                            jumpto = hex(int(i.op_str.split('#')[1],0)-file_offset) # remove # from '#0x14f30'
                            jump = {'type':type, 'from':jumpfrom, 'to':jumpto}
                            jumps.append(jump)
                    # zero static compare values and static variables
                    elif i.mnemonic == 'cmp' or i.mnemonic =='mov':  # select cmp or mov instructions
                        operands = i.op_str.split()
                        op_value = operands[len(operands)-1]
                        # ignore comparisons with zero and values stored in registers
                        if op_value!='#0' and '#' in op_value:
                            val = op_value.split('#')[1]
                            loc = hex(i.address)
                            if len(val)<=4:   # '0x' + 1 byte i.e. max 255
                                size = 1
                            elif len(val)<=6: # '0x' + 2 bytes
                                size = 2
                            cmpsmovs.append({'type':i.mnemonic,'size':size,'loc':loc})
        
        print("Number of jumps: ", len(jumps))
        print("Number of cmpsmovs: ", len(cmpsmovs))
        return allinstr, jumps, cmpsmovs
    except ELFError:
        logging.info("%s is invalid elf file" % elffile)

def copy_original_file(infile):
    print(infile)
    Path("none-extension-multi-faulted-binaries").mkdir(parents=True, exist_ok=True)
    outfile = 'none-extension-multi-faulted-binaries/'
    shutil.copy(infile,outfile)

def inject_jump_faults(jumps,allinstr,infile,arch):
    # General configuration
    config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
    # prepare the fault models
    fm_list = []
    jump_targets = [j['to'] for j in jumps]
    jump_targets = list(dict.fromkeys(jump_targets)) # remove duplicates
    print("The jump_targets array is: ", jump_targets)
    # try valid jump targets from the existing ones
    # for jump in jumps:
    #     for target in jump_targets:
    #         if target!=jump['to']:
    #             try:
    #                 if jump['type'] == ('jmp' or 'b'):
    #                     fault = {'type':jump['type'],'at':jump['from'],
    #                         'from':jump['to'],'to':target,
    #                         'fault':JMP(config, [jump['from'],target])}
    #                 else:
    #                     fault = {'type':jump['type'],'at':jump['from'],
    #                         'from':jump['to'],'to':target,
    #                         'fault':JBE(config, [jump['from'],target])}
    #                 fm_list.append(fault)
    #             except SystemExit:
    #                 pass # skip targets causing out of range erors and move on
    # try setting jump targets to all possible instruction addresses
    # this includes jumping in the middle of an instruction
    for idx,jump in enumerate(jumps):
        for target in allinstr:
            if target['addr']!=jump['to']:
                try:
                    for offset in range(0,target['size']):
                        loc = hex(target['addr']+offset)
                        if jump['type'] == ('jmp' or 'b'):
                            if offset>0:
                                type = jump['type'] + '_middlejmp'
                                print(type)
                                fault = {'type':type,'at':jump['from'],
                                    'from':jump['to'],'to':loc,
                                    'fault':JMP(config,[jump['from'],loc])}
                            else:
                                fault = {'type':jump['type'],'at':jump['from'],
                                    'from':jump['to'],'to':loc,
                                    'fault':JMP(config,[jump['from'],loc])}
                        else:
                            if offset>0:
                                type = jump['type'] + '_middlejmp'
                                fault = {'type':type,'at':jump['from'],
                                    'from':jump['to'],'to':loc,
                                    'fault':JBE(config,[jump['from'],loc])}
                            else:
                                fault = {'type':jump['type'],'at':jump['from'],
                                    'from':jump['to'],'to':loc,
                                    'fault':JBE(config, [jump['from'],loc])}
                        fm_list.append(fault)
                except SystemExit:
                    pass # skip targets causing out of range erors and move on

    print("Number of new binaries with changed jumps: ", len(fm_list))
    # create a folder for faulted binaries
    Path("jmp-extension-multi-faulted-binaries").mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for idx,f in enumerate(fm_list):
        print("Creating jump fault binary ", idx)
        outfile = 'jmp-extension-multi-faulted-binaries/%s_at_%s_from_%s_to_%s' %(f['type'],
        f['at'],f['from'],f['to'])
        shutil.copy(infile,outfile)
        with open(outfile, "r+b") as file:
            f['fault'].apply(file)

def inject_zero_faults(targets,infile,arch):
    # prepare the fault models
    fm_list = []
    for idx,target in enumerate(targets):
        try:
            if target['size'] == 1:
                config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
                fault = {'type':target['type'], 'loc':target['loc'], 'fault':Z1B(config,[target['loc']])}
                fm_list.append(fault)
            else:
                config = ExecConfig(os.path.expanduser(infile), None, arch, target['size'])
                fault = {'type':target['type'], 'loc':target['loc'], 'fault':Z1W(config,[target['loc']])}
                fm_list.append(fault)
        except SystemExit:
            pass # skip targets causing out of range erors and move on
    # print("Number of locations to zero: ", len(targets))
    print("Number of new binaries with zeroed values: ", len(fm_list))
    # create a folder for faulted binaries
    Path("zero-extension-multi-faulted-binaries").mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for idx,f in enumerate(fm_list):
        print("Creating zero fault binary ", idx)
        outfile = 'zero-extension-multi-faulted-binaries/%s_at_%s_zeroed' %(f['type'],f['loc'])
        shutil.copy(infile,outfile)
        with open(outfile, "r+b") as file:
            f['fault'].apply(file)

def inject_nop_faults(targets, infile, arch):
    # prepare the fault models
    fm_list = []
    for idx,target in enumerate(targets):
        try:
            config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
            addr_from = target['addr']
            addr_till = target['addr'] + target['size'] - 1
            noprange = hex(addr_from) + '-' + hex(addr_till)
            #print("From %x till %x = Range %s" %(addr_from,addr_till,range))
            #print("noprange: ", noprange)
            fault = {'range':noprange, 'fault':NOP(config,[noprange])}
            fm_list.append(fault)
        except SystemExit:
            pass # skip targets causing out of range erors and move on
    # print("Number of instructions to be NOPed: ", len(targets))
    print("Number of new binaries with NOPed instructions: ", len(fm_list))
    # create a folder for faulted binaries
    Path("nop-extension-multi-faulted-binaries").mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for idx,f in enumerate(fm_list):
        print("Creating NOP fault binary ", idx)
        outfile = 'nop-extension-multi-faulted-binaries/nop_%s' %f['range']
        shutil.copy(infile,outfile)
        with open(outfile, "r+b") as file:
            f['fault'].apply(file)

def inject_flp_faults(targets, infile, arch):
    # prepare the fault models
    fm_list = []
    for idx,target in enumerate(targets):
        try:
            config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
            addr_from = target['addr']
            for offset in range(0,target['size']):
                loc = hex(addr_from+offset)

                #with static significance bit
                sgnf = random.randint(0,7)
                fault = {'loc':loc, 'sgnf':sgnf, 'fault':FLP(config,[loc,sgnf])}
                fm_list.append(fault)

                # or with varied significance bit
                #for sgnf in range(0,5):
                 #   fault = {'loc':loc, 'sgnf':sgnf, 'fault':FLP(config,[loc,sgnf])}
                  #  fm_list.append(fault)
        except SystemExit:
            pass # skip targets causing out of range erors and move on
    # print("Number of instructions to be FLPed: ", len(targets))
    print("Number of new binaries with FLPed instructions: ", len(fm_list))
    # create a folder for faulted binaries
    Path("flp-extension-multi-faulted-binaries").mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for idx,f in enumerate(fm_list):
        print("Creating flip fault binary ", idx)
        outfile = 'flp-extension-multi-faulted-binaries/flp_at_%s_sgnf_%d' %(f['loc'],f['sgnf'])
        shutil.copy(infile,outfile)
        with open(outfile, "r+b") as file:
            f['fault'].apply(file)

def execute_with_each_input(infile, arch, fault_type, batchsize, faulty_binaries_list, row):
    print("Testing for temperature %s and light %s with index %s" %(row[1], row[2], row[0]))
    func = partial(execute_file, arch, row[1], row[2], fault_type)  # hack to pass more than 1 argument to execute_file function
    for i in range(0, len(faulty_binaries_list), batchsize):
        print("Executing binaries ", i, " : ", i+batchsize)
        batch = faulty_binaries_list[i:i+batchsize]
        with Pool() as pool:
            results = pool.imap(func, batch)
            pool.close()
            try:
                with open("%s_extension_multi_%s_results.csv" %(infile, fault_type), 'a') as csvfile:
                    writer = csv.writer(csvfile, delimiter=',')
                    for idx,res in enumerate(results):
                        writer.writerow([infile, res['filename'], row[0], row[1], row[2], res['stdout'], 
                                        res['stderr'], res['exitcode'], res['timedout'], fault_type.upper()])
            except:
                traceback.print_exc()
                continue

def execute_random_file_with_each_input(infile, arch, fault_type, batch, row):
    print("Testing for temperature %s and light %s with index %s" %(row[1], row[2], row[0]))
    func = partial(execute_file, arch, row[1], row[2], fault_type)  # hack to pass more than 1 argument to execute_file function
    with Pool() as pool:
        results = pool.imap(func, batch)
        pool.close()
        try:
            with open("%s_extension_multi_%s_results.csv" %(infile, fault_type), 'a') as csvfile:
                writer = csv.writer(csvfile, delimiter=',')
                for idx,res in enumerate(results):
                    print("type(res): ", type(res))
                    for item in res.items():
                        print("Key: ", item[0])
                        print("Value: ", item[1])
                    print("-------------------------------------------------------------")
                        
                    writer.writerow([infile, res['filename'], row[0], row[1], row[2], res['stdout'], 
                                    res['stderr'], res['exitcode'], res['timedout'], fault_type.upper()])
        except:
            traceback.print_exc()

def run_faulty_binaries(infile, arch, fault_type, input_data, batchsize):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    '''print("Parsing Data....")
    with np.printoptions(threshold=sys.maxsize):
        temperatures = df['temperature'].to_numpy()'''
    with open("%s_extension_multi_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Temperature', 'Light', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    faulty_binaries_list = os.listdir("%s-extension-multi-faulted-binaries" %(fault_type))
    print("Total binaries to execute: ", len(faulty_binaries_list))
    func_execute_with_each_input = partial(execute_with_each_input, infile, arch, fault_type, 
                                           batchsize, faulty_binaries_list)
    for j in range(0, input_data.shape[0], int(input_data.shape[0]/5)):
        print("Executing inputs ", j, " : ", int(j+(input_data.shape[0]/5)))
        input_batch = input_data[j:j+int((input_data.shape[0]/5))].to_records()
        with MyPool() as input_pool:
            input_results = input_pool.imap(func_execute_with_each_input, input_batch)
            input_pool.close()
            list(enumerate(input_results))

def run_faulty_binaries_random(infile, arch, fault_type, input_data, batchsize):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    '''print("Parsing Data....")
    with np.printoptions(threshold=sys.maxsize):
        temperatures = df['temperature'].to_numpy()'''
    with open("%s_extension_multi_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Temperature', 'Light', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    faulty_binaries_list = os.listdir("%s-extension-multi-faulted-binaries" %(fault_type))
    print("Total binaries to execute: ", len(faulty_binaries_list))
    for j in range(0, input_data.shape[0], int(input_data.shape[0]/5)):
        print("Executing inputs ", j, " : ", int(j+(input_data.shape[0]/5)))
        input_batch = input_data[j:j+int((input_data.shape[0]/5))].to_records()
        try:
            with MyPool() as input_pool:
                i = random.randint(0, len(faulty_binaries_list)-1)
                print("Executing binaries ", i, " : ", i+batchsize)
                batch = faulty_binaries_list[i:i+batchsize]
                func_execute_with_each_input = partial(execute_random_file_with_each_input, infile, arch, fault_type, batch)
                input_results = input_pool.imap(func_execute_with_each_input, input_batch)
                input_pool.close()
                list(enumerate(input_results))
            map(lambda x: faulty_binaries_list.remove(x), batch)
        except:
            traceback.print_exc()
            continue

def execute_file(arch, temperature, light, fault_type, filename):
    if arch=='x86':
        command = '%s-extension-multi-faulted-binaries/%s %s %s' %(fault_type, filename, temperature, light)
    elif arch=='arm':
        command = 'qemu-arm -L /usr/arm-linux-gnueabi/ %s-extension-multi-faulted-binaries/%s %s %s' %(fault_type, filename, temperature, light)
    args = shlex.split(command)
    # p = Popen(args,stdout=PIPE,stderr=PIPE,universal_newlines=True) # extract stdout in a textual utf-8 format
    p = Popen(args,stdout=PIPE,stderr=PIPE) # extract stdout in a binary-like format
    try:
        outs, errs = p.communicate(timeout=3)   # 3 sec
        # print(filename,outs,errs,p.returncode)
        return({'filename':filename,'stdout':outs,'stderr':errs,
            'exitcode':p.returncode,'timedout':False})
    except TimeoutExpired:
        p.kill()
        outs, errs = p.communicate()
        # print(filename,outs,errs,p.returncode)	
        return({'filename':filename,'stdout':outs,'stderr':errs,
            'exitcode':p.returncode,'timedout':True})
    finally:
        p.kill()

def main(argv):

    CLI=argparse.ArgumentParser()
    CLI.add_argument(
        "--filename",
        type=str,
        default='NovaHomeDaemon_Raspi'
    )
    CLI.add_argument(
        "--arch",
        type=str,
        default='arm'
    )
    CLI.add_argument(
        "--fault_list",
        nargs="*",
        type=str,
        default=['none']
    )


    args = CLI.parse_args()
    infile = args.filename
    arch = args.arch
    fault_types = args.fault_list


    if arch=='x86':
        allinstr, jumps, cmpsmovs = extract_x86_instructions(infile)
    elif arch=='arm':
        allinstr, jumps, cmpsmovs = extract_arm_instructions(infile)
    print("Number of detected instructions: ", len(allinstr))


    for fault_type in fault_types:
        print("fault_type: ", fault_type)
        if(fault_type=='none'):
            copy_original_file(infile)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("/media/sf_Code/Intel_Lab_Fault_Annotated.xlsx", sheet_name='No_Fault_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_faulty_binaries(infile, arch, fault_type, input_data, 1)
        if(fault_type=='jmp'):
            inject_jump_faults(jumps,allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("/media/sf_Code/Intel_Lab_Fault_Annotated.xlsx", sheet_name='Fault_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_faulty_binaries(infile, arch, fault_type, input_data, 100)
        if(fault_type=='zero'):
            inject_zero_faults(cmpsmovs,infile,arch)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("/media/sf_Code/Intel_Lab_Fault_Annotated.xlsx", sheet_name='Fault_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_faulty_binaries(infile, arch, fault_type, input_data, 100)
        if(fault_type=='nop'):
            #inject_nop_faults(allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("/media/sf_Code/Intel_Lab_Fault_Annotated.xlsx", sheet_name='No_Fault_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_faulty_binaries_random(infile, arch, fault_type, input_data, 1)
        if(fault_type=='flp'):
            #inject_flp_faults(allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("/media/sf_Code/Intel_Lab_Fault_Annotated.xlsx", sheet_name='Fault_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_faulty_binaries(infile, arch, fault_type, input_data, 100)


if __name__ == '__main__':
    main(sys.argv)
