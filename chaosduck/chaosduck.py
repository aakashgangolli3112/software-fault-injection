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
    Path("%s-none-faulted-binaries" %(infile)).mkdir(parents=True, exist_ok=True)
    outfile = "%s-none-faulted-binaries/" %(infile)
    shutil.copy(infile,outfile)

def inject_jump_faults(jumps,allinstr,infile,arch):
    # General configuration
    config = ExecConfig(os.path.expanduser(infile), None, arch, None) # None for outfile and wordsize
    # prepare the fault models
    fm_list = []
    jump_targets = [j['to'] for j in jumps]
    jump_targets = list(dict.fromkeys(jump_targets)) # remove duplicates
    #print("The jump_targets array is: ", jump_targets)
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
    Path("%s-jmp-faulted-binaries" %(infile)).mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for idx,f in enumerate(fm_list):
        print("Creating jump fault binary ", idx)
        outfile = '%s-jmp-faulted-binaries/%s_at_%s_from_%s_to_%s' %(infile, f['type'],
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
    Path("%s-zero-faulted-binaries" %(infile)).mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for idx,f in enumerate(fm_list):
        print("Creating zero fault binary ", idx)
        outfile = '%s-zero-faulted-binaries/%s_at_%s_zeroed' %(infile, f['type'],f['loc'])
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
            print("From %x till %x" %(addr_from,addr_till))
            #print("noprange: ", noprange)
            fault = {'range':noprange, 'fault':NOP(config,[noprange])}
            fm_list.append(fault)
        except SystemExit:
            pass # skip targets causing out of range erors and move on
    # print("Number of instructions to be NOPed: ", len(targets))
    print("Number of new binaries with NOPed instructions: ", len(fm_list))
    # create a folder for faulted binaries
    Path("%s-nop-faulted-binaries" %(infile)).mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for idx,f in enumerate(fm_list):
        print("Creating NOP fault binary ", idx)
        outfile = '%s-nop-faulted-binaries/nop_%s' %(infile, f['range'])
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
    Path("%s-flp-faulted-binaries" %(infile)).mkdir(parents=True, exist_ok=True)
    # Duplicate the input and then apply the faults
    for idx,f in enumerate(fm_list):
        try:
            print("Creating flip fault binary ", idx)
            outfile = '%s-flp-faulted-binaries/flp_at_%s_sgnf_%d' %(infile, f['loc'],f['sgnf'])
            shutil.copy(infile,outfile)
            with open(outfile, "r+b") as file:
                f['fault'].apply(file)
        except:
            continue

def execute_with_each_input_nova(infile, arch, fault_type, batchsize, faulty_binaries_list, row):
    print("Testing for temperature %s and light %s with index %s" %(row[1], row[2], row[0]))
    func = partial(execute_file_nova, "%s-%s-faulted-binaries" %(infile, fault_type), arch, row[1], row[2])
    execute_with_each_input(infile, fault_type, batchsize, faulty_binaries_list, func, row)

def execute_with_each_input_verifypin(infile, arch, fault_type, batchsize, faulty_binaries_list, row):
    print("Testing for card_pin %s and user_pin %s with index %s" %(row[1], row[2], row[0]))
    func = partial(execute_file_verifypin, "%s-%s-faulted-binaries" %(infile, fault_type), arch, row[1], row[2])
    execute_with_each_input(infile, fault_type, batchsize, faulty_binaries_list, func, row)

def execute_with_each_input(infile, fault_type, batchsize, faulty_binaries_list, func, row):
    for i in range(0, len(faulty_binaries_list), batchsize):
        print("Executing binaries ", i, " : ", i+batchsize)
        batch = faulty_binaries_list[i:i+batchsize]
        with Pool() as pool:
            results = pool.imap(func, batch)
            pool.close()
            try:
                with open("%s_%s_results.csv" %(infile, fault_type), 'a') as csvfile:
                    writer = csv.writer(csvfile, delimiter=',')
                    for idx,res in enumerate(results):
                        writer.writerow([infile, res['filename'], row[0], row[1], row[2], res['stdout'], 
                                        res['stderr'], res['exitcode'], res['timedout'], fault_type.upper()])
            except:
                traceback.print_exc()
                continue

def execute_random_file_with_each_input_nova(infile, arch, fault_type, batch, row):
    print("Testing for temperature %s and light %s with index %s" %(row[1], row[2], row[0]))
    func = partial(execute_file_nova, "%s-%s-faulted-binaries" %(infile, fault_type), arch, row[1], row[2])
    execute_random_file_with_each_input(infile, fault_type, batch, func, row)

def execute_random_file_with_each_input_verifypin(infile, arch, fault_type, batch, row):
    print("Testing for card_pin %s and user_pin %s with index %s" %(row[1], row[2], row[0]))
    func = partial(execute_file_verifypin, "%s-%s-faulted-binaries" %(infile, fault_type), arch, row[1], row[2])
    execute_random_file_with_each_input(infile, fault_type, batch, func, row)

def execute_random_file_with_each_input(infile, fault_type, batch, func, row):
    with Pool(processes=1) as pool:
        results = pool.imap(func, batch)
        pool.close()
        try:
             with open("%s_%s_results.csv" %(infile, fault_type), 'a') as csvfile:
                writer = csv.writer(csvfile, delimiter=',')
                for idx,res in enumerate(results):                        
                    writer.writerow([infile, res['filename'], row[0], row[1], row[2], res['stdout'], 
                                    res['stderr'], res['exitcode'], res['timedout'], fault_type.upper()])
        except:
            traceback.print_exc()

def execute_file_nova(dirname, arch, temperature, light, filename):
    if arch=='x86':
        command = '%s/%s %s %s' %(dirname, filename, temperature, light)
    elif arch=='arm':
        command = 'qemu-arm -L /usr/arm-linux-gnueabi/ %s/%s %s %s' %(dirname, filename, temperature, light)
    return execute_file(command, filename)

def execute_file_verifypin(dirname, arch, card_pin, user_pin, filename):
    if arch=='x86':
        command = '%s/%s %s %s' %(dirname, filename, card_pin, user_pin)
    elif arch=='arm':
        command = 'qemu-arm -L /usr/arm-linux-gnueabi/ %s/%s %s %s' %(dirname, filename, card_pin, user_pin)
    return execute_file(command, filename)

def execute_file(command, filename):
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

def run_all_faulty_executables_random_input_nova(infile, arch, fault_type, input_data, batchsize=50):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    with open("%s_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Temperature', 'Light', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    faulty_binaries_list = os.listdir("%s-%s-faulted-binaries" %(infile, fault_type))
    print("Total binaries to execute: ", len(faulty_binaries_list))
    with open("%s_%s_results.csv" %(infile, fault_type), 'a') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        for i in range(0, len(faulty_binaries_list), batchsize):
            print("Executing binaries ", i, " : ", i+batchsize)
            batch = faulty_binaries_list[i:i+batchsize]
            j = random.randint(0, (input_data.shape[0])-1)
            temperature = input_data.iloc[j].temperature
            light = input_data.iloc[j].light
            print("Testing for temperature %s and light %s with index %s" %(temperature, light, i))
            func = partial(execute_file_nova, "%s-%s-faulted-binaries" %(infile, fault_type), arch, temperature, light)
            with Pool(processes=batchsize) as pool:
                results = pool.imap(func, batch)
                pool.close()
                for idx,res in enumerate(results):                        
                    writer.writerow([infile, res['filename'], i, temperature, light, res['stdout'], 
                                        res['stderr'], res['exitcode'], res['timedout'], fault_type.upper()])

def run_faulty_executables_nova(infile, arch, fault_type, input_data, batchsize=50):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    with open("%s_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Temperature', 'Light', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    faulty_binaries_list = os.listdir("%s-%s-faulted-binaries" %(infile, fault_type))
    print("Total binaries to execute: ", len(faulty_binaries_list))
    with open("%s_%s_results.csv" %(infile, fault_type), 'a') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        for index, row in input_data.iterrows():
            print("Testing for temperature %s and light %s with index %s" %(row['temperature'], row['light'], index))
            func = partial(execute_file_nova, "%s-%s-faulted-binaries" %(infile, fault_type), arch, row['temperature'], row['light'])
            for i in range(0, len(faulty_binaries_list), batchsize):
                print("Executing binaries ", i, " : ", i+batchsize)
                batch = faulty_binaries_list[i:i+batchsize]
                with Pool(processes=batchsize) as pool:
                    results = pool.imap(func, batch)
                    pool.close()
                    for idx,res in enumerate(results):                        
                        writer.writerow([infile, res['filename'], index, row['temperature'], row['light'], res['stdout'], 
                                        res['stderr'], res['exitcode'], res['timedout'], fault_type.upper()])

def run_faulty_executables_verifypin(infile, arch, fault_type, input_data, batchsize=50):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    with open("%s_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Card_Pin', 'User_Pin', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    faulty_binaries_list = os.listdir("%s-%s-faulted-binaries" %(infile, fault_type))
    print("Total binaries to execute: ", len(faulty_binaries_list))
    with open("%s_%s_results.csv" %(infile, fault_type), 'a') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        for index, row in input_data.iterrows():
            print("Testing for card_pin %s and user_pin %s with index %s" %(row['card_pin'], row['user_pin'], index))
            func = partial(execute_file_verifypin, "%s-%s-faulted-binaries" %(infile, fault_type), arch, row['card_pin'], row['user_pin'])
            for i in range(0, len(faulty_binaries_list), batchsize):
                print("Executing binaries ", i, " : ", i+batchsize)
                batch = faulty_binaries_list[i:i+batchsize]
                with Pool(processes=batchsize) as pool:
                    results = pool.imap(func, batch)
                    pool.close()
                    for idx,res in enumerate(results):                        
                        writer.writerow([infile, res['filename'], index, row['card_pin'], row['user_pin'], res['stdout'], 
                                        res['stderr'], res['exitcode'], res['timedout'], fault_type.upper()])

def run_fixed_faulty_executables_nova(infile, arch, fault_type, input_data, faulty_binaries_list, batchsize=50):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    with open("%s_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Temperature', 'Light', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    print("Total binaries: ", len(faulty_binaries_list))
    input_batch_size = int(input_data.shape[0]/50)
    for i in range(0, len(faulty_binaries_list), batchsize): 
        for j in range(0, input_data.shape[0], input_batch_size):
            print("Executing inputs ", j, " : ", input_batch_size)
            input_batch = input_data[j : j+input_batch_size].to_records()
            try:
                with MyPool(processes=50) as input_pool:
                    print("Executing binaries ", i, " : ", i+batchsize)
                    batch = faulty_binaries_list[i:i+batchsize]
                    func_execute_with_each_input = partial(execute_random_file_with_each_input_nova, infile, arch, fault_type, batch)
                    input_results = input_pool.imap(func_execute_with_each_input, input_batch)
                    input_pool.close()
                    list(enumerate(input_results))
            except:
                traceback.print_exc()
                continue

def run_fixed_faulty_executables_verifypin(infile, arch, fault_type, input_data, faulty_binaries_list, batchsize=50):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    with open("%s_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Card_Pin', 'User_Pin', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    print("Total binaries: ", len(faulty_binaries_list))
    input_batch_size = int(input_data.shape[0]/50)
    for i in range(0, len(faulty_binaries_list), batchsize): 
        for j in range(0, input_data.shape[0], input_batch_size):
            print("Executing inputs ", j, " : ", input_batch_size)
            input_batch = input_data[j : j+input_batch_size].to_records()
            try:
                with MyPool(processes=50) as input_pool:
                    print("Executing binaries ", i, " : ", i+batchsize)
                    batch = faulty_binaries_list[i:i+batchsize]
                    func_execute_with_each_input = partial(execute_random_file_with_each_input_verifypin, infile, arch, fault_type, batch)
                    input_results = input_pool.imap(func_execute_with_each_input, input_batch)
                    input_pool.close()
                    list(enumerate(input_results))
            except:
                traceback.print_exc()
                continue

def run_random_faulty_executables_nova(infile, arch, fault_type, input_data, batchsize=50):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    with open("%s_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Temperature', 'Light', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    faulty_binaries_list = os.listdir("%s-%s-faulted-binaries" %(infile, fault_type))
    print("Total binaries: ", len(faulty_binaries_list))
    input_batch_size = int(input_data.shape[0]/50)
    for j in range(0, input_data.shape[0], input_batch_size):
        print("Executing inputs ", j, " : ", input_batch_size)
        input_batch = input_data[j : j+input_batch_size].to_records()
        try:
            with MyPool(processes=50) as input_pool:
                i = random.randint(0, len(faulty_binaries_list)-1)
                print("Executing binaries ", i, " : ", i+batchsize)
                batch = faulty_binaries_list[i:i+batchsize]
                func_execute_with_each_input = partial(execute_random_file_with_each_input_nova, infile, arch, fault_type, batch)
                input_results = input_pool.imap(func_execute_with_each_input, input_batch)
                input_pool.close()
                list(enumerate(input_results))
            map(lambda x: faulty_binaries_list.remove(x), batch)
        except:
            traceback.print_exc()
            continue

def run_random_faulty_executables_verifypin(infile, arch, fault_type, input_data, batchsize=50):
    print("\nRunning the faulty binaries and recording the results...\n")
    print("This may take a while...\n")
    with open("%s_%s_results.csv" %(infile, fault_type), 'w') as csvfile:
        writer = csv.writer(csvfile, delimiter=',')
        writer.writerow(['File_Name', 'Faulty_Executable', 'Og_Data_Index', 'Card_Pin', 'User_Pin', 'Output', 
                        'Error', 'Exit_Code', 'Time_Out', 'Fault_Type'])
    faulty_binaries_list = os.listdir("%s-%s-faulted-binaries" %(infile, fault_type))
    print("Total binaries: ", len(faulty_binaries_list))
    input_batch_size = int(input_data.shape[0]/5)
    for j in range(0, input_data.shape[0], input_batch_size):
        print("Executing inputs ", j, " : ", input_batch_size)
        input_batch = input_data[j : j+input_batch_size].to_records()
        try:
            with MyPool(processes=50) as input_pool:
                i = random.randint(0, len(faulty_binaries_list)-1)
                print("Executing binaries ", i, " : ", i+batchsize)
                batch = faulty_binaries_list[i:i+batchsize]
                func_execute_with_each_input = partial(execute_random_file_with_each_input_verifypin, infile, arch, fault_type, batch)
                input_results = input_pool.imap(func_execute_with_each_input, input_batch)
                input_pool.close()
                list(enumerate(input_results))
            map(lambda x: faulty_binaries_list.remove(x), batch)
        except:
            traceback.print_exc()
            continue

def main(argv):

    CLI=argparse.ArgumentParser()
    CLI.add_argument(
        "--filename",
        type=str,
        default='NovaHomeDaemon_Ext'
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

    # Nova Smart Home Control Daemon
    for fault_type in fault_types:
        print("fault_type: ", fault_type)
        if(fault_type=='none'):
            copy_original_file(infile)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("./Nova_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_faulty_executables_nova(infile, arch, fault_type, input_data, batch_size=1)
        if(fault_type=='jmp'):
            inject_jump_faults(jumps,allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("./Nova_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_all_faulty_executables_random_input_nova(infile, arch, fault_type, input_data)
        if(fault_type=='zero'):
            inject_zero_faults(cmpsmovs,infile,arch)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("./Nova_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_all_faulty_executables_random_input_nova(infile, arch, fault_type, input_data)
        if(fault_type=='nop'):
            inject_nop_faults(allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("./Nova_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_all_faulty_executables_random_input_nova(infile, arch, fault_type, input_data)
        if(fault_type=='flp'):
            inject_flp_faults(allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['temperature', 'light']
            input_data = pd.read_excel("./Nova_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            '''run_faulty_executables(infile, arch, fault_type, input_data)
            input_data = input_data[0:40000]
            run_fixed_faulty_executables(infile, arch, fault_type, input_data, ['flp_at_0x2c8_sgnf_7', 'flp_at_0x1c1c_sgnf_3', 'flp_at_0x1ea8_sgnf_1', 
                                                                           'flp_at_0x1eac_sgnf_4', 'flp_at_0x1b54_sgnf_7'])'''
            run_all_faulty_executables_random_input_nova(infile, arch, fault_type, input_data)



    # VerifyPIN
    for fault_type in fault_types:
        print("fault_type: ", fault_type)
        if(fault_type=='none'):
            copy_original_file(infile)
            print("Reading Data....")
            col_list = ['card_pin', 'user_pin']
            input_data = pd.read_excel("./VerifyPin_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_faulty_executables_verifypin(infile, arch, fault_type, input_data, batch_size=1)
        if(fault_type=='jmp'):
            inject_jump_faults(jumps,allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['card_pin', 'user_pin']
            input_data = pd.read_excel("./VerifyPin_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_random_faulty_executables_verifypin(infile, arch, fault_type, input_data)
        if(fault_type=='zero'):
            inject_zero_faults(cmpsmovs,infile,arch)
            print("Reading Data....")
            col_list = ['card_pin', 'user_pin']
            input_data = pd.read_excel("./VerifyPin_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_random_faulty_executables_verifypin(infile, arch, fault_type, input_data)
        if(fault_type=='nop'):
            inject_nop_faults(allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['card_pin', 'user_pin']
            input_data = pd.read_excel("./VerifyPin_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            run_random_faulty_executables_verifypin(infile, arch, fault_type, input_data)
        if(fault_type=='flp'):
            inject_flp_faults(allinstr,infile,arch)
            print("Reading Data....")
            col_list = ['card_pin', 'user_pin']
            input_data = pd.read_excel("./VerifyPin_Input_Data.xlsx", sheet_name='Input_Data', usecols=col_list)
            input_data = input_data.dropna()
            input_data = input_data[0:40000]
            run_fixed_faulty_executables_verifypin(infile, arch, fault_type, input_data, ['flp_at_0xea2_sgnf_6', 'flp_at_0xca2_sgnf_4', 'flp_at_0xdda_sgnf_7', 'flp_at_0xeac_sgnf_7', 'flp_at_0xe39_sgnf_6'])


if __name__ == '__main__':
    main(sys.argv)
