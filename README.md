# software-fault-injection
This repository contains code to generate a dataset that can be used to train supervised machine learning models to detect instruction-level software fault injection.

# Usage
python3 chaosduck.py --filename NovaHomeDaemon_Ext --arch arm --fault_list 'nop' 'flp'

filename - file name of the software executable to inject faults.

--arch - arch or x86 - hardware architecture for which the software executable was created.

--fault_list - list of faults to inject in the software executable. Example - 'nop' 'flp' 'jmp' 'none'

More information on usage and details to follow soon.

# Acknowledgement
This tool uses the uses Chaos Duck tool (developed by Igor Zavalyshyn) to inject faults into the software executable.
