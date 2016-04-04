# colorpc.py - deroko of ARTeam
#
# prev name was coloreipred.py but now, since it supports arm/aarch64,
# name is changed to colorpc.py
#
# IDA Script to color all PC redirection inside of selected procedure
# Colors are as follows:
#       blue   - call instructions
#       yellow - jcc/jmp instructions
#       red    - ret instruction
#       green  - call/jmp [mem/reg]
#
#       It binds to key "i", and that can be changed at the bottom of
#       the script
#
# Added support for arm/aarch64
#
#                               deroko of ARTeam
import	idaapi
import	idc
import  colorsys

#stop insts
stop_list = [
        idaapi.NN_retn,
        idaapi.NN_retf,
        idaapi.NN_retnq,
        idaapi.NN_retfq,
        
        ];

stop_list_arm = [
        idaapi.ARM_ret
        ];
	
#list of jcc instructions
jcc_list = [
        idaapi.NN_ja,
        idaapi.NN_jae,
        idaapi.NN_jb,
        idaapi.NN_jbe,
        idaapi.NN_jc,
        idaapi.NN_je,
        idaapi.NN_jg,
        idaapi.NN_jge,
        idaapi.NN_jl,
        idaapi.NN_jle,
        idaapi.NN_jna,
        idaapi.NN_jnae,
        idaapi.NN_jnb,
        idaapi.NN_jnbe,
        idaapi.NN_jnc,
        idaapi.NN_jne,
        idaapi.NN_jng,
        idaapi.NN_jnge,
        idaapi.NN_jnl,
        idaapi.NN_jnle,
        idaapi.NN_jno,
        idaapi.NN_jnp,
        idaapi.NN_jns,
        idaapi.NN_jnz,
        idaapi.NN_jo,
        idaapi.NN_jp,
        idaapi.NN_jpe,
        idaapi.NN_jpo,
        idaapi.NN_js,
        idaapi.NN_jz,
        idaapi.NN_jcxz,
        idaapi.NN_jecxz,
        idaapi.NN_jrcxz,
        idaapi.NN_jmp,
        idaapi.NN_jmpni,
        idaapi.NN_jmpshort,
        idaapi.NN_loop,
        idaapi.NN_loopq,
        idaapi.NN_loope,
        idaapi.NN_loopqe,
        idaapi.NN_loopne,
        idaapi.NN_loopqne
        ];       

jcc_list_arm = [
        idaapi.ARM_b,
        idaapi.ARM_bx,
        idaapi.ARM_bxj,
        
        ];

call_list = [
        idaapi.NN_call,
        idaapi.NN_callfi,
        idaapi.NN_callni,
        ];

call_list_arm = [
        idaapi.ARM_bl,
        idaapi.ARM_blx1,
        idaapi.ARM_blx2,
        ];         

def get_yellow():
        r = 0xFF/255.0;
        g = 0xFF/255.0;
        b = 0x00/255.0;
        
        (h,s,v) = colorsys.rgb_to_hsv(r,g,b);
        s -= 0.6;
        (r,g,b) = colorsys.hsv_to_rgb(h,s,v);
        ida_color = (int(b*255) << 16) + (int(g*255)<<8) + int(r*255);
	return ida_color;
	
def get_blue():
	r = 0x00/255.0;
        g = 0x00/255.0;
        b = 0xff/255.0;
        
        (h,s,v) = colorsys.rgb_to_hsv(r,g,b);
        s -= 0.7;
        (r,g,b) = colorsys.hsv_to_rgb(h,s,v);
        #it's BGR
        ida_color = (int(b*255) << 16) + (int(g*255)<<8) + int(r*255);
        return ida_color;

def get_green():
	r = 0x00/255.0;
        g = 0xff/255.0;
        b = 0x00/255.0;
        
        (h,s,v) = colorsys.rgb_to_hsv(r,g,b);
        s -= 0.7;
        (r,g,b) = colorsys.hsv_to_rgb(h,s,v);
        #it's BGR
        ida_color = (int(b*255) << 16) + (int(g*255)<<8) + int(r*255);
        return ida_color;

def get_red():
	r = 0xff/255.0;
        g = 0x00/255.0;
        b = 0x00/255.0;
        
        (h,s,v) = colorsys.rgb_to_hsv(r,g,b);
        s -= 0.7;
        (r,g,b) = colorsys.hsv_to_rgb(h,s,v);
        #it's BGR
        ida_color = (int(b*255) << 16) + (int(g*255)<<8) + int(r*255);
        return ida_color;

def get_proc_name():
        info = idaapi.get_inf_structure();
        return info.get_proc_name();

def get_call_list():
        proc_name = get_proc_name();
        if "metapc" in proc_name:
                return call_list;
        if "ARM" in proc_name:
                return call_list_arm;
        return None;

def get_jcc_list():
        proc_name = get_proc_name();
        if "metapc" in proc_name:
                return jcc_list;
        if "ARM" in proc_name:
                return jcc_list_arm;
        return None;

def get_stop_list():
        proc_name = get_proc_name();
        if "metapc" in proc_name:
                return stop_list;
        if "ARM" in proc_name:
                return stop_list_arm;
        return None;
        
def inst_is_jcc(pc):
        i = idaapi.cmd.itype;
        lst = get_jcc_list();
        for x in lst:
                if x == i: return True;
        return False;
def inst_is_call(pc):
        i = idaapi.cmd.itype;
        lst = get_call_list();
        for x in lst:
                if x == i: return True;
        return False;

#for ARM this has to be processed in different manner...
#we look for ldm/pop where pc is altered, and bx with lr
def inst_is_ret(pc):
        i = idaapi.cmd.itype;
        lst = get_stop_list();
        for x in lst:
                if x == i: return True;            
        if "ARM" in get_proc_name():
                #ok instead of understanding all specflags and vals for ARM in cmd.Operands
                #I'll use ins mnemonic...
                mne = idc.GetDisasm(pc);
                if idaapi.cmd.itype == idaapi.ARM_pop:
                        if "PC" in mne: return True;
                        #for x in idaapi.cmd.Operands:
                        #        print "%d %d %d" % (x.type, x.dtyp, x.specval);      
                if idaapi.cmd.itype == idaapi.ARM_bx:
                        if "LR" in mne: return True;
                if idaapi.cmd.itype == idaapi.ARM_ldm:
                        if "PC" in mne: return True;
        return False;

def is_indirect(pc):
	op = idaapi.cmd.Operands[0];
	if not op:
		return False;
	if op.type in [idaapi.o_mem, idaapi.o_displ, idaapi.o_reg, idaapi.o_phrase]:
		return True;
	return False;

def main():
        eip = idaapi.get_screen_ea();
        function = idaapi.func_item_iterator_t();
        function.set(idaapi.get_func(eip));
        	
        b_ok = function.first();
        while b_ok:
                pc = function.current();
                inslen = idaapi.decode_insn(function.current());
                if inslen == 0:
                        b_ok = function.next_code();
                        continue;	
                if inst_is_call(pc):
			color = get_blue();
			if is_indirect(pc):
				color = get_green();
			idc.SetColor(pc, CIC_ITEM, color);
		elif inst_is_ret(pc):			                      
                        color = get_red();
			idc.SetColor(pc, CIC_ITEM, color);	
                elif inst_is_jcc(pc):                                      
                        color = get_yellow();
			if is_indirect(pc):
				color = get_green();
			idc.SetColor(pc, CIC_ITEM, color);
                b_ok = function.next_code();		

if __name__ == "__main__":
	idaapi.CompileLine('static color_key() { RunPythonStatement("main()"); }')
        # Add the hotkey
        AddHotkey("i", 'color_key');


