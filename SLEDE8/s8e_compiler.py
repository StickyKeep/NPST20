"""
=============================================
SLEDE8 Enhanced Compiler
=============================================
Author: FairlyMagical
---------------------------------------------
Compiles .s8asm to the .s8e binary format.
---------------------------------------------
"""

class S8ECompiler():
	def __init__(self):
		self.data = ''
		self.code = ''
		self.line_number = 0
		self.compilation = ''
		self.labels = []
		self.unresolved_addr_lookups = []
	
	def compile(self, filename, output_file):
		# Compile Program
		with open(filename, 'r') as file:
			for line in file:
				self.parse_line(line)
		file.close()
		
		# Resolve Unresolved Address Entries
		for entry in self.unresolved_addr_lookups:
			for label in self.labels:
				if label[0] == entry[0]:
					addr = self.index_to_hex_addr(label[1])
					compiled_entry = addr[2] + entry[2] + addr[0:2]
					patched_compilation = self.compilation[:entry[1]] + compiled_entry + self.compilation[entry[1]+4:]
					self.compilation = patched_compilation
					print("Resolved Address Entry for:", entry[0], "at", str(entry[1]))
		
		# Write compiled program to file
		compilation = "2E534C45444538" + self.compilation + self.data
		byte_compilation = bytes.fromhex(compilation)
		with open(output_file, "wb") as file:
			file.write(byte_compilation)
		file.close()
			
	
	def error(self, msg):
		print("Error: ", msg)
	
	def parse_line(self, line):
		# TODO: Ignore blank lines and comments!
	
		# Decode Mnemonic and Arguments
		line = line.replace(",", "")
		line = line.replace("\n", "")
		tokens = line.split(" ")
		mnemonic = tokens[0]
		if len(tokens) > 1:
			arguments = tokens[1:]
		else:
			arguments = None
		
		# Attempt to Parse Mnemonic
		if self.parse_mnemonic(mnemonic, arguments):
			return
		if self.parse_data(mnemonic, arguments):
			return
		if self.parse_tag(mnemonic):
			return
			
		# Error!
		print("Unknown mnemonic or declaration encountered on line:", self.line_number)
		
	
	def parse_tag(self, mnemonic):
		if mnemonic[-1] == ":":
			addr = len(self.compilation)
			tag = mnemonic[0:len(mnemonic)-1]
			self.labels.append((tag, addr))
			return True
		return False
	
	def parse_data(self, mnemonic, arguments):
		if mnemonic == ".DATA":
			data_string = ""
			data_len = 0
			for arg in arguments:
				arg = arg[2:]
				data_string += arg
				data_len += int(len(arg) / 2)
			data_len = ''.join('{:02X}'.format(data_len))
			self.data += (data_len + data_string)
			return True
		return False
		
	def parse_mnemonic(self, mnemonic, arguments):
		if mnemonic == "SETT":
			self.parse_assignment(arguments)
		elif mnemonic == "SKRIV":
			self.parse_output(arguments)
		elif mnemonic == "LES":
			self.parse_input(arguments)
		elif mnemonic == "PLUSS":
			self.parse_arithmetic(arguments, mnemonic, "55")
		elif mnemonic == "MINUS":
			self.parse_arithmetic(arguments, mnemonic, "65")
		elif mnemonic == "NOPE":
			self.parse_nop(arguments)
		elif mnemonic == "STOPP":
			self.parse_stop(arguments)
		elif mnemonic == "OG":
			self.parse_arithmetic(arguments, mnemonic, "05")
		elif mnemonic ==  "ELLER":
			self.parse_arithmetic(arguments, mnemonic, "15")
		elif mnemonic == "XELLER":
			self.parse_arithmetic(arguments, mnemonic, "25")
		elif mnemonic == "VSKIFT":
			self.parse_arithmetic(arguments, mnemonic, "35")
		elif mnemonic == "HSKIFT":
			self.parse_arithmetic(arguments, mnemonic, "45")
		elif mnemonic == "LIK":
			self.parse_comparison(arguments, mnemonic, "07")
		elif mnemonic == "ULIK":
			self.parse_comparison(arguments, mnemonic, "17")
		elif mnemonic == "ME":
			self.parse_comparison(arguments, mnemonic, "27")
		elif mnemonic == "MEL":
			self.parse_comparison(arguments, mnemonic, "37")
		elif mnemonic == "SE":
			self.parse_comparison(arguments, mnemonic, "47")
		elif mnemonic == "SEL":
			self.parse_comparison(arguments, mnemonic, "57")
		elif mnemonic == "HOPP":
			self.parse_jmp(arguments, mnemonic, "8")
		elif mnemonic == "BHOPP":
			self.parse_jmp(arguments, mnemonic, "9")
		elif mnemonic == "FINN":
			self.parse_find(arguments)
		elif mnemonic == "LAST":
			self.parse_load(arguments)
		elif mnemonic == "LAGR":
			self.parse_store(arguments)
		elif mnemonic == "TUR":
			self.parse_call(arguments)
		elif mnemonic == "RETUR":
			self.parse_ret(arguments)
		else:
			return False
		return True
	
	def parse_assignment(self, arguments):
		if len(arguments) != 2:
			self.error("SETT - Invalid number of arguments")
			return
	
		r0 = arguments[0][1]
		if arguments[1][0] == 'r':
			r1 = arguments[1][1]
			compilation = r0 + "20" + r1
			self.compilation += compilation
		else:
			if len(arguments[1]) > 2 and arguments[1][0:2] == "0x":
				value = arguments[1][2:]
				value = int(value, 16)
			else:
				value = int(arguments[1])
			value = value % 256
			value = ''.join('{:02X}'.format(value))
			compilation = r0 + "1" + value
			self.compilation += compilation
			
	def parse_output(self, arguments):
		if len(arguments) != 1:
			self.error("SKRIV - Invalid number of arguments")
			return
		
		r0 = arguments[0][1]
		compilation = "160" + r0
		self.compilation += compilation
			
	def parse_input(self, arguments):		
		if len(arguments) != 1:
			self.error("LES - Invalid number of arguments")
			return
			
		r0 = arguments[0][1]
		compilation = "060" + r0
		self.compilation += compilation	
		
	def parse_nop(self, arguments):
		if arguments != None:
			self.error("NOPE - Invalid number of arguments")
			return
			
		compilation = "0C00"
		self.compilation += compilation
		
	def parse_stop(self, arguments):
		if arguments != None:
			self.error("NOPE - Invalid number of arguments")
			return
			
		compilation = "0000"
		self.compilation += compilation
	
	def parse_arithmetic(self, arguments, mnemonic, opcode):
		if len(arguments) != 2:
			self.error(mnemonic + " - Invalid number of arguments")
			return	
	
		r0 = arguments[0][1]
		r1 = arguments[1][1]
		compilation = opcode + r1 + r0
		self.compilation += compilation		
		
	def parse_comparison(self, arguments, mnemonic, opcode):
		if len(arguments) != 2:
			self.error(mnemonic + " - Invalid number of arguments")
			return	
		
		r0 = arguments[0][1]
		r1 = arguments[1][1]
		compilation = opcode + r1 + r0
		self.compilation += compilation	
		
	def parse_jmp(self, arguments, mnemonic, opcode):
		if len(arguments) != 1:
			self.error(mnemonic + " - Invalid number of arguments")
			return
		
		tag = arguments[0]
		for label in self.labels:
			if label[0] == tag:
				addr = self.index_to_hex_addr(label[1])
				compilation = addr[2] + opcode + addr[0:2]
				self.compilation += compilation
				return
		unresolved_addr_entry = (tag, len(self.compilation), opcode)
		self.unresolved_addr_lookups.append(unresolved_addr_entry)
		compilation = "F" + opcode + "FF" # Tmp Compilation until Addr will be resolved
		self.compilation += compilation
		print("Unresolved Addr Entry: ", unresolved_addr_entry[0], "at", str(unresolved_addr_entry[1]))
		
	def index_to_hex_addr(self, index):
		index = int(index / 2)
		return ''.join('{:03X}'.format(index))
	

comp = S8ECompiler()
comp.compile("test", "test.s8")