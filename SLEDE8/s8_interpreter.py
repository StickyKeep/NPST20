class S8Interpreter:
	"""
	USAGE
	-----
	interpreter = S8Interpreter()
	interpreter.interpret("program.s8", ['0e', '20'])
	"""
	def __init__(self):
		self.SLEDE8_HEADER = "2E534C45444538"
		self.ip = 7 # Instruction Pointer
		self.r = [0 for i in range(16)] # Emulated Registers
		self.input_index = 0
		self.running = False
		self.flag = False
		
	def read_program_file(self, filename, input):
		self.input = input
		with open(filename, "rb") as file:
			bits = file.read()
			hex_content = ["{:02X}".format(c) for c in bits]
			self.code = hex_content
		file.close()
		
	def valid_s8_header(self):
		header = ''.join(self.code[0:7])
		if self.SLEDE8_HEADER in header:
			print("File Recognized as s8")
			return True
		else:
			print("File not recognized as s8")
			return False

	def reset(self):
		self.ip = 7
		self.r = [0 for i in range(16)]
		self.input_index = 0
		self.running = False
		self.flag = False
			
	def interpret(self, filename, input):
		self.reset()
		self.read_program_file(filename, input)
		if not self.valid_s8_header():
			return
		
		self.running = True
		while self.ip < len(self.code) and self.running:
			opcode = self.code[self.ip]
			#print(opcode, "->", self.ip)
			self.execute_next(opcode)
		
	def execute_next(self, opcode):
		# I/O
		if opcode == "16":
			register_index = self.decode_value(1, high=False)
			self.print_value(register_index)
		elif opcode == "06":
			register_index = self.decode_value(1, high=False)
			self.read_value(register_index)

		# Arithmethic
		elif opcode == "55":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.add_values(r0, r1)
		elif opcode == "65":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.sub_values(r0, r1)
		
		# Bitwise Operations
		elif opcode == "05":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.bitwise_and(r0, r1)
		elif opcode == "15":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.bitwise_or(r0, r1)
		elif opcode == "25":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.bitwise_xor(r0, r1)
		elif opcode == "35":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.bitwise_shift_left(r0, r1)
		elif opcode == "45":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.bitwise_shift_right(r0, r1)
		
		# Misc
		elif opcode == "00":
			self.running = False
			return
		elif opcode == "0C":
			return
			
		# Comparisons
		elif opcode == "07":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.flag = self.compare_equal(r0, r1)
		elif opcode == "17":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.flag = self.compare_not_equal(r0, r1)
		elif opcode == "27":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.flag = self.compare_less_than(r0, r1)
		elif opcode == "37":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.flag = self.compare_less_than_or_equal(r0, r1)
		elif opcode == "47":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.flag = self.compare_greater_than(r0, r1)
		elif opcode == "57":
			r0 = self.decode_value(1, high=True)
			r1 = self.decode_value(1, high=False)
			self.flag = self.compare_greater_than_or_equal(r0, r1)

		# Register Assignment
		elif opcode[1] == "1":
			register_index = self.decode_value(0, high=True)
			value = int(self.code[self.ip+1], 16)
			self.set_register_to_value(register_index, value)
		elif opcode[1] == "0":
			r0 = self.decode_value(0, high=True)
			r1 = self.decode_value(1, high=False)
			self.set_register_to_register(r0, r1)
			
		# Jumps
		elif opcode[1] == "8":
			addr = self.calculate_address(opcode, self.code[self.ip+1])
			self.jump(addr)
			return
		elif opcode[1] == "9":
			addr = self.calculate_address(opcode, self.code[self.ip+1])
			if self.flag:
				self.flag = False
				self.jump(addr)		
				return
		self.ip += 2

	# Decodes Hex Value to Integer
	def decode_value(self, ip_offset, high=True):
		bytecode = self.code[self.ip+ip_offset]
		if high:
			return int(bytecode[0])
		else:
			return int(bytecode[1])		
	
	def calculate_address(self, opcode_a, opcode_b):
		low_byte = opcode_a[0]
		high_byte = opcode_b
		index = int(low_byte, 16) + (int(high_byte[0], 16) * 256) + (int(high_byte[1], 16) * 16) + 7
		return index
		
	def jump(self, addr):
		self.ip = addr
	
	def print_value(self, register_index):
		print(hex(self.r[register_index]))
	
	def read_value(self, register_index):
		self.r[register_index] = int(self.input[self.input_index], 16)
		self.input_index += 1
	
	def add_values(self, r0, r1):
		self.r[r1] = (self.r[r1] + self.r[r0]) % 0x100
		
	def sub_values(self, r0, r1):
		self.r[r1] = (self.r[r1] - self.r[r0]) % 0x100

	def set_register_to_value(self, register_index, value):
		self.r[register_index] = value
	
	def set_register_to_register(self, r0, r1):
		self.r[r0] = self.r[r1]
	
	def bitwise_and(self, r0, r1):
		self.r[r1] = self.r[r1] & self.r[r0]
		
	def bitwise_or(self, r0, r1):
		self.r[r1] = self.r[r1] | self.r[r0]
		
	def bitwise_xor(self, r0, r1):
		self.r[r1] = self.r[r1] ^ self.r[r0]
		
	def bitwise_shift_left(self, r0, r1):
		self.r[r1] = self.r[r1] << self.r[r0]
		
	def bitwise_shift_right(self, r0, r1):
		self.r[r1] = self.r[r1] >> self.r[r0]
	
	def compare_equal(self, r0, r1):
		return self.r[r1] == self.r[r0]
		
	def compare_not_equal(self, r0, r1):
		return self.r[r1] != self.r[r0]
		
	def compare_less_than(self, r0, r1):
		return self.r[r1] < self.r[r0]
		
	def compare_less_than_or_equal(self, r0, r1):
		return self.r[r1] <= self.r[r0]
		
	def compare_greater_than(self, r0, r1):
		return self.r[r1] > self.r[r0]
		
	def compare_greater_than_or_equal(self, r0, r1):
		return self.r[r1] >= self.r[r0]