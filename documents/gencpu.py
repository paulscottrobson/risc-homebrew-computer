# *******************************************************************************************
# *******************************************************************************************
#
#		Name : 		gencpu.py
#		Purpose :	Generate the CPU core (not B) in C
#		Date :		27th August 2019
#		Author : 	Paul Robson (paul@robsons.org.uk)
#
# *******************************************************************************************
# *******************************************************************************************

#
#		Work out the mnemonic for Non-B opcode.
#
def getMnemonic(opcode):
	m = ["ldr","str","add","sub","and","xor","ror","skb"][opcode >> 4]
	m = m + ("f" if (opcode & 0x08) != 0 else "")
	m = m + " ra,"
	if (opcode & 0x04) != 0:
		m = m + "#nnn"
	else:
		m = m + ["rb","(rb)","-(rb)","(rb)+"][opcode & 3]
	return m
#
#		EAC on mode (01,10,11)
#
def effectiveAddress(mode):
	if (mode == 2):
		print("\tR[RB]--;")
	print("\tMA = R[RB];")
	if (mode == 3):
		print("\tR[RB]++;")
#
#		Generate opcodes to STDOUT.
#
for opcode in range(0,128):										# High opcode byte.
	isStore = (opcode >> 4) == 1								# Store is a little different
	reject = isStore and (opcode & 0x04) != 0
	if not reject:
		mnemonic = getMnemonic(opcode)
		#
		print("case 0x{0:02x}: /*** ${0:02x} {1:12} ***/".format(opcode,mnemonic))
		#
		print("\tRA = (IR & 0x0F);")
		if (opcode & 0x04) != 0:								# immediate mode.
			print("\tMB = (IR >> 4) & 0x3F;")					# immediate constant.
		else:
			print("\tRB = (IR >> 4) & 0x0F;")					# working RHS register
			if not isStore:										# store is handled seperately.
				if (opcode & 0x03) == 0:						# direct mode.
					print("\tMB = R[RB];")						# data is register direct
				else:
					effectiveAddress(opcode & 0x03)				# do EAC.
					print("\tREAD();")							# and read it.
		#
		if (opcode >> 4) == 0:									# LDR
			print("\tR[RA] = MB;")
		#
		if (opcode >> 4) == 1:									# STR
			if (opcode & 3) == 0:								# Direct
				print("\tR[RB] = R[RA];")
			else:
				effectiveAddress(opcode & 3)
				print("\tMB = R[RA];")
				print("\tWRITE();")
		#
		if (opcode >> 4) == 2:									# ADD
			if (opcode & 0x08) == 0:
				print("\tR[RA] += MB;")
			else:
				print("\tADD32(MB,0);")
		#
		if (opcode >> 4) == 3:									# SUB
			if (opcode & 0x08) == 0:
				print("\tR[RA] -= MB;")
			else:
				print("\tADD32(MB^0xFFFF,1);")
		#
		if (opcode >> 4) == 4:									# AND
			print("\tR[RA] &= MB;")
		#
		if (opcode >> 4) == 5:									# XOR
			print("\tR[RA] ^= MB;")
		#
		if (opcode >> 4) == 6:									# ROR
			print("\tR[RA] = (MB >> 1)|(MB << 15);")
		#
		if (opcode >> 4) == 7:									# SKB
			print("\tif ((R[RA] & MB) == MB) R[15]++;")
		#
		if (opcode & 0x08) != 0:								# Flag bit set.
			if (opcode >> 4) == 2 or (opcode >> 4) == 3:		# Handle C NC M P Z NZ
				print("\tSETFLAGS_CNZ();")
			else:												# Handle 0 1 M P Z NZ
				print("\tSETFLAGS_NZ();")
		#
		print("\tbreak;\n")			
