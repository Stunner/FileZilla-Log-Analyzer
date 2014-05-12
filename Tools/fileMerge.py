#!/usr/bin/env python
#Script for merging files together

import shutil, sys, os

def confirmation(text):
	yn = raw_input(text)
	if yn != 'y' and yn != 'Y' and yn != 'n' and yn != 'N':
		while True:
			yn = raw_input("Incorrect input! Re-enter choice(Y/N): ")
			if yn == 'y' or yn == 'Y' or yn == 'n' or yn == 'N':
				break
	return yn

def main(argv):
	goAhead = True
	if len(argv) < 3:
		print "Usage: python fileMerge.py <merged filename> <file(s)>"
		exit()
	fname = argv[1]
	if os.path.exists(fname):
		goAhead = False
		yn = confirmation(fname + " exists, OK to overwrite? (Y/N)")
		if yn == 'N' or yn == 'n':
			print fname, "not overwritten."
		else:
			print "Overwriting", fname + "..."
			goAhead = True
			
	if goAhead:
		fout = file(fname, 'wb')
		i = 0
		for n in argv:
			if i > 1:
				fin = file(n, 'rb')
				shutil.copyfileobj(fin, fout, 65536)
			i += 1
		fin.close()
		fout.close()

if __name__ == '__main__':
	main(sys.argv)
