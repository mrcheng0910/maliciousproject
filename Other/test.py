import re
text = 'abababcccc'
pattern = 'ab'

for match in re.findall(pattern,text):
	print 'Found "%s"' % match