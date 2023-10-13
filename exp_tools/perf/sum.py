import sys
import os

fname = sys.argv[1]
njobs = 4
timeelap = 2
suml = []
first = 1
sumdict = {}
for i in range(njobs):
    curfname = fname + str(i+1) + ".log"
    with open(curfname, 'r') as f:
        for l in f:
            tmpl = l.strip().split(",")
            #print(tmpl)
            timekey = round(float(tmpl[0])/1000)
            try:
                sumdict[timekey].append(float(tmpl[1])/1000)
            except:
                sumdict[timekey] = []
                sumdict[timekey].append(float(tmpl[1])/1000)

for tk in sorted(sumdict.keys()):
    #print("{}\t{}".format(tk, float(sum(sumdict[tk]))/len(sumdict[tk])   ))
    print("{}\t{}".format(tk, float(sum(sumdict[tk]))))
