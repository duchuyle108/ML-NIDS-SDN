# merge and shuffle separated data files

import pandas as pd
from sklearn.utils import shuffle

types = ['icmpflood', 'ipsweep', 'normal', 'pingofdeath', 'portscan', 'tcpsynflood', 'udpflood']
flag = 3
if flag == 1 :
    base1 = 'datatest'
    base2 = 'datatest'
    prefix = 'test_'
elif flag == 2 :
    base1 = 'dataset'
    base2 = 'dataset'
    prefix = ''

dataset = []

for type in types: 
    data = pd.read_csv(base1 + '/' + prefix + type)
    data = shuffle(data)
    dataset.append(data)

final = pd.concat(dataset)
final.drop_duplicates(inplace=True)
final = shuffle(final)
final = shuffle(final)

final.to_csv(base1 +'/' + base2, index=False)

