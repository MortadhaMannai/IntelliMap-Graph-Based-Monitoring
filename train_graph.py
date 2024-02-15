from torch_geometric.data import HeteroData
from torch_geometric.loader import DataLoader, DataListLoader
import torch_geometric.transforms as T
from torch_geometric.nn import HGTConv, Linear

from torch.optim import Adam
from torch.nn import functional as F
from torch import nn

from sklearn.metrics import classification_report

import torch
import argparse
import numpy as np
from tqdm.auto import tqdm
import pandas as pd
import json
import pickle
import os



class CICdata():
    def __init__(self, path_data):
        f = open(path_data,'rb')
        self.df = pickle.load(f)
        self.conn_feat = ['Duration', 'Packets', 'Bytes', 'Proto_ICMP ', 'Proto_IGMP ','Proto_TCP  ', 'Proto_UDP  ','flag_A', 'flag_P', 'flag_R', 'flag_S','flag_F', 'Tos_0', 'Tos_16', 'Tos_32', 'Tos_192']
        self.label_cols_oh = ['attack_benign','attack_bruteForce', 'attack_dos', 'attack_pingScan', 'attack_portScan']
        
        
    def make_ip_map(self, data):
        unique_ip = np.unique(np.append(data['Src IP Addr'].to_numpy(), 
                                        data['Dst IP Addr'].to_numpy()))
        return {ip:idx for idx, ip in enumerate(unique_ip)}
    
    def encode_ip(self, value):
        temp = [0]*10
        if value == '192.168.100.6': #internal web server
            temp[0] = 1.0
        elif value == '192.168.100.5': #internal file server
            temp[1] = 1.0
        elif value == '192.168.100.4': #internal mail server
            temp[2] = 1.0
        elif value == '192.168.100.3': #internal backup server
            temp[3] = 1.0
        elif value[:11] == '192.168.100': #server subnet
            temp[4] = 1.0
        elif value[:11] == '192.168.200': #management subnet
            temp[5] = 1.0
        elif value[:11] == '192.168.210': #office subnet
            temp[6] = 1.0
        elif value[:11] == '192.168.220': #developer subnet
            temp[7] = 1.0
        elif value[5:6]=='_': #public ip
            temp[8] = 1.0
        elif value in ['0.0.0.0', '255.255.255.255']: #local ip
            temp[9] = 1.0

        return temp
    
    def get_ip_feat(self, ip_map):
        ip_data = []
        for ip, idx in ip_map.items():
            ip_data.append(self.encode_ip(ip))
        
        return torch.tensor(ip_data).float()
                
    def make_edges(self, data, ip_map):
        src = []
        dst = []
        count = 0
        for _, row in data.iterrows():
            #source ip to connection
            src.append(ip_map[row['Src IP Addr']])
            dst.append(count)

            #destination ip to connection
            src.append(ip_map[row['Dst IP Addr']])
            dst.append(count)
            count +=1

        return torch.tensor([src, dst]), torch.tensor([dst, src])

    def get_info_conn(self, data, cols):
        return torch.tensor(data[cols].values)
                
    def process(self, n_rows=200):
        x_conn = self.get_info_conn(self.df, self.conn_feat)
        y = self.get_info_conn(self.df, self.label_cols_oh)
        data_list = []
        
        
        for i in tqdm(range(1, (len(self.df)//n_rows)+1), desc='processing'):
            start_idx = (i-1)*n_rows
            end_idx = i*n_rows
            sample = self.df[start_idx:end_idx]
            ip_map = self.make_ip_map(sample)
            ip_to_conn, conn_to_ip = self.make_edges(sample, ip_map)
            data = HeteroData()
            data['ip'].x = self.get_ip_feat(ip_map) #encode ip's from the map
            data['connection'].x = x_conn[start_idx:end_idx].float()
            data['connection'].y = y[start_idx:end_idx]
            data['ip','connection'].edge_index = ip_to_conn
            data['connection','ip'].edge_index = conn_to_ip
            data_list.append(data)
        
        return data_list
    

class HGT(torch.nn.Module):
    def __init__(self, data_graph, hidden_channels, out_channels, num_heads, num_layers):
        super().__init__()

        self.lin_dict = torch.nn.ModuleDict()
        for node_type in data_graph.node_types:
            self.lin_dict[node_type] = Linear(-1, hidden_channels)

        print(self.lin_dict)
        self.convs = torch.nn.ModuleList()
        for _ in range(num_layers):
            conv = HGTConv(hidden_channels, hidden_channels, data_graph.metadata(),
                           num_heads, group='sum')
            self.convs.append(conv)

        self.lin = Linear(hidden_channels, out_channels)

    def forward(self, x_dict, edge_index_dict):        
        for node_type, x in x_dict.items():
            x_dict[node_type] = self.lin_dict[node_type](x).relu_()

        for conv in self.convs:
            x_dict = conv(x_dict, edge_index_dict)

        return self.lin(x_dict['connection'])
    

def main(args):
    device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
    cic_data = CICdata(args.train_data)
    #cic_data.df = cic_data.df[:2000]
    print('processing training data...\n')
    data_train = cic_data.process(n_rows=args.connections_graph)
    #out channels = number of classes
    #hidden channels and num_layers determines complexity
    model = HGT(data_graph= data_train[0], hidden_channels=args.hidden_channels, out_channels=5,
            num_heads=args.num_heads, num_layers=args.hidden_layers)
    
    # Initialize lazy module, still on cpu
    with torch.no_grad():
        out = model(data_train[0].x_dict, data_train[0].edge_index_dict)
        
    #hard code batch size
    batch_size = 64 
    optimizer = Adam(model.parameters())
    train_loader = DataLoader(data_train, batch_size=batch_size)


    model.to(device)
    model.train()
    for epoch in range(args.epochs):
        total_examples = total_loss = 0

        for batch in train_loader:
            optimizer.zero_grad()
            batch.to(device)
            out = model(batch.x_dict, batch.edge_index_dict)
            loss = F.cross_entropy(out, batch['connection'].y.float())
            loss.backward()
            optimizer.step()

            total_examples += batch_size
            total_loss += float(loss) * batch_size
            
        tqdm.write('EPOCH '+str(epoch)+' loss: '+ str(total_loss/total_examples))
        

    cic_val = CICdata(args.val_data)
    #cic_val.df = cic_val.df[:2000]
    print('\nprocessing validation data...\n')
    data_val = cic_val.process(n_rows=args.connections_graph)


    model.eval()
    count=0
    preds = []
    labels = []
    print('\npredicting on validation data...\n')
    for graph in tqdm(data_val, position=0, leave=True):
        graph.to(device)
        preds.append(model(graph.x_dict, graph.edge_index_dict).argmax(dim=1))
        labels.append(graph['connection'].y.argmax(dim=1))

    preds = torch.cat(preds)
    labels = torch.cat(labels)
    cr = classification_report(preds.cpu(), labels.cpu())
    print(cr)
    cr_df = pd.DataFrame(classification_report(preds.cpu(), labels.cpu(), output_dict=True)).transpose()
    
    os.makedirs(os.path.dirname(args.path_eval), exist_ok=True)
    with open(args.path_eval, 'w') as f:
        f.write('## Settings Training\n')
        f.write(json.dumps(vars(args)))
        f.write('\n## Evaluations results\n')
        f.write(cr_df.to_markdown())
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='train and evaluate Graph neural networks on network data')
    parser.add_argument('-td','--train-data', type=str, help='path of processed trainingsdata', default='data/train/week1_prep_train.pkl')
    parser.add_argument('-vd','--val-data', type=str, help='path of processed validation data', default='data/eval/week1_prep_val.pkl')
    parser.add_argument('-pe','--path-eval', type=str, help='path of evaluation results', default='runs/exp0.txt')
    
    parser.add_argument('-hc','--hidden-channels', type=int, help='number of hidden channels for algorithm', default=64)
    parser.add_argument('-hl','--hidden-layers', type=int, help='number of hidden layers for algorithm', default=2)
    parser.add_argument('-nh','--num-heads', type=int, help='number of heads for algorithm', default=4)
    parser.add_argument('-e','--epochs', type=int, help='number of epochs algorithm is trained', default=20)
    parser.add_argument('-cg','--connections-graph', type=int, help='number of network connections in a graph', default=200)
    
    arguments = parser.parse_args()
    main(arguments)
    
