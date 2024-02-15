import networkx as nx
from torch_geometric.utils.convert import to_networkx

def to_networkx_graph(ptgraph):
    G = nx.Graph()
    #add ip nodes
    for i in range(ptgraph['ip'].x.shape[0]):
        G.add_node('ip_'+str(i), ip=ptgraph['ip'].x[i])
    
    for i in range(ptgraph['connection'].x.shape[0]):
        G.add_node('conn_'+str(i), x=ptgraph['connection'].x[i], y=ptgraph['connection'].y[i].argmax().item())
        
    for ip_idx, conn_idx in ptgraph['ip','connection'].edge_index.T:
        G.add_edge('ip_'+str(ip_idx.item()), 'conn_'+str(conn_idx.item()))
    
    for conn_idx, ip_idx in ptgraph['connection','ip'].edge_index.T:
        G.add_edge('conn_'+str(conn_idx.item()), 'ip_'+str(ip_idx.item()))
    
    return G