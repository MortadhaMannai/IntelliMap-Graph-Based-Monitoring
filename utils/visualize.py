from svgpath2mpl import parse_path
import matplotlib as mpl
import matplotlib.pyplot as plt
import networkx as nx


markers = {}

#connection marker
markers['connection'] = parse_path("""M451 1059 c-139 -27 -285 -143 -349 -276 -203 -429 242 -874 671
-671 97 47 188 138 235 235 178 376 -147 792 -557 712z m201 -30 c177 -37 330
-190 367 -367 69 -332 -229 -630 -561 -561 -177 37 -330 190 -367 367 -69 332
229 630 561 561z
M270 765 l-64 -65 64 -65 c35 -36 70 -65 77 -65 27 0 23 24 -11 59
-20 20 -36 40 -36 44 0 4 134 8 298 9 256 3 297 5 297 18 0 13 -41 15 -297 18
-164 1 -298 5 -298 9 0 4 16 24 36 44 34 35 38 59 11 59 -7 0 -42 -29 -77 -65z
M744 569 c-3 -6 10 -27 30 -48 20 -20 36 -40 36 -44 0 -4 -134 -8
-297 -9 -257 -3 -298 -5 -298 -18 0 -13 41 -15 298 -18 163 -1 297 -5 297 -9
0 -4 -16 -24 -36 -44 -34 -35 -38 -59 -11 -59 7 0 42 29 77 65 l64 65 -64 65
c-64 65 -83 75 -96 54z""")

#pc marker
markers['pc'] = parse_path("""M20 242 c0 -41 6 -42 460 -42 454 0 460 1 460 42 0 17 -14 18 -200
18 -127 0 -200 -4 -200 -10 0 -6 -27 -10 -60 -10 -33 0 -60 4 -60 10 0 6 -73
10 -200 10 -186 0 -200 -1 -200 -18z
M152 748 c-9 -9 -12 -74 -12 -230 l0 -218 340 0 340 0 0 218 c0 156
-3 221 -12 230 -17 17 -639 17 -656 0z m608 -218 l0 -170 -280 0 -280 0 0 170
0 170 280 0 280 0 0 -170z""")

#malicious marker
markers['malicious'] = parse_path("""M180.494,39.687l-1.333-1.327c-5.009-5.015-11.667-7.772-18.754-7.772
c-7.082,0-13.739,2.758-18.748,7.767l-1.333,1.333L5.551,256.847c-5.466,6.413-7.016,14.196-4.112,21.207
c3.16,7.631,10.704,12.189,20.173,12.189h277.604c9.475,0,17.013-4.558,20.173-12.189c2.904-7.011,1.354-14.8-4.112-21.207
L180.494,39.687z M43.484,257.614L160.413,69.221l116.934,188.393H43.484z
M143.758,122.002v71.388c0,9.197,7.457,16.654,16.654,16.654s16.654-7.457,16.654-16.654v-71.388
c0-9.197-7.457-16.654-16.654-16.654C151.215,105.347,143.758,112.804,143.758,122.002z""")

#server marker
markers['server'] = parse_path("""m445,460h-24.998v-445c0-8.284-6.716-15-15-15h-320.002c-8.284,0-15,6.716-15,15v445h-25c-8.284,0-15,6.716-15,15s6.716,15 15,15h400c8.284,0 15-6.716 15-15s-6.716-15-15-15zm-54.998,0h-290.002v-430h290.002v430zm-245-160h199.998c8.284,0 15-6.716 15-15v-210c0-8.284-6.716-15-15-15h-199.998c-8.284,0-15,6.716-15,15v210c0,8.284 6.716,15 15,15zm15-210h169.998v40h-169.998v-40zm0,70h169.998v40h-169.998v-40zm0,70h169.998v40h-169.998v-40zm84.998,107.497c-24.813,0-44.999,20.188-44.999,45.004 0,24.813 20.188,45.001 45.001,45.001 24.813,0 44.999-20.188 44.999-45.004-5.68434e-14-24.813-20.188-45.001-45.001-45.001zm0,60.005c-8.271,0-14.999-6.729-14.999-15.004 0-8.271 6.729-15.001 14.999-15.001h0.002c8.271,0 14.999,6.729 14.999,15.004-5.68434e-14,8.271-6.73,15.001-15.001,15.001z""")

#centralize all icons + rotate some
for key, item in markers.items():
    markers[key].vertices -= item.vertices.mean(axis=0)
    if key in ['malicious','server','connection']:
        markers[key] = item.transformed(mpl.transforms.Affine2D().rotate_deg(180))

def visualize_network(G, layout='kamada-kawai', path_fig=None, path_expl=None):
    #filter connections based on benign or malicious
    #filter devices based on internal devices, internal servers or external devices.
    conns = list(filter(lambda x: x[0]=='c', list(G.nodes)))
    ips = list(filter(lambda x: x[0]=='i', list(G.nodes)))
    ip_server = list(filter(lambda x: G.nodes[x]['ip'].argmax() in [0,1,2,3,4] , ips))
    ip_device = list(filter(lambda x: G.nodes[x]['ip'].argmax() in [5,6,7,9] , ips))
    ip_external = list(filter(lambda x: G.nodes[x]['ip'].argmax()==8, ips))

    conns_attack = list(filter(lambda x: G.nodes[x]['y']!=0, conns))
    conns_normal = list(filter(lambda x: G.nodes[x]['y']==0, conns))

    #### EXPLANATION
    labels = ['attack_benign','attack_bruteForce', 'attack_dos', 'attack_pingScan', 'attack_portScan']
    subnets = ['the web server','the file server','the mail server','the backup server', 'the server subnet', 
           'the management subnet', 'the office subnet', 'the developer subnet', 'an external ip', 'a local ip']
    label_map = {idx:label for idx, label in enumerate(labels)}
    subnet_map = {idx:subnet for idx, subnet in enumerate(subnets)}
    
    ip_attack = {}
    for c in conns_attack:
        key = []
        for t in G.edges(c):
            key.append(t[1])
        key.sort()
        key = key+[label_map[G.nodes[c]['y']]]

        if tuple(key) in ip_attack.keys():
            ip_attack[tuple(key)] = ip_attack[tuple(key)]+[c]
        else:
            ip_attack[tuple(key)]=[c]
    
    explanation=''
    for key in ip_attack.keys():
        device_a = subnet_map[G.nodes[key[0]]['ip'].argmax().item()]
        device_b = subnet_map[G.nodes[key[1]]['ip'].argmax().item()]
        label_descr = label_map[G.nodes[ip_attack[key][0]]['y']]
        explanation += f'{len(ip_attack[key])} connections between {device_a} ({key[0]}) and {device_b} ({key[1]}) consists of {label_descr}\n'
    
    if path_expl:
            with open(path_expl, 'w') as f:
                f.write(explanation)
    
    print(explanation)
            
    #### PLOT
    #good layouts kamada_kawai, spring
    if layout=='spring':
        pos = nx.spring_layout(G)
    elif layout=='kamada-kawai':
        pos = nx.kamada_kawai_layout(G) 
    else:
        print('\n choose one of spring or kamada-kawai for layout\n')
    
    #draw edges and different nodes
    fig = plt.figure(figsize=(20,20))
    nx.draw_networkx_edges(G, pos=pos, arrows=True,  min_source_margin=10, min_target_margin=10, alpha=0.5)
    nx.draw_networkx_nodes(G, pos=pos, nodelist=conns_normal, node_color="tab:grey", alpha=0.5, node_size=30,
                          label='Benign connections')
    nx.draw_networkx_nodes(G, pos=pos, nodelist=conns_attack, node_shape=markers['malicious'], node_color="tab:red",
                          node_size=600, label='Malicious connections')
    nx.draw_networkx_nodes(G, pos=pos, nodelist=ip_server, node_shape=markers['server'], node_color="tab:green",
                          node_size=1000, label='Server')
    nx.draw_networkx_nodes(G, pos=pos, nodelist=ip_device, node_shape=markers['pc'], node_color="tab:blue",
                          node_size=500, label='Device')
    nx.draw_networkx_nodes(G, pos=pos, nodelist=ip_external, node_shape=markers['connection'], node_color="tab:blue",
                          node_size=350, label='External ip')
    
    #add legend with all nodes
    prop = {"weight":"bold", "size":"xx-large"}
    plt.legend(loc="upper right", fancybox=True, shadow=True,  
               fontsize="xx-large",
               title_fontproperties = prop,
               title="Node types")

    #provide explanation
    
    if path_fig:
        plt.savefig(path_fig, bbox_inches='tight')
    
    plt.show()
    