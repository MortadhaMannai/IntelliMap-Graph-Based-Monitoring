#limited data can be stored on github so download this from website
import wget
import zipfile
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import QuantileTransformer
import pickle
import os
from os import path
import pandas as pd
import numpy as np
import argparse


def download_extract():
    os.makedirs('data/')
    url = 'https://www.hs-coburg.de/fileadmin/hscoburg/WISENT-CIDDS-001.zip'
    wget.download(url, out='data/')
    with zipfile.ZipFile("data/WISENT-CIDDS-001.zip","r") as zip_ref:
        zip_ref.extractall("data/")

def drop_percentage(df,label_value, perc=0.8):
    temp = df[df['attackType']==label_value]
    remove_n = int(len(temp)*perc)
    drop_indices = np.random.choice(temp.index, remove_n, replace=False)
    df_subset = df.drop(drop_indices)
    return df_subset

def convert_flags(val):
    flag_string = '.APRSF'
    result = []
    for x, y in zip(flag_string[1:], val[1:]):
        if x==y:
            result.append(1)
        else:
            result.append(0)
            
    return result

def prepare_datasets(args):
        if not path.isfile(args.data_path):
            print("downloading data...")
            download_extract()
            print("\n")
        
        print("processing data...")
        df = pd.read_csv(args.data_path, low_memory=False)
        #graph requires data to be chronological to compare connections
        df = df.sort_values('Date first seen', ascending=True)
        df = df.drop_duplicates()
        df['attackType'].replace('---', 'benign', inplace=True)
        #drop part of normal network traffic to reduce dataset
        df = drop_percentage(df, 'benign', args.reduce_normal)
        #if compute is limited reduce dataset further
        if args.reduce_all != 0.:
            for value in df.attackType.unique():
                df = drop_percentage(df, value, args.reduce_all)

        #one-hot encode labels
        df = pd.get_dummies(df, prefix='attack', columns=['attackType'])

        #remove single-valued columns, 
        df.drop(columns=['Flows','attackDescription','attackID','class'], inplace=True)

        #convert TCP flags
        df = df.reset_index(drop=True)
        temp = df['Flags'].apply(convert_flags)
        temp = pd.DataFrame(temp.to_list(), columns=['flag_A','flag_P', 'flag_R', 'flag_S','flag_F'])
        df[temp.columns] = temp
        df.drop(columns=['Flags'], inplace=True)

        #convert categorical columns
        df = pd.get_dummies(df, columns=['Proto'])
        df = pd.get_dummies(df, prefix='Tos', columns=['Tos'])

        #There are a number of values of the Bytes column in string form. convert these
        # f.e. 31 MB of bytes
        temp = pd.to_numeric(df['Bytes'], errors='coerce', downcast='integer')
        a = df[temp.isnull()]['Bytes'].apply(lambda x: float(x.strip().split()[0])*10e6)
        df.loc[a.index, 'Bytes'] = a
        df['Bytes'] = pd.to_numeric(df['Bytes'], downcast='integer')

        df_train, df_test = train_test_split(df, shuffle=False, test_size=args.test_size)

        #robust for scaling outliers, number of bytes contains some
        qt = QuantileTransformer()
        qt.fit(df_train[['Duration', 'Packets', 'Bytes']])
        df_train[['Duration', 'Packets', 'Bytes']] = qt.transform(df_train[['Duration', 'Packets', 'Bytes']])
        df_test[['Duration', 'Packets', 'Bytes']] = qt.transform(df_test[['Duration', 'Packets', 'Bytes']])
        
        
        os.makedirs('data/train', exist_ok=True)
        os.makedirs('data/eval', exist_ok=True)
        
        f = open('data/train/week1_prep_train.pkl','wb')
        pickle.dump(df_train, f)
        f.close()

        f = open('data/eval/week1_prep_val.pkl', 'wb')
        pickle.dump(df_test, f)
        f.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process CIDD-01 dataset')
    parser.add_argument('-rn','--reduce-normal', type=float, help='reduce percentage of normal traffic', default=0.8)
    parser.add_argument('-ra','--reduce-all', type=float, help='reduce percentage of all type of traffic', default=0.0)
    parser.add_argument('-dp','--data-path', type=str, help='path of raw csv file to load', default="data/CIDDS-001/traffic/OpenStack/CIDDS-001-internal-week1.csv")
    parser.add_argument('-ts','--test-size', type=float, help='percentage of data to use as test data', default=0.2)
    arguments = parser.parse_args()
    prepare_datasets(arguments)