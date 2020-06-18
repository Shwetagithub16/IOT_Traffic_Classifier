# -*- coding: utf-8 -*-
"""
Created on Tue Mar 24 12:21:32 2020

@author: Dev
"""


import tensorflow as tf
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import OneHotEncoder, LabelEncoder



def visualize(data):
    '''
    This function visualizes the data in the DataFrame.

    Parameters
    ----------
    data : pandas DataFrame
        DataFrame to be visualized.

    Returns
    -------
    None.

    '''

    border = ['-' for i in range(79)]
    print(*border, sep='')
    print('\nData:\n', data)
    print(*border, sep='')
    print('\nColumn DataTypes:\n', data.dtypes)

    print(*border, sep='')
    print('\nColumn Unique Values:')
    for column in data.columns:
        print(*border, sep='')
        print('\n'+column+':\n', data[column].unique())

    print(*border, sep='')
    print('\n', data.isnull().sum())

    print(*border, sep='')
    print(data.describe())


def oneHotencode(data, column):
    '''
    This function OneHot encodes the categorical data column and returns
    inplace replaced dataset.

    Parameters
    ----------
    data : pandas DataFarame
        pandas DataFrame object.
    column : string
        Column in Dataframe to be OneHot Encoded.

    Returns
    -------
    data : padnas DataFrame
        Returns OneHot encoded column dataset.

    '''
    data = data.copy()
    oneHot = OneHotEncoder()
    col_onehot = oneHot.fit_transform(data[[column]])
    col_onehot = np.int32(col_onehot.toarray())
    col_onehot = pd.DataFrame(col_onehot)
    data = data.drop(column, axis=1)
    data = data.join(col_onehot)
    data = data.rename(columns={i: column+str(i) for i in
                                range(len(col_onehot))})
    return data


def df_to_dataset(df, target, shuffle=True, batch_size=32):
    df = df.copy()
    label = df.pop(target)
    dataset = tf.data.Dataset.from_tensor_slices((dict(df), label))
    if shuffle:
        dataset = dataset.shuffle(buffer_size=len(df))
    dataset = dataset.batch(batch_size)
    return(dataset)


def display_imdataset(im_dataset, num_images, labels=None, random=True):

    plt.figure(figsize=(15, 15))
    if random is True:
        figs = np.random.randint(0, high=len(im_dataset), size=num_images)
    else:
        figs = list(range(num_images))
    length = np.ceil(np.sqrt(num_images))
    for i in range(1, num_images+1):
        plt.subplot(length, length, i)
        plt.xticks([])
        plt.yticks([])
        if labels is None:
            plt.title(i)
        else:
            plt.title(str(labels[figs[i-1]]))
        plt.imshow(im_dataset[figs[i-1]])


def augment_imdatset(imdataset, all_images=False, delta=0.15, c_fac=0.2,
                     flip=True, rot90c=True, rot90a=True, brighten=True,
                     flip_per=0.1, rot_per=0.1, bright_per=0.25):

    if all_images is False:

        # Flip along y-axis
        if flip is True:
            rand_ind = np.random.randint(0, high=len(imdataset),
                                         size=int(len(imdataset)*flip_per))
            navin_dataset = tf.image.flip_left_right(
                imdataset[rand_ind]).numpy()

        # Rotate 90degrees clockwise
        if rot90c is True:
            rand_ind = np.random.randint(0, high=len(imdataset),
                                         size=int(len(imdataset)*rot_per))
            navin_dataset = np.append(navin_dataset, tf.image.rot90(
                imdataset[rand_ind]).numpy(), axis=0)

        # Rotate 90degrees anticlockwise
        if rot90a is True:
            rand_ind = np.random.randint(0, high=len(imdataset),
                                         size=int(len(imdataset)*rot_per))
            navin_dataset = np.append(navin_dataset, tf.image.rot90(
                imdataset[rand_ind], k=3).numpy(), axis=0)

        # Brightness Change
        if brighten is True:
            rand_ind = np.random.randint(0, high=len(imdataset),
                                         size=int(len(imdataset)*bright_per))
            navin_dataset = np.append(navin_dataset,
                                      tf.image.adjust_brightness(
                                          imdataset[rand_ind],
                                          delta=0.15).numpy(), axis=0)

    else:
        # Flip along y-axis
        if flip is True:
            navin_dataset = tf.image.flip_left_right(imdataset).numpy()
            print(navin_dataset.shape)

        # Rotate 90degrees clockwise
        if rot90c is True:
            print('rot90c done')
            navin_dataset = np.append(navin_dataset,
                                      tf.image.rot90(imdataset).numpy(),
                                      axis=0)

        # Rotate 90degrees anticlockwise
        if rot90a is True:
            navin_dataset = np.append(navin_dataset,
                                      tf.image.rot90(imdataset, k=3).numpy(),
                                      axis=0)

        # Brightness Change
        if brighten is True:
            navin_dataset = np.append(navin_dataset,
                                      tf.image.adjust_brightness(imdataset,
                                                                 delta=delta).
                                      numpy(),
                                      axis=0)

    return navin_dataset


def ZeekLogs_to_csv(file_path):
    try:
        out_data = pd.read_csv(file_path + '.csv')
        return out_data
    except:
        data_file = open(file_path)
        line = data_file.readline()
        attribs = {}
        while line.strip().startswith('#'):
            # print(line)
            key, *val = line.split()
            attribs[key[1:]] = val
            line = data_file.readline()
        #print(attribs)
        df = {}
        while line.strip().startswith('#close') is False:
            for k, v in zip(attribs['fields'], line.split()):
                #print(k, v)
                if k not in df.keys():
                    df[k] = []
                df[k].append(v)
            line = data_file.readline()

        data_file.close()
        out_data = pd.DataFrame(df)
        out_data.to_csv(file_path + '.csv', index=False)
        return out_data

def return_final_folder(path):
    while os.path.isdir(path):
        path = path + '/' +  os.listdir(path)[0]
    return path

def preprocess_data(list_filepath,
                    drop_col=['ts','uid','service','conn_state',
                              'local_resp', 'local_orig','history','tunnel_parents',
                              'label'],
                    int_cols = ['id.orig_p','id.resp_p', 'orig_bytes', 'resp_bytes', 'missed_bytes','orig_pkts',
                                'orig_ip_bytes','resp_pkts', 'resp_ip_bytes'],
                    float_cols = ['duration']):
    
    data = None
    for file in list_filepath:
        if data is None:
            data = ZeekLogs_to_csv(file)
        else:
            data_single = ZeekLogs_to_csv(file)
            data = pd.concat([data,data_single],ignore_index=True)
        print('Files Loaded:{}'.format(file))
    
    # drop_columns = ['uid','service','conn_state','local_resp', 'local_orig','history','tunnel_parents']
    data = data.drop(columns=drop_col)
    
    data['detailed-label'] = data['detailed-label'].replace(to_replace= '-',value= 'Benign')
    
    data = data.replace(to_replace='-', value=pd.NA)
    
    # int_cols = ['id.orig_p','id.resp_p', 'orig_bytes', 'resp_bytes', 'missed_bytes','orig_pkts',
    #             'orig_ip_bytes','resp_pkts', 'resp_ip_bytes']
    # float_cols = ['ts','duration']
    
    # Modified
    data = data.fillna(value=0)
    
    for col in int_cols:
        data[col] = data[col].astype(np.int32)
    
    for col in float_cols:
        data[col] = data[col].astype(np.float32)
    
        
    label_enc_col = ['id.orig_h', 'id.resp_h', 'proto']
    for col in label_enc_col:
        data[col] = LabelEncoder().fit_transform(data[col])
    
    return data