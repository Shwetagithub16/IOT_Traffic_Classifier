# -*- coding: utf-8 -*-
"""
Created on Tue Jun  9 15:10:10 2020

@author: Dev
"""

import pandas as pd


def ZeekLogs_to_csv(file_path):
    """
    Zeek Logs to CSV file.

    Parameters
    ----------
    file_path : str
        File path of the Zeek Log File.

    Returns
    -------
    out_data : DataFrame
        Converts Zeek Log files to csv and returns pandas DataFrame.

    """
    data_file = open(file_path)
    line = data_file.readline()
    attribs = {}
    while line.strip().startswith('#'):
        # print(line)
        key, *val = line.split()
        attribs[key[1:]] = val
        line = data_file.readline()
    # print(attribs)
    df = {}
    while line.strip().startswith('#close') is False:
        for k, v in zip(attribs['fields'], line.split()):
            # print(k, v)
            if k not in df.keys():
                df[k] = []
            df[k].append(v)
        line = data_file.readline()

    out_data = pd.DataFrame(df)
    out_data.to_csv(file_path + '.csv')
    return out_data
