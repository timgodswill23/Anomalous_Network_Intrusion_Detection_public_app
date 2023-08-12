# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

import numpy as np
import pickle
import streamlit as st

#loading the saved model
loaded_model = pickle.load(open('attack_model.sav', 'rb'))

#creating a function for prediction
def anomaly_detect(input_data):
    

    # changing the input_data to a numpy_array
    input_data_as_nparray = np.asarray(input_data)

    # reshaping  the array as we are predicting for one instance
    reshaped_input_data = input_data_as_nparray.reshape(1,-1)

    prediction = loaded_model.predict(reshaped_input_data)
    print(prediction)

    if (prediction[0] == 0):
      return'This Network traffic is Normal'
    else:
      return'This Network trafic is an Attack'

def main():
    
    #giving the page a title
    st.title('Anomalous Network Intrusion Detection System')
    
    #capturing input data from user
    
    id = st.text_input('id number')
    dur = st.text_input('total duration of packet flows')
    proto = st.text_input('transaction protocol')
    service = st.text_input('protocol service')
    spkts = st.text_input('source to destination packet count')
    dpkts = st.text_input('destination to source packet count')
    rate = st.text_input('rate of transmission')
    dttl = st.text_input('destination to source time to live value')
    dload = st.text_input('destination bits per second')
    dintpkt = st.text_input('destination interpacket arrival time')
    djit = st.text_input('destination jitter')
    smean = st.text_input('mean of packet size transmitted by source')
    trans_depth = st.text_input('the pipelined depth into the connection of http request')
    response_body_len = st.text_input('content size of data transferred server')
    ct_srv_src = st.text_input('num of connections with same service & source addr in 100 connections')
    is_ftp_login = st.text_input('check on ftp session login by user')
    attack_cat = st.text_input('suspicious attack type: 0 - 9 reconnaisance, fuzzers, Dos, exploits, analysis, backdoors, generic, shellcode, worms ')
    
    #code for prediction
    
    detection = ''
    
    #creating a button for detection
    
    if st.button('Run Sniffer'):
        detection = anomaly_detect([id, dur, proto, 
                                   service, spkts, 
                                   dpkts, rate, 
                                   dttl, dload, 
                                   dintpkt, djit, 
                                   smean, trans_depth, 
                                   response_body_len, 
                                   ct_srv_src, 
                                   is_ftp_login, 
                                   attack_cat])
    
    st.success(detection)

if __name__ == '__main__':
    main()