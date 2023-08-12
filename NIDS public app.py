# -*- coding: utf-8 -*-
"""
Created on Sat Aug 12 00:13:54 2023

@author: Stanmarx
"""

# -*- coding: utf-8 -*-
"""
Created on Fri Aug 11 23:14:02 2023

@author: Stanmarx
"""


# loading the saved model
import numpy as np
import pickle
import streamlit as st
loaded_model = pickle.load(open('attack_model.sav', 'rb'))

# sidebar for navigation
with st.sidebar:

    selected = option_menu('Anomalous Network Intrusion Detection',
                           ['anomaly detection'], icons=['network'], default_index=0)

# anomaly detection page
if (selected == 'Anomalous Network Intrusion Detection'):

    # page title
    st.title('Network flow Investigation')

    # getting input data from user

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        id = st.text_input('id number')
    with col2:
        dur = st.text_input('total duration of packet flows')
    with col3:
        proto = st.text_input('transaction protocol')
    with col4:
        service = st.text_input('protocol service')
    with col5:
        spkts = st.text_input('source to destination packet count')
    with col1:
        dpkts = st.text_input('destination to source packet count')
    with col2:
        rate = st.text_input('rate of transmission')
    with col3:
        dttl = st.text_input('destination to source time to live value')
    with col4:
        dload = st.text_input('destination bits per second')
    with col5:
        dintpkt = st.text_input('destination interpacket arrival time')
    with col1:
        djit = st.text_input('destination jitter')
    with col2:
        smean = st.text_input('mean of packet size transmitted by source')
    with col3:
        trans_depth = st.text_input(
        'the pipelined depth into the connection of http request')
    with col4:
        response_body_len = st.text_input(
        'content size of data transferred server')
    with col5:
        ct_srv_src = st.text_input(
        'num of connections with same service & source addr in 100 connections')
    with col1:
        is_ftp_login = st.text_input('check on ftp session login by user')
    with col2:
        attack_cat = st.text_input(
        'suspicious attack type: 0 - 9 reconnaisance, fuzzers, Dos, exploits, analysis, backdoors, generic, shellcode, worms ')


  
    # code for prediction

    detection = ''

    # creating a button for detection

    if st.button('Run Sniffer'):
        intru_detection = loaded_model.predict([[id, dur, proto,
                                       service, spkts,
                                       dpkts, rate,
                                       dttl, dload,
                                       dintpkt, djit,
                                       smean, trans_depth,
                                       response_body_len,
                                       ct_srv_src,
                                       is_ftp_login,
                                       attack_cat]])
        if (intru_detection[0] == 1):
            detection = 'This Traffic is an Attack'
        else:
            detection = 'This Network Traaffic is Normal'
    st.success(detection


