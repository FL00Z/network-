import streamlit as st
from Analyzer_cleaned import Analyzer

st.title("Network Analyzer Dashboard")

analyzer = Analyzer()
if st.button("Scan Network"):
    analyzer.PrivateScanner.ARP_DiscoverHosts(maxHostgroup=10)
    data = analyzer.PrivateScanner.DiscoveredData
    st.table(data)
