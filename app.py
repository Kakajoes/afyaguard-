import streamlit as st
from elasticsearch import Elasticsearch
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="AfyaGuard-OSS", layout="wide")
st.title("AfyaGuard-OSS – Kenyan Healthcare Threat Hunter")

es = Elasticsearch("http://localhost:9200")

# Live query – change this to whatever you want to hunt
query = {
    "query": {
        "bool": {
            "must": [{"range": {"@timestamp": {"gte": "now-15m"}}}],
            "should": [
                {"wildcard": {"file.name.keyword": "*marks*"}},
                {"wildcard": {"file.name.keyword": "*.xlsx"}},
                {"match": {"event.category": "file"}}
            ],
            "minimum_should_match": 1
        }
    }
}

res = es.search(index="filebeat-*", body=query, size=500)
hits = [hit['_source'] for hit in res['hits']['hits']]

if hits:
    df = pd.DataFrame(hits)
    st.error(f"ALERT: {len(df)} suspicious file events in last 15 min!")
    st.dataframe(df[['@timestamp','source.ip','destination.ip','file.name','file.size']].head(50))
    
    fig = px.scatter(df, x="@timestamp", y="file.size", color="source.ip",
                     hover_data=["file.name"], title="Potential Marks Exfiltration")
    st.plotly_chart(fig, use_container_width=True)
else:
    st.success("No suspicious activity detected – network clean")

st.markdown("Built by **Joachim Kioko Maluni** – Chuka University 2025")
