import streamlit as st
import pandas as pd
import joblib

# Load the trained model
model = joblib.load("model.pkl")

# Page setup
st.set_page_config(page_title="Intrusion Detection System", layout="centered")
st.title("🛡️ Intrusion Detection System")

# Tabs for input methods
tabs = st.tabs(["📂 Upload CSV", "✍️ Manual Input"])

with tabs[0]:
    st.subheader("Upload a CSV file for prediction")
    uploaded_file = st.file_uploader("Choose a CSV file", type=["csv"])
    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        st.write("📊 Uploaded Data:")
        st.dataframe(df)

        # Make predictions
        predictions = model.predict(df)
        df['Prediction'] = ["✅ Normal" if p == 11 else "⚠️ Attack" for p in predictions]
        st.write("🔍 Prediction Results:")
        st.dataframe(df)

with tabs[1]:
    st.subheader("Manually enter connection features")

    duration = st.number_input("⏱️ Duration", min_value=0)
    protocol_type = st.selectbox("🌐 Protocol Type", options={"tcp": 0, "udp": 1, "icmp": 2})
    src_bytes = st.number_input("📤 Source Bytes", min_value=0)
    dst_bytes = st.number_input("📥 Destination Bytes", min_value=0)
    flag = st.selectbox("🚩 Flag", options={"SF": 0, "S0": 1, "REJ": 2})
    count = st.number_input("📊 Count (connections to the same host)", min_value=0)
    srv_count = st.number_input("📊 Srv Count (connections to the same service)", min_value=0)

    if st.button("🔍 Predict"):
        # Prepare manual input as DataFrame
        input_data = pd.DataFrame([[
            duration, protocol_type, src_bytes, dst_bytes, flag, count, srv_count
        ]], columns=[
            'duration', 'protocol_type', 'src_bytes', 'dst_bytes',
            'flag', 'count', 'srv_count'
        ])

        # Fill missing columns with zeros
        all_features = model.feature_names_in_
        for col in all_features:
            if col not in input_data.columns:
                input_data[col] = 0
        input_data = input_data[all_features]

        # Predict
        prediction = model.predict(input_data)[0]
        if prediction == 11:
            st.success("✅ The connection is NORMAL")
        else:
            st.error("⚠️ The connection is an ATTACK")