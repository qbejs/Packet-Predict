import pyshark
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectKBest, chi2, RFE
from tqdm import tqdm
import utils
from rich.console import Console

console = Console()

if __name__ == '__main__':
    console.print("Packet Predict&Analyze")
    console.print("Using model: UNSW-NB15")

    # Load dataset
    console.print("# Reading csv...")
    data = pd.read_csv("trening_data/UNSW_NB15_training-set.csv", dtype=utils.generate_dtype())

    console.print("# Data preprocessing...")
    data = data.dropna()  # remove missing values
    data = data.drop("id", axis=1)  # remove id column

    console.print("# Split dataset into features and labels...")
    X = data.drop(['label', 'attack_cat', 'proto', 'service', 'state'], axis=1)
    y = data['label'].factorize()[0]

    # # Split dataset into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # Create and train the model
    #clf = RandomForestClassifier()
    clf = xgb.XGBClassifier(n_estimators=100)

    console.print("# Train and fit the selector to the data...")
    selector = RFE(clf, n_features_to_select=10)
    for _ in tqdm(range(len(X_train))):
        clf.fit(X_train, y_train)

    # Get the selected features
    X_new = selector.transform(X_train)

    console.log("# Create and train the model with selected features...")
    for _ in tqdm(range(len(X_new))):
        clf.fit(X_new, y_train)

    console.log("# Start capturing packets....")
    capture = pyshark.LiveCapture(interface='en0')
    capture.sniff(timeout=50)

    for packet in capture:
        if packet.transport_layer == 'TCP':
            if packet.highest_layer != 'TCP':
                print("Protocol: {}".format(packet.highest_layer))
            print("Source IP: {}".format(packet.ip.src))
            print("Source Port: {}".format(packet.tcp.srcport))
            print("Destination IP: {}".format(packet.ip.dst))
            print("Destination Port: {}".format(packet.tcp.dstport))

            # Extract features of the packet
            packet_features = [packet.ip.src, packet.tcp.srcport, packet.ip.dst, packet.tcp.dstport]
            console.log("# Predict the probability of vulnerability")
            proba = clf.predict_proba([packet_features])
            print("Probability of vulnerability:", proba)
