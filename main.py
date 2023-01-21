import pyshark
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectKBest, chi2, RFE
from tqdm import tqdm
import utils


# Press the green button in the gutter to run the script.
if __name__ == '__main__':
    # Load dataset
    data = pd.read_csv("UNSW-NB15/trening/UNSW_NB15_training-set.csv", dtype=utils.generate_dtype(), low_memory=False)
    # # Data preprocessing
    data = data.dropna()  # remove missing values
    data = data.drop("id", axis=1)  # remove id column

    # # Split dataset into features and labels
    X = data.drop(['label', 'attack_cat', 'proto', 'service', 'state'], axis=1)
    y = data['label'].factorize()[0]

    # print(X)
    # print(y)

    # # Split dataset into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)
    #
    # Create and train the model
    clf = RandomForestClassifier()
    selector = RFE(clf, n_features_to_select=10)

    # Fit the selector to the data
    for _ in tqdm(range(len(X_train))):
        clf.fit(X_train, y_train)

    # Get the selected features
    X_new = selector.transform(X_train)

    # Create and train the model
    clf = RandomForestClassifier()
    clf.fit(X_new, y_train)

    # Start capturing packets
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
            # Predict the probability of vulnerability
            proba = clf.predict_proba([packet_features])
            print("Probability of vulnerability:", proba)
