from prepocess import extract_features
import numpy as np
import pickle

one_hot_enc = pickle.load(open("one_hot_encoder", "rb"))
model = pickle.load(open("svm_model", "rb"))


with open('test_domain_list.log', 'r') as f:
    features_list = []
    lines = f.readlines()
    for i in range(len(lines)):
        print('count: ', i)
        line = lines[i]
        features = extract_features(line[:-1], True)
        transformed_point = one_hot_enc.transform(np.array(features[:-1]).reshape(1, -1))
        print("result: ")
        print("is phish" if model.predict(transformed_point)[0] == 1 else "not phish")
